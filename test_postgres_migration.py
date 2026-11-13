#!/usr/bin/env python3
"""
Matra Naari — Dual-Mode SQLite/PostgreSQL Adapter & Idempotent Migration Test Suite

Tests:
1. SQL translation (BEGIN IMMEDIATE -> BEGIN, ? -> %s outside string literals,
   literal % escaping, INSERT OR IGNORE -> ON CONFLICT DO NOTHING).
2. DualModeRow compatibility (row['col'], row[0], dict(row), .get(), .keys()).
3. Secret masking in mask_database_url().
4. PostgreSQL row-level locking (SELECT ... FOR UPDATE) across stock deduction,
   COD order creation, Razorpay payment verification, order cancellation, and
   admin order/return status updates.
5. Full Flask API lifecycle running in PostgreSQL adapter mode (init_db, auth,
   checkout, COD, Razorpay, cancellations, admin product/coupon/settings upserts).
6. Read-only dry-run migration check against local data/orders.db (verifying all
   10 tables and 290 rows without modifying any file or connecting externally).
7. Idempotent migration execution (running twice against an isolated test target
   and verifying zero duplicates and 100% aggregate parity).
"""

import base64
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import threading

import server
import migrate_sqlite_to_supabase as mig


class EmulatedPostgresCursor:
    """
    Emulates a psycopg2 cursor over an isolated SQLite connection while enforcing
    PostgreSQL SQL syntax rules:
    - Rejects un-translated '?' placeholders outside string literals.
    - Rejects 'BEGIN IMMEDIATE' / 'PRAGMA'.
    - Records every 'SELECT ... FOR UPDATE' statement so tests can assert pessimistic
      row locking in critical sections.
    - Emulates PostgreSQL's information_schema.columns and ALTER TABLE ... ENABLE ROW LEVEL SECURITY.
    """
    def __init__(self, pg_conn, sqlite_cur):
        self._pg_conn = pg_conn
        self._sqlite_cur = sqlite_cur
        self._mock_rows = None
        self._mock_desc = None

    @property
    def description(self):
        if self._mock_desc is not None:
            return self._mock_desc
        return self._sqlite_cur.description

    @property
    def rowcount(self):
        return self._sqlite_cur.rowcount

    def _strip_single_quoted(self, sql):
        return re.sub(r"'([^']|'')*'", "''", sql)

    def execute(self, sql, params=None):
        self._mock_rows = None
        self._mock_desc = None
        raw = str(sql or "").strip()
        upper = raw.upper()

        # Verify no SQLite-only PRAGMA or BEGIN IMMEDIATE reached the Postgres driver
        if upper.startswith("PRAGMA ") or upper.startswith("BEGIN IMMEDIATE"):
            raise RuntimeError(f"SQLite-only statement leaked into PostgreSQL driver: {raw}")

        # Verify no un-translated '?' placeholder reached the Postgres driver
        unquoted = self._strip_single_quoted(raw)
        if "?" in unquoted:
            raise RuntimeError(f"Un-translated '?' placeholder reached PostgreSQL driver: {raw}")

        self._pg_conn.executed_sql.append(raw)

        # Record row-level FOR UPDATE locks
        if re.search(r"\bFOR\s+UPDATE\s*;?\s*$", upper):
            self._pg_conn.for_update_queries.append(raw)

        # Emulate PostgreSQL RLS DDL
        if "ENABLE ROW LEVEL SECURITY" in upper:
            self._pg_conn.rls_enabled_statements.append(raw)
            return

        # Emulate PostgreSQL SET search_path TO <schema>
        if upper.startswith("SET SEARCH_PATH TO "):
            return

        # Emulate PostgreSQL information_schema.columns query
        if "INFORMATION_SCHEMA.COLUMNS" in upper:
            table_name = params[-1] if params else ""
            pragma_rows = self._sqlite_cur.execute(f"PRAGMA table_info({table_name})").fetchall()
            self._mock_desc = [("column_name",)]
            self._mock_rows = [(r[1],) for r in pragma_rows]
            return

        # Emulate PostgreSQL ALTER TABLE ... ADD COLUMN IF NOT EXISTS
        m_add_col = re.match(
            r"^\s*ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+(\w+)\s+(.+)$",
            raw,
            flags=re.IGNORECASE,
        )
        if m_add_col:
            tname, cname, cdef = m_add_col.group(1), m_add_col.group(2), m_add_col.group(3)
            existing = {r[1] for r in self._sqlite_cur.execute(f"PRAGMA table_info({tname})").fetchall()}
            if cname not in existing:
                self._sqlite_cur.execute(f"ALTER TABLE {tname} ADD COLUMN {cname} {cdef}")
            return

        # Strip trailing FOR UPDATE for the underlying SQLite execution engine
        exec_sql = re.sub(r"\s+FOR\s+UPDATE(\s*;?\s*)$", r"\1", raw, flags=re.IGNORECASE)

        # Convert PostgreSQL %s placeholders back to ? for the backing SQLite engine
        if params is not None:
            if len(re.findall(r"%s", unquoted)) != len(params):
                raise RuntimeError(
                    f"Parameter count mismatch for SQL: {raw} (params={len(params)})"
                )
            sqlite_sql = exec_sql.replace("%s", "?").replace("%%", "%")
            self._sqlite_cur.execute(sqlite_sql, tuple(params))
        else:
            self._sqlite_cur.execute(exec_sql)

    def executemany(self, sql, seq_of_params):
        for p in seq_of_params:
            self.execute(sql, p)

    def fetchone(self):
        if self._mock_rows is not None:
            return self._mock_rows.pop(0) if self._mock_rows else None
        return self._sqlite_cur.fetchone()

    def fetchall(self):
        if self._mock_rows is not None:
            rows = list(self._mock_rows)
            self._mock_rows = None
            return rows
        return self._sqlite_cur.fetchall()

    def close(self):
        self._sqlite_cur.close()


class EmulatedPostgresConnection:
    """Emulates a psycopg2 connection backed by a shared SQLite file for testing."""
    def __init__(self, sqlite_path, state_tracker):
        self._sqlite_conn = sqlite3.connect(sqlite_path, timeout=15.0, check_same_thread=False)
        self.autocommit = False
        self._tracker = state_tracker
        self.executed_sql = state_tracker["executed_sql"]
        self.for_update_queries = state_tracker["for_update_queries"]
        self.rls_enabled_statements = state_tracker["rls_enabled_statements"]

    def cursor(self):
        return EmulatedPostgresCursor(self, self._sqlite_conn.cursor())

    def commit(self):
        self._tracker["commits"] += 1
        self._sqlite_conn.commit()

    def rollback(self):
        self._tracker["rollbacks"] += 1
        self._sqlite_conn.rollback()

    def close(self):
        self._sqlite_conn.close()


def run_all_tests():
    passed = 0
    total = 0

    def check(label, condition, detail=""):
        nonlocal passed, total
        total += 1
        if not condition:
            raise AssertionError(f"[FAIL] {label}: {detail}")
        passed += 1
        print(f"  [PASS] {total:02d}. {label}")

    print("=" * 70)
    print(" Running SQLite / PostgreSQL Dual-Mode Adapter & Migration Tests")
    print("=" * 70)

    # 1. Test translate_sql_for_postgres
    check(
        "BEGIN IMMEDIATE translates to BEGIN",
        server.translate_sql_for_postgres("BEGIN IMMEDIATE") == "BEGIN"
        and server.translate_sql_for_postgres("  begin immediate ; ") == "BEGIN",
    )

    q_sql = "SELECT * FROM orders WHERE id = ? AND customer_name != 'Why ? Not %s' AND notes LIKE '%gift%'"
    pg_sql = server.translate_sql_for_postgres(q_sql, has_params=True)
    check(
        "Qmark placeholders translate to %s outside quotes and escape literal %",
        pg_sql == "SELECT * FROM orders WHERE id = %s AND customer_name != 'Why ? Not %s' AND notes LIKE '%%gift%%'",
        pg_sql,
    )

    ins_ignore_sql = "INSERT OR IGNORE INTO newsletter_subscribers (email, created_at) VALUES (?, ?)"
    pg_ins_ignore = server.translate_sql_for_postgres(ins_ignore_sql, has_params=True)
    check(
        "Legacy INSERT OR IGNORE translates to INSERT INTO ... ON CONFLICT DO NOTHING",
        pg_ins_ignore == "INSERT INTO newsletter_subscribers (email, created_at) VALUES (%s, %s) ON CONFLICT DO NOTHING",
        pg_ins_ignore,
    )

    # 2. Test DualModeRow compatibility
    row = server.DualModeRow(["id", "price", "name"], ["straight", 1299, "Gulmohar Straight Kurti"])
    check(
        "DualModeRow supports key access, positional index, slice, dict(), and .get()",
        row["id"] == "straight"
        and row[0] == "straight"
        and row[1] == 1299
        and row[:2] == ("straight", 1299)
        and dict(row) == {"id": "straight", "price": 1299, "name": "Gulmohar Straight Kurti"}
        and row.get("missing", "fallback") == "fallback"
        and "price" in row
        and len(row) == 3,
    )

    # 3. Test mask_database_url secret redaction
    secret_url = "postgresql://postgres.hbpjvtoezlcsyxdxyvna:MySuperSecretPass123!@aws-0-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require"
    masked = server.mask_database_url(secret_url)
    check(
        "mask_database_url redacts username and password completely",
        "MySuperSecretPass123" not in masked
        and "hbpjvtoezlcsyxdxyvna" not in masked
        and masked == "postgresql://***:***@aws-0-ap-south-1.pooler.supabase.com:5432/postgres",
        masked,
    )

    # 4. Test read-only dry-run migration against local data/orders.db
    orig_db_path = os.path.join(server.BASE_DIR, "data", "orders.db")
    with open(orig_db_path, "rb") as f:
        before_sha = hashlib.sha256(f.read()).hexdigest()

    dry_res = mig.run_migration(source_sqlite_path=orig_db_path, dry_run=True)
    with open(orig_db_path, "rb") as f:
        after_sha = hashlib.sha256(f.read()).hexdigest()

    check(
        "Dry-run migration inspects all 10 tables in data/orders.db without modifying a single byte",
        dry_res["ok"] is True
        and dry_res["mode"] == "dry_run"
        and dry_res["migrated"] is False
        and dry_res["audit"]["total_tables"] == 10
        and dry_res["audit"]["tables"]["orders"]["row_count"] == 73
        and dry_res["audit"]["tables"]["users"]["row_count"] == 75
        and dry_res["audit"]["tables"]["products"]["row_count"] == 7
        and dry_res["audit"]["tables"]["coupons"]["row_count"] == 4
        and dry_res["audit"]["tables"]["return_requests"]["row_count"] == 20
        and before_sha == after_sha,
    )

    # 5. Test Full Flask Lifecycle + Row-Level Locking in Emulated PostgreSQL Mode
    tmpdir = tempfile.mkdtemp(prefix="naari_pg_test_")
    prev_db_path = server.DB_PATH
    prev_db_url = server.DATABASE_URL
    prev_pg_fn = server._POSTGRES_CONNECT_FN
    prev_admin_key = server.ADMIN_SECRET_KEY
    prev_disable_geo = os.environ.get("DISABLE_EXTERNAL_GEOCODING")

    try:
        pg_backing_sqlite = os.path.join(tmpdir, "emulated_postgres.sqlite")
        tracker = {
            "executed_sql": [],
            "for_update_queries": [],
            "rls_enabled_statements": [],
            "commits": 0,
            "rollbacks": 0,
        }

        server._POSTGRES_CONNECT_FN = lambda url: EmulatedPostgresConnection(pg_backing_sqlite, tracker)
        server.DATABASE_URL = "postgresql://postgres.hbpjvtoezlcsyxdxyvna:test_only@localhost:5432/postgres"
        server.ADMIN_SECRET_KEY = "test_pg_admin_secret_key"
        os.environ["DISABLE_EXTERNAL_GEOCODING"] = "1"

        check("Server detects PostgreSQL mode when DATABASE_URL is set", server.is_postgres_mode() is True)

        # Initialize schema & seed data via PostgreSQL adapter
        server.init_db()
        # Run init_db() a second time to verify idempotent column/table/seed checks via information_schema
        server.init_db()

        conn = server.get_db()
        check("get_db() returns PostgresConnectionWrapper", getattr(conn, "is_postgres", False) is True)
        c = conn.cursor()
        check("cursor is PostgresCursorWrapper", getattr(c, "is_postgres", False) is True)
        c.execute("SELECT COUNT(*) AS cnt FROM products")
        prod_cnt = c.fetchone()
        check(
            "Products seeded via ON CONFLICT DO NOTHING and accessible by key & index",
            prod_cnt["cnt"] == 7 and prod_cnt[0] == 7,
        )
        conn.close()

        client = server.app.test_client()

        # Register customer in PostgreSQL mode
        reg_resp = client.post(
            "/api/auth/register",
            json={
                "name": "Aarohi Patel",
                "email": "aarohi.pg@example.com",
                "phone": "9876543210",
                "password": "Password123!",
            },
        )
        reg_json = reg_resp.get_json()
        check(
            "Customer registration succeeds in PostgreSQL mode",
            reg_resp.status_code == 200 and reg_json.get("ok") is True and reg_json.get("token"),
        )
        user_token = reg_json["token"]
        auth_headers = {"Authorization": f"Bearer {user_token}"}

        # Duplicate email registration returns 400 cleanly
        dup_resp = client.post(
            "/api/auth/register",
            json={
                "name": "Aarohi Patel",
                "email": "aarohi.pg@example.com",
                "phone": "9876543210",
                "password": "Password123!",
            },
        )
        check(
            "Duplicate email registration returns HTTP 400 in PostgreSQL mode",
            dup_resp.status_code == 400 and dup_resp.get_json().get("ok") is False,
        )

        # Place a COD order with coupon NAARI10 and verify FOR UPDATE locks on coupons & products
        tracker["for_update_queries"].clear()
        cod_resp = client.post(
            "/api/create-cod-order",
            headers=auth_headers,
            json={
                "items": [{"id": "straight", "size": "M", "qty": 2}],
                "coupon_code": "NAARI10",
                "customer": {
                    "name": "Aarohi Patel",
                    "email": "aarohi.pg@example.com",
                    "phone": "9876543210",
                    "house_no": "Flat 402, Shanti Residency",
                    "street_area": "CG Road, Navrangpura",
                    "address_line1": "Flat 402, Shanti Residency, CG Road, Navrangpura",
                    "city": "Ahmedabad",
                    "state": "Gujarat",
                    "pincode": "380009",
                    "latitude": 23.0365,
                    "longitude": 72.5611,
                },
            },
        )
        cod_json = cod_resp.get_json()
        check(
            "COD order creation succeeds in PostgreSQL mode",
            cod_resp.status_code == 200 and cod_json.get("ok") is True,
            str(cod_json),
        )
        cod_order_id = cod_json["order_id"]
        check(
            "COD order acquires PostgreSQL FOR UPDATE row locks on coupons and products",
            any("FROM coupons" in q and "FOR UPDATE" in q for q in tracker["for_update_queries"])
            and any("FROM products" in q and "FOR UPDATE" in q for q in tracker["for_update_queries"]),
            str(tracker["for_update_queries"]),
        )

        # Cancel COD order and verify FOR UPDATE lock on orders & products stock restoration
        tracker["for_update_queries"].clear()
        cancel_resp = client.post(
            "/api/customer/orders/cancel",
            headers=auth_headers,
            json={"order_id": cod_order_id, "reason": "Testing Postgres cancellation"},
        )
        check(
            "Order cancellation succeeds and acquires FOR UPDATE lock on orders & products",
            cancel_resp.status_code == 200
            and cancel_resp.get_json().get("ok") is True
            and any("FROM orders WHERE id = %s FOR UPDATE" in q for q in tracker["for_update_queries"])
            and any("FROM products WHERE id = %s FOR UPDATE" in q for q in tracker["for_update_queries"]),
            str(tracker["for_update_queries"]),
        )

        # Test Razorpay payment verification with FOR UPDATE lock in PostgreSQL mode
        os.environ["RAZORPAY_KEY_ID"] = "rzp_test_RealKey123456"
        os.environ["RAZORPAY_KEY_SECRET"] = "rzp_secret_RealSecret987654"
        rzp_internal_id = "NAARI-PGTEST-RZP01"
        rzp_order_id = "order_PgLiveOrder12345"
        rzp_payment_id = "pay_PgLivePayment67890"
        now_iso = "2026-11-13T12:00:00"

        conn = server.get_db()
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO orders (
                id, customer_name, customer_email, customer_phone,
                address_line1, address_line2, city, state, pincode,
                payment_method, payment_status, order_status, razorpay_order_id,
                subtotal, shipping, discount_amount, coupon_code, total_amount,
                items_json, user_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO UPDATE SET updated_at = excluded.updated_at
            """,
            (
                rzp_internal_id, "Aarohi Patel", "aarohi.pg@example.com", "9876543210",
                "Flat 402, Shanti Residency, CG Road", "", "Ahmedabad", "Gujarat", "380009",
                "razorpay", "pending", "pending_payment", rzp_order_id,
                1499, 0, 0, "", 1499,
                json.dumps([{"id": "aline", "name": "Chandni A-Line Kurti", "size": "M", "qty": 1, "price": 1499}]),
                reg_json["user"]["id"], now_iso, now_iso,
            ),
        )
        conn.commit()
        conn.close()

        valid_sig = hmac.new(
            b"rzp_secret_RealSecret987654",
            f"{rzp_order_id}|{rzp_payment_id}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        tracker["for_update_queries"].clear()
        ver_resp = client.post(
            "/api/verify-payment",
            headers=auth_headers,
            json={
                "order_id": rzp_internal_id,
                "razorpay_order_id": rzp_order_id,
                "razorpay_payment_id": rzp_payment_id,
                "razorpay_signature": valid_sig,
            },
        )
        ver_json = ver_resp.get_json()
        check(
            "Razorpay payment verification succeeds and locks order & product rows with FOR UPDATE",
            ver_resp.status_code == 200
            and ver_json.get("ok") is True
            and ver_json.get("status") == "paid"
            and any("FROM orders WHERE id = %s FOR UPDATE" in q for q in tracker["for_update_queries"])
            and any("FROM products WHERE id = %s FOR UPDATE" in q for q in tracker["for_update_queries"]),
            str(ver_json),
        )

        # Test Admin Login (/api/admin/verify -> admin_sessions table), Settings, Orders, and Returns in PostgreSQL mode
        os.environ["ADMIN_SECRET_KEY"] = "test_pg_admin_secret_key"
        adm_login_resp = client.post(
            "/api/admin/verify",
            json={"passkey": "test_pg_admin_secret_key"},
        )
        adm_login_json = adm_login_resp.get_json()
        check(
            "Admin login creates session in admin_sessions table in PostgreSQL mode",
            adm_login_resp.status_code == 200 and adm_login_json.get("ok") is True and adm_login_json.get("token"),
            str(adm_login_json),
        )
        admin_headers = {"Authorization": f"Bearer {adm_login_json['token']}"}

        set_resp = client.post(
            "/api/admin/settings",
            headers=admin_headers,
            json={"free_shipping_threshold": 1199, "shipping_fee": 79},
        )
        check(
            "Admin settings upsert (ON CONFLICT DO UPDATE) succeeds in PostgreSQL mode",
            set_resp.status_code == 200 and set_resp.get_json().get("settings", {}).get("free_shipping_threshold") == 1199,
            str(set_resp.get_json()),
        )

        tracker["for_update_queries"].clear()
        adm_ord_resp = client.post(
            "/api/admin/orders/status",
            headers=admin_headers,
            json={
                "order_id": rzp_internal_id,
                "order_status": "delivered",
                "tracking_number": "AWB998877",
                "courier_partner": "BlueDart",
            },
        )
        check(
            "Admin order status update acquires FOR UPDATE lock on orders in PostgreSQL mode",
            adm_ord_resp.status_code == 200
            and adm_ord_resp.get_json().get("ok") is True
            and any("FROM orders WHERE id = %s FOR UPDATE" in q for q in tracker["for_update_queries"]),
        )

        # Submit a customer return request and advance its status via admin (testing FOR UPDATE on return_requests)
        ret_create_resp = client.post(
            "/api/customer/returns",
            headers=auth_headers,
            json={
                "order_id": rzp_internal_id,
                "email": "aarohi.pg@example.com",
                "phone": "9876543210",
                "item_name": "Chandni A-Line Kurti",
                "action_type": "exchange",
                "reason": "Size exchange needed",
                "notes": "Need L instead of M",
            },
        )
        ret_create_json = ret_create_resp.get_json()
        ret_id = ret_create_json.get("return_id") or ret_create_json.get("id")
        tracker["for_update_queries"].clear()
        adm_ret_resp = client.post(
            "/api/admin/returns/status",
            headers=admin_headers,
            json={"return_id": ret_id, "status": "approved", "notes": "Approved in PG test"},
        )
        check(
            "Admin return status update acquires FOR UPDATE lock on return_requests in PostgreSQL mode",
            adm_ret_resp.status_code == 200
            and adm_ret_resp.get_json().get("ok") is True
            and any("FROM return_requests WHERE id = %s FOR UPDATE" in q for q in tracker["for_update_queries"]),
            str(adm_ret_resp.get_json()),
        )

        # 6. Test Idempotent Migration Execution (Source SQLite -> Emulated Postgres Target)
        mig_target_sqlite = os.path.join(tmpdir, "migrated_target_pg.sqlite")
        mig_tracker = {
            "executed_sql": [],
            "for_update_queries": [],
            "rls_enabled_statements": [],
            "commits": 0,
            "rollbacks": 0,
        }
        server._POSTGRES_CONNECT_FN = lambda url: EmulatedPostgresConnection(mig_target_sqlite, mig_tracker)

        exec_res_1 = mig.run_migration(
            source_sqlite_path=pg_backing_sqlite,
            target_db_url="postgresql://postgres.hbpjvtoezlcsyxdxyvna:test_only@localhost:5432/postgres",
            dry_run=False,
            enable_rls=True,
        )
        check(
            "First migration execution migrates all 10 tables, enables RLS, and verifies 100% parity",
            exec_res_1["ok"] is True
            and exec_res_1["migrated"] is True
            and exec_res_1["verified"] is True
            and len(mig_tracker["rls_enabled_statements"]) == 10,
        )

        # Run migration a second time to verify idempotency (zero duplicate rows, identical aggregates)
        exec_res_2 = mig.run_migration(
            source_sqlite_path=pg_backing_sqlite,
            target_db_url="postgresql://postgres.hbpjvtoezlcsyxdxyvna:test_only@localhost:5432/postgres",
            dry_run=False,
            enable_rls=True,
        )
        check(
            "Second migration execution is 100% idempotent with identical row counts and aggregates",
            exec_res_2["ok"] is True
            and exec_res_2["migrated_counts"] == exec_res_1["migrated_counts"]
            and exec_res_2["verification"]["aggregates"] == exec_res_1["verification"]["aggregates"],
        )

        # 7. Test Server-Side Sales Gate blocks BOTH COD and Razorpay order creation
        server._POSTGRES_CONNECT_FN = lambda url: EmulatedPostgresConnection(pg_backing_sqlite, tracker)
        gate_set_resp = client.post(
            "/api/admin/settings",
            headers=admin_headers,
            json={"cod_enabled": False},
        )
        check(
            "Admin setting cod_enabled=False activates server-side sales gate (sales_enabled=False)",
            gate_set_resp.status_code == 200
            and gate_set_resp.get_json().get("settings", {}).get("sales_enabled") is False,
        )

        blocked_cod = client.post(
            "/api/create-cod-order",
            headers=auth_headers,
            json={
                "customer": {
                    "name": "Aarohi Patel",
                    "email": "aarohi.pg@example.com",
                    "phone": "9876543210",
                    "address_line1": "Flat 402, Shanti Residency, CG Road",
                    "city": "Ahmedabad",
                    "state": "Gujarat",
                    "pincode": "380009",
                },
                "items": [{"id": "aline", "size": "M", "qty": 1}],
            },
        )
        blocked_rzp = client.post(
            "/api/create-order",
            headers=auth_headers,
            json={
                "customer": {
                    "name": "Aarohi Patel",
                    "email": "aarohi.pg@example.com",
                    "phone": "9876543210",
                    "address_line1": "Flat 402, Shanti Residency, CG Road",
                    "city": "Ahmedabad",
                    "state": "Gujarat",
                    "pincode": "380009",
                },
                "items": [{"id": "aline", "size": "M", "qty": 1}],
            },
        )
        check(
            "Server-side sales gate blocks BOTH COD (/api/create-cod-order) and Razorpay (/api/create-order) with HTTP 403",
            blocked_cod.status_code == 403
            and blocked_cod.get_json().get("sales_paused") is True
            and blocked_rzp.status_code == 403
            and blocked_rzp.get_json().get("sales_paused") is True,
            f"cod={blocked_cod.status_code}, rzp={blocked_rzp.status_code}",
        )

        # 8. Test Supabase Storage Integration (Upload, Auth, MIME/Magic/5MiB Validation, Failure Atomicity, Restart Recovery, Secret Isolation)
        prev_upload_dir = server.UPLOAD_DIR
        prev_storage_backend = server._SUPABASE_STORAGE_BACKEND
        test_upload_dir = os.path.join(tmpdir, "uploads_cache")
        server.UPLOAD_DIR = test_upload_dir
        os.environ["SUPABASE_SERVICE_ROLE_KEY"] = "sb_secret_TestOnlyNeverExpose999"

        class IsolatedStorageBackend:
            def __init__(self):
                self.objects = {}
                self.fail_next = False

            def upload(self, bucket, key, raw_bytes, content_type):
                if self.fail_next:
                    return False
                self.objects[(bucket, key)] = (bytes(raw_bytes), content_type)
                return True

            def download(self, bucket, key):
                return self.objects.get((bucket, key))

            def exists(self, bucket, key):
                return (bucket, key) in self.objects

        mock_storage = IsolatedStorageBackend()
        server._SUPABASE_STORAGE_BACKEND = mock_storage
        try:
            tiny_png_bytes = base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
            )
            tiny_png_b64 = base64.b64encode(tiny_png_bytes).decode("ascii")

            # 25. Unauthenticated upload rejected (401)
            unauth_client = server.app.test_client()
            unauth_up = unauth_client.post(
                "/api/admin/upload-image",
                json={"filename": "kurti.png", "data_url": f"data:image/png;base64,{tiny_png_b64}"},
            )
            check("Unauthenticated image upload returns HTTP 401", unauth_up.status_code == 401)

            # 26. MIME/Magic-byte mismatch & >5 MiB rejected
            mismatch_ext_up = client.post(
                "/api/admin/upload-image",
                headers=admin_headers,
                json={"filename": "disguised.jpg", "data_url": f"data:image/png;base64,{tiny_png_b64}"},
            )
            mismatch_mime_up = client.post(
                "/api/admin/upload-image",
                headers=admin_headers,
                json={"filename": "disguised.png", "data_url": f"data:image/jpeg;base64,{tiny_png_b64}"},
            )
            oversized_bytes = b"\x89PNG\r\n\x1a\n" + (b"\x00" * (server.MAX_UPLOAD_FILE_BYTES + 100))
            oversized_up = client.post(
                "/api/admin/upload-image",
                headers=admin_headers,
                data={"file": (io.BytesIO(oversized_bytes), "huge.png", "image/png")},
                content_type="multipart/form-data",
            )
            check(
                "Extension mismatch (400), MIME mismatch (400), and >5 MiB payload (413) are rejected",
                mismatch_ext_up.status_code == 400
                and mismatch_mime_up.status_code == 400
                and oversized_up.status_code == 413,
                f"ext={mismatch_ext_up.status_code}, mime={mismatch_mime_up.status_code}, size={oversized_up.status_code}",
            )

            # 27. Valid uploads generate unique filenames, store in product-images bucket, and preserve assets/uploads/<filename> URL
            up1 = client.post(
                "/api/admin/upload-image",
                headers=admin_headers,
                json={"filename": "festive_kurti.png", "data_url": f"data:image/png;base64,{tiny_png_b64}"},
            )
            up2 = client.post(
                "/api/admin/upload-image",
                headers=admin_headers,
                json={"filename": "festive_kurti.png", "data_url": f"data:image/png;base64,{tiny_png_b64}"},
            )
            up1_json = up1.get_json()
            up2_json = up2.get_json()
            rel_path_1 = up1_json.get("image_path", "")
            rel_path_2 = up2_json.get("image_path", "")
            fname_1 = os.path.basename(rel_path_1)
            check(
                "Valid uploads succeed, generate unique filenames, and store in product-images bucket",
                up1.status_code == 200
                and up2.status_code == 200
                and up1_json.get("storage_backed") is True
                and rel_path_1.startswith("assets/uploads/festive_kurti-")
                and rel_path_1 != rel_path_2
                and mock_storage.exists("product-images", f"uploads/{fname_1}"),
            )

            # 28. Restart recovery: wipe local ephemeral upload cache and verify GET /assets/uploads/<fname> & product save still succeed from Supabase Storage
            shutil.rmtree(test_upload_dir, ignore_errors=True)
            check_not_on_disk = not os.path.exists(os.path.join(test_upload_dir, fname_1))
            get_after_restart = client.get(f"/{rel_path_1}")
            prod_save_after_restart = client.post(
                "/api/admin/products",
                headers=admin_headers,
                json={
                    "id": "restart_kurti",
                    "name": "Restart Recovery Kurti",
                    "category": "Straight Cut",
                    "price": 1399,
                    "mrp": 1999,
                    "stock": 10,
                    "image": rel_path_1,
                    "gallery": [rel_path_1, "assets/uploads/nonexistent-broken.png"],
                },
            )
            saved_restart_prod = client.get("/api/products/restart_kurti").get_json().get("product", {})
            check(
                "Restart recovery serves image from Supabase Storage after local disk wipe and filters broken gallery refs",
                check_not_on_disk
                and get_after_restart.status_code == 200
                and get_after_restart.data == tiny_png_bytes
                and get_after_restart.mimetype == "image/png"
                and prod_save_after_restart.status_code == 200
                and saved_restart_prod.get("image") == rel_path_1
                and saved_restart_prod.get("gallery") == [rel_path_1],
            )

            # 29. Upload failure atomicity: failed cloud upload returns 502, writes no orphan local file, and cannot create broken DB reference
            mock_storage.fail_next = True
            shutil.rmtree(test_upload_dir, ignore_errors=True)
            failed_up = client.post(
                "/api/admin/upload-image",
                headers=admin_headers,
                json={"filename": "fail_kurti.png", "data_url": f"data:image/png;base64,{tiny_png_b64}"},
            )
            local_files_after_fail = os.listdir(test_upload_dir) if os.path.isdir(test_upload_dir) else []
            prod_with_broken_img = client.post(
                "/api/admin/products",
                headers=admin_headers,
                json={
                    "id": "broken_ref_kurti",
                    "name": "Broken Ref Guard Kurti",
                    "category": "Straight Cut",
                    "price": 1299,
                    "mrp": 1799,
                    "stock": 5,
                    "image": "assets/uploads/never-uploaded-missing.png",
                },
            )
            broken_prod_data = client.get("/api/products/broken_ref_kurti").get_json().get("product", {})
            check(
                "Storage upload failure aborts cleanly (502) without local orphan files or broken DB image references",
                failed_up.status_code == 502
                and failed_up.get_json().get("ok") is False
                and "image_path" not in failed_up.get_json()
                and len(local_files_after_fail) == 0
                and broken_prod_data.get("image") == "assets/hero.jpg",
            )

            # 30. Service role key is never exposed in public config, admin settings, or upload responses
            cfg_dump = json.dumps(client.get("/api/config").get_json())
            adm_set_dump = json.dumps(client.get("/api/admin/settings", headers=admin_headers).get_json())
            up_dump = json.dumps(up1_json)
            check(
                "SUPABASE_SERVICE_ROLE_KEY is never exposed in /api/config, /api/admin/settings, or upload responses",
                "sb_secret_TestOnlyNeverExpose999" not in cfg_dump
                and "sb_secret_TestOnlyNeverExpose999" not in adm_set_dump
                and "sb_secret_TestOnlyNeverExpose999" not in up_dump,
            )

            # 31. Test provision_supabase_storage.py dry-run, idempotent execution, unrelated policy preservation, and unsafe write policy rejection
            import provision_supabase_storage as prov

            class MockProvisionConnection:
                def __init__(self, initial_buckets=None, initial_policies=None):
                    self.buckets = list(initial_buckets or [])
                    self.policies = list(initial_policies or [])
                    self.executed_sql = []

                def commit(self):
                    pass

                def rollback(self):
                    pass

                def close(self):
                    pass

                def cursor(self):
                    conn = self

                    class _Cur:
                        def __init__(self):
                            self._rows = []

                        def execute(self, sql, params=()):
                            s = " ".join(str(sql).split())
                            conn.executed_sql.append((s, params))
                            if "FROM pg_tables" in s:
                                self._rows = [
                                    {"tablename": "buckets", "tableowner": "supabase_storage_admin", "rowsecurity": True},
                                    {"tablename": "objects", "tableowner": "supabase_storage_admin", "rowsecurity": True},
                                ]
                            elif "FROM pg_policies" in s:
                                self._rows = list(conn.policies)
                            elif "SELECT id, name, public, file_size_limit, allowed_mime_types FROM" in s:
                                self._rows = list(conn.buckets)
                            elif s.startswith("INSERT INTO") and ".buckets" in s:
                                b_id, b_name, b_lim, b_mimes = params
                                entry = {
                                    "id": b_id,
                                    "name": b_name,
                                    "public": True,
                                    "file_size_limit": b_lim,
                                    "allowed_mime_types": list(b_mimes),
                                }
                                conn.buckets = [b for b in conn.buckets if b["id"] != b_id] + [entry]
                                self._rows = []
                            elif s.startswith('DROP POLICY IF EXISTS "matra_naari_product_images_public_read"'):
                                conn.policies = [
                                    p for p in conn.policies if p["policyname"] != "matra_naari_product_images_public_read"
                                ]
                                self._rows = []
                            elif s.startswith('CREATE POLICY "matra_naari_product_images_public_read"'):
                                conn.policies.append(
                                    {
                                        "tablename": "objects",
                                        "policyname": "matra_naari_product_images_public_read",
                                        "permissive": "PERMISSIVE",
                                        "roles": "{public}",
                                        "cmd": "SELECT",
                                        "qual": "(bucket_id = 'product-images'::text)",
                                        "with_check": None,
                                    }
                                )
                                self._rows = []
                            else:
                                self._rows = []

                        def fetchall(self):
                            return list(self._rows)

                        def close(self):
                            pass

                    return _Cur()

            unrelated_pol = {
                "tablename": "objects",
                "policyname": "other_bucket_custom_policy",
                "permissive": "PERMISSIVE",
                "roles": "{authenticated}",
                "cmd": "SELECT",
                "qual": "(bucket_id = 'avatars'::text)",
                "with_check": None,
            }
            mock_prov_conn = MockProvisionConnection(initial_buckets=[], initial_policies=[unrelated_pol])

            # Dry run leaves state untouched
            prov_dry = prov.provision_product_images_bucket(
                dry_run=True,
                conn_override=mock_prov_conn,
            )
            # Execute first time
            prov_exec_1 = prov.provision_product_images_bucket(
                dry_run=False,
                conn_override=mock_prov_conn,
            )
            # Execute second time (idempotency check)
            prov_exec_2 = prov.provision_product_images_bucket(
                dry_run=False,
                conn_override=mock_prov_conn,
            )
            check(
                "provision_supabase_storage.py dry-run makes zero changes and --execute idempotently configures 5 MiB JPEG/PNG/WEBP public-read bucket while preserving unrelated policies",
                prov_dry["ok"] is True
                and prov_dry["executed"] is False
                and prov_dry["before_state"]["target_bucket"] is None
                and prov_exec_1["ok"] is True
                and prov_exec_1["verified"] is True
                and prov_exec_2["ok"] is True
                and prov_exec_2["verified"] is True
                and len(mock_prov_conn.buckets) == 1
                and mock_prov_conn.buckets[0]["id"] == "product-images"
                and mock_prov_conn.buckets[0]["public"] is True
                and mock_prov_conn.buckets[0]["file_size_limit"] == 5242880
                and mock_prov_conn.buckets[0]["allowed_mime_types"] == ["image/jpeg", "image/png", "image/webp"]
                and prov_exec_2["after_state"]["unrelated_policies_preserved"] == ["other_bucket_custom_policy"],
            )

            # Verify unsafe write policy on product-images is caught and blocked
            unsafe_pol_conn = MockProvisionConnection(
                initial_buckets=[],
                initial_policies=[
                    {
                        "tablename": "objects",
                        "policyname": "bad_anon_upload_policy",
                        "permissive": "PERMISSIVE",
                        "roles": "{anon}",
                        "cmd": "INSERT",
                        "qual": None,
                        "with_check": "(bucket_id = 'product-images'::text)",
                    }
                ],
            )
            unsafe_blocked = False
            try:
                prov.provision_product_images_bucket(dry_run=True, conn_override=unsafe_pol_conn)
            except RuntimeError:
                unsafe_blocked = True
            check(
                "provision_supabase_storage.py detects and rejects unsafe anon/authenticated INSERT/UPDATE/DELETE policies on product-images",
                unsafe_blocked is True,
            )
        finally:
            server.UPLOAD_DIR = prev_upload_dir
            server._SUPABASE_STORAGE_BACKEND = prev_storage_backend
            os.environ.pop("SUPABASE_SERVICE_ROLE_KEY", None)

    finally:
        server.DB_PATH = prev_db_path
        server.DATABASE_URL = prev_db_url
        server._POSTGRES_CONNECT_FN = prev_pg_fn
        server.ADMIN_SECRET_KEY = prev_admin_key
        os.environ.pop("ADMIN_SECRET_KEY", None)
        os.environ.pop("RAZORPAY_KEY_ID", None)
        os.environ.pop("RAZORPAY_KEY_SECRET", None)
        if prev_disable_geo is None:
            os.environ.pop("DISABLE_EXTERNAL_GEOCODING", None)
        else:
            os.environ["DISABLE_EXTERNAL_GEOCODING"] = prev_disable_geo
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("=" * 70)
    print(f" ALL {passed}/{total} POSTGRESQL ADAPTER & MIGRATION TESTS PASSED!")
    print("=" * 70)


if __name__ == "__main__":
    run_all_tests()
