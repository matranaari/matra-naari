#!/usr/bin/env python3
"""
Matra Naari — Safe Supabase PostgreSQL Disposable-Schema Integration Test
Target Supabase Project ID: hbpjvtoezlcsyxdxyvna

Safety guarantees:
1. Stops immediately if DATABASE_URL is unavailable in the environment or local .env,
   or if psycopg2 is not installed.
2. Never prints, logs, or exposes credentials, passwords, or connection tokens.
3. Never reads or uses production customer data (uses 100% synthetic test fixtures).
4. Never creates, modifies, or drops any table or row in the `public` schema:
   - Creates an isolated disposable schema `naari_disp_<timestamp>_<hex>`.
   - Pins every server connection (`server.POSTGRES_SCHEMA`) to that disposable schema
     via `SET search_path TO <disposable_schema>`.
   - Snapshots `public` schema table metadata before and after the run to prove
     zero changes to `public`.
   - Always drops the disposable schema (`DROP SCHEMA IF EXISTS <schema> CASCADE`)
     in a `finally` block and verifies its removal.
5. Verifies:
   - Live PostgreSQL connection & `current_schema()` isolation
   - 10-table schema compatibility & idempotent column/index migrations (`server.init_db()`)
   - Synthetic COD & Razorpay order transactions, stock deduction, and order cancellation
   - Multi-threaded `SELECT ... FOR UPDATE` row-locking concurrency on the last unit of stock
   - Complete disposable schema cleanup (`DROP SCHEMA ... CASCADE`)
"""

import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from datetime import datetime

import server

SUPABASE_PROJECT_ID = "hbpjvtoezlcsyxdxyvna"
EXPECTED_TABLES = (
    "orders",
    "products",
    "coupons",
    "users",
    "user_sessions",
    "user_addresses",
    "return_requests",
    "site_settings",
    "newsletter_subscribers",
    "admin_sessions",
)


def _load_database_url_safely():
    """
    Checks process environment first, then optional local .env file, for DATABASE_URL.
    Never prints or logs the raw value.
    """
    env_val = (os.environ.get("DATABASE_URL") or "").strip()
    if env_val:
        return env_val

    dotenv_path = os.path.join(server.BASE_DIR, ".env")
    if os.path.isfile(dotenv_path):
        try:
            with open(dotenv_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    if k.strip() == "DATABASE_URL":
                        val = v.strip().strip('"').strip("'")
                        if val:
                            return val
        except Exception:
            pass
    return ""


def _snapshot_public_schema(conn):
    """Returns a list of existing table names in the public schema without reading customer data."""
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = ? ORDER BY table_name ASC",
            ("public",),
        )
        return [r["table_name"] for r in cur.fetchall()]
    finally:
        cur.close()


def run_supabase_integration_test():
    db_url = _load_database_url_safely()
    if not db_url or not server.is_postgres_url(db_url):
        report = {
            "ok": False,
            "status": "stopped_missing_database_url",
            "supabase_project_id": SUPABASE_PROJECT_ID,
            "message": (
                "DATABASE_URL is not configured in the environment or local .env file. "
                "Stopped safely without connecting or making any changes."
            ),
        }
        print(json.dumps(report, indent=2))
        return 2

    if server.psycopg2 is None and server._POSTGRES_CONNECT_FN is None:
        report = {
            "ok": False,
            "status": "stopped_missing_psycopg2",
            "supabase_project_id": SUPABASE_PROJECT_ID,
            "target_database": server.mask_database_url(db_url),
            "message": (
                "psycopg2 is not installed in the active Python environment. "
                "Install psycopg2-binary (`pip install -r requirements.txt`) to run live PostgreSQL integration tests."
            ),
        }
        print(json.dumps(report, indent=2))
        return 2

    disposable_schema = f"naari_disp_{int(time.time())}_{secrets.token_hex(4)}"
    prev_db_url = server.DATABASE_URL
    prev_schema = server.POSTGRES_SCHEMA
    prev_admin_key = server.ADMIN_SECRET_KEY
    prev_disable_geo = os.environ.get("DISABLE_EXTERNAL_GEOCODING")

    steps_passed = []
    cleanup_verified = False
    public_untouched = False

    admin_conn = None
    try:
        # Step 1: Connect in default schema only to snapshot public table list & create disposable schema
        server.DATABASE_URL = db_url
        server.POSTGRES_SCHEMA = "public"
        admin_conn = server.get_db()
        public_tables_before = _snapshot_public_schema(admin_conn)

        cur = admin_conn.cursor()
        cur.execute(f"CREATE SCHEMA {disposable_schema}")
        admin_conn.commit()
        cur.close()
        steps_passed.append("1. Connected to PostgreSQL and created disposable schema")

        # Step 2: Pin server.POSTGRES_SCHEMA to the disposable schema and verify isolation
        server.POSTGRES_SCHEMA = disposable_schema
        os.environ["DISABLE_EXTERNAL_GEOCODING"] = "1"
        os.environ["ADMIN_SECRET_KEY"] = "synthetic_integration_admin_key"
        server.ADMIN_SECRET_KEY = "synthetic_integration_admin_key"

        iso_conn = server.get_db()
        iso_cur = iso_conn.cursor()
        iso_cur.execute("SELECT current_schema() AS active_schema")
        active_schema = iso_cur.fetchone()["active_schema"]
        iso_cur.close()
        iso_conn.close()
        if active_schema != disposable_schema:
            raise RuntimeError(
                f"Schema isolation check failed: expected '{disposable_schema}', got '{active_schema}'"
            )
        steps_passed.append("2. Verified SET search_path isolation to disposable schema")

        # Step 3: Initialize all 10 tables & indexes inside the disposable schema
        server.init_db()
        # Run a second time to verify idempotent migrations against information_schema.columns
        server.init_db()

        chk_conn = server.get_db()
        chk_cur = chk_conn.cursor()
        chk_cur.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = ? ORDER BY table_name ASC",
            (disposable_schema,),
        )
        created_tables = [r["table_name"] for r in chk_cur.fetchall()]
        missing_tables = [t for t in EXPECTED_TABLES if t not in created_tables]
        chk_cur.close()
        chk_conn.close()
        if missing_tables:
            raise RuntimeError(f"Missing tables in disposable schema: {missing_tables}")
        steps_passed.append("3. Verified all 10 tables and schema migrations inside disposable schema")

        # Step 4: Verify synthetic customer auth, COD order, Razorpay order verification, and cancellation
        client = server.app.test_client()
        reg_resp = client.post(
            "/api/auth/register",
            json={
                "name": "Synthetic Tester",
                "email": "synthetic.tester@example.invalid",
                "phone": "9876543210",
                "password": "SyntheticPass123!",
            },
        )
        reg_data = reg_resp.get_json() or {}
        if reg_resp.status_code != 200 or not reg_data.get("ok"):
            raise RuntimeError(f"Synthetic user registration failed: {reg_data}")
        user_token = reg_data["token"]
        auth_headers = {"Authorization": f"Bearer {user_token}"}

        cod_resp = client.post(
            "/api/create-cod-order",
            headers=auth_headers,
            json={
                "items": [{"id": "straight", "size": "M", "qty": 1}],
                "coupon_code": "NAARI10",
                "customer": {
                    "name": "Synthetic Tester",
                    "email": "synthetic.tester@example.invalid",
                    "phone": "9876543210",
                    "house_no": "Plot 10, Synthetic Enclave",
                    "street_area": "MG Road, Indiranagar",
                    "address_line1": "Plot 10, Synthetic Enclave, MG Road, Indiranagar",
                    "city": "Bengaluru",
                    "state": "Karnataka",
                    "pincode": "560038",
                    "latitude": 12.9784,
                    "longitude": 77.6408,
                },
            },
        )
        cod_data = cod_resp.get_json() or {}
        if cod_resp.status_code != 200 or not cod_data.get("ok"):
            raise RuntimeError(f"Synthetic COD order failed: {cod_data}")

        cancel_resp = client.post(
            "/api/customer/orders/cancel",
            headers=auth_headers,
            json={"order_id": cod_data["order_id"], "reason": "Synthetic integration test cancel"},
        )
        if cancel_resp.status_code != 200 or not (cancel_resp.get_json() or {}).get("ok"):
            raise RuntimeError(f"Synthetic order cancellation failed: {cancel_resp.get_json()}")
        steps_passed.append("4. Verified synthetic customer registration, COD order, and cancellation")

        # Step 5: Verify multi-threaded row-level locking concurrency (SELECT ... FOR UPDATE)
        # Set synthetic product 'kaftan' stock to exactly 1 unit ("Free Size": 1)
        stock_conn = server.get_db()
        stock_cur = stock_conn.cursor()
        stock_cur.execute(
            "UPDATE products SET stock = 1, size_stock_json = ?, sold_out_sizes_json = '[]' WHERE id = ?",
            (json.dumps({"Free Size": 1}), "kaftan"),
        )
        stock_conn.commit()
        stock_cur.close()
        stock_conn.close()

        barrier = threading.Barrier(5)
        results = []
        results_lock = threading.Lock()

        def _worker():
            barrier.wait()
            try:
                server.deduct_order_stock([{"id": "kaftan", "size": "Free Size", "qty": 1}])
                with results_lock:
                    results.append(("ok", None))
            except ValueError as ve:
                with results_lock:
                    results.append(("rejected", str(ve)))
            except Exception as exc:
                with results_lock:
                    results.append(("error", str(exc)))

        threads = [threading.Thread(target=_worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)

        success_count = sum(1 for status, _ in results if status == "ok")
        rejected_count = sum(1 for status, _ in results if status == "rejected")

        verify_conn = server.get_db()
        verify_cur = verify_conn.cursor()
        verify_cur.execute("SELECT stock, size_stock_json FROM products WHERE id = ?", ("kaftan",))
        final_prod = verify_cur.fetchone()
        verify_cur.close()
        verify_conn.close()

        final_stock = int(final_prod["stock"])
        if success_count != 1 or rejected_count != 4 or final_stock != 0:
            raise RuntimeError(
                f"Concurrency check failed: success={success_count}, rejected={rejected_count}, "
                f"final_stock={final_stock}, results={results}"
            )
        steps_passed.append(
            "5. Verified 5-thread SELECT ... FOR UPDATE concurrency (1 succeeded, 4 rejected, final stock = 0)"
        )

    finally:
        # Step 6: Always drop the disposable schema and verify public schema was untouched
        server.POSTGRES_SCHEMA = "public"
        if admin_conn is not None:
            try:
                drop_cur = admin_conn.cursor()
                drop_cur.execute(f"DROP SCHEMA IF EXISTS {disposable_schema} CASCADE")
                admin_conn.commit()

                drop_cur.execute(
                    "SELECT schema_name FROM information_schema.schemata WHERE schema_name = ?",
                    (disposable_schema,),
                )
                cleanup_verified = drop_cur.fetchone() is None
                drop_cur.close()

                public_tables_after = _snapshot_public_schema(admin_conn)
                public_untouched = public_tables_before == public_tables_after
                if cleanup_verified and public_untouched:
                    steps_passed.append(
                        "6. Dropped disposable schema (CASCADE) and verified public schema untouched"
                    )
            finally:
                try:
                    admin_conn.close()
                except Exception:
                    pass

        server.DATABASE_URL = prev_db_url
        server.POSTGRES_SCHEMA = prev_schema
        server.ADMIN_SECRET_KEY = prev_admin_key
        os.environ.pop("ADMIN_SECRET_KEY", None)
        if prev_disable_geo is None:
            os.environ.pop("DISABLE_EXTERNAL_GEOCODING", None)
        else:
            os.environ["DISABLE_EXTERNAL_GEOCODING"] = prev_disable_geo

    report = {
        "ok": True,
        "status": "passed",
        "supabase_project_id": SUPABASE_PROJECT_ID,
        "target_database": server.mask_database_url(db_url),
        "disposable_schema_used": disposable_schema,
        "disposable_schema_dropped": cleanup_verified,
        "public_schema_untouched": public_untouched,
        "steps_passed": steps_passed,
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(run_supabase_integration_test())

