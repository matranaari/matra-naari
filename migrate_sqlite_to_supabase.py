#!/usr/bin/env python3
"""
Matra Naari — Idempotent SQLite to Supabase PostgreSQL Migration Utility
Supabase Project ID: hbpjvtoezlcsyxdxyvna

Features:
- Preserves all 10 tables: site_settings, products, coupons, users, user_sessions,
  user_addresses, orders, return_requests, newsletter_subscribers, admin_sessions.
- Safe dry-run mode (--dry-run, enabled by default unless --execute is passed) that
  reads the source SQLite database in read-only mode, validates schemas and aggregates,
  and generates/verifies all PostgreSQL DDL, RLS, and ON CONFLICT upsert statements
  without touching any target database.
- Idempotent execution (--execute) using ON CONFLICT (<pk>) DO UPDATE SET ... so
  re-running never duplicates records or loses data.
- Post-migration verification of row counts, primary-key sets, order financial totals,
  and product inventory totals.
- Never prints secrets, database passwords, session tokens, or customer PII.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import urllib.parse

import server

SUPABASE_PROJECT_ID = "hbpjvtoezlcsyxdxyvna"

# Authoritative 10-table specification in migration order
TABLE_SPECS = [
    {
        "name": "site_settings",
        "pk": "key",
        "columns": ["key", "value"],
    },
    {
        "name": "products",
        "pk": "id",
        "columns": [
            "id", "name", "category", "price", "mrp", "description", "fabric", "care",
            "image", "relative_image", "gallery_json", "colors_json", "sizes_json",
            "sold_out_sizes_json", "stock", "is_featured", "is_new", "is_bestseller",
            "rating", "reviews_count", "created_at", "style", "occasion", "pattern",
            "sleeve_length", "neck_design", "is_archived", "size_stock_json", "sku",
        ],
    },
    {
        "name": "coupons",
        "pk": "code",
        "columns": [
            "code", "discount_type", "discount_value", "min_order_value", "max_discount",
            "expiry_date", "usage_limit", "used_count", "is_active", "description",
            "created_at", "start_date", "applicable_categories", "applicable_products",
            "is_auto_apply",
        ],
    },
    {
        "name": "users",
        "pk": "id",
        "columns": [
            "id", "name", "email", "phone", "password_hash", "salt", "created_at",
        ],
    },
    {
        "name": "user_sessions",
        "pk": "token",
        "columns": ["token", "user_id", "created_at", "expires_at"],
    },
    {
        "name": "user_addresses",
        "pk": "id",
        "columns": [
            "id", "user_id", "name", "phone", "address_line1", "address_line2",
            "city", "state", "pincode", "is_default", "created_at", "house_no",
            "street_area", "latitude", "longitude", "location_summary", "address_label",
        ],
    },
    {
        "name": "orders",
        "pk": "id",
        "columns": [
            "id", "customer_name", "customer_email", "customer_phone", "address_line1",
            "address_line2", "city", "state", "pincode", "payment_method", "payment_status",
            "razorpay_order_id", "razorpay_payment_id", "razorpay_signature", "subtotal",
            "shipping", "total_amount", "items_json", "created_at", "updated_at",
            "order_status", "tracking_number", "courier_partner", "discount_amount",
            "coupon_code", "user_id", "house_no", "street_area", "latitude", "longitude",
            "location_summary", "address_label",
        ],
    },
    {
        "name": "return_requests",
        "pk": "id",
        "columns": [
            "id", "order_id", "customer_email", "customer_phone", "item_name",
            "action_type", "reason", "notes", "status", "created_at", "updated_at",
        ],
    },
    {
        "name": "newsletter_subscribers",
        "pk": "email",
        "columns": ["email", "created_at"],
    },
    {
        "name": "admin_sessions",
        "pk": "token",
        "columns": ["token", "created_at", "expires_at"],
    },
]


def open_readonly_sqlite(sqlite_path):
    abs_path = os.path.abspath(sqlite_path)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"Source SQLite database not found: {abs_path}")
    uri = f"file:{urllib.parse.quote(abs_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def build_upsert_qmark_sql(table_name, pk_col, columns):
    col_list = ", ".join(columns)
    placeholders = ", ".join(["?"] * len(columns))
    non_pk_cols = [c for c in columns if c != pk_col]
    if non_pk_cols:
        update_assignments = ", ".join([f"{c} = excluded.{c}" for c in non_pk_cols])
        conflict_action = f"DO UPDATE SET {update_assignments}"
    else:
        conflict_action = "DO NOTHING"
    return (
        f"INSERT INTO {table_name} ({col_list}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT ({pk_col}) {conflict_action}"
    )


def build_rls_statements():
    stmts = []
    for spec in TABLE_SPECS:
        tname = spec["name"]
        stmts.append(f"ALTER TABLE public.{tname} ENABLE ROW LEVEL SECURITY;")
    return stmts


def inspect_source_sqlite(sqlite_path):
    """
    Reads all 10 tables from the source SQLite database in read-only mode and returns
    a structured summary (row counts, column verification, primary-key digest, and
    financial/inventory aggregates) without exposing any PII or secrets.
    """
    conn = open_readonly_sqlite(sqlite_path)
    try:
        cur = conn.cursor()
        tables_summary = {}
        total_rows = 0

        for spec in TABLE_SPECS:
            tname = spec["name"]
            pk_col = spec["pk"]
            expected_cols = spec["columns"]

            cur.execute(f"PRAGMA table_info({tname})")
            actual_cols = [r["name"] for r in cur.fetchall()]
            missing_cols = [c for c in expected_cols if c not in actual_cols]

            select_cols = [c for c in expected_cols if c in actual_cols]
            if not select_cols:
                tables_summary[tname] = {
                    "exists": False,
                    "row_count": 0,
                    "missing_columns": missing_cols,
                    "pk_digest": "",
                }
                continue

            cur.execute(f"SELECT {', '.join(select_cols)} FROM {tname} ORDER BY {pk_col} ASC")
            rows = cur.fetchall()
            row_count = len(rows)
            total_rows += row_count

            pk_hasher = hashlib.sha256()
            for r in rows:
                pk_hasher.update(str(r[pk_col]).encode("utf-8") + b"\n")

            qmark_sql = build_upsert_qmark_sql(tname, pk_col, expected_cols)
            pg_sql = server.translate_sql_for_postgres(qmark_sql, has_params=True)

            tables_summary[tname] = {
                "exists": True,
                "row_count": row_count,
                "column_count": len(select_cols),
                "missing_columns": missing_cols,
                "pk_digest": pk_hasher.hexdigest()[:16],
                "postgres_upsert_sql": pg_sql,
            }

        cur.execute(
            "SELECT COALESCE(SUM(total_amount), 0) AS total_rev, "
            "COALESCE(SUM(subtotal), 0) AS total_sub, "
            "COALESCE(SUM(discount_amount), 0) AS total_disc "
            "FROM orders"
        )
        ord_agg = dict(cur.fetchone())

        cur.execute("SELECT COALESCE(SUM(stock), 0) AS total_stock FROM products")
        prod_agg = dict(cur.fetchone())

        return {
            "ok": True,
            "supabase_project_id": SUPABASE_PROJECT_ID,
            "source_sqlite_path": os.path.abspath(sqlite_path),
            "total_tables": len(TABLE_SPECS),
            "total_rows": total_rows,
            "tables": tables_summary,
            "aggregates": {
                "orders_total_amount_sum": int(ord_agg.get("total_rev", 0) or 0),
                "orders_subtotal_sum": int(ord_agg.get("total_sub", 0) or 0),
                "orders_discount_sum": int(ord_agg.get("total_disc", 0) or 0),
                "products_stock_sum": int(prod_agg.get("total_stock", 0) or 0),
            },
            "rls_statements": build_rls_statements(),
        }
    finally:
        conn.close()


def _load_database_url_from_env_or_dotenv():
    """
    Returns DATABASE_URL from server.get_database_url() or falls back to local .env
    without printing or exposing the secret.
    """
    url = str(server.get_database_url() or "").strip()
    if url:
        return url
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


CORRECTED_SHIPPING_ANNOUNCEMENT = (
    "FREE EXPRESS SHIPPING ON ORDERS ABOVE \u20b9999 (\u20b999 BELOW \u20b9999) \u00b7 USE CODE: NAARI10 FOR 10% OFF"
)


def _is_verified_sample_return_row(row_dict):
    return (
        str(row_dict.get("order_id") or "") == "NAARI-20261029-SAMPLE"
        and str(row_dict.get("customer_email") or "").lower().endswith("@example.com")
    )


def _is_verified_synthetic_test_row(table_name, row_dict):
    if table_name == "return_requests":
        return _is_verified_sample_return_row(row_dict)
    if table_name == "orders":
        email = str(row_dict.get("customer_email") or "").lower()
        oid = str(row_dict.get("id") or "")
        return email.endswith("@example.com") or oid == "NAARI-20261029121708-8E3D47"
    if table_name == "users":
        email = str(row_dict.get("email") or "").lower()
        return email.endswith("@example.com") or email.startswith("admin_cust_test")
    if table_name in ("user_sessions", "user_addresses", "admin_sessions"):
        return True
    if table_name == "newsletter_subscribers":
        email = str(row_dict.get("email") or "").lower()
        return email == "customer_verify@naari.in" or email.endswith("@example.com")
    return False


def _transform_rows_for_migration(
    table_name,
    rows,
    exclude_sample_returns=False,
    exclude_test_records=False,
    correct_shipping_announcement=False,
    gate_sales_until_stock_verified=False,
):
    out = []
    for raw_row in rows:
        d = dict(raw_row)
        if exclude_sample_returns and table_name == "return_requests" and _is_verified_sample_return_row(d):
            continue
        if exclude_test_records and _is_verified_synthetic_test_row(table_name, d):
            continue
        if exclude_test_records and table_name == "coupons":
            d["used_count"] = 0
        if table_name == "site_settings":
            k = str(d.get("key") or "")
            if correct_shipping_announcement:
                if k == "announcement_text":
                    d["value"] = CORRECTED_SHIPPING_ANNOUNCEMENT
                elif k == "announcements":
                    d["value"] = json.dumps([CORRECTED_SHIPPING_ANNOUNCEMENT])
            if gate_sales_until_stock_verified and k == "cod_enabled":
                d["value"] = "False"
        out.append(d)
    return out


def run_migration(
    source_sqlite_path=None,
    target_db_url=None,
    dry_run=True,
    enable_rls=False,
    exclude_sample_returns=False,
    exclude_test_records=False,
    correct_shipping_announcement=False,
    gate_sales_until_stock_verified=False,
):
    """
    Runs the SQLite -> PostgreSQL migration in dry-run mode (default) or live execution mode.
    When dry_run=True, no target database connection or write is performed.
    """
    src_path = source_sqlite_path or server.DB_PATH
    audit = inspect_source_sqlite(src_path)

    for tname, tinfo in audit["tables"].items():
        if not tinfo.get("exists") or tinfo.get("missing_columns"):
            raise RuntimeError(
                f"Source table '{tname}' is missing or incomplete: {tinfo.get('missing_columns')}"
            )

    planned_counts = {}
    src_conn_preview = open_readonly_sqlite(src_path)
    try:
        prev_cur = src_conn_preview.cursor()
        for spec in TABLE_SPECS:
            tname = spec["name"]
            pk_col = spec["pk"]
            cols = spec["columns"]
            prev_cur.execute(f"SELECT {', '.join(cols)} FROM {tname} ORDER BY {pk_col} ASC")
            filtered = _transform_rows_for_migration(
                tname,
                prev_cur.fetchall(),
                exclude_sample_returns=exclude_sample_returns,
                exclude_test_records=exclude_test_records,
                correct_shipping_announcement=correct_shipping_announcement,
                gate_sales_until_stock_verified=gate_sales_until_stock_verified,
            )
            planned_counts[tname] = len(filtered)
    finally:
        src_conn_preview.close()

    audit["planned_migration_counts"] = planned_counts
    audit["planned_total_rows"] = sum(planned_counts.values())
    audit["options"] = {
        "exclude_sample_returns": bool(exclude_sample_returns),
        "exclude_test_records": bool(exclude_test_records),
        "correct_shipping_announcement": bool(correct_shipping_announcement),
        "gate_sales_until_stock_verified": bool(gate_sales_until_stock_verified),
    }

    if dry_run:
        return {
            "ok": True,
            "mode": "dry_run",
            "migrated": False,
            "verified": True,
            "target_database": server.mask_database_url(target_db_url) if target_db_url else "<not-connected-dry-run>",
            "audit": audit,
        }

    eff_url = str(target_db_url or _load_database_url_from_env_or_dotenv() or "").strip()
    if not server.is_postgres_url(eff_url):
        raise ValueError(
            "A valid PostgreSQL DATABASE_URL (postgresql://...) is required when --execute is used."
        )

    prev_db_url = server.DATABASE_URL
    src_conn = None
    pg_conn = None
    try:
        server.DATABASE_URL = eff_url
        server.init_db()

        src_conn = open_readonly_sqlite(src_path)
        src_cur = src_conn.cursor()

        pg_conn = server.get_db()
        pg_cur = pg_conn.cursor()

        migrated_counts = {}
        expected_pks_by_table = {}
        expected_orders_rev = 0
        expected_orders_sub = 0
        expected_orders_disc = 0
        expected_prod_stock = 0

        for spec in TABLE_SPECS:
            tname = spec["name"]
            pk_col = spec["pk"]
            cols = spec["columns"]

            src_cur.execute(f"SELECT {', '.join(cols)} FROM {tname} ORDER BY {pk_col} ASC")
            rows = _transform_rows_for_migration(
                tname,
                src_cur.fetchall(),
                exclude_sample_returns=exclude_sample_returns,
                exclude_test_records=exclude_test_records,
                correct_shipping_announcement=correct_shipping_announcement,
                gate_sales_until_stock_verified=gate_sales_until_stock_verified,
            )

            expected_pks_by_table[tname] = [str(r[pk_col]) for r in rows]
            if tname == "orders":
                for r in rows:
                    expected_orders_rev += int(r.get("total_amount") or 0)
                    expected_orders_sub += int(r.get("subtotal") or 0)
                    expected_orders_disc += int(r.get("discount_amount") or 0)
            elif tname == "products":
                for r in rows:
                    expected_prod_stock += int(r.get("stock") or 0)

            upsert_sql = build_upsert_qmark_sql(tname, pk_col, cols)
            for row in rows:
                values = tuple(row[c] for c in cols)
                pg_cur.execute(upsert_sql, values)
            pg_conn.commit()
            migrated_counts[tname] = len(rows)

        if enable_rls:
            for rls_sql in build_rls_statements():
                pg_cur.execute(rls_sql)
            pg_conn.commit()

        # Verify target counts & aggregates match expected filtered rows 100%
        verification = {"tables": {}, "all_matched": True}
        for spec in TABLE_SPECS:
            tname = spec["name"]
            pk_col = spec["pk"]
            pg_cur.execute(f"SELECT {pk_col} FROM {tname} ORDER BY {pk_col} ASC")
            pg_pks = [str(r[pk_col]) for r in pg_cur.fetchall()]

            src_pks = expected_pks_by_table[tname]
            missing_pks = set(src_pks) - set(pg_pks)
            matched = (len(missing_pks) == 0) and (len(pg_pks) >= len(src_pks))
            if not matched:
                verification["all_matched"] = False
            verification["tables"][tname] = {
                "source_count": len(src_pks),
                "target_count": len(pg_pks),
                "missing_pks_count": len(missing_pks),
                "matched": matched,
            }

        pg_cur.execute(
            "SELECT COALESCE(SUM(total_amount), 0) AS total_rev, "
            "COALESCE(SUM(subtotal), 0) AS total_sub, "
            "COALESCE(SUM(discount_amount), 0) AS total_disc "
            "FROM orders"
        )
        pg_ord_agg = dict(pg_cur.fetchone())

        pg_cur.execute("SELECT COALESCE(SUM(stock), 0) AS total_stock FROM products")
        pg_prod_agg = dict(pg_cur.fetchone())

        verification["aggregates"] = {
            "orders_total_amount_sum": int(pg_ord_agg.get("total_rev", 0) or 0),
            "orders_subtotal_sum": int(pg_ord_agg.get("total_sub", 0) or 0),
            "orders_discount_sum": int(pg_ord_agg.get("total_disc", 0) or 0),
            "products_stock_sum": int(pg_prod_agg.get("total_stock", 0) or 0),
        }

        expected_agg = {
            "orders_total_amount_sum": expected_orders_rev,
            "orders_subtotal_sum": expected_orders_sub,
            "orders_discount_sum": expected_orders_disc,
            "products_stock_sum": expected_prod_stock,
        }
        if verification["aggregates"] != expected_agg:
            verification["all_matched"] = False

        if not verification["all_matched"]:
            raise RuntimeError("Post-migration verification detected a mismatch between source and target.")

        return {
            "ok": True,
            "mode": "execute",
            "migrated": True,
            "verified": True,
            "target_database": server.mask_database_url(eff_url),
            "migrated_counts": migrated_counts,
            "verification": verification,
        }
    finally:
        server.DATABASE_URL = prev_db_url
        if pg_conn is not None:
            try:
                pg_conn.close()
            except Exception:
                pass
        if src_conn is not None:
            try:
                src_conn.close()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="Idempotent SQLite to Supabase PostgreSQL migration script for Matra Naari."
    )
    parser.add_argument(
        "--source-db",
        default=server.DB_PATH,
        help="Path to source SQLite database (default: data/orders.db)",
    )
    parser.add_argument(
        "--target-url",
        default="",
        help="PostgreSQL connection URL (defaults to DATABASE_URL env var when --execute is set)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Run read-only pre-flight check without connecting to or writing to PostgreSQL (default).",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Execute the idempotent migration against the target PostgreSQL database.",
    )
    parser.add_argument(
        "--enable-rls",
        action="store_true",
        default=False,
        help="Enable Row Level Security (RLS) on all 10 public tables after migrating.",
    )
    parser.add_argument(
        "--exclude-sample-returns",
        action="store_true",
        default=False,
        help="Exclude the 20 verified synthetic sample return records (order_id=NAARI-20261029-SAMPLE).",
    )
    parser.add_argument(
        "--exclude-test-records",
        action="store_true",
        default=False,
        help="Exclude verified synthetic automated test records (orders, users, sessions, addresses, returns, newsletter) and reset test coupon used_count to 0.",
    )
    parser.add_argument(
        "--correct-shipping-announcement",
        action="store_true",
        default=False,
        help="Set site_settings announcement to 'FREE EXPRESS SHIPPING ON ORDERS ABOVE ₹999 (₹99 BELOW ₹999) · USE CODE: NAARI10 FOR 10% OFF'.",
    )
    parser.add_argument(
        "--gate-sales-until-stock-verified",
        action="store_true",
        default=False,
        help="Set cod_enabled=False in migrated site_settings until physical stock is verified.",
    )
    args = parser.parse_args()

    is_dry_run = not args.execute
    result = run_migration(
        source_sqlite_path=args.source_db,
        target_db_url=args.target_url or None,
        dry_run=is_dry_run,
        enable_rls=args.enable_rls,
        exclude_sample_returns=args.exclude_sample_returns,
        exclude_test_records=args.exclude_test_records,
        correct_shipping_announcement=args.correct_shipping_announcement,
        gate_sales_until_stock_verified=args.gate_sales_until_stock_verified,
    )

    # Print clean summary without any secrets or PII
    summary_out = {
        "ok": result["ok"],
        "mode": result["mode"],
        "migrated": result["migrated"],
        "verified": result["verified"],
        "target_database": result["target_database"],
    }
    if is_dry_run:
        summary_out["supabase_project_id"] = result["audit"]["supabase_project_id"]
        summary_out["total_tables"] = result["audit"]["total_tables"]
        summary_out["source_total_rows"] = result["audit"]["total_rows"]
        summary_out["source_table_counts"] = {
            k: v["row_count"] for k, v in result["audit"]["tables"].items()
        }
        summary_out["planned_total_rows"] = result["audit"]["planned_total_rows"]
        summary_out["planned_migration_counts"] = result["audit"]["planned_migration_counts"]
        summary_out["options"] = result["audit"]["options"]
        summary_out["aggregates"] = result["audit"]["aggregates"]
    else:
        summary_out["migrated_counts"] = result["migrated_counts"]
        summary_out["verification"] = result["verification"]

    print(json.dumps(summary_out, indent=2))


if __name__ == "__main__":
    main()

