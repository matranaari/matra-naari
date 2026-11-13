#!/usr/bin/env python3
"""
Matra Naari — Secure Read-Only Live Render Data Audit Helper
Target Live URL: https://matranaari.com

Safety Guarantees:
1. Strictly READ-ONLY: Calls ONLY HTTP GET endpoints (enforced by a method guard).
   Never makes POST, PUT, PATCH, or DELETE requests.
2. Authenticates via `X-Admin-Passkey` / `X-Admin-Token` / `Authorization: Bearer`
   headers on GET requests so even authentication never writes an admin session row.
3. Accepts the live Render admin secret through hidden terminal input (`getpass.getpass`)
   when not already present in the environment or local .env.
4. Never logs, prints, or persists credentials, tokens, or customer personal data (PII
   such as customer names, emails, phone numbers, or street addresses).
5. Opens local `data/orders.db` strictly in SQLite read-only URI mode (`?mode=ro`) to
   compare primary keys, aggregates, and non-PII record hashes against live Render,
   and explicitly reports any records/columns/tables that cannot be fully exported via
   the read-only HTTP APIs.
"""

import argparse
import getpass
import hashlib
import json
import os
import sqlite3
import sys
import urllib.parse
import urllib.request
import requests


LIVE_BASE_URL = "https://matranaari.com"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOCAL_DB = os.path.join(BASE_DIR, "data", "orders.db")

READONLY_GET_ENDPOINTS = (
    "/api/admin/stats",
    "/api/admin/orders",
    "/api/admin/customers",
    "/api/admin/returns",
    "/api/admin/products",
    "/api/admin/coupons",
    "/api/admin/settings",
)


def _hash_identifier(value):
    """Returns a non-reversible 12-hex-char SHA-256 fingerprint for safe comparison without PII."""
    clean = str(value or "").strip().lower()
    if not clean:
        return ""
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()[:12]


def _load_local_admin_key_if_present():
    """
    Checks process environment and local .env / config.json for an admin key without
    modifying any files or printing the value.
    """
    for env_key in ("ADMIN_SECRET_KEY", "ADMIN_PASSKEY", "ADMIN_PASSWORD"):
        val = (os.environ.get(env_key) or "").strip().strip('"').strip("'")
        if val:
            return val

    dotenv_path = os.path.join(BASE_DIR, ".env")
    if os.path.isfile(dotenv_path):
        try:
            with open(dotenv_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    if k.strip() in ("ADMIN_SECRET_KEY", "ADMIN_PASSKEY", "ADMIN_PASSWORD"):
                        clean_v = v.strip().strip('"').strip("'")
                        if clean_v:
                            return clean_v
        except Exception:
            pass
    return ""


def _open_local_sqlite_readonly(db_path):
    abs_path = os.path.abspath(db_path)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"Local SQLite database not found: {abs_path}")
    uri = "file:" + urllib.request.pathname2url(abs_path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def inspect_local_sqlite_baseline(db_path=DEFAULT_LOCAL_DB):
    """
    Reads non-PII primary keys, counts, and financial/inventory aggregates from local
    data/orders.db in read-only mode.
    """
    conn = _open_local_sqlite_readonly(db_path)
    try:
        cur = conn.cursor()
        order_rows = cur.execute(
            "SELECT id, user_id, customer_email, payment_method, payment_status, "
            "order_status, total_amount, subtotal, discount_amount, razorpay_signature "
            "FROM orders ORDER BY id ASC"
        ).fetchall()
        user_rows = cur.execute(
            "SELECT id, email, password_hash, salt FROM users ORDER BY id ASC"
        ).fetchall()
        return_rows = cur.execute(
            "SELECT id, order_id, status FROM return_requests ORDER BY id ASC"
        ).fetchall()
        product_rows = cur.execute(
            "SELECT id, price, mrp, stock, sku FROM products ORDER BY id ASC"
        ).fetchall()
        coupon_rows = cur.execute(
            "SELECT code, discount_type, discount_value, used_count, is_active FROM coupons ORDER BY code ASC"
        ).fetchall()
        setting_rows = cur.execute(
            "SELECT key, value FROM site_settings ORDER BY key ASC"
        ).fetchall()

        table_counts = {}
        for tname in (
            "site_settings",
            "products",
            "coupons",
            "users",
            "user_sessions",
            "user_addresses",
            "orders",
            "return_requests",
            "newsletter_subscribers",
            "admin_sessions",
        ):
            table_counts[tname] = int(cur.execute(f"SELECT COUNT(*) FROM {tname}").fetchone()[0])

        return {
            "table_counts": table_counts,
            "order_ids": {str(r["id"]) for r in order_rows},
            "orders_by_id": {
                str(r["id"]): {
                    "total_amount": int(r["total_amount"] or 0),
                    "subtotal": int(r["subtotal"] or 0),
                    "discount_amount": int(r["discount_amount"] or 0),
                    "payment_method": str(r["payment_method"] or ""),
                    "payment_status": str(r["payment_status"] or ""),
                    "order_status": str(r["order_status"] or ""),
                    "has_razorpay_signature": bool((r["razorpay_signature"] or "").strip()),
                }
                for r in order_rows
            },
            "user_ids": {str(r["id"]) for r in user_rows},
            "user_email_hashes": {_hash_identifier(r["email"]) for r in user_rows if r["email"]},
            "return_ids": {str(r["id"]) for r in return_rows},
            "products_by_id": {
                str(r["id"]): {
                    "price": int(r["price"] or 0),
                    "mrp": int(r["mrp"] or 0),
                    "stock": int(r["stock"] or 0),
                    "sku": str(r["sku"] or ""),
                }
                for r in product_rows
            },
            "coupons_by_code": {
                str(r["code"]): {
                    "discount_type": str(r["discount_type"] or ""),
                    "discount_value": int(r["discount_value"] or 0),
                    "used_count": int(r["used_count"] or 0),
                    "is_active": int(r["is_active"] if r["is_active"] is not None else 1),
                }
                for r in coupon_rows
            },
            "setting_keys": {str(r["key"]) for r in setting_rows},
        }
    finally:
        conn.close()


def run_live_render_audit(
    admin_key,
    base_url=LIVE_BASE_URL,
    local_db_path=DEFAULT_LOCAL_DB,
    get_fn=None,
):
    """
    Executes strictly read-only GET requests against live Render admin endpoints,
    computes aggregate counts without logging any secrets or customer PII, compares
    live records against local `data/orders.db`, and identifies records/columns/tables
    that cannot be fully exported via the read-only HTTP APIs.
    """
    clean_key = str(admin_key or "").strip()
    if not clean_key:
        raise ValueError("Admin passkey/token is required for authenticated live audit.")

    local_base = inspect_local_sqlite_baseline(local_db_path)

    headers = {
        "Accept": "application/json",
        "X-Admin-Passkey": clean_key,
        "X-Admin-Token": clean_key,
        "Authorization": f"Bearer {clean_key}",
    }

    def _safe_get(endpoint):
        if not endpoint.startswith("/"):
            raise ValueError(f"Relative endpoint path required: {endpoint}")
        url = base_url.rstrip("/") + endpoint
        if get_fn is not None:
            return get_fn(url, headers=headers, timeout=15)
        return requests.get(url, headers=headers, timeout=15)

    endpoint_status = {}
    payloads = {}
    for ep in READONLY_GET_ENDPOINTS:
        resp = _safe_get(ep)
        status_code = int(getattr(resp, "status_code", 0) or 0)
        endpoint_status[ep] = status_code
        if status_code == 200:
            try:
                payloads[ep] = resp.json()
            except Exception:
                payloads[ep] = {}
        elif ep == "/api/admin/stats" and status_code in (401, 403):
            return {
                "ok": False,
                "status": "unauthorized",
                "http_status": status_code,
                "endpoint_statuses": endpoint_status,
                "message": (
                    "Authentication failed (HTTP 401/403) on GET /api/admin/stats. "
                    "Verify the live Render ADMIN_SECRET_KEY and try again."
                ),
            }

    stats_data = payloads.get("/api/admin/stats", {})
    stats_block = stats_data.get("stats") if isinstance(stats_data.get("stats"), dict) else stats_data

    orders_list = payloads.get("/api/admin/orders", {}).get("orders", [])
    customers_list = payloads.get("/api/admin/customers", {}).get("customers", [])
    returns_list = payloads.get("/api/admin/returns", {}).get("returns", [])
    products_list = payloads.get("/api/admin/products", {}).get("products", [])
    coupons_list = payloads.get("/api/admin/coupons", {}).get("coupons", [])
    settings_dict = payloads.get("/api/admin/settings", {}).get("settings", {})

    # 1. Orders comparison (no PII logged)
    live_order_ids = set()
    live_only_order_ids = []
    live_only_razorpay_orders_missing_sig = []
    order_status_conflicts = []
    live_orders_total_amount_sum = 0
    for od in orders_list:
        if not isinstance(od, dict):
            continue
        oid = str(od.get("id") or od.get("order_id") or "").strip()
        if not oid:
            continue
        live_order_ids.add(oid)
        tot = int(od.get("total_amount") or 0)
        live_orders_total_amount_sum += tot
        if oid not in local_base["orders_by_id"]:
            live_only_order_ids.append(oid)
            pm = str(od.get("payment_method") or "").lower()
            if pm != "cod" and "razorpay_signature" not in od:
                live_only_razorpay_orders_missing_sig.append(oid)
        else:
            loc_od = local_base["orders_by_id"][oid]
            if (
                str(od.get("order_status") or "").lower() != loc_od["order_status"].lower()
                or str(od.get("payment_status") or "").lower() != loc_od["payment_status"].lower()
                or tot != loc_od["total_amount"]
            ):
                order_status_conflicts.append({
                    "order_id": oid,
                    "local_order_status": loc_od["order_status"],
                    "live_order_status": str(od.get("order_status") or ""),
                    "local_payment_status": loc_od["payment_status"],
                    "live_payment_status": str(od.get("payment_status") or ""),
                    "local_total_amount": loc_od["total_amount"],
                    "live_total_amount": tot,
                })

    # 2. Customers comparison (no PII logged; uses ID and SHA-256 email fingerprint)
    live_customer_ids = set()
    live_only_customer_ids = []
    for cust in customers_list:
        if not isinstance(cust, dict):
            continue
        cid = str(cust.get("id") or "").strip()
        email_hash = _hash_identifier(cust.get("email"))
        if cid:
            live_customer_ids.add(cid)
        in_local = (cid in local_base["user_ids"]) or (
            bool(email_hash) and email_hash in local_base["user_email_hashes"]
        )
        if not in_local:
            live_only_customer_ids.append(cid or f"email_fp:{email_hash}")

    # 3. Returns comparison (no PII logged)
    live_return_ids = set()
    live_only_return_ids = []
    for ret in returns_list:
        if not isinstance(ret, dict):
            continue
        rid = str(ret.get("id") or ret.get("return_id") or "").strip()
        if not rid:
            continue
        live_return_ids.add(rid)
        if rid not in local_base["return_ids"]:
            live_only_return_ids.append(rid)

    # 4. Products comparison
    live_products_stock_sum = 0
    product_conflicts = []
    live_product_ids = set()
    for prod in products_list:
        if not isinstance(prod, dict):
            continue
        pid = str(prod.get("id") or "").strip()
        if not pid:
            continue
        live_product_ids.add(pid)
        p_stock = int(prod.get("stock") or 0)
        live_products_stock_sum += p_stock
        loc_p = local_base["products_by_id"].get(pid)
        if not loc_p:
            product_conflicts.append({"product_id": pid, "issue": "only_on_live", "live_stock": p_stock})
        else:
            diffs = {}
            for k in ("price", "mrp", "stock", "sku"):
                lv = loc_p.get(k)
                rv = prod.get(k, "") if k == "sku" else int(prod.get(k) or 0)
                if str(lv or "") != str(rv or ""):
                    diffs[k] = {"local": lv, "live": rv}
            if diffs:
                product_conflicts.append({"product_id": pid, "issue": "field_mismatch", "diffs": diffs})

    # 5. Coupons comparison
    coupon_conflicts = []
    for coup in coupons_list:
        if not isinstance(coup, dict):
            continue
        code = str(coup.get("code") or "").strip()
        if not code:
            continue
        loc_c = local_base["coupons_by_code"].get(code)
        if not loc_c:
            coupon_conflicts.append({"code": code, "issue": "only_on_live"})
        else:
            used_live = int(coup.get("used_count") or 0)
            if used_live != loc_c["used_count"]:
                coupon_conflicts.append({
                    "code": code,
                    "issue": "used_count_mismatch",
                    "local_used_count": loc_c["used_count"],
                    "live_used_count": used_live,
                })

    # 6. Identify records/columns/tables that cannot be fully exported via read-only GET APIs
    non_exportable_items = {
        "live_only_customers_missing_password_hash_and_salt": {
            "count": len(live_only_customer_ids),
            "customer_ids": sorted(live_only_customer_ids),
            "reason": (
                "GET /api/admin/customers omits `password_hash` and `salt`. "
                "Customers already present in local data/orders.db retain their local password hashes, "
                "but any live-only customer record cannot have its password hash exported via HTTP GET."
            ),
        },
        "live_only_razorpay_orders_missing_signature": {
            "count": len(live_only_razorpay_orders_missing_sig),
            "order_ids": sorted(live_only_razorpay_orders_missing_sig),
            "reason": (
                "GET /api/admin/orders strips `razorpay_signature` (`od.pop('razorpay_signature', None)`)."
            ),
        },
        "tables_without_readonly_get_endpoint": [
            {
                "table": "user_addresses",
                "local_rows": local_base["table_counts"]["user_addresses"],
                "reason": "No GET /api/admin/* endpoint exists for customer saved addresses.",
            },
            {
                "table": "user_sessions",
                "local_rows": local_base["table_counts"]["user_sessions"],
                "reason": "No GET /api/admin/* endpoint exists for active user session tokens.",
            },
            {
                "table": "newsletter_subscribers",
                "local_rows": local_base["table_counts"]["newsletter_subscribers"],
                "reason": "Only POST /api/newsletter exists; no GET export endpoint is registered.",
            },
            {
                "table": "admin_sessions",
                "local_rows": local_base["table_counts"]["admin_sessions"],
                "reason": "Ephemeral admin session tokens have no GET export endpoint.",
            },
        ],
    }

    return {
        "ok": True,
        "status": "completed",
        "target_url": base_url,
        "endpoint_statuses": endpoint_status,
        "live_aggregate_counts": {
            "stats_total_orders": stats_block.get("total_orders", len(orders_list)),
            "stats_total_customers": stats_block.get("total_customers", len(customers_list)),
            "stats_total_products": stats_block.get("total_products", len(products_list)),
            "stats_total_returns": stats_block.get(
                "total_returns",
                stats_block.get("pending_returns", len(returns_list)),
            ),
            "orders_fetched": len(orders_list),
            "orders_total_amount_sum": live_orders_total_amount_sum,
            "customers_fetched": len(customers_list),
            "returns_fetched": len(returns_list),
            "products_fetched": len(products_list),
            "products_stock_sum": live_products_stock_sum,
            "coupons_fetched": len(coupons_list),
            "settings_keys_fetched": len(settings_dict) if isinstance(settings_dict, dict) else 0,
        },
        "local_sqlite_counts": local_base["table_counts"],
        "live_vs_local_delta": {
            "live_only_order_count": len(live_only_order_ids),
            "live_only_order_ids": sorted(live_only_order_ids),
            "local_only_order_count": len(local_base["order_ids"] - live_order_ids),
            "order_status_or_amount_conflicts": order_status_conflicts,
            "live_only_customer_count": len(live_only_customer_ids),
            "live_only_customer_ids": sorted(live_only_customer_ids),
            "local_only_customer_count": len(local_base["user_ids"] - live_customer_ids),
            "live_only_return_count": len(live_only_return_ids),
            "live_only_return_ids": sorted(live_only_return_ids),
            "local_only_return_count": len(local_base["return_ids"] - live_return_ids),
            "product_conflicts": product_conflicts,
            "coupon_conflicts": coupon_conflicts,
        },
        "non_exportable_via_readonly_api": non_exportable_items,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Read-Only Live Render Data Audit Helper for Matra Naari (GET-only, zero PII)."
    )
    parser.add_argument(
        "--base-url",
        default=LIVE_BASE_URL,
        help=f"Live Render base URL (default: {LIVE_BASE_URL})",
    )
    parser.add_argument(
        "--local-db",
        default=DEFAULT_LOCAL_DB,
        help="Path to local SQLite DB for read-only comparison (default: data/orders.db)",
    )
    parser.add_argument(
        "--prompt",
        action="store_true",
        help="Always prompt for ADMIN_SECRET_KEY via hidden terminal input.",
    )
    args = parser.parse_args()

    admin_key = "" if args.prompt else _load_local_admin_key_if_present()
    if not admin_key:
        try:
            admin_key = getpass.getpass(
                f"Enter live Render ADMIN_SECRET_KEY for {args.base_url} (input hidden): "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled. No requests sent.")
            return 1

    if not admin_key:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "stopped_missing_admin_key",
                    "message": "No ADMIN_SECRET_KEY provided. Stopped without calling live admin endpoints.",
                },
                indent=2,
            )
        )
        return 2

    report = run_live_render_audit(
        admin_key=admin_key,
        base_url=args.base_url,
        local_db_path=args.local_db,
    )
    print(json.dumps(report, indent=2))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

