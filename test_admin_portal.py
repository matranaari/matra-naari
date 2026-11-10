#!/usr/bin/env python3
"""
Test suite for Matra Naari Staff Admin Portal APIs.
Verifies administrative passkey & session token security, unauthorized access rejection,
KPI metrics (best-selling products, low-stock alerts, pending orders),
order filtering & fulfillment, Razorpay payment status protection,
product creation/editing with S/M/L/XL size-wise stock, negative stock prevention,
visibility archive/publish toggle, secure image upload, coupons management, and store settings.
"""

import urllib.request
import urllib.error
import json
import base64
import os
import sys

BASE_URL = "http://127.0.0.1:8000"
ADMIN_PASSKEY = "naari@admin2026"


def make_req(path, method="GET", data=None, passkey=ADMIN_PASSKEY, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Admin-Token"] = token
    elif passkey:
        headers["X-Admin-Passkey"] = passkey

    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            err_json = json.loads(e.read().decode("utf-8"))
            return e.code, err_json
        except Exception:
            return e.code, {"error": str(e)}


def test_admin_flow():
    print("==================================================")
    print("Testing Matra Naari Admin Portal & Management APIs")
    print("==================================================")
    passed = 0
    total = 0

    # 1. Invalid Passkey Verification & Unauthorized Access Rejection
    total += 1
    code, res = make_req("/api/admin/verify", method="POST", data={"passkey": "wrong_key"}, passkey="wrong_key")
    code_stats, _ = make_req("/api/admin/stats", passkey=None)
    code_cust_noauth, _ = make_req("/api/admin/customers", passkey=None)
    code_cust_badkey, _ = make_req("/api/admin/customers", passkey="wrong_key")
    code_inv, _ = make_req("/api/admin/inventory/update", method="POST", data={"id": "straight", "stock": 10}, passkey="wrong")
    code_upl, _ = make_req("/api/admin/upload-image", method="POST", data={"filename": "a.png", "data": "abc"}, passkey=None)
    if (
        code == 401
        and code_stats == 401
        and code_cust_noauth == 401
        and code_cust_badkey == 401
        and code_inv == 401
        and code_upl == 401
        and not res.get("ok")
    ):
        print("✓ Test 1 Passed: Unauthorized access rejected with 401 across all admin endpoints (including /api/admin/customers)")
        passed += 1
    else:
        print(f"✗ Test 1 Failed: verify={code}, stats={code_stats}, cust={code_cust_noauth}/{code_cust_badkey}, inv={code_inv}, upl={code_upl}")

    # 2. Valid Passkey Verification & Session Token Issuance
    total += 1
    code, res = make_req("/api/admin/verify", method="POST", data={"passkey": ADMIN_PASSKEY})
    session_token = res.get("token", "")
    if code == 200 and res.get("ok") and res.get("authenticated") and len(session_token) >= 32:
        print("✓ Test 2 Passed: Admin passkey verified & session token issued")
        passed += 1
    else:
        print(f"✗ Test 2 Failed: {code} {res}")

    # 3. Admin KPI Stats (using issued Session Token)
    total += 1
    code, res = make_req("/api/admin/stats", passkey=None, token=session_token)
    if (
        code == 200
        and res.get("ok")
        and "stats" in res
        and "best_selling_products" in res
        and "low_stock_alerts" in res
    ):
        stats = res["stats"]
        print(
            f"✓ Test 3 Passed: KPI Stats retrieved via session token "
            f"(Orders: {stats.get('total_orders')}, Pending: {stats.get('pending_orders')}, "
            f"Kurtis: {stats.get('total_products')}, LowStock: {stats.get('low_stock_count')})"
        )
        passed += 1
    else:
        print(f"✗ Test 3 Failed: {code} {res}")

    # 4. Fetch & Filter Admin Orders
    total += 1
    code, res = make_req("/api/admin/orders?payment_method=cod&date_from=2020-01-01&date_to=2030-12-31")
    if code == 200 and res.get("ok") and isinstance(res.get("orders"), list):
        orders = res["orders"]
        print(f"✓ Test 4 Passed: Admin orders retrieved & filtered ({len(orders)} orders found)")
        passed += 1
    else:
        orders = []
        print(f"✗ Test 4 Failed: {code} {res}")

    # 5. Update Fulfillment Status & Courier Tracking on an order
    total += 1
    test_order_id = orders[0]["order_id"] if orders else "NAARI-SAMPLE"
    code, res = make_req("/api/admin/orders/status", method="POST", data={
        "order_id": test_order_id,
        "order_status": "shipped",
        "courier_partner": "Delhivery Express",
        "tracking_number": "DLHVY123456789IN"
    })
    if code == 200 and res.get("ok"):
        print(f"✓ Test 5 Passed: Order fulfillment and tracking updated ({test_order_id} -> shipped)")
        passed += 1
    else:
        print(f"✗ Test 5 Failed: {code} {res}")

    # 6. Fetch Admin Coupons
    total += 1
    code, res = make_req("/api/admin/coupons")
    if code == 200 and res.get("ok") and isinstance(res.get("coupons"), list):
        print(f"✓ Test 6 Passed: Admin coupon list retrieved ({len(res['coupons'])} coupons)")
        passed += 1
    else:
        print(f"✗ Test 6 Failed: {code} {res}")

    # 7. Create New Promo Coupon with Applicable Products & Categories
    total += 1
    code, res = make_req("/api/admin/coupons", method="POST", data={
        "code": "ROYAL25",
        "discount_type": "percentage",
        "discount_value": 25,
        "min_order_value": 1999,
        "max_discount": 750,
        "usage_limit": 50,
        "applicable_categories": ["Straight Cut", "Anarkali"],
        "applicable_products": ["straight", "anarkali"],
        "expiry_date": "2028-12-31",
        "description": "Royal Festive 25% Off"
    })
    if code == 200 and res.get("ok"):
        print("✓ Test 7 Passed: Promotional coupon 'ROYAL25' created with category/product rules")
        passed += 1
    else:
        print(f"✗ Test 7 Failed: {code} {res}")

    # 8. Server-Side Coupon Validation & Toggle/Delete
    total += 1
    c_app, r_app = make_req("/api/apply-coupon", method="POST", data={
        "code": "ROYAL25",
        "items": [{"id": "straight", "qty": 2}]
    }, passkey=None)
    c_tog, r_tog = make_req("/api/admin/coupons/toggle", method="POST", data={"code": "ROYAL25"})
    c_del, r_del = make_req("/api/admin/coupons/ROYAL25", method="DELETE")
    if c_app == 200 and r_app.get("ok") and c_tog == 200 and c_del == 200:
        print(f"✓ Test 8 Passed: Coupon validated on server (discount ₹{r_app.get('discount_amount')}), toggled & cleaned up")
        passed += 1
    else:
        print(f"✗ Test 8 Failed: apply={c_app} {r_app}, toggle={c_tog}, del={c_del}")

    # 9. Admin Product Catalog Edit + Size-Wise Stock (S, M, L, XL)
    total += 1
    code, res = make_req("/api/admin/products", method="POST", data={
        "id": "straight",
        "sku": "MN-STRAIGHT-01",
        "name": "Gulmohar Straight Kurti",
        "category": "Straight Cut",
        "price": 1299,
        "mrp": 1899,
        "size_stock": {"S": 10, "M": 12, "L": 13, "XL": 10},
        "image": "assets/hero.jpg",
        "relative_image": "assets/k-straight.jpg",
        "description": "Handloom cotton straight cut with side slits.",
        "is_bestseller": 1
    })
    if code == 200 and res.get("ok") and res.get("stock") == 45 and res.get("size_stock", {}).get("M") == 12:
        print("✓ Test 9 Passed: Product catalog & S/M/L/XL stock updated (Total stock: 45)")
        passed += 1
    else:
        print(f"✗ Test 9 Failed: {code} {res}")

    # 10. Negative Stock Prevention & Size-Wise Inventory Endpoint
    total += 1
    c_neg1, _ = make_req("/api/admin/products", method="POST", data={
        "id": "straight",
        "name": "Gulmohar Straight Kurti",
        "price": 1299,
        "mrp": 1899,
        "size_stock": {"S": -5, "M": 10, "L": 10, "XL": 10}
    })
    c_neg2, _ = make_req("/api/admin/inventory/update", method="POST", data={
        "id": "straight",
        "size_stock": {"S": 5, "M": -1, "L": 5, "XL": 5}
    })
    c_inv_ok, r_inv_ok = make_req("/api/admin/inventory/update", method="POST", data={
        "id": "straight",
        "size_stock": {"S": 10, "M": 15, "L": 10, "XL": 10}
    })
    if c_neg1 == 400 and c_neg2 == 400 and c_inv_ok == 200 and r_inv_ok.get("stock") == 45:
        print("✓ Test 10 Passed: Negative stock rejected (400) & valid size-wise inventory saved")
        passed += 1
    else:
        print(f"✗ Test 10 Failed: neg1={c_neg1}, neg2={c_neg2}, inv_ok={c_inv_ok} {r_inv_ok}")

    # 11. Product Creation, Archive/Publish Visibility Toggle & Cleanup
    total += 1
    c_new, r_new = make_req("/api/admin/products", method="POST", data={
        "id": "test_admin_kurti",
        "sku": "MN-TEST-999",
        "name": "Test Admin Zari Kurti",
        "category": "Festive",
        "price": 1599,
        "mrp": 2199,
        "size_stock": {"S": 2, "M": 0, "L": 4, "XL": 1},
        "image": "assets/hero.jpg",
        "description": "Temporary test kurti for admin suite."
    })
    c_arch, r_arch = make_req("/api/admin/products/visibility", method="POST", data={
        "id": "test_admin_kurti",
        "is_archived": True
    })
    c_pub, r_pub = make_req("/api/admin/products/visibility", method="POST", data={
        "id": "test_admin_kurti",
        "is_archived": False
    })
    c_del_p, _ = make_req("/api/admin/products/test_admin_kurti", method="DELETE")
    if (
        c_new == 200 and r_new.get("stock") == 7
        and c_arch == 200 and r_arch.get("is_archived") == 1
        and c_pub == 200 and r_pub.get("is_archived") == 0
        and c_del_p == 200
    ):
        print("✓ Test 11 Passed: Product created, archived, published, and cleaned up")
        passed += 1
    else:
        print(f"✗ Test 11 Failed: new={c_new}, arch={c_arch}, pub={c_pub}, del={c_del_p}")

    # 12. Secure Product Image Upload (Valid PNG accepted, Fake/Executable rejected)
    total += 1
    # Minimal 1x1 transparent PNG
    tiny_png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    c_up_ok, r_up_ok = make_req("/api/admin/upload-image", method="POST", data={
        "filename": "test_kurti.png",
        "data_url": f"data:image/png;base64,{tiny_png_b64}"
    })
    c_up_bad, _ = make_req("/api/admin/upload-image", method="POST", data={
        "filename": "malicious.php",
        "data_url": base64.b64encode(b"<?php echo 1; ?>").decode("ascii")
    })
    uploaded_rel = r_up_ok.get("image_path", "")
    if uploaded_rel and os.path.isfile(uploaded_rel):
        try:
            os.remove(uploaded_rel)
        except Exception:
            pass
    if c_up_ok == 200 and uploaded_rel.startswith("assets/uploads/") and c_up_bad == 400:
        print("✓ Test 12 Passed: Valid product image uploaded & disguised file rejected (400)")
        passed += 1
    else:
        print(f"✗ Test 12 Failed: ok={c_up_ok} {r_up_ok}, bad={c_up_bad}")

    # 13. Store Settings Fetch & Update (Never Exposing Secrets)
    total += 1
    code, res = make_req("/api/admin/settings", method="POST", data={
        "announcement_text": "FREE EXPRESS SHIPPING ON ALL ORDERS · USE CODE: NAARI10 FOR 10% OFF",
        "free_shipping_threshold": 999,
        "shipping_fee": 99,
        "cod_enabled": True
    })
    settings_obj = res.get("settings", {})
    has_no_secrets = (
        "razorpay_key_secret" not in settings_obj
        and "admin_passkey_hash" not in settings_obj
    )
    if code == 200 and res.get("ok") and "settings" in res and has_no_secrets:
        print("✓ Test 13 Passed: Store settings updated and verified free of secret credentials")
        passed += 1
    else:
        print(f"✗ Test 13 Failed: {code} {res}")

    # 14. Customer Management Endpoint: Admin Authorization, Search, Secret Redaction & UI Wiring
    total += 1
    test_email = f"admin_cust_test_{os.urandom(3).hex()}@naari.in"
    reg_code, reg_res = make_req("/api/auth/register", method="POST", data={
        "name": "Aaradhya Verma",
        "email": test_email,
        "phone": "9812345670",
        "password": "SuperSecretPassword123!"
    }, passkey=None)
    cust_token = reg_res.get("token", "")

    # Verify customer token cannot access /api/admin/customers
    req_cust_try = urllib.request.Request(
        f"{BASE_URL}/api/admin/customers",
        headers={"Authorization": f"Bearer {cust_token}"}
    )
    try:
        with urllib.request.urlopen(req_cust_try) as resp:
            cust_auth_code = resp.status
    except urllib.error.HTTPError as e:
        cust_auth_code = e.code

    # Authorized admin fetch of all customers & filtered search
    c_cust_all, r_cust_all = make_req("/api/admin/customers", passkey=None, token=session_token)
    c_cust_search, r_cust_search = make_req(f"/api/admin/customers?search={test_email}", passkey=None, token=session_token)

    customers_list = r_cust_all.get("customers", [])
    search_list = r_cust_search.get("customers", [])
    matched_cust = next((c for c in search_list if c.get("email") == test_email), None)

    forbidden_fields = {"password", "password_hash", "salt", "token", "session_token"}
    leaked_fields = any(
        any(f in c for f in forbidden_fields)
        for c in customers_list
    )

    with open("admin.html", "r", encoding="utf-8") as af:
        admin_html = af.read()
    ui_wired = (
        'data-tab="customers"' in admin_html
        and 'id="tab-customers"' in admin_html
        and 'id="customer-search-input"' in admin_html
        and 'id="customers-total-count"' in admin_html
        and 'id="admin-customers-tbody"' in admin_html
        and 'fetch("/api/admin/customers"' in admin_html
    )

    if (
        reg_code == 200
        and cust_auth_code == 401
        and c_cust_all == 200
        and r_cust_all.get("ok")
        and r_cust_all.get("total_customers", 0) >= 1
        and c_cust_search == 200
        and matched_cust is not None
        and matched_cust.get("name") == "Aaradhya Verma"
        and matched_cust.get("phone") == "9812345670"
        and bool(matched_cust.get("created_at"))
        and not leaked_fields
        and ui_wired
    ):
        print(
            f"✓ Test 14 Passed: Customer Management verified "
            f"(Total Customers: {r_cust_all.get('total_customers')}, search & secret redaction verified)"
        )
        passed += 1
    else:
        print(
            f"✗ Test 14 Failed: reg={reg_code}, cust_auth={cust_auth_code}, "
            f"all={c_cust_all}, matched={matched_cust}, leaked={leaked_fields}, ui={ui_wired}"
        )

    print("==================================================")
    print(f"Summary: {passed}/{total} Admin Portal Tests Passed")
    print("==================================================")
    assert passed == total, f"Expected all {total} tests to pass, but only {passed} passed"
    print("All Admin Management APIs are 100% OPERATIONAL!")
    return None


if __name__ == "__main__":
    try:
        test_admin_flow()
        sys.exit(0)
    except AssertionError:
        sys.exit(1)
