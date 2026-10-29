#!/usr/bin/env python3
"""
Test suite for Matra Naari Staff Admin Portal APIs.
Verifies administrative passkey security, KPI metrics, order fulfillment,
coupons management, product catalog management, and store settings.
"""

import urllib.request
import urllib.error
import json
import sys

BASE_URL = "http://127.0.0.1:8000"
ADMIN_PASSKEY = "naari@admin2026"

def make_req(path, method="GET", data=None, passkey=ADMIN_PASSKEY):
    headers = {"Content-Type": "application/json"}
    if passkey:
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

    # 1. Invalid Passkey Verification
    total += 1
    code, res = make_req("/api/admin/verify", method="POST", data={"passkey": "wrong_key"}, passkey="wrong_key")
    if code == 401 and not res.get("ok"):
        print("✓ Test 1 Passed: Unauthorized access correctly rejected with 401")
        passed += 1
    else:
        print(f"✗ Test 1 Failed: {code} {res}")

    # 2. Valid Passkey Verification
    total += 1
    code, res = make_req("/api/admin/verify", method="POST", data={"passkey": ADMIN_PASSKEY})
    if code == 200 and res.get("ok"):
        print("✓ Test 2 Passed: Admin passkey verified successfully")
        passed += 1
    else:
        print(f"✗ Test 2 Failed: {code} {res}")

    # 3. Admin KPI Stats
    total += 1
    code, res = make_req("/api/admin/stats")
    if code == 200 and res.get("ok") and "stats" in res:
        stats = res["stats"]
        print(f"✓ Test 3 Passed: KPI Stats retrieved (Orders: {stats.get('total_orders')}, Kurtis: {stats.get('total_products')})")
        passed += 1
    else:
        print(f"✗ Test 3 Failed: {code} {res}")

    # 4. Fetch All Orders
    total += 1
    code, res = make_req("/api/admin/orders")
    if code == 200 and res.get("ok") and isinstance(res.get("orders"), list):
        orders = res["orders"]
        print(f"✓ Test 4 Passed: Admin orders list retrieved ({len(orders)} orders found)")
        passed += 1
    else:
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

    # 7. Create New Promo Coupon
    total += 1
    code, res = make_req("/api/admin/coupons", method="POST", data={
        "code": "ROYAL25",
        "discount_type": "percentage",
        "discount_value": 25,
        "min_order_value": 1999,
        "max_discount": 750,
        "expiry_date": "2028-12-31",
        "description": "Royal Festive 25% Off"
    })
    if code == 200 and res.get("ok"):
        print("✓ Test 7 Passed: Promotional coupon 'ROYAL25' created and saved")
        passed += 1
    else:
        print(f"✗ Test 7 Failed: {code} {res}")

    # 8. Toggle Coupon Status
    total += 1
    code, res = make_req("/api/admin/coupons/toggle", method="POST", data={"code": "ROYAL25"})
    if code == 200 and res.get("ok"):
        print("✓ Test 8 Passed: Coupon status toggled successfully")
        passed += 1
    else:
        print(f"✗ Test 8 Failed: {code} {res}")

    # 9. Admin Product Catalog Edit
    total += 1
    code, res = make_req("/api/admin/products", method="POST", data={
        "id": "straight",
        "name": "Gulmohar Straight Kurti",
        "category": "Straight Cut",
        "price": 1299,
        "mrp": 1899,
        "stock": 45,
        "image": "assets/hero.jpg",
        "relative_image": "assets/k-straight.jpg",
        "description": "Handloom cotton straight cut with side slits.",
        "is_bestseller": 1
    })
    if code == 200 and res.get("ok"):
        print("✓ Test 9 Passed: Product catalog entry updated (Straight Kurti price: 1299, stock: 45)")
        passed += 1
    else:
        print(f"✗ Test 9 Failed: {code} {res}")

    # 10. Store Settings Fetch & Update
    total += 1
    code, res = make_req("/api/admin/settings", method="POST", data={
        "announcement_text": "FREE EXPRESS SHIPPING ON ALL ORDERS · USE CODE: NAARI10 FOR 10% OFF",
        "free_shipping_threshold": 999,
        "cod_enabled": True
    })
    if code == 200 and res.get("ok") and "settings" in res:
        print("✓ Test 10 Passed: Storefront business settings updated and retrieved")
        passed += 1
    else:
        print(f"✗ Test 10 Failed: {code} {res}")

    print("==================================================")
    print(f"Summary: {passed}/{total} Admin Portal Tests Passed")
    print("==================================================")
    if passed == total:
        print("All Admin Management APIs are 100% OPERATIONAL!")
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(test_admin_flow())
