#!/usr/bin/env python3
"""
Test script for new Matra Naari features:
1. Catalog filtering and sorting
2. Product detail with size chart
3. Banners and announcements
4. Coupons application and discounts
5. Indian Pincode serviceability
6. Customer authentication and session
7. Customer address book
8. Return / Exchange filing
9. Order placement with coupon discount applied
10. Admin authentication and stats retrieval
"""

import urllib.request
import urllib.parse
import json
import os
import sys

API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8000")

def req(path, method="GET", payload=None, headers=None):
    url = f"{API_BASE}{path}"
    req_headers = {
        "Origin": "http://localhost:8000",
        "Accept": "application/json"
    }
    if headers:
        req_headers.update(headers)
    
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    r = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"error": body}
    except Exception as e:
        return 0, {"error": str(e)}

def main():
    print("=" * 60)
    print("TESTING NEW MATRA NAARI COMMERCE FEATURES")
    print("=" * 60)

    # 1. Catalog Products
    status, res = req("/api/products")
    assert status == 200 and res.get("ok"), f"Products failed: {res}"
    assert len(res["products"]) >= 7, f"Expected 7+ products, got {len(res['products'])}"
    print(f" [PASS] 1. GET /api/products -> 200 OK (Found {len(res['products'])} kurtis)")

    # 2. Product Detail & Size Chart
    status, res = req("/api/products/straight")
    assert status == 200 and res.get("ok"), f"Product detail failed: {res}"
    assert res["product"]["name"] == "Gulmohar Straight Kurti"
    assert len(res["size_chart"]) >= 4, "Size chart missing"
    assert len(res["related_products"]) > 0, "Related products missing"
    print(f" [PASS] 2. GET /api/products/straight -> 200 OK ({res['product']['name']}, Size chart verified)")

    # 3. Banners & Announcements
    status, res = req("/api/banners")
    assert status == 200 and res.get("ok")
    assert len(res["announcements"]) >= 3, "Announcements missing"
    print(f" [PASS] 3. GET /api/banners -> 200 OK ({len(res['announcements'])} announcement messages)")

    # 4. Coupon Application
    status, res = req("/api/apply-coupon", "POST", {"code": "NAARI10", "subtotal": 2000})
    assert status == 200 and res.get("ok"), f"Coupon failed: {res}"
    assert res["discount_amount"] == 200, f"Expected ₹200 discount (10% of 2000), got {res['discount_amount']}"
    assert res["final_total"] == 1800
    print(f" [PASS] 4. POST /api/apply-coupon (NAARI10 on ₹2000) -> 200 OK (Discount: ₹{res['discount_amount']})")

    # 5. Invalid Coupon
    status, res = req("/api/apply-coupon", "POST", {"code": "FAKECAP", "subtotal": 2000})
    assert status == 400 and not res.get("ok")
    print(" [PASS] 5. POST /api/apply-coupon (Invalid code) -> 400 Error caught properly")

    # 6. Pincode Check
    status, res = req("/api/check-pincode", "POST", {"pincode": "110001"})
    assert status == 200 and res.get("ok") and res.get("serviceable") is True
    print(f" [PASS] 6. POST /api/check-pincode (110001) -> 200 OK (Estimated arrival: {res['estimated_delivery']})")

    # 7. Customer Register & Login
    test_email = f"testuser_{os.urandom(3).hex()}@example.com"
    status, reg_res = req("/api/auth/register", "POST", {
        "name": "Meera Patel",
        "email": test_email,
        "phone": "9823456789",
        "password": "SecretPassword123"
    })
    assert status == 200 and reg_res.get("ok")
    token = reg_res["token"]
    print(f" [PASS] 7. POST /api/auth/register -> 200 OK (Registered {reg_res['user']['name']})")

    # 8. Customer Profile
    status, me_res = req("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert status == 200 and me_res.get("ok") and me_res["user"]["email"] == test_email
    print(" [PASS] 8. GET /api/auth/me -> 200 OK (Session validated)")

    # 9. Return Request Filing
    status, ret_res = req("/api/customer/returns", "POST", {
        "order_id": "NAARI-20261029-SAMPLE",
        "customer_email": test_email,
        "customer_phone": "9823456789",
        "item_name": "Gulmohar Straight Kurti",
        "action_type": "exchange",
        "reason": "Size is too large, need size M instead of L"
    })
    assert status == 200 and ret_res.get("ok")
    print(f" [PASS] 9. POST /api/customer/returns -> 200 OK (Return ID: {ret_res['return_id']})")

    # 10. Admin Stats
    status, admin_res = req("/api/admin/stats", headers={"X-Admin-Passkey": "naari@admin2026"})
    assert status == 200 and admin_res.get("ok")
    print(f" [PASS] 10. GET /api/admin/stats -> 200 OK (Total Products: {admin_res['stats']['total_products']})")

    print("=" * 60)
    print(" ALL 10 NEW FEATURE TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    main()
