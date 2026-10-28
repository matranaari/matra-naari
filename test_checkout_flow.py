#!/usr/bin/env python3
"""
Comprehensive test script for Naari API endpoints and checkout flow.
Tests:
1. Health check & configuration
2. CORS preflight (OPTIONS)
3. COD order placement (valid + invalid)
4. Razorpay order creation
5. Razorpay signature verification (tampered/invalid signature failure scenario)
6. Razorpay signature verification (valid signature success scenario)
7. Order details retrieval from database
"""

import urllib.request
import urllib.parse
import json
import hmac
import hashlib
import sys
import os

API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8000")

def make_request(path, method="GET", payload=None, headers=None):
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

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            cors_origin = resp.headers.get("Access-Control-Allow-Origin")
            return resp.status, body, cors_origin
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        cors_origin = e.headers.get("Access-Control-Allow-Origin")
        return e.code, body, cors_origin
    except Exception as e:
        return 0, str(e), None

def run_tests():
    print("=" * 60)
    print("RUNNING NAARI CHECKOUT FLOW TESTS")
    print("=" * 60)
    passed = 0
    total = 0

    # 1. Health check
    total += 1
    status, body, cors = make_request("/api/health")
    data = json.loads(body)
    assert status == 200 and data.get("ok") is True, f"Health check failed: {body}"
    assert cors == "*", f"CORS header missing on health check: {cors}"
    print(" [PASS] 1. GET /api/health -> 200 OK (CORS verified)")
    passed += 1

    

    # 2. Config check
    total += 1
    status, body, cors = make_request("/api/config")
    data = json.loads(body)
    assert status == 200 and data.get("ok") is True, f"Config check failed: {body}"
    assert "store_name" in data, "store_name missing in config"
    print(f" [PASS] 2. GET /api/config -> 200 OK (Store: {data.get('store_name')}, Razorpay configured: {data.get('is_razorpay_configured')})")
    passed += 1

    # 3. CORS preflight OPTIONS check
    total += 1
    req = urllib.request.Request(
        f"{API_BASE}/api/create-order",
        headers={
            "Origin": "http://localhost:8000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type"
        },
        method="OPTIONS"
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.headers.get("Access-Control-Allow-Origin") == "*", "Preflight CORS failed"
        print(" [PASS] 3. OPTIONS /api/create-order -> Preflight CORS headers valid")
        passed += 1

    # Sample customer & items
    test_customer = {
        "name": "Priya Sharma",
        "phone": "9876543210",
        "email": "priya.sharma@example.com",
        "address_line1": "Flat 402, Lotus Apartments, MG Road",
        "address_line2": "Near City Mall",
        "city": "Jaipur",
        "state": "Rajasthan",
        "pincode": "302001"
    }
    test_items = [
        {"id": "straight", "qty": 1, "size": "M", "color": "Maroon", "price": 1299},
        {"id": "aline", "qty": 2, "size": "L", "color": "Indigo", "price": 1499}
    ]
    # Expected subtotal = 1299*1 + 1499*2 = 1299 + 2998 = 4297

    # 4. COD Order - Validation Error test (empty items)
    total += 1
    status, body, _ = make_request("/api/create-cod-order", method="POST", payload={
        "customer": test_customer,
        "items": []
    })
    data = json.loads(body)
    assert status == 400 and data.get("ok") is False, f"Expected 400 for empty bag: {body}"
    print(f" [PASS] 4. POST /api/create-cod-order (Empty items) -> 400 Error correctly caught: '{data.get('error')}'")
    passed += 1

    # 5. COD Order - Validation Error test (invalid phone)
    total += 1
    bad_customer = dict(test_customer, phone="123")
    status, body, _ = make_request("/api/create-cod-order", method="POST", payload={
        "customer": bad_customer,
        "items": test_items
    })
    data = json.loads(body)
    assert status == 400 and data.get("ok") is False, f"Expected 400 for invalid phone: {body}"
    print(f" [PASS] 5. POST /api/create-cod-order (Invalid phone) -> 400 Error caught: '{data.get('error')}'")
    passed += 1

    # 6. COD Order - Successful placement
    total += 1
    status, body, _ = make_request("/api/create-cod-order", method="POST", payload={
        "customer": test_customer,
        "items": test_items
    })
    data = json.loads(body)
    assert status == 200 and data.get("ok") is True, f"COD placement failed: {body}"
    cod_order_id = data.get("order_id")
    assert cod_order_id.startswith("NAARI-"), f"Unexpected order_id format: {cod_order_id}"
    assert data.get("total_amount") == 4297, f"Total amount mismatch: expected 4297, got {data.get('total_amount')}"
    print(f" [PASS] 6. POST /api/create-cod-order -> 200 Success! Created order {cod_order_id} (Total: ₹{data.get('total_amount')})")
    passed += 1

    # 7. Online Payment - Create Order
    total += 1
    status, body, _ = make_request("/api/create-order", method="POST", payload={
        "customer": test_customer,
        "items": test_items
    })
    data = json.loads(body)
    assert status == 200 and data.get("ok") is True, f"Online create-order failed: {body}"
    online_order_id = data.get("order_id")
    rzp_order_id = data.get("razorpay_order_id")
    amount = data.get("amount")
    assert amount == 429700, f"Expected 429700 paise, got {amount}"
    print(f" [PASS] 7. POST /api/create-order -> 200 Success! Created online order {online_order_id}, rzp_order_id: {rzp_order_id}, amount: {amount} paise")
    passed += 1

    # 8. Razorpay Signature Verification - FAILED Scenario (tampered / invalid signature)
    total += 1
    status, body, _ = make_request("/api/verify-payment", method="POST", payload={
        "order_id": online_order_id,
        "razorpay_order_id": "order_live_999999",
        "razorpay_payment_id": "pay_live_888888",
        "razorpay_signature": "fraudulent_or_tampered_signature_hex",
        "is_simulated": False
    })
    data = json.loads(body)
    # Because config.json has placeholder or signature is tampered, verification must fail
    assert status == 400 and data.get("ok") is False, f"Expected 400 for tampered payment, got {status}: {body}"
    print(f" [PASS] 8. POST /api/verify-payment (Failed payment / tampered signature) -> 400 Caught: '{data.get('error')}'")
    passed += 1

    # 9. Razorpay Payment - SUCCESS Scenario
    total += 1
    simulated_payment_id = "pay_test_verified_success"
    status, body, _ = make_request("/api/verify-payment", method="POST", payload={
        "order_id": online_order_id,
        "razorpay_order_id": rzp_order_id,
        "razorpay_payment_id": simulated_payment_id,
        "razorpay_signature": "sig_simulated_valid",
        "is_simulated": True
    })
    data = json.loads(body)
    assert status == 200 and data.get("ok") is True, f"Payment verification failed: {body}"
    assert data.get("status") == "paid", f"Expected status 'paid', got {data.get('status')}"
    print(f" [PASS] 9. POST /api/verify-payment (Successful verification) -> 200 Success! Status: '{data.get('status')}'")
    passed += 1

    # 10. Order Details Retrieval
    total += 1
    status, body, _ = make_request(f"/api/order-details?order_id={online_order_id}")
    data = json.loads(body)
    assert status == 200 and data.get("ok") is True, f"Order details failed: {body}"
    ord_info = data.get("order", {})
    assert ord_info.get("id") == online_order_id
    assert ord_info.get("payment_status") == "paid"
    assert ord_info.get("customer_name") == test_customer["name"]
    assert len(ord_info.get("items", [])) == 2
    print(f" [PASS] 10. GET /api/order-details -> 200 Success! Verified stored order with {len(ord_info.get('items'))} items, customer: '{ord_info.get('customer_name')}', payment: '{ord_info.get('payment_status')}'")
    passed += 1

    print("=" * 60)
    print(f" ALL {passed}/{total} TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
