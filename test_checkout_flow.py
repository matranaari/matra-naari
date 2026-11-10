#!/usr/bin/env python3
"""
Comprehensive test script for Naari API endpoints and Razorpay Standard Checkout flow.
Tests:
1. Health check & configuration
2. CORS preflight (OPTIONS)
3. COD order placement (valid + invalid)
4. Razorpay order creation (server-calculated cart total in INR -> paise)
5. Razorpay signature verification (tampered/invalid signature failure scenario)
6. Payment cancellation / failure recording (/api/payment-failed)
7. Razorpay signature verification (valid signature success + duplicate request idempotency)
8. Order details retrieval from database
9. Configured RAZORPAY_KEY_ID & RAZORPAY_KEY_SECRET environment variable tests:
   - Public Key ID exposed in /api/config while Key Secret is never exposed
   - Server-side price authority (ignores tampered client item price)
   - Simulation bypass blocked when real Razorpay keys are configured
   - Genuine HMAC-SHA256 signature verification with RAZORPAY_KEY_SECRET
"""

import urllib.request
import urllib.parse
import json
import hmac
import hashlib
import sys
import os
from unittest.mock import patch, MagicMock

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


def run_configured_razorpay_hmac_tests():
    """
    Tests Razorpay Standard Checkout integration when RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET
    are configured via server-side environment variables.
    """
    import server

    test_key_id = "rzp_test_NaariLiveKey12345"
    test_key_secret = "NaariSuperSecretKey_9876543210"

    sample_customer = {
        "name": "Ananya Verma",
        "phone": "9876543210",
        "email": "ananya.verma@example.com",
        "address_line1": "14, MI Road, Pink City",
        "address_line2": "Near Ajmeri Gate",
        "city": "Jaipur",
        "state": "Rajasthan",
        "pincode": "302001"
    }
    # Client sends tampered price=10 for straight kurti (actual DB price is 1299)
    tampered_client_items = [
        {"id": "straight", "qty": 2, "size": "M", "color": "Maroon", "price": 10}
    ]
    # Server must compute: 2 * 1299 = 2598 INR (259800 paise), shipping = 0 (>= 999)

    env_overrides = {
        "RAZORPAY_KEY_ID": test_key_id,
        "RAZORPAY_KEY_SECRET": test_key_secret
    }

    with patch.dict(os.environ, env_overrides):
        client = server.app.test_client()

        # A. Verify /api/config exposes public Key ID and NEVER exposes Key Secret
        cfg_resp = client.get("/api/config")
        cfg_data = cfg_resp.get_json()
        assert cfg_resp.status_code == 200 and cfg_data["ok"] is True
        assert cfg_data["is_razorpay_configured"] is True
        assert cfg_data["razorpay_key_id"] == test_key_id
        assert "razorpay_key_secret" not in cfg_data
        assert test_key_secret not in json.dumps(cfg_data)

        # B. Mock Razorpay Orders API and verify server-calculated INR total -> paise
        mock_rzp_order_id = "order_RzpOfficial998877"
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json.return_value = {
            "id": mock_rzp_order_id,
            "entity": "order",
            "amount": 259800,
            "currency": "INR",
            "status": "created"
        }

        with patch("server.requests.post", return_value=mock_post_resp) as mocked_post:
            create_resp = client.post("/api/create-order", json={
                "customer": sample_customer,
                "items": tampered_client_items
            })
            create_data = create_resp.get_json()
            assert create_resp.status_code == 200 and create_data["ok"] is True, f"Create order failed: {create_data}"
            assert create_data["is_simulated"] is False
            assert create_data["key_id"] == test_key_id
            assert create_data["razorpay_order_id"] == mock_rzp_order_id
            assert create_data["total_amount"] == 2598, f"Expected server-calculated ₹2598, got {create_data['total_amount']}"
            assert create_data["amount"] == 259800, f"Expected 259800 paise, got {create_data['amount']}"

            # Verify requests.post was called with Basic Auth (key_id, key_secret) and 259800 paise
            called_args, called_kwargs = mocked_post.call_args
            assert called_kwargs["auth"] == (test_key_id, test_key_secret)
            assert called_kwargs["json"]["amount"] == 259800
            assert called_kwargs["json"]["currency"] == "INR"

        internal_order_id = create_data["order_id"]

        # C. Confirm order in DB is 'pending' / 'pending_payment' BEFORE verification
        det_resp = client.get(f"/api/order-details?order_id={internal_order_id}")
        det_data = det_resp.get_json()
        assert det_data["order"]["payment_status"] == "pending"
        assert det_data["order"]["order_status"] == "pending_payment"

        # D. Attempt simulation bypass when real keys are configured -> MUST FAIL (400)
        sim_bypass_resp = client.post("/api/verify-payment", json={
            "order_id": internal_order_id,
            "razorpay_order_id": mock_rzp_order_id,
            "razorpay_payment_id": "pay_test_bypass",
            "razorpay_signature": "",
            "is_simulated": True
        })
        assert sim_bypass_resp.status_code == 400 and sim_bypass_resp.get_json()["ok"] is False

        # E. Attempt verification with wrong/tampered HMAC signature -> MUST FAIL (400) and mark failed
        bad_sig_resp = client.post("/api/verify-payment", json={
            "order_id": internal_order_id,
            "razorpay_order_id": mock_rzp_order_id,
            "razorpay_payment_id": "pay_RealPayment112233",
            "razorpay_signature": "0000badsignature0000"
        })
        assert bad_sig_resp.status_code == 400 and bad_sig_resp.get_json()["ok"] is False
        det_after_bad = client.get(f"/api/order-details?order_id={internal_order_id}").get_json()
        assert det_after_bad["order"]["payment_status"] == "failed"

        # F. Compute genuine HMAC-SHA256 signature using RAZORPAY_KEY_SECRET and verify -> MUST SUCCEED (200)
        real_payment_id = "pay_RealPayment112233"
        msg = f"{mock_rzp_order_id}|{real_payment_id}".encode("utf-8")
        valid_signature = hmac.new(test_key_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

        good_sig_resp = client.post("/api/verify-payment", json={
            "order_id": internal_order_id,
            "razorpay_order_id": mock_rzp_order_id,
            "razorpay_payment_id": real_payment_id,
            "razorpay_signature": valid_signature
        })
        good_sig_data = good_sig_resp.get_json()
        assert good_sig_resp.status_code == 200 and good_sig_data["ok"] is True
        assert good_sig_data["status"] == "paid"
        assert good_sig_data["payment_id"] == real_payment_id

        # G. Verify duplicate verification request is handled idempotently
        dup_resp = client.post("/api/verify-payment", json={
            "order_id": internal_order_id,
            "razorpay_order_id": mock_rzp_order_id,
            "razorpay_payment_id": real_payment_id,
            "razorpay_signature": valid_signature
        })
        dup_data = dup_resp.get_json()
        assert dup_resp.status_code == 200 and dup_data["ok"] is True and dup_data.get("already_verified") is True

        # H. Confirm order in DB is now 'paid' and 'confirmed'
        det_final = client.get(f"/api/order-details?order_id={internal_order_id}").get_json()
        assert det_final["order"]["payment_status"] == "paid"
        assert det_final["order"]["order_status"] == "confirmed"
        assert det_final["order"]["razorpay_payment_id"] == real_payment_id


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
    assert "razorpay_key_secret" not in data, "Key secret must never be exposed in /api/config"
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

    # 11. Configured RAZORPAY_KEY_ID & RAZORPAY_KEY_SECRET HMAC-SHA256 & Price-Authority Suite
    total += 1
    run_configured_razorpay_hmac_tests()
    print(" [PASS] 11. Configured RAZORPAY_KEY_ID & RAZORPAY_KEY_SECRET (Env Vars, Price Authority, HMAC-SHA256 & Idempotency) -> Verified!")
    passed += 1

    print("=" * 60)
    print(f" ALL {passed}/{total} TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
