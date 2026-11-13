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
import threading
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
        "RAZORPAY_KEY_SECRET": test_key_secret,
        "RAZORPAY_ENABLED": "1"
    }

    with patch.dict(os.environ, env_overrides):
        client = server.app.test_client()

        # A0. Guest checkout blocking before login -> MUST return 401 Unauthorized
        guest_rzp = client.post("/api/create-order", json={
            "customer": sample_customer,
            "items": tampered_client_items
        })
        assert guest_rzp.status_code == 401 and guest_rzp.get_json().get("auth_required") is True

        guest_cod = client.post("/api/create-cod-order", json={
            "customer": sample_customer,
            "items": tampered_client_items
        })
        assert guest_cod.status_code == 401 and guest_cod.get_json().get("auth_required") is True

        # Authenticate customer via /api/auth/register (sets HttpOnly user_token cookie & returns token)
        unique_email = f"ananya.{os.urandom(3).hex()}@example.com"
        sample_customer["email"] = unique_email
        reg_resp = client.post("/api/auth/register", json={
            "name": sample_customer["name"],
            "email": unique_email,
            "phone": sample_customer["phone"],
            "password": "SecurePassword123!"
        })
        reg_data = reg_resp.get_json()
        assert reg_resp.status_code == 200 and reg_data["ok"] is True
        customer_user_id = reg_data["user"]["id"]
        auth_headers = {"Authorization": f"Bearer {reg_data['token']}"}

        # A. Verify /api/config exposes public Key ID and NEVER exposes Key Secret
        cfg_resp = client.get("/api/config")
        cfg_data = cfg_resp.get_json()
        assert cfg_resp.status_code == 200 and cfg_data["ok"] is True
        assert cfg_data["is_razorpay_configured"] is True
        assert cfg_data["razorpay_key_id"] == test_key_id
        assert "razorpay_key_secret" not in cfg_data
        assert test_key_secret not in json.dumps(cfg_data)

        # Security regression: reject unknown product IDs even when client supplies a price.
        fake_product_items = [
            {
                "id": "fake-security-test-product",
                "name": "Fake Kurti",
                "qty": 1,
                "size": "M",
                "color": "Maroon",
                "price": 10,
                "mrp": 1299
            }
        ]

        fake_rzp_resp = client.post("/api/create-order", headers=auth_headers, json={
            "customer": sample_customer,
            "items": fake_product_items
        })
        fake_rzp_data = fake_rzp_resp.get_json()
        assert fake_rzp_resp.status_code == 400, (
            f"Unknown product should be rejected by Razorpay checkout: {fake_rzp_data}"
        )
        assert "Unrecognized product" in fake_rzp_data.get("error", "")

        fake_cod_resp = client.post("/api/create-cod-order", headers=auth_headers, json={
            "customer": sample_customer,
            "items": fake_product_items
        })
        fake_cod_data = fake_cod_resp.get_json()
        assert fake_cod_resp.status_code == 400, (
            f"Unknown product should be rejected by COD checkout: {fake_cod_data}"
        )
        assert "Unrecognized product" in fake_cod_data.get("error", "")

        print(" [PASS] Security: Unknown product with client-supplied price rejected by Razorpay and COD")

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
            create_resp = client.post("/api/create-order", headers=auth_headers, json={
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

        # C. Confirm order in DB is 'pending' / 'pending_payment' BEFORE verification and linked to customer_user_id
        det_resp = client.get(f"/api/order-details?order_id={internal_order_id}", headers=auth_headers)
        det_data = det_resp.get_json()
        assert det_data["order"]["payment_status"] == "pending"
        assert det_data["order"]["order_status"] == "pending_payment"
        assert det_data["order"]["user_id"] == customer_user_id

        # C2. Verify another authenticated customer CANNOT view or verify this order (403 Forbidden)
        other_client = server.app.test_client()
        other_reg = other_client.post("/api/auth/register", json={
            "name": "Other User",
            "email": f"other.{os.urandom(3).hex()}@example.com",
            "phone": "9123456780",
            "password": "OtherPassword123!"
        }).get_json()
        other_headers = {"Authorization": f"Bearer {other_reg['token']}"}
        other_det = other_client.get(f"/api/order-details?order_id={internal_order_id}", headers=other_headers)
        assert other_det.status_code == 403, f"Expected 403 for cross-user order access, got {other_det.status_code}"

        # D. Attempt simulation bypass when real keys are configured -> MUST FAIL (400)
        sim_bypass_resp = client.post("/api/verify-payment", headers=auth_headers, json={
            "order_id": internal_order_id,
            "razorpay_order_id": mock_rzp_order_id,
            "razorpay_payment_id": "pay_test_bypass",
            "razorpay_signature": "",
            "is_simulated": True
        })
        assert sim_bypass_resp.status_code == 400 and sim_bypass_resp.get_json()["ok"] is False

        # E. Test payment cancellation / failure recording (/api/payment-failed)
        cancel_resp = client.post("/api/payment-failed", headers=auth_headers, json={
            "order_id": internal_order_id,
            "razorpay_order_id": mock_rzp_order_id,
            "reason": "Payment cancelled by customer"
        })
        assert cancel_resp.status_code == 200 and cancel_resp.get_json()["payment_status"] == "cancelled"
        det_after_cancel = client.get(f"/api/order-details?order_id={internal_order_id}", headers=auth_headers).get_json()
        assert det_after_cancel["order"]["payment_status"] == "cancelled"

        # F. Attempt verification with wrong/tampered HMAC signature -> MUST FAIL (400) and mark failed
        bad_sig_resp = client.post("/api/verify-payment", headers=auth_headers, json={
            "order_id": internal_order_id,
            "razorpay_order_id": mock_rzp_order_id,
            "razorpay_payment_id": "pay_RealPayment112233",
            "razorpay_signature": "0000badsignature0000"
        })
        assert bad_sig_resp.status_code == 400 and bad_sig_resp.get_json()["ok"] is False
        det_after_bad = client.get(f"/api/order-details?order_id={internal_order_id}", headers=auth_headers).get_json()
        assert det_after_bad["order"]["payment_status"] == "failed"

        # G. Compute genuine HMAC-SHA256 signature using RAZORPAY_KEY_SECRET and verify -> MUST SUCCEED (200)
        real_payment_id = "pay_RealPayment112233"
        msg = f"{mock_rzp_order_id}|{real_payment_id}".encode("utf-8")
        valid_signature = hmac.new(test_key_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

        good_sig_resp = client.post("/api/verify-payment", headers=auth_headers, json={
            "order_id": internal_order_id,
            "razorpay_order_id": mock_rzp_order_id,
            "razorpay_payment_id": real_payment_id,
            "razorpay_signature": valid_signature
        })
        good_sig_data = good_sig_resp.get_json()
        assert good_sig_resp.status_code == 200 and good_sig_data["ok"] is True
        assert good_sig_data["status"] == "paid"
        assert good_sig_data["payment_id"] == real_payment_id

        # H. Verify duplicate verification request is handled idempotently
        dup_resp = client.post("/api/verify-payment", headers=auth_headers, json={
            "order_id": internal_order_id,
            "razorpay_order_id": mock_rzp_order_id,
            "razorpay_payment_id": real_payment_id,
            "razorpay_signature": valid_signature
        })
        dup_data = dup_resp.get_json()
        assert dup_resp.status_code == 200 and dup_data["ok"] is True and dup_data.get("already_verified") is True

        # I. Confirm order in DB is now 'paid' and 'confirmed'
        det_final = client.get(f"/api/order-details?order_id={internal_order_id}", headers=auth_headers).get_json()
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
    unique_suffix = os.urandom(3).hex()
    priya_email = f"priya.sharma.{unique_suffix}@example.com"
    test_customer = {
        "name": "Priya Sharma",
        "phone": "9876543210",
        "email": priya_email,
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

    # 3b. Guest Checkout Blocking: Unauthenticated COD and Razorpay order creation MUST be rejected (401)
    total += 1
    g_cod_status, g_cod_body, _ = make_request("/api/create-cod-order", method="POST", payload={
        "customer": test_customer,
        "items": test_items
    })
    g_cod_data = json.loads(g_cod_body)
    assert g_cod_status == 401 and g_cod_data.get("auth_required") is True, f"Expected 401 for guest COD order: {g_cod_body}"

    g_rzp_status, g_rzp_body, _ = make_request("/api/create-order", method="POST", payload={
        "customer": test_customer,
        "items": test_items
    })
    g_rzp_data = json.loads(g_rzp_body)
    assert g_rzp_status == 401 and g_rzp_data.get("auth_required") is True, f"Expected 401 for guest Razorpay order: {g_rzp_body}"
    print(" [PASS] 3b. Guest Checkout Blocked: Unauthenticated POST /api/create-cod-order & /api/create-order -> 401 Unauthorized")
    passed += 1

    # 3c. Customer Auth Suite: Register, Duplicate Email (400), Invalid Password (401), Login (200), Logout (200 -> 401)
    total += 1
    reg_status, reg_body, _ = make_request("/api/auth/register", method="POST", payload={
        "name": test_customer["name"],
        "email": priya_email,
        "phone": test_customer["phone"],
        "password": "PriyaSecurePass123"
    })
    reg_data = json.loads(reg_body)
    assert reg_status == 200 and reg_data.get("ok") is True, f"Registration failed: {reg_body}"
    priya_user_id = reg_data["user"]["id"]
    first_token = reg_data["token"]

    # Duplicate email registration must fail with 400
    dup_status, dup_body, _ = make_request("/api/auth/register", method="POST", payload={
        "name": "Duplicate Priya",
        "email": priya_email,
        "phone": "9876543210",
        "password": "AnotherPassword123"
    })
    assert dup_status == 400 and json.loads(dup_body).get("ok") is False, f"Expected 400 for duplicate email: {dup_body}"

    # Invalid password login must fail with 401
    bad_login_status, bad_login_body, _ = make_request("/api/auth/login", method="POST", payload={
        "email": priya_email,
        "password": "WrongPassword999"
    })
    assert bad_login_status == 401 and json.loads(bad_login_body).get("ok") is False, f"Expected 401 for wrong password: {bad_login_body}"

    # Logout invalidates first_token
    lo_status, lo_body, _ = make_request("/api/auth/logout", method="POST", headers={"Authorization": f"Bearer {first_token}"})
    assert lo_status == 200 and json.loads(lo_body).get("ok") is True
    me_after_lo_status, _, _ = make_request("/api/auth/me", headers={"Authorization": f"Bearer {first_token}"})
    assert me_after_lo_status == 401, f"Expected 401 after logout, got {me_after_lo_status}"

    # Valid Login returns active session token
    login_status, login_body, _ = make_request("/api/auth/login", method="POST", payload={
        "email": priya_email,
        "password": "PriyaSecurePass123"
    })
    login_data = json.loads(login_body)
    assert login_status == 200 and login_data.get("ok") is True
    auth_headers = {"Authorization": f"Bearer {login_data['token']}"}
    print(" [PASS] 3c. Customer Auth Verified: Register, Duplicate Email (400), Wrong Password (401), Logout Invalidation (401) & Login (200)")
    passed += 1

    # 4. COD Order - Validation Error test (empty items)
    total += 1
    status, body, _ = make_request("/api/create-cod-order", method="POST", payload={
        "customer": test_customer,
        "items": []
    }, headers=auth_headers)
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
    }, headers=auth_headers)
    data = json.loads(body)
    assert status == 400 and data.get("ok") is False, f"Expected 400 for invalid phone: {body}"
    print(f" [PASS] 5. POST /api/create-cod-order (Invalid phone) -> 400 Error caught: '{data.get('error')}'")
    passed += 1

    # 6. COD Order - Successful placement (Authenticated)
    total += 1
    status, body, _ = make_request("/api/create-cod-order", method="POST", payload={
        "customer": test_customer,
        "items": test_items
    }, headers=auth_headers)
    data = json.loads(body)
    assert status == 200 and data.get("ok") is True, f"COD placement failed: {body}"
    cod_order_id = data.get("order_id")
    assert cod_order_id.startswith("NAARI-"), f"Unexpected order_id format: {cod_order_id}"
    assert data.get("total_amount") == 4297, f"Total amount mismatch: expected 4297, got {data.get('total_amount')}"
    print(f" [PASS] 6. POST /api/create-cod-order -> 200 Success! Created order {cod_order_id} (Total: ₹{data.get('total_amount')})")
    passed += 1

    # 7. Regression Test: Online Payment when Razorpay keys are NOT configured MUST NOT simulate or bypass Razorpay
    # Use only the first item so the preceding COD test's stock deduction for the A-line size cannot interfere.
    total += 1
    status, body, _ = make_request("/api/create-order", method="POST", payload={
        "customer": test_customer,
        "items": [test_items[0]]
    }, headers=auth_headers)
    data = json.loads(body)
    assert status == 503 and data.get("ok") is False, f"Expected 503 when Razorpay keys are missing (never simulate), got {status}: {body}"
    assert not data.get("is_simulated"), "is_simulated must never be True"
    print(f" [PASS] 7. Regression: POST /api/create-order without keys -> 503 Rejected (No simulated payment bypass: '{data.get('error')}')")
    passed += 1

    # 8. Regression Test: POST /api/verify-payment rejects simulated & tampered requests
    total += 1
    status, body, _ = make_request("/api/verify-payment", method="POST", payload={
        "order_id": cod_order_id,
        "razorpay_order_id": "order_test_fake123",
        "razorpay_payment_id": "pay_test_fake123",
        "razorpay_signature": "simulated_test_signature",
        "is_simulated": True
    }, headers=auth_headers)
    data = json.loads(body)
    assert status == 400 and data.get("ok") is False, f"Expected 400 for simulated payment bypass, got {status}: {body}"
    print(f" [PASS] 8. Regression: POST /api/verify-payment blocks simulated payment bypass -> 400 Caught: '{data.get('error')}'")
    passed += 1

    # 9. Regression Test: Verify checkout.html has no simulated redirect and opens Razorpay Standard Checkout
    total += 1
    checkout_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "checkout.html")
    with open(checkout_path, "r", encoding="utf-8") as cf:
        checkout_html = cf.read()
    assert "if (createData.is_simulated)" not in checkout_html, "checkout.html must not contain simulated payment redirect branch"
    assert "simulated_test_signature" not in checkout_html, "checkout.html must not send simulated_test_signature"
    assert "new Razorpay(options)" in checkout_html and "rzpInstance.open()" in checkout_html, "checkout.html must open Razorpay Standard Checkout"
    print(" [PASS] 9. Regression: checkout.html verified free of simulated bypass; opens new Razorpay(options) -> rzpInstance.open()")
    passed += 1

    # 10. Order Details Retrieval & Strict Order Ownership Protection
    total += 1
    status, body, _ = make_request(f"/api/order-details?order_id={cod_order_id}", headers=auth_headers)
    data = json.loads(body)
    assert status == 200 and data.get("ok") is True, f"Order details failed: {body}"
    ord_info = data.get("order", {})
    assert ord_info.get("id") == cod_order_id
    assert ord_info.get("user_id") == priya_user_id
    assert ord_info.get("payment_status") == "cod_confirmed"
    assert ord_info.get("customer_name") == test_customer["name"]
    assert len(ord_info.get("items", [])) == 2

    # Unauthenticated access to /api/order-details or /api/customer/orders MUST return 401
    unauth_det_status, _, _ = make_request(f"/api/order-details?order_id={cod_order_id}")
    assert unauth_det_status == 401, f"Expected 401 for unauthenticated /api/order-details, got {unauth_det_status}"
    unauth_list_status, _, _ = make_request(f"/api/customer/orders?email={priya_email}")
    assert unauth_list_status == 401, f"Expected 401 for unauthenticated /api/customer/orders, got {unauth_list_status}"

    # Register Customer B and verify Customer B CANNOT access, cancel, or file returns for Customer A's order
    kavya_email = f"kavya.nair.{unique_suffix}@example.com"
    _, kavya_reg_body, _ = make_request("/api/auth/register", method="POST", payload={
        "email": kavya_email,
        "password": "KavyaPassword123"
    })
    kavya_headers = {"Authorization": f"Bearer {json.loads(kavya_reg_body)['token']}"}

    cross_det_status, _, _ = make_request(f"/api/order-details?order_id={cod_order_id}", headers=kavya_headers)
    assert cross_det_status == 403, f"Expected 403 when Customer B views Customer A's order, got {cross_det_status}"

    cross_cancel_status, _, _ = make_request("/api/customer/orders/cancel", method="POST", payload={
        "order_id": cod_order_id,
        "reason": "Unauthorized cancel attempt"
    }, headers=kavya_headers)
    assert cross_cancel_status == 403, f"Expected 403 when Customer B cancels Customer A's order, got {cross_cancel_status}"

    cross_ret_status, _, _ = make_request("/api/customer/returns", method="POST", payload={
        "order_id": cod_order_id,
        "item_name": "Gulmohar Straight Kurti",
        "action_type": "return",
        "reason": "Unauthorized return attempt"
    }, headers=kavya_headers)
    assert cross_ret_status == 403, f"Expected 403 when Customer B files return for Customer A's order, got {cross_ret_status}"

    _, kavya_orders_body, _ = make_request("/api/customer/orders", headers=kavya_headers)
    kavya_order_ids = [o["id"] for o in json.loads(kavya_orders_body).get("orders", [])]
    assert cod_order_id not in kavya_order_ids, "Customer B must never see Customer A's order in /api/customer/orders"

    print(f" [PASS] 10. GET /api/order-details & Strict Order Ownership (401 Unauthenticated, 403 Cross-Customer Blocked) -> Verified!")
    passed += 1

    # 11. Configured RAZORPAY_KEY_ID & RAZORPAY_KEY_SECRET HMAC-SHA256 & Price-Authority Suite
    total += 1
    run_configured_razorpay_hmac_tests()
    print(" [PASS] 11. Configured RAZORPAY_KEY_ID & RAZORPAY_KEY_SECRET (Env Vars, Price Authority, Cancellation, HMAC-SHA256 & Idempotency) -> Verified!")
    passed += 1

    # 12. Step 2 Header UI, account.html Endpoints & Redirect Integration
    total += 1
    base_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base_dir, "assets", "app.js"), "r", encoding="utf-8") as af:
        app_js = af.read()
    with open(os.path.join(base_dir, "account.html"), "r", encoding="utf-8") as acf:
        account_html = acf.read()

    # Verify header shows Login / Sign Up when logged out and Account (<Name>) + Logout when logged in on desktop & mobile
    assert "'Login / Sign Up'" in app_js, "app.js must show 'Login / Sign Up' when logged out"
    assert "`Account (${firstName})`" in app_js, "app.js must show 'Account (<Name>)' when logged in"
    assert "header-logout-btn" in app_js and "logoutCustomer" in app_js, "app.js must provide a Logout action when logged in"
    assert "el.classList.remove('hidden', 'sm:inline')" in app_js, "app.js must make header user label visible on mobile and desktop"
    assert "mobile-nav-auth-section" in app_js, "app.js must render mobile drawer auth section"

    # Verify account.html connects to /api/auth/login, /api/auth/register, /api/auth/me, /api/auth/logout and supports ?redirect=checkout.html
    for ep in ("/api/auth/login", "/api/auth/register", "/api/auth/me", "/api/auth/logout"):
        assert ep in account_html, f"account.html must connect to {ep}"
    assert "getSafeRedirectTarget" in account_html and "window.location.href = redirectTarget" in account_html, (
        "account.html must support ?redirect=checkout.html after login/signup"
    )
    assert "checkout-redirect-banner" in account_html, "account.html must include checkout redirect notice banner"

    # Verify HttpOnly user_token cookie works end-to-end across /api/auth/login -> /api/auth/me -> /api/auth/logout
    import server
    cookie_client = server.app.test_client()
    cookie_login_resp = cookie_client.post("/api/auth/login", json={
        "email": priya_email,
        "password": "PriyaSecurePass123"
    })
    assert cookie_login_resp.status_code == 200
    cookie_token = cookie_login_resp.get_json()["token"]
    set_cookie_hdr = cookie_login_resp.headers.get("Set-Cookie", "")
    assert f"user_token={cookie_token}" in set_cookie_hdr and "HttpOnly" in set_cookie_hdr, (
        f"Expected HttpOnly user_token cookie on login, got: {set_cookie_hdr}"
    )
    me_cookie_resp = cookie_client.get("/api/auth/me")
    assert me_cookie_resp.status_code == 200 and me_cookie_resp.get_json().get("user", {}).get("email") == priya_email
    lo_cookie_resp = cookie_client.post("/api/auth/logout")
    assert lo_cookie_resp.status_code == 200 and "user_token=;" in lo_cookie_resp.headers.get("Set-Cookie", "")
    me_after_cookie_lo = cookie_client.get("/api/auth/me")
    assert me_after_cookie_lo.status_code == 401
    print(" [PASS] 12. Step 2 Header Login/Sign Up UI, Account/Logout Action, account.html Auth Endpoints & ?redirect=checkout.html Verified!")
    passed += 1

    # 13. Step 3 Checkout Redirect, Pre-fill, Auth Credentials & Order Confirmation Ownership / Admin Access
    total += 1
    with open(os.path.join(base_dir, "checkout.html"), "r", encoding="utf-8") as chf:
        checkout_src = chf.read()
    with open(os.path.join(base_dir, "cart.html"), "r", encoding="utf-8") as crf:
        cart_src = crf.read()
    with open(os.path.join(base_dir, "order-confirmation.html"), "r", encoding="utf-8") as ocf:
        order_conf_src = ocf.read()

    # A. Verify checkout.html redirects logged-out visitors, pre-fills customer details, and sends auth credentials
    assert "account.html?redirect=checkout.html" in checkout_src, "checkout.html must redirect logged-out customers to account.html?redirect=checkout.html"
    assert "ensureCheckoutAuthenticated" in checkout_src and "prefillAuthenticatedCustomer" in checkout_src, (
        "checkout.html must verify auth on load and prefill authenticated customer details"
    )
    assert "buildCustomerFetchOptions" in checkout_src and "getCustomerAuthHeaders" in checkout_src, (
        "checkout.html must attach customer auth headers to API requests"
    )
    assert "credentials: 'same-origin'" in checkout_src, "checkout.html must include same-origin credentials on checkout requests"

    # B. Verify cart.html and app.js redirect logged-out customers clicking Proceed to Checkout
    assert "navigateToCheckout" in app_js and "account.html?redirect=checkout.html" in app_js, (
        "app.js must redirect logged-out drawer checkout clicks to account.html?redirect=checkout.html"
    )
    assert "navigateToCheckout" in cart_src and "account.html?redirect=checkout.html" in cart_src, (
        "cart.html must redirect logged-out Proceed to Checkout clicks to account.html?redirect=checkout.html"
    )
    assert "localStorage.removeItem('naari_last_order')" in app_js, (
        "clearUserSession in app.js must clear cached naari_last_order on logout"
    )

    # C. Verify order-confirmation.html attaches auth headers, blocks 401/403 from using cached order, and supports admin access
    assert "buildOrderAuthHeaders" in order_conf_src and "getCustomerAuthHeaders" in order_conf_src, (
        "order-confirmation.html must attach customer/admin auth headers"
    )
    assert "X-Admin-Token" in order_conf_src and "X-Admin-Passkey" in order_conf_src, (
        "order-confirmation.html must preserve separate admin access headers"
    )
    assert "res.status === 401" in order_conf_src and "res.status === 403" in order_conf_src, (
        "order-confirmation.html must explicitly handle 401 Login Required and 403 Access Denied"
    )
    assert "if (!serverResponded)" in order_conf_src, (
        "order-confirmation.html must never use localStorage fallback when server responded with 401/403/404"
    )

    # D. Verify saved address pre-fill endpoint, coupon-preserved COD checkout, customer-only confirmation, and separate admin access
    addr_save_status, addr_save_body, _ = make_request("/api/customer/addresses", method="POST", payload={
        "name": "Priya Nair",
        "phone": "9876543210",
        "address_line1": "24 Heritage Residency, C-Scheme",
        "address_line2": "Near Central Park",
        "city": "Jaipur",
        "state": "Rajasthan",
        "pincode": "302001",
        "is_default": True
    }, headers=auth_headers)
    assert addr_save_status == 200 and json.loads(addr_save_body).get("ok") is True
    addr_list_status, addr_list_body, _ = make_request("/api/customer/addresses", headers=auth_headers)
    addrs = json.loads(addr_list_body).get("addresses", [])
    assert addr_list_status == 200 and len(addrs) >= 1 and addrs[0]["address_line1"] == "24 Heritage Residency, C-Scheme"

    # Place COD order with preserved coupon NAARI10 (10% off 4297 = 430 discount -> 3867 total)
    coupon_cod_status, coupon_cod_body, _ = make_request("/api/create-cod-order", method="POST", payload={
        "customer": test_customer,
        "items": test_items,
        "coupon_code": "NAARI10"
    }, headers=auth_headers)
    coupon_cod_data = json.loads(coupon_cod_body)
    assert coupon_cod_status == 200 and coupon_cod_data.get("ok") is True, f"Coupon COD order failed: {coupon_cod_body}"
    assert coupon_cod_data.get("discount_amount") == 430 and coupon_cod_data.get("total_amount") == 3867
    coupon_order_id = coupon_cod_data["order_id"]

    # Customer A can view their own order confirmation; Customer B gets 403; Guest gets 401
    own_conf_status, _, _ = make_request(f"/api/order-details?order_id={coupon_order_id}", headers=auth_headers)
    assert own_conf_status == 200
    other_conf_status, _, _ = make_request(f"/api/order-details?order_id={coupon_order_id}", headers=kavya_headers)
    assert other_conf_status == 403
    guest_conf_status, _, _ = make_request(f"/api/order-details?order_id={coupon_order_id}")
    assert guest_conf_status == 401

    # Separate Admin Access: Admin with X-Admin-Token can view Customer A's order confirmation (even if Customer B's Bearer token is also present)
    with patch.dict(os.environ, {"ADMIN_SECRET_KEY": "TestOnlyAdminSecret_2026!"}):
        assert server.is_admin_passkey_configured() is True
        expected_admin_passkey = server.get_expected_admin_passkey()
        admin_verify_resp = cookie_client.post("/api/admin/verify", json={"passkey": expected_admin_passkey}, headers={"X-Admin-Passkey": expected_admin_passkey})
        assert admin_verify_resp.status_code == 200
        admin_token = admin_verify_resp.get_json()["token"]
    admin_conf_status, admin_conf_body, _ = make_request(
        f"/api/order-details?order_id={coupon_order_id}",
        headers={"X-Admin-Token": admin_token, **kavya_headers}
    )
    assert admin_conf_status == 200 and json.loads(admin_conf_body).get("order", {}).get("id") == coupon_order_id
    print(" [PASS] 13. Step 3 Checkout Redirect, Pre-fill, Auth Credentials, Coupon Preservation & Order Confirmation Ownership / Admin Access Verified!")
    passed += 1

    # 14. Static File Allowlist & Backup/Sensitive Path Protection + Admin Config Status Check
    total += 1
    sec_client = server.app.test_client()

    # A. Sensitive & backup paths that MUST return 404 Not Found
    blocked_paths = [
        "/server.py",
        "/server.py.address-backup",
        "/server.py.security-backup-20261111-155539",
        "/server.py.bak",
        "/config.json",
        "/config.local.json",
        "/.env",
        "/.env.example",
        "/.gitignore",
        "/Procfile",
        "/requirements.txt",
        "/test_checkout_flow.py",
        "/test_admin_portal.py",
        "/test_new_features.py",
        "/data/orders.db",
        "/data/naari.db",
        "/gh",
    ]
    for bpath in blocked_paths:
        b_resp = sec_client.get(bpath)
        assert b_resp.status_code == 404, f"Security regression: {bpath} returned HTTP {b_resp.status_code} instead of 404"

    # B. Legitimate public storefront pages, clean slugs, and static assets that MUST return 200 OK
    allowed_paths = [
        "/",
        "/index.html",
        "/shop",
        "/shop.html",
        "/shop/index.html",
        "/product.html",
        "/cart",
        "/cart.html",
        "/checkout",
        "/checkout.html",
        "/order-confirmation",
        "/order-confirmation.html",
        "/account",
        "/account.html",
        "/admin.html",
        "/story",
        "/story.html",
        "/contact",
        "/contact.html",
        "/favicon.ico",
        "/favicon.png",
        "/assets/app.js",
        "/assets/styles.css",
        "/assets/hero.jpg",
        "/images/naari-logo.png",
    ]
    for apath in allowed_paths:
        a_resp = sec_client.get(apath)
        assert a_resp.status_code == 200, f"Public route/asset regression: {apath} returned HTTP {a_resp.status_code}"

    # C. Admin configuration check without fallback password or secret exposure:
    #    Tests both (1) ADMIN_SECRET_KEY absent at import time and (2) ADMIN_SECRET_KEY present before import
    #    followed by environment removal, using fresh isolated subprocesses.
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory(prefix="naari_admin_cfg_iso_") as iso_dir:
        iso_db = os.path.join(iso_dir, "iso_orders.db")
        iso_cfg = os.path.join(iso_dir, "iso_config.json")
        with open(iso_cfg, "w", encoding="utf-8") as cf:
            json.dump({"store_name": "Matra Naari", "currency": "INR"}, cf)

        # Case 1: ADMIN_SECRET_KEY absent at import time -> unconfigured (401), then set dynamically -> configured (200)
        env_absent = {
            k: v for k, v in os.environ.items()
            if k not in ("ADMIN_SECRET_KEY", "ADMIN_PASSKEY", "ADMIN_PASSWORD")
        }
        env_absent["DB_PATH"] = iso_db
        env_absent["CONFIG_PATH"] = iso_cfg
        env_absent["DISABLE_EXTERNAL_GEOCODING"] = "1"

        case1_code = """
import os, json, server
assert server.get_expected_admin_passkey() == ""
assert server.is_admin_passkey_configured() is False
st = server.get_admin_auth_config_status()
assert st["is_admin_configured"] is False and st["env_configured"] is False
assert server.verify_admin_passkey_value("naari@admin2026") is False
c = server.app.test_client()
r = c.post("/api/admin/verify", json={"passkey": "naari@admin2026"})
assert r.status_code == 401 and r.get_json().get("is_admin_configured") is False
"""
        res1 = subprocess.run([sys.executable, "-c", case1_code], cwd=base_dir, env=env_absent, capture_output=True, text=True)
        assert res1.returncode == 0, f"Case 1 (absent at import) failed: {res1.stderr}"

        # Case 2: ADMIN_SECRET_KEY present BEFORE import, verified active, then removed from os.environ -> must immediately become unconfigured
        env_present = dict(env_absent)
        env_present["ADMIN_SECRET_KEY"] = "PreImportAdminSecret_99!"

        case2_code = """
import os, json, server
secret = "PreImportAdminSecret_99!"
assert server.is_admin_passkey_configured() is True
assert server.get_expected_admin_passkey() == secret
st_on = server.get_admin_auth_config_status()
assert st_on["is_admin_configured"] is True and st_on["env_configured"] is True
assert secret not in json.dumps(st_on)

c = server.app.test_client()
cfg_on = c.get("/api/config").get_json()
assert cfg_on.get("is_admin_configured") is True
assert secret not in json.dumps(cfg_on)

# Now remove ADMIN_SECRET_KEY from os.environ after import and verify stale import-time value is NOT used
os.environ.pop("ADMIN_SECRET_KEY", None)
assert server.get_expected_admin_passkey() == ""
assert server.is_admin_passkey_configured() is False
st_off = server.get_admin_auth_config_status()
assert st_off["is_admin_configured"] is False and st_off["env_configured"] is False
assert server.verify_admin_passkey_value(secret) is False
r_off = c.post("/api/admin/verify", json={"passkey": secret})
assert r_off.status_code == 401 and r_off.get_json().get("is_admin_configured") is False
"""
        res2 = subprocess.run([sys.executable, "-c", case2_code], cwd=base_dir, env=env_present, capture_output=True, text=True)
        assert res2.returncode == 0, f"Case 2 (present before import then removed) failed: {res2.stderr}"

    print(" [PASS] 14. Static File Allowlist (Backup & Sensitive URLs -> 404, Storefront & Assets -> 200) & Safe Admin Config Check Verified!")
    passed += 1

    # 15. Checkout Address/Map Lifecycle Wiring, Saved-Address Chips & Draft Restoration
    total += 1
    with open(os.path.join(base_dir, "checkout.html"), "r", encoding="utf-8") as ch_file:
        checkout_src = ch_file.read()

    # Verify required functions and lifecycle calls exist in checkout.html
    for required_symbol in [
        "function clearMapPinCoordinates(",
        "function initDeliveryMap()",
        "function setupGeolocationButton()",
        "function setupAddressAutocomplete()",
        "function fillCheckoutAddressFields(",
        "function renderSavedAddressChips(",
        "function setupAddressFormControls()",
        "async function handleConfirmAddress()",
    ]:
        assert required_symbol in checkout_src, f"Missing {required_symbol} in checkout.html"

    # Verify DOMContentLoaded initializes map & address controls in the proper order
    dom_loaded_idx = checkout_src.index("document.addEventListener('DOMContentLoaded'")
    dom_loaded_block = checkout_src[dom_loaded_idx:]
    render_summary_pos = dom_loaded_block.index("renderOrderSummary();")
    init_map_pos = dom_loaded_block.index("initDeliveryMap();")
    setup_geo_pos = dom_loaded_block.index("setupGeolocationButton();")
    setup_auto_pos = dom_loaded_block.index("setupAddressAutocomplete();")
    setup_controls_pos = dom_loaded_block.index("setupAddressFormControls();")
    prefill_pos = dom_loaded_block.index("await prefillAuthenticatedCustomer(authUser);")
    assert render_summary_pos < init_map_pos < setup_geo_pos < setup_auto_pos < setup_controls_pos < prefill_pos, (
        "DOMContentLoaded lifecycle order in checkout.html is incorrect"
    )

    # Verify restoreCheckoutFormDraft restores split fields, label, location_summary, and coordinates
    restore_idx = checkout_src.index("function restoreCheckoutFormDraft()")
    restore_block = checkout_src[restore_idx:checkout_src.index("function redirectToLoginForCheckout()")]
    for expected_draft_token in [
        "house_no: 'cust-house-no'",
        "street_area: 'cust-street-area'",
        "location_summary: 'cust-location-summary'",
        "setAddressLabelUI(draft.address_label)",
        "setMapPinLocation(Number(draft.latitude), Number(draft.longitude)",
    ]:
        assert expected_draft_token in restore_block, f"Missing {expected_draft_token} in restoreCheckoutFormDraft()"

    # Run Node.js behavioral harness against checkout.html inline script if node is installed
    import shutil
    node_bin = shutil.which("node")
    if node_bin:
        node_test_script = r"""
const fs = require('fs');
const vm = require('vm');
const html = fs.readFileSync('checkout.html', 'utf8');
const scriptBlocks = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
const inlineCode = scriptBlocks[scriptBlocks.length - 1];

// Minimal DOM & browser environment stub to exercise checkout.html lifecycle and address wiring
const elements = {};
const classListFactory = (initial = []) => {
  const set = new Set(initial);
  return {
    add: (...cls) => cls.forEach(c => set.add(c)),
    remove: (...cls) => cls.forEach(c => set.delete(c)),
    toggle: (c, force) => {
      if (force === undefined) {
        if (set.has(c)) { set.delete(c); return false; }
        set.add(c); return true;
      }
      if (force) set.add(c); else set.delete(c);
      return Boolean(force);
    },
    contains: (c) => set.has(c)
  };
};

function makeEl(id, extra = {}) {
  const listeners = {};
  const el = {
    id,
    value: extra.value || '',
    textContent: extra.textContent || '',
    innerHTML: '',
    disabled: false,
    className: extra.className || '',
    dataset: extra.dataset || {},
    options: extra.options || [],
    classList: classListFactory(extra.hidden ? ['hidden'] : []),
    listeners,
    addEventListener(type, fn) {
      if (!listeners[type]) listeners[type] = [];
      listeners[type].push(fn);
    },
    dispatchEvent(type, evt = {}) {
      (listeners[type] || []).forEach(fn => fn(evt));
    },
    getAttribute(attr) {
      if (attr === 'data-label') return this.dataset.label || '';
      if (attr === 'data-method') return this.dataset.method || '';
      return '';
    },
    querySelectorAll(sel) {
      if (sel === '.saved-addr-chip') return this._chips || [];
      return [];
    },
    scrollIntoView() {},
    focus() {},
    contains() { return false; }
  };
  elements[id] = el;
  return el;
}

const stateOptions = [
  { value: '' },
  { value: 'Rajasthan' },
  { value: 'Maharashtra' },
  { value: 'Karnataka' }
];

[
  'checkout-main-grid', 'checkout-empty-state', 'checkout-items-list',
  'checkout-subtotal', 'checkout-shipping', 'checkout-total',
  'checkout-discount-row', 'checkout-discount-code', 'checkout-discount-amount',
  'checkout-coupon-input', 'checkout-apply-coupon-btn', 'checkout-coupon-msg',
  'place-order-btn', 'place-order-text', 'place-order-spinner',
  'checkout-error-banner', 'delivery-map', 'use-current-location-btn',
  'use-current-location-text', 'map-geocode-status', 'map-coords-badge',
  'map-selected-address-text', 'address-search-input', 'address-autocomplete-dropdown',
  'address-search-spinner', 'address-search-clear-btn', 'address-autocomplete-container',
  'cust-lat', 'cust-lng', 'cust-location-summary', 'cust-address-label',
  'cust-name', 'cust-phone', 'cust-email', 'cust-house-no', 'cust-street-area',
  'cust-address1', 'cust-address2', 'cust-city', 'cust-pincode',
  'pincode-verify-status', 'confirm-preview-recipient', 'confirm-preview-address',
  'confirm-preview-coords', 'confirm-preview-label', 'address-confirmed-badge',
  'address-step-status-pill', 'address-confirm-feedback', 'confirm-address-btn',
  'saved-addresses-quickfill', 'saved-addresses-chips', 'checkout-form'
].forEach(id => makeEl(id, id === 'cust-state' ? { options: stateOptions } : {}));
makeEl('cust-state', { options: stateOptions });
elements['cust-address-label'].value = 'Home';
elements['saved-addresses-quickfill'].classList.add('hidden');

const labelBtns = ['Home', 'Work', 'Other'].map(lbl => {
  const b = makeEl('btn-label-' + lbl, { dataset: { label: lbl } });
  return b;
});

// Intercept innerHTML assignment on saved-addresses-chips to instantiate clickable chip buttons
let currentChips = [];
Object.defineProperty(elements['saved-addresses-chips'], 'innerHTML', {
  get() { return this._html || ''; },
  set(htmlStr) {
    this._html = htmlStr;
    const matches = [...String(htmlStr).matchAll(/data-addr-idx="(\d+)"/g)];
    currentChips = matches.map(m => {
      const chip = makeEl('chip-' + m[1], { dataset: { addrIdx: m[1] } });
      return chip;
    });
    this._chips = currentChips;
  }
});

let domReadyCallback = null;
const storage = {};
const sessionStore = {};
let markerLatLng = { lat: 26.9124, lng: 75.7873 };
let mapCenter = { lat: 26.9124, lng: 75.7873, zoom: 13 };
let mapInitCount = 0;

const sandbox = {
  window: {
    location: { protocol: 'http:', origin: 'http://127.0.0.1:8000', href: '', replace(u) { this.href = u; } },
    addEventListener() {},
    naariToast: { info() {}, success() {}, error() {} }
  },
  document: {
    getElementById(id) { return elements[id] || makeEl(id); },
    querySelector(sel) { return null; },
    querySelectorAll(sel) {
      if (sel === '.addr-label-btn') return labelBtns;
      if (sel === '.payment-option-label') return [];
      if (sel === 'input[name="payment_method"]') return [];
      return [];
    },
    addEventListener(type, fn) {
      if (type === 'DOMContentLoaded') domReadyCallback = fn;
    },
    createElement(tag) { return makeEl('dyn-' + Math.random()); }
  },
  navigator: {
    geolocation: {
      getCurrentPosition(success) {
        success({ coords: { latitude: 26.915, longitude: 75.801 } });
      }
    }
  },
  localStorage: {
    getItem(k) { return storage[k] || null; },
    setItem(k, v) { storage[k] = String(v); },
    removeItem(k) { delete storage[k]; }
  },
  sessionStorage: {
    getItem(k) { return sessionStore[k] || null; },
    setItem(k, v) { sessionStore[k] = String(v); },
    removeItem(k) { delete sessionStore[k]; }
  },
  FormData: class {
    constructor() {
      this.map = {
        name: elements['cust-name'].value,
        phone: elements['cust-phone'].value,
        email: elements['cust-email'].value,
        house_no: elements['cust-house-no'].value,
        street_area: elements['cust-street-area'].value,
        address_line1: elements['cust-address1'].value,
        address_line2: elements['cust-address2'].value,
        city: elements['cust-city'].value,
        state: elements['cust-state'].value,
        pincode: elements['cust-pincode'].value,
        latitude: elements['cust-lat'].value,
        longitude: elements['cust-lng'].value,
        location_summary: elements['cust-location-summary'].value,
        address_label: elements['cust-address-label'].value
      };
    }
    get(k) { return this.map[k] ?? ''; }
  },
  L: {
    map(id, opts) {
      mapInitCount += 1;
      mapCenter = { lat: opts.center[0], lng: opts.center[1], zoom: opts.zoom };
      return {
        on() {},
        getZoom() { return mapCenter.zoom; },
        setView(center, zoom) { mapCenter = { lat: center[0], lng: center[1], zoom }; },
        invalidateSize() {}
      };
    },
    tileLayer() { return { addTo() {} }; },
    marker(coords) {
      markerLatLng = { lat: coords[0], lng: coords[1] };
      return {
        addTo() { return this; },
        on() {},
        setLatLng(c) { markerLatLng = { lat: c[0], lng: c[1] }; },
        getLatLng() { return markerLatLng; }
      };
    }
  },
  fetch: async (url, opts = {}) => {
    const u = String(url);
    if (u.includes('/api/auth/me')) {
      return {
        ok: true, status: 200,
        headers: { get: () => 'application/json' },
        text: async () => JSON.stringify({ ok: true, user: { id: 1, name: 'Ananya Sharma', email: 'ananya@example.com', phone: '9876543210' } })
      };
    }
    if (u.includes('/api/config')) {
      return {
        ok: true, status: 200,
        headers: { get: () => 'application/json' },
        text: async () => JSON.stringify({ ok: true, cod_enabled: true })
      };
    }
    if (u.includes('/api/customer/addresses')) {
      return {
        ok: true, status: 200,
        headers: { get: () => 'application/json' },
        text: async () => JSON.stringify({
          ok: true,
          addresses: [
            {
              id: 10,
              name: 'Ananya <Home>',
              phone: '9876543210',
              house_no: 'Flat 301',
              street_area: 'Bapu Nagar',
              address_line1: 'Flat 301, Bapu Nagar',
              address_line2: 'Near Central Park',
              city: 'Jaipur',
              state: 'Rajasthan',
              pincode: '302015',
              latitude: 26.8912,
              longitude: 75.8091,
              location_summary: 'Bapu Nagar, Jaipur, Rajasthan',
              address_label: 'Work',
              is_default: 1
            },
            {
              id: 11,
              name: 'Ananya Parent Home',
              phone: '9876500001',
              house_no: '',
              street_area: '',
              address_line1: 'Plot 12, Malviya Nagar',
              address_line2: '',
              city: 'Jaipur',
              state: 'Rajasthan',
              pincode: '302017',
              latitude: null,
              longitude: null,
              location_summary: '',
              address_label: 'Home',
              is_default: 0
            }
          ]
        })
      };
    }
    if (u.includes('/api/address/pincode/')) {
      return {
        ok: true, status: 200,
        headers: { get: () => 'application/json' },
        text: async () => JSON.stringify({ ok: true, pincode: '302015', district: 'Jaipur', state: 'Rajasthan', allowed_states: ['Rajasthan'], post_offices: ['Bapu Nagar S.O'] })
      };
    }
    if (u.includes('/api/address/validate')) {
      const body = JSON.parse(opts.body || '{}');
      return {
        ok: true, status: 200,
        headers: { get: () => 'application/json' },
        text: async () => JSON.stringify({
          ok: true,
          address: body.address,
          addresses: [
            { ...body.address, id: 12, is_default: 1 }
          ]
        })
      };
    }
    return { ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => '{}' };
  },
  getCart: () => [{ id: 'indigo', title: 'Neelika Kurta', price: 2199, size: 'M', qty: 1 }],
  getCartTotal: () => 2199,
  formatPrice: (n) => '₹' + n,
  updateHeaderBagCount: () => {},
  getActiveCoupon: () => null,
  setActiveCoupon: () => {},
  getUserSession: () => ({ token: 'tok', user: { id: 1, name: 'Ananya Sharma', email: 'ananya@example.com', phone: '9876543210' } }),
  setUserSession: () => {},
  clearUserSession: () => {},
  getCustomerAuthHeaders: (h = {}) => ({ ...h, Authorization: 'Bearer tok' }),
  getToast: () => ({ info() {}, success() {}, error() {} }),
  setTimeout: (fn) => { fn(); return 1; },
  clearTimeout: () => {},
  console,
  Number, String, Boolean, Array, Object, Set, JSON, Math, RegExp, Date, Error, Promise, encodeURIComponent
};

vm.createContext(sandbox);
vm.runInContext(inlineCode, sandbox);

(async () => {
  // 1. Run DOMContentLoaded lifecycle
  await domReadyCallback();

  // Map initialized exactly once; calling initDeliveryMap again must not re-create map
  sandbox.initDeliveryMap();
  if (mapInitCount !== 1) throw new Error('Expected mapInitCount === 1, got ' + mapInitCount);

  // Calling setup functions again must not attach duplicate click listeners
  sandbox.setupAddressFormControls();
  sandbox.setupGeolocationButton();
  sandbox.setupAddressAutocomplete();
  if ((elements['confirm-address-btn'].listeners.click || []).length !== 1) {
    throw new Error('Duplicate click listener on confirm-address-btn');
  }
  if ((elements['use-current-location-btn'].listeners.click || []).length !== 1) {
    throw new Error('Duplicate click listener on use-current-location-btn');
  }

  // Default saved address should have auto-filled split fields, label, and map coordinates
  if (elements['cust-house-no'].value !== 'Flat 301') throw new Error('Default house_no not filled');
  if (elements['cust-street-area'].value !== 'Bapu Nagar') throw new Error('Default street_area not filled');
  if (elements['cust-address-label'].value !== 'Work') throw new Error('Default address_label not filled');
  if (elements['cust-lat'].value !== '26.891200' || elements['cust-lng'].value !== '75.809100') {
    throw new Error('Default saved address coordinates not restored');
  }
  // HTML escaping check on saved address chips
  if (!elements['saved-addresses-chips'].innerHTML.includes('Ananya &lt;Home&gt;')) {
    throw new Error('Saved address chip did not escape HTML');
  }

  // 2. Click second saved address chip (legacy address without house_no/street_area or coordinates)
  currentChips[1].dispatchEvent('click');
  if (elements['cust-house-no'].value !== 'Plot 12' || elements['cust-street-area'].value !== 'Malviya Nagar') {
    throw new Error('Legacy saved address did not derive split fields: ' + elements['cust-house-no'].value + ' / ' + elements['cust-street-area'].value);
  }
  if (elements['cust-lat'].value !== '' || elements['cust-lng'].value !== '') {
    throw new Error('Selecting address without coordinates did not clear stale coordinates');
  }

  // 3. Click confirm-address-btn and verify handleConfirmAddress runs and updates chips
  elements['cust-lat'].value = '26.854300';
  elements['cust-lng'].value = '75.812300';
  elements['confirm-address-btn'].dispatchEvent('click');
  await new Promise(r => setImmediate(r));
  if (elements['address-confirmed-badge'].classList.contains('hidden')) {
    throw new Error('Confirm address button did not mark address as confirmed');
  }

  // 4. Test restoreCheckoutFormDraft restores split fields, label, and map coordinates
  elements['cust-house-no'].value = '';
  elements['cust-street-area'].value = '';
  elements['cust-address1'].value = '';
  elements['cust-lat'].value = '';
  elements['cust-lng'].value = '';
  elements['cust-location-summary'].value = '';
  elements['cust-address-label'].value = 'Home';
  sessionStore['naari_checkout_draft_v1'] = JSON.stringify({
    name: 'Draft User',
    phone: '9876543210',
    email: 'draft@example.com',
    house_no: 'Villa 9',
    street_area: 'C-Scheme',
    address_line1: 'Villa 9, C-Scheme',
    city: 'Jaipur',
    state: 'Rajasthan',
    pincode: '302001',
    latitude: 26.9124,
    longitude: 75.7873,
    location_summary: 'C-Scheme, Jaipur',
    address_label: 'Other'
  });
  sandbox.restoreCheckoutFormDraft();
  if (elements['cust-house-no'].value !== 'Villa 9' || elements['cust-street-area'].value !== 'C-Scheme') {
    throw new Error('restoreCheckoutFormDraft did not restore split fields');
  }
  if (elements['cust-address-label'].value !== 'Other') {
    throw new Error('restoreCheckoutFormDraft did not restore address_label');
  }
  if (elements['cust-lat'].value !== '26.912400' || elements['cust-lng'].value !== '75.787300') {
    throw new Error('restoreCheckoutFormDraft did not restore coordinates');
  }
  if (elements['cust-location-summary'].value !== 'C-Scheme, Jaipur') {
    throw new Error('restoreCheckoutFormDraft did not restore location_summary');
  }
})().catch(err => {
  console.error(err);
  process.exit(1);
});
"""
        node_res = subprocess.run(
            [node_bin, "-e", node_test_script],
            cwd=base_dir,
            capture_output=True,
            text=True
        )
        assert node_res.returncode == 0, f"Checkout JS wiring harness failed:\nSTDOUT: {node_res.stdout}\nSTDERR: {node_res.stderr}"

    print(" [PASS] 15. Checkout Address/Map Lifecycle Wiring, Saved-Address Chips & Draft Coordinate Restoration Verified!")
    passed += 1

    # 16. Order Cancellation Stock & Coupon Restoration Regression Suite (COD, Paid Razorpay, Unpaid Razorpay, Idempotency & Admin/Customer Routes)
    total += 1
    cancel_test_passkey = "TestCancelAdminSecret_2026!"
    cancel_rzp_key_id = "rzp_test_CancelSuiteKey123"
    cancel_rzp_secret = "CancelSuiteRazorpaySecret_987654"

    def _get_coupon_used_count(code_str):
        conn_chk = server.get_db()
        cur_chk = conn_chk.cursor()
        cur_chk.execute("SELECT used_count FROM coupons WHERE UPPER(code) = UPPER(?)", (code_str,))
        row_chk = cur_chk.fetchone()
        conn_chk.close()
        return int(row_chk["used_count"]) if row_chk else 0

    with patch.dict(os.environ, {
        "ADMIN_SECRET_KEY": cancel_test_passkey,
        "RAZORPAY_KEY_ID": cancel_rzp_key_id,
        "RAZORPAY_KEY_SECRET": cancel_rzp_secret,
        "RAZORPAY_ENABLED": "1",
        "DISABLE_EXTERNAL_GEOCODING": "1"
    }):
        cancel_client = server.app.test_client()
        admin_hdrs = {"X-Admin-Passkey": cancel_test_passkey}

        # Register an isolated test customer for cancellation tests
        cancel_email = f"cancel.suite.{os.urandom(3).hex()}@example.com"
        reg_c = cancel_client.post("/api/auth/register", json={
            "name": "Meera Cancellation Test",
            "email": cancel_email,
            "phone": "9876501234",
            "password": "CancelSuitePass123!"
        })
        assert reg_c.status_code == 200 and reg_c.get_json().get("ok") is True
        cust_hdrs = {"Authorization": f"Bearer {reg_c.get_json()['token']}"}

        # Set a known size-wise inventory on 'anarkali' so we can test depleting a size to 0 (soldOutSizes) and restoring it
        inv_resp = cancel_client.post("/api/admin/inventory/update", headers=admin_hdrs, json={
            "id": "anarkali",
            "size_stock": {"XS": 0, "S": 2, "M": 5, "L": 4, "XL": 3, "XXL": 0}
        })
        assert inv_resp.status_code == 200 and inv_resp.get_json()["stock"] == 14

        prod_before = server.get_product_from_db("anarkali")
        assert prod_before["stock"] == 14
        assert prod_before["sizeStock"]["S"] == 2
        assert "S" not in prod_before["soldOutSizes"]
        coupon_before = _get_coupon_used_count("NAARI10")

        # A. Place COD order that buys all 2 units of size S (depleting size S to 0 -> soldOutSizes) with coupon NAARI10
        cod_create = cancel_client.post("/api/create-cod-order", headers=cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "anarkali", "qty": 2, "size": "S", "color": "Emerald"}],
            "coupon_code": "NAARI10"
        })
        assert cod_create.status_code == 200 and cod_create.get_json().get("ok") is True
        cod_cancel_oid = cod_create.get_json()["order_id"]

        prod_after_cod = server.get_product_from_db("anarkali")
        assert prod_after_cod["stock"] == 12, f"Expected total stock 12 after COD order, got {prod_after_cod['stock']}"
        assert prod_after_cod["sizeStock"]["S"] == 0, f"Expected size S stock 0 after COD order, got {prod_after_cod['sizeStock']['S']}"
        assert "S" in prod_after_cod["soldOutSizes"], "Depleted size S must be added to soldOutSizes"
        assert _get_coupon_used_count("NAARI10") == coupon_before + 1, "Coupon used_count must increment on COD order"

        # Cancel COD order via customer endpoint -> must restore total stock, per-size stock, soldOutSizes, and coupon used_count
        cust_cancel_1 = cancel_client.post("/api/customer/orders/cancel", headers=cust_hdrs, json={
            "order_id": cod_cancel_oid,
            "reason": "Ordered wrong size"
        })
        assert cust_cancel_1.status_code == 200 and cust_cancel_1.get_json().get("order_status") == "cancelled"

        prod_after_cust_cancel = server.get_product_from_db("anarkali")
        assert prod_after_cust_cancel["stock"] == 14, f"Expected stock restored to 14, got {prod_after_cust_cancel['stock']}"
        assert prod_after_cust_cancel["sizeStock"]["S"] == 2, f"Expected size S restored to 2, got {prod_after_cust_cancel['sizeStock']['S']}"
        assert "S" not in prod_after_cust_cancel["soldOutSizes"], "Restored size S must be removed from soldOutSizes"
        assert _get_coupon_used_count("NAARI10") == coupon_before, "Coupon used_count must be restored on COD cancellation"

        # B. Repeated cancellation idempotency (customer repeat + admin repeat + reopen prevention)
        cust_cancel_2 = cancel_client.post("/api/customer/orders/cancel", headers=cust_hdrs, json={
            "order_id": cod_cancel_oid,
            "reason": "Duplicate cancel click"
        })
        assert cust_cancel_2.status_code == 400, f"Expected 400 on repeated customer cancel, got {cust_cancel_2.status_code}"

        admin_cancel_repeat = cancel_client.post("/api/admin/orders/status", headers=admin_hdrs, json={
            "order_id": cod_cancel_oid,
            "order_status": "cancelled"
        })
        assert admin_cancel_repeat.status_code == 200

        admin_reopen_attempt = cancel_client.post("/api/admin/orders/status", headers=admin_hdrs, json={
            "order_id": cod_cancel_oid,
            "order_status": "confirmed"
        })
        assert admin_reopen_attempt.status_code == 400, "Cancelled order must not be reopenable to prevent double stock restoration"

        prod_after_repeats = server.get_product_from_db("anarkali")
        assert prod_after_repeats["stock"] == 14 and prod_after_repeats["sizeStock"]["S"] == 2, (
            "Repeated cancellation requests must never restore stock twice"
        )
        assert _get_coupon_used_count("NAARI10") == coupon_before

        # C. Admin cancellation of a COD order (/api/admin/orders/status) restores stock & coupon usage once
        cod_create_2 = cancel_client.post("/api/create-cod-order", headers=cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "anarkali", "qty": 3, "size": "XL", "color": "Emerald"}],
            "coupon_code": "NAARI10"
        })
        assert cod_create_2.status_code == 200
        cod_admin_oid = cod_create_2.get_json()["order_id"]

        prod_mid_admin = server.get_product_from_db("anarkali")
        assert prod_mid_admin["stock"] == 11 and prod_mid_admin["sizeStock"]["XL"] == 0 and "XL" in prod_mid_admin["soldOutSizes"]
        assert _get_coupon_used_count("NAARI10") == coupon_before + 1

        admin_cancel_1 = cancel_client.post("/api/admin/orders/status", headers=admin_hdrs, json={
            "order_id": cod_admin_oid,
            "order_status": "cancelled"
        })
        assert admin_cancel_1.status_code == 200 and admin_cancel_1.get_json().get("ok") is True

        prod_after_admin_cancel = server.get_product_from_db("anarkali")
        assert prod_after_admin_cancel["stock"] == 14 and prod_after_admin_cancel["sizeStock"]["XL"] == 3
        assert "XL" not in prod_after_admin_cancel["soldOutSizes"]
        assert _get_coupon_used_count("NAARI10") == coupon_before

        # D. Paid Razorpay order cancellation restores stock & coupon usage
        mock_paid_rzp_id = "order_RzpCancelPaid001"
        mock_rzp_resp = MagicMock()
        mock_rzp_resp.status_code = 200
        mock_rzp_resp.json.return_value = {
            "id": mock_paid_rzp_id,
            "entity": "order",
            "amount": 359800,
            "currency": "INR",
            "status": "created"
        }
        with patch("server.requests.post", return_value=mock_rzp_resp):
            rzp_paid_create = cancel_client.post("/api/create-order", headers=cust_hdrs, json={
                "customer": test_customer,
                "items": [{"id": "anarkali", "qty": 2, "size": "M", "color": "Emerald"}],
                "coupon_code": "NAARI10"
            })
            assert rzp_paid_create.status_code == 200
            rzp_paid_oid = rzp_paid_create.get_json()["order_id"]

        # Stock must NOT be deducted before Razorpay payment verification
        assert server.get_product_from_db("anarkali")["stock"] == 14
        assert _get_coupon_used_count("NAARI10") == coupon_before

        paid_pay_id = "pay_RzpCancelPaid001"
        paid_sig = hmac.new(
            cancel_rzp_secret.encode("utf-8"),
            f"{mock_paid_rzp_id}|{paid_pay_id}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        ver_resp = cancel_client.post("/api/verify-payment", headers=cust_hdrs, json={
            "order_id": rzp_paid_oid,
            "razorpay_order_id": mock_paid_rzp_id,
            "razorpay_payment_id": paid_pay_id,
            "razorpay_signature": paid_sig
        })
        assert ver_resp.status_code == 200 and ver_resp.get_json().get("status") == "paid"

        prod_after_rzp_paid = server.get_product_from_db("anarkali")
        assert prod_after_rzp_paid["stock"] == 12 and prod_after_rzp_paid["sizeStock"]["M"] == 3
        assert _get_coupon_used_count("NAARI10") == coupon_before + 1

        # Cancel paid Razorpay order -> must restore stock to 14 and M to 5, and decrement coupon used_count
        rzp_paid_cancel = cancel_client.post("/api/customer/orders/cancel", headers=cust_hdrs, json={
            "order_id": rzp_paid_oid,
            "reason": "Change of mind after payment"
        })
        assert rzp_paid_cancel.status_code == 200
        prod_after_rzp_paid_cancel = server.get_product_from_db("anarkali")
        assert prod_after_rzp_paid_cancel["stock"] == 14 and prod_after_rzp_paid_cancel["sizeStock"]["M"] == 5
        assert _get_coupon_used_count("NAARI10") == coupon_before

        # E. Unpaid pending_payment / failed Razorpay order cancellation MUST NEVER restore/inflate stock
        mock_unpaid_rzp_id_1 = "order_RzpCancelUnpaid001"
        mock_rzp_resp.json.return_value["id"] = mock_unpaid_rzp_id_1
        with patch("server.requests.post", return_value=mock_rzp_resp):
            rzp_unpaid_1 = cancel_client.post("/api/create-order", headers=cust_hdrs, json={
                "customer": test_customer,
                "items": [{"id": "anarkali", "qty": 2, "size": "S", "color": "Emerald"}],
                "coupon_code": "NAARI10"
            })
            assert rzp_unpaid_1.status_code == 200
            unpaid_oid_1 = rzp_unpaid_1.get_json()["order_id"]

        # Cancel unpaid pending_payment order via customer route -> stock must remain 14 (not become 16!)
        unpaid_cust_cancel = cancel_client.post("/api/customer/orders/cancel", headers=cust_hdrs, json={
            "order_id": unpaid_oid_1,
            "reason": "Abandoned payment"
        })
        assert unpaid_cust_cancel.status_code == 200
        prod_after_unpaid_1 = server.get_product_from_db("anarkali")
        assert prod_after_unpaid_1["stock"] == 14 and prod_after_unpaid_1["sizeStock"]["S"] == 2, (
            f"Unpaid pending_payment cancellation must never restore stock! Got {prod_after_unpaid_1}"
        )
        assert _get_coupon_used_count("NAARI10") == coupon_before

        # Create a second unpaid Razorpay order, mark payment failed, then cancel via admin -> stock must remain 14
        mock_unpaid_rzp_id_2 = "order_RzpCancelUnpaid002"
        mock_rzp_resp.json.return_value["id"] = mock_unpaid_rzp_id_2
        with patch("server.requests.post", return_value=mock_rzp_resp):
            rzp_unpaid_2 = cancel_client.post("/api/create-order", headers=cust_hdrs, json={
                "customer": test_customer,
                "items": [{"id": "anarkali", "qty": 4, "size": "L", "color": "Emerald"}],
                "coupon_code": "NAARI10"
            })
            assert rzp_unpaid_2.status_code == 200
            unpaid_oid_2 = rzp_unpaid_2.get_json()["order_id"]

        fail_mark = cancel_client.post("/api/payment-failed", headers=cust_hdrs, json={
            "order_id": unpaid_oid_2,
            "razorpay_order_id": mock_unpaid_rzp_id_2,
            "reason": "Payment declined by bank"
        })
        assert fail_mark.status_code == 200
        unpaid_admin_cancel = cancel_client.post("/api/admin/orders/status", headers=admin_hdrs, json={
            "order_id": unpaid_oid_2,
            "order_status": "cancelled"
        })
        assert unpaid_admin_cancel.status_code == 200
        prod_after_unpaid_2 = server.get_product_from_db("anarkali")
        assert prod_after_unpaid_2["stock"] == 14 and prod_after_unpaid_2["sizeStock"]["L"] == 4, (
            f"Failed Razorpay order cancellation must never restore stock! Got {prod_after_unpaid_2}"
        )
        assert _get_coupon_used_count("NAARI10") == coupon_before

        # F. Atomic transaction rollback check: if stock restoration raises, order_status must remain 'confirmed'
        cod_create_atomic = cancel_client.post("/api/create-cod-order", headers=cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "anarkali", "qty": 1, "size": "S", "color": "Emerald"}]
        })
        assert cod_create_atomic.status_code == 200
        atomic_oid = cod_create_atomic.get_json()["order_id"]
        assert server.get_product_from_db("anarkali")["stock"] == 13

        with patch("server.restore_order_stock", side_effect=RuntimeError("Simulated DB failure")):
            failed_cancel = cancel_client.post("/api/customer/orders/cancel", headers=cust_hdrs, json={
                "order_id": atomic_oid,
                "reason": "Should rollback on error"
            })
            assert failed_cancel.status_code == 500

        det_atomic = cancel_client.get(f"/api/order-details?order_id={atomic_oid}", headers=cust_hdrs).get_json()
        assert det_atomic["order"]["order_status"] == "confirmed", (
            "Order status must roll back to 'confirmed' if stock restoration fails inside transaction"
        )
        # Now cancel normally and verify clean restoration back to 14
        ok_cancel = cancel_client.post("/api/customer/orders/cancel", headers=cust_hdrs, json={
            "order_id": atomic_oid,
            "reason": "Clean cancel after rollback"
        })
        assert ok_cancel.status_code == 200
        assert server.get_product_from_db("anarkali")["stock"] == 14

    print(" [PASS] 16. Order Cancellation Stock & Coupon Restoration (COD, Paid/Unpaid Razorpay, Idempotency & Atomic Rollback) Verified!")
    passed += 1

    # 17. Duplicate Cart Lines (Same Product/Size across Colors), Per-Size Validation, Corrupt Stock Safety & Concurrent Stock Deduction
    total += 1
    import threading
    dup_admin_key = "TestDupLineAdminSecret_2026!"
    dup_rzp_id = "rzp_test_DupLineKey123"
    dup_rzp_secret = "DupLineRazorpaySecret_987654"

    with patch.dict(os.environ, {
        "ADMIN_SECRET_KEY": dup_admin_key,
        "RAZORPAY_KEY_ID": dup_rzp_id,
        "RAZORPAY_KEY_SECRET": dup_rzp_secret,
        "RAZORPAY_ENABLED": "1",
        "DISABLE_EXTERNAL_GEOCODING": "1"
    }):
        dup_client = server.app.test_client()
        dup_admin_hdrs = {"X-Admin-Passkey": dup_admin_key}

        dup_email = f"dupline.suite.{os.urandom(3).hex()}@example.com"
        reg_dup = dup_client.post("/api/auth/register", json={
            "name": "Riya Inventory Test",
            "email": dup_email,
            "phone": "9876504321",
            "password": "DupLineSuitePass123!"
        })
        assert reg_dup.status_code == 200 and reg_dup.get_json().get("ok") is True
        dup_cust_hdrs = {"Authorization": f"Bearer {reg_dup.get_json()['token']}"}

        # Configure 'anarkali' stock: S=3, M=4, L=2, XL=2 (total=11)
        inv_set = dup_client.post("/api/admin/inventory/update", headers=dup_admin_hdrs, json={
            "id": "anarkali",
            "size_stock": {"XS": 0, "S": 3, "M": 4, "L": 2, "XL": 2, "XXL": 0}
        })
        assert inv_set.status_code == 200 and inv_set.get_json()["stock"] == 11

        # A. Two cart lines with same product & size ('anarkali', 'S') but different colors ('Marigold' qty=2 + 'Emerald' qty=2 = 4 > 3) -> MUST REJECT (400)
        exceed_same_size_items = [
            {"id": "anarkali", "size": "S", "color": "Marigold", "qty": 2},
            {"id": "anarkali", "size": "S", "color": "Emerald", "qty": 2}
        ]
        rej_cod = dup_client.post("/api/create-cod-order", headers=dup_cust_hdrs, json={
            "customer": test_customer,
            "items": exceed_same_size_items
        })
        assert rej_cod.status_code == 400 and rej_cod.get_json().get("ok") is False, (
            f"Expected 400 when duplicate (product, size) lines across colors exceed size stock, got {rej_cod.status_code}: {rej_cod.get_json()}"
        )
        assert "Only 3 unit(s)" in rej_cod.get_json().get("error", "") and "Size S" in rej_cod.get_json().get("error", "")

        rej_rzp = dup_client.post("/api/create-order", headers=dup_cust_hdrs, json={
            "customer": test_customer,
            "items": exceed_same_size_items
        })
        assert rej_rzp.status_code == 400 and rej_rzp.get_json().get("ok") is False
        assert server.get_product_from_db("anarkali")["sizeStock"]["S"] == 3, "Rejected order must not alter stock"

        # B. Combined quantity within available stock ('anarkali', 'S': 'Marigold' qty=1 + 'Emerald' qty=2 = 3 <= 3) -> MUST ACCEPT (200)
        within_same_size_items = [
            {"id": "anarkali", "size": "S", "color": "Marigold", "qty": 1},
            {"id": "anarkali", "size": "S", "color": "Emerald", "qty": 2}
        ]
        acc_cod = dup_client.post("/api/create-cod-order", headers=dup_cust_hdrs, json={
            "customer": test_customer,
            "items": within_same_size_items
        })
        assert acc_cod.status_code == 200 and acc_cod.get_json().get("ok") is True, (
            f"Expected 200 when combined (product, size) qty is within stock, got {acc_cod.status_code}: {acc_cod.get_json()}"
        )
        acc_oid = acc_cod.get_json()["order_id"]
        prod_after_acc = server.get_product_from_db("anarkali")
        assert prod_after_acc["sizeStock"]["S"] == 0 and "S" in prod_after_acc["soldOutSizes"]
        assert prod_after_acc["stock"] == 8

        # Verify both color lines were preserved on the order, then cancel to restore S=3
        acc_det = dup_client.get(f"/api/order-details?order_id={acc_oid}", headers=dup_cust_hdrs).get_json()
        assert len(acc_det["order"]["items"]) == 2
        assert [it["color"] for it in acc_det["order"]["items"]] == ["Marigold", "Emerald"]
        cancel_acc = dup_client.post("/api/customer/orders/cancel", headers=dup_cust_hdrs, json={"order_id": acc_oid})
        assert cancel_acc.status_code == 200
        assert server.get_product_from_db("anarkali")["sizeStock"]["S"] == 3

        # C. Different sizes validated against each size's own stock (S=3, M=4)
        # S qty=3 + M qty=5 (exceeds M=4) -> MUST REJECT
        diff_size_exceed = [
            {"id": "anarkali", "size": "S", "color": "Marigold", "qty": 3},
            {"id": "anarkali", "size": "M", "color": "Emerald", "qty": 5}
        ]
        rej_diff = dup_client.post("/api/create-cod-order", headers=dup_cust_hdrs, json={
            "customer": test_customer,
            "items": diff_size_exceed
        })
        assert rej_diff.status_code == 400 and "Size M" in rej_diff.get_json().get("error", "")

        # S qty=2 + M qty=3 (both within S=3 and M=4) -> MUST ACCEPT
        diff_size_ok = [
            {"id": "anarkali", "size": "S", "color": "Marigold", "qty": 2},
            {"id": "anarkali", "size": "M", "color": "Emerald", "qty": 3}
        ]
        acc_diff = dup_client.post("/api/create-cod-order", headers=dup_cust_hdrs, json={
            "customer": test_customer,
            "items": diff_size_ok
        })
        assert acc_diff.status_code == 200 and acc_diff.get_json().get("ok") is True
        diff_oid = acc_diff.get_json()["order_id"]
        prod_after_diff = server.get_product_from_db("anarkali")
        assert prod_after_diff["sizeStock"]["S"] == 1 and prod_after_diff["sizeStock"]["M"] == 1 and prod_after_diff["stock"] == 6
        dup_client.post("/api/customer/orders/cancel", headers=dup_cust_hdrs, json={"order_id": diff_oid})
        assert server.get_product_from_db("anarkali")["stock"] == 11

        # D. Invalid or missing stock data / invalid quantities -> MUST FAIL SAFELY (never silently clamp)
        for bad_qty in (0, -2, "abc", None, True):
            bad_q_resp = dup_client.post("/api/create-cod-order", headers=dup_cust_hdrs, json={
                "customer": test_customer,
                "items": [{"id": "anarkali", "size": "S", "color": "Marigold", "qty": bad_qty}]
            })
            assert bad_q_resp.status_code == 400, f"Invalid qty {bad_qty!r} must be rejected with 400"

        # Direct deduct_order_stock call with oversold or invalid qty must raise ValueError and not clamp to 0
        try:
            server.deduct_order_stock([
                {"id": "anarkali", "size": "L", "color": "Marigold", "qty": 2},
                {"id": "anarkali", "size": "L", "color": "Emerald", "qty": 1}
            ])
            raise AssertionError("deduct_order_stock must raise ValueError when combined (id, size) qty exceeds stock")
        except ValueError as ve:
            assert "Size L" in str(ve)
        assert server.get_product_from_db("anarkali")["sizeStock"]["L"] == 2, "Failed deduct_order_stock must roll back cleanly"

        # Corrupt size_stock_json in DB -> must fail safely with 400 and restore cleanly
        conn_corrupt = server.get_db()
        cur_corrupt = conn_corrupt.cursor()
        cur_corrupt.execute("SELECT size_stock_json, stock FROM products WHERE id = 'anarkali'")
        saved_row = dict(cur_corrupt.fetchone())
        try:
            cur_corrupt.execute("UPDATE products SET size_stock_json = '{corrupt_json' WHERE id = 'anarkali'")
            conn_corrupt.commit()
            corrupt_resp = dup_client.post("/api/create-cod-order", headers=dup_cust_hdrs, json={
                "customer": test_customer,
                "items": [{"id": "anarkali", "size": "S", "color": "Marigold", "qty": 1}]
            })
            assert corrupt_resp.status_code == 400 and "invalid" in corrupt_resp.get_json().get("error", "").lower()

            cur_corrupt.execute("UPDATE products SET size_stock_json = ? WHERE id = 'anarkali'", (json.dumps({"S": -1, "M": 4}),))
            conn_corrupt.commit()
            neg_ss_resp = dup_client.post("/api/create-cod-order", headers=dup_cust_hdrs, json={
                "customer": test_customer,
                "items": [{"id": "anarkali", "size": "S", "color": "Marigold", "qty": 1}]
            })
            assert neg_ss_resp.status_code == 400 and "invalid" in neg_ss_resp.get_json().get("error", "").lower()
        finally:
            cur_corrupt.execute(
                "UPDATE products SET size_stock_json = ?, stock = ? WHERE id = 'anarkali'",
                (saved_row["size_stock_json"], saved_row["stock"])
            )
            conn_corrupt.commit()
            conn_corrupt.close()

        # E. Concurrent stock deduction across multiple threads for the last 2 units of ('anarkali', 'XL')
        # 5 concurrent threads each try to order qty=1 of ('anarkali', 'XL') where XL stock == 2.
        # Exactly 2 must succeed (200) and 3 must be rejected (400), leaving XL stock == 0 (never negative).
        barrier = threading.Barrier(5)
        thread_results = []
        results_lock = threading.Lock()

        def _concurrent_cod_worker(idx):
            t_client = server.app.test_client()
            barrier.wait(timeout=5)
            r = t_client.post("/api/create-cod-order", headers=dup_cust_hdrs, json={
                "customer": test_customer,
                "items": [{"id": "anarkali", "size": "XL", "color": f"Color-{idx}", "qty": 1}]
            })
            with results_lock:
                thread_results.append((r.status_code, r.get_json()))

        threads = [threading.Thread(target=_concurrent_cod_worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(thread_results) == 5, f"Expected 5 thread responses, got {len(thread_results)}"
        success_codes = [code for code, _ in thread_results if code == 200]
        reject_codes = [code for code, _ in thread_results if code == 400]
        assert len(success_codes) == 2 and len(reject_codes) == 3, (
            f"Expected exactly 2 successes and 3 rejections for 2 units of XL stock across 5 concurrent orders, got: {thread_results}"
        )
        prod_after_conc = server.get_product_from_db("anarkali")
        assert prod_after_conc["sizeStock"]["XL"] == 0 and "XL" in prod_after_conc["soldOutSizes"]
        assert prod_after_conc["stock"] == 9

    print(" [PASS] 17. Duplicate Cart Lines (Same Product/Size across Colors), Per-Size Validation, Corrupt Stock Safety & Concurrent Stock Deduction Verified!")
    passed += 1

    # 18. Coupon Eligibility, Discount Calculation, Tampering Resistance & Cart-Change Rejection Suite
    total += 1
    cp_admin_key = "TestCouponSuiteAdminSecret_2026!"
    cp_rzp_id = "rzp_test_CouponSuiteKey123"
    cp_rzp_secret = "CouponSuiteRazorpaySecret_987654"

    with patch.dict(os.environ, {
        "ADMIN_SECRET_KEY": cp_admin_key,
        "RAZORPAY_KEY_ID": cp_rzp_id,
        "RAZORPAY_KEY_SECRET": cp_rzp_secret,
        "RAZORPAY_ENABLED": "1",
        "DISABLE_EXTERNAL_GEOCODING": "1"
    }):
        cp_client = server.app.test_client()
        cp_admin_hdrs = {"X-Admin-Passkey": cp_admin_key}

        cp_email = f"coupon.suite.{os.urandom(3).hex()}@example.com"
        reg_cp = cp_client.post("/api/auth/register", json={
            "name": "Aditi Coupon Test",
            "email": cp_email,
            "phone": "9876512340",
            "password": "CouponSuitePass123!"
        })
        assert reg_cp.status_code == 200 and reg_cp.get_json().get("ok") is True
        cp_cust_hdrs = {"Authorization": f"Bearer {reg_cp.get_json()['token']}"}

        # Ensure ample stock on 'short' (₹899), 'straight' (₹1299), and 'anarkali' (₹2499)
        cp_client.post("/api/admin/inventory/update", headers=cp_admin_hdrs, json={
            "id": "anarkali",
            "size_stock": {"XS": 5, "S": 10, "M": 10, "L": 10, "XL": 10, "XXL": 5}
        })
        cp_client.post("/api/admin/inventory/update", headers=cp_admin_hdrs, json={
            "id": "short",
            "size_stock": {"XS": 5, "S": 10, "M": 10, "L": 10, "XL": 10}
        })

        # A. Valid coupon & full rule metadata returned from /api/apply-coupon + shipping threshold check
        # 1 'short' kurti = ₹899 (< ₹999 threshold -> shipping ₹99). NAARI10 (min_order_value=999) must fail on ₹899!
        min_fail_apply = cp_client.post("/api/apply-coupon", json={
            "code": "NAARI10",
            "subtotal": 5000,  # tampered client subtotal must be ignored when items are provided!
            "items": [{"id": "short", "qty": 1, "size": "M", "color": "Indigo", "price": 5000}]
        })
        assert min_fail_apply.status_code == 400, (
            f"Expected 400 when trusted DB subtotal (899) is below NAARI10 min_order_value (999) despite tampered client subtotal=5000: {min_fail_apply.get_json()}"
        )
        assert "minimum order value" in min_fail_apply.get_json().get("error", "").lower()

        # 2 'short' kurtis = 2 * 899 = ₹1798 (>= ₹999 -> shipping ₹0). NAARI10 -> 10% = ₹180 -> final_total = ₹1618
        valid_apply = cp_client.post("/api/apply-coupon", json={
            "code": "NAARI10",
            "subtotal": 100,  # tampered low subtotal ignored
            "items": [{"id": "short", "qty": 2, "size": "M", "color": "Indigo", "price": 50}]
        })
        valid_apply_data = valid_apply.get_json()
        assert valid_apply.status_code == 200 and valid_apply_data.get("ok") is True
        assert valid_apply_data["subtotal"] == 1798
        assert valid_apply_data["discount_amount"] == 180
        assert valid_apply_data["shipping"] == 0
        assert valid_apply_data["final_total"] == 1618
        for required_rule_field in (
            "min_order_value", "max_discount", "applicable_categories",
            "applicable_products", "start_date", "expiry_date", "usage_limit",
            "used_count", "is_active", "free_shipping_threshold"
        ):
            assert required_rule_field in valid_apply_data, f"Missing '{required_rule_field}' in /api/apply-coupon response"

        # B. Maximum discount cap enforcement (NAARI10 max_discount=500; 3 * anarkali (2499) = 7497; 10% = 750 -> capped at 500)
        cap_apply = cp_client.post("/api/apply-coupon", json={
            "code": "NAARI10",
            "items": [{"id": "anarkali", "qty": 3, "size": "M", "color": "Emerald"}]
        })
        cap_data = cap_apply.get_json()
        assert cap_apply.status_code == 200 and cap_data["subtotal"] == 7497
        assert cap_data["discount_amount"] == 500, f"Expected max_discount cap of ₹500, got {cap_data['discount_amount']}"
        assert cap_data["final_total"] == 6997

        # C. Category / Product eligibility enforcement + mixed-bag eligible subtotal calculation
        cp_client.post("/api/admin/coupons", headers=cp_admin_hdrs, json={
            "code": "FESTIVE30",
            "discount_type": "percentage",
            "discount_value": 30,
            "min_order_value": 800,
            "max_discount": 1000,
            "usage_limit": 10,
            "applicable_categories": ["Anarkali"],
            "applicable_products": ["anarkali"],
            "expiry_date": "2028-12-31",
            "description": "30% off Anarkali only"
        })

        # Ineligible bag ('short' is Short Kurti) -> rejected on /api/apply-coupon, /api/create-cod-order, and /api/create-order
        inelig_apply = cp_client.post("/api/apply-coupon", json={
            "code": "FESTIVE30",
            "items": [{"id": "short", "qty": 2, "size": "M", "color": "Indigo"}]
        })
        assert inelig_apply.status_code == 400 and "not applicable" in inelig_apply.get_json().get("error", "").lower()

        inelig_cod = cp_client.post("/api/create-cod-order", headers=cp_cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "short", "qty": 2, "size": "M", "color": "Indigo"}],
            "coupon_code": "FESTIVE30"
        })
        assert inelig_cod.status_code == 400 and "not applicable" in inelig_cod.get_json().get("error", "").lower()

        # Mixed bag: 1 'short' (₹899, ineligible) + 1 'anarkali' (₹2499, eligible) -> subtotal=3398, discount=30% of 2499 = 750 (NOT 30% of 3398=1019)
        mixed_apply = cp_client.post("/api/apply-coupon", json={
            "code": "FESTIVE30",
            "items": [
                {"id": "short", "qty": 1, "size": "M", "color": "Indigo"},
                {"id": "anarkali", "qty": 1, "size": "M", "color": "Emerald"}
            ]
        }).get_json()
        assert mixed_apply["ok"] is True and mixed_apply["subtotal"] == 3398
        assert mixed_apply["discount_amount"] == 750, f"Expected discount on eligible item only (750), got {mixed_apply['discount_amount']}"
        assert mixed_apply["final_total"] == 2648

        # D. Expired, Disabled, and Usage-Limit-Exceeded coupons -> rejected across apply & order creation
        exp_create = cp_client.post("/api/admin/coupons", headers=cp_admin_hdrs, json={
            "code": "EXPIRED50",
            "discount_type": "fixed",
            "discount_value": 200,
            "min_order_value": 500,
            "usage_limit": 10,
            "expiry_date": "2020-01-01",
            "description": "Expired test coupon"
        })
        assert exp_create.status_code == 200
        exp_cod = cp_client.post("/api/create-cod-order", headers=cp_cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "short", "qty": 2, "size": "M", "color": "Indigo"}],
            "coupon_code": "EXPIRED50"
        })
        assert exp_cod.status_code == 400 and "expired" in exp_cod.get_json().get("error", "").lower()

        lim_create = cp_client.post("/api/admin/coupons", headers=cp_admin_hdrs, json={
            "code": "LIM1ONLY",
            "discount_type": "fixed",
            "discount_value": 150,
            "min_order_value": 500,
            "usage_limit": 1,
            "expiry_date": "2028-12-31",
            "description": "Single-use coupon"
        })
        assert lim_create.status_code == 200
        lim_use_1 = cp_client.post("/api/create-cod-order", headers=cp_cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "short", "qty": 1, "size": "M", "color": "Indigo"}],
            "coupon_code": "LIM1ONLY"
        })
        assert lim_use_1.status_code == 200
        # 1 'short' (₹899) < ₹999 free shipping threshold -> shipping = ₹99, discount = ₹150 -> total = 899 - 150 + 99 = ₹848
        assert lim_use_1.get_json()["subtotal"] == 899
        assert lim_use_1.get_json()["shipping"] == 99
        assert lim_use_1.get_json()["discount_amount"] == 150
        assert lim_use_1.get_json()["total_amount"] == 848

        # Second order with LIM1ONLY must be rejected because usage_limit=1 is now reached!
        lim_use_2 = cp_client.post("/api/create-cod-order", headers=cp_cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "short", "qty": 1, "size": "M", "color": "Indigo"}],
            "coupon_code": "LIM1ONLY"
        })
        assert lim_use_2.status_code == 400 and "limit" in lim_use_2.get_json().get("error", "").lower()

        # Disable FESTIVE30 and verify it is rejected on both COD and Razorpay order creation
        cp_client.post("/api/admin/coupons/toggle", headers=cp_admin_hdrs, json={"code": "FESTIVE30"})
        dis_cod = cp_client.post("/api/create-cod-order", headers=cp_cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "anarkali", "qty": 1, "size": "M", "color": "Emerald"}],
            "coupon_code": "FESTIVE30"
        })
        assert dis_cod.status_code == 400 and "inactive" in dis_cod.get_json().get("error", "").lower()

        dis_rzp = cp_client.post("/api/create-order", headers=cp_cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "anarkali", "qty": 1, "size": "M", "color": "Emerald"}],
            "coupon_code": "FESTIVE30"
        })
        assert dis_rzp.status_code == 400 and "inactive" in dis_rzp.get_json().get("error", "").lower()

        # E. Coupon becoming invalid after cart changes -> MUST REJECT order (never silently drop coupon & charge full price!)
        # Customer applies FESTIVE300 (min_order_value=2499) when bag had 2 straight kurtis (2598), then reduces qty to 1 (1299 < 2499)
        cart_changed_cod = cp_client.post("/api/create-cod-order", headers=cp_cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "straight", "qty": 1, "size": "M", "color": "Maroon"}],
            "coupon_code": "FESTIVE300",
            "subtotal": 2598,
            "discount_amount": 300,
            "total_amount": 2298
        })
        assert cart_changed_cod.status_code == 400, (
            f"Order with coupon that became invalid after cart reduction must be rejected with 400, got {cart_changed_cod.status_code}: {cart_changed_cod.get_json()}"
        )
        assert "minimum order value" in cart_changed_cod.get_json().get("error", "").lower()

        cart_changed_rzp = cp_client.post("/api/create-order", headers=cp_cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "straight", "qty": 1, "size": "M", "color": "Maroon"}],
            "coupon_code": "FESTIVE300"
        })
        assert cart_changed_rzp.status_code == 400 and "minimum order value" in cart_changed_rzp.get_json().get("error", "").lower()

        # Valid Razorpay order with FESTIVE300 (2 straight kurtis = 2598, ₹300 off -> 2298 INR = 229800 paise)
        mock_cp_rzp_resp = MagicMock()
        mock_cp_rzp_resp.status_code = 200
        mock_cp_rzp_resp.json.return_value = {
            "id": "order_RzpCouponValid001",
            "entity": "order",
            "amount": 229800,
            "currency": "INR",
            "status": "created"
        }
        with patch("server.requests.post", return_value=mock_cp_rzp_resp) as mocked_rzp_post:
            valid_rzp_cp = cp_client.post("/api/create-order", headers=cp_cust_hdrs, json={
                "customer": test_customer,
                "items": [{"id": "straight", "qty": 2, "size": "M", "color": "Maroon", "price": 100}],
                "coupon_code": "FESTIVE300",
                "subtotal": 200,
                "discount_amount": 190,
                "total_amount": 10
            })
            v_rzp_data = valid_rzp_cp.get_json()
            assert valid_rzp_cp.status_code == 200 and v_rzp_data["ok"] is True
            assert v_rzp_data["subtotal"] == 2598
            assert v_rzp_data["discount_amount"] == 300
            assert v_rzp_data["shipping"] == 0
            assert v_rzp_data["total_amount"] == 2298
            assert v_rzp_data["amount"] == 229800
            assert mocked_rzp_post.call_args[1]["json"]["amount"] == 229800

        # Clean up test coupons
        for tmp_code in ("FESTIVE30", "EXPIRED50", "LIM1ONLY"):
            cp_client.delete(f"/api/admin/coupons/{tmp_code}", headers=cp_admin_hdrs)

    print(" [PASS] 18. Coupon Eligibility, Discount Cap, Category/Product Rules, Tampering Resistance & Cart-Change Rejection Verified!")
    passed += 1

    # 19. Atomic Razorpay Payment Verification, Late-Callback Rejection & Concurrency Regression
    total += 1
    test_rzp_key_id = "rzp_test_AtomicVerifyKey123"
    test_rzp_key_secret = "rzp_test_AtomicVerifySecret987654"
    av_admin_key = "AtomicVerifyAdminKey_9988"
    with patch.dict(os.environ, {
        "ADMIN_SECRET_KEY": av_admin_key,
        "RAZORPAY_KEY_ID": test_rzp_key_id,
        "RAZORPAY_KEY_SECRET": test_rzp_key_secret,
        "RAZORPAY_ENABLED": "1",
        "DISABLE_EXTERNAL_GEOCODING": "1"
    }, clear=False):
        av_client = server.app.test_client()
        av_admin_hdrs = {"X-Admin-Passkey": av_admin_key}

        av_email = f"atomic.rzp.{os.urandom(3).hex()}@example.com"
        reg_av = av_client.post("/api/auth/register", json={
            "name": "Meera Atomic Verify",
            "email": av_email,
            "phone": "9876509876",
            "password": "AtomicVerifyPass123!"
        })
        assert reg_av.status_code == 200 and reg_av.get_json().get("ok") is True
        av_cust_hdrs = {"Authorization": f"Bearer {reg_av.get_json()['token']}"}

        # Helper to sign Razorpay (order_id|payment_id) with HMAC-SHA256
        def _sign_rzp(rzp_oid, rzp_pid):
            msg = f"{rzp_oid}|{rzp_pid}".encode("utf-8")
            return hmac.new(test_rzp_key_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

        # Helper to create a mocked Razorpay order
        _rzp_seq = [0]
        def _create_unpaid_rzp_order(items, coupon_code=""):
            _rzp_seq[0] += 1
            fake_rzp_oid = f"order_AtomicTest_{_rzp_seq[0]:04d}"
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "id": fake_rzp_oid,
                "entity": "order",
                "amount": 100000,
                "currency": "INR",
                "status": "created"
            }
            with patch("server.requests.post", return_value=mock_resp):
                resp = av_client.post("/api/create-order", headers=av_cust_hdrs, json={
                    "customer": test_customer,
                    "items": items,
                    "coupon_code": coupon_code
                })
                data = resp.get_json()
                assert resp.status_code == 200 and data.get("ok") is True, f"Failed to create RZP order: {data}"
                return data["order_id"], fake_rzp_oid

        # Helper to query stock and coupon usage directly
        def _get_anarkali_state():
            prods = av_client.get("/api/products").get_json()["products"]
            p = next(x for x in prods if x["id"] == "anarkali")
            conn_q = server.get_db()
            row_c = conn_q.execute("SELECT used_count FROM coupons WHERE code = 'NAARI10'").fetchone()
            conn_q.close()
            return p["stock"], dict(p.get("size_stock") or {}), list(p.get("sold_out_sizes") or []), (row_c["used_count"] if row_c else 0)

        # Reset anarkali inventory to deterministic state: 5 per size across 6 sizes = 30 total
        reset_av_inv = av_client.post("/api/admin/inventory/update", headers=av_admin_hdrs, json={
            "id": "anarkali",
            "size_stock": {"XS": 5, "S": 5, "M": 5, "L": 5, "XL": 5, "XXL": 5}
        })
        assert reset_av_inv.status_code == 200 and reset_av_inv.get_json().get("ok") is True

        base_total_0, base_sizes_0, _, base_coupon_0 = _get_anarkali_state()
        assert base_total_0 == 30 and base_sizes_0["M"] == 5

        # A. Customer-cancelled unpaid Razorpay order receiving a late VALID payment callback -> 409 + refund_required, never confirmed or deducted
        oid_cust_cancel, rzp_oid_cust_cancel = _create_unpaid_rzp_order(
            [{"id": "anarkali", "qty": 2, "size": "M", "color": "Royal Blue"}],
            coupon_code="NAARI10"
        )
        # Cancel via customer endpoint while still pending_payment
        c_cancel_resp = av_client.post("/api/customer/orders/cancel", headers=av_cust_hdrs, json={
            "order_id": oid_cust_cancel,
            "reason": "Cancelled before payment callback arrived"
        })
        assert c_cancel_resp.status_code == 200 and c_cancel_resp.get_json().get("ok") is True

        # Late valid signature arrives from Razorpay handler
        late_pid_1 = "pay_LateAfterCustCancel01"
        late_sig_1 = _sign_rzp(rzp_oid_cust_cancel, late_pid_1)
        late_verify_1 = av_client.post("/api/verify-payment", headers=av_cust_hdrs, json={
            "order_id": oid_cust_cancel,
            "razorpay_order_id": rzp_oid_cust_cancel,
            "razorpay_payment_id": late_pid_1,
            "razorpay_signature": late_sig_1
        })
        late_data_1 = late_verify_1.get_json()
        assert late_verify_1.status_code == 409, f"Expected 409 on cancelled order verify, got {late_verify_1.status_code}: {late_data_1}"
        assert late_data_1.get("ok") is False
        assert late_data_1.get("order_status") == "cancelled"
        assert late_data_1.get("refund_required") is True
        assert late_data_1.get("payment_id") == late_pid_1

        # Verify DB state & inventory untouched
        det_cc = av_client.get(f"/api/order-details?order_id={oid_cust_cancel}", headers=av_cust_hdrs).get_json()["order"]
        assert det_cc["order_status"] == "cancelled"
        assert det_cc["payment_status"] == "cancelled"
        t_after_cc, s_after_cc, _, cp_after_cc = _get_anarkali_state()
        assert t_after_cc == 30 and s_after_cc["M"] == 5 and cp_after_cc == base_coupon_0

        # B. Admin-cancelled unpaid Razorpay order receiving a late VALID payment callback -> 409 + refund_required, never confirmed or deducted
        oid_adm_cancel, rzp_oid_adm_cancel = _create_unpaid_rzp_order(
            [{"id": "anarkali", "qty": 1, "size": "M", "color": "Emerald"}],
            coupon_code="NAARI10"
        )
        a_cancel_resp = av_client.post("/api/admin/orders/status", headers=av_admin_hdrs, json={
            "order_id": oid_adm_cancel,
            "order_status": "cancelled"
        })
        assert a_cancel_resp.status_code == 200 and a_cancel_resp.get_json().get("ok") is True

        late_pid_2 = "pay_LateAfterAdminCancel02"
        late_sig_2 = _sign_rzp(rzp_oid_adm_cancel, late_pid_2)
        late_verify_2 = av_client.post("/api/verify-payment", headers=av_cust_hdrs, json={
            "order_id": oid_adm_cancel,
            "razorpay_order_id": rzp_oid_adm_cancel,
            "razorpay_payment_id": late_pid_2,
            "razorpay_signature": late_sig_2
        })
        late_data_2 = late_verify_2.get_json()
        assert late_verify_2.status_code == 409, f"Expected 409 on admin-cancelled order verify, got {late_verify_2.status_code}: {late_data_2}"
        assert late_data_2.get("ok") is False
        assert late_data_2.get("order_status") == "cancelled"
        assert late_data_2.get("refund_required") is True
        det_ac = av_client.get(f"/api/order-details?order_id={oid_adm_cancel}", headers=av_cust_hdrs).get_json()["order"]
        assert det_ac["order_status"] == "cancelled"
        assert det_ac["payment_status"] != "paid"
        t_after_ac, s_after_ac, _, cp_after_ac = _get_anarkali_state()
        assert t_after_ac == 30 and s_after_ac["M"] == 5 and cp_after_ac == base_coupon_0

        # C. Invalid signature on a cancelled order must NOT clobber payment_status or order_status
        bad_sig_on_cancelled = av_client.post("/api/verify-payment", headers=av_cust_hdrs, json={
            "order_id": oid_cust_cancel,
            "razorpay_order_id": rzp_oid_cust_cancel,
            "razorpay_payment_id": "pay_FakeBadSig",
            "razorpay_signature": "0" * 64
        })
        assert bad_sig_on_cancelled.status_code == 400
        det_cc_after_bad = av_client.get(f"/api/order-details?order_id={oid_cust_cancel}", headers=av_cust_hdrs).get_json()["order"]
        assert det_cc_after_bad["order_status"] == "cancelled"
        assert det_cc_after_bad["payment_status"] == "cancelled"

        # D. Concurrent duplicate verification requests (5 threads simultaneously) -> deducts stock & increments coupon ONCE
        oid_conc_dup, rzp_oid_conc_dup = _create_unpaid_rzp_order(
            [{"id": "anarkali", "qty": 2, "size": "S", "color": "Royal Blue"}],
            coupon_code="NAARI10"
        )
        conc_pid = "pay_ConcurrentDupVerify01"
        conc_sig = _sign_rzp(rzp_oid_conc_dup, conc_pid)
        dup_barrier = threading.Barrier(5)
        dup_results = []
        dup_lock = threading.Lock()

        def _verify_worker():
            w_client = server.app.test_client()
            dup_barrier.wait(timeout=5)
            r = w_client.post("/api/verify-payment", headers=av_cust_hdrs, json={
                "order_id": oid_conc_dup,
                "razorpay_order_id": rzp_oid_conc_dup,
                "razorpay_payment_id": conc_pid,
                "razorpay_signature": conc_sig
            })
            with dup_lock:
                dup_results.append((r.status_code, r.get_json()))

        threads = [threading.Thread(target=_verify_worker) for _ in range(5)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=10)

        assert len(dup_results) == 5, f"Expected 5 responses, got {len(dup_results)}"
        assert all(code == 200 and body.get("ok") is True for code, body in dup_results), f"Unexpected responses: {dup_results}"
        fresh_verifications = [b for _, b in dup_results if not b.get("already_verified")]
        idempotent_verifications = [b for _, b in dup_results if b.get("already_verified") is True]
        assert len(fresh_verifications) == 1, f"Expected exactly 1 initial verification, got {len(fresh_verifications)}: {dup_results}"
        assert len(idempotent_verifications) == 4, f"Expected 4 idempotent duplicate responses, got {len(idempotent_verifications)}"

        # Stock for ("anarkali", "S") must have decreased by 2 (5 -> 3), total 30 -> 28, coupon +1
        t_after_dup, s_after_dup, _, cp_after_dup = _get_anarkali_state()
        assert t_after_dup == 28, f"Expected total stock 28 after 1 order of 2 units, got {t_after_dup}"
        assert s_after_dup["S"] == 3, f"Expected size S stock 3, got {s_after_dup['S']}"
        assert cp_after_dup == base_coupon_0 + 1, f"Expected coupon used_count {base_coupon_0 + 1}, got {cp_after_dup}"

        # Invalid signature on an already-paid order must NOT overwrite payment_status to 'failed'
        bad_sig_on_paid = av_client.post("/api/verify-payment", headers=av_cust_hdrs, json={
            "order_id": oid_conc_dup,
            "razorpay_order_id": rzp_oid_conc_dup,
            "razorpay_payment_id": "pay_BadAfterPaid",
            "razorpay_signature": "f" * 64
        })
        assert bad_sig_on_paid.status_code == 400
        det_paid_after_bad = av_client.get(f"/api/order-details?order_id={oid_conc_dup}", headers=av_cust_hdrs).get_json()["order"]
        assert det_paid_after_bad["payment_status"] == "paid"
        assert det_paid_after_bad["order_status"] == "confirmed"

        # Restore that order by cancelling it so stock returns to 30 and coupon returns to base_coupon_0
        cleanup_conc = av_client.post("/api/customer/orders/cancel", headers=av_cust_hdrs, json={
            "order_id": oid_conc_dup,
            "reason": "Reset stock after concurrent duplicate test"
        })
        assert cleanup_conc.status_code == 200
        t_reset, s_reset, _, cp_reset = _get_anarkali_state()
        assert t_reset == 30 and s_reset["S"] == 5 and cp_reset == base_coupon_0

        # E. Concurrent race between payment verification and customer cancellation
        for race_idx in range(3):
            oid_race, rzp_oid_race = _create_unpaid_rzp_order(
                [{"id": "anarkali", "qty": 2, "size": "L", "color": "Royal Blue"}],
                coupon_code="NAARI10"
            )
            race_pid = f"pay_RaceVerifyCancel_{race_idx}"
            race_sig = _sign_rzp(rzp_oid_race, race_pid)
            race_barrier = threading.Barrier(2)
            race_out = {}

            def _race_verify():
                vc = server.app.test_client()
                race_barrier.wait(timeout=5)
                rv = vc.post("/api/verify-payment", headers=av_cust_hdrs, json={
                    "order_id": oid_race,
                    "razorpay_order_id": rzp_oid_race,
                    "razorpay_payment_id": race_pid,
                    "razorpay_signature": race_sig
                })
                race_out["verify"] = (rv.status_code, rv.get_json())

            def _race_cancel():
                cc = server.app.test_client()
                race_barrier.wait(timeout=5)
                rc = cc.post("/api/customer/orders/cancel", headers=av_cust_hdrs, json={
                    "order_id": oid_race,
                    "reason": "Concurrent cancel vs verify"
                })
                race_out["cancel"] = (rc.status_code, rc.get_json())

            tv = threading.Thread(target=_race_verify)
            tc = threading.Thread(target=_race_cancel)
            tv.start()
            tc.start()
            tv.join(timeout=10)
            tc.join(timeout=10)

            v_code, v_body = race_out["verify"]
            c_code, c_body = race_out["cancel"]
            assert c_code == 200 and c_body.get("ok") is True, f"Cancel should succeed in either order: {race_out}"
            # Verify either succeeded first (200) and then cancel restored stock, OR cancel succeeded first and verify returned 409
            assert v_code in (200, 409), f"Unexpected verify status in race: {race_out}"
            if v_code == 409:
                assert v_body.get("order_status") == "cancelled" and v_body.get("refund_required") is True

            # Regardless of which thread won the lock first, the order ends up cancelled and stock/coupon must have zero net leak!
            det_race = av_client.get(f"/api/order-details?order_id={oid_race}", headers=av_cust_hdrs).get_json()["order"]
            assert det_race["order_status"] == "cancelled", f"Order must be cancelled after race: {det_race}"
            t_race, s_race, _, cp_race = _get_anarkali_state()
            assert t_race == 30 and s_race["L"] == 5 and cp_race == base_coupon_0, (
                f"Stock/coupon leak in verify-vs-cancel race #{race_idx}: total={t_race}, L={s_race['L']}, coupon={cp_race}"
            )

        # F. Stock exhaustion while Razorpay order is pending_payment -> atomic rollback, 400 + refund_required, order NOT marked paid
        # Set XL stock to 2 units (total 27)
        upd_xl = av_client.post("/api/admin/inventory/update", headers=av_admin_hdrs, json={
            "id": "anarkali",
            "size_stock": {"XS": 5, "S": 5, "M": 5, "L": 5, "XL": 2, "XXL": 5}
        })
        assert upd_xl.status_code == 200 and upd_xl.get_json().get("ok") is True
        oid_stock_race, rzp_oid_stock_race = _create_unpaid_rzp_order(
            [{"id": "anarkali", "qty": 2, "size": "XL", "color": "Royal Blue"}],
            coupon_code="NAARI10"
        )
        # Another customer/order buys the 2 XL units via COD while Razorpay payment is still pending
        cod_take_xl = av_client.post("/api/create-cod-order", headers=av_cust_hdrs, json={
            "customer": test_customer,
            "items": [{"id": "anarkali", "qty": 2, "size": "XL", "color": "Royal Blue"}]
        })
        assert cod_take_xl.status_code == 200 and cod_take_xl.get_json().get("ok") is True
        cod_xl_oid = cod_take_xl.get_json()["order_id"]

        # Now the pending Razorpay order's valid payment verification arrives when XL stock is 0
        exhaust_pid = "pay_StockExhaustedWhilePending01"
        exhaust_sig = _sign_rzp(rzp_oid_stock_race, exhaust_pid)
        exhaust_verify = av_client.post("/api/verify-payment", headers=av_cust_hdrs, json={
            "order_id": oid_stock_race,
            "razorpay_order_id": rzp_oid_stock_race,
            "razorpay_payment_id": exhaust_pid,
            "razorpay_signature": exhaust_sig
        })
        exhaust_data = exhaust_verify.get_json()
        assert exhaust_verify.status_code == 400, f"Expected 400 when stock exhausted before verify, got {exhaust_verify.status_code}: {exhaust_data}"
        assert exhaust_data.get("ok") is False
        assert exhaust_data.get("refund_required") is True
        assert exhaust_data.get("payment_id") == exhaust_pid

        # Order must NOT be marked paid or confirmed, and coupon must NOT be incremented
        det_exhaust = av_client.get(f"/api/order-details?order_id={oid_stock_race}", headers=av_cust_hdrs).get_json()["order"]
        assert det_exhaust["payment_status"] != "paid"
        assert det_exhaust["order_status"] == "pending_payment"
        _, _, _, cp_after_exhaust = _get_anarkali_state()
        assert cp_after_exhaust == base_coupon_0

        # Clean up COD order
        av_client.post("/api/customer/orders/cancel", headers=av_cust_hdrs, json={"order_id": cod_xl_oid})

    print(" [PASS] 19. Atomic Razorpay Payment Verification, Late-Callback Rejection & Concurrency Verified!")
    passed += 1

    # 20. Order Confirmation & Customer Order History (COD, Paid Razorpay, Ownership, Missing Order & Escaping)
    total += 1
    oc_rzp_id = "rzp_test_OrderConfKey111"
    oc_rzp_secret = "rzp_test_OrderConfSecret222"
    oc_admin_key = "OrderConfAdminPasskey_2026"
    with patch.dict(os.environ, {
        "ADMIN_SECRET_KEY": oc_admin_key,
        "RAZORPAY_KEY_ID": oc_rzp_id,
        "RAZORPAY_KEY_SECRET": oc_rzp_secret,
        "RAZORPAY_ENABLED": "1",
        "DISABLE_EXTERNAL_GEOCODING": "1"
    }, clear=False):
        oc_client = server.app.test_client()
        oc_admin_hdrs = {"X-Admin-Passkey": oc_admin_key}

        # Register Customer A and Customer B
        cust_a_email = f"order.hist.a.{os.urandom(3).hex()}@example.com"
        reg_a = oc_client.post("/api/auth/register", json={
            "name": "Kavya Menon",
            "email": cust_a_email,
            "phone": "9811223344",
            "password": "KavyaOrderPass123!"
        })
        assert reg_a.status_code == 200 and reg_a.get_json().get("ok") is True
        cust_a_user = reg_a.get_json()["user"]
        assert str(cust_a_user["id"]).startswith("usr_"), f"Expected string usr_ ID, got {cust_a_user['id']}"
        cust_a_hdrs = {"Authorization": f"Bearer {reg_a.get_json()['token']}"}

        cust_b_email = f"order.hist.b.{os.urandom(3).hex()}@example.com"
        reg_b = oc_client.post("/api/auth/register", json={
            "name": "Riya Kapoor",
            "email": cust_b_email,
            "phone": "9822334455",
            "password": "RiyaOrderPass123!"
        })
        assert reg_b.status_code == 200 and reg_b.get_json().get("ok") is True
        cust_b_hdrs = {"Authorization": f"Bearer {reg_b.get_json()['token']}"}

        # Ensure ample stock on 'straight' (₹1299) and 'short' (₹899)
        oc_client.post("/api/admin/inventory/update", headers=oc_admin_hdrs, json={
            "id": "straight",
            "size_stock": {"XS": 5, "S": 10, "M": 10, "L": 10, "XL": 10, "XXL": 5}
        })
        oc_client.post("/api/admin/inventory/update", headers=oc_admin_hdrs, json={
            "id": "short",
            "size_stock": {"XS": 5, "S": 10, "M": 10, "L": 10, "XL": 10}
        })

        cust_a_addr = {
            "name": "Kavya Menon",
            "phone": "9811223344",
            "email": cust_a_email,
            "house_no": "Flat 402",
            "street_area": "22, Civil Lines, Hawa Sadak",
            "address_line1": "Flat 402, 22, Civil Lines, Hawa Sadak",
            "address_line2": "Opposite Metro Pillar 18",
            "city": "Jaipur",
            "state": "Rajasthan",
            "pincode": "302006"
        }

        # A. COD Order placement with coupon + special characters in color to verify authoritative data & safe rendering
        cod_resp = oc_client.post("/api/create-cod-order", headers=cust_a_hdrs, json={
            "customer": cust_a_addr,
            "items": [{
                "id": "straight",
                "qty": 2,
                "size": "M",
                "color": "Maroon & Gold <Festive>",
                "name": "<script>alert(1)</script>",
                "price": 1
            }],
            "coupon_code": "NAARI10"
        })
        cod_data = cod_resp.get_json()
        assert cod_resp.status_code == 200 and cod_data.get("ok") is True
        cod_oid = cod_data["order_id"]
        assert cod_data["status"] == "cod_confirmed"
        assert cod_data["order_status"] == "confirmed"
        assert cod_data["subtotal"] == 2598
        assert cod_data["discount_amount"] == 260
        assert cod_data["shipping"] == 0
        assert cod_data["coupon_code"] == "NAARI10"
        assert cod_data["total_amount"] == 2338
        # Server must overwrite tampered item name and price with authoritative DB values
        assert isinstance(cod_data.get("items"), list) and len(cod_data["items"]) == 1
        assert cod_data["items"][0]["name"] == "Gulmohar Straight Kurti"
        assert cod_data["items"][0]["price"] == 1299
        assert cod_data["items"][0]["subtotal"] == 2598
        assert cod_data["items"][0]["size"] == "M"
        assert cod_data["items"][0]["color"] == "Maroon & Gold <Festive>"

        # Verify /api/order-details for COD order
        det_cod_resp = oc_client.get(f"/api/order-details?order_id={cod_oid}", headers=cust_a_hdrs)
        assert det_cod_resp.status_code == 200
        det_cod = det_cod_resp.get_json()["order"]
        assert det_cod["id"] == cod_oid
        assert det_cod["user_id"] == cust_a_user["id"]
        assert det_cod["customer_name"] == "Kavya Menon"
        assert det_cod["address_line1"] == "Flat 402, 22, Civil Lines, Hawa Sadak"
        assert det_cod["address_line2"] == "Opposite Metro Pillar 18"
        assert det_cod["city"] == "Jaipur" and det_cod["state"] == "Rajasthan" and det_cod["pincode"] == "302006"
        assert det_cod["payment_method"] == "cod"
        assert det_cod["payment_status"] == "cod_confirmed"
        assert det_cod["order_status"] == "confirmed"
        assert det_cod["subtotal"] == 2598 and det_cod["discount_amount"] == 260 and det_cod["shipping"] == 0 and det_cod["total_amount"] == 2338
        assert det_cod["coupon_code"] == "NAARI10"
        assert det_cod["items"][0]["name"] == "Gulmohar Straight Kurti"

        # B. Paid Razorpay order with shipping fee (1 'short' kurti = ₹899 + ₹99 shipping = ₹998) + tracking update
        fake_rzp_oid = "order_HistRzp001"
        mock_rzp = MagicMock()
        mock_rzp.status_code = 200
        mock_rzp.json.return_value = {
            "id": fake_rzp_oid,
            "entity": "order",
            "amount": 99800,
            "currency": "INR",
            "status": "created"
        }
        with patch("server.requests.post", return_value=mock_rzp):
            rzp_create_resp = oc_client.post("/api/create-order", headers=cust_a_hdrs, json={
                "customer": cust_a_addr,
                "items": [{"id": "short", "qty": 1, "size": "S", "color": "Indigo", "price": 10}]
            })
        rzp_create_data = rzp_create_resp.get_json()
        assert rzp_create_resp.status_code == 200 and rzp_create_data.get("ok") is True
        rzp_oid = rzp_create_data["order_id"]
        assert rzp_create_data["subtotal"] == 899
        assert rzp_create_data["shipping"] == 99
        assert rzp_create_data["discount_amount"] == 0
        assert rzp_create_data["total_amount"] == 998
        assert rzp_create_data["items"][0]["price"] == 899

        fake_pid = "pay_HistRzp001"
        valid_sig = hmac.new(
            oc_rzp_secret.encode("utf-8"),
            f"{fake_rzp_oid}|{fake_pid}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        rzp_ver_resp = oc_client.post("/api/verify-payment", headers=cust_a_hdrs, json={
            "order_id": rzp_oid,
            "razorpay_order_id": fake_rzp_oid,
            "razorpay_payment_id": fake_pid,
            "razorpay_signature": valid_sig
        })
        rzp_ver_data = rzp_ver_resp.get_json()
        assert rzp_ver_resp.status_code == 200 and rzp_ver_data.get("ok") is True
        assert rzp_ver_data["status"] == "paid"
        assert rzp_ver_data["order_status"] == "confirmed"
        assert rzp_ver_data["subtotal"] == 899 and rzp_ver_data["shipping"] == 99 and rzp_ver_data["total_amount"] == 998
        assert rzp_ver_data["items"][0]["price"] == 899

        # Admin updates Razorpay order to 'shipped' with courier & tracking number
        ship_upd = oc_client.post("/api/admin/orders/status", headers=oc_admin_hdrs, json={
            "order_id": rzp_oid,
            "order_status": "shipped",
            "tracking_number": "BD9988776655IN",
            "courier_partner": "Blue Dart Express"
        })
        assert ship_upd.status_code == 200 and ship_upd.get_json().get("ok") is True

        det_rzp = oc_client.get(f"/api/order-details?order_id={rzp_oid}", headers=cust_a_hdrs).get_json()["order"]
        assert det_rzp["payment_method"] == "razorpay"
        assert det_rzp["payment_status"] == "paid"
        assert det_rzp["order_status"] == "shipped"
        assert det_rzp["razorpay_payment_id"] == fake_pid
        assert "razorpay_signature" not in det_rzp
        assert det_rzp["tracking_number"] == "BD9988776655IN"
        assert det_rzp["courier_partner"] == "Blue Dart Express"
        assert det_rzp["subtotal"] == 899 and det_rzp["shipping"] == 99 and det_rzp["total_amount"] == 998

        # C. Verify /api/customer/orders for Customer A returns both orders with complete authoritative fields
        hist_a_resp = oc_client.get("/api/customer/orders", headers=cust_a_hdrs)
        assert hist_a_resp.status_code == 200
        hist_a_orders = hist_a_resp.get_json()["orders"]
        hist_a_ids = {o["id"]: o for o in hist_a_orders}
        assert cod_oid in hist_a_ids and rzp_oid in hist_a_ids
        assert "razorpay_signature" not in hist_a_ids[rzp_oid]
        assert hist_a_ids[rzp_oid]["tracking_number"] == "BD9988776655IN"
        assert hist_a_ids[cod_oid]["discount_amount"] == 260 and hist_a_ids[cod_oid]["coupon_code"] == "NAARI10"

        # D. Strict Order Ownership & Unauthorized Access Checks (401, 403, Isolated History)
        anon_client = server.app.test_client()
        unauth_det = anon_client.get(f"/api/order-details?order_id={cod_oid}")
        assert unauth_det.status_code == 401
        unauth_list = anon_client.get("/api/customer/orders")
        assert unauth_list.status_code == 401

        cross_det_cod = oc_client.get(f"/api/order-details?order_id={cod_oid}", headers=cust_b_hdrs)
        assert cross_det_cod.status_code == 403
        cross_det_rzp = oc_client.get(f"/api/order-details?order_id={rzp_oid}", headers=cust_b_hdrs)
        assert cross_det_rzp.status_code == 403
        cross_cancel = oc_client.post("/api/customer/orders/cancel", headers=cust_b_hdrs, json={"order_id": cod_oid})
        assert cross_cancel.status_code == 403
        cross_return = oc_client.post("/api/customer/returns", headers=cust_b_hdrs, json={
            "order_id": cod_oid,
            "item_name": "Gulmohar Straight Kurti (M)",
            "action_type": "return",
            "reason": "Cross account attempt"
        })
        assert cross_return.status_code == 403

        hist_b_resp = oc_client.get("/api/customer/orders", headers=cust_b_hdrs)
        assert hist_b_resp.status_code == 200
        assert hist_b_resp.get_json()["orders"] == [], "Customer B must never see Customer A's orders"

        # E. Missing Order (404) & Empty order_id (400)
        missing_det = oc_client.get("/api/order-details?order_id=NAARI-NONEXISTENT-000000", headers=cust_a_hdrs)
        assert missing_det.status_code == 404
        empty_det = oc_client.get("/api/order-details", headers=cust_a_hdrs)
        assert empty_det.status_code == 400

        # F. Frontend order-confirmation.html & account.html verification (localStorage string user_id comparison, consolidated renderer, HTML escaping)
        oc_html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "order-confirmation.html")
        ac_html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "account.html")
        with open(oc_html_path, "r", encoding="utf-8") as f:
            oc_html = f.read()
        with open(ac_html_path, "r", encoding="utf-8") as f:
            ac_html = f.read()

        assert "Number(cachedOrder.user_id) === Number(session.user.id)" not in oc_html, (
            "order-confirmation.html must not use Number() on usr_ string user IDs"
        )
        assert "cachedUserId === sessionUserId" in oc_html, (
            "order-confirmation.html must compare string user_id values in localStorage fallback"
        )
        assert "function escapeHtml(" in oc_html and "function sanitizeImageSrc(" in oc_html, (
            "order-confirmation.html must define escapeHtml and sanitizeImageSrc helpers"
        )
        assert "renderOrderFromData(order);" in oc_html and "renderOrderFromData(cachedOrder);" in oc_html, (
            "order-confirmation.html must use consolidated renderOrderFromData for both API and fallback paths"
        )
        assert "function escapeHtml(" in ac_html and "function sanitizeImageSrc(" in ac_html, (
            "account.html must define escapeHtml and sanitizeImageSrc helpers"
        )
        assert "data-cancel-order-id=" in ac_html and "onclick=\"cancelCustomerOrder(" not in ac_html, (
            "account.html must bind cancel buttons via escaped data-cancel-order-id attribute instead of inline onclick"
        )

    print(" [PASS] 20. Order Confirmation & Customer Order History (COD, Paid Razorpay, Ownership, Missing Order & Escaping) Verified!")
    passed += 1

    # 21. Admin Order Management, Revenue Accuracy, Pricing Discount & Status Transition Guardrails
    total += 1
    adm_rzp_key_id = "rzp_test_AdminRevKey123"
    adm_rzp_secret = "rzp_test_AdminRevSecret987654"
    adm_passkey = "AdminRevPasskey_2026"
    with patch.dict(os.environ, {
        "ADMIN_SECRET_KEY": adm_passkey,
        "RAZORPAY_KEY_ID": adm_rzp_key_id,
        "RAZORPAY_KEY_SECRET": adm_rzp_secret,
        "RAZORPAY_ENABLED": "1",
        "DISABLE_EXTERNAL_GEOCODING": "1"
    }, clear=False):
        adm_client = server.app.test_client()
        unauth_adm_client = server.app.test_client()
        adm_hdrs = {"X-Admin-Passkey": adm_passkey}

        # A. Admin endpoints enforce authentication (401 without passkey/token)
        assert unauth_adm_client.get("/api/admin/stats").status_code == 401
        assert unauth_adm_client.get("/api/admin/orders").status_code == 401
        assert unauth_adm_client.get("/api/admin/customers").status_code == 401
        assert unauth_adm_client.post("/api/admin/orders/status", json={"order_id": "X", "order_status": "shipped"}).status_code == 401

        # Invalid status values and non-existent order IDs are rejected
        bad_st = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
            "order_id": "NAARI-SAMPLE",
            "order_status": "teleported"
        })
        assert bad_st.status_code == 400
        bad_pay_st = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
            "order_id": "NAARI-SAMPLE",
            "order_status": "confirmed",
            "payment_status": "bogus_pay"
        })
        assert bad_pay_st.status_code == 400
        missing_ord_st = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
            "order_id": "NAARI-MISSING-999999",
            "order_status": "shipped"
        })
        assert missing_ord_st.status_code == 404

        # Register an isolated customer for revenue & customer total_spent tracking
        rev_cust_email = f"admin.rev.{os.urandom(3).hex()}@example.com"
        reg_rev = adm_client.post("/api/auth/register", json={
            "name": "Devika Sharma",
            "email": rev_cust_email,
            "phone": "9811223344",
            "password": "Password123!"
        })
        assert reg_rev.status_code == 200
        rev_cust_token = reg_rev.get_json()["token"]
        rev_cust_id = reg_rev.get_json()["user"]["id"]
        rev_cust_hdrs = {"Authorization": f"Bearer {rev_cust_token}"}
        rev_addr = {
            "name": "Devika Sharma",
            "email": rev_cust_email,
            "phone": "9811223344",
            "address_line1": "House 14, Sardar Patel Marg, C-Scheme",
            "address_line2": "Near Deer Park",
            "city": "Jaipur",
            "state": "Rajasthan",
            "pincode": "302001",
            "lat": 26.9124,
            "lng": 75.7873
        }

        # Ensure 'anarkali' size L has known stock and NAARI10 coupon is active
        adm_client.post("/api/admin/inventory/update", headers=adm_hdrs, json={
            "id": "anarkali",
            "size_stock": {"S": 10, "M": 10, "L": 10, "XL": 10}
        })

        # Capture baseline stats before creating test orders
        base_stats = adm_client.get("/api/admin/stats", headers=adm_hdrs).get_json()["stats"]
        base_total_rev = base_stats["total_revenue"]
        base_paid_rev = base_stats["paid_revenue"]
        base_ver_paid_rev = base_stats["verified_paid_revenue"]
        base_cod_rev = base_stats["cod_revenue"]
        base_total_orders = base_stats["total_orders"]
        base_paid_orders = base_stats["paid_orders"]
        base_cod_orders = base_stats["cod_orders"]
        base_unpaid_orders = base_stats["unpaid_orders"]
        base_cancelled_orders = base_stats["cancelled_orders"]

        # B. Create an UNPAID pending_payment Razorpay order -> must NOT count toward revenue, total_orders, or customer total_spent
        mock_unpaid_rzp = MagicMock()
        mock_unpaid_rzp.status_code = 200
        mock_unpaid_rzp.json.return_value = {
            "id": "order_UnpaidAdminRev01",
            "entity": "order",
            "amount": 249900,
            "currency": "INR",
            "status": "created"
        }
        with patch("server.requests.post", return_value=mock_unpaid_rzp):
            unpaid_resp = adm_client.post("/api/create-order", headers=rev_cust_hdrs, json={
                "customer": rev_addr,
                "items": [{"id": "anarkali", "qty": 1, "size": "L", "color": "Emerald"}]
            })
        assert unpaid_resp.status_code == 200
        unpaid_oid = unpaid_resp.get_json()["order_id"]

        stats_after_unpaid = adm_client.get("/api/admin/stats", headers=adm_hdrs).get_json()["stats"]
        assert stats_after_unpaid["total_revenue"] == base_total_rev, "Unpaid Razorpay order must not inflate total_revenue"
        assert stats_after_unpaid["paid_revenue"] == base_paid_rev, "Unpaid Razorpay order must not inflate paid_revenue"
        assert stats_after_unpaid["verified_paid_revenue"] == base_ver_paid_rev
        assert stats_after_unpaid["cod_revenue"] == base_cod_rev
        assert stats_after_unpaid["total_orders"] == base_total_orders, "Unpaid Razorpay order must not inflate total_orders"
        assert stats_after_unpaid["unpaid_orders"] == base_unpaid_orders + 1

        cust_list_unpaid = adm_client.get(f"/api/admin/customers?search={rev_cust_email}", headers=adm_hdrs).get_json()["customers"]
        assert len(cust_list_unpaid) == 1
        assert cust_list_unpaid[0]["orders_count"] == 0 and cust_list_unpaid[0]["total_spent"] == 0, (
            "Unpaid Razorpay order must not count in customer orders_count or total_spent"
        )

        # Admin cannot move an unpaid Razorpay order to fulfillment statuses (confirmed, packed, shipped, delivered) or mark it paid
        for forbidden_st in ("confirmed", "packed", "shipped", "out for delivery", "delivered"):
            forb_resp = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
                "order_id": unpaid_oid,
                "order_status": forbidden_st
            })
            assert forb_resp.status_code == 400, f"Unpaid Razorpay order must reject transition to {forbidden_st}"

        forb_pay = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
            "order_id": unpaid_oid,
            "order_status": "pending_payment",
            "payment_status": "paid"
        })
        assert forb_pay.status_code == 400

        # Mark a second Razorpay order as payment-failed -> must also remain excluded from revenue
        mock_failed_rzp = MagicMock()
        mock_failed_rzp.status_code = 200
        mock_failed_rzp.json.return_value = {
            "id": "order_FailedAdminRev02",
            "entity": "order",
            "amount": 249900,
            "currency": "INR",
            "status": "created"
        }
        with patch("server.requests.post", return_value=mock_failed_rzp):
            failed_create = adm_client.post("/api/create-order", headers=rev_cust_hdrs, json={
                "customer": rev_addr,
                "items": [{"id": "anarkali", "qty": 1, "size": "L", "color": "Emerald"}]
            })
        failed_oid = failed_create.get_json()["order_id"]
        adm_client.post("/api/payment-failed", headers=rev_cust_hdrs, json={
            "order_id": failed_oid,
            "reason": "Payment declined by bank"
        })
        stats_after_failed = adm_client.get("/api/admin/stats", headers=adm_hdrs).get_json()["stats"]
        assert stats_after_failed["total_revenue"] == base_total_rev
        assert stats_after_failed["total_orders"] == base_total_orders

        # C. Place a confirmed COD order with coupon NAARI10 (1 'anarkali' = ₹2499, 10% off = ₹250, total = ₹2249)
        conn_chk = server.get_db()
        coupon_used_before = conn_chk.execute("SELECT used_count FROM coupons WHERE code = 'NAARI10'").fetchone()["used_count"]
        stock_l_before = json.loads(conn_chk.execute("SELECT size_stock_json FROM products WHERE id = 'anarkali'").fetchone()["size_stock_json"])["L"]
        conn_chk.close()

        cod_rev_resp = adm_client.post("/api/create-cod-order", headers=rev_cust_hdrs, json={
            "customer": rev_addr,
            "items": [{"id": "anarkali", "qty": 1, "size": "L", "color": "Emerald"}],
            "coupon_code": "NAARI10"
        })
        assert cod_rev_resp.status_code == 200
        cod_rev_data = cod_rev_resp.get_json()
        cod_rev_oid = cod_rev_data["order_id"]
        assert cod_rev_data["subtotal"] == 2499 and cod_rev_data["discount_amount"] == 250 and cod_rev_data["total_amount"] == 2249

        stats_after_cod = adm_client.get("/api/admin/stats", headers=adm_hdrs).get_json()["stats"]
        assert stats_after_cod["cod_orders"] == base_cod_orders + 1
        assert stats_after_cod["cod_revenue"] == base_cod_rev + 2249
        assert stats_after_cod["paid_orders"] == base_paid_orders
        assert stats_after_cod["verified_paid_revenue"] == base_ver_paid_rev
        assert stats_after_cod["paid_revenue"] == base_paid_rev
        assert stats_after_cod["total_orders"] == base_total_orders + 1
        assert stats_after_cod["total_revenue"] == base_total_rev + 2249

        # Verify /api/admin/orders pricing.discount matches discount_amount (250) and items include subtotal & line_total
        adm_orders_list = adm_client.get(f"/api/admin/orders?search={cod_rev_oid}", headers=adm_hdrs).get_json()["orders"]
        assert len(adm_orders_list) == 1
        adm_cod_ord = adm_orders_list[0]
        assert adm_cod_ord["pricing"]["subtotal"] == 2499
        assert adm_cod_ord["pricing"]["discount"] == 250
        assert adm_cod_ord["pricing"]["discount_amount"] == 250
        assert adm_cod_ord["pricing"]["shipping"] == 0
        assert adm_cod_ord["pricing"]["total"] == 2249
        assert adm_cod_ord["pricing"]["coupon_code"] == "NAARI10"
        assert adm_cod_ord["items"][0]["price"] == 2499
        assert adm_cod_ord["items"][0]["unit_price"] == 2499
        assert adm_cod_ord["items"][0]["subtotal"] == 2499
        assert adm_cod_ord["items"][0]["line_total"] == 2499

        # Update COD order status to 'Out for Delivery' and payment_status to 'paid' (cash collected) -> must NOT double-count in verified_paid_revenue!
        upd_cod_paid = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
            "order_id": cod_rev_oid,
            "order_status": "Out for Delivery",
            "payment_status": "paid",
            "courier_name": "Delhivery",
            "tracking_number": "DLV77889900IN"
        })
        assert upd_cod_paid.status_code == 200

        # Filter /api/admin/orders by both 'out_for_delivery' and 'Out for Delivery'
        filt_1 = adm_client.get("/api/admin/orders?status=out_for_delivery", headers=adm_hdrs).get_json()["orders"]
        filt_2 = adm_client.get("/api/admin/orders?status=Out+for+Delivery", headers=adm_hdrs).get_json()["orders"]
        assert any(o["order_id"] == cod_rev_oid for o in filt_1)
        assert any(o["order_id"] == cod_rev_oid for o in filt_2)

        stats_cod_collected = adm_client.get("/api/admin/stats", headers=adm_hdrs).get_json()["stats"]
        assert stats_cod_collected["cod_orders"] == base_cod_orders + 1
        assert stats_cod_collected["cod_revenue"] == base_cod_rev + 2249
        assert stats_cod_collected["paid_orders"] == base_paid_orders, "COD order marked paid must not double-count in online paid_orders"
        assert stats_cod_collected["verified_paid_revenue"] == base_ver_paid_rev, "COD order marked paid must not double-count in verified_paid_revenue"
        assert stats_cod_collected["total_revenue"] == base_total_rev + 2249

        # Cannot revert a stock-deducted COD order back to pending_payment
        revert_pending = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
            "order_id": cod_rev_oid,
            "order_status": "pending_payment"
        })
        assert revert_pending.status_code == 400

        # D. Create and verify a PAID Razorpay order (1 'short' kurti = ₹899 + ₹99 shipping = ₹998)
        fake_paid_rzp_id = "order_PaidAdminRev03"
        mock_paid_rzp = MagicMock()
        mock_paid_rzp.status_code = 200
        mock_paid_rzp.json.return_value = {
            "id": fake_paid_rzp_id,
            "entity": "order",
            "amount": 99800,
            "currency": "INR",
            "status": "created"
        }
        with patch("server.requests.post", return_value=mock_paid_rzp):
            paid_rzp_create = adm_client.post("/api/create-order", headers=rev_cust_hdrs, json={
                "customer": rev_addr,
                "items": [{"id": "short", "qty": 1, "size": "M", "color": "Indigo"}]
            })
        paid_rzp_oid = paid_rzp_create.get_json()["order_id"]
        fake_paid_pid = "pay_PaidAdminRev03"
        paid_sig = hmac.new(
            adm_rzp_secret.encode("utf-8"),
            f"{fake_paid_rzp_id}|{fake_paid_pid}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        ver_paid_resp = adm_client.post("/api/verify-payment", headers=rev_cust_hdrs, json={
            "order_id": paid_rzp_oid,
            "razorpay_order_id": fake_paid_rzp_id,
            "razorpay_payment_id": fake_paid_pid,
            "razorpay_signature": paid_sig
        })
        assert ver_paid_resp.status_code == 200

        stats_after_both = adm_client.get("/api/admin/stats", headers=adm_hdrs).get_json()["stats"]
        assert stats_after_both["paid_orders"] == base_paid_orders + 1
        assert stats_after_both["verified_paid_revenue"] == base_ver_paid_rev + 998
        assert stats_after_both["paid_revenue"] == base_paid_rev + 998
        assert stats_after_both["cod_orders"] == base_cod_orders + 1
        assert stats_after_both["cod_revenue"] == base_cod_rev + 2249
        assert stats_after_both["total_orders"] == base_total_orders + 2
        assert stats_after_both["total_revenue"] == base_total_rev + 2249 + 998

        cust_after_both = adm_client.get(f"/api/admin/customers?search={rev_cust_email}", headers=adm_hdrs).get_json()["customers"][0]
        assert cust_after_both["id"] == rev_cust_id
        assert cust_after_both["orders_count"] == 2
        assert cust_after_both["total_spent"] == 2249 + 998

        # Cannot revert a paid Razorpay order to pending_payment
        revert_rzp_pending = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
            "order_id": paid_rzp_oid,
            "order_status": "pending_payment"
        })
        assert revert_rzp_pending.status_code == 400

        # E. Admin cancels the COD order -> stock and coupon used_count restored once, revenue & customer total_spent reduced by 2249
        cancel_cod_1 = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
            "order_id": cod_rev_oid,
            "order_status": "cancelled"
        })
        assert cancel_cod_1.status_code == 200

        conn_chk = server.get_db()
        coupon_used_after_cancel = conn_chk.execute("SELECT used_count FROM coupons WHERE code = 'NAARI10'").fetchone()["used_count"]
        stock_l_after_cancel = json.loads(conn_chk.execute("SELECT size_stock_json FROM products WHERE id = 'anarkali'").fetchone()["size_stock_json"])["L"]
        conn_chk.close()
        assert coupon_used_after_cancel == coupon_used_before, "Admin cancellation must restore coupon used_count"
        assert stock_l_after_cancel == stock_l_before, "Admin cancellation must restore size L stock"

        stats_after_cancel = adm_client.get("/api/admin/stats", headers=adm_hdrs).get_json()["stats"]
        assert stats_after_cancel["cod_orders"] == base_cod_orders
        assert stats_after_cancel["cod_revenue"] == base_cod_rev
        assert stats_after_cancel["paid_orders"] == base_paid_orders + 1
        assert stats_after_cancel["verified_paid_revenue"] == base_ver_paid_rev + 998
        assert stats_after_cancel["total_orders"] == base_total_orders + 1
        assert stats_after_cancel["total_revenue"] == base_total_rev + 998
        assert stats_after_cancel["cancelled_orders"] == base_cancelled_orders + 1

        cust_after_cancel = adm_client.get(f"/api/admin/customers?search={rev_cust_email}", headers=adm_hdrs).get_json()["customers"][0]
        assert cust_after_cancel["orders_count"] == 1
        assert cust_after_cancel["total_spent"] == 998

        # Repeated admin cancellation must not restore stock or coupon used_count a second time
        cancel_cod_2 = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
            "order_id": cod_rev_oid,
            "order_status": "cancelled"
        })
        assert cancel_cod_2.status_code == 200
        conn_chk = server.get_db()
        assert conn_chk.execute("SELECT used_count FROM coupons WHERE code = 'NAARI10'").fetchone()["used_count"] == coupon_used_before
        assert json.loads(conn_chk.execute("SELECT size_stock_json FROM products WHERE id = 'anarkali'").fetchone()["size_stock_json"])["L"] == stock_l_before
        conn_chk.close()

        # Reopening a cancelled order must be rejected with 400
        for reopen_st in ("confirmed", "packed", "shipped", "delivered"):
            reopen_resp = adm_client.post("/api/admin/orders/status", headers=adm_hdrs, json={
                "order_id": cod_rev_oid,
                "order_status": reopen_st
            })
            assert reopen_resp.status_code == 400, f"Cancelled order must not be reopened to {reopen_st}"

        # Place one final active COD order so the newest COD order in DB is in 'confirmed' status
        final_active_cod = adm_client.post("/api/create-cod-order", headers=rev_cust_hdrs, json={
            "customer": rev_addr,
            "items": [{"id": "anarkali", "qty": 1, "size": "L", "color": "Emerald"}]
        })
        assert final_active_cod.status_code == 200
        stats_final = adm_client.get("/api/admin/stats", headers=adm_hdrs).get_json()["stats"]
        assert stats_final["cod_orders"] == base_cod_orders + 1
        assert stats_final["cod_revenue"] == base_cod_rev + 2499
        assert stats_final["total_orders"] == base_total_orders + 2
        assert stats_final["total_revenue"] == base_total_rev + 998 + 2499

        # F. Verify admin.html contains the status normalization and pricing/line_total fixes
        admin_html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin.html")
        with open(admin_html_path, "r", encoding="utf-8") as f:
            admin_html_content = f.read()
        assert "function normalizeOrderStatusKey(" in admin_html_content
        assert "s.verified_paid_revenue ?? s.paid_revenue" in admin_html_content
        assert "item.subtotal ?? item.line_total" in admin_html_content

    print(" [PASS] 21. Admin Order Management, Revenue Accuracy, Pricing Discount & Status Transition Guardrails Verified!")
    passed += 1

    # 22. Admin Session Cookie Security (HttpOnly, SameSite=Lax, Path=/, Conditional Secure over HTTPS/X-Forwarded-Proto & Logout Invalidation)
    total += 1
    cookie_adm_passkey = "AdminCookieSecPasskey_2026!"
    with patch.dict(os.environ, {"ADMIN_SECRET_KEY": cookie_adm_passkey}, clear=False):
        # A. Local HTTP development: sets HttpOnly, SameSite=Lax, Path=/, Max-Age=86400, and omits Secure so local HTTP works
        http_adm_client = server.app.test_client()
        http_login = http_adm_client.post("/api/admin/verify", json={"passkey": cookie_adm_passkey})
        assert http_login.status_code == 200 and http_login.get_json().get("authenticated") is True
        http_token = http_login.get_json()["token"]
        http_cookie_hdr = http_login.headers.get("Set-Cookie", "")
        assert "naari_admin_token=" in http_cookie_hdr
        assert "HttpOnly" in http_cookie_hdr
        assert "SameSite=Lax" in http_cookie_hdr
        assert "Path=/" in http_cookie_hdr
        assert "Max-Age=86400" in http_cookie_hdr
        assert "Secure" not in http_cookie_hdr, (
            f"Local HTTP admin login must not set Secure flag, got: {http_cookie_hdr}"
        )

        # Cookie-only authentication works for admin endpoints without custom headers
        cookie_only_stats = http_adm_client.get("/api/admin/stats")
        assert cookie_only_stats.status_code == 200 and cookie_only_stats.get_json().get("ok") is True

        # Logout via cookie clears cookie with matching attributes and deletes session from DB
        http_logout = http_adm_client.post("/api/admin/logout")
        assert http_logout.status_code == 200
        http_lo_cookie = http_logout.headers.get("Set-Cookie", "")
        assert "naari_admin_token=;" in http_lo_cookie or "Max-Age=0" in http_lo_cookie
        assert "HttpOnly" in http_lo_cookie and "SameSite=Lax" in http_lo_cookie and "Path=/" in http_lo_cookie
        assert "Secure" not in http_lo_cookie

        # Subsequent request with cleared cookie or old token is rejected with 401
        assert http_adm_client.get("/api/admin/stats").status_code == 401
        assert http_adm_client.get("/api/admin/stats", headers={"X-Admin-Token": http_token}).status_code == 401

        # B. Direct HTTPS (wsgi.url_scheme == 'https'): sets Secure flag on login and logout
        https_adm_client = server.app.test_client()
        https_login = https_adm_client.post(
            "/api/admin/verify",
            base_url="https://localhost",
            json={"passkey": cookie_adm_passkey}
        )
        assert https_login.status_code == 200
        https_cookie_hdr = https_login.headers.get("Set-Cookie", "")
        assert "naari_admin_token=" in https_cookie_hdr
        assert "HttpOnly" in https_cookie_hdr
        assert "SameSite=Lax" in https_cookie_hdr
        assert "Path=/" in https_cookie_hdr
        assert "Secure" in https_cookie_hdr, (
            f"Direct HTTPS admin login must set Secure flag, got: {https_cookie_hdr}"
        )
        https_logout = https_adm_client.post("/api/admin/logout", base_url="https://localhost")
        assert https_logout.status_code == 200
        https_lo_cookie = https_logout.headers.get("Set-Cookie", "")
        assert "Secure" in https_lo_cookie and "HttpOnly" in https_lo_cookie and "SameSite=Lax" in https_lo_cookie

        # C. Reverse-proxy HTTPS via X-Forwarded-Proto (single & multi-hop) and Authorization: Bearer logout
        proxy_adm_client = server.app.test_client()
        proxy_login = proxy_adm_client.post(
            "/api/admin/verify",
            headers={"X-Forwarded-Proto": "https, http"},
            json={"passkey": cookie_adm_passkey}
        )
        assert proxy_login.status_code == 200
        proxy_token = proxy_login.get_json()["token"]
        proxy_cookie_hdr = proxy_login.headers.get("Set-Cookie", "")
        assert "Secure" in proxy_cookie_hdr and "HttpOnly" in proxy_cookie_hdr and "SameSite=Lax" in proxy_cookie_hdr

        # Logout via Authorization: Bearer header over proxied HTTPS
        bearer_lo_client = server.app.test_client()
        bearer_logout = bearer_lo_client.post(
            "/api/admin/logout",
            headers={"Authorization": f"Bearer {proxy_token}", "X-Forwarded-Proto": "https"}
        )
        assert bearer_logout.status_code == 200
        assert "Secure" in bearer_logout.headers.get("Set-Cookie", "")
        assert bearer_lo_client.get("/api/admin/stats", headers={"Authorization": f"Bearer {proxy_token}"}).status_code == 401

    print(" [PASS] 22. Admin Session Cookie Security (HttpOnly, SameSite=Lax, Path=/, Conditional Secure & Logout Invalidation) Verified!")
    passed += 1

    # 23. Customer/Admin Authorization, Session Separation, Input Validation & API Security Audit Regression
    total += 1
    audit_admin_key = "AuditAdminSecret_2026!"
    audit_rzp_id = "rzp_test_AuditKey123"
    audit_rzp_secret = "rzp_test_AuditSecret987654"
    with patch.dict(os.environ, {
        "ADMIN_SECRET_KEY": audit_admin_key,
        "RAZORPAY_KEY_ID": audit_rzp_id,
        "RAZORPAY_KEY_SECRET": audit_rzp_secret,
        "RAZORPAY_ENABLED": "1",
        "DISABLE_EXTERNAL_GEOCODING": "1"
    }, clear=False):
        anon_c = server.app.test_client()
        cust_a_c = server.app.test_client()
        cust_b_c = server.app.test_client()
        admin_c = server.app.test_client()

        # Register Customer A and Customer B
        email_a = f"audit.a.{os.urandom(3).hex()}@example.com"
        email_b = f"audit.b.{os.urandom(3).hex()}@example.com"
        reg_a = cust_a_c.post("/api/auth/register", json={
            "name": "Aarti Audit",
            "email": email_a,
            "phone": "9811001100",
            "password": "Password123!"
        })
        reg_b = cust_b_c.post("/api/auth/register", json={
            "name": "Bhumi Audit",
            "email": email_b,
            "phone": "9822002200",
            "password": "Password123!"
        })
        assert reg_a.status_code == 200 and reg_b.status_code == 200
        tok_a = reg_a.get_json()["token"]
        uid_a = reg_a.get_json()["user"]["id"]
        tok_b = reg_b.get_json()["token"]
        uid_b = reg_b.get_json()["user"]["id"]
        hdr_a = {"Authorization": f"Bearer {tok_a}"}
        hdr_b = {"Authorization": f"Bearer {tok_b}"}

        # Authenticate Admin session
        adm_login = admin_c.post("/api/admin/verify", json={"passkey": audit_admin_key})
        assert adm_login.status_code == 200
        adm_tok = adm_login.get_json()["token"]
        hdr_adm = {"X-Admin-Token": adm_tok}

        # 1. Every admin API endpoint rejects unauthenticated AND customer-authenticated requests with 401
        admin_endpoints = [
            ("GET", "/api/admin/stats", None),
            ("GET", "/api/admin/customers", None),
            ("GET", "/api/admin/orders", None),
            ("POST", "/api/admin/orders/status", {"order_id": "NAARI-SAMPLE", "order_status": "shipped"}),
            ("GET", "/api/admin/products", None),
            ("POST", "/api/admin/products", {"name": "Unauthorized Kurti", "price": 999}),
            ("POST", "/api/admin/products/visibility", {"id": "straight", "is_archived": True}),
            ("POST", "/api/admin/inventory/update", {"id": "straight", "stock": 20}),
            ("POST", "/api/admin/upload-image", {"filename": "x.jpg", "data": "abc"}),
            ("DELETE", "/api/admin/products/nonexistent_prod", None),
            ("GET", "/api/admin/coupons", None),
            ("POST", "/api/admin/coupons", {"code": "HACK10", "discount_value": 10}),
            ("POST", "/api/admin/coupons/toggle", {"code": "NAARI10"}),
            ("DELETE", "/api/admin/coupons/HACK10", None),
            ("GET", "/api/admin/settings", None),
            ("POST", "/api/admin/settings", {"store_name": "Hacked"}),
            ("GET", "/api/admin/returns", None),
            ("POST", "/api/admin/returns/status", {"return_id": "RET-SAMPLE", "status": "approved"}),
        ]
        for method, path, body in admin_endpoints:
            r_anon = anon_c.open(path, method=method, json=body)
            assert r_anon.status_code == 401, f"Unauthenticated {method} {path} returned {r_anon.status_code}"
            # Customer A (with both Bearer token and user_token cookie, and even sending customer token in X-Admin-Token) must get 401
            r_cust = cust_a_c.open(path, method=method, json=body, headers={"Authorization": f"Bearer {tok_a}", "X-Admin-Token": tok_a})
            assert r_cust.status_code == 401, f"Customer-authenticated {method} {path} returned {r_cust.status_code}"

        # 2. Admin token/passkey cannot be used as a customer session on customer-only endpoints
        cust_only_endpoints = [
            ("GET", "/api/auth/me", None),
            ("PUT", "/api/auth/profile", {"name": "Admin Impersonator"}),
            ("GET", "/api/customer/orders", None),
            ("POST", "/api/customer/orders/cancel", {"order_id": "X"}),
            ("GET", "/api/customer/addresses", None),
            ("POST", "/api/customer/addresses", {"address_line1": "123 St", "city": "Jaipur", "state": "Rajasthan", "pincode": "302001"}),
            ("DELETE", "/api/customer/addresses/addr_fake", None),
            ("GET", "/api/customer/returns", None),
            ("POST", "/api/customer/returns", {"order_id": "X", "item_name": "Y", "reason": "Z"}),
            ("POST", "/api/address/validate", {"address_line1": "123 St", "city": "Jaipur", "state": "Rajasthan", "pincode": "302001"}),
            ("POST", "/api/create-cod-order", {"items": [{"id": "straight", "qty": 1, "size": "M"}]}),
            ("POST", "/api/create-order", {"items": [{"id": "straight", "qty": 1, "size": "M"}]}),
        ]
        for method, path, body in cust_only_endpoints:
            r_adm_as_cust = admin_c.open(
                path,
                method=method,
                json=body,
                headers={"Authorization": f"Bearer {adm_tok}", "X-Admin-Token": adm_tok, "X-Admin-Passkey": audit_admin_key}
            )
            assert r_adm_as_cust.status_code == 401, f"Admin token on customer endpoint {method} {path} returned {r_adm_as_cust.status_code}"

        # Dual-session coexistence: Admin logged in via naari_admin_token cookie while sending customer Authorization: Bearer header
        coexist_stats = admin_c.get("/api/admin/stats", headers={"Authorization": f"Bearer {tok_a}"})
        assert coexist_stats.status_code == 200 and coexist_stats.get_json().get("ok") is True

        # 3. Customer address & profile ownership isolation
        addr_a_payload = {
            "name": "Aarti Audit",
            "phone": "9811001100",
            "email": email_a,
            "house_no": "Plot 9",
            "street_area": "Malviya Nagar Sector 4",
            "address_line1": "Plot 9, Malviya Nagar Sector 4",
            "city": "Jaipur",
            "state": "Rajasthan",
            "pincode": "302017",
            "is_default": True
        }
        save_addr_a = cust_a_c.post("/api/customer/addresses", headers=hdr_a, json=addr_a_payload)
        assert save_addr_a.status_code == 200
        addrs_a = save_addr_a.get_json()["addresses"]
        assert len(addrs_a) == 1
        addr_a_id = addrs_a[0]["id"]

        # Customer B attempts to delete Customer A's address -> Customer A's address remains untouched
        cust_b_c.delete(f"/api/customer/addresses/{addr_a_id}", headers=hdr_b)
        addrs_a_after = cust_a_c.get("/api/customer/addresses", headers=hdr_a).get_json()["addresses"]
        assert len(addrs_a_after) == 1 and addrs_a_after[0]["id"] == addr_a_id

        # Customer B attempts to pass Customer A's id/email in PUT /api/auth/profile -> only Customer B is updated
        prof_b_upd = cust_b_c.put("/api/auth/profile", headers=hdr_b, json={
            "id": uid_a,
            "email": email_a,
            "name": "Bhumi Updated"
        })
        assert prof_b_upd.status_code == 200
        assert prof_b_upd.get_json()["user"]["id"] == uid_b
        assert cust_a_c.get("/api/auth/me", headers=hdr_a).get_json()["user"]["name"] == "Aarti Audit"

        # 4. Cross-customer order retry, payment-failed, and return filing protections
        cod_a = cust_a_c.post("/api/create-cod-order", headers=hdr_a, json={
            "customer": addr_a_payload,
            "items": [{"id": "straight", "qty": 1, "size": "M", "color": "Maroon"}]
        })
        assert cod_a.status_code == 200
        cod_a_oid = cod_a.get_json()["order_id"]

        # /api/payment-failed must reject COD orders (400), cross-customer orders (403), and non-existent orders (404)
        assert cust_a_c.post("/api/payment-failed", headers=hdr_a, json={"order_id": cod_a_oid}).status_code == 400
        assert cust_b_c.post("/api/payment-failed", headers=hdr_b, json={"order_id": cod_a_oid}).status_code == 403
        assert cust_a_c.post("/api/payment-failed", headers=hdr_a, json={"order_id": "NAARI-NO-SUCH-ORDER"}).status_code == 404

        # Customer B cannot pass Customer A's order_id to POST /api/create-order for retry (403)
        retry_cross = cust_b_c.post("/api/create-order", headers=hdr_b, json={
            "order_id": cod_a_oid,
            "customer": {**addr_a_payload, "name": "Bhumi", "email": email_b, "phone": "9822002200"},
            "items": [{"id": "straight", "qty": 1, "size": "M", "color": "Maroon"}]
        })
        assert retry_cross.status_code == 403

        # Customer A cancels cod_a_oid, then passes cancelled cod_a_oid to POST /api/create-order -> must NOT overwrite cancelled order!
        assert cust_a_c.post("/api/customer/orders/cancel", headers=hdr_a, json={"order_id": cod_a_oid}).status_code == 200
        mock_audit_rzp = MagicMock()
        mock_audit_rzp.status_code = 200
        mock_audit_rzp.json.return_value = {
            "id": "order_AuditRetryNew01",
            "entity": "order",
            "amount": 129900,
            "currency": "INR",
            "status": "created"
        }
        with patch("server.requests.post", return_value=mock_audit_rzp):
            retry_cancelled = cust_a_c.post("/api/create-order", headers=hdr_a, json={
                "order_id": cod_a_oid,
                "customer": addr_a_payload,
                "items": [{"id": "straight", "qty": 1, "size": "M", "color": "Maroon"}]
            })
        assert retry_cancelled.status_code == 200
        new_rzp_oid = retry_cancelled.get_json()["order_id"]
        assert new_rzp_oid != cod_a_oid, "Cancelled order ID must never be overwritten by /api/create-order"
        # Verify cod_a_oid is still 'cancelled' in DB
        assert cust_a_c.get(f"/api/order-details?order_id={cod_a_oid}", headers=hdr_a).get_json()["order"]["order_status"] == "cancelled"

        # Place one active COD order at the end so the newest COD order in DB remains 'confirmed'
        active_cod_a = cust_a_c.post("/api/create-cod-order", headers=hdr_a, json={
            "customer": addr_a_payload,
            "items": [{"id": "straight", "qty": 1, "size": "M", "color": "Maroon"}]
        })
        assert active_cod_a.status_code == 200
        active_cod_oid = active_cod_a.get_json()["order_id"]

        # 5. Return request & admin return status validation
        assert cust_a_c.post("/api/customer/returns", headers=hdr_a, json={
            "order_id": active_cod_oid,
            "item_name": "Gulmohar Straight Kurti",
            "action_type": "invalid_action",
            "reason": "Test"
        }).status_code == 400
        assert cust_a_c.post("/api/customer/returns", headers=hdr_a, json={
            "order_id": "NAARI-NONEXISTENT-999",
            "item_name": "Gulmohar Straight Kurti",
            "action_type": "return",
            "reason": "Test"
        }).status_code == 404

        valid_ret = cust_a_c.post("/api/customer/returns", headers=hdr_a, json={
            "order_id": active_cod_oid,
            "item_name": "Gulmohar Straight Kurti",
            "action_type": "return",
            "reason": "Fit issue"
        })
        assert valid_ret.status_code == 200
        ret_id = valid_ret.get_json()["return_id"]

        assert admin_c.post("/api/admin/returns/status", headers=hdr_adm, json={
            "return_id": ret_id,
            "status": "invalid_ret_status"
        }).status_code == 400
        assert admin_c.post("/api/admin/returns/status", headers=hdr_adm, json={
            "return_id": "RET-NONEXISTENT-999",
            "status": "approved"
        }).status_code == 404
        assert admin_c.post("/api/admin/returns/status", headers=hdr_adm, json={
            "return_id": ret_id,
            "status": "Approved"
        }).status_code == 200

        # 6. Archived product hidden from public /api/products/<pid> (404), visible to admin (200)
        admin_c.post("/api/admin/products/visibility", headers=hdr_adm, json={"id": "short", "is_archived": True})
        try:
            assert anon_c.get("/api/products/short").status_code == 404
            assert cust_a_c.get("/api/products/short", headers=hdr_a).status_code == 404
            assert admin_c.get("/api/products/short", headers=hdr_adm).status_code == 200
        finally:
            admin_c.post("/api/admin/products/visibility", headers=hdr_adm, json={"id": "short", "is_archived": False})

        # 7. Admin settings numeric validation & secret redaction + CORS header verification
        assert admin_c.post("/api/admin/settings", headers=hdr_adm, json={"shipping_fee": -50}).status_code == 400
        assert admin_c.post("/api/admin/settings", headers=hdr_adm, json={"gst_percentage": 150}).status_code == 400
        adm_set_resp = admin_c.post("/api/admin/settings", headers=hdr_adm, json={
            "admin_secret_key": "ShouldNotPersist",
            "razorpay_key_secret": "ShouldNotPersist"
        })
        assert adm_set_resp.status_code == 200
        adm_settings_dict = adm_set_resp.get_json()["settings"]
        for forbidden_k in ("admin_secret_key", "admin_passkey", "admin_passkey_hash", "admin_passkey_salt", "razorpay_key_secret"):
            assert forbidden_k not in adm_settings_dict
        assert adm_set_resp.headers.get("Access-Control-Allow-Origin") == "*"
        assert adm_set_resp.headers.get("Access-Control-Allow-Credentials") is None

    print(" [PASS] 23. Customer/Admin Authorization, Session Separation, Input Validation & API Security Audit Verified!")
    passed += 1

    # 24. Return Workflow, Allowed Transitions, Duplicate Prevention & Refund Consistency Audit
    total += 1
    ret_admin_key = "ReturnWorkflowAdmin_2026!"
    ret_rzp_id = "rzp_test_ReturnKey123"
    ret_rzp_secret = "rzp_test_ReturnSecret987654"
    with patch.dict(os.environ, {
        "ADMIN_SECRET_KEY": ret_admin_key,
        "RAZORPAY_KEY_ID": ret_rzp_id,
        "RAZORPAY_KEY_SECRET": ret_rzp_secret,
        "RAZORPAY_ENABLED": "1",
        "DISABLE_EXTERNAL_GEOCODING": "1"
    }, clear=False):
        # 1. Verify exact 'picked_up' status vs leading-space '" picked_up"'
        assert "picked_up" in server.RETURN_STATUS_MAP
        assert "picked_up" in server.ALLOWED_RETURN_TRANSITIONS
        assert " picked_up" not in server.RETURN_STATUS_MAP
        assert " picked_up" not in server.ALLOWED_RETURN_TRANSITIONS

        ret_cust_a = server.app.test_client()
        ret_cust_b = server.app.test_client()
        ret_adm = server.app.test_client()

        email_ra = f"ret.a.{os.urandom(3).hex()}@example.com"
        email_rb = f"ret.b.{os.urandom(3).hex()}@example.com"
        reg_ra = ret_cust_a.post("/api/auth/register", json={
            "name": "Roshni Return",
            "email": email_ra,
            "phone": "9833003300",
            "password": "Password123!"
        })
        reg_rb = ret_cust_b.post("/api/auth/register", json={
            "name": "Simran Return",
            "email": email_rb,
            "phone": "9844004400",
            "password": "Password123!"
        })
        assert reg_ra.status_code == 200 and reg_rb.status_code == 200
        hdr_ra = {"Authorization": f"Bearer {reg_ra.get_json()['token']}"}
        hdr_rb = {"Authorization": f"Bearer {reg_rb.get_json()['token']}"}

        adm_ver = ret_adm.post("/api/admin/verify", json={"passkey": ret_admin_key})
        assert adm_ver.status_code == 200
        hdr_radm = {"X-Admin-Token": adm_ver.get_json()["token"]}

        ret_addr = {
            "name": "Roshni Return",
            "phone": "9833003300",
            "email": email_ra,
            "house_no": "14B",
            "street_area": "Bapu Nagar",
            "address_line1": "14B, Bapu Nagar",
            "city": "Jaipur",
            "state": "Rajasthan",
            "pincode": "302015"
        }

        # Reset 'straight' inventory and check coupon NAARI10 baseline
        inv_res = ret_adm.post("/api/admin/inventory/update", headers=hdr_radm, json={
            "id": "straight",
            "size_stock": {"S": 10, "M": 10, "L": 10, "XL": 10}
        })
        assert inv_res.status_code == 200

        def _get_straight_m_stock_and_coupon():
            conn_chk = server.get_db()
            c_chk = conn_chk.cursor()
            c_chk.execute("SELECT stock, size_stock_json FROM products WHERE id = 'straight'")
            prow = c_chk.fetchone()
            c_chk.execute("SELECT used_count FROM coupons WHERE code = 'NAARI10'")
            crow = c_chk.fetchone()
            conn_chk.close()
            sz = json.loads(prow["size_stock_json"] or "{}")
            return int(prow["stock"]), int(sz.get("M", 0)), int(crow["used_count"])

        stock_t0, stock_m0, cp_used0 = _get_straight_m_stock_and_coupon()

        # Place COD order with coupon NAARI10 (2 items: Gulmohar Straight Kurti M and Chandni A-Line Kurti M)
        ord_ret_resp = ret_cust_a.post("/api/create-cod-order", headers=hdr_ra, json={
            "customer": ret_addr,
            "coupon_code": "NAARI10",
            "items": [
                {"id": "straight", "qty": 1, "size": "M", "color": "Maroon"},
                {"id": "aline", "qty": 1, "size": "M", "color": "Ivory"}
            ]
        })
        assert ord_ret_resp.status_code == 200
        ord_ret_id = ord_ret_resp.get_json()["order_id"]

        stock_t1, stock_m1, cp_used1 = _get_straight_m_stock_and_coupon()
        assert stock_t1 == stock_t0 - 1 and stock_m1 == stock_m0 - 1 and cp_used1 == cp_used0 + 1

        # 2. Unpaid pending_payment and cancelled orders cannot have returns created
        mock_unpaid_rzp = MagicMock()
        mock_unpaid_rzp.status_code = 200
        mock_unpaid_rzp.json.return_value = {
            "id": "order_RetUnpaid01",
            "entity": "order",
            "amount": 129900,
            "currency": "INR",
            "status": "created"
        }
        with patch("server.requests.post", return_value=mock_unpaid_rzp):
            unpaid_ord = ret_cust_a.post("/api/create-order", headers=hdr_ra, json={
                "customer": ret_addr,
                "items": [{"id": "straight", "qty": 1, "size": "M", "color": "Maroon"}]
            })
        assert unpaid_ord.status_code == 200
        unpaid_oid = unpaid_ord.get_json()["order_id"]
        assert ret_cust_a.post("/api/customer/returns", headers=hdr_ra, json={
            "order_id": unpaid_oid,
            "item_name": "Gulmohar Straight Kurti (M)",
            "action_type": "return",
            "reason": "Size too large"
        }).status_code == 400

        # Cancel unpaid_oid -> still cannot create return on cancelled order
        assert ret_cust_a.post("/api/customer/orders/cancel", headers=hdr_ra, json={"order_id": unpaid_oid}).status_code == 200
        assert ret_cust_a.post("/api/customer/returns", headers=hdr_ra, json={
            "order_id": unpaid_oid,
            "item_name": "Gulmohar Straight Kurti (M)",
            "action_type": "return",
            "reason": "Size too large"
        }).status_code == 400

        # 3. Create return request on valid order -> initial status is 'requested', duplicate request rejected (400)
        ret1_resp = ret_cust_a.post("/api/customer/returns", headers=hdr_ra, json={
            "order_id": ord_ret_id,
            "item_name": "Gulmohar Straight Kurti (M)",
            "action_type": "return",
            "reason": "Size too small",
            "notes": "Need refund"
        })
        assert ret1_resp.status_code == 200
        ret1_json = ret1_resp.get_json()
        ret1_id = ret1_json["return_id"]
        assert ret1_json["id"] == ret1_id and ret1_json["status"] == "requested"

        # Duplicate request for same order + item is rejected with 400
        dup_ret1 = ret_cust_a.post("/api/customer/returns", headers=hdr_ra, json={
            "order_id": ord_ret_id,
            "item_name": "Gulmohar Straight Kurti (M)",
            "action_type": "exchange",
            "reason": "Duplicate attempt"
        })
        assert dup_ret1.status_code == 400
        assert dup_ret1.get_json().get("return_id") == ret1_id

        # Customer B cannot see Customer A's returns
        cust_b_rets = ret_cust_b.get("/api/customer/returns", headers=hdr_rb).get_json()["returns"]
        assert all(r["return_id"] != ret1_id for r in cust_b_rets)

        # 4. Trace full workflow: requested -> approved -> picked_up -> completed -> refunded
        # From 'requested': skipping to picked_up, completed, or refunded must be rejected (400)
        for bad_from_req in ("picked_up", "completed", "refunded", " picked_up"):
            r_bad = ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={
                "return_id": ret1_id,
                "status": bad_from_req
            })
            assert r_bad.status_code == 400, f"Transition requested -> {bad_from_req!r} should be 400, got {r_bad.status_code}"

        # Idempotent requested -> requested succeeds
        assert ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret1_id, "status": "requested"}).status_code == 200

        # Transition requested -> approved
        to_app = ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret1_id, "status": "approved"})
        assert to_app.status_code == 200 and to_app.get_json()["status"] == "approved"
        # From 'approved': moving backward to 'requested' or skipping pickup to 'refunded' or leading-space '" picked_up"' is rejected (400)
        for bad_from_app in ("requested", "completed", "refunded", " picked_up"):
            assert ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret1_id, "status": bad_from_app}).status_code == 400

        # Transition approved -> picked_up (exact 'picked_up')
        to_pick = ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret1_id, "status": "picked_up"})
        assert to_pick.status_code == 200 and to_pick.get_json()["status"] == "picked_up"
        # Once picked_up, parent order cannot be cancelled to double-restore stock
        assert ret_cust_a.post("/api/customer/orders/cancel", headers=hdr_ra, json={"order_id": ord_ret_id}).status_code == 400
        assert ret_adm.post("/api/admin/orders/status", headers=hdr_radm, json={"order_id": ord_ret_id, "order_status": "cancelled"}).status_code == 400

        # From 'picked_up': backward transitions (requested, approved, rejected) are rejected (400)
        for bad_from_pick in ("requested", "approved", "rejected"):
            assert ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret1_id, "status": bad_from_pick}).status_code == 400

        # Transition picked_up -> completed (distinct from refunded)
        to_comp = ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret1_id, "status": "completed"})
        assert to_comp.status_code == 200 and to_comp.get_json()["status"] == "completed"
        # From 'completed': backward transitions (requested, approved, picked_up, rejected) are rejected (400)
        for bad_from_comp in ("requested", "approved", "picked_up", "rejected"):
            assert ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret1_id, "status": bad_from_comp}).status_code == 400

        # Transition completed -> refunded (must NOT call external Razorpay refund API)
        with patch("server.requests.post", side_effect=AssertionError("Razorpay API must not be called on manual return status update")):
            to_ref = ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret1_id, "status": "refunded"})
        assert to_ref.status_code == 200 and to_ref.get_json()["status"] == "refunded"
        # Repeated 'refunded' update is idempotent (200)
        assert ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret1_id, "status": "refunded"}).status_code == 200

        # From terminal 'refunded': all transitions to other states are rejected (400)
        for bad_from_ref in ("requested", "approved", "picked_up", "completed", "rejected"):
            assert ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret1_id, "status": bad_from_ref}).status_code == 400

        # 5. Rejection workflow on second item in order: requested -> rejected (terminal)
        ret2_resp = ret_cust_a.post("/api/customer/returns", headers=hdr_ra, json={
            "order_id": ord_ret_id,
            "item_name": "Chandni A-Line Kurti (M)",
            "action_type": "exchange",
            "reason": "Color preference"
        })
        assert ret2_resp.status_code == 200
        ret2_id = ret2_resp.get_json()["return_id"]

        to_rej = ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret2_id, "status": "rejected"})
        assert to_rej.status_code == 200 and to_rej.get_json()["status"] == "rejected"
        for bad_from_rej in ("requested", "approved", "picked_up", "completed", "refunded"):
            assert ret_adm.post("/api/admin/returns/status", headers=hdr_radm, json={"return_id": ret2_id, "status": bad_from_rej}).status_code == 400

        # Verify stock and coupon usage were NOT altered or double-restored by return status updates
        stock_t2, stock_m2, cp_used2 = _get_straight_m_stock_and_coupon()
        assert stock_t2 == stock_t1 and stock_m2 == stock_m1 and cp_used2 == cp_used1

        # 6. Verify customer & admin GET endpoints return consistent id, return_id, and canonical status
        cust_ret_list = ret_cust_a.get("/api/customer/returns", headers=hdr_ra).get_json()["returns"]
        adm_ret_list = ret_adm.get("/api/admin/returns", headers=hdr_radm).get_json()["returns"]
        cust_r1 = next(r for r in cust_ret_list if r["return_id"] == ret1_id)
        adm_r1 = next(r for r in adm_ret_list if r["return_id"] == ret1_id)
        assert cust_r1["id"] == ret1_id and cust_r1["status"] == "refunded"
        assert adm_r1["id"] == ret1_id and adm_r1["status"] == "refunded"

        # Verify UI files contain canonical 'picked_up', 'completed', 'refunded' options/badges
        with open(os.path.join(server.BASE_DIR, "admin.html"), "r", encoding="utf-8") as f_adm:
            adm_html_src = f_adm.read()
        assert '<option value="picked_up"' in adm_html_src
        assert '<option value="completed"' in adm_html_src
        assert '<option value="refunded"' in adm_html_src

        with open(os.path.join(server.BASE_DIR, "account.html"), "r", encoding="utf-8") as f_acc:
            acc_html_src = f_acc.read()
        assert "normSt === 'picked_up'" in acc_html_src
        assert "normSt === 'completed'" in acc_html_src
        assert "normSt === 'refunded'" in acc_html_src

        # Place one clean confirmed COD order at the end so orders[0] has no active return locks for subsequent suites
        final_clean_cod = ret_cust_a.post("/api/create-cod-order", headers=hdr_ra, json={
            "customer": ret_addr,
            "items": [{"id": "straight", "qty": 1, "size": "M", "color": "Maroon"}]
        })
        assert final_clean_cod.status_code == 200

    print(" [PASS] 24. Return Workflow, Allowed Transitions, Duplicate Prevention & Refund Consistency Verified!")
    passed += 1

    # 25. SQLite Startup & Concurrency Hardening (busy_timeout, concurrent init_db on fresh & legacy DBs, data preservation)
    total += 1
    import tempfile
    import sqlite3 as _sqlite3
    import server

    orig_db_path = server.DB_PATH
    with tempfile.TemporaryDirectory() as tmp_sq_dir:
        try:
            # A. Verify get_db() busy_timeout and journal_mode behavior on a fresh DB
            fresh_db_path = os.path.join(tmp_sq_dir, "fresh_concurrent.db")
            server.DB_PATH = fresh_db_path

            # Simulate 8 concurrent worker threads calling init_db() simultaneously on a brand-new empty DB
            fresh_barrier = threading.Barrier(8)
            fresh_errors = []

            def _init_fresh_worker():
                try:
                    fresh_barrier.wait(timeout=5.0)
                    server.init_db()
                except Exception as exc:
                    fresh_errors.append(exc)

            fresh_threads = [threading.Thread(target=_init_fresh_worker) for _ in range(8)]
            for t in fresh_threads:
                t.start()
            for t in fresh_threads:
                t.join(timeout=15.0)

            assert not fresh_errors, f"Concurrent init_db() on fresh DB raised errors: {fresh_errors}"

            conn_check = server.get_db()
            try:
                bt_row = conn_check.execute("PRAGMA busy_timeout").fetchone()
                assert int(bt_row[0]) == 15000, f"Expected busy_timeout=15000, got {bt_row[0]}"

                jm_row = conn_check.execute("PRAGMA journal_mode").fetchone()
                assert str(jm_row[0]).lower() != "wal", f"Expected default journal_mode not to force WAL, got {jm_row[0]}"

                tables = {
                    r["name"]
                    for r in conn_check.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                }
                expected_tables = {
                    "orders", "products", "coupons", "users", "user_sessions",
                    "user_addresses", "return_requests", "site_settings",
                    "newsletter_subscribers", "admin_sessions"
                }
                assert expected_tables.issubset(tables), f"Missing tables: {expected_tables - tables}"

                prod_cnt = conn_check.execute("SELECT COUNT(*) AS cnt FROM products").fetchone()["cnt"]
                cp_cnt = conn_check.execute("SELECT COUNT(*) AS cnt FROM coupons").fetchone()["cnt"]
                st_cnt = conn_check.execute("SELECT COUNT(*) AS cnt FROM site_settings").fetchone()["cnt"]
                assert prod_cnt == len(server.DEFAULT_PRODUCTS), f"Expected {len(server.DEFAULT_PRODUCTS)} products, got {prod_cnt}"
                assert cp_cnt == len(server.DEFAULT_COUPONS), f"Expected {len(server.DEFAULT_COUPONS)} coupons, got {cp_cnt}"
                assert st_cnt == 7, f"Expected 7 site_settings rows, got {st_cnt}"
            finally:
                conn_check.close()

            # Verify get_site_settings_dict() works cleanly and closes its connection
            settings_dict = server.get_site_settings_dict()
            assert settings_dict.get("promo_banner_code") == "NAARI10"
            assert int(settings_dict.get("free_shipping_threshold")) == 999

            # B. Simulate 8 concurrent worker threads calling init_db() on an older schema DB with custom admin data
            legacy_db_path = os.path.join(tmp_sq_dir, "legacy_concurrent.db")
            raw_conn = _sqlite3.connect(legacy_db_path)
            try:
                raw_c = raw_conn.cursor()
                # Older orders table without migration columns
                raw_c.execute("""
                    CREATE TABLE orders (
                        id TEXT PRIMARY KEY,
                        customer_name TEXT NOT NULL,
                        customer_email TEXT NOT NULL,
                        customer_phone TEXT NOT NULL,
                        address_line1 TEXT NOT NULL,
                        address_line2 TEXT,
                        city TEXT NOT NULL,
                        state TEXT NOT NULL,
                        pincode TEXT NOT NULL,
                        payment_method TEXT NOT NULL,
                        payment_status TEXT NOT NULL,
                        razorpay_order_id TEXT,
                        razorpay_payment_id TEXT,
                        razorpay_signature TEXT,
                        subtotal INTEGER NOT NULL,
                        shipping INTEGER NOT NULL,
                        total_amount INTEGER NOT NULL,
                        items_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                # Older products table without style, occasion, pattern, sleeve_length, neck_design, is_archived, size_stock_json, sku
                raw_c.execute("""
                    CREATE TABLE products (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        category TEXT NOT NULL,
                        price INTEGER NOT NULL,
                        mrp INTEGER NOT NULL,
                        description TEXT,
                        fabric TEXT,
                        care TEXT,
                        image TEXT NOT NULL,
                        relative_image TEXT NOT NULL,
                        gallery_json TEXT NOT NULL,
                        colors_json TEXT NOT NULL,
                        sizes_json TEXT NOT NULL,
                        sold_out_sizes_json TEXT NOT NULL,
                        stock INTEGER DEFAULT 50,
                        is_featured INTEGER DEFAULT 0,
                        is_new INTEGER DEFAULT 0,
                        is_bestseller INTEGER DEFAULT 0,
                        rating REAL DEFAULT 4.8,
                        reviews_count INTEGER DEFAULT 35,
                        created_at TEXT NOT NULL
                    )
                """)
                # Seed customized default product ('straight') with custom price=2499, stock=7, broken image path
                raw_c.execute("""
                    INSERT INTO products (
                        id, name, category, price, mrp, description, fabric, care,
                        image, relative_image, gallery_json, colors_json, sizes_json,
                        sold_out_sizes_json, stock, is_featured, is_new, is_bestseller,
                        rating, reviews_count, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    "straight", "Custom Straight Kurti", "Daily Wear", 2499, 3499,
                    "Custom admin description", "", "",
                    "/assets/non_existent_broken_image.jpg", "assets/non_existent_broken_image.jpg",
                    "[]", '["Standard"]', '["S","M","L"]', "[]",
                    7, 1, 0, 1, 4.9, 99, "2025-01-01T00:00:00"
                ))
                # Seed custom admin-created product ('custom-kurti-99')
                raw_c.execute("""
                    INSERT INTO products (
                        id, name, category, price, mrp, description, fabric, care,
                        image, relative_image, gallery_json, colors_json, sizes_json,
                        sold_out_sizes_json, stock, is_featured, is_new, is_bestseller,
                        rating, reviews_count, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    "custom-kurti-99", "Admin Exclusive Silk Kurta", "Festive Wear", 3999, 4999,
                    "Admin created product", "Pure Silk", "Dry Clean",
                    "/assets/kurti-festive.jpg", "assets/kurti-festive.jpg",
                    '["/assets/kurti-festive.jpg"]', '["Gold"]', '["M","L"]', "[]",
                    12, 1, 1, 0, 5.0, 10, "2025-02-01T00:00:00"
                ))
                # Older coupons table without start_date, applicable_categories, applicable_products, is_auto_apply
                raw_c.execute("""
                    CREATE TABLE coupons (
                        code TEXT PRIMARY KEY,
                        discount_type TEXT NOT NULL,
                        discount_value INTEGER NOT NULL,
                        min_order_value INTEGER DEFAULT 0,
                        max_discount INTEGER DEFAULT 0,
                        expiry_date TEXT,
                        usage_limit INTEGER DEFAULT 1000,
                        used_count INTEGER DEFAULT 0,
                        is_active INTEGER DEFAULT 1,
                        description TEXT,
                        created_at TEXT NOT NULL
                    )
                """)
                raw_c.execute("""
                    INSERT INTO coupons (
                        code, discount_type, discount_value, min_order_value, max_discount,
                        expiry_date, usage_limit, used_count, is_active, description, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    "NAARI10", "percent", 15, 1499, 750, "2027-12-31", 500, 9, 1, "Customized NAARI10", "2025-01-01T00:00:00"
                ))
                # Older user_addresses table without house_no, street_area, latitude, longitude, location_summary, address_label
                raw_c.execute("""
                    CREATE TABLE user_addresses (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        phone TEXT NOT NULL,
                        address_line1 TEXT NOT NULL,
                        address_line2 TEXT,
                        city TEXT NOT NULL,
                        state TEXT NOT NULL,
                        pincode TEXT NOT NULL,
                        is_default INTEGER DEFAULT 0,
                        created_at TEXT NOT NULL
                    )
                """)
                # Customized site_settings
                raw_c.execute("CREATE TABLE site_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                raw_c.execute("INSERT INTO site_settings (key, value) VALUES ('free_shipping_threshold', '1499')")
                raw_conn.commit()
            finally:
                raw_conn.close()

            server.DB_PATH = legacy_db_path
            legacy_barrier = threading.Barrier(8)
            legacy_errors = []

            def _init_legacy_worker():
                try:
                    legacy_barrier.wait(timeout=5.0)
                    server.init_db()
                except Exception as exc:
                    legacy_errors.append(exc)

            legacy_threads = [threading.Thread(target=_init_legacy_worker) for _ in range(8)]
            for t in legacy_threads:
                t.start()
            for t in legacy_threads:
                t.join(timeout=15.0)

            assert not legacy_errors, f"Concurrent init_db() on legacy DB raised errors: {legacy_errors}"

            conn_leg = server.get_db()
            try:
                # Verify all migrated columns exist
                ord_cols = {r["name"] for r in conn_leg.execute("PRAGMA table_info(orders)").fetchall()}
                for c_name in ("order_status", "tracking_number", "courier_partner", "discount_amount", "coupon_code", "user_id", "house_no", "street_area", "latitude", "longitude", "location_summary", "address_label"):
                    assert c_name in ord_cols, f"Missing migrated column {c_name} in orders"

                prd_cols = {r["name"] for r in conn_leg.execute("PRAGMA table_info(products)").fetchall()}
                for c_name in ("style", "occasion", "pattern", "sleeve_length", "neck_design", "is_archived", "size_stock_json", "sku"):
                    assert c_name in prd_cols, f"Missing migrated column {c_name} in products"

                cpn_cols = {r["name"] for r in conn_leg.execute("PRAGMA table_info(coupons)").fetchall()}
                for c_name in ("start_date", "applicable_categories", "applicable_products", "is_auto_apply"):
                    assert c_name in cpn_cols, f"Missing migrated column {c_name} in coupons"

                adr_cols = {r["name"] for r in conn_leg.execute("PRAGMA table_info(user_addresses)").fetchall()}
                for c_name in ("house_no", "street_area", "latitude", "longitude", "location_summary", "address_label"):
                    assert c_name in adr_cols, f"Missing migrated column {c_name} in user_addresses"

                # Verify customized product price/stock/name preserved while missing attributes & broken image were repaired
                st_prod = conn_leg.execute("SELECT * FROM products WHERE id = 'straight'").fetchone()
                assert st_prod["price"] == 2499, f"Expected customized price 2499 preserved, got {st_prod['price']}"
                assert st_prod["stock"] == 7, f"Expected customized stock 7 preserved, got {st_prod['stock']}"
                assert st_prod["name"] == "Custom Straight Kurti"
                assert st_prod["style"] == "Straight Kurta", f"Expected backfilled style, got {st_prod['style']}"
                assert st_prod["fabric"] != "", "Expected empty fabric to be backfilled"
                assert st_prod["image"] == "assets/hero.jpg", f"Expected broken image repaired, got {st_prod['image']}"

                # Verify custom admin product preserved and default products were NOT re-inserted over non-empty table
                cust_prod = conn_leg.execute("SELECT * FROM products WHERE id = 'custom-kurti-99'").fetchone()
                assert cust_prod is not None and cust_prod["price"] == 3999 and cust_prod["stock"] == 12
                total_prods = conn_leg.execute("SELECT COUNT(*) AS cnt FROM products").fetchone()["cnt"]
                assert total_prods == 2, f"Expected 2 existing products preserved without re-seeding defaults, got {total_prods}"

                # Verify customized coupon preserved
                naari_cp = conn_leg.execute("SELECT * FROM coupons WHERE code = 'NAARI10'").fetchone()
                assert naari_cp["discount_value"] == 15 and naari_cp["used_count"] == 9 and naari_cp["min_order_value"] == 1499

                # Verify customized site_settings preserved
                fs_row = conn_leg.execute("SELECT value FROM site_settings WHERE key = 'free_shipping_threshold'").fetchone()
                assert fs_row["value"] == "1499"
            finally:
                conn_leg.close()
        finally:
            server.DB_PATH = orig_db_path

    print(" [PASS] 25. SQLite Startup & Concurrency Hardening (busy_timeout, concurrent init_db & migrations) Verified!")
    passed += 1

    # 26. Persistent Upload Storage, Legacy Fallback & Request/File Size Validation (HTTP 413)
    total += 1
    import io
    import base64 as _b64

    orig_upload_dir = server.UPLOAD_DIR
    orig_legacy_dir = server.LEGACY_UPLOAD_DIR
    orig_data_dir = server.DATA_DIR
    with tempfile.TemporaryDirectory() as tmp_up_root:
        try:
            # Verify MAX_CONTENT_LENGTH is configured to 6 MiB
            assert server.app.config.get("MAX_CONTENT_LENGTH") == 6 * 1024 * 1024, (
                f"Expected MAX_CONTENT_LENGTH=6MiB, got {server.app.config.get('MAX_CONTENT_LENGTH')}"
            )

            # Configure isolated persistent DATA_DIR/uploads and isolated legacy fallback directory
            test_data_dir = os.path.join(tmp_up_root, "persistent_data")
            test_upload_dir = os.path.join(test_data_dir, "uploads")
            test_legacy_dir = os.path.join(tmp_up_root, "legacy_assets_uploads")
            os.makedirs(test_legacy_dir, exist_ok=True)

            server.DATA_DIR = test_data_dir
            server.UPLOAD_DIR = test_upload_dir
            server.LEGACY_UPLOAD_DIR = test_legacy_dir
            assert server.get_upload_dir() == os.path.abspath(test_upload_dir)
            # Upload dir does not need to pre-exist before first upload; ensure_upload_dir creates it safely
            assert not os.path.exists(test_upload_dir)

            admin_key_up = "UpTestAdminSecret_2026!"
            with patch.dict(os.environ, {"ADMIN_SECRET_KEY": admin_key_up}, clear=False):
                up_client = server.app.test_client()
                adm_login = up_client.post("/api/admin/verify", json={"passkey": admin_key_up})
                assert adm_login.status_code == 200
                adm_tok = adm_login.get_json()["token"]
                adm_hdrs = {"X-Admin-Token": adm_tok}

                valid_png_bytes = _b64.b64decode(
                    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
                )
                valid_jpg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
                valid_webp_bytes = b"RIFF\x1a\x00\x00\x00WEBPVP8 \x0e\x00\x00\x00\x30\x01\x00\x9d\x01\x2a\x01\x00\x01\x00\x00\x00"

                # A. Unauthorized uploads must be rejected (401) for unauthenticated, wrong passkey, and customer session
                unauth_up = server.app.test_client().post("/api/admin/upload-image", json={
                    "filename": "kurti.png",
                    "data_url": _b64.b64encode(valid_png_bytes).decode("ascii")
                })
                assert unauth_up.status_code == 401

                bad_pk_up = server.app.test_client().post(
                    "/api/admin/upload-image",
                    headers={"X-Admin-Passkey": "wrong-passkey"},
                    json={"filename": "kurti.png", "data_url": _b64.b64encode(valid_png_bytes).decode("ascii")}
                )
                assert bad_pk_up.status_code == 401

                cust_up_client = server.app.test_client()
                cust_reg = cust_up_client.post("/api/auth/register", json={
                    "name": "Upload Test Customer",
                    "email": f"upcust.{os.urandom(3).hex()}@example.com",
                    "phone": "9876509988",
                    "password": "CustPassword123!"
                }).get_json()
                cust_try_up = cust_up_client.post(
                    "/api/admin/upload-image",
                    headers={"Authorization": f"Bearer {cust_reg['token']}"},
                    json={"filename": "kurti.png", "data_url": _b64.b64encode(valid_png_bytes).decode("ascii")}
                )
                assert cust_try_up.status_code == 401

                # B. Disallowed extensions must be rejected (400), even if file bytes start with valid PNG magic bytes
                for bad_ext_name in ("exploit.php", "vector.svg", "page.html", "script.js", "archive.zip"):
                    bad_ext_res = up_client.post("/api/admin/upload-image", headers=adm_hdrs, json={
                        "filename": bad_ext_name,
                        "data_url": _b64.b64encode(valid_png_bytes).decode("ascii")
                    })
                    assert bad_ext_res.status_code == 400 and bad_ext_res.get_json()["ok"] is False

                # C. Invalid file signatures / magic bytes must be rejected (400) for allowed extensions
                for fake_img_name in ("disguised.png", "disguised.jpg", "disguised.jpeg", "disguised.webp"):
                    fake_sig_res = up_client.post("/api/admin/upload-image", headers=adm_hdrs, json={
                        "filename": fake_img_name,
                        "data_url": _b64.b64encode(b"<html><script>alert(1)</script></html>").decode("ascii")
                    })
                    assert fake_sig_res.status_code == 400 and fake_sig_res.get_json()["ok"] is False

                # D. Valid uploads (multipart PNG, JSON JPEG, multipart WebP with traversal-like filename)
                mp_png_res = up_client.post(
                    "/api/admin/upload-image",
                    headers=adm_hdrs,
                    data={"image": (io.BytesIO(valid_png_bytes), "festive_anarkali.png")},
                    content_type="multipart/form-data"
                )
                assert mp_png_res.status_code == 200
                mp_png_json = mp_png_res.get_json()
                assert mp_png_json["ok"] is True
                png_rel_path = mp_png_json["image_path"]
                assert png_rel_path.startswith("assets/uploads/festive_anarkali-") and png_rel_path.endswith(".png")
                png_fname = os.path.basename(png_rel_path)

                # Verify UPLOAD_DIR was created automatically and file lives in UPLOAD_DIR, NOT in BASE_DIR/assets/uploads
                assert os.path.isdir(test_upload_dir)
                assert os.path.isfile(os.path.join(test_upload_dir, png_fname))
                assert not os.path.isfile(os.path.join(server.BASE_DIR, "assets", "uploads", png_fname))

                # Verify public GET /assets/uploads/<filename> serves the file from UPLOAD_DIR
                get_png_res = up_client.get(f"/{png_rel_path}")
                assert get_png_res.status_code == 200 and get_png_res.data == valid_png_bytes

                # Verify JSON JPEG upload and path-traversal filename sanitization
                jpg_trav_res = up_client.post("/api/admin/upload-image", headers=adm_hdrs, json={
                    "filename": "../../etc/passwd/../../royal_kurti.jpeg",
                    "data_url": f"data:image/jpeg;base64,{_b64.b64encode(valid_jpg_bytes).decode('ascii')}"
                })
                assert jpg_trav_res.status_code == 200
                jpg_rel_path = jpg_trav_res.get_json()["image_path"]
                assert jpg_rel_path.startswith("assets/uploads/royal_kurti-") and jpg_rel_path.endswith(".jpeg")
                assert ".." not in jpg_rel_path
                get_jpg_res = up_client.get(f"/{jpg_rel_path}")
                assert get_jpg_res.status_code == 200 and get_jpg_res.data == valid_jpg_bytes

                # Verify WebP upload
                webp_res = up_client.post(
                    "/api/admin/upload-image",
                    headers=adm_hdrs,
                    data={"file": (io.BytesIO(valid_webp_bytes), "chanderi_suit.webp")},
                    content_type="multipart/form-data"
                )
                assert webp_res.status_code == 200
                webp_rel_path = webp_res.get_json()["image_path"]
                assert up_client.get(f"/{webp_rel_path}").status_code == 200

                # E. Verify init_db() preserves default product image when set to an uploaded image in UPLOAD_DIR
                conn_up = server.get_db()
                try:
                    orig_st_img = conn_up.execute("SELECT image, relative_image FROM products WHERE id = 'straight'").fetchone()
                    conn_up.execute(
                        "UPDATE products SET image = ?, relative_image = ? WHERE id = 'straight'",
                        (png_rel_path, png_rel_path)
                    )
                    conn_up.commit()
                finally:
                    conn_up.close()

                server.init_db()
                conn_up2 = server.get_db()
                try:
                    after_init_img = conn_up2.execute("SELECT image, relative_image FROM products WHERE id = 'straight'").fetchone()
                    assert after_init_img["image"] == png_rel_path, (
                        f"Expected uploaded image {png_rel_path} preserved across init_db(), got {after_init_img['image']}"
                    )
                    # Restore 'straight' default image
                    conn_up2.execute(
                        "UPDATE products SET image = ?, relative_image = ? WHERE id = 'straight'",
                        (orig_st_img["image"], orig_st_img["relative_image"])
                    )
                    conn_up2.commit()
                finally:
                    conn_up2.close()

                # F. Verify Legacy Fallback: file existing only in LEGACY_UPLOAD_DIR is still served at /assets/uploads/<name>
                legacy_fname = "legacy-heritage-kurti-a1b2c3d4.png"
                with open(os.path.join(test_legacy_dir, legacy_fname), "wb") as lf:
                    lf.write(valid_png_bytes)
                leg_get_res = up_client.get(f"/assets/uploads/{legacy_fname}")
                assert leg_get_res.status_code == 200 and leg_get_res.data == valid_png_bytes
                assert server._public_asset_file_exists(f"assets/uploads/{legacy_fname}") is True

                # F2. Verify POST /api/admin/products validation for newly uploaded images, legacy uploads, built-in images, and invalid paths
                test_prod_up_id = "test_uploaded_img_kurti"
                test_prod_bad_id = "test_invalid_img_kurti"
                try:
                    # 1) Newly uploaded image in UPLOAD_DIR is accepted & retained when creating a product
                    save_up_res = up_client.post("/api/admin/products", headers=adm_hdrs, json={
                        "id": test_prod_up_id,
                        "name": "Uploaded Image Kurti",
                        "category": "Festive",
                        "price": 1799,
                        "mrp": 2499,
                        "stock": 12,
                        "image": png_rel_path
                    })
                    assert save_up_res.status_code == 200 and save_up_res.get_json()["ok"] is True
                    prod_up_row = server.get_product_from_db(test_prod_up_id)
                    assert prod_up_row is not None
                    assert prod_up_row["image"] == png_rel_path, f"Expected uploaded image {png_rel_path}, got {prod_up_row['image']}"
                    assert prod_up_row["relative_image"] == png_rel_path, f"Expected relative_image {png_rel_path}, got {prod_up_row['relative_image']}"
                    assert prod_up_row["gallery"] == [png_rel_path]

                    # 2) Existing product with uploaded image is NOT overwritten when updated without image or with invalid/missing image paths
                    upd_no_img_res = up_client.post("/api/admin/products", headers=adm_hdrs, json={
                        "id": test_prod_up_id,
                        "price": 1899
                    })
                    assert upd_no_img_res.status_code == 200
                    prod_after_no_img = server.get_product_from_db(test_prod_up_id)
                    assert prod_after_no_img["price"] == 1899
                    assert prod_after_no_img["image"] == png_rel_path, "Existing uploaded image must not be overwritten on partial update"
                    assert prod_after_no_img["relative_image"] == png_rel_path

                    for bad_img_candidate in (
                        "assets/uploads/nonexistent-99999999.png",
                        "assets/does_not_exist.jpg",
                        "../server.py",
                        "server.py",
                        "config.json",
                        "data/orders.db",
                        "assets/styles.css",
                        "http_not_a_url.jpg",
                    ):
                        upd_bad_img_res = up_client.post("/api/admin/products", headers=adm_hdrs, json={
                            "id": test_prod_up_id,
                            "price": 1899,
                            "image": bad_img_candidate,
                            "relative_image": bad_img_candidate
                        })
                        assert upd_bad_img_res.status_code == 200
                        prod_after_bad = server.get_product_from_db(test_prod_up_id)
                        assert prod_after_bad["image"] == png_rel_path, (
                            f"Invalid image '{bad_img_candidate}' must not overwrite existing valid image {png_rel_path}, got {prod_after_bad['image']}"
                        )
                        assert prod_after_bad["relative_image"] == png_rel_path

                    # 3) Legacy uploaded image in LEGACY_UPLOAD_DIR and built-in product images are accepted when updating product
                    legacy_rel_path = f"assets/uploads/{legacy_fname}"
                    upd_leg_res = up_client.post("/api/admin/products", headers=adm_hdrs, json={
                        "id": test_prod_up_id,
                        "image": f"/{legacy_rel_path}"
                    })
                    assert upd_leg_res.status_code == 200
                    prod_after_leg = server.get_product_from_db(test_prod_up_id)
                    assert prod_after_leg["image"] == legacy_rel_path
                    assert prod_after_leg["relative_image"] == legacy_rel_path

                    upd_builtin_res = up_client.post("/api/admin/products", headers=adm_hdrs, json={
                        "id": test_prod_up_id,
                        "image": "assets/k-aline.jpg"
                    })
                    assert upd_builtin_res.status_code == 200
                    prod_after_builtin = server.get_product_from_db(test_prod_up_id)
                    assert prod_after_builtin["image"] == "assets/k-aline.jpg"
                    assert prod_after_builtin["relative_image"] == "assets/k-aline.jpg"

                    # 4) New product created with invalid/missing image path safely falls back to assets/hero.jpg
                    for bad_new_img in ("assets/uploads/missing-file.png", "../server.py", "server.py", "config.json"):
                        save_bad_new = up_client.post("/api/admin/products", headers=adm_hdrs, json={
                            "id": test_prod_bad_id,
                            "name": "Fallback Image Kurti",
                            "category": "Straight Cut",
                            "price": 1299,
                            "mrp": 1699,
                            "stock": 5,
                            "image": bad_new_img,
                            "relative_image": bad_new_img
                        })
                        assert save_bad_new.status_code == 200
                        prod_bad_row = server.get_product_from_db(test_prod_bad_id)
                        assert prod_bad_row["image"] == "assets/hero.jpg", (
                            f"Expected fallback 'assets/hero.jpg' for invalid new product image '{bad_new_img}', got {prod_bad_row['image']}"
                        )
                        assert prod_bad_row["relative_image"] == "assets/hero.jpg"
                        up_client.delete(f"/api/admin/products/{test_prod_bad_id}", headers=adm_hdrs)
                finally:
                    up_client.delete(f"/api/admin/products/{test_prod_up_id}", headers=adm_hdrs)
                    up_client.delete(f"/api/admin/products/{test_prod_bad_id}", headers=adm_hdrs)

                # G. Oversized Upload Validation (5 MiB per-file limit & 6 MiB MAX_CONTENT_LENGTH -> HTTP 413 JSON)
                # G1. File > 5 MiB (5.2 MiB) sent via multipart/form-data (under 6 MiB request limit, over 5 MiB file limit)
                over_5mb_bytes = valid_png_bytes + (b"\x00" * (5 * 1024 * 1024 + 200 * 1024))
                over_5mb_res = up_client.post(
                    "/api/admin/upload-image",
                    headers=adm_hdrs,
                    data={"image": (io.BytesIO(over_5mb_bytes), "huge_5_2mb.png")},
                    content_type="multipart/form-data"
                )
                assert over_5mb_res.status_code == 413, f"Expected 413 for >5MiB file, got {over_5mb_res.status_code}"
                over_5mb_json = over_5mb_res.get_json()
                assert isinstance(over_5mb_json, dict) and over_5mb_json.get("ok") is False
                assert "5mb" in over_5mb_json.get("error", "").lower()

                # G2. Request > 6 MiB (exceeding Flask MAX_CONTENT_LENGTH) -> HTTP 413 predictable JSON response
                over_6mb_bytes = valid_png_bytes + (b"\x00" * (6 * 1024 * 1024 + 100 * 1024))
                over_6mb_res = up_client.post(
                    "/api/admin/upload-image",
                    headers=adm_hdrs,
                    data={"image": (io.BytesIO(over_6mb_bytes), "huge_6_1mb.png")},
                    content_type="multipart/form-data"
                )
                assert over_6mb_res.status_code == 413, f"Expected 413 for >6MiB request, got {over_6mb_res.status_code}"
                over_6mb_json = over_6mb_res.get_json()
                assert isinstance(over_6mb_json, dict) and over_6mb_json.get("ok") is False
                assert "6mb" in over_6mb_json.get("error", "").lower() or "maximum" in over_6mb_json.get("error", "").lower()
        finally:
            server.UPLOAD_DIR = orig_upload_dir
            server.LEGACY_UPLOAD_DIR = orig_legacy_dir
            server.DATA_DIR = orig_data_dir

    print(" [PASS] 26. Persistent Upload Storage, Legacy Fallback & Request/File Size Validation (HTTP 413) Verified!")
    passed += 1

    # 27. Safe SQLite Backup Helper (sqlite3.Connection.backup, integrity_check, Overwrite Guard & Isolated Restore)
    total += 1
    orig_db_for_bkp = server.DB_PATH
    with tempfile.TemporaryDirectory() as tmp_bkp_dir:
        try:
            src_db_path = os.path.join(tmp_bkp_dir, "sample_source.db")
            bkp_db_path = os.path.join(tmp_bkp_dir, "backups", "orders_backup_v1.db")
            os.makedirs(os.path.dirname(bkp_db_path), exist_ok=True)

            server.DB_PATH = src_db_path
            server.init_db()

            # 1. Populate sample data in isolated source DB
            seed_conn = server.get_db()
            try:
                seed_c = seed_conn.cursor()
                seed_c.execute("""
                    INSERT INTO users (id, name, email, phone, password_hash, salt, created_at)
                    VALUES ('usr_bkp_1', 'Kavya Nair', 'kavya.bkp@example.com', '9876543219', 'hash123', 'salt123', '2026-11-12T00:00:00')
                """)
                seed_c.execute("""
                    INSERT INTO orders (
                        id, customer_name, customer_email, customer_phone,
                        address_line1, address_line2, city, state, pincode,
                        payment_method, payment_status, order_status,
                        subtotal, shipping, discount_amount, coupon_code, total_amount,
                        items_json, user_id, created_at, updated_at
                    ) VALUES (
                        'NAARI-BKP-0001', 'Kavya Nair', 'kavya.bkp@example.com', '9876543219',
                        '12 Lotus Enclave', 'MG Road', 'Bengaluru', 'Karnataka', '560001',
                        'cod', 'pending', 'confirmed',
                        2499, 0, 250, 'NAARI10', 2249,
                        '[{"id":"anarkali","name":"Genda Anarkali Kurta","size":"M","color":"Marigold","price":2499,"qty":1}]',
                        'usr_bkp_1', '2026-11-12T01:00:00', '2026-11-12T01:00:00'
                    )
                """)
                seed_c.execute("UPDATE products SET price = 1599, stock = 21 WHERE id = 'straight'")
                seed_c.execute("UPDATE coupons SET used_count = 4 WHERE code = 'NAARI10'")
                seed_c.execute("""
                    INSERT INTO return_requests (
                        id, order_id, customer_email, customer_phone,
                        item_name, action_type, reason, notes, status, created_at, updated_at
                    ) VALUES (
                        'RET-BKP-01', 'NAARI-BKP-0001', 'kavya.bkp@example.com', '9876543219',
                        'Genda Anarkali Kurta', 'exchange', 'Size Exchange', 'Need size L', 'approved',
                        '2026-11-12T02:00:00', '2026-11-12T02:00:00'
                    )
                """)
                seed_conn.commit()
            finally:
                seed_conn.close()

            # 2. Back up while a source connection is actively open and reading
            open_src_conn = server.get_db()
            try:
                _ = open_src_conn.execute("SELECT COUNT(*) FROM orders").fetchone()
                bkp_res1 = server.backup_sqlite_db(bkp_db_path)
                assert bkp_res1["ok"] is True, f"Backup failed: {bkp_res1}"
                assert bkp_res1["integrity_check"] == "ok"
                assert bkp_res1["overwritten"] is False
                assert bkp_res1["bytes_written"] > 0
                assert os.path.isfile(bkp_db_path)
            finally:
                open_src_conn.close()

            # 3. Verify backup passes PRAGMA integrity_check and matches schema & representative rows
            bkp_check_conn = _sqlite3.connect(bkp_db_path)
            bkp_check_conn.row_factory = _sqlite3.Row
            try:
                ic_rows = bkp_check_conn.execute("PRAGMA integrity_check").fetchall()
                assert len(ic_rows) == 1 and ic_rows[0][0].lower() == "ok"

                bkp_tables = {
                    r["name"]
                    for r in bkp_check_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                }
                for req_tbl in (
                    "orders", "products", "coupons", "users", "user_sessions",
                    "user_addresses", "return_requests", "site_settings",
                    "newsletter_subscribers", "admin_sessions"
                ):
                    assert req_tbl in bkp_tables, f"Missing table {req_tbl} in backup"

                bkp_ord = bkp_check_conn.execute("SELECT * FROM orders WHERE id = 'NAARI-BKP-0001'").fetchone()
                assert bkp_ord is not None
                assert bkp_ord["customer_name"] == "Kavya Nair"
                assert bkp_ord["total_amount"] == 2249
                assert bkp_ord["discount_amount"] == 250
                assert bkp_ord["coupon_code"] == "NAARI10"

                bkp_prod = bkp_check_conn.execute("SELECT price, stock FROM products WHERE id = 'straight'").fetchone()
                assert bkp_prod["price"] == 1599 and bkp_prod["stock"] == 21

                bkp_cp = bkp_check_conn.execute("SELECT used_count FROM coupons WHERE code = 'NAARI10'").fetchone()
                assert bkp_cp["used_count"] == 4

                bkp_ret = bkp_check_conn.execute("SELECT status, action_type FROM return_requests WHERE id = 'RET-BKP-01'").fetchone()
                assert bkp_ret["status"] == "approved" and bkp_ret["action_type"] == "exchange"
            finally:
                bkp_check_conn.close()

            # 4. Mutate source DB, then verify existing destination is NOT overwritten by default (overwrite=False)
            with open(bkp_db_path, "rb") as bf_before:
                bkp_bytes_v1 = bf_before.read()

            mut_conn = server.get_db()
            try:
                mut_conn.execute("""
                    INSERT INTO orders (
                        id, customer_name, customer_email, customer_phone,
                        address_line1, address_line2, city, state, pincode,
                        payment_method, payment_status, order_status,
                        subtotal, shipping, discount_amount, coupon_code, total_amount,
                        items_json, user_id, created_at, updated_at
                    ) VALUES (
                        'NAARI-BKP-0002', 'Kavya Nair', 'kavya.bkp@example.com', '9876543219',
                        '12 Lotus Enclave', 'MG Road', 'Bengaluru', 'Karnataka', '560001',
                        'cod', 'pending', 'confirmed',
                        1299, 0, 0, '', 1299,
                        '[{"id":"straight","name":"Gulmohar Straight Kurti","size":"S","color":"Maroon","price":1299,"qty":1}]',
                        'usr_bkp_1', '2026-11-12T03:00:00', '2026-11-12T03:00:00'
                    )
                """)
                mut_conn.commit()
            finally:
                mut_conn.close()

            no_ow_res = server.backup_sqlite_db(bkp_db_path)
            assert no_ow_res["ok"] is False and "overwrite" in (no_ow_res["error"] or "").lower()

            raised_ow = False
            try:
                server.backup_sqlite_db(bkp_db_path, raise_on_error=True)
            except server.SQLiteBackupError:
                raised_ow = True
            assert raised_ow is True

            with open(bkp_db_path, "rb") as bf_after_no_ow:
                assert bf_after_no_ow.read() == bkp_bytes_v1, "Existing backup must remain byte-for-byte unchanged when overwrite=False"

            # 5. Verify overwrite=True updates the backup and preserves integrity
            ow_res = server.backup_sqlite_db(bkp_db_path, overwrite=True)
            assert ow_res["ok"] is True and ow_res["overwritten"] is True and ow_res["integrity_check"] == "ok"

            # Verify isolated restore by pointing server.DB_PATH to a restored copy of the backup
            restored_db_path = os.path.join(tmp_bkp_dir, "restored_instance.db")
            shutil.copy2(bkp_db_path, restored_db_path)
            server.DB_PATH = restored_db_path
            rest_conn = server.get_db()
            try:
                ord_cnt = rest_conn.execute("SELECT COUNT(*) AS cnt FROM orders").fetchone()["cnt"]
                assert ord_cnt == 2, f"Expected 2 orders in restored backup after overwrite=True, got {ord_cnt}"
                ord2 = rest_conn.execute("SELECT total_amount FROM orders WHERE id = 'NAARI-BKP-0002'").fetchone()
                assert ord2 is not None and ord2["total_amount"] == 1299
            finally:
                rest_conn.close()
            server.DB_PATH = src_db_path

            # 6. Verify invalid paths & failure handling (without corrupting existing backup or leaking sensitive data)
            for bad_dest in (None, "", "   ", True):
                bad_r = server.backup_sqlite_db(bad_dest)
                assert bad_r["ok"] is False

            # Same source and destination path rejected
            same_path_r = server.backup_sqlite_db(src_db_path, source_path=src_db_path, overwrite=True)
            assert same_path_r["ok"] is False and "differ" in (same_path_r["error"] or "").lower()

            # Destination is an existing directory rejected
            dir_dest_r = server.backup_sqlite_db(tmp_bkp_dir, overwrite=True)
            assert dir_dest_r["ok"] is False and "directory" in (dir_dest_r["error"] or "").lower()

            # Non-existent parent directory rejected when create_parent_dirs=False, allowed when create_parent_dirs=True
            nested_dest = os.path.join(tmp_bkp_dir, "missing_parent", "sub", "bkp.db")
            no_parent_r = server.backup_sqlite_db(nested_dest, create_parent_dirs=False)
            assert no_parent_r["ok"] is False
            with_parent_r = server.backup_sqlite_db(nested_dest, create_parent_dirs=True)
            assert with_parent_r["ok"] is True and os.path.isfile(nested_dest)

            # Non-existent source file rejected
            missing_src_r = server.backup_sqlite_db(
                os.path.join(tmp_bkp_dir, "out_missing.db"),
                source_path=os.path.join(tmp_bkp_dir, "does_not_exist.db")
            )
            assert missing_src_r["ok"] is False

            # Corrupted/non-SQLite source file fails safely AND preserves existing valid destination backup even with overwrite=True
            corrupt_src_path = os.path.join(tmp_bkp_dir, "corrupt_not_sqlite.db")
            with open(corrupt_src_path, "wb") as cf:
                cf.write(b"NOT A VALID SQLITE DATABASE HEADER" * 50)
            with open(bkp_db_path, "rb") as bf_v2:
                bkp_bytes_v2 = bf_v2.read()

            corrupt_bkp_r = server.backup_sqlite_db(bkp_db_path, source_path=corrupt_src_path, overwrite=True)
            assert corrupt_bkp_r["ok"] is False
            assert "kavya" not in (corrupt_bkp_r["error"] or "").lower()
            with open(bkp_db_path, "rb") as bf_after_corrupt:
                assert bf_after_corrupt.read() == bkp_bytes_v2, "Failed backup must not corrupt pre-existing valid backup file"

            # 7. Concurrent no-clobber race test: two workers backing up to the same nonexistent destination with overwrite=False
            race_src_a = os.path.join(tmp_bkp_dir, "race_src_a.db")
            race_src_b = os.path.join(tmp_bkp_dir, "race_src_b.db")
            shutil.copy2(src_db_path, race_src_a)
            shutil.copy2(src_db_path, race_src_b)

            conn_ra = _sqlite3.connect(race_src_a)
            try:
                conn_ra.execute("UPDATE site_settings SET value = 'WINNER_A' WHERE key = 'promo_banner_code'")
                conn_ra.commit()
            finally:
                conn_ra.close()

            conn_rb = _sqlite3.connect(race_src_b)
            try:
                conn_rb.execute("UPDATE site_settings SET value = 'WINNER_B' WHERE key = 'promo_banner_code'")
                conn_rb.commit()
            finally:
                conn_rb.close()

            race_dest_path = os.path.join(tmp_bkp_dir, "backups", "concurrent_no_clobber_target.db")
            assert not os.path.exists(race_dest_path)

            orig_os_link = os.link
            link_entry_barrier = threading.Barrier(2)

            def _synced_os_link(src_p, dst_p):
                if os.path.abspath(dst_p) == os.path.abspath(race_dest_path):
                    try:
                        link_entry_barrier.wait(timeout=5.0)
                    except Exception:
                        pass
                return orig_os_link(src_p, dst_p)

            race_results = [None, None]
            race_start_barrier = threading.Barrier(2)

            def _run_race_backup(idx, src_file):
                race_start_barrier.wait(timeout=5.0)
                race_results[idx] = server.backup_sqlite_db(
                    race_dest_path,
                    source_path=src_file,
                    overwrite=False,
                    pages=1,
                )

            with patch("os.link", side_effect=_synced_os_link):
                t_race_a = threading.Thread(target=_run_race_backup, args=(0, race_src_a))
                t_race_b = threading.Thread(target=_run_race_backup, args=(1, race_src_b))
                t_race_a.start()
                t_race_b.start()
                t_race_a.join(timeout=15.0)
                t_race_b.join(timeout=15.0)

            assert race_results[0] is not None and race_results[1] is not None
            success_list = [r for r in race_results if r.get("ok") is True]
            failure_list = [r for r in race_results if r.get("ok") is False]
            assert len(success_list) == 1, f"Expected exactly 1 winner in overwrite=False race, got {race_results}"
            assert len(failure_list) == 1
            assert "overwrite" in (failure_list[0].get("error") or "").lower()

            winner_src = success_list[0]["source_path"]
            expected_marker = "WINNER_A" if os.path.abspath(winner_src) == os.path.abspath(race_src_a) else "WINNER_B"
            conn_race_chk = _sqlite3.connect(race_dest_path)
            try:
                ic_race = conn_race_chk.execute("PRAGMA integrity_check").fetchall()
                assert len(ic_race) == 1 and ic_race[0][0].lower() == "ok"
                marker_row = conn_race_chk.execute(
                    "SELECT value FROM site_settings WHERE key = 'promo_banner_code'"
                ).fetchone()
                assert marker_row is not None and marker_row[0] == expected_marker, (
                    f"Expected winner marker {expected_marker} preserved intact, got {marker_row}"
                )
            finally:
                conn_race_chk.close()

            # 8. Symlink destination protection (both overwrite=False and overwrite=True must reject symlinks)
            innocent_target = os.path.join(tmp_bkp_dir, "innocent_target.db")
            innocent_bytes = b"INNOCENT_FILE_DO_NOT_OVERWRITE"
            with open(innocent_target, "wb") as inf:
                inf.write(innocent_bytes)

            symlink_to_file = os.path.join(tmp_bkp_dir, "backups", "symlink_dest.db")
            dangling_symlink = os.path.join(tmp_bkp_dir, "backups", "dangling_dest.db")
            nonexistent_sym_target = os.path.join(tmp_bkp_dir, "nonexistent_sym_target.db")
            os.symlink(innocent_target, symlink_to_file)
            os.symlink(nonexistent_sym_target, dangling_symlink)

            for sym_path in (symlink_to_file, dangling_symlink):
                for ow_flag in (False, True):
                    sym_res = server.backup_sqlite_db(sym_path, overwrite=ow_flag)
                    assert sym_res["ok"] is False and "symbolic link" in (sym_res["error"] or "").lower(), (
                        f"Expected symlink rejection for {sym_path} (overwrite={ow_flag}), got {sym_res}"
                    )
                    assert os.path.islink(sym_path), f"Symlink {sym_path} must remain untouched"

            with open(innocent_target, "rb") as inf_chk:
                assert inf_chk.read() == innocent_bytes, "Symlink target file must remain byte-for-byte untouched"
            assert not os.path.exists(nonexistent_sym_target), "Dangling symlink target must not be created"

            # 9. Non-hardlink fallback claim-file cleanup, error preservation & existing destination protection
            import errno as _errno
            fb_dest_path = os.path.join(tmp_bkp_dir, "backups", "fallback_claim_cleanup.db")
            assert not os.path.exists(fb_dest_path)

            # 9a. Simulate os.link EOPNOTSUPP -> os.open creates claim file -> os.replace fails -> claim file is cleaned up
            with patch("os.link", side_effect=OSError(_errno.EOPNOTSUPP, "Hard links not supported")), \
                 patch("os.replace", side_effect=OSError(_errno.EIO, "Simulated replace failure")):
                fb_fail_res = server.backup_sqlite_db(fb_dest_path, overwrite=False)
                assert fb_fail_res["ok"] is False
                assert "backup failed" in (fb_fail_res["error"] or "").lower()
                assert not os.path.exists(fb_dest_path), "Empty claim file must be removed if fallback os.replace fails"

            # Subsequent backup to fb_dest_path with overwrite=False must succeed (not blocked by a leftover claim file)
            with patch("os.link", side_effect=OSError(_errno.EOPNOTSUPP, "Hard links not supported")):
                fb_ok_res = server.backup_sqlite_db(fb_dest_path, overwrite=False)
                assert fb_ok_res["ok"] is True and fb_ok_res["integrity_check"] == "ok"
                assert os.path.isfile(fb_dest_path) and os.path.getsize(fb_dest_path) > 0

            # 9b. Verify original publication error is NOT masked if claim-file cleanup os.remove itself raises
            fb_mask_dest = os.path.join(tmp_bkp_dir, "backups", "fallback_mask_check.db")
            orig_os_remove = os.remove

            def _remove_fail_on_claim(target_p):
                if os.path.abspath(target_p) == os.path.abspath(fb_mask_dest):
                    raise PermissionError("Simulated cleanup remove failure")
                return orig_os_remove(target_p)

            raised_orig_bkp_err = False
            with patch("os.link", side_effect=OSError(_errno.EOPNOTSUPP, "Hard links not supported")), \
                 patch("os.replace", side_effect=OSError(_errno.EIO, "Primary replace failure")), \
                 patch("os.remove", side_effect=_remove_fail_on_claim):
                try:
                    server.backup_sqlite_db(fb_mask_dest, overwrite=False, raise_on_error=True)
                except server.SQLiteBackupError as bkp_exc:
                    raised_orig_bkp_err = ("backup failed" in str(bkp_exc).lower())
            assert raised_orig_bkp_err is True, "Cleanup failure must not mask the original SQLiteBackupError"
            if os.path.exists(fb_mask_dest):
                orig_os_remove(fb_mask_dest)

            # 9c. Verify fallback never removes a destination created by another process if os.open raises FileExistsError
            fb_other_proc_dest = os.path.join(tmp_bkp_dir, "backups", "fallback_other_proc.db")
            other_proc_bytes = b"OTHER_PROCESS_VALID_BACKUP_BYTES"
            orig_os_open = os.open

            def _open_race_other_proc(path_arg, flags_arg, mode_arg=0o777):
                if os.path.abspath(path_arg) == os.path.abspath(fb_other_proc_dest):
                    with open(fb_other_proc_dest, "wb") as opf:
                        opf.write(other_proc_bytes)
                    raise FileExistsError(_errno.EEXIST, "File exists", path_arg)
                return orig_os_open(path_arg, flags_arg, mode_arg)

            with patch("os.link", side_effect=OSError(_errno.EOPNOTSUPP, "Hard links not supported")), \
                 patch("os.open", side_effect=_open_race_other_proc):
                fb_race_res = server.backup_sqlite_db(fb_other_proc_dest, overwrite=False)
                assert fb_race_res["ok"] is False and "overwrite" in (fb_race_res["error"] or "").lower()
                assert os.path.isfile(fb_other_proc_dest), "Destination created by another process must not be removed"
                with open(fb_other_proc_dest, "rb") as opf_chk:
                    assert opf_chk.read() == other_proc_bytes

            # Ensure no leftover .tmp-* staging files remain in the backup directory
            leftover_tmps = [f for f in os.listdir(os.path.dirname(bkp_db_path)) if ".tmp-" in f]
            assert not leftover_tmps, f"Unexpected leftover temp backup files: {leftover_tmps}"
        finally:
            server.DB_PATH = orig_db_for_bkp

    print(" [PASS] 27. Safe SQLite Backup Helper (sqlite3.Connection.backup, integrity_check, Overwrite Guard & Isolated Restore) Verified!")
    passed += 1

    # 28. Free Address Autocomplete, Map Pin Reverse Geocoding, Indian PIN Lookup & Fake/Incomplete Address Rejection ("abcd", etc.)
    total += 1
    with patch.dict(os.environ, {
        "RAZORPAY_KEY_ID": "rzp_test_AddrSuiteKey123",
        "RAZORPAY_KEY_SECRET": "rzp_test_AddrSuiteSecret987",
        "RAZORPAY_ENABLED": "1",
        "DISABLE_EXTERNAL_GEOCODING": "0"
    }, clear=False):
        addr_client = server.app.test_client()
        addr_email = f"addr.suite.{os.urandom(3).hex()}@example.com"
        reg_addr = addr_client.post("/api/auth/register", json={
            "name": "Nandini Rathore",
            "email": addr_email,
            "phone": "9829012345",
            "password": "AddrSuitePassword123!"
        })
        assert reg_addr.status_code == 200 and reg_addr.get_json().get("ok") is True
        addr_hdrs = {"Authorization": f"Bearer {reg_addr.get_json()['token']}"}

        # A. Address Autocomplete endpoint (/api/address/autocomplete)
        short_ac = addr_client.get("/api/address/autocomplete?q=ab")
        assert short_ac.status_code == 400
        short_ac_json = short_ac.get_json()
        assert short_ac_json["ok"] is False and short_ac_json["suggestions"] == []

        placeholder_ac = addr_client.get("/api/address/autocomplete?q=abcd")
        assert placeholder_ac.status_code == 200
        placeholder_ac_json = placeholder_ac.get_json()
        assert placeholder_ac_json["ok"] is True and placeholder_ac_json["suggestions"] == []

        mock_nom_search_resp = MagicMock()
        mock_nom_search_resp.status_code = 200
        mock_nom_search_resp.json.return_value = [
            {
                "display_name": "Plot 44, Malviya Nagar, Jaipur, Rajasthan, 302017, India",
                "lat": "26.854300",
                "lon": "75.812300",
                "address": {
                    "house_number": "Plot 44",
                    "suburb": "Malviya Nagar",
                    "city": "Jaipur",
                    "state": "Rajasthan",
                    "postcode": "302017"
                }
            }
        ]
        server._GEOCODE_CACHE.clear()
        with patch("server._throttle_nominatim"), patch("server.requests.get", return_value=mock_nom_search_resp) as mocked_nom_get:
            ac_res = addr_client.get("/api/address/autocomplete?q=Malviya+Nagar+Jaipur")
            assert ac_res.status_code == 200
            ac_data = ac_res.get_json()
            assert ac_data["ok"] is True
            assert len(ac_data["suggestions"]) == 1, f"Expected 1 suggestion, got {ac_data['suggestions']}"
            assert mocked_nom_get.call_args[1]["params"]["countrycodes"] == "in"
            sug = ac_data["suggestions"][0]
            assert sug["house_no"] == "Plot 44"
            assert sug["street_area"] == "Malviya Nagar"
            assert sug["city"] == "Jaipur"
            assert sug["state"] == "Rajasthan"
            assert sug["pincode"] == "302017"
            assert sug["lat"] == 26.8543 and sug["lon"] == 75.8123

        # B. Map Pin Reverse Geocoding endpoint (/api/address/reverse)
        # Out-of-India or missing coordinates must return 400
        assert addr_client.get("/api/address/reverse").status_code == 400
        assert addr_client.get("/api/address/reverse?lat=51.5074&lon=-0.1278").status_code == 400
        assert addr_client.get("/api/address/reverse?lat=0&lon=0").status_code == 400

        mock_nom_rev_resp = MagicMock()
        mock_nom_rev_resp.status_code = 200
        mock_nom_rev_resp.json.return_value = {
            "display_name": "18, C-Scheme, Ashok Nagar, Jaipur, Rajasthan, 302001, India",
            "lat": "26.912400",
            "lon": "75.787300",
            "address": {
                "house_number": "18",
                "road": "Sardar Patel Marg",
                "suburb": "C-Scheme",
                "city": "Jaipur",
                "state": "Rajasthan",
                "postcode": "302001"
            }
        }
        with patch("server._throttle_nominatim"), patch("server.requests.get", return_value=mock_nom_rev_resp):
            rev_res = addr_client.get("/api/address/reverse?lat=26.9124&lon=75.7873")
            assert rev_res.status_code == 200
            rev_data = rev_res.get_json()
            assert rev_data["ok"] is True
            assert rev_data["address"]["house_no"] == "18"
            assert "Sardar Patel Marg" in rev_data["address"]["street_area"]
            assert rev_data["address"]["city"] == "Jaipur"
            assert rev_data["address"]["state"] == "Rajasthan"
            assert rev_data["address"]["pincode"] == "302001"

        # C. Indian PIN Code Verification (/api/address/pincode/<pincode>)
        with patch.dict(os.environ, {"DISABLE_EXTERNAL_GEOCODING": "1"}, clear=False):
            server._PINCODE_CACHE.clear()
            valid_pin_res = addr_client.get("/api/address/pincode/302001")
            assert valid_pin_res.status_code == 200
            valid_pin_data = valid_pin_res.get_json()
            assert valid_pin_data["ok"] is True and "Rajasthan" in valid_pin_data["allowed_states"]

            for bad_pin in ("123", "000000", "123456", "654321", "999999", "300000", "910001", "abcdef"):
                bad_pin_res = addr_client.get(f"/api/address/pincode/{bad_pin}")
                assert bad_pin_res.status_code == 400 and bad_pin_res.get_json()["ok"] is False, (
                    f"Expected 400 for invalid PIN {bad_pin}, got {bad_pin_res.status_code}"
                )

            # D. Strict Fake / Incomplete Address Rejection ("abcd", "12, abcd", "abcd road", "qwerty", "aaaa", single-word, PIN/state mismatch, out-of-India coords)
            valid_base_addr = {
                "name": "Nandini Rathore",
                "phone": "9829012345",
                "email": addr_email,
                "house_no": "Plot 44",
                "street_area": "Malviya Nagar Sector 4",
                "address_line1": "Plot 44, Malviya Nagar Sector 4",
                "address_line2": "Near Gaurav Tower",
                "city": "Jaipur",
                "state": "Rajasthan",
                "pincode": "302017",
                "latitude": 26.8543,
                "longitude": 75.8123
            }

            fake_address_cases = [
                # 1. "abcd" in street_area / address_line1 / house_no / city / name / landmark
                {**valid_base_addr, "house_no": "abcd", "street_area": "abcd", "address_line1": "abcd"},
                {**valid_base_addr, "house_no": "", "street_area": "", "address_line1": "abcd"},
                {**valid_base_addr, "house_no": "12", "street_area": "abcd", "address_line1": "12, abcd"},
                {**valid_base_addr, "house_no": "", "street_area": "", "address_line1": "12, abcd"},
                {**valid_base_addr, "house_no": "Flat 4", "street_area": "abcd road", "address_line1": "Flat 4, abcd road"},
                {**valid_base_addr, "house_no": "Flat 4", "street_area": "abcd123", "address_line1": "Flat 4, abcd123"},
                {**valid_base_addr, "name": "abcd"},
                {**valid_base_addr, "city": "abcd"},
                {**valid_base_addr, "address_line2": "abcd"},
                # 2. Keyboard smash / repeated chars / numeric-only street or city
                {**valid_base_addr, "house_no": "10", "street_area": "qwerty", "address_line1": "10, qwerty"},
                {**valid_base_addr, "house_no": "10", "street_area": "asdfgh", "address_line1": "10, asdfgh"},
                {**valid_base_addr, "house_no": "10", "street_area": "aaaaaa", "address_line1": "10, aaaaaa"},
                {**valid_base_addr, "house_no": "10", "street_area": "123456", "address_line1": "10, 123456"},
                {**valid_base_addr, "city": "12345"},
                # 3. Incomplete single-word address or missing house_no
                {**valid_base_addr, "house_no": "", "street_area": "", "address_line1": "Jaipur"},
                {**valid_base_addr, "house_no": "", "street_area": "Malviya Nagar", "address_line1": "Malviya Nagar"},
                # 4. State vs PIN code mismatch (302017 is Rajasthan, not Maharashtra)
                {**valid_base_addr, "state": "Maharashtra", "pincode": "302017"},
                # 5. Out-of-India map coordinates
                {**valid_base_addr, "latitude": 40.7128, "longitude": -74.0060},
            ]

            for idx, bad_addr in enumerate(fake_address_cases):
                val_r = addr_client.post("/api/address/validate", headers=addr_hdrs, json={
                    "address": bad_addr,
                    "require_split_fields": False,
                    "save_to_account": False
                })
                assert val_r.status_code == 400 and val_r.get_json().get("ok") is False, (
                    f"Case #{idx} should be rejected by /api/address/validate: {bad_addr} -> {val_r.status_code} {val_r.get_json()}"
                )

                cod_r = addr_client.post("/api/create-cod-order", headers=addr_hdrs, json={
                    "customer": bad_addr,
                    "items": [{"id": "straight", "qty": 1, "size": "M", "color": "Maroon"}]
                })
                assert cod_r.status_code == 400 and cod_r.get_json().get("ok") is False, (
                    f"Case #{idx} should be rejected by /api/create-cod-order: {bad_addr}"
                )

                rzp_r = addr_client.post("/api/create-order", headers=addr_hdrs, json={
                    "customer": bad_addr,
                    "items": [{"id": "straight", "qty": 1, "size": "M", "color": "Maroon"}]
                })
                assert rzp_r.status_code == 400 and rzp_r.get_json().get("ok") is False, (
                    f"Case #{idx} should be rejected by /api/create-order: {bad_addr}"
                )

            # Valid complete address succeeds on /api/address/validate and saves to user_addresses
            ok_val_r = addr_client.post("/api/address/validate", headers=addr_hdrs, json={
                "address": valid_base_addr,
                "require_split_fields": True,
                "save_to_account": True,
                "is_default": True
            })
            assert ok_val_r.status_code == 200 and ok_val_r.get_json().get("ok") is True
            saved_addr_obj = ok_val_r.get_json()["address"]
            assert saved_addr_obj["house_no"] == "Plot 44"
            assert saved_addr_obj["street_area"] == "Malviya Nagar Sector 4"
            assert saved_addr_obj["pincode"] == "302017"
            assert saved_addr_obj["latitude"] == 26.8543 and saved_addr_obj["longitude"] == 75.8123

    print(" [PASS] 28. Free Address Autocomplete, Map Pin Reverse Geocoding, Indian PIN Lookup & Fake/Incomplete Address Rejection Verified!")
    passed += 1

    # 29. Google Maps JS API & Places Autocomplete (New) Integration, Billing Safeguards, Secret Isolation & OpenStreetMap Fallback
    total += 1
    # A. Unconfigured / placeholder GOOGLE_MAPS_API_KEY -> is_google_maps_configured is False, fallback active
    with patch.dict(os.environ, {
        "GOOGLE_MAPS_API_KEY": "",
        "GOOGLE_MAPS_BROWSER_KEY": "",
        "GOOGLE_PLACES_API_KEY": "",
        "GOOGLE_MAPS_MAP_ID": ""
    }, clear=False):
        gm_client = server.app.test_client()
        unconf_res = gm_client.get("/api/config")
        assert unconf_res.status_code == 200
        unconf_data = unconf_res.get_json()
        assert unconf_data["ok"] is True
        assert unconf_data["is_google_maps_configured"] is False
        assert unconf_data["google_maps_api_key"] == ""
        assert unconf_data["google_maps_billing_safeguards"]["fallback_provider"] == "openstreetmap_nominatim"

    # B. Placeholder key rejection
    with patch.dict(os.environ, {
        "GOOGLE_MAPS_API_KEY": "YOUR_GOOGLE_MAPS_BROWSER_API_KEY"
    }, clear=False):
        gm_client = server.app.test_client()
        ph_data = gm_client.get("/api/config").get_json()
        assert ph_data["is_google_maps_configured"] is False
        assert ph_data["google_maps_api_key"] == ""

    # C. Valid domain-restricted browser key configured -> exposed with billing safeguards while server secrets remain hidden
    fake_browser_gmaps_key = "AIzaSyMatraNaariBrowserRestrictedKey998877"
    fake_secret_service_role = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SuperSecretServiceRole"
    fake_rzp_secret = "rzp_secret_NeverExposeMe999"
    with patch.dict(os.environ, {
        "GOOGLE_MAPS_API_KEY": fake_browser_gmaps_key,
        "GOOGLE_MAPS_MAP_ID": "DEMO_MAP_ID",
        "SUPABASE_SERVICE_ROLE_KEY": fake_secret_service_role,
        "RAZORPAY_KEY_SECRET": fake_rzp_secret
    }, clear=False):
        gm_client = server.app.test_client()
        conf_res = gm_client.get("/api/config")
        assert conf_res.status_code == 200
        conf_raw = conf_res.get_data(as_text=True)
        conf_data = conf_res.get_json()
        assert conf_data["is_google_maps_configured"] is True
        assert conf_data["google_maps_api_key"] == fake_browser_gmaps_key
        assert conf_data["google_maps_map_id"] == "DEMO_MAP_ID"
        safeguards = conf_data["google_maps_billing_safeguards"]
        assert safeguards["session_token_enabled"] is True
        assert safeguards["country_restriction"] == "IN"
        assert safeguards["debounce_ms"] == 380
        assert safeguards["min_query_length"] == 3
        assert safeguards["max_requests_per_session"] == 25
        assert safeguards["fields_mask"] == [
            "id",
            "displayName",
            "formattedAddress",
            "location",
            "addressComponents"
        ]
        assert safeguards["fallback_provider"] == "openstreetmap_nominatim"
        # Verify secret credentials are NEVER leaked in /api/config
        assert fake_secret_service_role not in conf_raw
        assert fake_rzp_secret not in conf_raw
        assert "supabase_service_role_key" not in conf_raw.lower()
        assert "razorpay_key_secret" not in conf_raw.lower()

    # D. Verify checkout.html contains Google Maps JS SDK loader, Places (New) AutocompleteSuggestion, SessionToken,
    #    restricted field mask, draggable marker, manual house_no preservation, and OpenStreetMap fallback
    checkout_html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "checkout.html")
    with open(checkout_html_path, "r", encoding="utf-8") as f:
        checkout_html = f.read()
    assert "maps.googleapis.com/maps/api/js" in checkout_html
    assert "AutocompleteSuggestion.fetchAutocompleteSuggestions" in checkout_html
    assert "AutocompleteSessionToken" in checkout_html
    assert "place.fetchFields" in checkout_html
    assert "'id', 'displayName', 'formattedAddress', 'location', 'addressComponents'" in checkout_html
    assert "includedRegionCodes: ['in']" in checkout_html
    assert "preserveExistingHouseNo: true" in checkout_html
    assert "initLeafletFallbackMap" in checkout_html
    assert "/api/address/autocomplete" in checkout_html
    assert "/api/address/reverse" in checkout_html

    # E. End-to-End Indian Society Autocomplete, Draggable Map Pin & Address Autofill Validation (Preserving Manual Flat/House No.)
    with patch.dict(os.environ, {"DISABLE_EXTERNAL_GEOCODING": "1"}, clear=False):
        soc_client = server.app.test_client()
        soc_email = f"society.test.{os.urandom(3).hex()}@example.com"
        reg_soc = soc_client.post("/api/auth/register", json={
            "name": "Meera Sharma",
            "email": soc_email,
            "phone": "9829098765",
            "password": "SocietyTestPassword123!"
        })
        assert reg_soc.status_code == 200 and reg_soc.get_json().get("ok") is True
        soc_hdrs = {"Authorization": f"Bearer {reg_soc.get_json()['token']}"}

        # Simulate customer manually entering "Flat B-402" and selecting "Mahima Panorama, Jagatpura, Jaipur" from Google Places (New)
        society_autofilled_address = {
            "name": "Meera Sharma",
            "phone": "9829098765",
            "email": soc_email,
            "house_no": "Flat B-402",
            "street_area": "Mahima Panorama, VIT Road, Jagatpura",
            "address_line1": "Flat B-402, Mahima Panorama, VIT Road, Jagatpura",
            "address_line2": "Near SRN International School",
            "city": "Jaipur",
            "state": "Rajasthan",
            "pincode": "302017",
            "latitude": 26.814343,
            "longitude": 75.864358,
            "location_summary": "Mahima Panorama, VIT Road Near SRN INTERNATIONAL SCHOOL, Jagatpura, Jaipur, Rajasthan 302017, India",
            "address_label": "Home"
        }
        val_soc = soc_client.post("/api/address/validate", headers=soc_hdrs, json={
            "address": society_autofilled_address,
            "require_split_fields": True,
            "save_to_account": True,
            "is_default": True
        })
        assert val_soc.status_code == 200 and val_soc.get_json().get("ok") is True
        saved_soc = val_soc.get_json()["address"]
        assert saved_soc["house_no"] == "Flat B-402"
        assert "Mahima Panorama" in saved_soc["street_area"]
        assert saved_soc["city"] == "Jaipur"
        assert saved_soc["state"] == "Rajasthan"
        assert saved_soc["pincode"] == "302017"
        assert abs(saved_soc["latitude"] - 26.814343) < 1e-5
        assert abs(saved_soc["longitude"] - 75.864358) < 1e-5

    print(" [PASS] 29. Google Maps JS API & Places Autocomplete (New) Integration, Billing Safeguards, Secret Isolation & OpenStreetMap Fallback Verified!")
    passed += 1

    # 30. Production COD-Only Mode (Razorpay On Hold + Ready for Future Activation), Real Stock Verification, Order Saving, Stock Deduction & Admin Visibility
    total += 1
    cod_only_admin_key = "CodOnlyLaunchAdmin_2026!"
    with patch.dict(os.environ, {
        "ADMIN_SECRET_KEY": cod_only_admin_key,
        "RAZORPAY_KEY_ID": "rzp_live_ReadyButOnHold123",
        "RAZORPAY_KEY_SECRET": "rzp_secret_ReadyButOnHold987",
        "RAZORPAY_ENABLED": "0",
        "SALES_ENABLED": "1",
        "DISABLE_EXTERNAL_GEOCODING": "1"
    }, clear=False):
        cod_client = server.app.test_client()
        adm_hdrs = {"X-Admin-Passkey": cod_only_admin_key}

        # A. Verify /api/config reports COD & sales enabled, Razorpay credentials intact (is_razorpay_configured=True), and razorpay_enabled=False (on hold)
        cfg_r = cod_client.get("/api/config")
        assert cfg_r.status_code == 200
        cfg_d = cfg_r.get_json()
        assert cfg_d["sales_enabled"] is True
        assert cfg_d["cod_enabled"] is True
        assert cfg_d["razorpay_enabled"] is False
        assert cfg_d["is_razorpay_configured"] is True
        assert cfg_d["razorpay_key_id"] == "rzp_live_ReadyButOnHold123"
        assert "rzp_secret_ReadyButOnHold987" not in cfg_r.get_data(as_text=True)

        # Register isolated test customer
        cust_email = f"cod.launch.{os.urandom(3).hex()}@example.com"
        reg_c = cod_client.post("/api/auth/register", json={
            "name": "Roshni Rathore",
            "email": cust_email,
            "phone": "9829055443",
            "password": "CodLaunchPassword123!"
        })
        assert reg_c.status_code == 200 and reg_c.get_json().get("ok") is True
        cust_hdrs = {"Authorization": f"Bearer {reg_c.get_json()['token']}"}

        valid_cust = {
            "name": "Roshni Rathore",
            "phone": "9829055443",
            "email": cust_email,
            "house_no": "Flat B-402",
            "street_area": "Mahima Panorama, Jagatpura",
            "address_line1": "Flat B-402, Mahima Panorama, Jagatpura",
            "address_line2": "Near VIT Road",
            "city": "Jaipur",
            "state": "Rajasthan",
            "pincode": "302017",
            "latitude": 26.814343,
            "longitude": 75.864358
        }

        # B. Online payment order creation (/api/create-order) MUST be blocked with 503 while Razorpay is on hold
        rzp_hold_r = cod_client.post("/api/create-order", headers=cust_hdrs, json={
            "customer": valid_cust,
            "items": [{"id": "angrakha", "qty": 1, "size": "M", "color": "Ivory"}]
        })
        assert rzp_hold_r.status_code == 503
        rzp_hold_d = rzp_hold_r.get_json()
        assert rzp_hold_d["ok"] is False
        assert rzp_hold_d.get("razorpay_on_hold") is True
        assert rzp_hold_d.get("razorpay_disabled") is True

        # C. Real Product Availability Verification before accepting COD orders
        # 1. Set 'angrakha' Size 'XS' stock to 0 and verify sold-out size is rejected -> 400
        pre_inv = cod_client.get("/api/products/angrakha").get_json()["product"]["sizeStock"]
        zero_xs_stock = dict(pre_inv)
        zero_xs_stock["XS"] = 0
        assert cod_client.post("/api/admin/inventory/update", headers=adm_hdrs, json={
            "id": "angrakha",
            "size_stock": zero_xs_stock
        }).status_code == 200
        sold_out_r = cod_client.post("/api/create-cod-order", headers=cust_hdrs, json={
            "customer": valid_cust,
            "items": [{"id": "angrakha", "qty": 1, "size": "XS", "color": "Ivory"}]
        })
        assert sold_out_r.status_code == 400 and sold_out_r.get_json()["ok"] is False

        # 2. Quantity exceeding available size stock ('angrakha' Size 'S' requesting 99 units) -> 400
        excess_r = cod_client.post("/api/create-cod-order", headers=cust_hdrs, json={
            "customer": valid_cust,
            "items": [{"id": "angrakha", "qty": 99, "size": "S", "color": "Ivory"}]
        })
        assert excess_r.status_code == 400 and excess_r.get_json()["ok"] is False

        # D. Valid COD Checkout, Order Saving, Atomic Stock Deduction & Admin Order Visibility
        before_prod = cod_client.get("/api/products/angrakha").get_json()["product"]
        before_total_stock = int(before_prod["stock"])
        before_m_stock = int(before_prod["sizeStock"]["M"])
        expected_unit_price = int(before_prod["price"])  # ₹1799

        # Client sends tampered price=50 -> server must enforce real DB price (₹1799 * 2 = ₹3598, free shipping >= ₹999)
        cod_ok_r = cod_client.post("/api/create-cod-order", headers=cust_hdrs, json={
            "customer": valid_cust,
            "items": [{"id": "angrakha", "qty": 2, "size": "M", "color": "Ivory", "price": 50}]
        })
        assert cod_ok_r.status_code == 200, f"COD order failed: {cod_ok_r.get_json()}"
        cod_ok_d = cod_ok_r.get_json()
        assert cod_ok_d["ok"] is True
        new_cod_id = cod_ok_d["order_id"]
        assert cod_ok_d["total_amount"] == expected_unit_price * 2

        # Verify stock & size stock deducted by exactly 2 units
        after_prod = cod_client.get("/api/products/angrakha").get_json()["product"]
        assert int(after_prod["stock"]) == before_total_stock - 2
        assert int(after_prod["sizeStock"]["M"]) == before_m_stock - 2

        # Verify order is visible in Admin Orders (/api/admin/orders) and Admin Stats (/api/admin/stats)
        adm_orders_r = cod_client.get("/api/admin/orders", headers=adm_hdrs)
        assert adm_orders_r.status_code == 200
        adm_orders_list = adm_orders_r.get_json()["orders"]
        matched_adm_order = next((o for o in adm_orders_list if o["id"] == new_cod_id), None)
        assert matched_adm_order is not None, f"Order {new_cod_id} not visible in /api/admin/orders"
        assert matched_adm_order["payment_method"] == "cod"
        assert matched_adm_order["payment_status"] == "cod_confirmed"
        assert matched_adm_order["order_status"] == "confirmed"
        assert matched_adm_order["total_amount"] == expected_unit_price * 2

        adm_stats_r = cod_client.get("/api/admin/stats", headers=adm_hdrs)
        assert adm_stats_r.status_code == 200 and adm_stats_r.get_json()["ok"] is True

        # E. Verify checkout.html keeps both payment options visible (COD enabled & selected; Razorpay visible & disabled with Temporarily Unavailable · Coming Soon badge) while ready for future activation
        assert "let selectedPaymentMethod = 'cod';" in checkout_html
        assert "function isRazorpayEnabledInConfig()" in checkout_html
        assert "Place Cash on Delivery Order" in checkout_html
        assert "new Razorpay(options)" in checkout_html
        assert "Razorpay Online Payment (UPI, Cards, Net Banking)" in checkout_html
        assert "Temporarily Unavailable · Coming Soon" in checkout_html
        assert 'class="payment-option-label hidden' not in checkout_html
        assert "rzpLabel.classList.add('hidden')" not in checkout_html

    print(" [PASS] 30. Production COD-Only Mode (Razorpay On Hold + Ready for Future Activation), Real Stock Verification, Order Saving, Stock Deduction & Admin Visibility Verified!")
    passed += 1

    print("=" * 60)
    print(f" ALL {passed}/{total} TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
