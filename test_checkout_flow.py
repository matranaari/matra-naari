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
    total += 1
    status, body, _ = make_request("/api/create-order", method="POST", payload={
        "customer": test_customer,
        "items": test_items
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

    print("=" * 60)
    print(f" ALL {passed}/{total} TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
