#!/usr/bin/env python3
"""
Isolated Automated Test Suite for Matra Naari Order Confirmation & Owner Alert Notifications
Tests all 9 required scenarios against a temporary SQLite database with mocked transports.
Never touches production Supabase or sends external network requests.
"""

import os
import hmac
import json
import hashlib
import tempfile
import unittest
from unittest.mock import patch

import server
import notifications


class FakeHttpResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class OrderNotificationAutomationTests(unittest.TestCase):
    def setUp(self):
        # Ensure complete isolation from production database and live providers
        os.environ.pop("DATABASE_URL", None)
        os.environ.pop("POSTGRES_SCHEMA", None)
        os.environ.pop("NOTIFICATION_ALLOWED_RECIPIENTS", None)

        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_orders.db")
        self.config_path = os.path.join(self.tmp_dir.name, "test_config.json")

        self.test_key_id = "rzp_live_TestKeyId12345"
        self.test_key_secret = "TestLiveSecretKey987654321"
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "razorpay_key_id": self.test_key_id,
                    "razorpay_key_secret": self.test_key_secret,
                    "razorpay_enabled": True,
                    "cod_enabled": True,
                    "sales_enabled": True,
                    "free_shipping_threshold": 999,
                    "shipping_fee": 99,
                    "support_email": "matranaari@gmail.com",
                    "support_phone": "+91 88493 66915",
                },
                f,
            )

        server.DATA_DIR = self.tmp_dir.name
        server.DB_PATH = self.db_path
        server.DATABASE_URL = ""
        server.CONFIG_PATH = self.config_path
        server.init_db()

        self.sent_emails = []
        self.sent_whatsapps = []

        def fake_email_transport(to_email, subject, html_body, text_body, from_address, reply_to):
            self.sent_emails.append(
                {
                    "to": to_email,
                    "subject": subject,
                    "html": html_body,
                    "text": text_body,
                    "from": from_address,
                    "reply_to": reply_to,
                }
            )
            return True, f"email_{len(self.sent_emails)}", ""

        def fake_whatsapp_transport(to_wa_id, payload, sender_number):
            self.sent_whatsapps.append(
                {
                    "to": f"+{to_wa_id}" if not str(to_wa_id).startswith("+") else str(to_wa_id),
                    "payload": payload,
                }
            )
            return True, f"wamid_{len(self.sent_whatsapps)}", ""

        notifications.set_test_transports(
            email_fn=fake_email_transport,
            whatsapp_fn=fake_whatsapp_transport,
        )

        self.client = server.app.test_client()
        reg_res = self.client.post(
            "/api/auth/register",
            json={
                "name": "Ananya Sharma",
                "email": "ananya.test@example.com",
                "phone": "9876543210",
                "password": "Password123!",
            },
        )
        reg_data = reg_res.get_json()
        self.assertTrue(reg_data.get("ok"), f"Auth register failed: {reg_data}")
        self.auth_token = reg_data["token"]
        self.auth_headers = {"Authorization": f"Bearer {self.auth_token}"}

    def tearDown(self):
        notifications.set_test_transports(None, None)
        os.environ.pop("NOTIFICATION_ALLOWED_RECIPIENTS", None)
        self.tmp_dir.cleanup()

    def _sample_checkout_payload(self, whatsapp_opt_in=True):
        return {
            "customer": {
                "name": "Ananya Sharma",
                "email": "ananya.test@example.com",
                "phone": "9876543210",
                "house_no": "Flat 402, Tower B",
                "street_area": "Lotus Enclave, MI Road",
                "address_line1": "Flat 402, Tower B, Lotus Enclave, MI Road",
                "address_line2": "Near Central Park Gate 2",
                "city": "Jaipur",
                "state": "Rajasthan",
                "pincode": "302001",
                "address_label": "Home",
                "whatsapp_opt_in": whatsapp_opt_in,
            },
            "items": [
                {
                    "id": "straight",
                    "size": "M",
                    "color": "Burgundy",
                    "qty": 2,
                }
            ],
        }

    def test_01_website_official_contact_links_and_config(self):
        """Verify official email (matranaari@gmail.com) and WhatsApp (+91 8849366915) across HTML, JS, and API."""
        cfg_res = self.client.get("/api/config").get_json()
        self.assertTrue(cfg_res["ok"])
        self.assertEqual(cfg_res["support_email"], "matranaari@gmail.com")
        self.assertIn("88493", cfg_res["support_phone"])

        html_files = [
            "index.html",
            "contact.html",
            "contact/index.html",
            "shop.html",
            "shop/index.html",
            "product.html",
            "story.html",
            "story/index.html",
            "cart.html",
            "cart/index.html",
            "checkout.html",
            "checkout/index.html",
            "order-confirmation.html",
            "order-confirmation/index.html",
            "account.html",
        ]
        for rel_path in html_files:
            full_path = os.path.join(server.BASE_DIR, rel_path)
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("hello@naari.in", content, f"Stale email found in {rel_path}")
            self.assertIn("mailto:matranaari@gmail.com", content, f"Missing clickable mailto in {rel_path}")
            self.assertIn("https://wa.me/918849366915", content, f"Missing clickable wa.me link in {rel_path}")

    def test_02_successful_cod_order_triggers_all_three_notifications(self):
        """Verify COD order sends customer email, owner email, and customer WhatsApp with COD pending payment status."""
        payload = self._sample_checkout_payload(whatsapp_opt_in=True)
        res = self.client.post("/api/create-cod-order", json=payload, headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["ok"])
        order_id = data["order_id"]

        # 2 emails (1 customer + 1 owner) and 1 WhatsApp template message
        self.assertEqual(len(self.sent_emails), 2)
        self.assertEqual(len(self.sent_whatsapps), 1)

        cust_email = next(e for e in self.sent_emails if e["to"] == "ananya.test@example.com")
        owner_email = next(e for e in self.sent_emails if e["to"] == "matranaari@gmail.com")

        # Verify customer email contents
        self.assertIn(order_id, cust_email["subject"])
        self.assertIn("MATRA NAARI", cust_email["html"])
        self.assertIn("Ananya Sharma", cust_email["html"])
        self.assertIn("Gulmohar Straight Kurti", cust_email["html"])
        self.assertIn("Cash on Delivery (COD)", cust_email["html"])
        self.assertIn("Payment Pending Collection on Delivery", cust_email["html"])
        self.assertNotIn("PAID &amp; VERIFIED", cust_email["html"])
        self.assertIn("Flat 402, Tower B, Lotus Enclave, MI Road", cust_email["html"])
        self.assertIn("mailto:matranaari@gmail.com", cust_email["html"])
        self.assertIn("https://wa.me/918849366915", cust_email["html"])
        self.assertIn("IST", cust_email["html"])

        # Verify owner alert email contents
        self.assertIn(order_id, owner_email["subject"])
        self.assertIn("Cash on Delivery (COD)", owner_email["subject"])
        self.assertIn("Ananya Sharma", owner_email["html"])
        self.assertIn("9876543210", owner_email["html"])
        self.assertIn("ananya.test@example.com", owner_email["html"])
        self.assertIn("Payment Pending Collection on Delivery", owner_email["html"])

        # Verify WhatsApp Cloud API template payload
        wa_msg = self.sent_whatsapps[0]
        self.assertEqual(wa_msg["to"], "+919876543210")
        self.assertEqual(wa_msg["payload"]["type"], "template")
        self.assertEqual(wa_msg["payload"]["template"]["name"], "matra_naari_order_confirmation")
        params = [p["text"] for p in wa_msg["payload"]["template"]["components"][0]["parameters"]]
        self.assertEqual(len(params), 6)
        self.assertEqual(params[0], "Ananya Sharma")
        self.assertEqual(params[1], order_id)
        self.assertIn("Pending Collection on Delivery", params[3])
        self.assertEqual(params[4], "Confirmed")
        self.assertIn("matranaari@gmail.com", params[5])

    def test_03_razorpay_order_triggers_only_after_hmac_verification_and_is_idempotent(self):
        """Verify create-order sends 0 notifications, verify-payment sends 3, and duplicate verify sends 0."""
        payload = self._sample_checkout_payload(whatsapp_opt_in=True)
        fake_rzp_order_id = "order_LiveRzpOrder999"

        with patch("server.requests.post", return_value=FakeHttpResponse(200, {"id": fake_rzp_order_id, "status": "created"})):
            create_res = self.client.post("/api/create-order", json=payload, headers=self.auth_headers)
        self.assertEqual(create_res.status_code, 200)
        create_data = create_res.get_json()
        order_id = create_data["order_id"]

        # CRITICAL: No notifications while order is pending_payment
        self.assertEqual(len(self.sent_emails), 0)
        self.assertEqual(len(self.sent_whatsapps), 0)

        # Compute valid HMAC-SHA256 signature
        fake_payment_id = "pay_LiveRzpPay888"
        sig_msg = f"{fake_rzp_order_id}|{fake_payment_id}".encode("utf-8")
        valid_sig = hmac.new(self.test_key_secret.encode("utf-8"), sig_msg, hashlib.sha256).hexdigest()

        verify_res = self.client.post(
            "/api/verify-payment",
            json={
                "order_id": order_id,
                "razorpay_order_id": fake_rzp_order_id,
                "razorpay_payment_id": fake_payment_id,
                "razorpay_signature": valid_sig,
            },
            headers=self.auth_headers,
        )
        self.assertEqual(verify_res.status_code, 200)
        verify_data = verify_res.get_json()
        self.assertTrue(verify_data["ok"])
        self.assertEqual(verify_data["status"], "paid")

        # Now all 3 notifications must be sent with Verified Paid status
        self.assertEqual(len(self.sent_emails), 2)
        self.assertEqual(len(self.sent_whatsapps), 1)
        cust_email = next(e for e in self.sent_emails if e["to"] == "ananya.test@example.com")
        self.assertIn("PAID &amp; VERIFIED", cust_email["html"])
        self.assertIn("cryptographically verified", cust_email["html"])
        self.assertIn(fake_payment_id, cust_email["html"])

        # Duplicate /api/verify-payment request -> must NOT send duplicate emails or WhatsApp messages
        dup_res = self.client.post(
            "/api/verify-payment",
            json={
                "order_id": order_id,
                "razorpay_order_id": fake_rzp_order_id,
                "razorpay_payment_id": fake_payment_id,
                "razorpay_signature": valid_sig,
            },
            headers=self.auth_headers,
        )
        self.assertEqual(dup_res.status_code, 200)
        dup_data = dup_res.get_json()
        self.assertTrue(dup_data.get("already_verified"))
        self.assertEqual(len(self.sent_emails), 2)
        self.assertEqual(len(self.sent_whatsapps), 1)
        self.assertEqual(dup_data["notifications"]["channels"]["customer_email"]["status"], "already_sent")
        self.assertEqual(dup_data["notifications"]["channels"]["owner_email"]["status"], "already_sent")
        self.assertEqual(dup_data["notifications"]["channels"]["customer_whatsapp"]["status"], "already_sent")

    def test_04_failed_or_abandoned_checkout_never_triggers_notifications(self):
        """Verify failed HMAC verification and /api/payment-failed send zero notifications."""
        payload = self._sample_checkout_payload(whatsapp_opt_in=True)
        fake_rzp_order_id = "order_LiveRzpFailed111"

        with patch("server.requests.post", return_value=FakeHttpResponse(200, {"id": fake_rzp_order_id, "status": "created"})):
            create_res = self.client.post("/api/create-order", json=payload, headers=self.auth_headers)
        order_id = create_res.get_json()["order_id"]

        # 1. Invalid signature attempt
        bad_verify = self.client.post(
            "/api/verify-payment",
            json={
                "order_id": order_id,
                "razorpay_order_id": fake_rzp_order_id,
                "razorpay_payment_id": "pay_LiveBad999",
                "razorpay_signature": "0000badsignature0000",
            },
            headers=self.auth_headers,
        )
        self.assertEqual(bad_verify.status_code, 400)
        self.assertEqual(len(self.sent_emails), 0)
        self.assertEqual(len(self.sent_whatsapps), 0)

        # 2. Explicit payment-failed callback
        fail_res = self.client.post(
            "/api/payment-failed",
            json={
                "order_id": order_id,
                "razorpay_order_id": fake_rzp_order_id,
                "reason": "Payment cancelled by customer",
            },
            headers=self.auth_headers,
        )
        self.assertEqual(fail_res.status_code, 200)
        self.assertEqual(len(self.sent_emails), 0)
        self.assertEqual(len(self.sent_whatsapps), 0)

    def test_05_provider_failures_never_break_checkout_and_bounded_retries_work(self):
        """Verify email/WhatsApp provider outages do not fail order creation and bounded retries stop at 3."""
        def failing_email_transport(to_email, subject, html_body, text_body, cfg):
            raise RuntimeError("Simulated SMTP/HTTP 503 outage")

        def failing_whatsapp_transport(to_phone_e164, payload, cfg):
            return {"ok": False, "provider": "mock_whatsapp", "error": "Simulated Meta API 500 error"}

        notifications.set_test_transports(
            email_fn=failing_email_transport,
            whatsapp_fn=failing_whatsapp_transport,
        )

        payload = self._sample_checkout_payload(whatsapp_opt_in=True)
        res = self.client.post("/api/create-cod-order", json=payload, headers=self.auth_headers)
        # Checkout MUST still succeed with HTTP 200!
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["ok"])
        order_id = data["order_id"]
        self.assertEqual(data["notifications"]["channels"]["customer_email"]["status"], "failed")
        self.assertEqual(data["notifications"]["channels"]["customer_email"]["attempt_count"], 1)
        self.assertEqual(data["notifications"]["channels"]["customer_whatsapp"]["status"], "failed")

        # Attempt 2 & Attempt 3 also fail
        r2 = notifications.trigger_order_confirmation_notifications(server.get_db, order_id)
        self.assertEqual(r2["channels"]["customer_email"]["attempt_count"], 2)
        r3 = notifications.trigger_order_confirmation_notifications(server.get_db, order_id)
        self.assertEqual(r3["channels"]["customer_email"]["attempt_count"], 3)

        # Attempt 4 is blocked by bounded retry cap (MAX_NOTIFICATION_ATTEMPTS = 3)
        r4 = notifications.trigger_order_confirmation_notifications(server.get_db, order_id)
        self.assertEqual(r4["channels"]["customer_email"]["status"], "max_attempts_exceeded")
        self.assertEqual(r4["channels"]["customer_email"]["attempt_count"], 3)

    def test_06_customer_whatsapp_opt_out_and_allowlist_guard(self):
        """Verify whatsapp_opt_in=False skips WhatsApp while sending emails, and allowlist blocks non-allowlisted recipients."""
        # 1. Customer unchecks WhatsApp opt-in at checkout
        payload = self._sample_checkout_payload(whatsapp_opt_in=False)
        res = self.client.post("/api/create-cod-order", json=payload, headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(len(self.sent_emails), 2)
        self.assertEqual(len(self.sent_whatsapps), 0)
        self.assertEqual(data["notifications"]["channels"]["customer_whatsapp"]["status"], "skipped_no_consent")

        # 2. Test recipient allowlist protection
        self.sent_emails.clear()
        self.sent_whatsapps.clear()
        os.environ["NOTIFICATION_ALLOWED_RECIPIENTS"] = "matranaari@gmail.com"
        payload2 = self._sample_checkout_payload(whatsapp_opt_in=True)
        res2 = self.client.post("/api/create-cod-order", json=payload2, headers=self.auth_headers)
        data2 = res2.get_json()
        # Only matranaari@gmail.com is in allowlist; customer email & WhatsApp must be blocked
        self.assertEqual(len(self.sent_emails), 1)
        self.assertEqual(self.sent_emails[0]["to"], "matranaari@gmail.com")
        self.assertEqual(len(self.sent_whatsapps), 0)
        self.assertEqual(data2["notifications"]["channels"]["customer_email"]["status"], "blocked_not_in_allowlist")
        self.assertEqual(data2["notifications"]["channels"]["customer_whatsapp"]["status"], "blocked_not_in_allowlist")
        self.assertEqual(data2["notifications"]["channels"]["owner_email"]["status"], "sent")

    def test_07_whatsapp_disabled_by_default_and_env_var_check(self):
        """Verify WhatsApp API sending remains disabled by default until WHATSAPP_ENABLED=true, and /api/config checks all 5 email env vars."""
        # Remove test whatsapp transport so production default WHATSAPP_ENABLED=false applies
        notifications.set_test_transports(
            email_fn=notifications._TEST_EMAIL_TRANSPORT,
            whatsapp_fn=None,
        )
        os.environ.pop("WHATSAPP_ENABLED", None)
        os.environ["EMAIL_PROVIDER"] = "resend"
        os.environ["RESEND_API_KEY"] = "re_test_dummy_key_not_real"
        os.environ["EMAIL_FROM_ADDRESS"] = "Matra Naari <orders@matranaari.com>"
        os.environ["EMAIL_REPLY_TO"] = "matranaari@gmail.com"
        os.environ["OWNER_NOTIFICATION_EMAIL"] = "matranaari@gmail.com"
        try:
            cfg_res = self.client.get("/api/config").get_json()
            notif_cfg = cfg_res["notifications"]
            self.assertFalse(notif_cfg["whatsapp_enabled"])
            self.assertFalse(notif_cfg["is_whatsapp_configured"])
            self.assertTrue(notif_cfg["is_email_configured"])
            env_flags = notif_cfg["required_email_env_vars_present"]
            for req_key in (
                "EMAIL_PROVIDER",
                "RESEND_API_KEY",
                "EMAIL_FROM_ADDRESS",
                "EMAIL_REPLY_TO",
                "OWNER_NOTIFICATION_EMAIL",
            ):
                self.assertIs(env_flags[req_key], True, f"Expected {req_key} presence flag to be True")
            # Ensure secret value is never exposed in /api/config
            self.assertNotIn("re_test_dummy_key_not_real", json.dumps(cfg_res))

            payload = self._sample_checkout_payload(whatsapp_opt_in=True)
            res = self.client.post("/api/create-cod-order", json=payload, headers=self.auth_headers)
            data = res.get_json()
            self.assertEqual(len(self.sent_emails), 2)
            self.assertEqual(len(self.sent_whatsapps), 0)
            self.assertEqual(data["notifications"]["channels"]["customer_whatsapp"]["status"], "skipped_whatsapp_disabled")
        finally:
            for k in (
                "EMAIL_PROVIDER",
                "RESEND_API_KEY",
                "EMAIL_FROM_ADDRESS",
                "EMAIL_REPLY_TO",
                "OWNER_NOTIFICATION_EMAIL",
            ):
                os.environ.pop(k, None)

    def test_08_historical_orders_never_trigger_notifications(self):
        """Verify historical orders (>24h old) never receive notifications on init_db() or manual trigger."""
        conn = server.get_db()
        c = conn.cursor()
        hist_id = "NAARI-20260320091848-773332"
        c.execute(
            """
            INSERT INTO orders (
                id, customer_name, customer_email, customer_phone,
                address_line1, address_line2, city, state, pincode,
                payment_method, payment_status, order_status,
                subtotal, shipping, discount_amount, coupon_code, total_amount, items_json,
                user_id, whatsapp_opt_in, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hist_id,
                "Historical Customer",
                "historical@example.com",
                "9876543210",
                "12 Heritage Lane",
                "",
                "Jaipur",
                "Rajasthan",
                "302001",
                "cod",
                "cod_confirmed",
                "confirmed",
                1299,
                0,
                0,
                "",
                1299,
                json.dumps([{"id": "straight", "name": "Gulmohar Straight Kurti", "size": "M", "qty": 1, "price": 1299}]),
                "usr_hist",
                1,
                "2026-03-20T09:18:48",
                "2026-03-20T09:18:48",
            ),
        )
        conn.commit()
        conn.close()

        # Re-running init_db() on startup must never send notifications for existing orders
        server.init_db()
        self.assertEqual(len(self.sent_emails), 0)
        self.assertEqual(len(self.sent_whatsapps), 0)

        # Even a direct call to trigger_order_confirmation_notifications on a historical order is blocked
        hist_res = notifications.trigger_order_confirmation_notifications(server.get_db, hist_id)
        self.assertFalse(hist_res["ok"])
        self.assertEqual(hist_res["reason"], "historical_order_skipped")
        self.assertEqual(len(self.sent_emails), 0)
        self.assertEqual(len(self.sent_whatsapps), 0)

    def test_09_explicit_whatsapp_consent_default_zero_and_null_handling(self):
        """Verify whatsapp_opt_in defaults to 0 for new records without explicit consent and NULL/0 is never treated as opted in."""
        payload = self._sample_checkout_payload()
        payload["customer"].pop("whatsapp_opt_in", None)
        payload.pop("whatsapp_opt_in", None)

        res = self.client.post("/api/create-cod-order", json=payload, headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        order_id = data["order_id"]

        # Verify DB stored whatsapp_opt_in = 0 by default
        conn = server.get_db()
        c = conn.cursor()
        c.execute("SELECT whatsapp_opt_in FROM orders WHERE id = ?", (order_id,))
        row = c.fetchone()
        conn.close()
        self.assertEqual(row["whatsapp_opt_in"], 0)

        # Emails sent, WhatsApp skipped due to no explicit consent
        self.assertEqual(len(self.sent_emails), 2)
        self.assertEqual(len(self.sent_whatsapps), 0)
        self.assertEqual(data["notifications"]["channels"]["customer_whatsapp"]["status"], "skipped_no_consent")

        # Verify NULL, 0, False, '', and missing whatsapp_opt_in all evaluate to False
        for non_consent_val in (None, 0, False, "", "0", "false", "no", "off"):
            self.assertFalse(
                notifications.has_explicit_whatsapp_consent({"whatsapp_opt_in": non_consent_val}),
                f"Expected False for {non_consent_val!r}",
            )
        self.assertFalse(notifications.has_explicit_whatsapp_consent({}))
        for explicit_val in (1, True, "1", "true", "yes", "on"):
            self.assertTrue(
                notifications.has_explicit_whatsapp_consent({"whatsapp_opt_in": explicit_val}),
                f"Expected True for {explicit_val!r}",
            )

    def test_10_render_restart_recovery_and_retry_without_duplicates(self):
        """Verify notification jobs survive Render restarts via order_notifications and partial failures retry without duplicates."""
        # 1. Simulate a partial failure on checkout: customer_email succeeds, owner_email fails
        call_counts = {"customer": 0, "owner": 0}

        def partial_fail_email_transport(to_email, subject, html_body, text_body, from_address, reply_to):
            if to_email == "matranaari@gmail.com":
                call_counts["owner"] += 1
                if call_counts["owner"] == 1:
                    return False, "", "Simulated transient Resend 503 on owner alert"
            else:
                call_counts["customer"] += 1
            self.sent_emails.append({"to": to_email, "subject": subject})
            return True, f"msg_{len(self.sent_emails)}", ""

        notifications.set_test_transports(
            email_fn=partial_fail_email_transport,
            whatsapp_fn=None,
        )

        payload = self._sample_checkout_payload(whatsapp_opt_in=False)
        res = self.client.post("/api/create-cod-order", json=payload, headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        order_id = data["order_id"]

        # Customer email succeeded (1), owner email failed on attempt 1
        self.assertEqual(data["notifications"]["channels"]["customer_email"]["status"], "sent")
        self.assertEqual(data["notifications"]["channels"]["owner_email"]["status"], "failed")
        self.assertEqual(call_counts["customer"], 1)
        self.assertEqual(call_counts["owner"], 1)
        self.assertEqual(len(self.sent_emails), 1)

        # Now run startup/background recovery: must retry ONLY owner_email and NOT re-send customer_email
        rec_res = server.recover_order_notifications_on_startup()
        self.assertTrue(rec_res["ok"])
        self.assertEqual(rec_res["recovered_count"], 1)
        self.assertEqual(call_counts["customer"], 1, "Customer email must NOT be sent a second time!")
        self.assertEqual(call_counts["owner"], 2, "Owner email must be retried once and succeed!")
        self.assertEqual(len(self.sent_emails), 2)

        # Running recovery again does nothing (0 pending/failed jobs left)
        rec_res_2 = server.recover_order_notifications_on_startup()
        self.assertEqual(rec_res_2["recovered_count"], 0)
        self.assertEqual(len(self.sent_emails), 2)

        # 2. Simulate Render restart immediately after order transaction COMMIT (before trigger_order_confirmation_notifications runs)
        self.sent_emails.clear()
        conn = server.get_db()
        c = conn.cursor()
        restart_oid = "NAARI-RESTART-TEST-001"
        now_iso = server.datetime.now().isoformat()
        ord_dict = {
            "id": restart_oid,
            "customer_name": "Restart Test User",
            "customer_email": "restart.user@example.com",
            "customer_phone": "9876543210",
            "address_line1": "101 MG Road",
            "city": "Pune",
            "state": "Maharashtra",
            "pincode": "411001",
            "payment_method": "cod",
            "payment_status": "cod_confirmed",
            "order_status": "confirmed",
            "subtotal": 1299,
            "shipping": 0,
            "discount_amount": 0,
            "coupon_code": "",
            "total_amount": 1299,
            "items_json": json.dumps([{"id": "straight", "name": "Gulmohar Straight Kurti", "size": "M", "qty": 1, "price": 1299}]),
            "user_id": "usr_restart",
            "whatsapp_opt_in": 0,
            "created_at": now_iso,
            "updated_at": now_iso,
        }
        c.execute(
            """
            INSERT INTO orders (
                id, customer_name, customer_email, customer_phone,
                address_line1, city, state, pincode,
                payment_method, payment_status, order_status,
                subtotal, shipping, discount_amount, coupon_code, total_amount, items_json,
                user_id, whatsapp_opt_in, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ord_dict["id"], ord_dict["customer_name"], ord_dict["customer_email"], ord_dict["customer_phone"],
                ord_dict["address_line1"], ord_dict["city"], ord_dict["state"], ord_dict["pincode"],
                ord_dict["payment_method"], ord_dict["payment_status"], ord_dict["order_status"],
                ord_dict["subtotal"], ord_dict["shipping"], ord_dict["discount_amount"], ord_dict["coupon_code"],
                ord_dict["total_amount"], ord_dict["items_json"], ord_dict["user_id"], ord_dict["whatsapp_opt_in"],
                ord_dict["created_at"], ord_dict["updated_at"],
            ),
        )
        notifications.enqueue_order_confirmation_notifications(ord_dict, cursor=c)
        conn.commit()
        conn.close()

        # Simulate Render restart recovery picking up the committed 'pending' notification jobs
        rec_restart = server.recover_order_notifications_on_startup()
        self.assertTrue(rec_restart["ok"])
        self.assertEqual(rec_restart["recovered_count"], 1)
        self.assertEqual(len(self.sent_emails), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
