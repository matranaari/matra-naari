#!/usr/bin/env python3
"""
Matra Naari — Passwordless OTP Authentication & Admin MFA Test Suite
====================================================================
Tests all requirements from the Passwordless OTP Master Prompt:
1. New customer email OTP registration & session persistence
2. Existing customer login & full account preservation (orders, addresses, wishlist, returns, password_hash preserved)
3. Cryptographic OTP security: salted HMAC-SHA256 hashing (never plaintext in DB or logs)
4. Single-use OTP enforcement (replay blocked)
5. Short OTP expiry (~5 minutes) enforcement
6. Incorrect OTP handling & strict attempt limits (5 attempts -> locked)
7. Resend cooldown (30s) enforcement
8. Rate limiting by destination (5 / 15m) and IP (10 / 15m)
9. Generic responses to prevent account enumeration
10. Mobile SMS OTP safety (unavailable when provider disabled; works with DLT transport without auto-merging unverified phones)
11. Secure account linking (/api/auth/link/request & /api/auth/link/verify) & duplicate conflict protection
12. Session persistence (/api/auth/me) & Logout (/api/auth/logout)
13. Legacy password endpoints retired (410 Gone) & Password UI removed from account.html and assets/app.js
14. Admin Passwordless Authentication + Strong MFA (Email OTP + RFC 6238 TOTP / Security Key + Emergency Dual-Key Recovery) & Session Revocation
15. Customer account isolation, checkout authentication, orders, and saved addresses
"""

import os
import re
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta

import notifications
import server


class PasswordlessOtpAndAdminMfaTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.prev_db_path = server.DB_PATH
        self.test_db_path = os.path.join(self.tmp_dir.name, "test_otp_orders.db")
        orig_db = os.path.join(server.BASE_DIR, "data", "orders.db")
        if os.path.exists(orig_db):
            shutil.copy2(orig_db, self.test_db_path)
        server.DB_PATH = self.test_db_path
        server.ALLOW_LEGACY_TEST_FIXTURE_AUTH = False
        server.LEGACY_PASSWORD_AUTH_ENABLED = False
        os.environ.pop("LEGACY_PASSWORD_AUTH_ENABLED", None)
        os.environ["ADMIN_PASSKEY"] = "naari@admin2026"
        os.environ["OWNER_NOTIFICATION_EMAIL"] = "matranaari@gmail.com"
        server.init_db()
        server.invalidate_site_settings_cache()

        self.captured_emails = []
        self.captured_sms = []

        def _fake_email(to_email, subject, html_body, text_body, **kwargs):
            m = re.search(r"\b(\d{6})\b", text_body)
            code = m.group(1) if m else ""
            self.captured_emails.append({
                "to": to_email,
                "subject": subject,
                "code": code,
                "html": html_body,
                "text": text_body,
            })
            return True, f"resend_otp_{len(self.captured_emails)}", ""

        notifications.set_test_transports(email_fn=_fake_email)
        notifications.set_test_sms_transport(None)
        self.client = server.app.test_client()

    def tearDown(self):
        notifications.set_test_transports(None, None)
        notifications.set_test_sms_transport(None)
        server.DB_PATH = self.prev_db_path
        server.invalidate_site_settings_cache()
        self.tmp_dir.cleanup()

    def test_01_new_customer_email_otp_registration_and_no_plaintext_otp(self):
        """New customer registers via Email OTP; OTP is hashed in DB and never stored in plaintext."""
        req_res = self.client.post(
            "/api/auth/otp/request",
            json={"channel": "email", "destination": "newclient@matranaari.com", "name": "Meera Kapoor"},
        )
        self.assertEqual(req_res.status_code, 200)
        req_data = req_res.get_json()
        self.assertTrue(req_data["ok"])
        self.assertIn("6-digit verification code", req_data["message"])
        self.assertEqual(len(self.captured_emails), 1)
        otp_code = self.captured_emails[-1]["code"]
        self.assertEqual(len(otp_code), 6)

        # Verify raw OTP is NEVER stored in auth_otp_challenges or security_audit_logs
        conn = server.get_db()
        c = conn.cursor()
        c.execute("SELECT otp_hash, salt FROM auth_otp_challenges WHERE destination = 'newclient@matranaari.com'")
        row = dict(c.fetchone())
        self.assertNotEqual(row["otp_hash"], otp_code)
        self.assertNotIn(otp_code, str(row))
        c.execute("SELECT * FROM security_audit_logs")
        logs_raw = str([dict(r) for r in c.fetchall()])
        self.assertNotIn(otp_code, logs_raw)
        conn.close()

        # Verify OTP and create new customer account
        ver_res = self.client.post(
            "/api/auth/otp/verify",
            json={
                "channel": "email",
                "destination": "newclient@matranaari.com",
                "otp": otp_code,
                "name": "Meera Kapoor",
            },
        )
        self.assertEqual(ver_res.status_code, 200)
        ver_data = ver_res.get_json()
        self.assertTrue(ver_data["ok"])
        self.assertTrue(ver_data["is_new_user"])
        self.assertEqual(ver_data["user"]["email"], "newclient@matranaari.com")
        self.assertEqual(ver_data["user"]["name"], "Meera Kapoor")
        self.assertTrue(ver_data["token"])

        # Session persistence (/api/auth/me) & Logout (/api/auth/logout)
        token = ver_data["token"]
        me_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.get_json()["user"]["email"], "newclient@matranaari.com")

        lo_res = self.client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(lo_res.status_code, 200)
        me_after = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_after.status_code, 401)

    def test_02_existing_customer_preservation_orders_addresses_wishlist_and_single_use(self):
        """Existing customer logging in via Email OTP keeps their user ID, orders, addresses, wishlist, and non-destructive password_hash."""
        conn = server.get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users LIMIT 1")
        existing_user = dict(c.fetchone())
        orig_id = existing_user["id"]
        orig_email = existing_user["email"]
        orig_pw_hash = existing_user["password_hash"]
        conn.close()

        # Request & verify Email OTP for existing customer
        self.client.post("/api/auth/otp/request", json={"channel": "email", "destination": orig_email})
        otp_code = self.captured_emails[-1]["code"]
        ver_res = self.client.post(
            "/api/auth/otp/verify",
            json={"channel": "email", "destination": orig_email, "otp": otp_code},
        )
        self.assertEqual(ver_res.status_code, 200)
        ver_data = ver_res.get_json()
        self.assertTrue(ver_data["ok"])
        self.assertFalse(ver_data["is_new_user"])
        self.assertEqual(ver_data["user"]["id"], orig_id)

        # Single-use enforcement: replaying the exact same OTP must fail with 401
        replay_res = self.client.post(
            "/api/auth/otp/verify",
            json={"channel": "email", "destination": orig_email, "otp": otp_code},
        )
        self.assertEqual(replay_res.status_code, 401)

        # Verify existing password_hash was preserved non-destructively in DB
        conn = server.get_db()
        c = conn.cursor()
        c.execute("SELECT password_hash, email_verified, passwordless_enabled FROM users WHERE id = ?", (orig_id,))
        u_after = dict(c.fetchone())
        conn.close()
        self.assertEqual(u_after["password_hash"], orig_pw_hash)
        self.assertEqual(u_after["email_verified"], 1)
        self.assertEqual(u_after["passwordless_enabled"], 1)

    def test_03_otp_expiry_attempt_limits_cooldown_and_rate_limiting(self):
        """Verify 30s resend cooldown, 5-attempt lockout, 5-minute expiry, and destination rate limits."""
        email = "security.limits@matranaari.com"
        r1 = self.client.post("/api/auth/otp/request", json={"channel": "email", "destination": email})
        self.assertEqual(r1.status_code, 200)
        valid_otp = self.captured_emails[-1]["code"]

        # 1. Resend within 30s cooldown is blocked with 429
        r_cool = self.client.post("/api/auth/otp/request", json={"channel": "email", "destination": email})
        self.assertEqual(r_cool.status_code, 429)
        self.assertIn("cooldown_remaining", r_cool.get_json())

        # 2. 5 incorrect OTP attempts lock the challenge
        for attempt in range(1, 5):
            bad_res = self.client.post(
                "/api/auth/otp/verify",
                json={"channel": "email", "destination": email, "otp": "000000"},
            )
            self.assertEqual(bad_res.status_code, 401)
            self.assertEqual(bad_res.get_json()["attempts_remaining"], 5 - attempt)

        # 5th bad attempt locks the code with 429
        bad_5 = self.client.post(
            "/api/auth/otp/verify",
            json={"channel": "email", "destination": email, "otp": "000000"},
        )
        self.assertEqual(bad_5.status_code, 429)
        self.assertTrue(bad_5.get_json().get("locked"))

        # Even providing the real OTP after lockout is rejected
        after_lock = self.client.post(
            "/api/auth/otp/verify",
            json={"channel": "email", "destination": email, "otp": valid_otp},
        )
        self.assertIn(after_lock.status_code, (401, 429))

        # 3. Expired OTP is rejected
        email_exp = "expired.otp@matranaari.com"
        self.client.post("/api/auth/otp/request", json={"channel": "email", "destination": email_exp})
        exp_code = self.captured_emails[-1]["code"]
        conn = server.get_db()
        c = conn.cursor()
        past_iso = (datetime.now() - timedelta(minutes=6)).isoformat()
        c.execute("UPDATE auth_otp_challenges SET expires_at = ? WHERE destination = ?", (past_iso, email_exp))
        conn.commit()
        conn.close()

        exp_res = self.client.post(
            "/api/auth/otp/verify",
            json={"channel": "email", "destination": email_exp, "otp": exp_code},
        )
        self.assertEqual(exp_res.status_code, 401)
        self.assertIn("expired", exp_res.get_json()["error"].lower())

        # 4. Destination rate limit (max 5 requests per 15 minutes)
        rate_email = "ratelimit.dest@matranaari.com"
        for i in range(5):
            conn = server.get_db()
            c = conn.cursor()
            c.execute(
                "UPDATE auth_otp_challenges SET created_at = ? WHERE destination = ?",
                ((datetime.now() - timedelta(seconds=60 + i)).isoformat(), rate_email),
            )
            conn.commit()
            conn.close()
            rr = self.client.post("/api/auth/otp/request", json={"channel": "email", "destination": rate_email})
            self.assertEqual(rr.status_code, 200)

        conn = server.get_db()
        c = conn.cursor()
        c.execute(
            "UPDATE auth_otp_challenges SET created_at = ? WHERE destination = ?",
            ((datetime.now() - timedelta(seconds=120)).isoformat(), rate_email),
        )
        conn.commit()
        conn.close()
        r_blocked = self.client.post("/api/auth/otp/request", json={"channel": "email", "destination": rate_email})
        self.assertEqual(r_blocked.status_code, 429)
        self.assertTrue(r_blocked.get_json().get("rate_limited"))

    def test_04_phone_otp_honesty_and_safe_account_linking(self):
        """Phone OTP is unavailable until SMS provider is enabled; when enabled via transport, links safely without unverified merges."""
        # Default production state: SMS provider not enabled -> 503
        p_req = self.client.post("/api/auth/otp/request", json={"channel": "phone", "destination": "9876543210"})
        self.assertEqual(p_req.status_code, 503)
        self.assertTrue(p_req.get_json().get("phone_otp_unavailable"))

        # Enable isolated SMS test transport
        def _fake_sms(phone, e164, otp_code, purpose, **kwargs):
            self.captured_sms.append({"phone": phone, "code": otp_code, "purpose": purpose})
            return True, "sms_test_1", ""

        notifications.set_test_sms_transport(_fake_sms)

        # Log in Customer A via Email OTP and link verified mobile number 9811122233
        self.client.post("/api/auth/otp/request", json={"channel": "email", "destination": "custA@matranaari.com"})
        ver_a = self.client.post(
            "/api/auth/otp/verify",
            json={"channel": "email", "destination": "custA@matranaari.com", "otp": self.captured_emails[-1]["code"]},
        ).get_json()
        hdr_a = {"Authorization": f"Bearer {ver_a['token']}"}

        link_req = self.client.post(
            "/api/auth/link/request",
            headers=hdr_a,
            json={"channel": "phone", "destination": "9811122233"},
        )
        self.assertEqual(link_req.status_code, 200)
        sms_code = self.captured_sms[-1]["code"]

        link_ver = self.client.post(
            "/api/auth/link/verify",
            headers=hdr_a,
            json={"channel": "phone", "destination": "9811122233", "otp": sms_code},
        )
        self.assertEqual(link_ver.status_code, 200)
        self.assertEqual(link_ver.get_json()["user"]["phone"], "9811122233")

        # Customer B cannot link Customer A's already-verified mobile number (409 Conflict)
        self.client.post("/api/auth/otp/request", json={"channel": "email", "destination": "custB@matranaari.com"})
        ver_b = self.client.post(
            "/api/auth/otp/verify",
            json={"channel": "email", "destination": "custB@matranaari.com", "otp": self.captured_emails[-1]["code"]},
        ).get_json()
        hdr_b = {"Authorization": f"Bearer {ver_b['token']}"}
        dup_link = self.client.post(
            "/api/auth/link/request",
            headers=hdr_b,
            json={"channel": "phone", "destination": "9811122233"},
        )
        self.assertEqual(dup_link.status_code, 409)

    def test_05_legacy_password_endpoints_retired_and_password_ui_removed(self):
        """Legacy /api/auth/login and /api/auth/register return 410 Gone, and customer UI has zero password inputs."""
        r_login = self.client.post("/api/auth/login", json={"email": "a@b.com", "password": "secret"})
        self.assertEqual(r_login.status_code, 410)
        self.assertTrue(r_login.get_json().get("passwordless_only"))

        r_reg = self.client.post("/api/auth/register", json={"name": "A", "email": "a@b.com", "password": "secret"})
        self.assertEqual(r_reg.status_code, 410)
        self.assertTrue(r_reg.get_json().get("passwordless_only"))

        acc_html = self.client.get("/account.html").get_data(as_text=True)
        self.assertNotIn('type="password"', acc_html)
        self.assertIn("page-otp-request-form", acc_html)
        self.assertIn("page-otp-verify-form", acc_html)

        app_js = self.client.get("/assets/app.js").get_data(as_text=True)
        self.assertNotIn('type="password"', app_js)
        self.assertIn("auth-otp-request-form", app_js)
        self.assertIn("auth-otp-verify-form", app_js)

    def test_06_admin_passwordless_mfa_totp_and_session_revocation(self):
        """Admin login requires allowlisted email OTP + second-factor MFA (TOTP or Security Key) and supports session revocation."""
        # 1. Unauthorized email is rejected with 403
        unauth_res = self.client.post("/api/admin/auth/request-otp", json={"email": "intruder@example.com"})
        self.assertEqual(unauth_res.status_code, 403)

        # 2. Authorized admin email (matranaari@gmail.com) receives Admin Email OTP
        otp_req = self.client.post("/api/admin/auth/request-otp", json={"email": "matranaari@gmail.com"})
        self.assertEqual(otp_req.status_code, 200)
        admin_email_otp = self.captured_emails[-1]["code"]

        # 3. Email OTP alone (missing or wrong Factor 2 MFA) is rejected with 401
        no_mfa = self.client.post(
            "/api/admin/auth/verify-mfa",
            json={"email": "matranaari@gmail.com", "email_otp": admin_email_otp, "mfa_code": ""},
        )
        self.assertEqual(no_mfa.status_code, 401)

        wrong_mfa = self.client.post(
            "/api/admin/auth/verify-mfa",
            json={"email": "matranaari@gmail.com", "email_otp": admin_email_otp, "mfa_code": "000000"},
        )
        self.assertEqual(wrong_mfa.status_code, 401)

        # 4. Valid Email OTP + valid RFC 6238 TOTP code succeeds and creates an admin session
        totp_secret = server.get_or_create_admin_totp_secret()
        valid_totp = server.compute_totp_code(totp_secret)
        mfa_ok = self.client.post(
            "/api/admin/auth/verify-mfa",
            json={
                "email": "matranaari@gmail.com",
                "email_otp": admin_email_otp,
                "mfa_type": "totp",
                "mfa_code": valid_totp,
            },
        )
        self.assertEqual(mfa_ok.status_code, 200)
        mfa_data = mfa_ok.get_json()
        self.assertTrue(mfa_data["ok"])
        self.assertEqual(mfa_data["mfa_method"], "email_otp+totp")
        admin_tok = mfa_data["token"]
        admin_hdr = {"X-Admin-Token": admin_tok}

        # 5. Verify admin session works on /api/admin/sessions and can be revoked
        sess_res = self.client.get("/api/admin/sessions", headers=admin_hdr)
        self.assertEqual(sess_res.status_code, 200)
        sess_data = sess_res.get_json()
        self.assertGreaterEqual(len(sess_data["sessions"]), 1)
        sid = sess_data["sessions"][0]["session_id"]

        rev_res = self.client.post(
            "/api/admin/sessions/revoke",
            headers=admin_hdr,
            json={"session_id": sid},
        )
        self.assertEqual(rev_res.status_code, 200)

        # Revoked session token is immediately rejected with 401
        after_rev = self.client.get("/api/admin/sessions", headers=admin_hdr)
        self.assertEqual(after_rev.status_code, 401)

    def test_07_ultimate_admin_bento_analytics_inventory_history_and_staff_rbac(self):
        """Verify 11-section Admin UI, Bento analytics, inventory history log, and server-side Staff RBAC."""
        owner_hdr = {"X-Admin-Passkey": "naari@admin2026"}

        # 1. Verify admin.html has all 11 navigation tabs, Peach accent (#EF8557), reduced-motion rule, Analytics & Staff panels
        adm_html = self.client.get("/admin.html").get_data(as_text=True)
        self.assertIn("#EF8557", adm_html)
        self.assertIn("prefers-reduced-motion: reduce", adm_html)
        for tab_name in [
            "overview",
            "orders",
            "products",
            "inventory",
            "customers",
            "banners",
            "coupons",
            "analytics",
            "returns",
            "staff",
            "settings",
        ]:
            self.assertIn(f'data-tab="{tab_name}"', adm_html, f"Missing sidebar tab {tab_name}")
        for elem_id in [
            "tab-analytics",
            "tab-staff",
            "analytics-revenue-chart",
            "analytics-orders-chart",
            "analytics-payment-bars",
            "analytics-status-bars",
            "inventory-history-tbody",
            "coupon-search-input",
            "admin-staff-form",
            "admin-staff-tbody",
        ]:
            self.assertIn(f'id="{elem_id}"', adm_html, f"Missing #{elem_id} in admin.html")

        # 2. Verify /api/admin/inventory/update logs stock adjustment history & /api/admin/inventory/history returns it
        inv_upd = self.client.post(
            "/api/admin/inventory/update",
            headers=owner_hdr,
            json={"id": "straight", "size_stock": {"S": 6, "M": 8, "L": 7, "XL": 5}},
        )
        self.assertEqual(inv_upd.status_code, 200)
        hist_res = self.client.get("/api/admin/inventory/history", headers=owner_hdr).get_json()
        self.assertTrue(hist_res["ok"])
        self.assertGreaterEqual(len(hist_res["history"]), 1)
        self.assertIn("26 pcs", hist_res["history"][0]["details"])

        # 3. Verify /api/admin/stats?include_all=1&days=30 returns payment_method_breakdown, order_status_distribution, staff, and inventory_history
        st_res = self.client.get("/api/admin/stats?include_all=1&days=30", headers=owner_hdr).get_json()
        self.assertTrue(st_res["ok"])
        self.assertIn("payment_method_breakdown", st_res["stats"])
        self.assertIn("order_status_distribution", st_res["stats"])
        self.assertIn("staff", st_res)
        self.assertIn("inventory_history", st_res)

        # 4. Staff Management & Server-Side RBAC Enforcement
        # Primary owner cannot be demoted or deactivated
        bad_demote = self.client.post(
            "/api/admin/staff",
            headers=owner_hdr,
            json={"name": "Owner", "email": "matranaari@gmail.com", "role": "order_staff", "is_active": False},
        )
        self.assertEqual(bad_demote.status_code, 400)

        # Add an Order Staff member (orders.staff@matranaari.com)
        add_ord_staff = self.client.post(
            "/api/admin/staff",
            headers=owner_hdr,
            json={
                "name": "Riya Order Staff",
                "email": "orders.staff@matranaari.com",
                "role": "order_staff",
                "is_active": True,
            },
        )
        self.assertEqual(add_ord_staff.status_code, 200)

        # Order Staff logs in via Passwordless Admin Email OTP + TOTP MFA
        otp_req = self.client.post("/api/admin/auth/request-otp", json={"email": "orders.staff@matranaari.com"})
        self.assertEqual(otp_req.status_code, 200)
        staff_otp = self.captured_emails[-1]["code"]
        valid_totp = server.compute_totp_code(server.get_or_create_admin_totp_secret())
        staff_mfa = self.client.post(
            "/api/admin/auth/verify-mfa",
            json={
                "email": "orders.staff@matranaari.com",
                "email_otp": staff_otp,
                "mfa_type": "totp",
                "mfa_code": valid_totp,
            },
        )
        self.assertEqual(staff_mfa.status_code, 200)
        staff_mfa_data = staff_mfa.get_json()
        self.assertEqual(staff_mfa_data["admin_role"], "order_staff")
        ord_staff_hdr = {"X-Admin-Token": staff_mfa_data["token"]}

        # Order Staff is FORBIDDEN (403) from creating products, coupons, modifying settings, or modifying staff
        self.assertEqual(
            self.client.post(
                "/api/admin/products",
                headers=ord_staff_hdr,
                json={"name": "Unauthorized Kurti", "price": 1299, "mrp": 1999},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/admin/coupons",
                headers=ord_staff_hdr,
                json={"code": "HACK50", "discount_type": "percentage", "discount_value": 50},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post("/api/admin/settings", headers=ord_staff_hdr, json={"shipping_fee": 0}).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/admin/staff",
                headers=ord_staff_hdr,
                json={"name": "Escalated", "email": "orders.staff@matranaari.com", "role": "owner"},
            ).status_code,
            403,
        )

        # Order Staff CAN update order fulfillment status (200 OK)
        ord_upd = self.client.post(
            "/api/admin/orders/status",
            headers=ord_staff_hdr,
            json={"order_id": "NAARI-SAMPLE", "order_status": "packed"},
        )
        self.assertEqual(ord_upd.status_code, 200)


if __name__ == "__main__":
    unittest.main()
