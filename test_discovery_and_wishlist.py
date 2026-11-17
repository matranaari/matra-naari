import json
import os
import tempfile
import unittest

import server


class DiscoveryAndWishlistTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.prev_db_path = server.DB_PATH
        server.DB_PATH = os.path.join(self.tmp_dir.name, "test_wishlist.db")
        server.init_db()
        server.invalidate_site_settings_cache()
        self.client = server.app.test_client()

    def tearDown(self):
        server.DB_PATH = self.prev_db_path
        server.invalidate_site_settings_cache()
        self.tmp_dir.cleanup()

    def _register_user(self, email, name="Ananya Sharma", phone="9876543210"):
        res = self.client.post(
            "/api/auth/register",
            json={
                "name": name,
                "email": email,
                "phone": phone,
                "password": "Password123!",
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["ok"])
        return data["token"], data["user"]

    def _get_admin_headers(self):
        os.environ["ADMIN_PASSKEY"] = "naari@admin2026"
        return {"X-Admin-Passkey": "naari@admin2026"}

    def test_01_unauthenticated_wishlist_requires_auth(self):
        res = self.client.get("/api/customer/wishlist")
        self.assertEqual(res.status_code, 401)
        res_post = self.client.post("/api/customer/wishlist", json={"action": "add", "product_id": "straight"})
        self.assertEqual(res_post.status_code, 401)

    def test_02_authenticated_wishlist_add_remove_toggle_and_deduplication(self):
        token, _ = self._register_user("wishlist1@example.com")
        headers = {"Authorization": f"Bearer {token}"}

        r0 = self.client.get("/api/customer/wishlist", headers=headers).get_json()
        self.assertTrue(r0["ok"])
        self.assertEqual(r0["product_ids"], [])

        r1 = self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={"action": "add", "product_id": "straight"},
        ).get_json()
        self.assertTrue(r1["ok"])
        self.assertEqual(r1["product_ids"], ["straight"])

        r2 = self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={"action": "add", "product_id": "straight"},
        ).get_json()
        self.assertEqual(r2["product_ids"], ["straight"])

        r3 = self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={"action": "toggle", "product_id": "anarkali"},
        ).get_json()
        self.assertTrue(r3["saved"])
        self.assertEqual(r3["product_ids"], ["straight", "anarkali"])

        r4 = self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={"action": "toggle", "product_id": "anarkali"},
        ).get_json()
        self.assertFalse(r4["saved"])
        self.assertEqual(r4["product_ids"], ["straight"])

        r5 = self.client.delete("/api/customer/wishlist/straight", headers=headers).get_json()
        self.assertTrue(r5["ok"])
        self.assertEqual(r5["product_ids"], [])

    def test_03_guest_wishlist_merge_on_login_and_unavailable_product_handling(self):
        token, _ = self._register_user("merge@example.com")
        headers = {"Authorization": f"Bearer {token}"}

        self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={"action": "add", "product_id": "straight"},
        )

        sync_res = self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={
                "action": "sync",
                "product_ids": ["straight", "anarkali", "coord", "nonexistent_kurti_999"],
            },
        ).get_json()
        self.assertTrue(sync_res["ok"])
        self.assertEqual(sync_res["product_ids"], ["straight", "anarkali", "coord"])
        self.assertIn("nonexistent_kurti_999", sync_res["unavailable_ids"])
        self.assertEqual(len(sync_res["items"]), 3)

    def test_04_user_isolation_and_no_leak_into_store_settings(self):
        token_a, _ = self._register_user("usera@example.com")
        token_b, _ = self._register_user("userb@example.com")

        self.client.post(
            "/api/customer/wishlist",
            headers={"Authorization": f"Bearer {token_a}"},
            json={"action": "sync", "product_ids": ["straight", "kaftan"]},
        )
        self.client.post(
            "/api/customer/wishlist",
            headers={"Authorization": f"Bearer {token_b}"},
            json={"action": "sync", "product_ids": ["anarkali"]},
        )

        res_a = self.client.get("/api/customer/wishlist", headers={"Authorization": f"Bearer {token_a}"}).get_json()
        res_b = self.client.get("/api/customer/wishlist", headers={"Authorization": f"Bearer {token_b}"}).get_json()
        self.assertEqual(res_a["product_ids"], ["straight", "kaftan"])
        self.assertEqual(res_b["product_ids"], ["anarkali"])

        cfg_res = self.client.get("/api/config").get_json()
        for k in cfg_res.keys():
            self.assertFalse(str(k).startswith("user_wishlist:"))

    def test_05_manrope_inter_typography_and_promo_delivery_card_frontend(self):
        home_resp = self.client.get("/")
        home_html = home_resp.get_data(as_text=True)
        home_resp.close()

        self.assertIn("family=Manrope", home_html)
        self.assertIn("family=Inter", home_html)
        self.assertNotIn("Cormorant", home_html)
        self.assertNotIn("Baskerville", home_html)
        self.assertIn("Shop by Style", home_html)
        self.assertIn(">Bestsellers<", home_html)
        self.assertIn('class="mn-promo-delivery-card"', home_html)
        self.assertIn('id="mn-promo-copy-btn"', home_html)
        self.assertIn('id="home-hero-carousel"', home_html)
        self.assertIn("initHeroCarousel(3500)", home_html)

        css_resp = self.client.get("/assets/styles.css")
        css_txt = css_resp.get_data(as_text=True)
        css_resp.close()
        self.assertIn('"Manrope", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', css_txt)
        self.assertNotIn("Cormorant", css_txt)
        self.assertNotIn("Baskerville", css_txt)
        self.assertIn("#EF8557", css_txt)
        self.assertIn(".mn-promo-delivery-card", css_txt)

        js_resp = self.client.get("/assets/app.js")
        js_txt = js_resp.get_data(as_text=True)
        js_resp.close()
        self.assertIn("copyCouponCodeToClipboard", js_txt)

    def test_06_admin_banner_management_crud_reorder_and_editorial_campaigns(self):
        # Unauthenticated admin banner access must be rejected with 401
        unauth = self.client.get("/api/admin/banners")
        self.assertEqual(unauth.status_code, 401)

        # Public /api/banners returns default 3.5s duration (3500ms) and 3 enabled banners
        pub0 = self.client.get("/api/banners").get_json()
        self.assertTrue(pub0["ok"])
        self.assertEqual(pub0["hero_slide_duration_ms"], 3500)
        self.assertEqual(len(pub0["hero_banners"]), 3)
        self.assertEqual(len(pub0["editorial_campaigns"]), 2)

        admin_headers = self._get_admin_headers()

        # Upsert a new campaign banner (image-only / optional text supported)
        up_res = self.client.post(
            "/api/admin/banners",
            headers=admin_headers,
            json={
                "action": "upsert_banner",
                "hero_slide_duration_ms": 4000,
                "banner": {
                    "id": "bnr_festive_campaign",
                    "desktop_image": "assets/k-angrakha.jpg",
                    "mobile_image": "assets/k-short.jpg",
                    "eyebrow": "LIMITED ATELIER EDIT",
                    "headline": "Hand-Tied Angrakha Silhouettes",
                    "subtitle": "Crafted for festive evenings.",
                    "cta_text": "Explore Angrakhas",
                    "cta_link": "shop.html?category=Angrakha",
                    "text_align": "right",
                    "text_position": "bottom-right",
                    "overlay_theme": "dark",
                    "enabled": True,
                },
            },
        ).get_json()
        self.assertTrue(up_res["ok"])
        self.assertEqual(up_res["hero_slide_duration_ms"], 4000)
        self.assertEqual(len(up_res["hero_banners"]), 4)

        # Reorder banners so bnr_festive_campaign is first
        re_res = self.client.post(
            "/api/admin/banners",
            headers=admin_headers,
            json={
                "action": "reorder",
                "banner_ids": ["bnr_festive_campaign", "bnr_1", "bnr_2", "bnr_3"],
            },
        ).get_json()
        self.assertTrue(re_res["ok"])
        self.assertEqual(re_res["hero_banners"][0]["id"], "bnr_festive_campaign")

        # Disable bnr_2 and verify public /api/banners excludes disabled banners
        banners_copy = re_res["hero_banners"]
        for b in banners_copy:
            if b["id"] == "bnr_2":
                b["enabled"] = False
        self.client.post(
            "/api/admin/banners",
            headers=admin_headers,
            json={"action": "save_all", "hero_slide_duration_ms": 3500, "hero_banners": banners_copy},
        )
        pub1 = self.client.get("/api/banners").get_json()
        self.assertEqual(pub1["hero_slide_duration_ms"], 3500)
        pub_ids = [b["id"] for b in pub1["hero_banners"]]
        self.assertNotIn("bnr_2", pub_ids)
        self.assertEqual(pub_ids[0], "bnr_festive_campaign")

        # Delete bnr_festive_campaign
        del_res = self.client.delete("/api/admin/banners/bnr_festive_campaign", headers=admin_headers).get_json()
        self.assertTrue(del_res["ok"])

        # Editorial campaign section with empty image is omitted from public /api/banners so homepage hides it gracefully
        self.client.post(
            "/api/admin/banners",
            headers=admin_headers,
            json={
                "action": "save_all",
                "editorial_campaigns": [
                    {
                        "id": "camp_1",
                        "layout": "split",
                        "headline": "Visible Campaign",
                        "desktop_image": "assets/k-angrakha.jpg",
                        "enabled": True,
                    },
                    {
                        "id": "camp_2",
                        "layout": "full",
                        "headline": "Hidden Campaign Without Image",
                        "desktop_image": "",
                        "enabled": True,
                    },
                ],
            },
        )
        pub2 = self.client.get("/api/banners").get_json()
        self.assertEqual(len(pub2["editorial_campaigns"]), 1)
        self.assertEqual(pub2["editorial_campaigns"][0]["id"], "camp_1")

    def test_07_product_search_category_filter_and_pricing_regression(self):
        s_res = self.client.get("/api/products?search=anarkali").get_json()
        self.assertTrue(s_res["ok"])
        self.assertGreaterEqual(len(s_res["products"]), 1)
        self.assertEqual(s_res["products"][0]["id"], "anarkali")

        c_res = self.client.get("/api/products?category=Straight%20Cut").get_json()
        self.assertTrue(c_res["ok"])
        self.assertTrue(all(p["category"] == "Straight Cut" for p in c_res["products"]))

        p_res = self.client.get("/api/products/straight").get_json()
        self.assertTrue(p_res["ok"])
        self.assertEqual(p_res["product"]["price"], 1299)
        self.assertGreater(p_res["product"]["stock"], 0)

    def test_08_checkout_mobile_responsive_and_controls_regression(self):
        """Regression test for mobile checkout horizontal overflow prevention (320px+) and checkout controls."""
        for route in ["/checkout.html", "/checkout/"]:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 200)
            html = resp.get_data(as_text=True)

            # 1. Responsive grid and min-w-0 / minmax(0, 1fr) rules present; no undefined sm:w-auto collapsing flex rows
            self.assertIn("lg:grid-cols-[1fr_400px]", html)
            self.assertIn("minmax(0, 1fr)", html)
            self.assertIn("min-w-0", html)
            self.assertIn("resizeActiveDeliveryMap", html)
            self.assertIn("bindMapResizeObserver", html)
            self.assertNotIn("sm:w-auto", html)

            # 2. All essential checkout controls present and intact
            for control_id in [
                "checkout-main-grid",
                "address-search-input",
                "address-autocomplete-dropdown",
                "use-current-location-btn",
                "delivery-map",
                "map-selected-address-text",
                "map-coords-badge",
                "checkout-form",
                "cust-name",
                "cust-phone",
                "cust-email",
                "cust-house-no",
                "cust-street-area",
                "cust-address1",
                "cust-address2",
                "cust-pincode",
                "cust-city",
                "cust-state",
                "address-confirmation-card",
                "confirm-address-btn",
                "payment-method-cod",
                "payment-method-razorpay",
                "place-order-btn",
                "summary-items-list",
                "checkout-coupon-input",
                "checkout-apply-coupon-btn",
            ]:
                self.assertIn(f'id="{control_id}"', html, f"Missing control #{control_id} in {route}")

        # 3. Verify CSS rules in assets/styles.css enforce responsive checkout sizing without 1-char-per-line overflow-wrap: anywhere on p/label
        css_resp = self.client.get("/assets/styles.css")
        self.assertEqual(css_resp.status_code, 200)
        css_text = css_resp.get_data(as_text=True)
        self.assertIn("#checkout-main-grid", css_text)
        self.assertIn("grid-template-columns: minmax(0, 1fr);", css_text)
        self.assertIn("#delivery-map .gm-style", css_text)
        self.assertIn("#delivery-map img", css_text)
        self.assertIn("overflow-wrap: break-word", css_text)
        self.assertNotIn("#checkout-main-grid p", css_text)
        self.assertNotIn("#checkout-main-grid label", css_text)

        # 4. Verify address validation, saved addresses, and coupon APIs work for authenticated checkout customer
        token, _ = self._register_user("checkout_resp@matranaari.com")
        headers = {"Authorization": f"Bearer {token}"}
        val_res = self.client.post(
            "/api/address/validate",
            headers=headers,
            json={
                "address": {
                    "name": "Ananya Sharma",
                    "phone": "9876543210",
                    "email": "checkout_resp@matranaari.com",
                    "house_no": "Flat 402, Tower B",
                    "street_area": "Lotus Apartments, MI Road",
                    "address_line1": "Flat 402, Tower B, Lotus Apartments, MI Road",
                    "address_line2": "Near Ajmeri Gate",
                    "city": "Jaipur",
                    "state": "Rajasthan",
                    "pincode": "302001",
                    "latitude": 26.9124,
                    "longitude": 75.7873,
                    "address_label": "Home",
                },
                "require_split_fields": True,
                "save_to_account": True,
                "is_default": True,
            },
        ).get_json()
        self.assertTrue(val_res["ok"])
        self.assertGreaterEqual(len(val_res.get("addresses", [])), 1)

        cp_res = self.client.post(
            "/api/apply-coupon",
            json={"code": "NAARI10", "subtotal": 2499, "items": [{"id": "anarkali", "qty": 1, "price": 2499}]},
        ).get_json()
        self.assertTrue(cp_res["ok"])
        self.assertGreater(cp_res["discount_amount"], 0)

    def test_09_hero_banner_cropping_and_admin_focal_point_control(self):
        """Verify hero banner cropping fix, atmospheric backdrop, and admin focal-point & fit-mode persistence."""
        pub = self.client.get("/api/banners").get_json()
        self.assertTrue(pub["ok"])
        self.assertGreaterEqual(len(pub["hero_banners"]), 3)
        first_bnr = pub["hero_banners"][0]
        self.assertEqual(first_bnr["image_fit"], "editorial")
        self.assertEqual(first_bnr["focal_x"], 50)
        self.assertEqual(first_bnr["focal_y"], 6)
        self.assertEqual(first_bnr["mobile_focal_x"], 50)
        self.assertEqual(first_bnr["mobile_focal_y"], 6)
        self.assertEqual(first_bnr["object_position_desktop"], "50% 6%")
        self.assertEqual(first_bnr["object_position_mobile"], "50% 6%")

        # Upsert banner with custom focal points & fit mode via Admin API
        admin_headers = self._get_admin_headers()
        up_res = self.client.post(
            "/api/admin/banners",
            headers=admin_headers,
            json={
                "action": "upsert_banner",
                "hero_slide_duration_ms": 3500,
                "banner": {
                    "id": "bnr_1",
                    "desktop_image": "assets/hero.jpg",
                    "mobile_image": "assets/k-short.jpg",
                    "eyebrow": "MATRA NAARI · SIGNATURE CAMPAIGN",
                    "headline": "Modern Kurtis, Rooted in Craft",
                    "subtitle": "Sizes XS to XXL · Ready to Ship",
                    "cta_text": "Explore Collection",
                    "cta_link": "shop.html",
                    "image_fit": "editorial",
                    "focal_x": 46,
                    "focal_y": 8,
                    "mobile_focal_x": 52,
                    "mobile_focal_y": 10,
                    "enabled": True,
                },
            },
        ).get_json()
        self.assertTrue(up_res["ok"])
        b1 = next(b for b in up_res["hero_banners"] if b["id"] == "bnr_1")
        self.assertEqual(b1["image_fit"], "editorial")
        self.assertEqual(b1["focal_x"], 46)
        self.assertEqual(b1["focal_y"], 8)
        self.assertEqual(b1["mobile_focal_x"], 52)
        self.assertEqual(b1["mobile_focal_y"], 10)
        self.assertEqual(b1["mobile_image"], "assets/k-short.jpg")
        self.assertEqual(b1["object_position_desktop"], "46% 8%")
        self.assertEqual(b1["object_position_mobile"], "52% 10%")

        # Verify out-of-range focal values are safely clamped to [0, 100]
        clamp_res = self.client.post(
            "/api/admin/banners",
            headers=admin_headers,
            json={
                "action": "upsert_banner",
                "banner": {
                    "id": "bnr_2",
                    "desktop_image": "assets/k-anarkali.jpg",
                    "image_fit": "cover",
                    "focal_x": -20,
                    "focal_y": 140,
                    "enabled": True,
                },
            },
        ).get_json()
        self.assertTrue(clamp_res["ok"])
        b2 = next(b for b in clamp_res["hero_banners"] if b["id"] == "bnr_2")
        self.assertEqual(b2["image_fit"], "cover")
        self.assertEqual(b2["focal_x"], 0)
        self.assertEqual(b2["focal_y"], 100)

        # Verify index.html, admin.html, and assets/styles.css contain the hero crop & focal controls
        idx_html = self.client.get("/").get_data(as_text=True)
        self.assertIn("mn-cinematic-backdrop", idx_html)
        self.assertIn("mn-fit-editorial", idx_html)
        self.assertIn("--desk-focal-x", idx_html)

        adm_html = self.client.get("/admin.html").get_data(as_text=True)
        for admin_id in [
            "bnr-image-fit",
            "bnr-focal-x",
            "bnr-focal-y",
            "bnr-mobile-focal-x",
            "bnr-mobile-focal-y",
            "bnr-preview-focal-pin",
            "bnr-preview-backdrop",
        ]:
            self.assertIn(f'id="{admin_id}"', adm_html, f"Missing #{admin_id} in admin.html")

        css_text = self.client.get("/assets/styles.css").get_data(as_text=True)
        self.assertIn(".mn-cinematic-backdrop", css_text)
        self.assertIn("aspect-ratio: 0.85;", css_text)

    def test_10_admin_panel_redesign_metrics_and_mobile_ui(self):
        """Verify redesigned Admin Panel design system, mobile nav, quick actions, real DB analytics, and customer address privacy."""
        admin_headers = self._get_admin_headers()

        # 1. Register a customer, add a saved address, and place a COD order so today_sales and revenue_trend are populated
        tok, user = self._register_user("admin.redesign@matranaari.com")
        addr_res = self.client.post(
            "/api/customer/addresses",
            headers={"Authorization": f"Bearer {tok}"},
            json={
                "label": "Home",
                "recipient_name": "Ananya Verma",
                "phone": "9876543210",
                "address_line1": "Flat 402, Heritage Residency",
                "city": "Pune",
                "state": "Maharashtra",
                "pincode": "411001",
                "is_default": True,
            },
        ).get_json()
        self.assertTrue(addr_res["ok"])

        ord_res = self.client.post(
            "/api/create-cod-order",
            headers={"Authorization": f"Bearer {tok}"},
            json={
                "customer": {
                    "name": "Ananya Verma",
                    "email": "admin.redesign@matranaari.com",
                    "phone": "9876543210",
                    "house_no": "Flat 402",
                    "street_area": "Heritage Residency",
                    "address_line1": "Flat 402, Heritage Residency",
                    "city": "Pune",
                    "state": "Maharashtra",
                    "pincode": "411001",
                    "whatsapp_opt_in": False,
                },
                "items": [{"id": "anarkali", "size": "M", "qty": 1}],
            },
        ).get_json()
        self.assertTrue(ord_res["ok"])

        # 2. Verify /api/admin/stats returns today_sales, today_orders, and revenue_trend
        stats_res = self.client.get("/api/admin/stats?include_all=1", headers=admin_headers).get_json()
        self.assertTrue(stats_res["ok"])
        st = stats_res["stats"]
        self.assertIn("today_sales", st)
        self.assertIn("today_orders", st)
        self.assertIn("revenue_trend", st)
        self.assertGreaterEqual(st["today_orders"], 1)
        self.assertGreater(st["today_sales"], 0)
        self.assertIsInstance(st["revenue_trend"], list)
        self.assertGreaterEqual(len(st["revenue_trend"]), 1)
        self.assertIn("date", st["revenue_trend"][0])
        self.assertIn("revenue", st["revenue_trend"][0])
        self.assertIn("orders", st["revenue_trend"][0])

        # 3. Verify /api/admin/customers attaches saved_addresses and default_address without exposing passwords/tokens
        cust_res = self.client.get("/api/admin/customers", headers=admin_headers).get_json()
        self.assertTrue(cust_res["ok"])
        cust_raw = str(cust_res)
        self.assertNotIn("password_hash", cust_raw)
        self.assertNotIn("password_salt", cust_raw)
        target_cust = next(c for c in cust_res["customers"] if c["email"] == "admin.redesign@matranaari.com")
        self.assertIn("saved_addresses", target_cust)
        self.assertGreaterEqual(len(target_cust["saved_addresses"]), 1)
        self.assertIn("Pune", target_cust["default_address"])

        # 4. Verify admin.html Quiet Luxury design system, typography, mobile bottom nav, and step-by-step product modal
        adm_html = self.client.get("/admin.html").get_data(as_text=True)
        self.assertIn("family=Manrope", adm_html)
        self.assertIn("family=Inter", adm_html)
        self.assertNotIn("Cormorant+Garamond", adm_html)
        self.assertNotIn("family=Kalam", adm_html)
        for token in ["#542C34", "#F7F4EE", "#292725", "#706963"]:
            self.assertIn(token, adm_html)
        for elem_id in [
            "admin-mobile-bottom-nav",
            "admin-mobile-more-sheet",
            "dashboard-quick-actions",
            "qa-add-product-btn",
            "qa-view-orders-btn",
            "qa-manage-banners-btn",
            "qa-create-coupon-btn",
            "stat-today-sales",
            "stat-today-orders",
            "dashboard-revenue-trend-chart",
            "dashboard-fulfillment-breakdown",
            "customer-detail-modal",
            "coupon-live-promo-preview",
            "p-preview-storefront-link",
            "p-discount-preview-badge",
        ]:
            self.assertIn(f'id="{elem_id}"', adm_html, f"Missing #{elem_id} in admin.html")


if __name__ == "__main__":
    unittest.main()
