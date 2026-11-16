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


if __name__ == "__main__":
    unittest.main()
