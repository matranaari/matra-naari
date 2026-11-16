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
        self.client = server.app.test_client()

    def tearDown(self):
        server.DB_PATH = self.prev_db_path
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

    def test_01_unauthenticated_wishlist_requires_auth(self):
        res = self.client.get("/api/customer/wishlist")
        self.assertEqual(res.status_code, 401)
        res_post = self.client.post("/api/customer/wishlist", json={"action": "add", "product_id": "straight"})
        self.assertEqual(res_post.status_code, 401)

    def test_02_authenticated_wishlist_add_remove_toggle_and_deduplication(self):
        token, user = self._register_user("wishlist1@example.com")
        headers = {"Authorization": f"Bearer {token}"}

        # Initially empty
        r0 = self.client.get("/api/customer/wishlist", headers=headers).get_json()
        self.assertTrue(r0["ok"])
        self.assertEqual(r0["product_ids"], [])
        self.assertEqual(r0["items"], [])

        # Add 'straight'
        r1 = self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={"action": "add", "product_id": "straight"},
        ).get_json()
        self.assertTrue(r1["ok"])
        self.assertEqual(r1["product_ids"], ["straight"])
        self.assertEqual(len(r1["items"]), 1)
        self.assertEqual(r1["items"][0]["id"], "straight")

        # Duplicate add of 'straight' does not create duplicate entry
        r2 = self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={"action": "add", "product_id": "straight"},
        ).get_json()
        self.assertEqual(r2["product_ids"], ["straight"])

        # Toggle 'anarkali' -> adds it
        r3 = self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={"action": "toggle", "product_id": "anarkali"},
        ).get_json()
        self.assertTrue(r3["saved"])
        self.assertEqual(r3["product_ids"], ["straight", "anarkali"])

        # Toggle 'anarkali' again -> removes it
        r4 = self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={"action": "toggle", "product_id": "anarkali"},
        ).get_json()
        self.assertFalse(r4["saved"])
        self.assertEqual(r4["product_ids"], ["straight"])

        # DELETE item endpoint
        r5 = self.client.delete("/api/customer/wishlist/straight", headers=headers).get_json()
        self.assertTrue(r5["ok"])
        self.assertEqual(r5["product_ids"], [])

    def test_03_guest_wishlist_merge_on_login_and_unavailable_product_handling(self):
        token, _ = self._register_user("merge@example.com")
        headers = {"Authorization": f"Bearer {token}"}

        # Pre-existing account item: 'straight'
        self.client.post(
            "/api/customer/wishlist",
            headers=headers,
            json={"action": "add", "product_id": "straight"},
        )

        # Guest localStorage has ['straight', 'anarkali', 'coord', 'nonexistent_kurti_999']
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

        # Ensure /api/config never leaks user_wishlist:* keys
        cfg_res = self.client.get("/api/config").get_json()
        for k in cfg_res.keys():
            self.assertFalse(str(k).startswith("user_wishlist:"))

    def test_05_frontend_discovery_pages_and_floating_bottom_nav(self):
        # Verify Homepage has Hero Carousel, Categories, Curated Trends, and Offer Ribbon
        home_html = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="home-hero-carousel"', home_html)
        self.assertIn('data-hero-slide="0"', home_html)
        self.assertIn('data-hero-slide="1"', home_html)
        self.assertIn('data-hero-slide="2"', home_html)
        self.assertIn('id="home-categories"', home_html)
        self.assertIn('id="home-trends"', home_html)
        self.assertIn('id="mn-offer-ribbon"', home_html)

        # Verify Shop Page has Discovery Mode Switcher (All, Categories, Trends, Wishlist) & Visual Categories
        shop_html = self.client.get("/shop.html").get_data(as_text=True)
        self.assertIn('id="shop-discovery-mode-bar"', shop_html)
        self.assertIn('data-shop-mode="categories"', shop_html)
        self.assertIn('data-shop-mode="trends"', shop_html)
        self.assertIn('data-shop-mode="wishlist"', shop_html)
        self.assertIn('id="shop-visual-cat-strip"', shop_html)
        self.assertIn('id="shop-trends-bar"', shop_html)

        # Verify app.js has Floating Mobile Bottom Navigation with all 5 tabs & Server Wishlist Sync
        app_js = self.client.get("/assets/app.js").get_data(as_text=True)
        self.assertIn("injectFloatingMobileBottomNav", app_js)
        self.assertIn('data-bnav-tab="home"', app_js)
        self.assertIn('data-bnav-tab="categories"', app_js)
        self.assertIn('data-bnav-tab="trends"', app_js)
        self.assertIn('data-bnav-tab="wishlist"', app_js)
        self.assertIn('data-bnav-tab="account"', app_js)
        self.assertIn("syncWishlistWithServer", app_js)

    def test_06_product_search_category_filter_and_pricing_regression(self):
        # Search API
        s_res = self.client.get("/api/products?search=anarkali").get_json()
        self.assertTrue(s_res["ok"])
        self.assertGreaterEqual(len(s_res["products"]), 1)
        self.assertEqual(s_res["products"][0]["id"], "anarkali")

        # Category Filter API
        c_res = self.client.get("/api/products?category=Straight%20Cut").get_json()
        self.assertTrue(c_res["ok"])
        self.assertTrue(all(p["category"] == "Straight Cut" for p in c_res["products"]))

        # Product Detail & Pricing Integrity
        p_res = self.client.get("/api/products/straight").get_json()
        self.assertTrue(p_res["ok"])
        self.assertEqual(p_res["product"]["price"], 1299)
        self.assertGreater(p_res["product"]["stock"], 0)


if __name__ == "__main__":
    unittest.main()
