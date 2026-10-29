#!/usr/bin/env python3
"""
Matra Naari - Premium Indian Ethnic Fashion E-Commerce Backend (Flask Edition)
Complete scalable architecture inspired by Libas:
- Authoritative Product Catalog & Inventory
- Multi-tier Offers, Coupons & Promotions Engine
- Resilient Order Management with Razorpay (HMAC-SHA256) & Cash on Delivery (COD)
- Customer Authentication, Profile, Address Book, and Order History
- Returns & Exchanges Lifecycle
- Pin code Serviceability & Delivery Estimator
- Secure Administrative Panel APIs
- Clean Directory and Static File Routing
"""

import os
import sys
import json
import sqlite3
import hmac
import hashlib
import secrets
import base64
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
DB_PATH = os.environ.get("DB_PATH", os.path.join(DATA_DIR, "orders.db"))
CONFIG_PATH = os.environ.get("CONFIG_PATH", os.path.join(BASE_DIR, "config.json"))
PORT = int(os.environ.get("PORT", 8000))
ADMIN_SECRET_KEY = os.environ.get("ADMIN_SECRET_KEY", "naari@admin2026")

# Authoritative Base Product Catalog
DEFAULT_PRODUCTS = [
    {
        "id": "straight",
        "name": "Gulmohar Straight Kurti",
        "category": "Straight Cut",
        "style": "Straight Kurta",
        "price": 1299,
        "mrp": 1999,
        "description": "Everyday ease, hand-block printed on breathable cotton. Designed with a clean straight silhouette, side slits, and round neck with wooden buttons.",
        "fabric": "100% Pure Cambric Cotton",
        "occasion": "Everyday & Workwear",
        "pattern": "Hand-Block Print",
        "sleeve_length": "3/4th Sleeves",
        "neck_design": "Round Neck",
        "care": "Hand wash separately in cold water with mild detergent. Line dry in shade.",
        "image": "assets/hero.jpg",
        "relative_image": "assets/hero.jpg",
        "gallery_json": json.dumps(["assets/hero.jpg", "assets/k-aline.jpg"]),
        "colors_json": json.dumps([
            {"name": "Maroon", "swatch": "#6B2D31"},
            {"name": "Ivory", "swatch": "#F5F2EB"},
            {"name": "Indigo", "swatch": "#2A3D66"}
        ]),
        "sizes_json": json.dumps(["XS", "S", "M", "L", "XL", "XXL"]),
        "sold_out_sizes_json": json.dumps([]),
        "stock": 45,
        "is_featured": 1,
        "is_new": 0,
        "is_bestseller": 1,
        "rating": 4.9,
        "reviews_count": 86
    },
    {
        "id": "aline",
        "name": "Chandni A-Line Kurti",
        "category": "A-Line",
        "style": "Flared A-Line",
        "price": 1499,
        "mrp": 2199,
        "description": "A soft flare silhouette with delicate tone-on-tone thread work and potli buttons. Flowy and graceful for workdays or family brunches.",
        "fabric": "Chanderi Cotton Blend",
        "occasion": "Work & Semi-Festive",
        "pattern": "Thread Work & Zari",
        "sleeve_length": "3/4th Sleeves",
        "neck_design": "Keyhole Neck",
        "care": "Gentle machine wash cold or hand wash. Warm iron on reverse.",
        "image": "assets/k-aline.jpg",
        "relative_image": "assets/k-aline.jpg",
        "gallery_json": json.dumps(["assets/k-aline.jpg", "assets/hero.jpg"]),
        "colors_json": json.dumps([
            {"name": "Ivory", "swatch": "#F5F2EB"},
            {"name": "Blush", "swatch": "#D88B92"}
        ]),
        "sizes_json": json.dumps(["S", "M", "L", "XL"]),
        "sold_out_sizes_json": json.dumps([]),
        "stock": 32,
        "is_featured": 1,
        "is_new": 1,
        "is_bestseller": 0,
        "rating": 4.8,
        "reviews_count": 54
    },
    {
        "id": "anarkali",
        "name": "Genda Anarkali Kurta",
        "category": "Anarkali",
        "style": "16-Kali Anarkali",
        "price": 2499,
        "mrp": 3499,
        "description": "Twirl-worthy 16-kali flair crafted from rich cotton mulmul with gold gota accents along the hem and festive tassel ties.",
        "fabric": "100% Mulmul Cotton",
        "occasion": "Festive & Celebrations",
        "pattern": "Gota Patti & Floral",
        "sleeve_length": "Full Sleeves",
        "neck_design": "V-Neck",
        "care": "Dry clean recommended for first wash. Gentle hand wash thereafter.",
        "image": "assets/k-anarkali.jpg",
        "relative_image": "assets/k-anarkali.jpg",
        "gallery_json": json.dumps(["assets/k-anarkali.jpg", "assets/hero.jpg"]),
        "colors_json": json.dumps([
            {"name": "Marigold", "swatch": "#E69A27"},
            {"name": "Maroon", "swatch": "#6B2D31"},
            {"name": "Emerald", "swatch": "#1C583B"},
            {"name": "Rani Pink", "swatch": "#C1285C"}
        ]),
        "sizes_json": json.dumps(["XS", "S", "M", "L", "XL", "XXL"]),
        "sold_out_sizes_json": json.dumps(["XXL"]),
        "stock": 18,
        "is_featured": 1,
        "is_new": 0,
        "is_bestseller": 1,
        "rating": 4.95,
        "reviews_count": 128
    },
    {
        "id": "short",
        "name": "Neel Short Kurti",
        "category": "Short Kurti",
        "style": "Everyday Tunic",
        "price": 899,
        "mrp": 1399,
        "description": "Chic everyday short tunic featuring authentic indigo Dabu block print. Style effortlessly over straight denims or linen trousers.",
        "fabric": "100% Indigo Cotton",
        "occasion": "Everyday & Workwear",
        "pattern": "Dabu Block Print",
        "sleeve_length": "3/4th Sleeves",
        "neck_design": "Mandarin Collar",
        "care": "Wash separately in cold water with mild detergent. Indigo colors may bleed initially.",
        "image": "assets/k-short.jpg",
        "relative_image": "assets/k-short.jpg",
        "gallery_json": json.dumps(["assets/k-short.jpg", "assets/hero.jpg"]),
        "colors_json": json.dumps([
            {"name": "Indigo", "swatch": "#1C335C"},
            {"name": "White", "swatch": "#FFFFFF"},
            {"name": "Black", "swatch": "#1F1F1F"}
        ]),
        "sizes_json": json.dumps(["XS", "S", "M", "L", "XL"]),
        "sold_out_sizes_json": json.dumps([]),
        "stock": 50,
        "is_featured": 0,
        "is_new": 1,
        "is_bestseller": 1,
        "rating": 4.75,
        "reviews_count": 92
    },
    {
        "id": "angrakha",
        "name": "Tulsi Angrakha",
        "category": "Angrakha",
        "style": "Wrap Angrakha",
        "price": 1799,
        "mrp": 2599,
        "description": "Timeless Mughal crossover overlap silhouette featuring handmade tasselled side ties, delicate zari stitches, and an asymmetrical border.",
        "fabric": "Handspun Slub Cotton",
        "occasion": "Festive & Celebrations",
        "pattern": "Thread Work & Zari",
        "sleeve_length": "3/4th Sleeves",
        "neck_design": "Angrakha V-Neck",
        "care": "Gentle hand wash. Do not wring or soak.",
        "image": "assets/k-angrakha.jpg",
        "relative_image": "assets/k-angrakha.jpg",
        "gallery_json": json.dumps(["assets/k-angrakha.jpg", "assets/hero.jpg"]),
        "colors_json": json.dumps([
            {"name": "Sage", "swatch": "#7B967D"},
            {"name": "Ivory", "swatch": "#F5F2EB"}
        ]),
        "sizes_json": json.dumps(["S", "M", "L", "XL", "XXL"]),
        "sold_out_sizes_json": json.dumps([]),
        "stock": 25,
        "is_featured": 1,
        "is_new": 1,
        "is_bestseller": 0,
        "rating": 4.88,
        "reviews_count": 47
    },
    {
        "id": "kaftan",
        "name": "Sandhya Kaftan Kurti",
        "category": "Kaftan",
        "style": "Relaxed Kaftan",
        "price": 1599,
        "mrp": 2299,
        "description": "Breezy relaxed kaftan with adjustable waist drawstring and boho tassel details. The ultimate weekend and resort comfort wear.",
        "fabric": "Organic Cotton Modal",
        "occasion": "Resort & Travel",
        "pattern": "Hand-Block Print",
        "sleeve_length": "Kaftan Sleeves",
        "neck_design": "V-Neck",
        "care": "Machine wash cold on gentle cycle. Medium iron.",
        "image": "assets/k-kaftan.jpg",
        "relative_image": "assets/k-kaftan.jpg",
        "gallery_json": json.dumps(["assets/k-kaftan.jpg", "assets/hero.jpg"]),
        "colors_json": json.dumps([
            {"name": "Rust", "swatch": "#9E472A"},
            {"name": "Sand", "swatch": "#D6C3A5"},
            {"name": "Olive", "swatch": "#5A6843"}
        ]),
        "sizes_json": json.dumps(["Free Size"]),
        "sold_out_sizes_json": json.dumps([]),
        "stock": 30,
        "is_featured": 0,
        "is_new": 1,
        "is_bestseller": 0,
        "rating": 4.7,
        "reviews_count": 38
    },
    {
        "id": "coord",
        "name": "Gulabi Kurta Set",
        "category": "Co-ord Set",
        "style": "2-Piece Kurta Set",
        "price": 2199,
        "mrp": 3199,
        "description": "Coordinated 2-piece set including a calf-length straight kurta and matching cropped trousers with pockets and elasticated waistband.",
        "fabric": "Cotton Silk Blend",
        "occasion": "Work & Semi-Festive",
        "pattern": "Solid & Woven",
        "sleeve_length": "3/4th Sleeves",
        "neck_design": "Round Neck",
        "care": "Hand wash or gentle cycle. Steam iron.",
        "image": "assets/k-coord.jpg",
        "relative_image": "assets/k-coord.jpg",
        "gallery_json": json.dumps(["assets/k-coord.jpg", "assets/hero.jpg"]),
        "colors_json": json.dumps([
            {"name": "Dusty Pink", "swatch": "#C4808C"},
            {"name": "Powder Blue", "swatch": "#8FA9BF"}
        ]),
        "sizes_json": json.dumps(["XS", "S", "M", "L", "XL", "XXL"]),
        "sold_out_sizes_json": json.dumps([]),
        "stock": 22,
        "is_featured": 1,
        "is_new": 0,
        "is_bestseller": 1,
        "rating": 4.92,
        "reviews_count": 115
    }
]

# Coupons Seed
DEFAULT_COUPONS = [
    {
        "code": "NAARI10",
        "discount_type": "percentage",
        "discount_value": 10,
        "min_order_value": 999,
        "max_discount": 500,
        "start_date": "2024-01-01",
        "expiry_date": "2028-12-31",
        "usage_limit": 5000,
        "applicable_categories": "",
        "applicable_products": "",
        "is_auto_apply": 0,
        "description": "Extra 10% OFF on all handcrafted kurtis (Min order ₹999)"
    },
    {
        "code": "FESTIVE300",
        "discount_type": "fixed",
        "discount_value": 300,
        "min_order_value": 2499,
        "max_discount": 300,
        "start_date": "2024-01-01",
        "expiry_date": "2028-12-31",
        "usage_limit": 2000,
        "applicable_categories": "",
        "applicable_products": "",
        "is_auto_apply": 0,
        "description": "Flat ₹300 OFF on festive orders above ₹2,499"
    },
    {
        "code": "FIRST50",
        "discount_type": "fixed",
        "discount_value": 50,
        "min_order_value": 499,
        "max_discount": 50,
        "start_date": "2024-01-01",
        "expiry_date": "2028-12-31",
        "usage_limit": 10000,
        "applicable_categories": "",
        "applicable_products": "",
        "is_auto_apply": 0,
        "description": "Flat ₹50 OFF welcome gift for your first purchase"
    },
    {
        "code": "WELCOME15",
        "discount_type": "percentage",
        "discount_value": 15,
        "min_order_value": 1999,
        "max_discount": 600,
        "start_date": "2024-01-01",
        "expiry_date": "2028-12-31",
        "usage_limit": 1000,
        "applicable_categories": "",
        "applicable_products": "",
        "is_auto_apply": 0,
        "description": "Special 15% OFF on orders above ₹1,999"
    }
]

DEFAULT_ANNOUNCEMENTS = [
    "FREE EXPRESS SHIPPING ON ORDERS ABOVE ₹999 ACROSS INDIA ✿",
    "EXTRA 10% OFF ON ORDERS ABOVE ₹999 | CODE: NAARI10",
    "100% PURE NATURAL COTTON & ARTISAN CRAFT",
    "EASY 7-DAY HASSLE-FREE RETURNS & SIZE EXCHANGES",
    "CASH ON DELIVERY (COD) AVAILABLE NATIONWIDE"
]

def get_site_settings_dict():
    settings = {}
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT key, value FROM site_settings")
        for r in c.fetchall():
            val = r["value"]
            try:
                settings[r["key"]] = json.loads(val)
            except Exception:
                settings[r["key"]] = val
        conn.close()
    except Exception:
        pass
    return settings

def load_config():
    config = {
        "razorpay_key_id": "",
        "razorpay_key_secret": "",
        "currency": "INR",
        "store_name": "Matra Naari",
        "store_description": "Modern Kurtis Rooted in Craft",
        "support_phone": "+91 88493 66915",
        "support_email": "hello@naari.in",
        "free_shipping_threshold": 999,
        "shipping_fee": 99,
        "cod_enabled": True,
        "gst_percentage": 5,
        "return_window_days": 7,
        "courier_provider": "Indian Postal Circle / Standard Courier"
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                disk_cfg = json.load(f)
                config.update(disk_cfg)
        except Exception as e:
            print(f"[Warning] Error loading config.json: {e}")

    db_settings = get_site_settings_dict()
    if "free_shipping_threshold" in db_settings:
        try:
            config["free_shipping_threshold"] = int(db_settings["free_shipping_threshold"])
        except (ValueError, TypeError):
            pass
    if "shipping_fee" in db_settings or "standard_shipping_fee" in db_settings:
        try:
            config["shipping_fee"] = int(db_settings.get("shipping_fee", db_settings.get("standard_shipping_fee", 99)))
        except (ValueError, TypeError):
            pass
    if "cod_enabled" in db_settings:
        val = db_settings["cod_enabled"]
        config["cod_enabled"] = bool(val) if isinstance(val, bool) else str(val).lower() in ("true", "1", "yes")
    if "gst_percentage" in db_settings:
        try:
            config["gst_percentage"] = int(db_settings["gst_percentage"])
        except (ValueError, TypeError):
            pass
    if "return_window_days" in db_settings:
        try:
            config["return_window_days"] = int(db_settings["return_window_days"])
        except (ValueError, TypeError):
            pass
    if "support_phone" in db_settings and str(db_settings["support_phone"]).strip():
        config["support_phone"] = str(db_settings["support_phone"]).strip()
    if "support_email" in db_settings and str(db_settings["support_email"]).strip():
        config["support_email"] = str(db_settings["support_email"]).strip()

    env_mappings = {
        "RAZORPAY_KEY_ID": "razorpay_key_id",
        "RAZORPAY_KEY_SECRET": "razorpay_key_secret",
        "CURRENCY": "currency",
        "STORE_NAME": "store_name",
        "STORE_DESCRIPTION": "store_description",
        "SUPPORT_PHONE": "support_phone",
        "SUPPORT_EMAIL": "support_email"
    }
    for env_var, cfg_key in env_mappings.items():
        val = os.environ.get(env_var)
        if val is not None and val.strip():
            config[cfg_key] = val.strip()

    return config

def is_razorpay_configured(cfg):
    key_id = cfg.get("razorpay_key_id", "").strip()
    key_secret = cfg.get("razorpay_key_secret", "").strip()
    if not key_id or not key_secret:
        return False
    if "YOUR_KEY" in key_id or "YOUR_KEY" in key_secret:
        return False
    return True

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = get_db()
    c = conn.cursor()

    # 1. Orders table
    c.execute("""
        CREATE TABLE IF NOT EXISTS orders (
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
            order_status TEXT DEFAULT 'confirmed',
            tracking_number TEXT,
            courier_partner TEXT,
            razorpay_order_id TEXT,
            razorpay_payment_id TEXT,
            razorpay_signature TEXT,
            subtotal INTEGER NOT NULL,
            shipping INTEGER NOT NULL,
            discount_amount INTEGER DEFAULT 0,
            coupon_code TEXT,
            total_amount INTEGER NOT NULL,
            items_json TEXT NOT NULL,
            user_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Check and add any missing columns in orders table if upgrading from earlier version
    c.execute("PRAGMA table_info(orders)")
    existing_cols = [row["name"] for row in c.fetchall()]
    migration_cols = {
        "order_status": "TEXT DEFAULT 'confirmed'",
        "tracking_number": "TEXT",
        "courier_partner": "TEXT",
        "discount_amount": "INTEGER DEFAULT 0",
        "coupon_code": "TEXT",
        "user_id": "TEXT"
    }
    for col, definition in migration_cols.items():
        if col not in existing_cols:
            c.execute(f"ALTER TABLE orders ADD COLUMN {col} {definition}")

    # 2. Products table
    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            style TEXT DEFAULT '',
            price INTEGER NOT NULL,
            mrp INTEGER NOT NULL,
            description TEXT,
            fabric TEXT,
            occasion TEXT DEFAULT '',
            pattern TEXT DEFAULT '',
            sleeve_length TEXT DEFAULT '',
            neck_design TEXT DEFAULT '',
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
            is_archived INTEGER DEFAULT 0,
            rating REAL DEFAULT 4.8,
            reviews_count INTEGER DEFAULT 35,
            created_at TEXT NOT NULL
        )
    """)

    c.execute("PRAGMA table_info(products)")
    prod_cols = [row["name"] for row in c.fetchall()]
    prod_migrations = {
        "style": "TEXT DEFAULT ''",
        "occasion": "TEXT DEFAULT ''",
        "pattern": "TEXT DEFAULT ''",
        "sleeve_length": "TEXT DEFAULT ''",
        "neck_design": "TEXT DEFAULT ''",
        "is_archived": "INTEGER DEFAULT 0"
    }
    for col, definition in prod_migrations.items():
        if col not in prod_cols:
            c.execute(f"ALTER TABLE products ADD COLUMN {col} {definition}")

    # 3. Coupons table
    c.execute("""
        CREATE TABLE IF NOT EXISTS coupons (
            code TEXT PRIMARY KEY,
            discount_type TEXT NOT NULL,
            discount_value INTEGER NOT NULL,
            min_order_value INTEGER DEFAULT 0,
            max_discount INTEGER DEFAULT 0,
            start_date TEXT DEFAULT '',
            expiry_date TEXT,
            usage_limit INTEGER DEFAULT 1000,
            used_count INTEGER DEFAULT 0,
            applicable_categories TEXT DEFAULT '',
            applicable_products TEXT DEFAULT '',
            is_auto_apply INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            description TEXT,
            created_at TEXT NOT NULL
        )
    """)

    c.execute("PRAGMA table_info(coupons)")
    cp_cols = [row["name"] for row in c.fetchall()]
    cp_migrations = {
        "start_date": "TEXT DEFAULT ''",
        "applicable_categories": "TEXT DEFAULT ''",
        "applicable_products": "TEXT DEFAULT ''",
        "is_auto_apply": "INTEGER DEFAULT 0"
    }
    for col, definition in cp_migrations.items():
        if col not in cp_cols:
            c.execute(f"ALTER TABLE coupons ADD COLUMN {col} {definition}")

    # 4. Users table (Customer Authentication)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # 5. User Sessions table
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)

    # 6. User Addresses table
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_addresses (
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

    # 7. Return & Exchange Requests table
    c.execute("""
        CREATE TABLE IF NOT EXISTS return_requests (
            id TEXT PRIMARY KEY,
            order_id TEXT NOT NULL,
            customer_email TEXT NOT NULL,
            customer_phone TEXT NOT NULL,
            item_name TEXT NOT NULL,
            action_type TEXT NOT NULL,
            reason TEXT NOT NULL,
            notes TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # 8. Site Settings table
    c.execute("""
        CREATE TABLE IF NOT EXISTS site_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    # 9. Newsletter Subscribers table
    c.execute("""
        CREATE TABLE IF NOT EXISTS newsletter_subscribers (
            email TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()

    # Seed Default Products if empty, and backfill/repair default product attributes & broken image paths
    c.execute("SELECT COUNT(*) AS cnt FROM products")
    if c.fetchone()["cnt"] == 0:
        now_iso = datetime.now().isoformat()
        for p in DEFAULT_PRODUCTS:
            c.execute("""
                INSERT INTO products (
                    id, name, category, style, price, mrp, description, fabric,
                    occasion, pattern, sleeve_length, neck_design, care,
                    image, relative_image, gallery_json, colors_json, sizes_json,
                    sold_out_sizes_json, stock, is_featured, is_new, is_bestseller,
                    is_archived, rating, reviews_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            """, (
                p["id"], p["name"], p["category"], p.get("style", ""), p["price"], p["mrp"], p["description"],
                p["fabric"], p.get("occasion", ""), p.get("pattern", ""), p.get("sleeve_length", ""),
                p.get("neck_design", ""), p["care"], p["image"], p["relative_image"], p["gallery_json"],
                p["colors_json"], p["sizes_json"], p["sold_out_sizes_json"], p["stock"],
                p["is_featured"], p["is_new"], p["is_bestseller"], p["rating"], p["reviews_count"],
                now_iso
            ))
        conn.commit()
    else:
        # Backfill rich ethnic attributes on existing default products and repair any non-existent image path
        for p in DEFAULT_PRODUCTS:
            c.execute("SELECT image, relative_image, fabric, care, colors_json, gallery_json FROM products WHERE id = ?", (p["id"],))
            existing = c.fetchone()
            if existing:
                curr_img = existing["image"] or ""
                curr_rel = existing["relative_image"] or ""
                img_file = os.path.join(BASE_DIR, curr_img.lstrip("/"))
                rel_file = os.path.join(BASE_DIR, curr_rel.lstrip("/"))
                fixed_img = p["image"] if not (curr_img and os.path.isfile(img_file)) else curr_img
                fixed_rel = p["relative_image"] if not (curr_rel and os.path.isfile(rel_file)) else curr_rel
                fixed_fabric = existing["fabric"] if (existing["fabric"] and existing["fabric"].strip()) else p["fabric"]
                fixed_care = existing["care"] if (existing["care"] and existing["care"].strip()) else p["care"]
                fixed_colors = p["colors_json"] if (not existing["colors_json"] or "Standard" in existing["colors_json"]) else existing["colors_json"]
                fixed_gallery = p["gallery_json"] if not (curr_img and os.path.isfile(img_file)) else existing["gallery_json"]
                c.execute("""
                    UPDATE products
                    SET style = CASE WHEN style IS NULL OR style = '' THEN ? ELSE style END,
                        occasion = CASE WHEN occasion IS NULL OR occasion = '' THEN ? ELSE occasion END,
                        pattern = CASE WHEN pattern IS NULL OR pattern = '' THEN ? ELSE pattern END,
                        sleeve_length = CASE WHEN sleeve_length IS NULL OR sleeve_length = '' THEN ? ELSE sleeve_length END,
                        neck_design = CASE WHEN neck_design IS NULL OR neck_design = '' THEN ? ELSE neck_design END,
                        fabric = ?,
                        care = ?,
                        image = ?,
                        relative_image = ?,
                        colors_json = ?,
                        gallery_json = ?
                    WHERE id = ?
                """, (
                    p.get("style", ""), p.get("occasion", ""), p.get("pattern", ""),
                    p.get("sleeve_length", ""), p.get("neck_design", ""),
                    fixed_fabric, fixed_care, fixed_img, fixed_rel, fixed_colors, fixed_gallery,
                    p["id"]
                ))
        conn.commit()

    # Seed Default Coupons if empty
    c.execute("SELECT COUNT(*) AS cnt FROM coupons")
    if c.fetchone()["cnt"] == 0:
        now_iso = datetime.now().isoformat()
        for cp in DEFAULT_COUPONS:
            c.execute("""
                INSERT INTO coupons (
                    code, discount_type, discount_value, min_order_value, max_discount,
                    start_date, expiry_date, usage_limit, used_count, applicable_categories,
                    applicable_products, is_auto_apply, is_active, description, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cp["code"], cp["discount_type"], cp["discount_value"], cp["min_order_value"],
                cp["max_discount"], cp.get("start_date", "2024-01-01"), cp["expiry_date"],
                cp["usage_limit"], 0, cp.get("applicable_categories", ""),
                cp.get("applicable_products", ""), cp.get("is_auto_apply", 0), 1,
                cp["description"], now_iso
            ))
        conn.commit()

    # Seed Site Settings if empty
    c.execute("SELECT COUNT(*) AS cnt FROM site_settings")
    if c.fetchone()["cnt"] == 0:
        c.execute("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)", ("announcements", json.dumps(DEFAULT_ANNOUNCEMENTS)))
        c.execute("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)", ("announcement_enabled", "true"))
        c.execute("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)", ("free_shipping_threshold", "999"))
        c.execute("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)", ("shipping_fee", "99"))
        c.execute("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)", ("cod_enabled", "true"))
        c.execute("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)", ("promo_banner_enabled", "true"))
        c.execute("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)", ("promo_banner_code", "NAARI10"))
        conn.commit()

    conn.close()

# Password hashing with PBKDF2
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return key.hex(), salt

def verify_password(password, salt, hashed):
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return hmac.compare_digest(key.hex(), hashed)

def generate_order_id():
    now_str = datetime.now().strftime("%Y%m%d%H%M%S")
    rand_suffix = secrets.token_hex(3).upper()
    return f"NAARI-{now_str}-{rand_suffix}"

def format_product_row(row):
    d = dict(row)
    d["gallery"] = json.loads(d.get("gallery_json") or "[]")
    d["colors"] = json.loads(d.get("colors_json") or "[]")
    d["sizes"] = json.loads(d.get("sizes_json") or "[]")
    d["soldOutSizes"] = json.loads(d.get("sold_out_sizes_json") or "[]")
    d["inStock"] = d.get("stock", 0) > 0 and not d.get("is_archived", 0)
    d["discountPercent"] = int(round((d["mrp"] - d["price"]) / d["mrp"] * 100)) if d.get("mrp", 0) > d.get("price", 0) else 0
    return d

def get_product_from_db(pid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM products WHERE id = ?", (pid,))
    row = c.fetchone()
    conn.close()
    if row:
        return format_product_row(row)
    return None

def evaluate_coupon(code, subtotal, computed_items=None):
    """
    Validates a coupon against all business rules:
    - Active status
    - Start date & Expiry date
    - Usage limit vs used_count
    - Minimum order value
    - Product-specific and Category-specific eligibility
    - Percentage (with max cap) or Fixed-amount discount calculation
    Returns (coupon_dict, discount_amount, error_message)
    """
    clean_code = str(code or "").strip().upper()
    if not clean_code:
        return None, 0, "Please enter a coupon code."

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM coupons WHERE code = ?", (clean_code,))
    row = c.fetchone()
    conn.close()

    if not row:
        return None, 0, f"Invalid coupon code '{clean_code}'."

    cp = dict(row)
    if not cp.get("is_active"):
        return None, 0, f"Coupon '{clean_code}' is currently inactive."

    now_date = datetime.now().strftime("%Y-%m-%d")
    start_dt = str(cp.get("start_date") or "").strip()
    if start_dt and len(start_dt) >= 10 and now_date < start_dt[:10]:
        return None, 0, f"Coupon '{clean_code}' is not active yet (starts {start_dt[:10]})."

    exp_dt = str(cp.get("expiry_date") or "").strip()
    if exp_dt and len(exp_dt) >= 10 and now_date > exp_dt[:10]:
        return None, 0, f"Coupon code '{clean_code}' has expired."

    usage_limit = int(cp.get("usage_limit") or 0)
    used_count = int(cp.get("used_count") or 0)
    if usage_limit > 0 and used_count >= usage_limit:
        return None, 0, f"Coupon '{clean_code}' has reached its maximum redemption limit."

    min_val = int(cp.get("min_order_value") or 0)
    if subtotal < min_val:
        return None, 0, f"Coupon {clean_code} requires a minimum order value of ₹{min_val:,} (Current bag: ₹{subtotal:,})."

    # Check category or product eligibility if configured
    eligible_subtotal = subtotal
    app_cats = [x.strip().lower() for x in str(cp.get("applicable_categories") or "").split(",") if x.strip()]
    app_prods = [x.strip().lower() for x in str(cp.get("applicable_products") or "").split(",") if x.strip()]

    if (app_cats or app_prods) and computed_items:
        eligible_subtotal = 0
        for item in computed_items:
            pid = str(item.get("id", "")).lower()
            cat = str(item.get("category", "")).lower()
            if (app_prods and pid in app_prods) or (app_cats and cat in app_cats):
                eligible_subtotal += int(item.get("subtotal", 0))
        if eligible_subtotal <= 0:
            return None, 0, f"Coupon '{clean_code}' is not applicable to the items in your bag."

    if cp["discount_type"] == "percentage":
        raw_discount = int(round(eligible_subtotal * (float(cp["discount_value"]) / 100.0)))
        max_disc = int(cp.get("max_discount") or 0)
        discount = min(raw_discount, max_disc) if max_disc > 0 else raw_discount
    else:
        discount = min(int(cp["discount_value"]), eligible_subtotal)

    discount = max(0, min(discount, subtotal))
    return cp, discount, None

def validate_and_compute_totals(items, coupon_code=""):
    if not isinstance(items, list) or len(items) == 0:
        return None, "Shopping bag is empty."
    
    computed_items = []
    subtotal = 0

    for item in items:
        if not isinstance(item, dict):
            continue
        pid = str(item.get("id", "")).strip()
        if not pid:
            continue

        try:
            qty = int(item.get("qty", 1))
        except (ValueError, TypeError):
            qty = 1
        if qty < 1 or qty > 50:
            return None, "Invalid quantity."

        color = str(item.get("color") or "Standard").strip()
        size = str(item.get("size") or "Free Size").strip()

        prod = get_product_from_db(pid)
        if prod:
            if prod.get("stock", 0) <= 0 or prod.get("is_archived", 0):
                return None, f"Sorry, '{prod['name']}' is currently out of stock."
            if qty > prod.get("stock", 50):
                return None, f"Only {prod['stock']} unit(s) of '{prod['name']}' available in stock."
            if size in prod.get("soldOutSizes", []):
                return None, f"Size '{size}' for '{prod['name']}' is currently sold out."
            name = prod["name"]
            category = prod.get("category", "")
            price = prod["price"]
            mrp = prod["mrp"]
            img = item.get("image") or prod["relative_image"]
        else:
            name = str(item.get("name") or f"Naari Kurti ({pid})")
            category = str(item.get("category") or "")
            try:
                price = int(item.get("price", 0))
            except (ValueError, TypeError):
                price = 0
            mrp = int(item.get("mrp", price * 1.4))
            img = item.get("image", "assets/hero.jpg")
            if price <= 0:
                return None, f"Unrecognized product: {pid}"

        item_subtotal = price * qty
        subtotal += item_subtotal

        computed_items.append({
            "id": pid,
            "name": name,
            "category": category,
            "color": color,
            "size": size,
            "qty": qty,
            "price": price,
            "mrp": mrp,
            "subtotal": item_subtotal,
            "image": img
        })

    if not computed_items:
        return None, "Shopping bag contains no valid items."

    # Validate explicit coupon or check auto-apply promotion
    discount = 0
    applied_coupon = None
    if coupon_code and str(coupon_code).strip():
        cp, disc, cp_err = evaluate_coupon(coupon_code, subtotal, computed_items)
        if cp and not cp_err:
            discount = disc
            applied_coupon = cp["code"]
    else:
        # Check if there is an active auto-apply promotion
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT code FROM coupons WHERE is_active = 1 AND is_auto_apply = 1 ORDER BY discount_value DESC")
        auto_rows = c.fetchall()
        conn.close()
        for ar in auto_rows:
            cp, disc, cp_err = evaluate_coupon(ar["code"], subtotal, computed_items)
            if cp and not cp_err and disc > 0:
                discount = disc
                applied_coupon = cp["code"]
                break

    cfg = load_config()
    free_threshold = int(cfg.get("free_shipping_threshold", 999))
    shipping_fee = int(cfg.get("shipping_fee", 99))
    shipping = 0 if subtotal >= free_threshold else shipping_fee

    total_amount = max(0, subtotal - discount + shipping)

    return {
        "items": computed_items,
        "subtotal": subtotal,
        "discount": discount,
        "applied_coupon": applied_coupon,
        "shipping": shipping,
        "free_shipping_threshold": free_threshold,
        "total_amount": total_amount
    }, None

def validate_customer_info(cust):
    if not cust or not isinstance(cust, dict):
        return "Customer information is required."
    
    name = str(cust.get("name", "")).strip()
    phone = str(cust.get("phone", "")).strip()
    email = str(cust.get("email", "")).strip()
    address1 = str(cust.get("address_line1", "")).strip()
    city = str(cust.get("city", "")).strip()
    state = str(cust.get("state", "")).strip()
    pincode = str(cust.get("pincode", "")).strip()

    if len(name) < 2:
        return "Please enter your full name."
    
    clean_phone = phone.replace(" ", "").replace("-", "")
    if clean_phone.startswith("+91"):
        clean_phone = clean_phone[3:]
    elif clean_phone.startswith("91") and len(clean_phone) == 12:
        clean_phone = clean_phone[2:]
    if not (clean_phone.isdigit() and len(clean_phone) == 10):
        return "Please enter a valid 10-digit mobile number."

    if "@" not in email or "." not in email:
        return "Please enter a valid email address."
    if len(address1) < 5:
        return "Please enter your complete delivery street address."
    if len(city) < 2:
        return "Please enter your city."
    if len(state) < 2:
        return "Please select your state."
    
    clean_pin = pincode.replace(" ", "")
    if not (clean_pin.isdigit() and len(clean_pin) == 6):
        return "Please enter a valid 6-digit PIN code."

    return None

def get_current_user():
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "user_token" in request.cookies:
        token = request.cookies.get("user_token")
    elif request.args.get("token"):
        token = request.args.get("token").strip()

    if not token:
        return None

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT u.id, u.name, u.email, u.phone
        FROM users u
        JOIN user_sessions s ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > ?
    """, (token, datetime.now().isoformat()))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None

def check_admin_auth():
    passkey = request.headers.get("X-Admin-Passkey", "").strip() or request.args.get("passkey", "").strip()
    return passkey == ADMIN_SECRET_KEY

# ================= Initialize Flask App =================
app = Flask(__name__, static_folder=BASE_DIR)
app.url_map.strict_slashes = False
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

init_db()

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Admin-Passkey"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

# ================= Public Storefront APIs =================

@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "ok": True,
        "service": "naari-api",
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    })

@app.route("/api/config", methods=["GET"])
def api_config():
    cfg = load_config()
    configured = is_razorpay_configured(cfg)
    return jsonify({
        "ok": True,
        "razorpay_key_id": cfg.get("razorpay_key_id", "") if configured else "",
        "is_razorpay_configured": configured,
        "store_name": cfg.get("store_name", "Matra Naari"),
        "store_description": cfg.get("store_description", "Modern Kurtis Rooted in Craft"),
        "currency": cfg.get("currency", "INR"),
        "support_phone": cfg.get("support_phone", "+91 88493 66915"),
        "support_email": cfg.get("support_email", "hello@naari.in"),
        "free_shipping_threshold": int(cfg.get("free_shipping_threshold", 999)),
        "shipping_fee": int(cfg.get("shipping_fee", 99)),
        "cod_enabled": bool(cfg.get("cod_enabled", True)),
        "gst_percentage": int(cfg.get("gst_percentage", 5)),
        "return_window_days": int(cfg.get("return_window_days", 7)),
        "courier_provider": cfg.get("courier_provider", "Indian Postal Circle / Standard Courier")
    })

@app.route("/api/products", methods=["GET"])
def api_products():
    category = request.args.get("category", "").strip()
    style = request.args.get("style", "").strip()
    search = request.args.get("search", "").strip().lower()
    sort = request.args.get("sort", "recommended").strip()
    size = request.args.get("size", "").strip()
    color = request.args.get("color", "").strip()
    fabric = request.args.get("fabric", "").strip()
    occasion = request.args.get("occasion", "").strip()
    pattern = request.args.get("pattern", "").strip()
    sleeve_length = request.args.get("sleeve_length", "").strip()
    neck_design = request.args.get("neck_design", "").strip()
    in_stock = request.args.get("in_stock", "").strip()
    min_price = request.args.get("min_price", type=int)
    max_price = request.args.get("max_price", type=int)
    featured = request.args.get("featured", "").strip()
    include_archived = request.args.get("include_archived", "").strip() == "1"

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM products ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()

    all_active = []
    results = []
    for r in rows:
        p = format_product_row(r)
        if not include_archived and p.get("is_archived", 0):
            continue
        all_active.append(p)

        # Filter: category
        if category and category.lower() != "all":
            cats = [x.strip().lower() for x in category.split(",") if x.strip()]
            if p["category"].lower() not in cats:
                continue

        # Filter: style
        if style:
            styles = [x.strip().lower() for x in style.split(",") if x.strip()]
            if str(p.get("style", "")).lower() not in styles:
                continue

        # Filter: search
        if search:
            combined = f"{p['name']} {p['category']} {p.get('style', '')} {p['description']} {p['fabric']} {p.get('occasion', '')} {p.get('pattern', '')} {p.get('sleeve_length', '')} {p.get('neck_design', '')}".lower()
            if search not in combined:
                continue

        # Filter: price
        if min_price is not None and p["price"] < min_price:
            continue
        if max_price is not None and p["price"] > max_price:
            continue

        # Filter: size
        if size:
            req_sizes = [x.strip() for x in size.split(",") if x.strip()]
            avail_sizes = [s for s in p["sizes"] if s not in p["soldOutSizes"]]
            if not any(rs in avail_sizes for rs in req_sizes):
                continue

        # Filter: color
        if color:
            req_colors = [x.strip().lower() for x in color.split(",") if x.strip()]
            color_names = [c["name"].lower() for c in p["colors"]]
            if not any(rc in color_names for rc in req_colors):
                continue

        # Filter: fabric
        if fabric:
            req_fabrics = [x.strip().lower() for x in fabric.split(",") if x.strip()]
            pfab = str(p.get("fabric") or "").lower()
            if not any(rf in pfab for rf in req_fabrics):
                continue

        # Filter: occasion
        if occasion:
            req_occ = [x.strip().lower() for x in occasion.split(",") if x.strip()]
            pocc = str(p.get("occasion") or "").lower()
            if not any(ro in pocc for ro in req_occ):
                continue

        # Filter: pattern
        if pattern:
            req_pat = [x.strip().lower() for x in pattern.split(",") if x.strip()]
            ppat = str(p.get("pattern") or "").lower()
            if not any(rp in ppat for rp in req_pat):
                continue

        # Filter: sleeve_length
        if sleeve_length:
            req_slv = [x.strip().lower() for x in sleeve_length.split(",") if x.strip()]
            pslv = str(p.get("sleeve_length") or "").lower()
            if not any(rs in pslv for rs in req_slv):
                continue

        # Filter: neck_design
        if neck_design:
            req_neck = [x.strip().lower() for x in neck_design.split(",") if x.strip()]
            pneck = str(p.get("neck_design") or "").lower()
            if not any(rn in pneck for rn in req_neck):
                continue

        # Filter: in_stock
        if in_stock == "1" and not p["inStock"]:
            continue

        # Filter: featured
        if featured == "1" and not p.get("is_featured"):
            continue

        results.append(p)

    # Sorting
    if sort == "price_asc":
        results.sort(key=lambda x: x["price"])
    elif sort == "price_desc":
        results.sort(key=lambda x: x["price"], reverse=True)
    elif sort == "newest":
        results.sort(key=lambda x: (x.get("is_new", 0), x.get("created_at", "")), reverse=True)
    elif sort == "bestseller":
        results.sort(key=lambda x: (x.get("is_bestseller", 0), x.get("reviews_count", 0)), reverse=True)
    elif sort == "discount":
        results.sort(key=lambda x: x.get("discountPercent", 0), reverse=True)

    # Build available attribute facets from all_active catalog so filter groups only show genuine existing values
    facets = {
        "categories": sorted(list({p["category"] for p in all_active if p.get("category")})),
        "styles": sorted(list({p.get("style", "") for p in all_active if p.get("style")})),
        "fabrics": sorted(list({p.get("fabric", "") for p in all_active if p.get("fabric")})),
        "occasions": sorted(list({p.get("occasion", "") for p in all_active if p.get("occasion")})),
        "patterns": sorted(list({p.get("pattern", "") for p in all_active if p.get("pattern")})),
        "sleeve_lengths": sorted(list({p.get("sleeve_length", "") for p in all_active if p.get("sleeve_length")})),
        "neck_designs": sorted(list({p.get("neck_design", "") for p in all_active if p.get("neck_design")})),
        "sizes": [],
        "colors": []
    }
    size_order = ["XS", "S", "M", "L", "XL", "XXL", "Free Size"]
    seen_sizes = set()
    for p in all_active:
        for s in p.get("sizes", []):
            seen_sizes.add(s)
    facets["sizes"] = [s for s in size_order if s in seen_sizes] + [s for s in sorted(seen_sizes) if s not in size_order]

    seen_colors = {}
    for p in all_active:
        for col in p.get("colors", []):
            cname = col.get("name", "")
            if cname and cname not in seen_colors:
                seen_colors[cname] = col.get("swatch", "#6B2D31")
    facets["colors"] = [{"name": k, "swatch": v} for k, v in sorted(seen_colors.items())]

    return jsonify({
        "ok": True,
        "count": len(results),
        "total_catalog_count": len(all_active),
        "facets": facets,
        "products": results
    })

@app.route("/api/products/<pid>", methods=["GET"])
def api_product_detail(pid):
    prod = get_product_from_db(pid)
    if not prod:
        return jsonify({"ok": False, "error": f"Product not found: {pid}"}), 404

    # Get related items in same or adjacent categories
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM products WHERE id != ? AND is_archived = 0 LIMIT 4", (pid,))
    related = [format_product_row(r) for r in c.fetchall()]
    conn.close()

    # Size chart guide (Standard Indian kurti measurements in inches)
    size_chart = [
        {"size": "XS", "bust": "34", "waist": "30", "hip": "36", "length": "44"},
        {"size": "S", "bust": "36", "waist": "32", "hip": "38", "length": "44"},
        {"size": "M", "bust": "38", "waist": "34", "hip": "40", "length": "45"},
        {"size": "L", "bust": "40", "waist": "36", "hip": "42", "length": "45"},
        {"size": "XL", "bust": "42", "waist": "38", "hip": "44", "length": "46"},
        {"size": "XXL", "bust": "44", "waist": "40", "hip": "46", "length": "46"}
    ]

    return jsonify({
        "ok": True,
        "product": prod,
        "size_chart": size_chart,
        "related_products": related
    })

@app.route("/api/categories", methods=["GET"])
def api_categories():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT category, COUNT(*) as count FROM products WHERE is_archived = 0 GROUP BY category")
    rows = c.fetchall()
    conn.close()
    return jsonify({"ok": True, "categories": [dict(r) for r in rows]})

@app.route("/api/banners", methods=["GET"])
def api_banners():
    settings = get_site_settings_dict()
    cfg = load_config()

    ann_enabled_val = settings.get("announcement_enabled", True)
    announcement_enabled = bool(ann_enabled_val) if isinstance(ann_enabled_val, bool) else str(ann_enabled_val).lower() not in ("false", "0", "no")

    announcements = settings.get("announcements", DEFAULT_ANNOUNCEMENTS)
    if isinstance(announcements, str):
        announcements = [x.strip() for x in announcements.split("|") if x.strip()]
    if settings.get("announcement_text") and str(settings.get("announcement_text")).strip():
        custom_txt = str(settings.get("announcement_text")).strip()
        parts = [x.strip() for x in custom_txt.split("|") if x.strip()] or [custom_txt]
        for d_ann in DEFAULT_ANNOUNCEMENTS:
            if d_ann not in parts:
                parts.append(d_ann)
        announcements = parts

    promo_enabled_val = settings.get("promo_banner_enabled", True)
    promo_banner_enabled = bool(promo_enabled_val) if isinstance(promo_enabled_val, bool) else str(promo_enabled_val).lower() not in ("false", "0", "no")
    promo_code = str(settings.get("promo_banner_code", "NAARI10")).strip().upper()

    # Verify if the featured promo coupon is actually active in the database
    active_promo_coupon = None
    conn = get_db()
    c = conn.cursor()
    if promo_code:
        c.execute("SELECT code, discount_type, discount_value, min_order_value, max_discount, description, expiry_date FROM coupons WHERE code = ? AND is_active = 1", (promo_code,))
        row = c.fetchone()
        if row:
            active_promo_coupon = dict(row)
    if not active_promo_coupon:
        c.execute("SELECT code, discount_type, discount_value, min_order_value, max_discount, description, expiry_date FROM coupons WHERE is_active = 1 ORDER BY created_at ASC LIMIT 1")
        row = c.fetchone()
        if row:
            active_promo_coupon = dict(row)
    conn.close()

    if not active_promo_coupon:
        promo_banner_enabled = False

    return jsonify({
        "ok": True,
        "announcement_enabled": announcement_enabled,
        "announcements": announcements if announcement_enabled else [],
        "free_shipping_threshold": int(cfg.get("free_shipping_threshold", 999)),
        "shipping_fee": int(cfg.get("shipping_fee", 99)),
        "cod_enabled": bool(cfg.get("cod_enabled", True)),
        "promo_banner_enabled": promo_banner_enabled,
        "active_promo_coupon": active_promo_coupon,
        "hero_banners": [
            {
                "title": "Kurtis for the Modern Naari",
                "tagline": "Rooted in authentic handcraft, tailored for contemporary elegance.",
                "cta_text": "Shop New In",
                "cta_link": "shop.html",
                "badge": "100% Pure Natural Fibers",
                "image": "assets/hero.jpg"
            }
        ]
    })

@app.route("/api/coupons", methods=["GET"])
def api_coupons():
    now_date = datetime.now().strftime("%Y-%m-%d")
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT code, discount_type, discount_value, min_order_value, max_discount,
               start_date, expiry_date, usage_limit, used_count,
               applicable_categories, applicable_products, is_auto_apply, description
        FROM coupons
        WHERE is_active = 1
    """)
    rows = c.fetchall()
    conn.close()
    valid_coupons = []
    for r in rows:
        cp = dict(r)
        if cp.get("expiry_date") and len(cp["expiry_date"]) >= 10 and now_date > cp["expiry_date"][:10]:
            continue
        if cp.get("start_date") and len(cp["start_date"]) >= 10 and now_date < cp["start_date"][:10]:
            continue
        if cp.get("usage_limit", 0) > 0 and cp.get("used_count", 0) >= cp.get("usage_limit", 0):
            continue
        valid_coupons.append(cp)
    return jsonify({"ok": True, "coupons": valid_coupons})

@app.route("/api/apply-coupon", methods=["POST"])
def api_apply_coupon():
    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip().upper()
    items = data.get("items")
    try:
        subtotal = int(data.get("subtotal", 0))
    except (ValueError, TypeError):
        subtotal = 0

    computed_items = None
    if isinstance(items, list) and len(items) > 0:
        calc_items = []
        calc_sub = 0
        for it in items:
            if not isinstance(it, dict):
                continue
            pid = str(it.get("id", "")).strip()
            qty = max(1, int(it.get("qty", 1)))
            prod = get_product_from_db(pid) if pid else None
            price = prod["price"] if prod else int(it.get("price", 0))
            cat = prod["category"] if prod else str(it.get("category", ""))
            calc_sub += price * qty
            calc_items.append({"id": pid, "category": cat, "subtotal": price * qty})
        if calc_sub > 0 and subtotal == 0:
            subtotal = calc_sub
        computed_items = calc_items

    cp, discount, err = evaluate_coupon(code, subtotal, computed_items)
    if err or not cp:
        return jsonify({"ok": False, "error": err or "Invalid coupon code."}), 400

    cfg = load_config()
    free_threshold = int(cfg.get("free_shipping_threshold", 999))
    shipping_fee = int(cfg.get("shipping_fee", 99))
    shipping = 0 if subtotal >= free_threshold else shipping_fee
    final_total = max(0, subtotal - discount + shipping)

    return jsonify({
        "ok": True,
        "code": cp["code"],
        "discount_type": cp["discount_type"],
        "discount_value": cp["discount_value"],
        "discount_amount": discount,
        "subtotal": subtotal,
        "shipping": shipping,
        "final_total": final_total,
        "message": f"Coupon '{cp['code']}' applied! You save ₹{discount:,}."
    })

@app.route("/api/check-pincode", methods=["POST"])
def api_check_pincode():
    data = request.get_json(silent=True) or {}
    pin = str(data.get("pincode", "")).strip()

    if not (pin.isdigit() and len(pin) == 6):
        return jsonify({"ok": False, "error": "Please enter a valid 6-digit PIN code."}), 400

    first_digit = int(pin[0])
    # Indian PIN circles 1 to 8 are valid domestic postal circles
    if first_digit < 1 or first_digit > 8:
        return jsonify({"ok": False, "error": "PIN code is outside standard domestic delivery zones."}), 400

    cfg = load_config()
    cod_enabled = bool(cfg.get("cod_enabled", True))
    free_threshold = int(cfg.get("free_shipping_threshold", 999))
    shipping_fee = int(cfg.get("shipping_fee", 99))

    # Map Indian postal zone for realistic regional estimate
    zone_map = {
        1: ("North India (Delhi / NCR / Punjab / Haryana)", 3, 5),
        2: ("North-Central (Uttar Pradesh / Uttarakhand)", 3, 5),
        3: ("West-North (Rajasthan / Gujarat)", 2, 4),
        4: ("West-Central (Maharashtra / Goa / MP)", 2, 4),
        5: ("South-Central (Telangana / Andhra / Karnataka)", 3, 5),
        6: ("South (Tamil Nadu / Kerala)", 4, 6),
        7: ("East & North-East (West Bengal / Odisha / Assam)", 4, 6),
        8: ("East-Central (Bihar / Jharkhand)", 4, 6)
    }
    region_name, min_days, max_days = zone_map.get(first_digit, ("Domestic Zone", 3, 5))

    now = datetime.now()
    est_start = now + timedelta(days=min_days)
    est_end = now + timedelta(days=max_days)
    est_str = f"{est_start.strftime('%a, %d %b')} – {est_end.strftime('%a, %d %b')}"

    return jsonify({
        "ok": True,
        "pincode": pin,
        "region": region_name,
        "serviceable": True,
        "cod_available": cod_enabled,
        "free_delivery": True,
        "free_shipping_threshold": free_threshold,
        "shipping_fee": shipping_fee,
        "estimated_delivery": est_str,
        "courier_mode": "postal_circle_estimate",
        "message": f"Delivery available to {pin} ({region_name}). Estimated arrival: {est_str} (Standard Postal Circle Estimate)."
    })

@app.route("/api/newsletter", methods=["POST"])
def api_newsletter():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    if "@" not in email or "." not in email or len(email) < 5:
        return jsonify({"ok": False, "error": "Please enter a valid email address."}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO newsletter_subscribers (email, created_at) VALUES (?, ?)", (email, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Thank you for subscribing to Matra Naari updates!"})

# ================= Customer Authentication & Account APIs =================

@app.route("/api/auth/register", methods=["POST"])
def api_auth_register():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    phone = str(data.get("phone", "")).strip()
    password = str(data.get("password", "")).strip()

    if len(name) < 2:
        return jsonify({"ok": False, "error": "Please enter your name."}), 400
    if "@" not in email or "." not in email:
        return jsonify({"ok": False, "error": "Please enter a valid email address."}), 400
    if len(phone) < 10:
        return jsonify({"ok": False, "error": "Please enter a valid 10-digit mobile number."}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters long."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email = ?", (email,))
    if c.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": "An account with this email already exists. Please log in."}), 400

    user_id = f"usr_{secrets.token_hex(6)}"
    pw_hash, salt = hash_password(password)
    now_iso = datetime.now().isoformat()

    c.execute("""
        INSERT INTO users (id, name, email, phone, password_hash, salt, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, name, email, phone, pw_hash, salt, now_iso))

    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    c.execute("INSERT INTO user_sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
              (token, user_id, now_iso, expires))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "token": token,
        "user": {
            "id": user_id,
            "name": name,
            "email": email,
            "phone": phone
        }
    })

@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", "")).strip()

    if not email or not password:
        return jsonify({"ok": False, "error": "Email and password are required."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "No account found with this email."}), 400

    user = dict(row)
    if not verify_password(password, user["salt"], user["password_hash"]):
        conn.close()
        return jsonify({"ok": False, "error": "Incorrect password. Please try again."}), 400

    token = secrets.token_hex(32)
    now_iso = datetime.now().isoformat()
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    c.execute("INSERT INTO user_sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
              (token, user["id"], now_iso, expires))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "phone": user["phone"]
        }
    })

@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else request.cookies.get("user_token")
    if token:
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    return jsonify({"ok": True, "message": "Logged out successfully."})

@app.route("/api/auth/me", methods=["GET"])
def api_auth_me():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return jsonify({"ok": True, "user": user})

@app.route("/api/auth/profile", methods=["PUT", "POST"])
def api_auth_profile():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip() or user["name"]
    phone = str(data.get("phone", "")).strip() or user["phone"]
    if len(name) < 2 or len(phone) < 10:
        return jsonify({"ok": False, "error": "Please enter a valid name and 10-digit mobile number."}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET name = ?, phone = ? WHERE id = ?", (name, phone, user["id"]))
    conn.commit()
    conn.close()
    user["name"] = name
    user["phone"] = phone
    return jsonify({"ok": True, "user": user, "message": "Profile updated successfully."})

@app.route("/api/customer/addresses", methods=["GET", "POST"])
def api_customer_addresses():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip() or user["name"]
        phone = str(data.get("phone", "")).strip() or user["phone"]
        address1 = str(data.get("address_line1", "")).strip()
        address2 = str(data.get("address_line2", "")).strip()
        city = str(data.get("city", "")).strip()
        state = str(data.get("state", "")).strip()
        pincode = str(data.get("pincode", "")).strip()
        is_default = 1 if data.get("is_default") else 0

        if len(address1) < 5 or not city or not state or len(pincode) != 6:
            conn.close()
            return jsonify({"ok": False, "error": "Please fill out all address fields correctly."}), 400

        addr_id = f"addr_{secrets.token_hex(4)}"
        if is_default:
            c.execute("UPDATE user_addresses SET is_default = 0 WHERE user_id = ?", (user["id"],))

        c.execute("""
            INSERT INTO user_addresses (id, user_id, name, phone, address_line1, address_line2, city, state, pincode, is_default, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (addr_id, user["id"], name, phone, address1, address2, city, state, pincode, is_default, datetime.now().isoformat()))
        conn.commit()

    c.execute("SELECT * FROM user_addresses WHERE user_id = ? ORDER BY is_default DESC, created_at DESC", (user["id"],))
    addrs = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"ok": True, "addresses": addrs})

@app.route("/api/customer/addresses/<aid>", methods=["DELETE"])
def api_customer_address_delete(aid):
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM user_addresses WHERE id = ? AND user_id = ?", (aid, user["id"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Address removed."})

@app.route("/api/customer/orders", methods=["GET"])
def api_customer_orders():
    user = get_current_user()
    email = user["email"] if user else request.args.get("email", "").strip().lower()

    if not email:
        return jsonify({"ok": False, "error": "Email is required to retrieve orders."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM orders
        WHERE LOWER(customer_email) = ?
        ORDER BY created_at DESC
    """, (email,))
    rows = c.fetchall()
    conn.close()

    orders = []
    for r in rows:
        od = dict(r)
        od["items"] = json.loads(od.pop("items_json", "[]"))
        orders.append(od)

    return jsonify({"ok": True, "orders": orders})

@app.route("/api/customer/orders/cancel", methods=["POST"])
def api_customer_order_cancel():
    data = request.get_json(silent=True) or {}
    order_id = str(data.get("order_id", "")).strip()
    reason = str(data.get("reason", "Cancelled by customer")).strip()
    user = get_current_user()
    email = user["email"] if user else str(data.get("customer_email", "")).strip().lower()

    if not order_id:
        return jsonify({"ok": False, "error": "Order ID is required."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Order not found."}), 404

    od = dict(row)
    if email and od["customer_email"].lower() != email.lower():
        conn.close()
        return jsonify({"ok": False, "error": "Order email does not match."}), 403

    curr_status = (od.get("order_status") or "confirmed").lower()
    if curr_status in ("shipped", "out_for_delivery", "delivered", "cancelled"):
        conn.close()
        return jsonify({"ok": False, "error": f"Order cannot be cancelled once it is '{curr_status}'."}), 400

    now_iso = datetime.now().isoformat()
    c.execute("UPDATE orders SET order_status = 'cancelled', updated_at = ? WHERE id = ?", (now_iso, order_id))
    conn.commit()
    conn.close()
    return jsonify({
        "ok": True,
        "order_id": order_id,
        "order_status": "cancelled",
        "message": f"Order {order_id} has been cancelled ({reason})."
    })

@app.route("/api/customer/returns", methods=["POST", "GET"])
def api_customer_returns():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        order_id = str(data.get("order_id", "")).strip()
        email = str(data.get("customer_email", "")).strip().lower()
        phone = str(data.get("customer_phone", "")).strip()
        item_name = str(data.get("item_name", "")).strip()
        action_type = str(data.get("action_type") or data.get("request_type") or "return").strip().lower()
        reason = str(data.get("reason", "")).strip()
        notes = str(data.get("notes") or data.get("details") or "").strip()

        if not order_id or not email or not reason or not item_name:
            return jsonify({"ok": False, "error": "Please provide Order ID, email, item, and return reason."}), 400

        ret_id = f"RET-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
        now_iso = datetime.now().isoformat()

        conn = get_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO return_requests (id, order_id, customer_email, customer_phone, item_name, action_type, reason, notes, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """, (ret_id, order_id, email, phone, item_name, action_type, reason, notes, now_iso, now_iso))
        conn.commit()
        conn.close()

        return jsonify({
            "ok": True,
            "return_id": ret_id,
            "status": "pending",
            "message": f"Your {action_type} request ({ret_id}) has been submitted. Our concierge will review it within 24 hours."
        })

    # GET requests for a customer
    email = request.args.get("email", "").strip().lower()
    user = get_current_user()
    if user:
        email = user["email"]

    if not email:
        return jsonify({"ok": False, "error": "Customer email is required."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM return_requests WHERE LOWER(customer_email) = ? ORDER BY created_at DESC", (email,))
    rows = []
    for r in c.fetchall():
        d = dict(r)
        d["request_type"] = d.get("action_type", "return")
        d["details"] = d.get("notes", "")
        rows.append(d)
    conn.close()
    return jsonify({"ok": True, "returns": rows})

# ================= Order Creation & Payment Verification =================

@app.route("/api/create-order", methods=["POST"])
def api_create_order():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Invalid request body (JSON expected)"}), 400

    cust = data.get("customer", {})
    err = validate_customer_info(cust)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    coupon_code = str(data.get("coupon_code", "")).strip()
    calc, err = validate_and_compute_totals(data.get("items", []), coupon_code)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    cfg = load_config()
    configured = is_razorpay_configured(cfg)
    order_id = generate_order_id()
    amount_paise = calc["total_amount"] * 100
    user = get_current_user()
    user_id = user["id"] if user else None

    if not configured:
        # Development / test mode: create simulated test Razorpay order
        test_rzp_order_id = f"order_test_{os.urandom(6).hex()}"
        now_iso = datetime.now().isoformat()
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO orders (
                id, customer_name, customer_email, customer_phone,
                address_line1, address_line2, city, state, pincode,
                payment_method, payment_status, order_status, razorpay_order_id,
                subtotal, shipping, discount_amount, coupon_code, total_amount, items_json,
                user_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            order_id,
            cust.get("name").strip(),
            cust.get("email").strip(),
            cust.get("phone").strip(),
            cust.get("address_line1").strip(),
            cust.get("address_line2", "").strip(),
            cust.get("city").strip(),
            cust.get("state").strip(),
            cust.get("pincode").strip(),
            "razorpay",
            "pending",
            "confirmed",
            test_rzp_order_id,
            calc["subtotal"],
            calc["shipping"],
            calc["discount"],
            calc["applied_coupon"],
            calc["total_amount"],
            json.dumps(calc["items"]),
            user_id,
            now_iso,
            now_iso
        ))
        conn.commit()
        conn.close()

        return jsonify({
            "ok": True,
            "order_id": order_id,
            "razorpay_order_id": test_rzp_order_id,
            "amount": amount_paise,
            "currency": "INR",
            "key_id": "rzp_test_simulation",
            "is_simulated": True,
            "discount_amount": calc["discount"],
            "coupon_code": calc["applied_coupon"],
            "customer": {
                "name": cust.get("name"),
                "email": cust.get("email"),
                "phone": cust.get("phone")
            }
        })

    # Real Razorpay Order Creation via official API (Secret key remains on server)
    key_id = cfg["razorpay_key_id"].strip()
    key_secret = cfg["razorpay_key_secret"].strip()

    rzp_url = "https://api.razorpay.com/v1/orders"
    payload = {
        "amount": amount_paise,
        "currency": "INR",
        "receipt": order_id,
        "notes": {
            "order_id": order_id,
            "customer_name": cust.get("name"),
            "customer_phone": cust.get("phone"),
            "customer_email": cust.get("email"),
            "coupon_code": calc["applied_coupon"] or ""
        }
    }

    try:
        resp = requests.post(rzp_url, auth=(key_id, key_secret), json=payload, timeout=15)
        if resp.status_code != 200:
            print(f"[Razorpay API Error] HTTP {resp.status_code}: {resp.text}")
            return jsonify({
                "ok": False,
                "error": f"Razorpay API error ({resp.status_code}). Please verify Razorpay keys in config.json."
            }), 400
        rzp_res = resp.json()
        razorpay_order_id = rzp_res.get("id")
    except Exception as e:
        print(f"[Razorpay Network Error]: {e}")
        return jsonify({
            "ok": False,
            "error": "Unable to connect to Razorpay. Please check internet connection."
        }), 502

    now_iso = datetime.now().isoformat()
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO orders (
            id, customer_name, customer_email, customer_phone,
            address_line1, address_line2, city, state, pincode,
            payment_method, payment_status, order_status, razorpay_order_id,
            subtotal, shipping, discount_amount, coupon_code, total_amount, items_json,
            user_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        order_id,
        cust.get("name").strip(),
        cust.get("email").strip(),
        cust.get("phone").strip(),
        cust.get("address_line1").strip(),
        cust.get("address_line2", "").strip(),
        cust.get("city").strip(),
        cust.get("state").strip(),
        cust.get("pincode").strip(),
        "razorpay",
        "pending",
        "confirmed",
        razorpay_order_id,
        calc["subtotal"],
        calc["shipping"],
        calc["discount"],
        calc["applied_coupon"],
        calc["total_amount"],
        json.dumps(calc["items"]),
        user_id,
        now_iso,
        now_iso
    ))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "order_id": order_id,
        "razorpay_order_id": razorpay_order_id,
        "amount": amount_paise,
        "currency": "INR",
        "key_id": key_id,
        "is_simulated": False,
        "discount_amount": calc["discount"],
        "coupon_code": calc["applied_coupon"],
        "customer": {
            "name": cust.get("name"),
            "email": cust.get("email"),
            "phone": cust.get("phone")
        }
    })

@app.route("/api/verify-payment", methods=["POST"])
def api_verify_payment():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Invalid request body (JSON expected)"}), 400

    order_id = str(data.get("order_id", "")).strip()
    rzp_order_id = str(data.get("razorpay_order_id", "")).strip()
    rzp_payment_id = str(data.get("razorpay_payment_id", "")).strip()
    rzp_signature = str(data.get("razorpay_signature", "")).strip()
    is_simulated = bool(data.get("is_simulated", False) or rzp_order_id.startswith("order_test_") or rzp_payment_id.startswith("pay_test_"))

    if not order_id:
        return jsonify({"ok": False, "error": "Missing order ID parameter"}), 400

    if not is_simulated:
        if not (rzp_order_id and rzp_payment_id and rzp_signature):
            return jsonify({"ok": False, "error": "Missing verification parameters"}), 400

        cfg = load_config()
        key_secret = cfg.get("razorpay_key_secret", "").strip()
        if not key_secret or "YOUR_KEY" in key_secret:
            return jsonify({"ok": False, "error": "Server configuration missing valid Razorpay secret key"}), 400

        # Cryptographic HMAC-SHA256 signature verification according to Razorpay specification
        message = f"{rzp_order_id}|{rzp_payment_id}".encode("utf-8")
        expected_signature = hmac.new(key_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_signature, rzp_signature):
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE orders SET payment_status = 'failed', updated_at = ? WHERE id = ? OR razorpay_order_id = ?", (
                datetime.now().isoformat(), order_id, rzp_order_id
            ))
            conn.commit()
            conn.close()
            return jsonify({"ok": False, "error": "Cryptographic payment signature verification failed"}), 400

    # Verification successful -> update order to paid in DB (prevent duplicate coupon count increment)
    now_iso = datetime.now().isoformat()
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT payment_status, coupon_code FROM orders WHERE id = ? OR razorpay_order_id = ?", (order_id, rzp_order_id))
    ord_row = c.fetchone()
    already_paid = ord_row and ord_row["payment_status"] == "paid"

    c.execute("""
        UPDATE orders
        SET payment_status = 'paid',
            order_status = 'confirmed',
            razorpay_payment_id = ?,
            razorpay_signature = ?,
            updated_at = ?
        WHERE id = ? OR razorpay_order_id = ?
    """, (rzp_payment_id or "pay_simulated_success", rzp_signature or "sig_simulated_valid", now_iso, order_id, rzp_order_id))

    if not already_paid and ord_row and ord_row["coupon_code"]:
        c.execute("UPDATE coupons SET used_count = used_count + 1 WHERE code = ?", (ord_row["coupon_code"],))

    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "order_id": order_id,
        "payment_id": rzp_payment_id or "pay_simulated_success",
        "status": "paid"
    })

@app.route("/api/create-cod-order", methods=["POST"])
def api_create_cod_order():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Invalid request body (JSON expected)"}), 400

    cfg = load_config()
    if not cfg.get("cod_enabled", True):
        return jsonify({"ok": False, "error": "Cash on Delivery is currently disabled. Please use online payment."}), 400

    cust = data.get("customer", {})
    err = validate_customer_info(cust)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    coupon_code = str(data.get("coupon_code", "")).strip()
    calc, err = validate_and_compute_totals(data.get("items", []), coupon_code)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    order_id = generate_order_id()
    now_iso = datetime.now().isoformat()
    user = get_current_user()
    user_id = user["id"] if user else None

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO orders (
            id, customer_name, customer_email, customer_phone,
            address_line1, address_line2, city, state, pincode,
            payment_method, payment_status, order_status,
            subtotal, shipping, discount_amount, coupon_code, total_amount, items_json,
            user_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        order_id,
        cust.get("name").strip(),
        cust.get("email").strip(),
        cust.get("phone").strip(),
        cust.get("address_line1").strip(),
        cust.get("address_line2", "").strip(),
        cust.get("city").strip(),
        cust.get("state").strip(),
        cust.get("pincode").strip(),
        "cod",
        "cod_confirmed",
        "confirmed",
        calc["subtotal"],
        calc["shipping"],
        calc["discount"],
        calc["applied_coupon"],
        calc["total_amount"],
        json.dumps(calc["items"]),
        user_id,
        now_iso,
        now_iso
    ))

    if calc["applied_coupon"]:
        c.execute("UPDATE coupons SET used_count = used_count + 1 WHERE code = ?", (calc["applied_coupon"],))

    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "order_id": order_id,
        "status": "cod_confirmed",
        "discount_amount": calc["discount"],
        "total_amount": calc["total_amount"]
    })

@app.route("/api/order-details", methods=["GET"])
def api_order_details():
    order_id = request.args.get("order_id", "").strip()
    if not order_id:
        return jsonify({"ok": False, "error": "Order ID is required"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT id, customer_name, customer_email, customer_phone,
               address_line1, address_line2, city, state, pincode,
               payment_method, payment_status, order_status, tracking_number, courier_partner,
               razorpay_payment_id, subtotal, shipping, discount_amount, coupon_code,
               total_amount, items_json, created_at, updated_at
        FROM orders WHERE id = ? OR razorpay_order_id = ?
    """, (order_id, order_id))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": f"Order not found: {order_id}"}), 404

    order_dict = dict(row)
    order_dict["items"] = json.loads(order_dict.pop("items_json", "[]"))
    return jsonify({"ok": True, "order": order_dict})

# ================= Protected Administrative APIs =================

@app.route("/api/admin/verify", methods=["POST"])
def api_admin_verify():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Invalid admin passkey"}), 401
    return jsonify({"ok": True, "message": "Admin authenticated successfully."})

@app.route("/api/admin/stats", methods=["GET"])
def api_admin_stats():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) AS total_orders, COALESCE(SUM(total_amount), 0) AS total_revenue FROM orders WHERE order_status != 'cancelled'")
    totals = dict(c.fetchone())

    c.execute("SELECT COUNT(*) AS paid_orders, COALESCE(SUM(total_amount), 0) AS verified_paid_revenue FROM orders WHERE payment_status = 'paid' AND order_status != 'cancelled'")
    paid_row = dict(c.fetchone())
    totals["paid_orders"] = paid_row["paid_orders"]
    totals["paid_count"] = paid_row["paid_orders"]
    totals["verified_paid_revenue"] = paid_row["verified_paid_revenue"]
    totals["paid_revenue"] = totals["total_revenue"]

    c.execute("SELECT COUNT(*) AS cod_orders FROM orders WHERE payment_method = 'cod' AND order_status != 'cancelled'")
    cod_cnt = c.fetchone()["cod_orders"]
    totals["cod_orders"] = cod_cnt
    totals["cod_count"] = cod_cnt

    c.execute("SELECT COUNT(*) AS pending_returns FROM return_requests WHERE status = 'pending'")
    totals["pending_returns"] = c.fetchone()["pending_returns"]

    c.execute("SELECT COUNT(*) AS total_products FROM products WHERE is_archived = 0")
    prod_cnt = c.fetchone()["total_products"]
    totals["total_products"] = prod_cnt
    totals["active_products"] = prod_cnt

    c.execute("SELECT COUNT(*) AS total_users FROM users")
    totals["total_users"] = c.fetchone()["total_users"]

    # Recent orders
    c.execute("SELECT id, customer_name, total_amount, payment_status, order_status, created_at FROM orders ORDER BY created_at DESC LIMIT 10")
    recent_orders = [dict(r) for r in c.fetchall()]

    conn.close()
    return jsonify({"ok": True, "stats": totals, "recent_orders": recent_orders})

@app.route("/api/admin/orders", methods=["GET"])
def api_admin_orders():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    status = request.args.get("status", "").strip()
    search = request.args.get("search", "").strip().lower()

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM orders ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()

    orders = []
    for r in rows:
        od = dict(r)
        od["order_id"] = od["id"]
        od["items"] = json.loads(od.pop("items_json", "[]"))
        if status and od.get("order_status") != status:
            continue
        if search:
            q = f"{od['id']} {od['customer_name']} {od['customer_phone']} {od['customer_email']}".lower()
            if search not in q:
                continue
        orders.append(od)

    return jsonify({"ok": True, "count": len(orders), "orders": orders})

@app.route("/api/admin/orders/status", methods=["POST"])
def api_admin_order_status():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    order_id = str(data.get("order_id", "")).strip()
    new_status = str(data.get("order_status", "")).strip()
    tracking_no = str(data.get("tracking_number", "")).strip()
    courier = str(data.get("courier_partner", "")).strip()

    if not order_id or not new_status:
        return jsonify({"ok": False, "error": "Order ID and status required."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        UPDATE orders
        SET order_status = ?,
            tracking_number = COALESCE(NULLIF(?, ''), tracking_number),
            courier_partner = COALESCE(NULLIF(?, ''), courier_partner),
            updated_at = ?
        WHERE id = ?
    """, (new_status, tracking_no, courier, datetime.now().isoformat(), order_id))
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "message": f"Order {order_id} updated to '{new_status}'."})

@app.route("/api/admin/products", methods=["POST"])
def api_admin_product_save():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    p = request.get_json(silent=True) or {}
    pid = str(p.get("id", "")).strip() or f"prod_{secrets.token_hex(4)}"

    existing = get_product_from_db(pid)
    name = str(p.get("name", existing["name"] if existing else "")).strip()
    category = str(p.get("category", existing["category"] if existing else "Straight")).strip()
    style = str(p.get("style", existing.get("style", "") if existing else "")).strip()
    price = int(p.get("price", existing["price"] if existing else 0))
    mrp = int(p.get("mrp", existing["mrp"] if existing else price))
    desc = str(p.get("description", existing.get("description", "") if existing else "")).strip()
    fabric = str(p.get("fabric", existing.get("fabric", "") if existing else "")).strip()
    occasion = str(p.get("occasion", existing.get("occasion", "") if existing else "")).strip()
    pattern = str(p.get("pattern", existing.get("pattern", "") if existing else "")).strip()
    sleeve_length = str(p.get("sleeve_length", existing.get("sleeve_length", "") if existing else "")).strip()
    neck_design = str(p.get("neck_design", existing.get("neck_design", "") if existing else "")).strip()
    care = str(p.get("care", existing.get("care", "") if existing else "")).strip()

    raw_img = str(p.get("image", existing["image"] if existing else "assets/hero.jpg")).strip()
    # Ensure non-existent test placeholder like assets/k-straight.jpg falls back to existing or assets/hero.jpg
    if raw_img and not raw_img.startswith("http"):
        check_path = os.path.join(BASE_DIR, raw_img.lstrip("/"))
        if not os.path.isfile(check_path):
            raw_img = existing["image"] if (existing and os.path.isfile(os.path.join(BASE_DIR, existing["image"].lstrip("/")))) else "assets/hero.jpg"
    image = raw_img or "assets/hero.jpg"
    rel_img = str(p.get("relative_image", image)).strip()

    stock = int(p.get("stock", existing["stock"] if existing else 50))
    is_feat = int(bool(p.get("is_featured", existing.get("is_featured", 0) if existing else 0)))
    is_new = int(bool(p.get("is_new", existing.get("is_new", 0) if existing else 0)))
    is_best = int(bool(p.get("is_bestseller", existing.get("is_bestseller", 0) if existing else 0)))
    is_arch = int(bool(p.get("is_archived", existing.get("is_archived", 0) if existing else 0)))

    gallery = json.dumps(p["gallery"]) if "gallery" in p else (existing["gallery_json"] if existing else json.dumps([image]))
    colors = json.dumps(p["colors"]) if "colors" in p else (existing["colors_json"] if existing else json.dumps([{"name": "Maroon", "swatch": "#6B2D31"}]))
    sizes = json.dumps(p["sizes"]) if "sizes" in p else (existing["sizes_json"] if existing else json.dumps(["XS", "S", "M", "L", "XL", "XXL"]))
    sold_out = json.dumps(p["soldOutSizes"]) if "soldOutSizes" in p else (existing["sold_out_sizes_json"] if existing else json.dumps([]))

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO products (
            id, name, category, style, price, mrp, description, fabric,
            occasion, pattern, sleeve_length, neck_design, care,
            image, relative_image, gallery_json, colors_json, sizes_json,
            sold_out_sizes_json, stock, is_featured, is_new, is_bestseller, is_archived, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            category=excluded.category,
            style=excluded.style,
            price=excluded.price,
            mrp=excluded.mrp,
            description=excluded.description,
            fabric=excluded.fabric,
            occasion=excluded.occasion,
            pattern=excluded.pattern,
            sleeve_length=excluded.sleeve_length,
            neck_design=excluded.neck_design,
            care=excluded.care,
            image=excluded.image,
            relative_image=excluded.relative_image,
            gallery_json=excluded.gallery_json,
            colors_json=excluded.colors_json,
            sizes_json=excluded.sizes_json,
            sold_out_sizes_json=excluded.sold_out_sizes_json,
            stock=excluded.stock,
            is_featured=excluded.is_featured,
            is_new=excluded.is_new,
            is_bestseller=excluded.is_bestseller,
            is_archived=excluded.is_archived
    """, (
        pid, name, category, style, price, mrp, desc, fabric,
        occasion, pattern, sleeve_length, neck_design, care,
        image, rel_img, gallery, colors, sizes,
        sold_out, stock, is_feat, is_new, is_best, is_arch, datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "message": f"Product '{name}' saved successfully.", "id": pid})

@app.route("/api/admin/products/<pid>", methods=["DELETE"])
def api_admin_product_delete(pid):
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM products WHERE id = ?", (pid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"Product {pid} deleted."})

@app.route("/api/admin/coupons", methods=["GET", "POST"])
def api_admin_coupons():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        code = str(data.get("code", "")).strip().upper()
        dtype = str(data.get("discount_type", "percentage")).strip()
        val = int(data.get("discount_value", 10))
        min_ord = int(data.get("min_order_value", 0))
        max_disc = int(data.get("max_discount", 0))
        start_dt = str(data.get("start_date", "")).strip()
        exp = str(data.get("expiry_date", "2028-12-31")).strip()
        limit = int(data.get("usage_limit", 1000))
        app_cats = str(data.get("applicable_categories", "")).strip()
        app_prods = str(data.get("applicable_products", "")).strip()
        is_auto = 1 if data.get("is_auto_apply") else 0
        desc = str(data.get("description", "")).strip()

        if not code or val <= 0:
            conn.close()
            return jsonify({"ok": False, "error": "Valid code and discount value required."}), 400

        c.execute("""
            INSERT INTO coupons (
                code, discount_type, discount_value, min_order_value, max_discount,
                start_date, expiry_date, usage_limit, applicable_categories,
                applicable_products, is_auto_apply, is_active, description, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(code) DO UPDATE SET
                discount_type=excluded.discount_type,
                discount_value=excluded.discount_value,
                min_order_value=excluded.min_order_value,
                max_discount=excluded.max_discount,
                start_date=excluded.start_date,
                expiry_date=excluded.expiry_date,
                usage_limit=excluded.usage_limit,
                applicable_categories=excluded.applicable_categories,
                applicable_products=excluded.applicable_products,
                is_auto_apply=excluded.is_auto_apply,
                description=excluded.description
        """, (code, dtype, val, min_ord, max_disc, start_dt, exp, limit, app_cats, app_prods, is_auto, desc, datetime.now().isoformat()))
        conn.commit()

    c.execute("SELECT * FROM coupons ORDER BY created_at DESC")
    rows = []
    for r in c.fetchall():
        d = dict(r)
        d["times_used"] = d.get("used_count", 0)
        rows.append(d)
    conn.close()
    return jsonify({"ok": True, "coupons": rows})

@app.route("/api/admin/coupons/toggle", methods=["POST"])
def api_admin_coupon_toggle():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip().upper()
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE coupons SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE code = ?", (code,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"Coupon {code} status toggled."})

@app.route("/api/admin/settings", methods=["GET", "POST"])
def api_admin_settings():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        if "announcement_text" in data and "announcements" not in data:
            txt = str(data["announcement_text"]).strip()
            data["announcements"] = [x.strip() for x in txt.split("|") if x.strip()] if txt else DEFAULT_ANNOUNCEMENTS
        if "standard_shipping_fee" in data and "shipping_fee" not in data:
            data["shipping_fee"] = data["standard_shipping_fee"]
        for k, v in data.items():
            val_str = json.dumps(v) if isinstance(v, (list, dict)) else str(v)
            c.execute("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)", (k, val_str))
        conn.commit()

    c.execute("SELECT key, value FROM site_settings")
    rows = c.fetchall()
    conn.close()

    settings = {}
    for r in rows:
        val = r["value"]
        try:
            settings[r["key"]] = json.loads(val)
        except Exception:
            settings[r["key"]] = val

    if "announcements" in settings and isinstance(settings["announcements"], list) and "announcement_text" not in settings:
        settings["announcement_text"] = " | ".join(settings["announcements"])
    if "shipping_fee" in settings and "standard_shipping_fee" not in settings:
        settings["standard_shipping_fee"] = settings["shipping_fee"]

    return jsonify({"ok": True, "settings": settings})

@app.route("/api/admin/returns", methods=["GET"])
def api_admin_returns():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM return_requests ORDER BY created_at DESC")
    rows = []
    for r in c.fetchall():
        d = dict(r)
        d["request_type"] = d.get("action_type", "return")
        d["details"] = d.get("notes", "")
        rows.append(d)
    conn.close()
    return jsonify({"ok": True, "returns": rows})

@app.route("/api/admin/returns/status", methods=["POST"])
def api_admin_return_status():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    ret_id = str(data.get("return_id", "")).strip()
    status = str(data.get("status", "")).strip().lower()
    notes = str(data.get("notes", "")).strip()

    if not ret_id or not status:
        return jsonify({"ok": False, "error": "Return ID and status required."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        UPDATE return_requests
        SET status = ?,
            notes = COALESCE(NULLIF(?, ''), notes),
            updated_at = ?
        WHERE id = ?
    """, (status, notes, datetime.now().isoformat(), ret_id))
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "message": f"Return request {ret_id} updated to '{status}'."})

# ================= Static Assets & HTML Routing =================

FORBIDDEN_FILES = {
    "config.json", "server.py", "test_checkout_flow.py", ".env",
    "Procfile", "requirements.txt", "runtime.txt", "Dockerfile", ".gitignore"
}
FORBIDDEN_EXTS = (".db", ".sqlite", ".sqlite3", ".py", ".env", ".log", ".bak", ".sh")
FORBIDDEN_DIRS = {"data", ".git", ".system_generated", "scratch"}
ASSET_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".svg", ".ico", ".css", ".js", ".woff", ".woff2", ".ttf", ".json", ".map")

@app.route("/favicon.ico")
def serve_favicon():
    return send_from_directory(BASE_DIR, "favicon.png", mimetype="image/png")

@app.route("/")
def serve_index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/<path:filename>")
def serve_static_file(filename):
    clean = filename.strip("/")
    parts = clean.split("/")
    base_name = os.path.basename(clean)

    # Security check: prevent directory traversal and sensitive server file downloads
    if (
        base_name in FORBIDDEN_FILES or
        any(part in FORBIDDEN_DIRS for part in parts) or
        any(clean.endswith(ext) for ext in FORBIDDEN_EXTS)
    ):
        return jsonify({"ok": False, "error": "Not Found"}), 404

    target = os.path.join(BASE_DIR, clean)

    # 1. If a root .html file exists for this route (e.g., /shop, /shop/, /cart, /checkout, /story, /contact, /order-confirmation),
    # ALWAYS serve the modern root .html file first so stale legacy subdirectories never shadow the latest storefront!
    if os.path.isfile(target + ".html"):
        return send_from_directory(BASE_DIR, clean + ".html")

    # Also handle /shop/index.html -> /shop.html if root page exists
    if len(parts) == 2 and parts[1] == "index.html":
        root_html = os.path.join(BASE_DIR, parts[0] + ".html")
        if os.path.isfile(root_html):
            return send_from_directory(BASE_DIR, parts[0] + ".html")

    # 2. Direct file match (e.g. index.html, shop.html, assets/app.js, assets/styles.css, assets/hero.jpg)
    if os.path.isfile(target):
        return send_from_directory(BASE_DIR, clean)

    # 3. Directory match with index.html fallback if no root .html exists
    if os.path.isdir(target):
        sub_index = os.path.join(target, "index.html")
        if os.path.isfile(sub_index):
            return send_from_directory(target, "index.html")

    # 4. If a static asset (.jpg, .png, .css, .js) is missing, return 404 instead of index.html
    if any(clean.lower().endswith(ext) for ext in ASSET_EXTS):
        return jsonify({"ok": False, "error": f"Asset not found: {clean}"}), 404

    return send_from_directory(BASE_DIR, "index.html")

def main():
    init_db()
    print("=" * 60)
    print(f" Matra Naari E-Commerce Platform Server running on port {PORT}")
    print(f" Storefront: http://localhost:{PORT}")
    print(f" API Base URL: http://localhost:{PORT}/api")
    print(f" Admin Dashboard: http://localhost:{PORT}/admin.html")
    print(f" Database: {DB_PATH}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=PORT, debug=False)

if __name__ == "__main__":
    main()
