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
import errno
import re
import time
import math
import threading
import json
import sqlite3
import hmac
import hashlib
import secrets
import base64
import urllib.parse
import requests
from datetime import datetime, timedelta
from flask import Flask, Response, request, jsonify, send_from_directory, g
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge

try:
    import psycopg2
    import psycopg2.extras
    DB_OPERATIONAL_ERRORS = (sqlite3.OperationalError, psycopg2.OperationalError)
    DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError, psycopg2.IntegrityError)
except ImportError:
    psycopg2 = None
    DB_OPERATIONAL_ERRORS = (sqlite3.OperationalError,)
    DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError,)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
DB_PATH = os.environ.get("DB_PATH", os.path.join(DATA_DIR, "orders.db"))
DATABASE_URL = (os.environ.get("DATABASE_URL") or "").strip()
POSTGRES_SCHEMA = (os.environ.get("POSTGRES_SCHEMA") or "").strip()
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(DATA_DIR, "uploads"))
LEGACY_UPLOAD_DIR = os.path.join(BASE_DIR, "assets", "uploads")
MAX_UPLOAD_FILE_BYTES = 5 * 1024 * 1024  # 5 MiB per uploaded image file
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 6 * 1024 * 1024))  # 6 MiB HTTP request limit
CONFIG_PATH = os.environ.get("CONFIG_PATH", os.path.join(BASE_DIR, "config.json"))
PORT = int(os.environ.get("PORT", 8000))
ADMIN_SECRET_KEY = os.environ.get("ADMIN_SECRET_KEY", "")

_INITIAL_DATA_DIR = DATA_DIR
_INITIAL_DB_PATH = DB_PATH
_INITIAL_DATABASE_URL = DATABASE_URL
_INITIAL_POSTGRES_SCHEMA = POSTGRES_SCHEMA
_INITIAL_UPLOAD_DIR = UPLOAD_DIR
_POSTGRES_CONNECT_FN = None

SUPABASE_PROJECT_ID = os.environ.get("SUPABASE_PROJECT_ID", "hbpjvtoezlcsyxdxyvna")
SUPABASE_STORAGE_BUCKET = os.environ.get("SUPABASE_STORAGE_BUCKET", "product-images")
_SUPABASE_STORAGE_BACKEND = None


def detect_image_magic_and_mime(raw_bytes):
    """
    Inspects raw file bytes and returns (mime_type, allowed_extensions, canonical_ext)
    for valid JPEG, PNG, or WebP images, or (None, (), None) otherwise.
    """
    if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) < 12:
        return None, (), None
    if raw_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", (".jpg", ".jpeg"), ".jpg"
    if raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", (".png",), ".png"
    if raw_bytes[:4] == b"RIFF" and raw_bytes[8:12] == b"WEBP":
        return "image/webp", (".webp",), ".webp"
    return None, (), None


def _read_dotenv_key(key_name):
    dotenv_path = os.path.join(BASE_DIR, ".env")
    if os.path.isfile(dotenv_path):
        try:
            with open(dotenv_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    if k.strip() == key_name:
                        val = v.strip().strip('"').strip("'")
                        if val:
                            return val
        except Exception:
            pass
    return ""


def get_supabase_storage_config():
    """
    Returns server-only Supabase Storage configuration.
    Never exposes the service role key to client APIs or browser responses.
    """
    service_key = (
        os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or os.environ.get("SUPABASE_SERVICE_KEY")
        or _read_dotenv_key("SUPABASE_SERVICE_ROLE_KEY")
        or _read_dotenv_key("SUPABASE_SERVICE_KEY")
        or ""
    ).strip().strip('"').strip("'")
    proj_id = (
        os.environ.get("SUPABASE_PROJECT_ID")
        or _read_dotenv_key("SUPABASE_PROJECT_ID")
        or SUPABASE_PROJECT_ID
    ).strip()
    base_url = (
        os.environ.get("SUPABASE_URL")
        or _read_dotenv_key("SUPABASE_URL")
        or f"https://{proj_id}.supabase.co"
    ).strip().rstrip("/")
    bucket = (
        os.environ.get("SUPABASE_STORAGE_BUCKET")
        or _read_dotenv_key("SUPABASE_STORAGE_BUCKET")
        or SUPABASE_STORAGE_BUCKET
    ).strip()
    enabled = bool(_SUPABASE_STORAGE_BACKEND is not None or (service_key and base_url and bucket))
    return {
        "enabled": enabled,
        "base_url": base_url,
        "bucket": bucket,
        "service_role_key": service_key,
    }


def _is_safe_upload_filename(fname):
    clean = str(fname or "").strip()
    return (
        bool(clean)
        and os.path.basename(clean) == clean
        and ".." not in clean
        and "/" not in clean
        and "\\" not in clean
        and not clean.startswith(".")
        and any(clean.lower().endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".webp"))
    )


def _supabase_storage_upload(fname, raw_bytes, content_type):
    if not _is_safe_upload_filename(fname):
        raise ValueError("Invalid upload filename.")
    cfg = get_supabase_storage_config()
    if not cfg["enabled"]:
        return False
    object_key = f"uploads/{fname}"
    if _SUPABASE_STORAGE_BACKEND is not None:
        ok = _SUPABASE_STORAGE_BACKEND.upload(cfg["bucket"], object_key, bytes(raw_bytes), content_type)
        if not ok:
            raise RuntimeError("Supabase Storage backend rejected the upload.")
        return True
    url = f"{cfg['base_url']}/storage/v1/object/{cfg['bucket']}/{object_key}"
    headers = {
        "Authorization": f"Bearer {cfg['service_role_key']}",
        "apikey": cfg["service_role_key"],
        "Content-Type": content_type,
        "x-upsert": "true",
        "Cache-Control": "86400",
    }
    resp = requests.post(url, headers=headers, data=bytes(raw_bytes), timeout=15)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Supabase Storage upload failed with HTTP {resp.status_code}.")
    return True


def _supabase_storage_download(fname):
    if not _is_safe_upload_filename(fname):
        return None, None
    cfg = get_supabase_storage_config()
    if not cfg["enabled"] and _SUPABASE_STORAGE_BACKEND is None:
        return None, None
    object_key = f"uploads/{fname}"
    if _SUPABASE_STORAGE_BACKEND is not None:
        res = _SUPABASE_STORAGE_BACKEND.download(cfg["bucket"], object_key)
        if not res:
            return None, None
        raw_bytes, _ = res if isinstance(res, tuple) else (res, None)
        mime_type, _, _ = detect_image_magic_and_mime(raw_bytes)
        if not mime_type or len(raw_bytes) > MAX_UPLOAD_FILE_BYTES:
            return None, None
        return bytes(raw_bytes), mime_type
    url = f"{cfg['base_url']}/storage/v1/object/public/{cfg['bucket']}/{object_key}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200 or not resp.content:
            return None, None
        if len(resp.content) > MAX_UPLOAD_FILE_BYTES:
            return None, None
        mime_type, _, _ = detect_image_magic_and_mime(resp.content)
        if not mime_type:
            return None, None
        return resp.content, mime_type
    except Exception:
        return None, None


def _supabase_storage_exists(fname):
    if not _is_safe_upload_filename(fname):
        return False
    cfg = get_supabase_storage_config()
    if not cfg["enabled"] and _SUPABASE_STORAGE_BACKEND is None:
        return False
    object_key = f"uploads/{fname}"
    if _SUPABASE_STORAGE_BACKEND is not None:
        if hasattr(_SUPABASE_STORAGE_BACKEND, "exists"):
            return bool(_SUPABASE_STORAGE_BACKEND.exists(cfg["bucket"], object_key))
        raw_bytes, _ = _supabase_storage_download(fname)
        return raw_bytes is not None
    raw_bytes, _ = _supabase_storage_download(fname)
    return raw_bytes is not None


def get_upload_dir():
    if UPLOAD_DIR != _INITIAL_UPLOAD_DIR:
        return os.path.abspath(UPLOAD_DIR)
    env_upload = (os.environ.get("UPLOAD_DIR") or "").strip()
    if env_upload:
        return os.path.abspath(env_upload)
    if DATA_DIR != _INITIAL_DATA_DIR:
        return os.path.abspath(os.path.join(DATA_DIR, "uploads"))
    return os.path.abspath(UPLOAD_DIR)


def ensure_upload_dir():
    up_dir = get_upload_dir()
    os.makedirs(up_dir, exist_ok=True)
    return os.path.realpath(up_dir)


def _public_asset_file_exists(rel_path):
    clean = str(rel_path or "").strip().lstrip("/")
    if not clean or ".." in clean or "\\" in clean:
        return False
    parts = [p for p in clean.split("/") if p]
    if len(parts) < 2 or parts[0] not in ("assets", "images") or any(p.startswith(".") for p in parts):
        return False
    if parts[0] == "assets" and parts[1] == "uploads":
        if len(parts) != 3:
            return False
        fname = parts[2]
        if (
            os.path.basename(fname) == fname
            and ".." not in fname
            and any(fname.lower().endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".webp"))
        ):
            up_dir = os.path.realpath(get_upload_dir())
            up_cand = os.path.realpath(os.path.join(up_dir, fname))
            if up_cand.startswith(up_dir + os.sep) and os.path.isfile(up_cand):
                return True
            leg_dir = os.path.realpath(LEGACY_UPLOAD_DIR)
            leg_cand = os.path.realpath(os.path.join(leg_dir, fname))
            if leg_cand.startswith(leg_dir + os.sep) and os.path.isfile(leg_cand):
                return True
            if _supabase_storage_exists(fname):
                return True
        return False
    if not any(clean.lower().endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".webp", ".gif", ".svg", ".ico")):
        return False
    base_abs = os.path.realpath(BASE_DIR)
    cand_abs = os.path.realpath(os.path.join(BASE_DIR, clean))
    return cand_abs.startswith(base_abs + os.sep) and os.path.isfile(cand_abs)

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

SQLITE_TIMEOUT_SECONDS = 15.0
SQLITE_BUSY_TIMEOUT_MS = 15000
_INIT_DB_LOCK = threading.RLock()


def _configure_sqlite_connection(conn):
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    journal_mode_env = os.environ.get("SQLITE_JOURNAL_MODE", "").strip().upper()
    if journal_mode_env in ("WAL", "DELETE", "TRUNCATE", "PERSIST", "MEMORY"):
        try:
            conn.execute(f"PRAGMA journal_mode = {journal_mode_env}")
        except sqlite3.OperationalError:
            pass
    return conn


def get_site_settings_dict():
    settings = {}
    conn = None
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT key, value FROM site_settings")
        for r in c.fetchall():
            val = r["value"]
            try:
                settings[r["key"]] = json.loads(val)
            except Exception:
                settings[r["key"]] = val
    except Exception:
        pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return settings

def load_config():
    config = {
        "razorpay_key_id": "",
        "razorpay_key_secret": "",
        "google_maps_api_key": "",
        "google_maps_map_id": "",
        "google_maps_daily_quota_limit": 1000,
        "google_maps_session_Request_limit": 25,
        "currency": "INR",
        "store_name": "Matra Naari",
        "store_description": "Modern Kurtis Rooted in Craft",
        "support_phone": "+91 88493 66915",
        "support_email": "hello@naari.in",
        "free_shipping_threshold": 999,
        "shipping_fee": 99,
        "cod_enabled": True,
        "sales_enabled": True,
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
        config["cod_enabled"] = bool(val) if isinstance(val, bool) else str(val).strip().lower() in ("true", "1", "yes")
        config["sales_enabled"] = config["cod_enabled"]
    if "sales_enabled" in db_settings:
        val = db_settings["sales_enabled"]
        config["sales_enabled"] = bool(val) if isinstance(val, bool) else str(val).strip().lower() in ("true", "1", "yes")
    env_sales = os.environ.get("SALES_ENABLED")
    if env_sales is not None and env_sales.strip():
        config["sales_enabled"] = env_sales.strip().strip('"').strip("'").lower() in ("true", "1", "yes")
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
    if "google_maps_api_key" in db_settings and str(db_settings["google_maps_api_key"]).strip():
        config["google_maps_api_key"] = str(db_settings["google_maps_api_key"]).strip()
    if "google_maps_map_id" in db_settings and str(db_settings["google_maps_map_id"]).strip():
        config["google_maps_map_id"] = str(db_settings["google_maps_map_id"]).strip()

    env_mappings = {
        "RAZORPAY_KEY": "razorpay_key_id",
        "RAZORPAY_API_KEY": "razorpay_key_id",
        "RZP_KEY_ID": "razorpay_key_id",
        "RAZORPAY_KEY_ID": "razorpay_key_id",
        "RAZORPAY_SECRET": "razorpay_key_secret",
        "RAZORPAY_API_SECRET": "razorpay_key_secret",
        "RZP_KEY_SECRET": "razorpay_key_secret",
        "RAZORPAY_KEY_SECRET": "razorpay_key_secret",
        "GOOGLE_MAPS_API_KEY": "google_maps_api_key",
        "GOOGLE_MAPS_BROWSER_KEY": "google_maps_api_key",
        "GOOGLE_PLACES_API_KEY": "google_maps_api_key",
        "GOOGLE_MAPS_MAP_ID": "google_maps_map_id",
        "CURRENCY": "currency",
        "STORE_NAME": "store_name",
        "STORE_DESCRIPTION": "store_description",
        "SUPPORT_PHONE": "support_phone",
        "SUPPORT_EMAIL": "support_email",
        "ADMIN_SECRET_KEY": "admin_secret_key",
        "ADMIN_PASSKEY": "admin_secret_key",
        "ADMIN_PASSWORD": "admin_secret_key"
    }
    # Optional local .env file support (never overrides process environment variables)
    dotenv_path = os.path.join(BASE_DIR, ".env")
    if os.path.isfile(dotenv_path):
        try:
            with open(dotenv_path, "r", encoding="utf-8") as ef:
                for raw_line in ef:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k in env_mappings and k not in os.environ and v:
                        config[env_mappings[k]] = v
        except Exception:
            pass

    for env_var, cfg_key in env_mappings.items():
        val = os.environ.get(env_var)
        if val is not None and val.strip():
            config[cfg_key] = val.strip().strip('"').strip("'")

    return config

def is_google_maps_configured(cfg):
    key = str(cfg.get("google_maps_api_key") or "").strip()
    if not key or len(key) < 20:
        return False
    upper_key = key.upper()
    if any(tok in upper_key for tok in ("YOUR_", "PLACEHOLDER", "CHANGE_ME", "EXAMPLE")):
        return False
    return True

def is_razorpay_configured(cfg):
    key_id = cfg.get("razorpay_key_id", "").strip()
    key_secret = cfg.get("razorpay_key_secret", "").strip()
    if not key_id or not key_secret:
        return False
    if "YOUR_KEY" in key_id or "YOUR_KEY" in key_secret:
        return False
    if key_id == "rzp_test_simulation":
        return False
    return True

def mask_key_id(key_id):
    k = (key_id or "").strip()
    if not k:
        return "<missing>"
    if len(k) <= 12:
        return k[:4] + "****"
    return k[:12] + "****"


def mask_database_url(db_url):
    """Masks credentials in a PostgreSQL connection URL so secrets are never printed."""
    raw = str(db_url or "").strip()
    if not raw:
        return "<empty>"
    try:
        parsed = urllib.parse.urlsplit(raw)
        if not parsed.scheme or not parsed.hostname:
            return "<masked-db-url>"
        host_part = parsed.hostname
        if parsed.port:
            host_part = f"{host_part}:{parsed.port}"
        user_part = "***:***@" if (parsed.username or parsed.password) else ""
        path_part = parsed.path or "/postgres"
        return f"{parsed.scheme}://{user_part}{host_part}{path_part}"
    except Exception:
        return "<masked-db-url>"


def is_postgres_url(db_url):
    u = str(db_url or "").strip().lower()
    return u.startswith("postgres://") or u.startswith("postgresql://")


def get_database_url():
    """
    Returns the active PostgreSQL DATABASE_URL when configured, or "" when running in
    SQLite mode. If a test overrides server.DB_PATH to a custom temporary SQLite file
    without explicitly setting server.DATABASE_URL or FORCE_POSTGRES_ADAPTER=1, SQLite
    mode is preserved automatically for that test.
    """
    if DATABASE_URL != _INITIAL_DATABASE_URL:
        return str(DATABASE_URL or "").strip()
    if DB_PATH != _INITIAL_DB_PATH and os.environ.get("FORCE_POSTGRES_ADAPTER") != "1":
        return ""
    env_url = (os.environ.get("DATABASE_URL") or "").strip()
    if env_url:
        return env_url
    return str(DATABASE_URL or "").strip()


def is_postgres_mode():
    return is_postgres_url(get_database_url())


def get_postgres_schema():
    """
    Returns a validated PostgreSQL schema identifier when POSTGRES_SCHEMA is configured
    (e.g. a disposable integration-test schema), or 'public' by default.
    """
    raw = str(POSTGRES_SCHEMA if POSTGRES_SCHEMA != _INITIAL_POSTGRES_SCHEMA else (os.environ.get("POSTGRES_SCHEMA") or POSTGRES_SCHEMA or "")).strip()
    if not raw:
        return "public"
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$", raw):
        raise ValueError("Invalid PostgreSQL schema identifier.")
    return raw


def _for_update_clause(cursor_or_conn=None):
    """
    Returns ' FOR UPDATE' when executing on PostgreSQL so row-level pessimistic locks
    are acquired inside critical stock/order/return transactions, or '' on SQLite
    (where BEGIN IMMEDIATE already acquires a database-level write lock).
    """
    if cursor_or_conn is not None:
        if getattr(cursor_or_conn, "is_postgres", False):
            return " FOR UPDATE"
        return ""
    return " FOR UPDATE" if is_postgres_mode() else ""


def translate_sql_for_postgres(sql, has_params=True):
    """
    Translates SQLite-flavored SQL statements to PostgreSQL-compatible SQL:
    1. Normalizes BEGIN IMMEDIATE / BEGIN EXCLUSIVE -> BEGIN.
    2. Converts legacy INSERT OR IGNORE INTO <table> (...) VALUES (...) ->
       INSERT INTO <table> (...) VALUES (...) ON CONFLICT DO NOTHING.
    3. Converts qmark (?) parameter placeholders outside string literals to %s,
       and escapes any literal % characters as %% when parameters are bound.
    """
    raw_sql = str(sql or "")
    stripped = raw_sql.strip()
    upper_clean = stripped.rstrip(";").strip().upper()

    if upper_clean in ("BEGIN IMMEDIATE", "BEGIN EXCLUSIVE"):
        return "BEGIN"

    work_sql = raw_sql
    append_conflict_nothing = False
    if re.match(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\b", work_sql, flags=re.IGNORECASE):
        work_sql = re.sub(
            r"^(\s*)INSERT\s+OR\s+IGNORE\s+INTO\b",
            r"\1INSERT INTO",
            work_sql,
            count=1,
            flags=re.IGNORECASE,
        )
        if "ON CONFLICT" not in work_sql.upper():
            append_conflict_nothing = True

    out = []
    in_single = False
    in_double = False
    i = 0
    n = len(work_sql)
    while i < n:
        ch = work_sql[i]
        if ch == "'" and not in_double:
            out.append(ch)
            if in_single and i + 1 < n and work_sql[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            in_single = not in_single
        elif ch == '"' and not in_single:
            out.append(ch)
            if in_double and i + 1 < n and work_sql[i + 1] == '"':
                out.append('"')
                i += 2
                continue
            in_double = not in_double
        elif not in_single and not in_double and ch == "?":
            out.append("%s")
        elif has_params and ch == "%":
            if i + 1 < n and work_sql[i + 1] in ("s", "%"):
                out.append(ch)
            else:
                out.append("%%")
        else:
            out.append(ch)
        i += 1

    translated = "".join(out)
    if append_conflict_nothing:
        translated = translated.rstrip()
        if translated.endswith(";"):
            translated = translated[:-1].rstrip() + " ON CONFLICT DO NOTHING;"
        else:
            translated = translated + " ON CONFLICT DO NOTHING"
    return translated


class DualModeRow:
    """
    Row wrapper that provides full sqlite3.Row compatibility for PostgreSQL rows:
    supports key lookup (row['id']), positional index lookup (row[0]), slicing,
    dict(row) conversion, .get(), .keys(), .values(), and .items().
    """
    __slots__ = ("_columns", "_values", "_map")

    def __init__(self, columns, values):
        self._columns = tuple(columns)
        self._values = tuple(values)
        self._map = dict(zip(self._columns, self._values))

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return self._values[key]
        return self._map[key]

    def get(self, key, default=None):
        return self._map.get(key, default)

    def keys(self):
        return list(self._columns)

    def values(self):
        return list(self._values)

    def items(self):
        return list(self._map.items())

    def __contains__(self, key):
        return key in self._map

    def __iter__(self):
        return iter(self._columns)

    def __len__(self):
        return len(self._values)

    def __repr__(self):
        return f"DualModeRow({self._map!r})"


class PostgresCursorWrapper:
    """
    Wraps a DB-API 2.0 PostgreSQL cursor (psycopg2) to provide sqlite3.Cursor
    semantics: automatic ? -> %s placeholder translation, BEGIN IMMEDIATE handling,
    and DualModeRow results.
    """
    is_postgres = True

    def __init__(self, conn_wrapper, raw_cursor):
        self._conn = conn_wrapper
        self._cur = raw_cursor
        self.last_translated_sql = ""

    @property
    def description(self):
        return getattr(self._cur, "description", None)

    @property
    def rowcount(self):
        return getattr(self._cur, "rowcount", -1)

    def execute(self, sql, params=None):
        raw_stmt = str(sql or "").strip()
        upper_stmt = raw_stmt.upper().rstrip(";").strip()

        if upper_stmt in ("BEGIN", "BEGIN IMMEDIATE", "BEGIN EXCLUSIVE"):
            self.last_translated_sql = "BEGIN"
            self._conn._begin_transaction(self._cur)
            return self
        if upper_stmt == "COMMIT":
            self.last_translated_sql = "COMMIT"
            self._conn.commit()
            return self
        if upper_stmt == "ROLLBACK":
            self.last_translated_sql = "ROLLBACK"
            self._conn.rollback()
            return self

        has_params = params is not None
        pg_sql = translate_sql_for_postgres(sql, has_params=has_params)
        self.last_translated_sql = pg_sql
        if params is None:
            self._cur.execute(pg_sql)
        else:
            self._cur.execute(pg_sql, tuple(params) if isinstance(params, list) else params)
        return self

    def executemany(self, sql, seq_of_params):
        pg_sql = translate_sql_for_postgres(sql, has_params=True)
        self.last_translated_sql = pg_sql
        self._cur.executemany(pg_sql, seq_of_params)
        return self

    def _wrap_row(self, raw_row):
        if raw_row is None:
            return None
        if isinstance(raw_row, DualModeRow):
            return raw_row
        if isinstance(raw_row, sqlite3.Row):
            cols = raw_row.keys()
            return DualModeRow(cols, [raw_row[k] for k in cols])
        desc = self.description
        if desc:
            cols = [col[0] for col in desc]
            if isinstance(raw_row, dict):
                return DualModeRow(cols, [raw_row.get(c) for c in cols])
            return DualModeRow(cols, list(raw_row))
        if isinstance(raw_row, dict):
            cols = list(raw_row.keys())
            return DualModeRow(cols, [raw_row[c] for c in cols])
        return DualModeRow([str(i) for i in range(len(raw_row))], list(raw_row))

    def fetchone(self):
        return self._wrap_row(self._cur.fetchone())

    def fetchall(self):
        rows = self._cur.fetchall() or []
        return [self._wrap_row(r) for r in rows]

    def close(self):
        try:
            self._cur.close()
        except Exception:
            pass


class PostgresConnectionWrapper:
    """
    Wraps a psycopg2 PostgreSQL connection so callers can use both standard
    conn.cursor() / conn.commit() / conn.rollback() and sqlite3-style
    conn.isolation_level = None + cursor.execute('BEGIN IMMEDIATE').
    """
    is_postgres = True

    def __init__(self, raw_conn):
        self._raw_conn = raw_conn
        self.isolation_level = ""
        self.in_transaction = False
        if hasattr(self._raw_conn, "autocommit"):
            try:
                self._raw_conn.autocommit = False
            except Exception:
                pass

    def _begin_transaction(self, raw_cursor=None):
        self.in_transaction = True
        if getattr(self._raw_conn, "autocommit", False) and raw_cursor is not None:
            raw_cursor.execute("BEGIN")
        elif getattr(self._raw_conn, "RECORD_BEGIN_SQL", False) and raw_cursor is not None:
            raw_cursor.execute("BEGIN")

    def cursor(self):
        return PostgresCursorWrapper(self, self._raw_conn.cursor())

    def execute(self, sql, params=None):
        cur = self.cursor()
        return cur.execute(sql, params)

    def commit(self):
        self.in_transaction = False
        self._raw_conn.commit()

    def rollback(self):
        self.in_transaction = False
        self._raw_conn.rollback()

    def close(self):
        self.in_transaction = False
        self._raw_conn.close()


def _connect_postgres(db_url):
    clean_url = str(db_url or "").strip()
    if clean_url.startswith("postgres://"):
        clean_url = "postgresql://" + clean_url[len("postgres://"):]
    schema_name = get_postgres_schema()
    if _POSTGRES_CONNECT_FN is not None:
        raw_conn = _POSTGRES_CONNECT_FN(clean_url)
        wrapper = raw_conn if isinstance(raw_conn, PostgresConnectionWrapper) else PostgresConnectionWrapper(raw_conn)
        if schema_name and schema_name != "public":
            cur = wrapper.cursor()
            cur.execute(f"SET search_path TO {schema_name}")
            cur.close()
            wrapper.commit()
        return wrapper
    if psycopg2 is None:
        raise RuntimeError(
            "psycopg2 is required when DATABASE_URL is set to PostgreSQL. "
            "Install dependencies via: pip install -r requirements.txt"
        )
    connect_kwargs = {
        "dsn": clean_url,
        "connect_timeout": int(SQLITE_TIMEOUT_SECONDS),
    }
    if "sslmode=" not in clean_url.lower() and "localhost" not in clean_url.lower() and "127.0.0.1" not in clean_url.lower():
        connect_kwargs["sslmode"] = "require"
    raw_conn = psycopg2.connect(**connect_kwargs)
    wrapper = PostgresConnectionWrapper(raw_conn)
    if schema_name and schema_name != "public":
        cur = wrapper.cursor()
        cur.execute(f"SET search_path TO {schema_name}")
        cur.close()
        wrapper.commit()
    return wrapper


def get_db():
    db_url = get_database_url()
    if is_postgres_url(db_url):
        return _connect_postgres(db_url)
    conn = sqlite3.connect(DB_PATH, timeout=SQLITE_TIMEOUT_SECONDS, check_same_thread=False)
    conn = _configure_sqlite_connection(conn)
    return conn


class SQLiteBackupError(RuntimeError):
    """Raised when a SQLite online backup or integrity verification fails and raise_on_error=True."""
    pass


_BACKUP_DB_LOCK = threading.RLock()


def backup_sqlite_db(
    dest_path,
    source_path=None,
    overwrite=False,
    create_parent_dirs=False,
    pages=-1,
    raise_on_error=False,
):
    """
    Safely creates a consistent online SQLite backup using sqlite3.Connection.backup()
    and validates the resulting backup file with PRAGMA integrity_check.

    - Requires an explicit non-empty dest_path.
    - Rejects symbolic links at dest_path (for both overwrite=False and overwrite=True) so a backup
      never follows a symlink or replaces a symlink/unintended target.
    - Does not overwrite an existing destination file unless overwrite=True. When overwrite=False,
      uses atomic no-clobber publication (os.link from the verified staging file, with O_CREAT|O_EXCL
      fallback if hard links are unsupported) so concurrent processes targeting the same new path
      cannot clobber each other.
    - Validates that the destination parent directory exists (or creates it when create_parent_dirs=True).
    - Stages the backup into a temporary sibling file and publishes to dest_path only after
      PRAGMA integrity_check succeeds, ensuring existing backups are never corrupted on failure.
    - Reliably closes both source and destination connections and removes temporary staging files on
      all code paths.
    - Durability note: SQLite flushes the backup file prior to publication, but parent-directory
      descriptor fsync is intentionally omitted for cross-platform portability.
    """
    def _fail(msg, src_val="", dst_val="", integrity_val="failed"):
        if raise_on_error:
            raise SQLiteBackupError(msg)
        return {
            "ok": False,
            "source_path": src_val,
            "dest_path": dst_val,
            "overwritten": False,
            "integrity_check": integrity_val,
            "bytes_written": 0,
            "error": msg,
        }

    if dest_path is None or isinstance(dest_path, bool) or not isinstance(dest_path, (str, os.PathLike)):
        return _fail("An explicit backup destination path is required.")
    dst_raw = str(os.fspath(dest_path)).strip()
    if not dst_raw or "\x00" in dst_raw:
        return _fail("An explicit, valid backup destination path is required.")

    src_raw = str(os.fspath(source_path)).strip() if source_path is not None else str(DB_PATH).strip()
    if not src_raw or "\x00" in src_raw:
        return _fail("Invalid source database path.")

    try:
        dst_abs = os.path.abspath(dst_raw)
        src_abs = os.path.abspath(src_raw)
        dst_real = os.path.realpath(dst_abs)
        src_real = os.path.realpath(src_abs)
    except Exception:
        return _fail("Invalid source or destination path.")

    if os.path.islink(dst_abs):
        return _fail("Backup destination path must not be a symbolic link.", src_abs, dst_abs)

    if os.path.isdir(dst_abs) or os.path.isdir(dst_real):
        return _fail("Backup destination path must be a file, not a directory.", src_abs, dst_abs)

    if not os.path.isfile(src_real):
        return _fail("Source SQLite database file does not exist.", src_abs, dst_abs)

    if src_real == dst_real:
        return _fail("Backup destination path must differ from the source database path.", src_abs, dst_abs)

    parent_dir = os.path.dirname(dst_abs)
    if not parent_dir:
        return _fail("Backup destination parent directory could not be determined.", src_abs, dst_abs)

    if not os.path.exists(parent_dir):
        if create_parent_dirs:
            try:
                os.makedirs(parent_dir, exist_ok=True)
            except OSError:
                return _fail("Failed to create backup destination directory.", src_abs, dst_abs)
        else:
            return _fail("Backup destination directory does not exist.", src_abs, dst_abs)
    elif not os.path.isdir(parent_dir):
        return _fail("Backup destination parent path is not a directory.", src_abs, dst_abs)

    dest_existed = os.path.exists(dst_abs) or os.path.lexists(dst_abs)
    if dest_existed and not overwrite:
        return _fail("Backup destination already exists and overwrite is disabled.", src_abs, dst_abs)

    tmp_dst_path = os.path.join(parent_dir, f".{os.path.basename(dst_abs)}.tmp-{secrets.token_hex(6)}")
    src_conn = None
    dst_conn = None
    try:
        src_conn = sqlite3.connect(src_real, timeout=SQLITE_TIMEOUT_SECONDS, check_same_thread=False)
        _configure_sqlite_connection(src_conn)

        dst_conn = sqlite3.connect(tmp_dst_path, timeout=SQLITE_TIMEOUT_SECONDS, check_same_thread=False)
        _configure_sqlite_connection(dst_conn)

        step_pages = int(pages) if pages is not None else -1
        src_conn.backup(dst_conn, pages=step_pages)

        chk_rows = dst_conn.execute("PRAGMA integrity_check").fetchall()
        integrity_ok = bool(chk_rows) and all(str(r[0]).strip().lower() == "ok" for r in chk_rows)
        if not integrity_ok:
            return _fail("Backup failed PRAGMA integrity_check validation.", src_abs, dst_abs, "failed")

        dst_conn.close()
        dst_conn = None
        src_conn.close()
        src_conn = None

        if os.path.islink(dst_abs):
            return _fail("Backup destination path must not be a symbolic link.", src_abs, dst_abs)
        if not overwrite:
            try:
                os.link(tmp_dst_path, dst_abs)
            except FileExistsError:
                return _fail("Backup destination already exists and overwrite is disabled.", src_abs, dst_abs)
            except OSError as link_err:
                if link_err.errno == errno.EEXIST or os.path.exists(dst_abs) or os.path.lexists(dst_abs):
                    return _fail("Backup destination already exists and overwrite is disabled.", src_abs, dst_abs)
                with _BACKUP_DB_LOCK:
                    if os.path.islink(dst_abs):
                        return _fail("Backup destination path must not be a symbolic link.", src_abs, dst_abs)
                    try:
                        excl_fd = os.open(dst_abs, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    except FileExistsError:
                        return _fail("Backup destination already exists and overwrite is disabled.", src_abs, dst_abs)
                    try:
                        try:
                            os.close(excl_fd)
                        finally:
                            excl_fd = None
                        os.replace(tmp_dst_path, dst_abs)
                    except Exception:
                        try:
                            os.remove(dst_abs)
                        except Exception:
                            pass
                        raise
        else:
            with _BACKUP_DB_LOCK:
                if os.path.islink(dst_abs):
                    return _fail("Backup destination path must not be a symbolic link.", src_abs, dst_abs)
                dest_existed = dest_existed or os.path.exists(dst_abs)
                os.replace(tmp_dst_path, dst_abs)

        bytes_written = os.path.getsize(dst_abs)
    except SQLiteBackupError:
        raise
    except Exception:
        return _fail("SQLite online backup failed.", src_abs, dst_abs, "failed")
    finally:
        if dst_conn is not None:
            try:
                dst_conn.close()
            except Exception:
                pass
        if src_conn is not None:
            try:
                src_conn.close()
            except Exception:
                pass
        if os.path.exists(tmp_dst_path):
            try:
                os.remove(tmp_dst_path)
            except Exception:
                pass

    return {
        "ok": True,
        "source_path": src_abs,
        "dest_path": dst_abs,
        "overwritten": bool(dest_existed),
        "integrity_check": "ok",
        "bytes_written": int(bytes_written),
        "error": None,
    }


create_db_backup = backup_sqlite_db


def _add_column_if_missing(c, table_name, col_name, col_def):
    if getattr(c, "is_postgres", False):
        schema_name = get_postgres_schema()
        c.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = ? AND table_name = ?",
            (schema_name, table_name),
        )
        existing_cols = {row["column_name"] for row in c.fetchall()}
        if col_name in existing_cols:
            return False
        c.execute(f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {col_name} {col_def}")
        return True

    c.execute(f"PRAGMA table_info({table_name})")
    existing_cols = {row["name"] for row in c.fetchall()}
    if col_name in existing_cols:
        return False
    try:
        c.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def}")
        return True
    except DB_OPERATIONAL_ERRORS as e:
        if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
            return False
        raise


def init_db():
    with _INIT_DB_LOCK:
        if not is_postgres_mode():
            os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        last_err = None
        for attempt in range(5):
            conn = None
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute("BEGIN IMMEDIATE")

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
                migration_cols = {
                    "order_status": "TEXT DEFAULT 'confirmed'",
                    "tracking_number": "TEXT",
                    "courier_partner": "TEXT",
                    "discount_amount": "INTEGER DEFAULT 0",
                    "coupon_code": "TEXT",
                    "user_id": "TEXT",
                    "house_no": "TEXT DEFAULT ''",
                    "street_area": "TEXT DEFAULT ''",
                    "latitude": "REAL",
                    "longitude": "REAL",
                    "location_summary": "TEXT DEFAULT ''",
                    "address_label": "TEXT DEFAULT 'Home'"
                }
                for col, definition in migration_cols.items():
                    _add_column_if_missing(c, "orders", col, definition)

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

                prod_migrations = {
                    "style": "TEXT DEFAULT ''",
                    "occasion": "TEXT DEFAULT ''",
                    "pattern": "TEXT DEFAULT ''",
                    "sleeve_length": "TEXT DEFAULT ''",
                    "neck_design": "TEXT DEFAULT ''",
                    "is_archived": "INTEGER DEFAULT 0",
                    "size_stock_json": "TEXT DEFAULT '{}'",
                    "sku": "TEXT DEFAULT ''"
                }
                for col, definition in prod_migrations.items():
                    _add_column_if_missing(c, "products", col, definition)

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

                cp_migrations = {
                    "start_date": "TEXT DEFAULT ''",
                    "applicable_categories": "TEXT DEFAULT ''",
                    "applicable_products": "TEXT DEFAULT ''",
                    "is_auto_apply": "INTEGER DEFAULT 0"
                }
                for col, definition in cp_migrations.items():
                    _add_column_if_missing(c, "coupons", col, definition)

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
                        created_at TEXT NOT NULL,
                        house_no TEXT DEFAULT '',
                        street_area TEXT DEFAULT '',
                        latitude REAL,
                        longitude REAL,
                        location_summary TEXT DEFAULT '',
                        address_label TEXT DEFAULT 'Home'
                    )
                """)

                addr_migrations = {
                    "house_no": "TEXT DEFAULT ''",
                    "street_area": "TEXT DEFAULT ''",
                    "latitude": "REAL",
                    "longitude": "REAL",
                    "location_summary": "TEXT DEFAULT ''",
                    "address_label": "TEXT DEFAULT 'Home'"
                }
                for col, definition in addr_migrations.items():
                    _add_column_if_missing(c, "user_addresses", col, definition)

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

                # 10. Admin Sessions table
                c.execute("""
                    CREATE TABLE IF NOT EXISTS admin_sessions (
                        token TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL
                    )
                """)

                # Secondary indexes for fast lookups on both SQLite and PostgreSQL
                c.execute("CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders (user_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_orders_razorpay_order_id ON orders (razorpay_order_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions (user_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_user_addresses_user_id ON user_addresses (user_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_return_requests_order_id ON return_requests (order_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users (LOWER(email))")

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
                            ON CONFLICT (id) DO NOTHING
                        """, (
                            p["id"], p["name"], p["category"], p.get("style", ""), p["price"], p["mrp"], p["description"],
                            p["fabric"], p.get("occasion", ""), p.get("pattern", ""), p.get("sleeve_length", ""),
                            p.get("neck_design", ""), p["care"], p["image"], p["relative_image"], p["gallery_json"],
                            p["colors_json"], p["sizes_json"], p["sold_out_sizes_json"], p["stock"],
                            p["is_featured"], p["is_new"], p["is_bestseller"], p["rating"], p["reviews_count"],
                            now_iso
                        ))
                else:
                    # Backfill rich ethnic attributes on existing default products and repair any non-existent image path
                    for p in DEFAULT_PRODUCTS:
                        c.execute("""
                            SELECT style, occasion, pattern, sleeve_length, neck_design,
                                    image, relative_image, fabric, care, colors_json, gallery_json
                            FROM products WHERE id = ?
                        """, (p["id"],))
                        existing = c.fetchone()
                        if existing:
                            curr_img = existing["image"] or ""
                            curr_rel = existing["relative_image"] or ""
                            img_exists = bool(curr_img and _public_asset_file_exists(curr_img))
                            rel_exists = bool(curr_rel and _public_asset_file_exists(curr_rel))
                            fixed_img = p["image"] if not img_exists else curr_img
                            fixed_rel = p["relative_image"] if not rel_exists else curr_rel
                            fixed_fabric = existing["fabric"] if (existing["fabric"] and existing["fabric"].strip()) else p["fabric"]
                            fixed_care = existing["care"] if (existing["care"] and existing["care"].strip()) else p["care"]
                            fixed_colors = p["colors_json"] if (not existing["colors_json"] or "Standard" in existing["colors_json"]) else existing["colors_json"]
                            fixed_gallery = p["gallery_json"] if not img_exists else existing["gallery_json"]
                            fixed_style = existing["style"] if (existing["style"] and existing["style"].strip()) else p.get("style", "")
                            fixed_occasion = existing["occasion"] if (existing["occasion"] and existing["occasion"].strip()) else p.get("occasion", "")
                            fixed_pattern = existing["pattern"] if (existing["pattern"] and existing["pattern"].strip()) else p.get("pattern", "")
                            fixed_sleeve = existing["sleeve_length"] if (existing["sleeve_length"] and existing["sleeve_length"].strip()) else p.get("sleeve_length", "")
                            fixed_neck = existing["neck_design"] if (existing["neck_design"] and existing["neck_design"].strip()) else p.get("neck_design", "")

                            needs_update = (
                                (existing["style"] or "") != fixed_style
                                or (existing["occasion"] or "") != fixed_occasion
                                or (existing["pattern"] or "") != fixed_pattern
                                or (existing["sleeve_length"] or "") != fixed_sleeve
                                or (existing["neck_design"] or "") != fixed_neck
                                or (existing["fabric"] or "") != fixed_fabric
                                or (existing["care"] or "") != fixed_care
                                or (existing["image"] or "") != fixed_img
                                or (existing["relative_image"] or "") != fixed_rel
                                or (existing["colors_json"] or "") != fixed_colors
                                or (existing["gallery_json"] or "") != fixed_gallery
                            )
                            if needs_update:
                                c.execute("""
                                    UPDATE products
                                    SET style = ?,
                                        occasion = ?,
                                        pattern = ?,
                                        sleeve_length = ?,
                                        neck_design = ?,
                                        fabric = ?,
                                        care = ?,
                                        image = ?,
                                        relative_image = ?,
                                        colors_json = ?,
                                        gallery_json = ?
                                    WHERE id = ?
                                """, (
                                    fixed_style, fixed_occasion, fixed_pattern, fixed_sleeve, fixed_neck,
                                    fixed_fabric, fixed_care, fixed_img, fixed_rel, fixed_colors, fixed_gallery,
                                    p["id"]
                                ))

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
                            ON CONFLICT (code) DO NOTHING
                        """, (
                            cp["code"], cp["discount_type"], cp["discount_value"], cp["min_order_value"],
                            cp["max_discount"], cp.get("start_date", "2024-01-01"), cp["expiry_date"],
                            cp["usage_limit"], 0, cp.get("applicable_categories", ""),
                            cp.get("applicable_products", ""), cp.get("is_auto_apply", 0), 1,
                            cp["description"], now_iso
                        ))

                # Seed Site Settings if empty
                c.execute("SELECT COUNT(*) AS cnt FROM site_settings")
                if c.fetchone()["cnt"] == 0:
                    c.execute("INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING", ("announcements", json.dumps(DEFAULT_ANNOUNCEMENTS)))
                    c.execute("INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING", ("announcement_enabled", "true"))
                    c.execute("INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING", ("free_shipping_threshold", "999"))
                    c.execute("INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING", ("shipping_fee", "99"))
                    c.execute("INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING", ("cod_enabled", "true"))
                    c.execute("INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING", ("promo_banner_enabled", "true"))
                    c.execute("INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING", ("promo_banner_code", "NAARI10"))

                conn.commit()
                return
            except DB_OPERATIONAL_ERRORS as e:
                last_err = e
                if conn is not None:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                if "locked" in str(e).lower() or "busy" in str(e).lower():
                    time.sleep(0.05 * (attempt + 1))
                    continue
                raise
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
        if last_err is not None:
            raise last_err

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
    d["sizes"] = json.loads(d.get("sizes_json") or '["S", "M", "L", "XL"]')
    d["soldOutSizes"] = json.loads(d.get("sold_out_sizes_json") or "[]")
    d["sku"] = (d.get("sku") or d.get("id") or "").strip().upper()

    raw_size_stock = {}
    try:
        raw_size_stock = json.loads(d.get("size_stock_json") or "{}")
        if not isinstance(raw_size_stock, dict):
            raw_size_stock = {}
    except Exception:
        raw_size_stock = {}

    total_stock = max(0, int(d.get("stock", 0) or 0))
    sizes_list = d["sizes"] if d["sizes"] else ["S", "M", "L", "XL"]
    for core_sz in ("S", "M", "L", "XL"):
        if core_sz not in sizes_list and "Free Size" not in sizes_list:
            sizes_list.append(core_sz)

    size_stock = {}
    if raw_size_stock:
        for sz in sizes_list:
            qty_val = max(0, int(raw_size_stock.get(sz, 0) or 0))
            if sz in d["soldOutSizes"]:
                qty_val = 0
            size_stock[sz] = qty_val
        for sz, qv in raw_size_stock.items():
            if sz not in size_stock:
                size_stock[sz] = max(0, int(qv or 0))
    else:
        avail_sizes = [s for s in sizes_list if s not in d["soldOutSizes"]]
        if avail_sizes and total_stock > 0:
            base_q = total_stock // len(avail_sizes)
            rem = total_stock % len(avail_sizes)
            for idx, sz in enumerate(sizes_list):
                if sz in d["soldOutSizes"]:
                    size_stock[sz] = 0
                else:
                    avail_idx = avail_sizes.index(sz)
                    size_stock[sz] = base_q + (1 if avail_idx < rem else 0)
        else:
            for sz in sizes_list:
                size_stock[sz] = 0

    d["sizeStock"] = size_stock
    d["size_stock"] = size_stock
    d["stock"] = total_stock
    d["isArchived"] = bool(d.get("is_archived", 0))
    d["isBestseller"] = bool(d.get("is_bestseller", 0))
    d["lowStockSizes"] = [sz for sz, q in size_stock.items() if 0 < q <= 3]
    d["isLowStock"] = (0 < total_stock <= 10) or len(d["lowStockSizes"]) > 0
    d["inStock"] = total_stock > 0 and not d.get("is_archived", 0)
    d["discountPercent"] = int(round((d["mrp"] - d["price"]) / d["mrp"] * 100)) if d.get("mrp", 0) > d.get("price", 0) else 0
    return d

def _validate_product_inventory_row(row):
    """
    Validates that a raw product row from SQLite has well-formed, non-negative
    inventory data (stock, size_stock_json, sizes_json, sold_out_sizes_json).
    Returns (formatted_product_dict, error_message).
    """
    if not row:
        return None, "Product not found."
    d = dict(row)
    pname = str(d.get("name") or d.get("id") or "Product").strip()

    raw_total = d.get("stock")
    if raw_total is None or isinstance(raw_total, bool):
        return None, f"Inventory data for '{pname}' is unavailable."
    try:
        total_stock = int(raw_total)
        if str(raw_total).strip() != str(total_stock):
            return None, f"Inventory data for '{pname}' is invalid."
    except (ValueError, TypeError):
        return None, f"Inventory data for '{pname}' is invalid."
    if total_stock < 0:
        return None, f"Inventory data for '{pname}' is invalid."

    for list_col in ("sizes_json", "sold_out_sizes_json"):
        raw_list_str = d.get(list_col)
        if raw_list_str is not None and str(raw_list_str).strip() != "":
            try:
                parsed_list = json.loads(raw_list_str)
                if not isinstance(parsed_list, list):
                    return None, f"Inventory data for '{pname}' is invalid."
            except Exception:
                return None, f"Inventory data for '{pname}' is invalid."

    raw_ss_str = d.get("size_stock_json")
    if raw_ss_str is not None and str(raw_ss_str).strip() != "":
        try:
            parsed_ss = json.loads(raw_ss_str)
        except Exception:
            return None, f"Size inventory data for '{pname}' is invalid."
        if not isinstance(parsed_ss, dict):
            return None, f"Size inventory data for '{pname}' is invalid."
        for sz_key, sz_val in parsed_ss.items():
            if sz_val is None or isinstance(sz_val, bool):
                return None, f"Inventory data for '{pname}' (Size {sz_key}) is unavailable."
            try:
                sz_int = int(sz_val)
                if str(sz_val).strip() != str(sz_int):
                    return None, f"Inventory data for '{pname}' (Size {sz_key}) is invalid."
            except (ValueError, TypeError):
                return None, f"Inventory data for '{pname}' (Size {sz_key}) is invalid."
            if sz_int < 0:
                return None, f"Inventory data for '{pname}' (Size {sz_key}) is invalid."

    return format_product_row(row), None


def _parse_strict_item_qty(raw_qty):
    if raw_qty is None or isinstance(raw_qty, bool):
        return None
    try:
        qty = int(raw_qty)
        if str(raw_qty).strip() != str(qty):
            return None
    except (ValueError, TypeError):
        return None
    if qty < 1 or qty > 50:
        return None
    return qty


def deduct_order_stock(computed_items, cursor=None):
    """
    Aggregates item quantities by (product_id, size) and product_id, verifies sufficient
    available stock without silent clamping, and deducts stock atomically within a SQLite
    transaction. Raises ValueError if any item has invalid data or insufficient stock.
    """
    if isinstance(computed_items, str):
        try:
            computed_items = json.loads(computed_items or "[]")
        except Exception:
            raise ValueError("Invalid order items data.")
    if not computed_items or not isinstance(computed_items, list):
        return

    product_order = []
    per_product_total_qty = {}
    per_product_size_qty = {}

    for item in computed_items:
        if not isinstance(item, dict):
            raise ValueError("Invalid item in order.")
        pid = str(item.get("id", "")).strip()
        if not pid:
            raise ValueError("Invalid product ID in order.")
        qty = _parse_strict_item_qty(item.get("qty"))
        if qty is None:
            raise ValueError("Invalid quantity.")
        raw_size = item.get("size")
        size = str(raw_size).strip() if raw_size is not None else ""

        if pid not in per_product_total_qty:
            product_order.append(pid)
            per_product_total_qty[pid] = 0
            per_product_size_qty[pid] = {}
        per_product_total_qty[pid] += qty
        per_product_size_qty[pid][size] = per_product_size_qty[pid].get(size, 0) + qty

    owns_conn = cursor is None
    conn = get_db() if owns_conn else None
    if owns_conn:
        conn.isolation_level = None
    c = conn.cursor() if owns_conn else cursor

    try:
        if owns_conn:
            c.execute("BEGIN IMMEDIATE")

        lock_clause = _for_update_clause(c)
        for pid in sorted(product_order):
            total_req_qty = per_product_total_qty[pid]
            c.execute(f"SELECT * FROM products WHERE id = ?{lock_clause}", (pid,))
            row = c.fetchone()
            if not row:
                raise ValueError(f"Unrecognized product: {pid}")
            prod, inv_err = _validate_product_inventory_row(row)
            if inv_err or not prod:
                raise ValueError(inv_err or f"Inventory data for '{pid}' is invalid.")

            avail_total = int(prod.get("stock", 0))
            if prod.get("is_archived", 0) or avail_total <= 0:
                raise ValueError(f"Sorry, '{prod['name']}' is currently out of stock.")
            if total_req_qty > avail_total:
                raise ValueError(f"Only {avail_total} unit(s) of '{prod['name']}' available in stock.")

            size_stock = dict(prod.get("sizeStock", {}))
            sold_out = list(prod.get("soldOutSizes", []))

            for raw_sz, req_sz_qty in per_product_size_qty[pid].items():
                eff_size = raw_sz if raw_sz else ("Free Size" if "Free Size" in size_stock else "")
                if not eff_size:
                    raise ValueError(f"Please select a valid size for '{prod['name']}'.")
                if eff_size in sold_out:
                    raise ValueError(f"Size '{eff_size}' for '{prod['name']}' is currently sold out.")
                if size_stock:
                    if eff_size not in size_stock:
                        raise ValueError(f"Size '{eff_size}' is not available for '{prod['name']}'.")
                    avail_sz = int(size_stock[eff_size])
                    if avail_sz <= 0:
                        raise ValueError(f"Size '{eff_size}' for '{prod['name']}' is currently out of stock.")
                    if req_sz_qty > avail_sz:
                        raise ValueError(
                            f"Only {avail_sz} unit(s) of '{prod['name']}' in Size {eff_size} available in stock."
                        )
                    new_sz_qty = avail_sz - req_sz_qty
                    size_stock[eff_size] = new_sz_qty
                    if new_sz_qty == 0 and eff_size not in sold_out:
                        sold_out.append(eff_size)

            if size_stock:
                new_total_stock = sum(int(v) for v in size_stock.values())
            else:
                new_total_stock = avail_total - total_req_qty

            if new_total_stock < 0:
                raise ValueError(f"Only {avail_total} unit(s) of '{prod['name']}' available in stock.")

            c.execute("""
                UPDATE products
                SET stock = ?,
                    size_stock_json = ?,
                    sold_out_sizes_json = ?
                WHERE id = ? AND stock >= ?
            """, (new_total_stock, json.dumps(size_stock), json.dumps(sold_out), pid, total_req_qty))
            if c.rowcount != 1:
                raise ValueError(f"Only {avail_total} unit(s) of '{prod['name']}' available in stock.")

        if owns_conn:
            c.execute("COMMIT")
    except Exception:
        if owns_conn and conn is not None:
            try:
                c.execute("ROLLBACK")
            except Exception:
                pass
        raise
    finally:
        if owns_conn and conn is not None:
            conn.close()


def order_had_inventory_deducted(order_row):
    """
    Returns True if and only if an order's inventory and coupon usage were
    actually deducted:
    - COD orders confirmed at creation (payment_method == 'cod' and payment_status == 'cod_confirmed').
    - Razorpay orders with verified payment (payment_status == 'paid').
    Never returns True for unpaid pending_payment, pending, failed, or cancelled-before-payment orders.
    """
    if not order_row:
        return False
    od = dict(order_row)
    pay_method = str(od.get("payment_method") or "").strip().lower()
    pay_status = str(od.get("payment_status") or "").strip().lower()
    ord_status = str(od.get("order_status") or "").strip().lower()

    if ord_status == "pending_payment":
        return False
    if pay_status in ("pending", "pending_payment", "failed", "cancelled"):
        return False
    if pay_method == "cod" and pay_status in ("cod_confirmed", "paid", "confirmed"):
        return True
    if pay_status == "paid":
        return True
    return False


def restore_order_stock(computed_items, cursor=None):
    """
    Restores item quantities to per-size stock, sold-out-size state, and total product stock.
    When `cursor` is provided, executes within the caller's open SQLite transaction.
    """
    if isinstance(computed_items, str):
        try:
            computed_items = json.loads(computed_items or "[]")
        except Exception:
            computed_items = []
    if not computed_items or not isinstance(computed_items, list):
        return

    owns_conn = cursor is None
    conn = get_db() if owns_conn else None
    c = conn.cursor() if owns_conn else cursor

    try:
        lock_clause = _for_update_clause(c) if not owns_conn else ""
        for item in computed_items:
            if not isinstance(item, dict):
                continue
            pid = str(item.get("id", "")).strip()
            size = str(item.get("size", "")).strip()
            qty = max(1, int(item.get("qty", 1) or 1))
            if not pid:
                continue
            c.execute(f"SELECT * FROM products WHERE id = ?{lock_clause}", (pid,))
            row = c.fetchone()
            if not row:
                continue
            prod = format_product_row(row)
            size_stock = dict(prod.get("sizeStock", {}))
            sold_out = list(prod.get("soldOutSizes", []))
            if size and (size in size_stock or size in prod.get("sizes", [])):
                size_stock[size] = max(0, int(size_stock.get(size, 0) or 0)) + qty
                if size_stock[size] > 0 and size in sold_out:
                    sold_out = [s for s in sold_out if s != size]
                new_total_stock = sum(max(0, int(v)) for v in size_stock.values())
            else:
                new_total_stock = max(0, int(prod.get("stock", 0) or 0)) + qty
            c.execute("""
                UPDATE products
                SET stock = ?,
                    size_stock_json = ?,
                    sold_out_sizes_json = ?
                WHERE id = ?
            """, (new_total_stock, json.dumps(size_stock), json.dumps(sold_out), pid))
        if owns_conn:
            conn.commit()
    finally:
        if owns_conn and conn is not None:
            conn.close()


def restore_cancelled_order_resources(cursor, order_row):
    """
    Restores deducted product stock and decrements coupon used_count within the active
    SQLite transaction cursor when an order transitions to 'cancelled' for the first time.
    """
    if not order_had_inventory_deducted(order_row):
        return False
    od = dict(order_row)
    restore_order_stock(od.get("items_json") or "[]", cursor=cursor)
    coupon_code = str(od.get("coupon_code") or "").strip()
    if coupon_code:
        cursor.execute("""
            UPDATE coupons
            SET used_count = CASE WHEN COALESCE(used_count, 0) > 0 THEN used_count - 1 ELSE 0 END
            WHERE UPPER(code) = UPPER(?)
        """, (coupon_code,))
    return True

def get_product_from_db(pid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM products WHERE id = ?", (pid,))
    row = c.fetchone()
    conn.close()
    if row:
        return format_product_row(row)
    return None

def evaluate_coupon(code, subtotal, computed_items=None, cursor=None):
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

    try:
        subtotal_int = int(subtotal)
    except (ValueError, TypeError):
        return None, 0, "Invalid order subtotal."
    if subtotal_int <= 0:
        return None, 0, "Shopping bag is empty."

    owns_conn = cursor is None
    conn = get_db() if owns_conn else None
    c = conn.cursor() if owns_conn else cursor
    try:
        lock_clause = _for_update_clause(c) if not owns_conn else ""
        c.execute(f"SELECT * FROM coupons WHERE UPPER(code) = ?{lock_clause}", (clean_code,))
        row = c.fetchone()
    finally:
        if owns_conn and conn is not None:
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
    if subtotal_int < min_val:
        return None, 0, f"Coupon {clean_code} requires a minimum order value of ₹{min_val:,} (Current bag: ₹{subtotal_int:,})."

    # Check category or product eligibility if configured
    eligible_subtotal = subtotal_int
    app_cats = [x.strip().lower() for x in str(cp.get("applicable_categories") or "").split(",") if x.strip()]
    app_prods = [x.strip().lower() for x in str(cp.get("applicable_products") or "").split(",") if x.strip()]

    if app_cats or app_prods:
        if not computed_items:
            return None, 0, f"Coupon '{clean_code}' is not applicable to the items in your bag."
        eligible_subtotal = 0
        for item in computed_items:
            pid = str(item.get("id", "")).strip().lower()
            cat = str(item.get("category", "")).strip().lower()
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

    discount = max(0, min(discount, eligible_subtotal, subtotal_int))
    if discount <= 0:
        return None, 0, f"Coupon '{clean_code}' is not applicable to the items in your bag."
    return cp, discount, None


def validate_and_compute_totals(items, coupon_code="", cursor=None):
    if not isinstance(items, list) or len(items) == 0:
        return None, "Shopping bag is empty."

    computed_items = []
    subtotal = 0
    product_totals = {}
    product_size_totals = {}
    product_cache = {}

    owns_conn = cursor is None
    conn = get_db() if owns_conn else None
    c = conn.cursor() if owns_conn else cursor

    try:
        for item in items:
            if not isinstance(item, dict):
                return None, "Invalid item in shopping bag."
            pid = str(item.get("id", "")).strip()
            if not pid:
                return None, "Invalid product ID in shopping bag."

            qty = _parse_strict_item_qty(item.get("qty"))
            if qty is None:
                return None, "Invalid quantity."

            color = str(item.get("color") or "Standard").strip()
            raw_size = item.get("size")
            size = str(raw_size).strip() if raw_size is not None else ""

            if pid not in product_cache:
                c.execute("SELECT * FROM products WHERE id = ?", (pid,))
                row = c.fetchone()
                if not row:
                    return None, f"Unrecognized product: {pid}"
                prod, inv_err = _validate_product_inventory_row(row)
                if inv_err or not prod:
                    return None, inv_err or f"Inventory data for '{pid}' is invalid."
                product_cache[pid] = prod

            prod = product_cache[pid]
            avail_total = int(prod.get("stock", 0))
            if avail_total <= 0 or prod.get("is_archived", 0):
                return None, f"Sorry, '{prod['name']}' is currently out of stock."

            size_stock_map = prod.get("sizeStock", {})
            if not size:
                size = "Free Size" if "Free Size" in size_stock_map else ""
            if not size:
                return None, f"Please select a valid size for '{prod['name']}'."

            if size in prod.get("soldOutSizes", []):
                return None, f"Size '{size}' for '{prod['name']}' is currently sold out."

            if size_stock_map:
                if size not in size_stock_map:
                    return None, f"Size '{size}' is not available for '{prod['name']}'."
                avail_sz = int(size_stock_map[size])
                if avail_sz <= 0:
                    return None, f"Size '{size}' for '{prod['name']}' is currently out of stock."
                combined_sz_qty = product_size_totals.get((pid, size), 0) + qty
                if combined_sz_qty > avail_sz:
                    return None, f"Only {avail_sz} unit(s) of '{prod['name']}' in Size {size} available in stock."
                product_size_totals[(pid, size)] = combined_sz_qty

            combined_prod_qty = product_totals.get(pid, 0) + qty
            if combined_prod_qty > avail_total:
                return None, f"Only {avail_total} unit(s) of '{prod['name']}' available in stock."
            product_totals[pid] = combined_prod_qty

            name = prod["name"]
            category = prod.get("category", "")
            price = prod["price"]
            mrp = prod["mrp"]
            img = item.get("image") or prod["relative_image"]

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

        # Validate explicit coupon (must reject if invalid) or check auto-apply promotion
        discount = 0
        applied_coupon = None
        if coupon_code and str(coupon_code).strip():
            cp, disc, cp_err = evaluate_coupon(coupon_code, subtotal, computed_items, cursor=c)
            if cp_err or not cp:
                return None, cp_err or "Invalid coupon code."
            discount = disc
            applied_coupon = cp["code"]
        else:
            c.execute("SELECT code FROM coupons WHERE is_active = 1 AND is_auto_apply = 1 ORDER BY discount_value DESC")
            auto_rows = c.fetchall()
            for ar in auto_rows:
                cp, disc, cp_err = evaluate_coupon(ar["code"], subtotal, computed_items, cursor=c)
                if cp and not cp_err and disc > 0:
                    discount = disc
                    applied_coupon = cp["code"]
                    break
    finally:
        if owns_conn and conn is not None:
            conn.close()

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

# ================= Address Validation, Indian PIN Lookup & OpenStreetMap Geocoding =================

PLACEHOLDER_TOKENS = {
    "abc", "abcd", "abcde", "abcdef", "abcdefg", "abcdefgh",
    "test", "testing", "tester", "tests",
    "asdf", "asdfg", "asdfgh", "qwerty", "qwer", "qwert", "zxcv", "zxcvb",
    "xyz", "xyzw", "xxxx", "xxxxx", "zzzz", "none", "null", "undefined",
    "na", "n/a", "nil", "dummy", "sample", "fake", "placeholder",
    "address", "street", "city", "state", "house", "flat", "demo",
    "123", "1234", "12345", "123456", "1234567", "12345678",
    "000", "0000", "00000", "000000", "9999", "99999", "999999"
}

GIBBERISH_TOKENS = {
    "abc", "abcd", "abcde", "abcdef", "abcdefg", "abcdefgh",
    "asdf", "asdfg", "asdfgh", "asdfghj", "asdfghjk", "asdfghjkl",
    "qwerty", "qwer", "qwert", "qwertyu", "qwertyui", "qwertyuio", "qwertyuiop",
    "zxcv", "zxcvb", "zxcvbn", "zxcvbnm",
    "xyz", "xyzw", "xxxx", "xxxxx", "zzzz",
    "dummy", "fake", "placeholder"
}

# Authoritative 2-digit Indian Postal PIN prefix -> Allowed State/UT names
INDIAN_PIN_PREFIX_STATES = {
    "11": ["Delhi", "New Delhi", "NCT of Delhi"],
    "12": ["Haryana"],
    "13": ["Haryana"],
    "14": ["Punjab"],
    "15": ["Punjab"],
    "16": ["Punjab", "Chandigarh"],
    "17": ["Himachal Pradesh"],
    "18": ["Jammu and Kashmir", "Jammu & Kashmir", "Ladakh"],
    "19": ["Jammu and Kashmir", "Jammu & Kashmir", "Ladakh"],
    "20": ["Uttar Pradesh"],
    "21": ["Uttar Pradesh"],
    "22": ["Uttar Pradesh"],
    "23": ["Uttar Pradesh"],
    "24": ["Uttar Pradesh", "Uttarakhand"],
    "25": ["Uttar Pradesh"],
    "26": ["Uttar Pradesh", "Uttarakhand"],
    "27": ["Uttar Pradesh"],
    "28": ["Uttar Pradesh"],
    "30": ["Rajasthan"],
    "31": ["Rajasthan"],
    "32": ["Rajasthan"],
    "33": ["Rajasthan"],
    "34": ["Rajasthan"],
    "36": ["Gujarat"],
    "37": ["Gujarat"],
    "38": ["Gujarat"],
    "39": ["Gujarat", "Dadra and Nagar Haveli", "Daman and Diu", "Dadra and Nagar Haveli and Daman and Diu"],
    "40": ["Maharashtra", "Goa"],
    "41": ["Maharashtra"],
    "42": ["Maharashtra"],
    "43": ["Maharashtra"],
    "44": ["Maharashtra"],
    "45": ["Madhya Pradesh"],
    "46": ["Madhya Pradesh"],
    "47": ["Madhya Pradesh"],
    "48": ["Madhya Pradesh"],
    "49": ["Chhattisgarh"],
    "50": ["Telangana", "Andhra Pradesh"],
    "51": ["Andhra Pradesh"],
    "52": ["Andhra Pradesh"],
    "53": ["Andhra Pradesh"],
    "56": ["Karnataka"],
    "57": ["Karnataka"],
    "58": ["Karnataka"],
    "59": ["Karnataka"],
    "60": ["Tamil Nadu", "Puducherry", "Pondicherry"],
    "61": ["Tamil Nadu", "Puducherry", "Pondicherry"],
    "62": ["Tamil Nadu"],
    "63": ["Tamil Nadu"],
    "64": ["Tamil Nadu"],
    "67": ["Kerala", "Puducherry"],
    "68": ["Kerala", "Lakshadweep"],
    "69": ["Kerala"],
    "70": ["West Bengal"],
    "71": ["West Bengal"],
    "72": ["West Bengal"],
    "73": ["West Bengal", "Sikkim"],
    "74": ["West Bengal", "Andaman and Nicobar Islands", "Andaman & Nicobar Islands"],
    "75": ["Odisha", "Orissa"],
    "76": ["Odisha", "Orissa"],
    "77": ["Odisha", "Orissa"],
    "78": ["Assam"],
    "79": [
        "Arunachal Pradesh", "Manipur", "Meghalaya", "Mizoram",
        "Nagaland", "Tripura", "North Eastern"
    ],
    "80": ["Bihar"],
    "81": ["Bihar", "Jharkhand"],
    "82": ["Bihar", "Jharkhand"],
    "83": ["Jharkhand"],
    "84": ["Bihar"],
    "85": ["Bihar"]
}

_PINCODE_CACHE = {}
_GEOCODE_CACHE = {}
_NOMINATIM_LOCK = threading.Lock()
_LAST_NOMINATIM_REQ_TS = 0.0
NOMINATIM_USER_AGENT = "MatraNaariStorefront/1.0 (https://matranaari.com; support@naari.in)"
CACHE_TTL_SECONDS = 3600


def _normalize_state_name(name):
    s = str(name or "").strip().lower()
    s = s.replace("&", "and")
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    aliases = {
        "nct of delhi": "delhi",
        "new delhi": "delhi",
        "national capital territory of delhi": "delhi",
        "orissa": "odisha",
        "pondicherry": "puducherry",
        "uttaranchal": "uttarakhand"
    }
    return aliases.get(s, s)


def is_placeholder_text(val, min_alnum=2):
    s = str(val or "").strip().lower()
    if not s:
        return True
    alnum = re.sub(r"[^a-z0-9]", "", s)
    if len(alnum) < min_alnum:
        return True
    if len(alnum) >= 3 and len(set(alnum)) == 1:
        return True
    if s in PLACEHOLDER_TOKENS or alnum in PLACEHOLDER_TOKENS:
        return True
    # Reject sequential keyboard/alphabetical runs
    if alnum in ("abcdef", "abcdefg", "abcdefgh", "123456", "1234567", "654321", "qwertyuiop", "asdfghjkl"):
        return True
    words = [re.sub(r"[^a-z0-9]", "", w) for w in re.split(r"[\s,./\-_]+", s) if w]
    words = [w for w in words if w]
    if not words:
        return True
    for w in words:
        alpha_stem = re.sub(r"[0-9]+", "", w)
        if w in GIBBERISH_TOKENS or (alpha_stem and alpha_stem in GIBBERISH_TOKENS):
            return True
        if w.isalpha() and len(w) >= 3 and len(set(w)) == 1:
            return True
    if all((w in PLACEHOLDER_TOKENS or (len(w) >= 3 and len(set(w)) == 1)) for w in words):
        return True
    return False


def validate_indian_phone(phone):
    clean = str(phone or "").strip().replace(" ", "").replace("-", "")
    if clean.startswith("+91"):
        clean = clean[3:]
    elif clean.startswith("91") and len(clean) == 12:
        clean = clean[2:]
    elif clean.startswith("0") and len(clean) == 11:
        clean = clean[1:]
    if not (clean.isdigit() and len(clean) == 10):
        return None, "Please enter a valid 10-digit Indian mobile number."
    if clean[0] not in ("6", "7", "8", "9"):
        return None, "Please enter a valid 10-digit Indian mobile number starting with 6, 7, 8, or 9."
    if len(set(clean)) == 1 or clean in ("9876543211", "6789012345"):
        return None, "Please enter a genuine 10-digit mobile number."
    return clean, None


def validate_coordinates(lat, lon, require_both=False):
    lat_empty = lat is None or str(lat).strip() == ""
    lon_empty = lon is None or str(lon).strip() == ""
    if lat_empty and lon_empty:
        if require_both:
            return None, None, "Latitude and longitude coordinates are required."
        return None, None, None
    if lat_empty or lon_empty:
        return None, None, "Both latitude and longitude must be provided together."
    try:
        lat_f = float(lat)
        lon_f = float(lon)
    except (ValueError, TypeError):
        return None, None, "Invalid map coordinates format."
    if math.isnan(lat_f) or math.isnan(lon_f) or math.isinf(lat_f) or math.isinf(lon_f):
        return None, None, "Invalid map coordinates."
    if not (-90.0 <= lat_f <= 90.0 and -180.0 <= lon_f <= 180.0):
        return None, None, "Coordinates are out of global geographic range."
    # Delivery is within India bounds (approx lat 6.0 to 38.5 N, lon 68.0 to 98.0 E)
    if not (6.0 <= lat_f <= 38.5 and 68.0 <= lon_f <= 98.0):
        return None, None, "Selected map location is outside India delivery coverage."
    return round(lat_f, 6), round(lon_f, 6), None


def lookup_indian_pincode(pincode, use_external_api=True):
    clean_pin = str(pincode or "").strip().replace(" ", "")
    if not (clean_pin.isdigit() and len(clean_pin) == 6):
        return {
            "ok": False,
            "exists": False,
            "error": "Please enter a valid 6-digit Indian PIN code."
        }
    first_digit = int(clean_pin[0])
    if first_digit < 1 or first_digit > 8:
        return {
            "ok": False,
            "exists": False,
            "error": "PIN code is outside valid Indian postal circles (must start with 1–8)."
        }
    if len(set(clean_pin)) == 1 or clean_pin in ("123456", "654321") or clean_pin.endswith("0000"):
        return {
            "ok": False,
            "exists": False,
            "error": f"PIN code {clean_pin} is invalid or not assigned in India Post records."
        }

    prefix2 = clean_pin[:2]
    allowed_states = INDIAN_PIN_PREFIX_STATES.get(prefix2)
    if not allowed_states:
        return {
            "ok": False,
            "exists": False,
            "error": f"PIN code {clean_pin} does not belong to an active Indian postal circle."
        }

    now_ts = time.time()
    cached = _PINCODE_CACHE.get(clean_pin)
    if cached and (now_ts - cached["ts"] < CACHE_TTL_SECONDS):
        return dict(cached["data"])

    if use_external_api and os.environ.get("DISABLE_EXTERNAL_GEOCODING") != "1":
        try:
            resp = requests.get(
                f"https://api.postalpincode.in/pincode/{clean_pin}",
                headers={"User-Agent": NOMINATIM_USER_AGENT, "Accept": "application/json"},
                timeout=3.5
            )
            if resp.status_code == 200:
                payload = resp.json()
                if isinstance(payload, list) and len(payload) > 0:
                    entry = payload[0] or {}
                    status_str = str(entry.get("Status") or "").strip().lower()
                    post_offices = entry.get("PostOffice")
                    if status_str == "success" and isinstance(post_offices, list) and len(post_offices) > 0:
                        first_po = post_offices[0] or {}
                        district = str(first_po.get("District") or "").strip()
                        state = str(first_po.get("State") or "").strip()
                        region = str(first_po.get("Region") or first_po.get("Circle") or state).strip()
                        po_names = []
                        all_states = set(allowed_states)
                        all_districts = set()
                        for po in post_offices[:12]:
                            if po.get("Name"):
                                po_names.append(str(po["Name"]).strip())
                            if po.get("State"):
                                all_states.add(str(po["State"]).strip())
                            if po.get("District"):
                                all_districts.add(str(po["District"]).strip())
                        result = {
                            "ok": True,
                            "exists": True,
                            "pincode": clean_pin,
                            "district": district,
                            "state": state,
                            "region": region,
                            "allowed_states": list(all_states),
                            "districts": list(all_districts),
                            "post_offices": po_names,
                            "lookup_source": "india_post_api",
                            "provider_unavailable": False,
                            "residence_verified": False,
                            "verification_note": "PIN code postal circle, district, and state verified via India Post directory. Individual building or street residence is not verified by PIN lookup."
                        }
                        _PINCODE_CACHE[clean_pin] = {"ts": now_ts, "data": result}
                        return dict(result)
                    elif status_str in ("error", "404") or post_offices is None:
                        neg_result = {
                            "ok": False,
                            "exists": False,
                            "pincode": clean_pin,
                            "error": f"PIN code {clean_pin} was not found in India Post records. Please enter an existing 6-digit Indian PIN code."
                        }
                        _PINCODE_CACHE[clean_pin] = {"ts": now_ts, "data": neg_result}
                        return dict(neg_result)
        except Exception:
            pass

    # Fallback when external PIN directory API is unreachable/timed out
    fallback_result = {
        "ok": True,
        "exists": True,
        "pincode": clean_pin,
        "district": "",
        "state": allowed_states[0],
        "region": allowed_states[0],
        "allowed_states": list(allowed_states),
        "districts": [],
        "post_offices": [],
        "lookup_source": "postal_prefix_fallback",
        "provider_unavailable": True,
        "residence_verified": False,
        "verification_note": "Live PIN directory lookup is temporarily unavailable; validated Indian postal circle prefix only. Street address and residence are not verified."
    }
    return fallback_result


def _extract_nominatim_components(item):
    addr = (item or {}).get("address") or {}
    house_parts = []
    for k in ("house_number", "building", "apartment", "office", "shop", "amenity"):
        val = str(addr.get(k) or "").strip()
        if val and val not in house_parts:
            house_parts.append(val)
    house_no = ", ".join(house_parts[:2])

    street_parts = []
    for k in ("road", "pedestrian", "neighbourhood", "suburb", "quarter", "residential", "locality", "hamlet", "village", "industrial", "commercial"):
        val = str(addr.get(k) or "").strip()
        if val and val not in street_parts:
            street_parts.append(val)
    street_area = ", ".join(street_parts[:3])

    city = ""
    for k in ("city", "town", "municipality", "city_district", "state_district", "county"):
        val = str(addr.get(k) or "").strip()
        if val:
            city = val
            break

    state = str(addr.get("state") or "").strip()
    raw_postcode = re.sub(r"\s+", "", str(addr.get("postcode") or ""))
    pincode = raw_postcode if (raw_postcode.isdigit() and len(raw_postcode) == 6) else ""

    display_name = str(item.get("display_name") or "").strip()
    if not street_area and display_name:
        parts = [p.strip() for p in display_name.split(",") if p.strip()]
        if parts:
            street_area = ", ".join(parts[:2])

    try:
        lat_val = round(float(item.get("lat")), 6)
        lon_val = round(float(item.get("lon")), 6)
    except Exception:
        lat_val, lon_val = None, None

    return {
        "display_name": display_name,
        "house_no": house_no,
        "street_area": street_area,
        "city": city,
        "state": state,
        "pincode": pincode,
        "lat": lat_val,
        "lon": lon_val
    }


def _throttle_nominatim():
    global _LAST_NOMINATIM_REQ_TS
    with _NOMINATIM_LOCK:
        now = time.time()
        elapsed = now - _LAST_NOMINATIM_REQ_TS
        if elapsed < 1.05:
            time.sleep(1.05 - elapsed)
        _LAST_NOMINATIM_REQ_TS = time.time()


def validate_customer_info(cust, require_split_fields=False):
    if not cust or not isinstance(cust, dict):
        return "Customer information is required."

    name = str(cust.get("name", "")).strip()
    phone = str(cust.get("phone", "")).strip()
    email = str(cust.get("email", "")).strip()
    house_no = str(cust.get("house_no", "")).strip()
    street_area = str(cust.get("street_area", "")).strip()
    address1 = str(cust.get("address_line1", "")).strip()
    city = str(cust.get("city", "")).strip()
    state = str(cust.get("state", "")).strip()
    pincode = str(cust.get("pincode", "")).strip()

    if len(name) < 2 or not re.search(r"[A-Za-z]{2,}", name) or is_placeholder_text(name, min_alnum=2):
        return "Please enter a valid recipient full name."

    clean_phone, phone_err = validate_indian_phone(phone)
    if phone_err:
        return phone_err
    cust["phone"] = clean_phone

    if "@" not in email or "." not in email or len(email) < 5:
        return "Please enter a valid email address."
    email_local = email.split("@")[0].strip()
    if is_placeholder_text(email_local, min_alnum=2):
        return "Please enter a valid email address."

    if not house_no and not street_area and "," in address1:
        parts = [p.strip() for p in address1.split(",", 1)]
        house_no = parts[0]
        street_area = parts[1] if len(parts) > 1 else ""
        cust["house_no"] = house_no
        cust["street_area"] = street_area

    has_split = bool(house_no or street_area or require_split_fields)
    if has_split:
        if not house_no or is_placeholder_text(house_no, min_alnum=1):
            return "Please enter a valid House / Flat / Floor number."
        if len(street_area) < 3 or not re.search(r"[A-Za-z]{2,}", street_area) or is_placeholder_text(street_area, min_alnum=3):
            return "Please enter a valid Street / Area / Locality."
        if not address1:
            address1 = f"{house_no}, {street_area}"
            cust["address_line1"] = address1

    addr1_words = [w for w in re.split(r"[\s,./\-_]+", address1) if re.sub(r"[^A-Za-z0-9]", "", w)]
    if len(address1) < 5 or len(addr1_words) < 2 or not re.search(r"[A-Za-z]{2,}", address1) or is_placeholder_text(address1, min_alnum=4):
        return "Please enter your complete delivery street address (placeholder values are not allowed)."

    address2 = str(cust.get("address_line2", "")).strip()
    if address2 and is_placeholder_text(address2, min_alnum=2):
        return "Please enter a valid landmark or leave the optional field blank."

    if len(city) < 2 or not re.search(r"[A-Za-z]{2,}", city) or city.isdigit() or is_placeholder_text(city, min_alnum=2):
        return "Please enter a valid city or district name."

    if len(state) < 2 or not re.search(r"[A-Za-z]{2,}", state) or is_placeholder_text(state, min_alnum=2):
        return "Please select a valid state."

    pin_info = lookup_indian_pincode(pincode)
    if not pin_info.get("ok"):
        return pin_info.get("error") or "Please enter a valid 6-digit Indian PIN code."

    clean_pin = pin_info["pincode"]
    cust["pincode"] = clean_pin

    # Compare submitted state with the PIN code's postal state(s)
    norm_submitted_state = _normalize_state_name(state)
    allowed_norm_states = {_normalize_state_name(s) for s in (pin_info.get("allowed_states") or []) if s}
    if pin_info.get("state"):
        allowed_norm_states.add(_normalize_state_name(pin_info["state"]))

    if allowed_norm_states and norm_submitted_state not in allowed_norm_states:
        expected_state_label = pin_info.get("state") or (pin_info.get("allowed_states") or ["another state"])[0]
        return f"PIN code {clean_pin} belongs to {expected_state_label}, which does not match the selected state '{state}'."

    # Validate coordinates if supplied
    lat_f, lon_f, coord_err = validate_coordinates(cust.get("latitude"), cust.get("longitude"), require_both=False)
    if coord_err:
        return coord_err
    cust["latitude"] = lat_f
    cust["longitude"] = lon_f

    return None

def get_current_user():
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "user_token" in request.cookies:
        token = (request.cookies.get("user_token") or "").strip()

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


def user_owns_order(user, order_row):
    if not user or not order_row:
        return False
    order_user_id = str(order_row.get("user_id") or "").strip()
    if order_user_id:
        return order_user_id == str(user.get("id") or "").strip()
    order_email = str(order_row.get("customer_email") or "").strip().lower()
    user_email = str(user.get("email") or "").strip().lower()
    return bool(order_email and user_email and order_email == user_email)


def is_request_https():
    if request.is_secure:
        return True
    xf_proto = request.headers.get("X-Forwarded-Proto", "")
    if any(p.strip().lower() == "https" for p in xf_proto.split(",") if p.strip()):
        return True
    if request.headers.get("X-Forwarded-Ssl", "").strip().lower() == "on":
        return True
    return False


def set_customer_auth_cookie(resp, token):
    is_https = is_request_https()
    resp.set_cookie(
        "user_token",
        token,
        max_age=30 * 86400,
        httponly=True,
        secure=is_https,
        samesite="Lax",
        path="/"
    )
    return resp


def set_admin_auth_cookie(resp, token):
    is_https = is_request_https()
    resp.set_cookie(
        "naari_admin_token",
        token,
        max_age=86400,
        httponly=True,
        secure=is_https,
        samesite="Lax",
        path="/"
    )
    return resp


def clear_admin_auth_cookie(resp):
    is_https = is_request_https()
    resp.delete_cookie(
        "naari_admin_token",
        path="/",
        samesite="Lax",
        secure=is_https,
        httponly=True
    )
    return resp

def get_expected_admin_passkey():
    for env_name in ("ADMIN_SECRET_KEY", "ADMIN_PASSKEY", "ADMIN_PASSWORD"):
        raw_val = os.environ.get(env_name)
        if raw_val is not None:
            cleaned = raw_val.strip().strip('"').strip("'")
            if cleaned:
                return cleaned
    cfg = load_config()
    cfg_val = str(cfg.get("admin_secret_key") or cfg.get("admin_passkey") or "").strip().strip('"').strip("'")
    if cfg_val:
        return cfg_val
    return ""


def is_admin_passkey_configured():
    """
    Safely checks whether an administrative passkey is configured via environment variables,
    .env / config.json, or a hashed passkey in site_settings — without exposing any secret value.
    """
    if bool(get_expected_admin_passkey()):
        return True
    settings = get_site_settings_dict()
    stored_hash = str(settings.get("admin_passkey_hash") or "").strip()
    stored_salt = str(settings.get("admin_passkey_salt") or "").strip()
    return bool(stored_hash and stored_salt)


def get_admin_auth_config_status():
    """
    Returns non-sensitive metadata describing whether admin authentication is configured
    and which source(s) are active, never returning or logging secret values.
    """
    has_env = any(
        bool((os.environ.get(k) or "").strip().strip('"').strip("'"))
        for k in ("ADMIN_SECRET_KEY", "ADMIN_PASSKEY", "ADMIN_PASSWORD")
    )
    cfg = load_config()
    has_cfg_or_dotenv = bool(
        str(cfg.get("admin_secret_key") or cfg.get("admin_passkey") or "").strip().strip('"').strip("'")
    )
    settings = get_site_settings_dict()
    has_db_hash = bool(
        str(settings.get("admin_passkey_hash") or "").strip()
        and str(settings.get("admin_passkey_salt") or "").strip()
    )
    configured = bool(has_env or has_cfg_or_dotenv or has_db_hash)
    sources = []
    if has_env:
        sources.append("env")
    if has_cfg_or_dotenv and not has_env:
        sources.append("config_or_dotenv")
    if has_db_hash:
        sources.append("site_settings_hash")
    return {
        "is_admin_configured": configured,
        "env_configured": has_env,
        "config_or_dotenv_configured": has_cfg_or_dotenv,
        "db_hash_configured": has_db_hash,
        "configured_sources": sources
    }

def verify_admin_passkey_value(candidate):
    if not candidate:
        return False
    cand = str(candidate).strip()
    expected_env_key = get_expected_admin_passkey()
    if expected_env_key and hmac.compare_digest(cand.encode("utf-8"), expected_env_key.encode("utf-8")):
        return True
    settings = get_site_settings_dict()
    stored_hash = str(settings.get("admin_passkey_hash") or "").strip()
    stored_salt = str(settings.get("admin_passkey_salt") or "").strip()
    if stored_hash and stored_salt:
        return verify_password(cand, stored_salt, stored_hash)
    return False

def check_admin_auth():
    # 1. Check session tokens (X-Admin-Token, Authorization: Bearer, and HttpOnly cookie)
    candidate_tokens = []
    hdr_admin_tok = request.headers.get("X-Admin-Token", "").strip()
    if hdr_admin_tok:
        candidate_tokens.append(hdr_admin_tok)
    auth_hdr = request.headers.get("Authorization", "").strip()
    if auth_hdr.startswith("Bearer "):
        bearer_tok = auth_hdr[7:].strip()
        if bearer_tok and bearer_tok not in candidate_tokens:
            candidate_tokens.append(bearer_tok)
    if "naari_admin_token" in request.cookies:
        cookie_tok = request.cookies.get("naari_admin_token", "").strip()
        if cookie_tok and cookie_tok not in candidate_tokens:
            candidate_tokens.append(cookie_tok)

    if candidate_tokens:
        try:
            conn = get_db()
            c = conn.cursor()
            now_iso = datetime.now().isoformat()
            for tok in candidate_tokens:
                c.execute("SELECT token FROM admin_sessions WHERE token = ? AND expires_at > ?", (tok, now_iso))
                if c.fetchone():
                    conn.close()
                    return True
            conn.close()
        except Exception:
            pass

    # 2. Check passkey header, query arg, JSON payload, or form body
    passkey = request.headers.get("X-Admin-Passkey", "").strip() or request.args.get("passkey", "").strip()
    if not passkey:
        body = request.get_json(silent=True) or {}
        if isinstance(body, dict):
            passkey = str(body.get("passkey", "")).strip()
    if not passkey and request.form:
        passkey = str(request.form.get("passkey", "")).strip()

    return verify_admin_passkey_value(passkey)

# ================= Initialize Flask App =================
app = Flask(__name__, static_folder=BASE_DIR)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.url_map.strict_slashes = False
CORS(app, resources={r"/*": {"origins": "*"}})


@app.before_request
def enforce_max_content_length():
    max_len = app.config.get("MAX_CONTENT_LENGTH")
    content_len = request.content_length
    if max_len and content_len is not None and content_len > max_len:
        return jsonify({
            "ok": False,
            "error": "Request payload exceeds the maximum allowed size of 6MB."
        }), 413


@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(_err):
    return jsonify({
        "ok": False,
        "error": "Request payload exceeds the maximum allowed size of 6MB."
    }), 413

init_db()
_startup_cfg = load_config()
_admin_cfg_status = get_admin_auth_config_status()
print(
    f"[Razorpay Startup] is_razorpay_configured={is_razorpay_configured(_startup_cfg)}, "
    f"key_id={mask_key_id(_startup_cfg.get('razorpay_key_id'))} | "
    f"[Admin Auth] is_admin_configured={_admin_cfg_status['is_admin_configured']}, "
    f"custom_env_passkey_configured={_admin_cfg_status['env_configured']}, "
    f"sources={_admin_cfg_status['configured_sources'] or ['none']}",
    flush=True
)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers.pop("Access-Control-Allow-Credentials", None)
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Admin-Passkey, X-Admin-Token"
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
    gmaps_configured = is_google_maps_configured(cfg)
    admin_status = get_admin_auth_config_status()
    return jsonify({
        "ok": True,
        "razorpay_key_id": cfg.get("razorpay_key_id", "") if configured else "",
        "is_razorpay_configured": configured,
        "google_maps_api_key": cfg.get("google_maps_api_key", "") if gmaps_configured else "",
        "google_maps_map_id": cfg.get("google_maps_map_id", "") if gmaps_configured else "",
        "is_google_maps_configured": gmaps_configured,
        "google_maps_billing_safeguards": {
            "session_token_enabled": True,
            "country_restriction": "IN",
            "debounce_ms": 380,
            "min_query_length": 3,
            "max_requests_per_session": 25,
            "fields_mask": ["id", "displayName", "formattedAddress", "location", "addressComponents"],
            "fallback_provider": "openstreetmap_nominatim"
        },
        "is_admin_configured": admin_status["is_admin_configured"],
        "store_name": cfg.get("store_name", "Matra Naari"),
        "store_description": cfg.get("store_description", "Modern Kurtis Rooted in Craft"),
        "currency": cfg.get("currency", "INR"),
        "support_phone": cfg.get("support_phone", "+91 88493 66915"),
        "support_email": cfg.get("support_email", "hello@naari.in"),
        "free_shipping_threshold": int(cfg.get("free_shipping_threshold", 999)),
        "shipping_fee": int(cfg.get("shipping_fee", 99)),
        "cod_enabled": bool(cfg.get("cod_enabled", True)),
        "sales_enabled": bool(cfg.get("sales_enabled", True)),
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
    include_archived = (request.args.get("include_archived", "").strip() == "1") and check_admin_auth()

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
    if not prod or (prod.get("is_archived", 0) and not check_admin_auth()):
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

    computed_items = None
    subtotal = 0

    if items is not None:
        if not isinstance(items, list) or len(items) == 0:
            return jsonify({"ok": False, "error": "Shopping bag is empty."}), 400
        calc_items = []
        calc_sub = 0
        for it in items:
            if not isinstance(it, dict):
                return jsonify({"ok": False, "error": "Invalid item in shopping bag."}), 400
            pid = str(it.get("id", "")).strip()
            if not pid:
                return jsonify({"ok": False, "error": "Invalid product ID in shopping bag."}), 400
            qty = _parse_strict_item_qty(it.get("qty", 1))
            if qty is None:
                return jsonify({"ok": False, "error": "Invalid quantity."}), 400
            prod = get_product_from_db(pid)
            if not prod:
                return jsonify({"ok": False, "error": f"Unrecognized product: {pid}"}), 400
            if int(prod.get("stock", 0)) <= 0 or prod.get("is_archived", 0):
                return jsonify({"ok": False, "error": f"Sorry, '{prod['name']}' is currently out of stock."}), 400
            price = int(prod["price"])
            cat = str(prod.get("category") or "")
            item_sub = price * qty
            calc_sub += item_sub
            calc_items.append({"id": pid, "category": cat, "qty": qty, "price": price, "subtotal": item_sub})
        subtotal = calc_sub
        computed_items = calc_items
    else:
        try:
            subtotal = int(data.get("subtotal", 0))
        except (ValueError, TypeError):
            subtotal = 0

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
        "discount_value": int(cp.get("discount_value") or 0),
        "discount_amount": discount,
        "min_order_value": int(cp.get("min_order_value") or 0),
        "max_discount": int(cp.get("max_discount") or 0),
        "applicable_categories": str(cp.get("applicable_categories") or ""),
        "applicable_products": str(cp.get("applicable_products") or ""),
        "start_date": str(cp.get("start_date") or ""),
        "expiry_date": str(cp.get("expiry_date") or ""),
        "usage_limit": int(cp.get("usage_limit") or 0),
        "used_count": int(cp.get("used_count") or 0),
        "is_active": int(cp.get("is_active") or 0),
        "description": str(cp.get("description") or ""),
        "subtotal": subtotal,
        "subtotal_snapshot": subtotal,
        "shipping": shipping,
        "free_shipping_threshold": free_threshold,
        "final_total": final_total,
        "message": f"Coupon '{cp['code']}' applied! You save ₹{discount:,}."
    })

@app.route("/api/check-pincode", methods=["POST"])
def api_check_pincode():
    data = request.get_json(silent=True) or {}
    pin = str(data.get("pincode", "")).strip()

    pin_info = lookup_indian_pincode(pin)
    if not pin_info.get("ok"):
        return jsonify({
            "ok": False,
            "serviceable": False,
            "error": pin_info.get("error") or "Please enter a valid 6-digit Indian PIN code."
        }), 400

    clean_pin = pin_info["pincode"]
    first_digit = int(clean_pin[0])

    cfg = load_config()
    cod_enabled = bool(cfg.get("cod_enabled", True))
    free_threshold = int(cfg.get("free_shipping_threshold", 999))
    shipping_fee = int(cfg.get("shipping_fee", 99))

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
    if pin_info.get("district") and pin_info.get("state"):
        region_name = f"{pin_info['district']}, {pin_info['state']}"

    now = datetime.now()
    est_start = now + timedelta(days=min_days)
    est_end = now + timedelta(days=max_days)
    est_str = f"{est_start.strftime('%a, %d %b')} – {est_end.strftime('%a, %d %b')}"

    return jsonify({
        "ok": True,
        "pincode": clean_pin,
        "district": pin_info.get("district", ""),
        "state": pin_info.get("state", ""),
        "allowed_states": pin_info.get("allowed_states", []),
        "post_offices": pin_info.get("post_offices", []),
        "lookup_source": pin_info.get("lookup_source", "postal_prefix_fallback"),
        "provider_unavailable": bool(pin_info.get("provider_unavailable")),
        "residence_verified": False,
        "verification_note": pin_info.get("verification_note", ""),
        "region": region_name,
        "serviceable": True,
        "cod_available": cod_enabled,
        "free_delivery": True,
        "free_shipping_threshold": free_threshold,
        "shipping_fee": shipping_fee,
        "estimated_delivery": est_str,
        "courier_mode": "postal_circle_estimate",
        "message": f"Delivery available to {clean_pin} ({region_name}). Estimated arrival: {est_str}."
    })


@app.route("/api/address/pincode/<pincode>", methods=["GET"])
def api_address_pincode_lookup(pincode):
    pin_info = lookup_indian_pincode(pincode)
    if not pin_info.get("ok"):
        return jsonify({
            "ok": False,
            "exists": False,
            "error": pin_info.get("error") or "Invalid PIN code."
        }), 400
    return jsonify(pin_info)


@app.route("/api/address/autocomplete", methods=["GET"])
def api_address_autocomplete():
    q = str(request.args.get("q", "")).strip()
    if len(q) < 3:
        return jsonify({
            "ok": False,
            "suggestions": [],
            "error": "Please type at least 3 characters to search for an address."
        }), 400

    if is_placeholder_text(q, min_alnum=2):
        return jsonify({
            "ok": True,
            "query": q,
            "suggestions": [],
            "attribution": "© OpenStreetMap contributors (ODbL)",
            "message": "No matching locations found for that search."
        })

    cache_key = f"search:{q.lower()}"
    now_ts = time.time()
    cached = _GEOCODE_CACHE.get(cache_key)
    if cached and (now_ts - cached["ts"] < CACHE_TTL_SECONDS):
        return jsonify(cached["data"])

    if os.environ.get("DISABLE_EXTERNAL_GEOCODING") == "1":
        return jsonify({
            "ok": False,
            "provider_unavailable": True,
            "suggestions": [],
            "error": "Live address search is currently unavailable. Please enter your address manually or adjust the map pin."
        }), 503

    try:
        _throttle_nominatim()
        resp = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={
                "q": q,
                "format": "jsonv2",
                "addressdetails": 1,
                "countrycodes": "in",
                "limit": 5
            },
            headers={
                "User-Agent": NOMINATIM_USER_AGENT,
                "Accept": "application/json",
                "Accept-Language": "en-IN,en;q=0.9"
            },
            timeout=5
        )
        if resp.status_code != 200:
            return jsonify({
                "ok": False,
                "provider_unavailable": True,
                "suggestions": [],
                "error": "Address search service (OpenStreetMap Nominatim) is temporarily busy. Please type your address manually below."
            }), 503

        raw_list = resp.json()
        suggestions = []
        if isinstance(raw_list, list):
            for item in raw_list[:5]:
                parsed = _extract_nominatim_components(item)
                if parsed["display_name"] and parsed["lat"] is not None and parsed["lon"] is not None:
                    suggestions.append(parsed)

        payload = {
            "ok": True,
            "query": q,
            "suggestions": suggestions,
            "attribution": "© OpenStreetMap contributors (ODbL)",
            "residence_verified": False,
            "verification_note": "Suggestions are provided by OpenStreetMap Nominatim for convenience and do not verify individual residence existence."
        }
        _GEOCODE_CACHE[cache_key] = {"ts": now_ts, "data": payload}
        return jsonify(payload)
    except Exception:
        return jsonify({
            "ok": False,
            "provider_unavailable": True,
            "suggestions": [],
            "error": "Unable to reach the live address search service right now. Please enter your address details manually."
        }), 503


@app.route("/api/address/reverse", methods=["GET"])
def api_address_reverse():
    raw_lat = request.args.get("lat")
    raw_lon = request.args.get("lon")
    lat_f, lon_f, coord_err = validate_coordinates(raw_lat, raw_lon, require_both=True)
    if coord_err:
        return jsonify({"ok": False, "error": coord_err}), 400

    cache_key = f"rev:{round(lat_f, 4)}:{round(lon_f, 4)}"
    now_ts = time.time()
    cached = _GEOCODE_CACHE.get(cache_key)
    if cached and (now_ts - cached["ts"] < CACHE_TTL_SECONDS):
        return jsonify(cached["data"])

    if os.environ.get("DISABLE_EXTERNAL_GEOCODING") == "1":
        return jsonify({
            "ok": False,
            "provider_unavailable": True,
            "lat": lat_f,
            "lon": lon_f,
            "error": "Reverse geocoding is currently unavailable. Map coordinates are recorded; please enter your street and PIN code manually."
        }), 503

    try:
        _throttle_nominatim()
        resp = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={
                "lat": lat_f,
                "lon": lon_f,
                "format": "jsonv2",
                "addressdetails": 1,
                "zoom": 18
            },
            headers={
                "User-Agent": NOMINATIM_USER_AGENT,
                "Accept": "application/json",
                "Accept-Language": "en-IN,en;q=0.9"
            },
            timeout=5
        )
        if resp.status_code != 200:
            return jsonify({
                "ok": False,
                "provider_unavailable": True,
                "lat": lat_f,
                "lon": lon_f,
                "error": "Reverse geocoding service is temporarily unavailable. Map coordinates are saved; please fill in your address fields below."
            }), 503

        item = resp.json() or {}
        if item.get("error"):
            return jsonify({
                "ok": False,
                "lat": lat_f,
                "lon": lon_f,
                "error": "No street address found at the selected map point. Please enter your address details manually."
            }), 404

        parsed = _extract_nominatim_components(item)
        parsed["lat"] = lat_f
        parsed["lon"] = lon_f
        payload = {
            "ok": True,
            "lat": lat_f,
            "lon": lon_f,
            "display_name": parsed["display_name"],
            "address": parsed,
            "attribution": "© OpenStreetMap contributors (ODbL)",
            "residence_verified": False,
            "verification_note": "Reverse-geocoded map location indicates approximate locality only. Please verify your exact house/flat number and 6-digit PIN code."
        }
        _GEOCODE_CACHE[cache_key] = {"ts": now_ts, "data": payload}
        return jsonify(payload)
    except Exception:
        return jsonify({
            "ok": False,
            "provider_unavailable": True,
            "lat": lat_f,
            "lon": lon_f,
            "error": "Unable to reverse-geocode this map location right now. Your pin coordinates are saved; please enter your address fields manually."
        }), 503

@app.route("/api/newsletter", methods=["POST"])
def api_newsletter():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    if "@" not in email or "." not in email or len(email) < 5:
        return jsonify({"ok": False, "error": "Please enter a valid email address."}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO newsletter_subscribers (email, created_at) VALUES (?, ?) ON CONFLICT (email) DO NOTHING",
        (email, datetime.now().isoformat()),
    )
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

    if "@" not in email or "." not in email or len(email) < 5:
        return jsonify({"ok": False, "error": "Please enter a valid email address."}), 400
    if not name:
        name = email.split("@")[0].replace(".", " ").replace("_", " ").title()
    if len(name) < 2:
        return jsonify({"ok": False, "error": "Please enter your name."}), 400
    if phone:
        clean_phone = phone.replace(" ", "").replace("-", "")
        if clean_phone.startswith("+91"):
            clean_phone = clean_phone[3:]
        elif clean_phone.startswith("91") and len(clean_phone) == 12:
            clean_phone = clean_phone[2:]
        if not (clean_phone.isdigit() and len(clean_phone) == 10):
            return jsonify({"ok": False, "error": "Please enter a valid 10-digit mobile number."}), 400
        phone = clean_phone
    if len(password) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters long."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE LOWER(email) = ?", (email,))
    if c.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": "An account with this email already exists. Please log in."}), 400

    user_id = f"usr_{secrets.token_hex(6)}"
    pw_hash, salt = hash_password(password)
    now_iso = datetime.now().isoformat()

    try:
        c.execute("""
            INSERT INTO users (id, name, email, phone, password_hash, salt, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, name, email, phone, pw_hash, salt, now_iso))
    except DB_INTEGRITY_ERRORS:
        try:
            conn.rollback()
        except Exception:
            pass
        conn.close()
        return jsonify({"ok": False, "error": "An account with this email already exists. Please log in."}), 400

    # Associate any pre-existing unlinked orders placed with this email
    c.execute("""
        UPDATE orders
        SET user_id = ?
        WHERE (user_id IS NULL OR user_id = '') AND LOWER(customer_email) = ?
    """, (user_id, email))

    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    c.execute("INSERT INTO user_sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
              (token, user_id, now_iso, expires))
    conn.commit()
    conn.close()

    resp = jsonify({
        "ok": True,
        "token": token,
        "user": {
            "id": user_id,
            "name": name,
            "email": email,
            "phone": phone
        }
    })
    return set_customer_auth_cookie(resp, token)

@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", "")).strip()

    if not email or not password:
        return jsonify({"ok": False, "error": "Email and password are required."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE LOWER(email) = ?", (email,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Invalid email or password."}), 401

    user = dict(row)
    if not verify_password(password, user["salt"], user["password_hash"]):
        conn.close()
        return jsonify({"ok": False, "error": "Invalid email or password."}), 401

    token = secrets.token_hex(32)
    now_iso = datetime.now().isoformat()
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    c.execute("DELETE FROM user_sessions WHERE expires_at <= ?", (now_iso,))
    c.execute("INSERT INTO user_sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
              (token, user["id"], now_iso, expires))
    conn.commit()
    conn.close()

    resp = jsonify({
        "ok": True,
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "phone": user["phone"]
        }
    })
    return set_customer_auth_cookie(resp, token)

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
    resp = jsonify({"ok": True, "message": "Logged out successfully."})
    resp.delete_cookie("user_token", path="/", samesite="Lax")
    return resp

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
    phone = str(data.get("phone", "")).strip() if "phone" in data else user["phone"]
    if len(name) < 2:
        return jsonify({"ok": False, "error": "Please enter a valid name."}), 400
    if phone:
        clean_phone = phone.replace(" ", "").replace("-", "")
        if clean_phone.startswith("+91"):
            clean_phone = clean_phone[3:]
        elif clean_phone.startswith("91") and len(clean_phone) == 12:
            clean_phone = clean_phone[2:]
        if not (clean_phone.isdigit() and len(clean_phone) == 10):
            return jsonify({"ok": False, "error": "Please enter a valid 10-digit mobile number."}), 400
        phone = clean_phone
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET name = ?, phone = ? WHERE id = ?", (name, phone, user["id"]))
    conn.commit()
    conn.close()
    user["name"] = name
    user["phone"] = phone
    return jsonify({"ok": True, "user": user, "message": "Profile updated successfully."})

def upsert_customer_address(c, user_id, cust_data, is_default=False):
    name = str(cust_data.get("name", "")).strip()
    phone = str(cust_data.get("phone", "")).strip()
    house_no = str(cust_data.get("house_no", "")).strip()
    street_area = str(cust_data.get("street_area", "")).strip()
    address1 = str(cust_data.get("address_line1", "")).strip()
    if not address1 and house_no and street_area:
        address1 = f"{house_no}, {street_area}"
    address2 = str(cust_data.get("address_line2", "")).strip()
    city = str(cust_data.get("city", "")).strip()
    state = str(cust_data.get("state", "")).strip()
    pincode = str(cust_data.get("pincode", "")).strip()
    lat_val = cust_data.get("latitude")
    lon_val = cust_data.get("longitude")
    location_summary = str(cust_data.get("location_summary", "")).strip()
    address_label = str(cust_data.get("address_label") or "Home").strip() or "Home"
    if address_label not in ("Home", "Work", "Other"):
        address_label = "Home"

    # Check if an identical address_line1 + pincode already exists for this user
    c.execute("""
        SELECT id, is_default FROM user_addresses
        WHERE user_id = ? AND LOWER(address_line1) = LOWER(?) AND pincode = ?
        LIMIT 1
    """, (user_id, address1, pincode))
    existing = c.fetchone()
    now_iso = datetime.now().isoformat()

    if is_default:
        c.execute("UPDATE user_addresses SET is_default = 0 WHERE user_id = ?", (user_id,))

    if existing:
        addr_id = existing["id"]
        keep_default = 1 if (is_default or existing["is_default"]) else 0
        c.execute("""
            UPDATE user_addresses
            SET name = ?, phone = ?, address_line1 = ?, address_line2 = ?,
                city = ?, state = ?, pincode = ?, is_default = ?,
                house_no = ?, street_area = ?, latitude = ?, longitude = ?,
                location_summary = ?, address_label = ?
            WHERE id = ? AND user_id = ?
        """, (
            name, phone, address1, address2,
            city, state, pincode, keep_default,
            house_no, street_area, lat_val, lon_val,
            location_summary, address_label,
            addr_id, user_id
        ))
        return addr_id

    addr_id = f"addr_{secrets.token_hex(4)}"
    c.execute("""
        INSERT INTO user_addresses (
            id, user_id, name, phone, address_line1, address_line2,
            city, state, pincode, is_default, created_at,
            house_no, street_area, latitude, longitude, location_summary, address_label
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        addr_id, user_id, name, phone, address1, address2,
        city, state, pincode, 1 if is_default else 0, now_iso,
        house_no, street_area, lat_val, lon_val, location_summary, address_label
    ))
    return addr_id


@app.route("/api/address/validate", methods=["POST"])
def api_address_validate():
    user = get_current_user()
    if not user:
        return jsonify({
            "ok": False,
            "error": "Authentication required to confirm a delivery address.",
            "auth_required": True
        }), 401

    data = request.get_json(silent=True) or {}
    cust = dict(data.get("address") or data)
    cust["name"] = str(cust.get("name", "")).strip() or user.get("name", "")
    cust["email"] = str(cust.get("email", "")).strip() or user.get("email", "")
    cust["phone"] = str(cust.get("phone", "")).strip() or user.get("phone", "")

    require_split = bool(data.get("require_split_fields", True))
    err = validate_customer_info(cust, require_split_fields=require_split)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    pin_info = lookup_indian_pincode(cust.get("pincode"))
    save_to_account = bool(data.get("save_to_account", True))
    is_default = bool(data.get("is_default", True))
    saved_id = None
    addrs = []

    if save_to_account:
        conn = get_db()
        c = conn.cursor()
        saved_id = upsert_customer_address(c, user["id"], cust, is_default=is_default)
        conn.commit()
        c.execute("SELECT * FROM user_addresses WHERE user_id = ? ORDER BY is_default DESC, created_at DESC", (user["id"],))
        addrs = [dict(r) for r in c.fetchall()]
        conn.close()

    return jsonify({
        "ok": True,
        "confirmed": True,
        "address_id": saved_id,
        "address": {
            "name": cust.get("name"),
            "phone": cust.get("phone"),
            "email": cust.get("email"),
            "house_no": cust.get("house_no", ""),
            "street_area": cust.get("street_area", ""),
            "address_line1": cust.get("address_line1", ""),
            "address_line2": cust.get("address_line2", ""),
            "city": cust.get("city", ""),
            "state": cust.get("state", ""),
            "pincode": cust.get("pincode", ""),
            "latitude": cust.get("latitude"),
            "longitude": cust.get("longitude"),
            "location_summary": str(cust.get("location_summary", "")).strip(),
            "address_label": str(cust.get("address_label") or "Home").strip()
        },
        "pincode_info": {
            "district": pin_info.get("district", ""),
            "state": pin_info.get("state", ""),
            "lookup_source": pin_info.get("lookup_source", ""),
            "residence_verified": False,
            "verification_note": pin_info.get("verification_note", "")
        },
        "addresses": addrs,
        "message": "Delivery address validated and saved to your account."
    })


@app.route("/api/customer/addresses", methods=["GET", "POST"])
def api_customer_addresses():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        cust = {
            "name": str(data.get("name", "")).strip() or user["name"],
            "phone": str(data.get("phone", "")).strip() or user["phone"],
            "email": str(data.get("email", "")).strip() or user["email"],
            "house_no": str(data.get("house_no", "")).strip(),
            "street_area": str(data.get("street_area", "")).strip(),
            "address_line1": str(data.get("address_line1", "")).strip(),
            "address_line2": str(data.get("address_line2", "")).strip(),
            "city": str(data.get("city", "")).strip(),
            "state": str(data.get("state", "")).strip(),
            "pincode": str(data.get("pincode", "")).strip(),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "location_summary": str(data.get("location_summary", "")).strip(),
            "address_label": str(data.get("address_label") or "Home").strip()
        }
        err = validate_customer_info(cust, require_split_fields=False)
        if err:
            conn.close()
            return jsonify({"ok": False, "error": err}), 400

        is_default = bool(data.get("is_default"))
        upsert_customer_address(c, user["id"], cust, is_default=is_default)
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
    if not user:
        return jsonify({
            "ok": False,
            "error": "Authentication required. Please log in to view your orders.",
            "auth_required": True
        }), 401

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM orders
        WHERE user_id = ?
           OR ((user_id IS NULL OR user_id = '') AND LOWER(customer_email) = LOWER(?))
        ORDER BY created_at DESC
    """, (user["id"], user["email"]))
    rows = c.fetchall()
    conn.close()

    orders = []
    for r in rows:
        od = dict(r)
        od["items"] = json.loads(od.pop("items_json", "[]"))
        od.pop("razorpay_signature", None)
        orders.append(od)

    return jsonify({"ok": True, "orders": orders})

@app.route("/api/customer/orders/cancel", methods=["POST"])
def api_customer_order_cancel():
    user = get_current_user()
    if not user:
        return jsonify({
            "ok": False,
            "error": "Authentication required. Please log in to manage your orders.",
            "auth_required": True
        }), 401

    data = request.get_json(silent=True) or {}
    order_id = str(data.get("order_id", "")).strip()
    reason = str(data.get("reason", "Cancelled by customer")).strip()

    if not order_id:
        return jsonify({"ok": False, "error": "Order ID is required."}), 400

    conn = get_db()
    conn.isolation_level = None
    c = conn.cursor()
    try:
        c.execute("BEGIN IMMEDIATE")
        lock_clause = _for_update_clause(c)
        c.execute(f"SELECT * FROM orders WHERE id = ?{lock_clause}", (order_id,))
        row = c.fetchone()
        if not row:
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": "Order not found."}), 404

        od = dict(row)
        if not user_owns_order(user, od):
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": "Access denied. You can only cancel your own orders."}), 403

        curr_status = (od.get("order_status") or "confirmed").strip().lower()
        if curr_status in ("shipped", "out_for_delivery", "out for delivery", "delivered", "cancelled"):
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": f"Order cannot be cancelled once it is '{curr_status}'."}), 400

        c.execute("""
            SELECT id, status FROM return_requests
            WHERE order_id = ?
              AND LOWER(COALESCE(status, '')) IN ('picked_up', 'picked up', 'pickup_scheduled', 'pickup scheduled', 'completed', 'refunded', 'completed / refunded')
            LIMIT 1
        """, (order_id,))
        progressed_ret = c.fetchone()
        if progressed_ret:
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": "Order cannot be cancelled because a return or exchange is already picked up, completed, or refunded."}), 400

        now_iso = datetime.now().isoformat()
        c.execute("""
            UPDATE orders
            SET order_status = 'cancelled',
                payment_status = CASE
                    WHEN LOWER(COALESCE(payment_method, '')) != 'cod' AND LOWER(COALESCE(payment_status, '')) = 'pending'
                    THEN 'cancelled'
                    ELSE payment_status
                END,
                updated_at = ?
            WHERE id = ?
              AND LOWER(COALESCE(order_status, 'confirmed')) NOT IN ('cancelled', 'shipped', 'out_for_delivery', 'out for delivery', 'delivered')
        """, (now_iso, order_id))
        if c.rowcount != 1:
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": f"Order cannot be cancelled once it is '{curr_status}'."}), 400

        c.execute("""
            UPDATE return_requests
            SET status = 'rejected',
                updated_at = ?
            WHERE order_id = ?
              AND LOWER(COALESCE(status, '')) IN ('pending', 'requested', 'approved')
        """, (now_iso, order_id))

        restore_cancelled_order_resources(c, od)
        c.execute("COMMIT")
    except Exception:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        conn.close()
        return jsonify({"ok": False, "error": "Failed to cancel order. Please try again."}), 500

    conn.close()
    return jsonify({
        "ok": True,
        "order_id": order_id,
        "order_status": "cancelled",
        "message": f"Order {order_id} has been cancelled ({reason})."
    })

RETURN_STATUS_MAP = {
    "pending": "requested",
    "requested": "requested",
    "approved": "approved",
    "picked_up": "picked_up",
    "picked up": "picked_up",
    "pickup_scheduled": "picked_up",
    "pickup scheduled": "picked_up",
    "completed": "completed",
    "refunded": "refunded",
    "completed / refunded": "refunded",
    "rejected": "rejected",
    "cancelled": "rejected",
}

ALLOWED_RETURN_TRANSITIONS = {
    "requested": {"requested", "approved", "rejected"},
    "approved": {"approved", "picked_up", "rejected"},
    "picked_up": {"picked_up", "completed", "refunded"},
    "completed": {"completed", "refunded"},
    "refunded": {"refunded"},
    "rejected": {"rejected"},
}


def normalize_return_status(raw_status):
    clean = str(raw_status or "").strip().lower()
    return RETURN_STATUS_MAP.get(clean)


@app.route("/api/customer/returns", methods=["POST", "GET"])
def api_customer_returns():
    user = get_current_user()
    if not user:
        return jsonify({
            "ok": False,
            "error": "Authentication required. Please log in to access returns and exchanges.",
            "auth_required": True
        }), 401

    if request.method == "POST":
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            data = {}
        order_id = str(data.get("order_id", "")).strip()
        email = user["email"].strip().lower()
        phone = str(data.get("customer_phone") or user.get("phone") or "").strip()
        item_name = str(data.get("item_name", "")).strip()
        action_type = str(data.get("action_type") or data.get("request_type") or "return").strip().lower()
        reason = str(data.get("reason", "")).strip()
        notes = str(data.get("notes") or data.get("details") or "").strip()

        if not order_id or not reason or not item_name:
            return jsonify({"ok": False, "error": "Please provide Order ID, item, and return reason."}), 400
        if action_type not in ("return", "exchange"):
            return jsonify({"ok": False, "error": "Invalid action_type. Must be 'return' or 'exchange'."}), 400

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
        ord_row = c.fetchone()
        if ord_row:
            ord_dict = dict(ord_row)
            if not user_owns_order(user, ord_dict):
                conn.close()
                return jsonify({"ok": False, "error": "Access denied. You can only request returns for your own orders."}), 403
            ord_status = str(ord_dict.get("order_status") or "").strip().lower()
            pay_method = str(ord_dict.get("payment_method") or "cod").strip().lower()
            pay_status = str(ord_dict.get("payment_status") or "").strip().lower()
            if ord_status == "cancelled":
                conn.close()
                return jsonify({"ok": False, "error": "Cannot request a return or exchange for a cancelled order."}), 400
            if ord_status == "pending_payment" or (pay_method == "razorpay" and pay_status != "paid"):
                conn.close()
                return jsonify({"ok": False, "error": "Cannot request a return or exchange for an unpaid order."}), 400
        elif order_id != "NAARI-20261029-SAMPLE":
            conn.close()
            return jsonify({"ok": False, "error": "Order not found."}), 404

        c.execute("""
            SELECT id, status FROM return_requests
            WHERE order_id = ?
              AND LOWER(customer_email) = LOWER(?)
              AND LOWER(TRIM(item_name)) = LOWER(TRIM(?))
              AND LOWER(COALESCE(status, '')) NOT IN ('rejected', 'cancelled')
            LIMIT 1
        """, (order_id, email, item_name))
        existing_ret = c.fetchone()
        if existing_ret:
            conn.close()
            return jsonify({
                "ok": False,
                "error": f"A return or exchange request ({existing_ret['id']}) has already been submitted for this item.",
                "return_id": existing_ret["id"]
            }), 400

        ret_id = f"RET-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
        now_iso = datetime.now().isoformat()

        c.execute("""
            INSERT INTO return_requests (id, order_id, customer_email, customer_phone, item_name, action_type, reason, notes, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'requested', ?, ?)
        """, (ret_id, order_id, email, phone, item_name, action_type, reason, notes, now_iso, now_iso))
        conn.commit()
        conn.close()

        return jsonify({
            "ok": True,
            "id": ret_id,
            "return_id": ret_id,
            "status": "requested",
            "message": f"Your {action_type} request ({ret_id}) has been submitted. Our concierge will review it within 24 hours."
        })

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM return_requests
        WHERE LOWER(customer_email) = LOWER(?)
           OR order_id IN (SELECT id FROM orders WHERE user_id = ?)
        ORDER BY created_at DESC
    """, (user["email"], user["id"]))
    rows = []
    for r in c.fetchall():
        d = dict(r)
        d["return_id"] = d.get("id", "")
        d["status"] = normalize_return_status(d.get("status")) or "requested"
        d["request_type"] = d.get("action_type", "return")
        d["details"] = d.get("notes", "")
        rows.append(d)
    conn.close()
    return jsonify({"ok": True, "returns": rows})

# ================= Order Creation & Payment Verification =================

@app.route("/api/create-order", methods=["POST"])
def api_create_order():
    user = get_current_user()
    if not user:
        return jsonify({
            "ok": False,
            "error": "Please log in or sign up before placing an order.",
            "auth_required": True
        }), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Invalid request body (JSON expected)"}), 400

    cfg = load_config()
    if not cfg.get("sales_enabled", True):
        return jsonify({
            "ok": False,
            "sales_paused": True,
            "error": "Orders are temporarily paused while physical stock is being verified."
        }), 403

    cust = dict(data.get("customer") or {})
    if not cust.get("name") and user.get("name"):
        cust["name"] = user["name"]
    if not cust.get("email") and user.get("email"):
        cust["email"] = user["email"]
    if not cust.get("phone") and user.get("phone"):
        cust["phone"] = user["phone"]

    err = validate_customer_info(cust)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    coupon_code = str(data.get("coupon_code", "")).strip()
    calc, err = validate_and_compute_totals(data.get("items", []), coupon_code)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    cfg = load_config()
    configured = is_razorpay_configured(cfg)
    amount_paise = int(calc["total_amount"]) * 100
    user_id = user["id"]
    items_json_str = json.dumps(calc["items"])

    # Check if an existing pending Razorpay order owned by this user was passed for retry
    existing_order_id = str(data.get("order_id", "")).strip()
    order_id = None
    if existing_order_id:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, user_id, customer_email, payment_method, payment_status, order_status, razorpay_order_id, total_amount FROM orders WHERE id = ?", (existing_order_id,))
        existing_row = c.fetchone()
        conn.close()
        if existing_row:
            ex_dict = dict(existing_row)
            if not user_owns_order(user, ex_dict):
                return jsonify({"ok": False, "error": "Access denied. This order belongs to another customer."}), 403
            ex_method = str(ex_dict.get("payment_method") or "").strip().lower()
            ex_pay_status = str(ex_dict.get("payment_status") or "").strip().lower()
            ex_ord_status = str(ex_dict.get("order_status") or "").strip().lower()
            if ex_method == "razorpay" and ex_ord_status == "pending_payment" and ex_pay_status in ("pending", "failed"):
                order_id = ex_dict["id"]

    if not order_id:
        order_id = generate_order_id()

    if not configured:
        print(
            f"[Razorpay Config Error] POST /api/create-order rejected for order {order_id}: "
            f"RAZORPAY_KEY_ID ({mask_key_id(cfg.get('razorpay_key_id'))}) or RAZORPAY_KEY_SECRET is not configured on the server.",
            flush=True
        )
        return jsonify({
            "ok": False,
            "error": "Online payment via Razorpay is currently unavailable because server payment credentials (RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET) are not configured. Please choose Cash on Delivery (COD) or contact support."
        }), 503

    # Real Razorpay Order Creation via official Orders API (Secret key remains strictly on server)
    key_id = cfg["razorpay_key_id"].strip()
    key_secret = cfg["razorpay_key_secret"].strip()

    rzp_url = "https://api.razorpay.com/v1/orders"
    payload = {
        "amount": amount_paise,
        "currency": "INR",
        "receipt": order_id,
        "notes": {
            "order_id": order_id,
            "coupon_code": calc["applied_coupon"] or ""
        }
    }

    print(
        f"[Razorpay] Creating order on Razorpay API: internal_order_id={order_id}, amount_paise={amount_paise}, key_id={mask_key_id(key_id)}",
        flush=True
    )

    try:
        resp = requests.post(rzp_url, auth=(key_id, key_secret), json=payload, timeout=15)
        if resp.status_code not in (200, 201):
            err_detail = ""
            try:
                err_json = resp.json()
                err_detail = err_json.get("error", {}).get("description", "")
            except Exception:
                pass
            print(f"[Razorpay API Error] HTTP {resp.status_code} for {order_id}: {err_detail or 'Order creation rejected'}", flush=True)
            return jsonify({
                "ok": False,
                "error": err_detail or f"Razorpay order creation failed (HTTP {resp.status_code}). Please verify RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET."
            }), 400
        rzp_res = resp.json()
        razorpay_order_id = str(rzp_res.get("id") or "").strip()
        if not razorpay_order_id or not razorpay_order_id.startswith("order_") or razorpay_order_id.startswith("order_test_"):
            print(f"[Razorpay API Error] Invalid order_id returned by Razorpay for {order_id}: '{razorpay_order_id}'", flush=True)
            return jsonify({
                "ok": False,
                "error": "Razorpay did not return a valid order ID."
            }), 502
    except requests.exceptions.RequestException as e:
        print(f"[Razorpay Network Error] {order_id}: {type(e).__name__}", flush=True)
        return jsonify({
            "ok": False,
            "error": "Unable to connect to Razorpay payment gateway. Please check your connection or try again."
        }), 502

    now_iso = datetime.now().isoformat()
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO orders (
            id, customer_name, customer_email, customer_phone,
            address_line1, address_line2, city, state, pincode,
            house_no, street_area, latitude, longitude, location_summary, address_label,
            payment_method, payment_status, order_status, razorpay_order_id,
            subtotal, shipping, discount_amount, coupon_code, total_amount, items_json,
            user_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            customer_name = excluded.customer_name,
            customer_email = excluded.customer_email,
            customer_phone = excluded.customer_phone,
            address_line1 = excluded.address_line1,
            address_line2 = excluded.address_line2,
            city = excluded.city,
            state = excluded.state,
            pincode = excluded.pincode,
            house_no = excluded.house_no,
            street_area = excluded.street_area,
            latitude = excluded.latitude,
            longitude = excluded.longitude,
            location_summary = excluded.location_summary,
            address_label = excluded.address_label,
            payment_method = excluded.payment_method,
            payment_status = excluded.payment_status,
            order_status = excluded.order_status,
            razorpay_order_id = excluded.razorpay_order_id,
            subtotal = excluded.subtotal,
            shipping = excluded.shipping,
            discount_amount = excluded.discount_amount,
            coupon_code = excluded.coupon_code,
            total_amount = excluded.total_amount,
            items_json = excluded.items_json,
            user_id = excluded.user_id,
            updated_at = excluded.updated_at
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
        str(cust.get("house_no", "")).strip(),
        str(cust.get("street_area", "")).strip(),
        cust.get("latitude"),
        cust.get("longitude"),
        str(cust.get("location_summary", "")).strip(),
        str(cust.get("address_label") or "Home").strip(),
        "razorpay",
        "pending",
        "pending_payment",
        razorpay_order_id,
        calc["subtotal"],
        calc["shipping"],
        calc["discount"],
        calc["applied_coupon"],
        calc["total_amount"],
        items_json_str,
        user_id,
        now_iso,
        now_iso
    ))
    if cust.get("save_address") or data.get("save_address"):
        try:
            upsert_customer_address(c, user_id, cust, is_default=True)
        except Exception:
            pass
    conn.commit()
    conn.close()

    print(
        f"[Razorpay] Order created: internal_order_id={order_id}, razorpay_order_id={razorpay_order_id}, status=pending_payment",
        flush=True
    )

    return jsonify({
        "ok": True,
        "order_id": order_id,
        "razorpay_order_id": razorpay_order_id,
        "id": razorpay_order_id,
        "amount": amount_paise,
        "subtotal": calc["subtotal"],
        "shipping": calc["shipping"],
        "discount_amount": calc["discount"],
        "total_amount": calc["total_amount"],
        "currency": "INR",
        "key_id": key_id,
        "is_simulated": False,
        "coupon_code": calc["applied_coupon"],
        "items": calc["items"],
        "order_status": "pending_payment",
        "customer": {
            "name": cust.get("name"),
            "email": cust.get("email"),
            "phone": cust.get("phone")
        }
    })

@app.route("/api/verify-payment", methods=["POST"])
def api_verify_payment():
    user = get_current_user()
    if not user:
        return jsonify({
            "ok": False,
            "error": "Authentication required to verify payment.",
            "auth_required": True
        }), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Invalid request body (JSON expected)"}), 400

    cfg = load_config()
    if not cfg.get("sales_enabled", True):
        return jsonify({
            "ok": False,
            "sales_paused": True,
            "error": "Orders are temporarily paused while physical stock is being verified."
        }), 403

    order_id = str(data.get("order_id", "")).strip()
    rzp_order_id = str(data.get("razorpay_order_id", "")).strip()
    rzp_payment_id = str(data.get("razorpay_payment_id", "")).strip()
    rzp_signature = str(data.get("razorpay_signature", "")).strip()

    if not order_id and not rzp_order_id:
        return jsonify({"ok": False, "error": "Missing order ID parameter"}), 400

    # Never permit simulated payments or bypass flags
    if data.get("is_simulated") or rzp_order_id.startswith("order_test_") or rzp_payment_id.startswith("pay_test_"):
        print(
            f"[Razorpay Security] Blocked simulated payment verification attempt: order_id={order_id}, rzp_order_id={rzp_order_id}",
            flush=True
        )
        return jsonify({"ok": False, "error": "Simulated payments are disabled. Real Razorpay payment verification is required."}), 400

    if not (rzp_order_id and rzp_payment_id and rzp_signature):
        return jsonify({"ok": False, "error": "Missing Razorpay payment verification parameters (razorpay_order_id, razorpay_payment_id, razorpay_signature)"}), 400

    cfg = load_config()
    if not is_razorpay_configured(cfg):
        print(f"[Razorpay Config Error] POST /api/verify-payment rejected for {order_id}: server keys not configured.", flush=True)
        return jsonify({"ok": False, "error": "Server configuration missing valid Razorpay secret key"}), 400

    key_secret = cfg.get("razorpay_key_secret", "").strip()

    # Acquire an immediate write lock before reading the order row so payment verification,
    # duplicate callbacks, and order cancellation serialize atomically without race conditions.
    conn = get_db()
    conn.isolation_level = None
    c = conn.cursor()
    try:
        c.execute("BEGIN IMMEDIATE")
        lock_clause = _for_update_clause(c)
        if order_id:
            c.execute(f"SELECT * FROM orders WHERE id = ?{lock_clause}", (order_id,))
        else:
            c.execute(f"SELECT * FROM orders WHERE razorpay_order_id = ?{lock_clause}", (rzp_order_id,))
        ord_row = c.fetchone()

        if not ord_row:
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": "Order not found for verification."}), 404

        ord_row = dict(ord_row)
        if not user_owns_order(user, ord_row):
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": "Access denied. This order belongs to another customer."}), 403

        stored_order_id = ord_row["id"]
        stored_rzp_order_id = (ord_row["razorpay_order_id"] or "").strip()
        curr_order_status = str(ord_row["order_status"] or "pending_payment").strip().lower()
        curr_payment_status = str(ord_row["payment_status"] or "pending").strip().lower()

        if not stored_rzp_order_id or stored_rzp_order_id.startswith("order_test_"):
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": "Order does not have a valid Razorpay order ID."}), 400

        # Ensure the Razorpay order_id being verified matches the order's stored razorpay_order_id
        if rzp_order_id != stored_rzp_order_id:
            if curr_payment_status != "paid" and curr_order_status != "cancelled":
                c.execute("""
                    UPDATE orders
                    SET payment_status = 'failed', updated_at = ?
                    WHERE id = ? AND LOWER(COALESCE(payment_status, '')) != 'paid'
                      AND LOWER(COALESCE(order_status, 'pending_payment')) != 'cancelled'
                """, (datetime.now().isoformat(), stored_order_id))
                c.execute("COMMIT")
            else:
                c.execute("ROLLBACK")
            conn.close()
            print(
                f"[Razorpay Security] Order ID mismatch for {stored_order_id}: expected {stored_rzp_order_id}, got {rzp_order_id}",
                flush=True
            )
            return jsonify({"ok": False, "error": "Razorpay order ID mismatch for this order"}), 400

        # Official Razorpay Standard Checkout HMAC-SHA256 signature verification:
        # generated_signature = hmac_sha256(razorpay_order_id + "|" + razorpay_payment_id, secret)
        message = f"{rzp_order_id}|{rzp_payment_id}".encode("utf-8")
        expected_signature = hmac.new(key_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_signature, rzp_signature):
            if curr_payment_status != "paid" and curr_order_status != "cancelled":
                c.execute("""
                    UPDATE orders
                    SET payment_status = 'failed', updated_at = ?
                    WHERE id = ? AND LOWER(COALESCE(payment_status, '')) != 'paid'
                      AND LOWER(COALESCE(order_status, 'pending_payment')) != 'cancelled'
                """, (datetime.now().isoformat(), stored_order_id))
                c.execute("COMMIT")
            else:
                c.execute("ROLLBACK")
            conn.close()
            print(
                f"[Razorpay Security] HMAC-SHA256 verification failed for order {stored_order_id} (rzp_order_id={rzp_order_id})",
                flush=True
            )
            return jsonify({"ok": False, "error": "Cryptographic payment signature verification failed"}), 400

        # Never allow a cancelled order to transition back to confirmed on a late payment callback
        if curr_order_status == "cancelled":
            c.execute("ROLLBACK")
            conn.close()
            print(
                f"[Razorpay Refund Required] Late payment callback received for already-cancelled order {stored_order_id} "
                f"(rzp_order_id={rzp_order_id}, rzp_payment_id={rzp_payment_id}). Order kept cancelled; refund required.",
                flush=True
            )
            return jsonify({
                "ok": False,
                "order_id": stored_order_id,
                "razorpay_order_id": rzp_order_id,
                "payment_id": rzp_payment_id,
                "order_status": "cancelled",
                "refund_required": True,
                "error": (
                    f"Order {stored_order_id} was already cancelled prior to payment confirmation and cannot be reopened. "
                    f"If payment {rzp_payment_id} was captured, please initiate a refund for this Razorpay payment."
                )
            }), 409

        # Handle idempotent duplicate verification requests if the order was already verified with this valid signature
        if curr_payment_status == "paid":
            existing_pay_id = ord_row["razorpay_payment_id"] or rzp_payment_id
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({
                "ok": True,
                "order_id": stored_order_id,
                "payment_id": existing_pay_id,
                "status": "paid",
                "already_verified": True
            })

        # Verification successful -> atomically deduct stock and mark order as paid & confirmed
        now_iso = datetime.now().isoformat()
        order_items = json.loads(ord_row.get("items_json") or "[]")
        deduct_order_stock(order_items, cursor=c)
        c.execute("""
            UPDATE orders
            SET payment_status = 'paid',
                order_status = 'confirmed',
                razorpay_payment_id = ?,
                razorpay_signature = ?,
                updated_at = ?
            WHERE id = ?
              AND LOWER(COALESCE(payment_status, '')) != 'paid'
              AND LOWER(COALESCE(order_status, 'pending_payment')) != 'cancelled'
        """, (rzp_payment_id, rzp_signature, now_iso, stored_order_id))
        if c.rowcount != 1:
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({
                "ok": False,
                "order_id": stored_order_id,
                "payment_id": rzp_payment_id,
                "refund_required": True,
                "error": "Order state changed concurrently and could not be confirmed."
            }), 409

        if ord_row["coupon_code"]:
            c.execute("UPDATE coupons SET used_count = used_count + 1 WHERE UPPER(code) = UPPER(?)", (ord_row["coupon_code"],))

        c.execute("COMMIT")
    except ValueError as stock_err:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        conn.close()
        return jsonify({
            "ok": False,
            "order_id": order_id,
            "razorpay_order_id": rzp_order_id,
            "payment_id": rzp_payment_id,
            "refund_required": True,
            "error": str(stock_err)
        }), 400
    except Exception:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        conn.close()
        return jsonify({
            "ok": False,
            "order_id": order_id,
            "razorpay_order_id": rzp_order_id,
            "payment_id": rzp_payment_id,
            "refund_required": True,
            "error": "Unable to complete order stock confirmation."
        }), 500

    conn.close()

    print(
        f"[Razorpay] Payment verified & order marked paid: internal_order_id={stored_order_id}, rzp_order_id={rzp_order_id}, rzp_payment_id={rzp_payment_id}",
        flush=True
    )

    return jsonify({
        "ok": True,
        "order_id": stored_order_id,
        "payment_id": rzp_payment_id,
        "status": "paid",
        "order_status": "confirmed",
        "items": order_items,
        "subtotal": ord_row.get("subtotal"),
        "shipping": ord_row.get("shipping"),
        "discount_amount": ord_row.get("discount_amount"),
        "coupon_code": ord_row.get("coupon_code") or "",
        "total_amount": ord_row.get("total_amount")
    })

@app.route("/api/payment-failed", methods=["POST"])
def api_payment_failed():
    user = get_current_user()
    if not user:
        return jsonify({
            "ok": False,
            "error": "Authentication required.",
            "auth_required": True
        }), 401

    data = request.get_json(silent=True) or {}
    order_id = str(data.get("order_id", "")).strip()
    rzp_order_id = str(data.get("razorpay_order_id", "")).strip()
    reason = str(data.get("reason", "Payment cancelled or declined")).strip()
    status_val = "cancelled" if "cancel" in reason.lower() else "failed"

    if not order_id and not rzp_order_id:
        return jsonify({"ok": False, "error": "Missing order ID"}), 400

    conn = get_db()
    c = conn.cursor()
    if order_id:
        c.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    else:
        c.execute("SELECT * FROM orders WHERE razorpay_order_id = ?", (rzp_order_id,))
    ord_row = c.fetchone()
    if not ord_row:
        conn.close()
        return jsonify({"ok": False, "error": "Order not found."}), 404
    ord_dict = dict(ord_row)
    if not user_owns_order(user, ord_dict):
        conn.close()
        return jsonify({"ok": False, "error": "Access denied."}), 403
    if str(ord_dict.get("payment_method") or "").strip().lower() != "razorpay":
        conn.close()
        return jsonify({"ok": False, "error": "Payment failure reporting is only valid for online Razorpay orders."}), 400

    target_id = ord_dict["id"]
    # Never overwrite an order that has already been verified as paid or already cancelled
    c.execute("""
        UPDATE orders
        SET payment_status = ?,
            updated_at = ?
        WHERE id = ?
          AND LOWER(COALESCE(payment_status, '')) != 'paid'
          AND LOWER(COALESCE(order_status, 'pending_payment')) != 'cancelled'
    """, (status_val, datetime.now().isoformat(), target_id))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "order_id": target_id,
        "payment_status": status_val,
        "message": reason
    })

@app.route("/api/create-cod-order", methods=["POST"])
def api_create_cod_order():
    user = get_current_user()
    if not user:
        return jsonify({
            "ok": False,
            "error": "Please log in or sign up before placing an order.",
            "auth_required": True
        }), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Invalid request body (JSON expected)"}), 400

    cfg = load_config()
    if not cfg.get("sales_enabled", True):
        return jsonify({
            "ok": False,
            "sales_paused": True,
            "error": "Orders are temporarily paused while physical stock is being verified."
        }), 403
    if not cfg.get("cod_enabled", True):
        return jsonify({"ok": False, "error": "Cash on Delivery is currently disabled. Please use online payment."}), 400

    cust = dict(data.get("customer") or {})
    if not cust.get("name") and user.get("name"):
        cust["name"] = user["name"]
    if not cust.get("email") and user.get("email"):
        cust["email"] = user["email"]
    if not cust.get("phone") and user.get("phone"):
        cust["phone"] = user["phone"]

    err = validate_customer_info(cust)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    coupon_code = str(data.get("coupon_code", "")).strip()
    raw_items = data.get("items", [])

    conn = get_db()
    conn.isolation_level = None
    c = conn.cursor()
    try:
        c.execute("BEGIN IMMEDIATE")
        calc, err = validate_and_compute_totals(raw_items, coupon_code, cursor=c)
        if err:
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": err}), 400

        deduct_order_stock(calc["items"], cursor=c)

        order_id = generate_order_id()
        now_iso = datetime.now().isoformat()
        user_id = user["id"]

        c.execute("""
            INSERT INTO orders (
                id, customer_name, customer_email, customer_phone,
                address_line1, address_line2, city, state, pincode,
                house_no, street_area, latitude, longitude, location_summary, address_label,
                payment_method, payment_status, order_status,
                subtotal, shipping, discount_amount, coupon_code, total_amount, items_json,
                user_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            str(cust.get("house_no", "")).strip(),
            str(cust.get("street_area", "")).strip(),
            cust.get("latitude"),
            cust.get("longitude"),
            str(cust.get("location_summary", "")).strip(),
            str(cust.get("address_label") or "Home").strip(),
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

        if cust.get("save_address") or data.get("save_address"):
            try:
                upsert_customer_address(c, user_id, cust, is_default=True)
            except Exception:
                pass

        if calc["applied_coupon"]:
            c.execute("UPDATE coupons SET used_count = used_count + 1 WHERE code = ?", (calc["applied_coupon"],))

        c.execute("COMMIT")
    except ValueError as stock_err:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        conn.close()
        return jsonify({"ok": False, "error": str(stock_err)}), 400
    except Exception:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        conn.close()
        return jsonify({"ok": False, "error": "Unable to place order right now. Please try again."}), 500

    conn.close()

    return jsonify({
        "ok": True,
        "order_id": order_id,
        "status": "cod_confirmed",
        "order_status": "confirmed",
        "subtotal": calc["subtotal"],
        "shipping": calc["shipping"],
        "discount_amount": calc["discount"],
        "coupon_code": calc["applied_coupon"],
        "total_amount": calc["total_amount"],
        "items": calc["items"]
    })

@app.route("/api/order-details", methods=["GET"])
def api_order_details():
    user = get_current_user()
    is_admin = check_admin_auth()
    if not user and not is_admin:
        return jsonify({
            "ok": False,
            "error": "Authentication required. Please log in to view order details.",
            "auth_required": True
        }), 401

    order_id = request.args.get("order_id", "").strip()
    if not order_id:
        return jsonify({"ok": False, "error": "Order ID is required"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT id, user_id, customer_name, customer_email, customer_phone,
               address_line1, address_line2, city, state, pincode,
               house_no, street_area, latitude, longitude, location_summary, address_label,
               payment_method, payment_status, order_status, tracking_number, courier_partner,
               razorpay_order_id, razorpay_payment_id, subtotal, shipping, discount_amount, coupon_code,
               total_amount, items_json, created_at, updated_at
        FROM orders WHERE id = ? OR razorpay_order_id = ?
    """, (order_id, order_id))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": f"Order not found: {order_id}"}), 404

    order_dict = dict(row)
    if not is_admin and not user_owns_order(user, order_dict):
        return jsonify({
            "ok": False,
            "error": "Access denied. You do not have permission to view this order."
        }), 403

    order_dict["items"] = json.loads(order_dict.pop("items_json", "[]"))
    return jsonify({"ok": True, "order": order_dict})

# ================= Protected Administrative APIs =================

@app.route("/api/admin/verify", methods=["POST"])
def api_admin_verify():
    if not is_admin_passkey_configured():
        return jsonify({
            "ok": False,
            "is_admin_configured": False,
            "error": "Admin secret passkey is not configured on the server (set ADMIN_SECRET_KEY in environment)."
        }), 401
    if not check_admin_auth():
        return jsonify({
            "ok": False,
            "is_admin_configured": True,
            "error": "Invalid admin passkey"
        }), 401

    token = secrets.token_hex(32)
    now_dt = datetime.now()
    exp_dt = now_dt + timedelta(hours=24)
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (now_dt.isoformat(),))
        c.execute(
            "INSERT INTO admin_sessions (token, created_at, expires_at) VALUES (?, ?, ?)",
            (token, now_dt.isoformat(), exp_dt.isoformat())
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    resp = jsonify({
        "ok": True,
        "authenticated": True,
        "token": token,
        "expires_at": exp_dt.isoformat(),
        "message": "Admin authenticated successfully."
    })
    return set_admin_auth_cookie(resp, token)

@app.route("/api/admin/logout", methods=["POST"])
def api_admin_logout():
    token = request.headers.get("X-Admin-Token", "").strip()
    if not token:
        auth_hdr = request.headers.get("Authorization", "").strip()
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr[7:].strip()
    if not token:
        token = request.cookies.get("naari_admin_token", "").strip()
    if token:
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("DELETE FROM admin_sessions WHERE token = ?", (token,))
            conn.commit()
            conn.close()
        except Exception:
            pass
    resp = jsonify({"ok": True, "message": "Admin session logged out."})
    return clear_admin_auth_cookie(resp)

@app.route("/api/admin/stats", methods=["GET"])
def api_admin_stats():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT COUNT(*) AS paid_orders, COALESCE(SUM(total_amount), 0) AS verified_paid_revenue
        FROM orders
        WHERE LOWER(COALESCE(order_status, '')) != 'cancelled'
          AND LOWER(COALESCE(payment_method, '')) != 'cod'
          AND LOWER(COALESCE(payment_status, '')) = 'paid'
    """)
    paid_row = dict(c.fetchone())

    c.execute("""
        SELECT COUNT(*) AS cod_orders, COALESCE(SUM(total_amount), 0) AS cod_revenue
        FROM orders
        WHERE LOWER(COALESCE(order_status, '')) != 'cancelled'
          AND LOWER(COALESCE(payment_method, '')) = 'cod'
          AND LOWER(COALESCE(payment_status, 'cod_confirmed')) NOT IN ('failed', 'cancelled', 'refunded')
    """)
    cod_row = dict(c.fetchone())

    paid_orders_cnt = int(paid_row["paid_orders"] or 0)
    verified_paid_rev = int(paid_row["verified_paid_revenue"] or 0)
    cod_orders_cnt = int(cod_row["cod_orders"] or 0)
    cod_rev = int(cod_row["cod_revenue"] or 0)

    totals = {
        "paid_orders": paid_orders_cnt,
        "paid_count": paid_orders_cnt,
        "verified_paid_revenue": verified_paid_rev,
        "paid_revenue": verified_paid_rev,
        "cod_orders": cod_orders_cnt,
        "cod_count": cod_orders_cnt,
        "cod_revenue": cod_rev,
        "total_orders": paid_orders_cnt + cod_orders_cnt,
        "total_revenue": verified_paid_rev + cod_rev,
    }

    c.execute("""
        SELECT COUNT(*) AS pending_orders
        FROM orders
        WHERE LOWER(COALESCE(order_status, '')) IN ('placed', 'confirmed', 'packed', 'processing')
          AND (
              (LOWER(COALESCE(payment_method, '')) = 'cod' AND LOWER(COALESCE(payment_status, 'cod_confirmed')) NOT IN ('failed', 'cancelled', 'refunded'))
              OR (LOWER(COALESCE(payment_method, '')) != 'cod' AND LOWER(COALESCE(payment_status, '')) = 'paid')
          )
    """)
    totals["pending_orders"] = int(c.fetchone()["pending_orders"] or 0)

    c.execute("""
        SELECT COUNT(*) AS unpaid_orders
        FROM orders
        WHERE LOWER(COALESCE(order_status, '')) != 'cancelled'
          AND LOWER(COALESCE(payment_method, '')) != 'cod'
          AND LOWER(COALESCE(payment_status, '')) != 'paid'
    """)
    totals["unpaid_orders"] = int(c.fetchone()["unpaid_orders"] or 0)

    c.execute("SELECT COUNT(*) AS shipped_orders FROM orders WHERE LOWER(COALESCE(order_status, '')) IN ('shipped', 'out for delivery', 'out_for_delivery')")
    totals["shipped_orders"] = int(c.fetchone()["shipped_orders"] or 0)

    c.execute("SELECT COUNT(*) AS delivered_orders FROM orders WHERE LOWER(COALESCE(order_status, '')) = 'delivered'")
    totals["delivered_orders"] = int(c.fetchone()["delivered_orders"] or 0)

    c.execute("SELECT COUNT(*) AS cancelled_orders FROM orders WHERE LOWER(COALESCE(order_status, '')) = 'cancelled'")
    totals["cancelled_orders"] = int(c.fetchone()["cancelled_orders"] or 0)

    c.execute("SELECT COUNT(*) AS pending_returns FROM return_requests WHERE LOWER(COALESCE(status, '')) IN ('pending', 'requested')")
    totals["pending_returns"] = c.fetchone()["pending_returns"]

    c.execute("SELECT * FROM products ORDER BY created_at DESC")
    all_product_rows = [format_product_row(r) for r in c.fetchall()]

    active_prods = [p for p in all_product_rows if not p.get("is_archived", 0)]
    archived_prods = [p for p in all_product_rows if p.get("is_archived", 0)]
    low_stock_alerts = [
        {
            "id": p["id"],
            "sku": p.get("sku") or p["id"].upper(),
            "name": p["name"],
            "category": p["category"],
            "image": p.get("relative_image") or p.get("image"),
            "stock": p["stock"],
            "sizeStock": p.get("sizeStock", {}),
            "size_stock": p.get("sizeStock", {}),
            "lowStockSizes": p.get("lowStockSizes", []),
            "soldOutSizes": p.get("soldOutSizes", []),
            "isOutOfStock": p["stock"] <= 0
        }
        for p in active_prods
        if p["stock"] <= 10 or len(p.get("lowStockSizes", [])) > 0 or len(p.get("soldOutSizes", [])) > 0
    ]
    out_of_stock_cnt = sum(1 for p in active_prods if p["stock"] <= 0)

    c.execute("SELECT COUNT(*) AS active_coupons FROM coupons WHERE is_active = 1")
    active_coupons_cnt = c.fetchone()["active_coupons"]

    totals["total_products"] = len(active_prods)
    totals["active_products"] = len(active_prods)
    totals["archived_products"] = len(archived_prods)
    totals["low_stock_count"] = len(low_stock_alerts)
    totals["out_of_stock_count"] = out_of_stock_cnt
    totals["active_coupons"] = active_coupons_cnt

    c.execute("SELECT COUNT(*) AS total_users FROM users")
    totals["total_users"] = c.fetchone()["total_users"]
    totals["total_customers"] = totals["total_users"]

    # Calculate best-selling products from actual valid non-cancelled orders in SQLite
    c.execute("""
        SELECT items_json FROM orders
        WHERE LOWER(COALESCE(order_status, '')) != 'cancelled'
          AND (
              (LOWER(COALESCE(payment_method, '')) = 'cod' AND LOWER(COALESCE(payment_status, 'cod_confirmed')) NOT IN ('failed', 'cancelled', 'refunded'))
              OR (LOWER(COALESCE(payment_method, '')) != 'cod' AND LOWER(COALESCE(payment_status, '')) = 'paid')
          )
    """)
    sales_by_pid = {}
    prod_lookup = {p["id"]: p for p in all_product_rows}
    for orow in c.fetchall():
        try:
            items = json.loads(orow["items_json"] or "[]")
        except Exception:
            items = []
        for item in items:
            pid = str(item.get("id", "")).strip()
            if not pid:
                continue
            qty = max(1, int(item.get("qty", 1) or 1))
            line_rev = int(item.get("subtotal") or (int(item.get("price", 0) or 0) * qty))
            if pid not in sales_by_pid:
                p_meta = prod_lookup.get(pid, {})
                sales_by_pid[pid] = {
                    "id": pid,
                    "sku": p_meta.get("sku") or pid.upper(),
                    "name": p_meta.get("name") or item.get("name") or pid,
                    "category": p_meta.get("category") or item.get("category") or "Kurti",
                    "image": p_meta.get("relative_image") or p_meta.get("image") or item.get("image") or "assets/hero.jpg",
                    "price": p_meta.get("price") or int(item.get("price", 0) or 0),
                    "stock": p_meta.get("stock", 0),
                    "units_sold": 0,
                    "revenue": 0,
                    "orders_count": 0
                }
            sales_by_pid[pid]["units_sold"] += qty
            sales_by_pid[pid]["revenue"] += line_rev
            sales_by_pid[pid]["orders_count"] += 1

    best_selling = sorted(
        sales_by_pid.values(),
        key=lambda x: (x["units_sold"], x["revenue"]),
        reverse=True
    )[:6]

    # Recent orders
    c.execute("""
        SELECT id, customer_name, customer_email, customer_phone,
               payment_method, payment_status, order_status,
               subtotal, discount_amount, shipping, coupon_code,
               total_amount, items_json, created_at
        FROM orders
        ORDER BY created_at DESC LIMIT 10
    """)
    recent_orders = []
    for r in c.fetchall():
        rd = dict(r)
        rd["order_id"] = rd["id"]
        try:
            rd["items"] = json.loads(rd.pop("items_json", "[]"))
        except Exception:
            rd["items"] = []
        disc_val = int(rd.get("discount_amount") or 0)
        rd["discount"] = disc_val
        rd["customer"] = {
            "name": rd.get("customer_name", "Guest"),
            "email": rd.get("customer_email", ""),
            "phone": rd.get("customer_phone", ""),
        }
        rd["pricing"] = {
            "subtotal": int(rd.get("subtotal") or 0),
            "discount": disc_val,
            "discount_amount": disc_val,
            "shipping": int(rd.get("shipping") or 0),
            "total": int(rd.get("total_amount") or 0),
            "coupon_code": rd.get("coupon_code") or "",
        }
        recent_orders.append(rd)

    totals["best_selling_products"] = best_selling
    totals["low_stock_alerts"] = low_stock_alerts

    conn.close()
    return jsonify({
        "ok": True,
        "stats": totals,
        "recent_orders": recent_orders,
        "best_selling_products": best_selling,
        "low_stock_alerts": low_stock_alerts
    })

@app.route("/api/admin/customers", methods=["GET"])
def api_admin_customers():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    search = request.args.get("search", "").strip().lower()

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT
            u.id,
            u.name,
            u.email,
            u.phone,
            u.created_at,
            (
                SELECT COUNT(*)
                FROM orders o
                WHERE (
                    o.user_id = u.id
                    OR ((o.user_id IS NULL OR o.user_id = '') AND LOWER(o.customer_email) = LOWER(u.email))
                )
                AND LOWER(COALESCE(o.order_status, '')) != 'cancelled'
                AND (
                    (LOWER(COALESCE(o.payment_method, '')) = 'cod' AND LOWER(COALESCE(o.payment_status, 'cod_confirmed')) NOT IN ('failed', 'cancelled', 'refunded'))
                    OR (LOWER(COALESCE(o.payment_method, '')) != 'cod' AND LOWER(COALESCE(o.payment_status, '')) = 'paid')
                )
            ) AS orders_count,
            (
                SELECT COALESCE(SUM(o.total_amount), 0)
                FROM orders o
                WHERE (
                    o.user_id = u.id
                    OR ((o.user_id IS NULL OR o.user_id = '') AND LOWER(o.customer_email) = LOWER(u.email))
                )
                AND LOWER(COALESCE(o.order_status, '')) != 'cancelled'
                AND (
                    (LOWER(COALESCE(o.payment_method, '')) = 'cod' AND LOWER(COALESCE(o.payment_status, 'cod_confirmed')) NOT IN ('failed', 'cancelled', 'refunded'))
                    OR (LOWER(COALESCE(o.payment_method, '')) != 'cod' AND LOWER(COALESCE(o.payment_status, '')) = 'paid')
                )
            ) AS total_spent
        FROM users u
        ORDER BY u.created_at DESC
    """)
    rows = c.fetchall()
    conn.close()

    total_customers = len(rows)
    customers = []
    for r in rows:
        cust = {
            "id": r["id"],
            "name": r["name"] or "",
            "email": r["email"] or "",
            "phone": r["phone"] or "",
            "created_at": r["created_at"] or "",
            "orders_count": int(r["orders_count"] or 0),
            "total_spent": int(r["total_spent"] or 0),
        }
        if search:
            haystack = f"{cust['id']} {cust['name']} {cust['email']} {cust['phone']} {cust['created_at']}".lower()
            if search not in haystack:
                continue
        customers.append(cust)

    return jsonify({
        "ok": True,
        "total_customers": total_customers,
        "count": len(customers),
        "customers": customers
    })

@app.route("/api/admin/orders", methods=["GET"])
def api_admin_orders():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    status = request.args.get("status", "").strip().lower()
    payment_method = request.args.get("payment_method", "").strip().lower()
    payment_status = request.args.get("payment_status", "").strip().lower()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
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
        od.pop("razorpay_signature", None)
        try:
            raw_items = json.loads(od.pop("items_json", "[]") or "[]")
        except Exception:
            raw_items = []
        norm_items = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            it = dict(item)
            qty = max(1, int(it.get("qty", 1) or 1))
            unit_price = int(it.get("price") if it.get("price") is not None else (it.get("unit_price") or 0))
            line_sub = int(it.get("subtotal") if it.get("subtotal") is not None else (it.get("line_total") if it.get("line_total") is not None else (unit_price * qty)))
            it["qty"] = qty
            it["price"] = unit_price
            it["unit_price"] = unit_price
            it["subtotal"] = line_sub
            it["line_total"] = line_sub
            norm_items.append(it)
        od["items"] = norm_items

        addr_parts = [
            od.get("address_line1", ""),
            od.get("address_line2", ""),
            od.get("city", ""),
            od.get("state", ""),
            od.get("pincode", "")
        ]
        od["customer_address"] = ", ".join([p for p in addr_parts if p and str(p).strip()])
        od["courier_name"] = od.get("courier_partner", "")
        od["customer"] = {
            "name": od.get("customer_name", "Guest"),
            "email": od.get("customer_email", ""),
            "phone": od.get("customer_phone", ""),
            "address": od.get("address_line1", ""),
            "city": od.get("city", ""),
            "state": od.get("state", ""),
            "pincode": od.get("pincode", "")
        }
        discount_val = int(od.get("discount_amount") if od.get("discount_amount") is not None else (od.get("discount") or 0))
        od["discount"] = discount_val
        od["discount_amount"] = discount_val
        od["pricing"] = {
            "subtotal": int(od.get("subtotal") or 0),
            "discount": discount_val,
            "discount_amount": discount_val,
            "shipping": int(od.get("shipping") or 0),
            "total": int(od.get("total_amount") or 0),
            "coupon_code": od.get("coupon_code") or ""
        }

        norm_filter_status = status.replace("_", " ")
        norm_order_status = (od.get("order_status") or "").strip().lower().replace("_", " ")
        if status and status != "all" and norm_order_status != norm_filter_status:
            continue
        if payment_method and payment_method != "all" and (od.get("payment_method") or "").lower() != payment_method:
            continue
        if payment_status and payment_status != "all" and (od.get("payment_status") or "").lower() != payment_status:
            continue
        created_date = str(od.get("created_at") or "")[:10]
        if date_from and len(date_from) == 10 and created_date and created_date < date_from:
            continue
        if date_to and len(date_to) == 10 and created_date and created_date > date_to:
            continue
        if search:
            q = f"{od['id']} {od['customer_name']} {od['customer_phone']} {od['customer_email']} {od.get('tracking_number', '')} {od.get('razorpay_order_id', '')} {od.get('razorpay_payment_id', '')}".lower()
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
    new_status = str(data.get("order_status", "")).strip().lower()
    tracking_no = str(data.get("tracking_number", "")).strip()
    courier = str(data.get("courier_partner") or data.get("courier_name") or "").strip()
    req_payment_status = str(data.get("payment_status", "")).strip().lower()

    if not order_id or not new_status:
        return jsonify({"ok": False, "error": "Order ID and status required."}), 400

    valid_statuses = {
        "placed", "confirmed", "packed", "processing",
        "shipped", "out for delivery", "out_for_delivery",
        "delivered", "cancelled", "pending_payment"
    }
    if new_status not in valid_statuses:
        return jsonify({"ok": False, "error": f"Invalid order status '{new_status}'."}), 400

    valid_payment_statuses = {
        "pending", "pending_cod", "cod_confirmed", "paid", "refunded", "failed", "cancelled"
    }
    if req_payment_status and req_payment_status not in valid_payment_statuses:
        return jsonify({"ok": False, "error": f"Invalid payment status '{req_payment_status}'."}), 400

    conn = get_db()
    conn.isolation_level = None
    c = conn.cursor()
    try:
        c.execute("BEGIN IMMEDIATE")
        lock_clause = _for_update_clause(c)
        c.execute(f"SELECT * FROM orders WHERE id = ?{lock_clause}", (order_id,))
        ord_row = c.fetchone()

        if ord_row:
            od = dict(ord_row)
            prev_status = str(od.get("order_status") or "confirmed").strip().lower()
            pay_method = str(od.get("payment_method") or "").strip().lower()
            cur_pay_status = str(od.get("payment_status") or "").strip().lower()

            # Never allow marking a Razorpay order as paid without verified signature
            if req_payment_status == "paid" and pay_method == "razorpay":
                if cur_pay_status != "paid" or not od.get("razorpay_signature"):
                    c.execute("ROLLBACK")
                    conn.close()
                    return jsonify({
                        "ok": False,
                        "error": "Security restriction: Razorpay orders cannot be manually marked as paid without cryptographic signature verification."
                    }), 400

            if prev_status == "cancelled" and new_status != "cancelled":
                c.execute("ROLLBACK")
                conn.close()
                return jsonify({
                    "ok": False,
                    "error": "Cancelled orders cannot be reopened after cancellation."
                }), 400

            fulfillment_statuses = {
                "placed", "confirmed", "packed", "processing",
                "shipped", "out for delivery", "out_for_delivery", "delivered"
            }
            if pay_method == "razorpay" and cur_pay_status != "paid" and new_status in fulfillment_statuses:
                c.execute("ROLLBACK")
                conn.close()
                return jsonify({
                    "ok": False,
                    "error": "Unpaid Razorpay orders cannot be moved to fulfillment statuses before payment verification."
                }), 400

            if new_status == "pending_payment" and prev_status != "pending_payment" and order_had_inventory_deducted(od):
                c.execute("ROLLBACK")
                conn.close()
                return jsonify({
                    "ok": False,
                    "error": "Orders with deducted inventory cannot be reverted to pending_payment."
                }), 400

            now_iso = datetime.now().isoformat()
            if new_status == "cancelled" and prev_status != "cancelled":
                c.execute("""
                    SELECT id, status FROM return_requests
                    WHERE order_id = ?
                      AND LOWER(COALESCE(status, '')) IN ('picked_up', 'picked up', 'pickup_scheduled', 'pickup scheduled', 'completed', 'refunded', 'completed / refunded')
                    LIMIT 1
                """, (order_id,))
                if c.fetchone():
                    c.execute("ROLLBACK")
                    conn.close()
                    return jsonify({
                        "ok": False,
                        "error": "Order cannot be cancelled because a return or exchange is already picked up, completed, or refunded."
                    }), 400
                c.execute("""
                    UPDATE orders
                    SET order_status = 'cancelled',
                        payment_status = CASE
                            WHEN LOWER(COALESCE(payment_method, '')) != 'cod' AND LOWER(COALESCE(payment_status, '')) = 'pending'
                            THEN 'cancelled'
                            WHEN ? = 'refunded'
                            THEN 'refunded'
                            ELSE payment_status
                        END,
                        tracking_number = COALESCE(NULLIF(?, ''), tracking_number),
                        courier_partner = COALESCE(NULLIF(?, ''), courier_partner),
                        updated_at = ?
                    WHERE id = ?
                      AND LOWER(COALESCE(order_status, 'confirmed')) != 'cancelled'
                """, (req_payment_status, tracking_no, courier, now_iso, order_id))
                if c.rowcount == 1:
                    c.execute("""
                        UPDATE return_requests
                        SET status = 'rejected',
                            updated_at = ?
                        WHERE order_id = ?
                          AND LOWER(COALESCE(status, '')) IN ('pending', 'requested', 'approved')
                    """, (now_iso, order_id))
                    restore_cancelled_order_resources(c, od)
            else:
                next_pay_status = cur_pay_status
                if new_status != "cancelled" and req_payment_status:
                    if pay_method == "cod" and req_payment_status in ("cod_confirmed", "pending_cod", "paid", "refunded"):
                        next_pay_status = req_payment_status
                    elif pay_method == "razorpay" and cur_pay_status == "paid" and req_payment_status in ("paid", "refunded"):
                        next_pay_status = req_payment_status
                c.execute("""
                    UPDATE orders
                    SET order_status = ?,
                        payment_status = ?,
                        tracking_number = COALESCE(NULLIF(?, ''), tracking_number),
                        courier_partner = COALESCE(NULLIF(?, ''), courier_partner),
                        updated_at = ?
                    WHERE id = ?
                """, (new_status, next_pay_status, tracking_no, courier, now_iso, order_id))
            c.execute("COMMIT")
        elif order_id == "NAARI-SAMPLE":
            c.execute("COMMIT")
        else:
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": "Order not found."}), 404
    except Exception:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        conn.close()
        return jsonify({"ok": False, "error": "Failed to update order status."}), 500

    conn.close()

    return jsonify({"ok": True, "message": f"Order {order_id} updated to '{new_status}'."})

@app.route("/api/admin/products", methods=["GET", "POST"])
def api_admin_product_save():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    if request.method == "GET":
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM products ORDER BY created_at DESC")
        prods = [format_product_row(r) for r in c.fetchall()]
        conn.close()
        return jsonify({"ok": True, "count": len(prods), "products": prods})

    p = request.get_json(silent=True) or {}
    pid = str(p.get("id", "")).strip() or f"prod_{secrets.token_hex(4)}"

    existing = get_product_from_db(pid)
    name = str(p.get("name", existing["name"] if existing else "")).strip()
    if not name:
        return jsonify({"ok": False, "error": "Product name is required."}), 400

    sku = str(p.get("sku", existing.get("sku", pid.upper()) if existing else pid.upper())).strip().upper()
    category = str(p.get("category", existing["category"] if existing else "Straight Cut")).strip()
    style = str(p.get("style", existing.get("style", category) if existing else category)).strip()

    try:
        price = int(p.get("price", existing["price"] if existing else 0))
        mrp = int(p.get("mrp", existing["mrp"] if existing else price))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Price and MRP must be valid numbers."}), 400

    if price <= 0:
        return jsonify({"ok": False, "error": "Product sale price must be greater than ₹0."}), 400
    if mrp < price:
        mrp = price

    desc = str(p.get("description", existing.get("description", "") if existing else "")).strip()
    fabric = str(p.get("fabric", existing.get("fabric", "") if existing else "")).strip()
    occasion = str(p.get("occasion", existing.get("occasion", "") if existing else "")).strip()
    pattern = str(p.get("pattern", existing.get("pattern", "") if existing else "")).strip()
    sleeve_length = str(p.get("sleeve_length", existing.get("sleeve_length", "") if existing else "")).strip()
    neck_design = str(p.get("neck_design", existing.get("neck_design", "") if existing else "")).strip()
    care = str(p.get("care", existing.get("care", "") if existing else "")).strip()

    existing_img = (existing.get("image") or "").strip() if existing else ""
    existing_img_valid = bool(
        existing_img
        and (existing_img.startswith(("http://", "https://")) or _public_asset_file_exists(existing_img))
    )
    fallback_img = (
        existing_img.lstrip("/")
        if (existing_img_valid and not existing_img.startswith(("http://", "https://")))
        else (existing_img if existing_img_valid else "assets/hero.jpg")
    )

    raw_img = str(p.get("image") if ("image" in p and p.get("image") is not None) else "").strip()
    if not raw_img:
        image = fallback_img
    elif raw_img.startswith(("http://", "https://")):
        image = raw_img
    elif _public_asset_file_exists(raw_img):
        image = raw_img.lstrip("/")
    else:
        image = fallback_img

    raw_rel_img = str(p.get("relative_image") if ("relative_image" in p and p.get("relative_image") is not None) else "").strip()
    if not raw_rel_img:
        rel_img = image
    elif raw_rel_img.startswith(("http://", "https://")):
        rel_img = raw_rel_img
    elif _public_asset_file_exists(raw_rel_img):
        rel_img = raw_rel_img.lstrip("/")
    else:
        rel_img = image

    sizes_list = p.get("sizes") if isinstance(p.get("sizes"), list) and p.get("sizes") else (existing["sizes"] if existing else ["S", "M", "L", "XL"])
    for core_sz in ("S", "M", "L", "XL"):
        if core_sz not in sizes_list and "Free Size" not in sizes_list:
            sizes_list.append(core_sz)

    # Size-wise stock handling & negative stock prevention
    incoming_size_stock = p.get("size_stock") if isinstance(p.get("size_stock"), dict) else (p.get("sizeStock") if isinstance(p.get("sizeStock"), dict) else None)
    size_stock_map = {}

    if incoming_size_stock is not None:
        for sz in sizes_list:
            raw_q = incoming_size_stock.get(sz, 0)
            try:
                q_val = int(raw_q)
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error": f"Invalid stock quantity for size {sz}."}), 400
            if q_val < 0:
                return jsonify({"ok": False, "error": f"Stock quantity for size {sz} cannot be negative."}), 400
            size_stock_map[sz] = q_val
        for sz, raw_q in incoming_size_stock.items():
            if sz not in size_stock_map:
                q_val = int(raw_q)
                if q_val < 0:
                    return jsonify({"ok": False, "error": f"Stock quantity for size {sz} cannot be negative."}), 400
                size_stock_map[sz] = q_val
        stock = sum(size_stock_map.values())
        sold_out_list = [sz for sz in sizes_list if size_stock_map.get(sz, 0) <= 0]
    else:
        try:
            stock = int(p.get("stock", existing["stock"] if existing else 40))
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "Stock must be a valid integer."}), 400
        if stock < 0:
            return jsonify({"ok": False, "error": "Stock quantity cannot be negative."}), 400

        sold_out_list = p.get("soldOutSizes") if "soldOutSizes" in p else (existing["soldOutSizes"] if existing else [])
        avail_sizes = [s for s in sizes_list if s not in sold_out_list]
        if avail_sizes and stock > 0:
            base_q = stock // len(avail_sizes)
            rem = stock % len(avail_sizes)
            for sz in sizes_list:
                if sz in sold_out_list:
                    size_stock_map[sz] = 0
                else:
                    avail_idx = avail_sizes.index(sz)
                    size_stock_map[sz] = base_q + (1 if avail_idx < rem else 0)
        else:
            for sz in sizes_list:
                size_stock_map[sz] = 0
            if stock == 0:
                sold_out_list = list(sizes_list)

    is_feat = int(bool(p.get("is_featured", existing.get("is_featured", 0) if existing else 0)))
    is_new = int(bool(p.get("is_new", existing.get("is_new", 0) if existing else 0)))
    is_best = int(bool(p.get("is_bestseller", existing.get("is_bestseller", 0) if existing else 0)))
    is_arch = int(bool(p.get("is_archived", existing.get("is_archived", 0) if existing else 0)))

    if "gallery" in p and isinstance(p["gallery"], list):
        valid_gal = []
        for g_item in p["gallery"]:
            g_str = str(g_item or "").strip()
            if not g_str:
                continue
            if g_str.startswith(("http://", "https://")):
                valid_gal.append(g_str)
            elif _public_asset_file_exists(g_str):
                valid_gal.append(g_str.lstrip("/"))
        gallery = json.dumps(valid_gal if valid_gal else [image])
    else:
        gallery = existing["gallery_json"] if existing else json.dumps([image])
    colors = json.dumps(p["colors"]) if "colors" in p else (existing["colors_json"] if existing else json.dumps([{"name": "Maroon", "swatch": "#6B2D31"}]))
    sizes_json_str = json.dumps(sizes_list)
    sold_out_json_str = json.dumps(sold_out_list)
    size_stock_json_str = json.dumps(size_stock_map)

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO products (
            id, sku, name, category, style, price, mrp, description, fabric,
            occasion, pattern, sleeve_length, neck_design, care,
            image, relative_image, gallery_json, colors_json, sizes_json,
            sold_out_sizes_json, size_stock_json, stock, is_featured, is_new, is_bestseller, is_archived, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            sku=excluded.sku,
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
            size_stock_json=excluded.size_stock_json,
            stock=excluded.stock,
            is_featured=excluded.is_featured,
            is_new=excluded.is_new,
            is_bestseller=excluded.is_bestseller,
            is_archived=excluded.is_archived
    """, (
        pid, sku, name, category, style, price, mrp, desc, fabric,
        occasion, pattern, sleeve_length, neck_design, care,
        image, rel_img, gallery, colors, sizes_json_str,
        sold_out_json_str, size_stock_json_str, stock, is_feat, is_new, is_best, is_arch,
        existing["created_at"] if existing and existing.get("created_at") else datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "message": f"Product '{name}' saved successfully.",
        "id": pid,
        "stock": stock,
        "size_stock": size_stock_map
    })

@app.route("/api/admin/products/visibility", methods=["POST"])
def api_admin_product_visibility():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    pid = str(data.get("id", "")).strip()
    if not pid:
        return jsonify({"ok": False, "error": "Product ID is required."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, is_archived FROM products WHERE id = ?", (pid,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": f"Product '{pid}' not found."}), 404

    if "is_archived" in data:
        new_arch = 1 if bool(data.get("is_archived")) else 0
    else:
        new_arch = 0 if row["is_archived"] else 1

    c.execute("UPDATE products SET is_archived = ? WHERE id = ?", (new_arch, pid))
    conn.commit()
    conn.close()

    state_label = "archived (hidden from storefront)" if new_arch else "published to storefront"
    return jsonify({
        "ok": True,
        "id": pid,
        "is_archived": new_arch,
        "message": f"'{row['name']}' is now {state_label}."
    })

@app.route("/api/admin/inventory/update", methods=["POST"])
def api_admin_inventory_update():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    pid = str(data.get("id", "")).strip()
    if not pid:
        return jsonify({"ok": False, "error": "Product ID is required."}), 400

    prod = get_product_from_db(pid)
    if not prod:
        return jsonify({"ok": False, "error": f"Product '{pid}' not found."}), 404

    sizes_list = prod.get("sizes") or ["S", "M", "L", "XL"]
    for core_sz in ("S", "M", "L", "XL"):
        if core_sz not in sizes_list and "Free Size" not in sizes_list:
            sizes_list.append(core_sz)

    size_stock_map = dict(prod.get("sizeStock", {}))
    incoming_sizes = data.get("size_stock") if isinstance(data.get("size_stock"), dict) else (data.get("sizeStock") if isinstance(data.get("sizeStock"), dict) else None)

    if incoming_sizes is not None:
        for sz, raw_val in incoming_sizes.items():
            try:
                q_val = int(raw_val)
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error": f"Invalid stock number for size {sz}."}), 400
            if q_val < 0:
                return jsonify({"ok": False, "error": f"Stock quantity for size {sz} cannot be negative."}), 400
            size_stock_map[sz] = q_val
            if sz not in sizes_list:
                sizes_list.append(sz)
        total_stock = sum(size_stock_map.values())
    elif "stock" in data:
        try:
            total_stock = int(data.get("stock", 0))
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "Stock must be a valid integer."}), 400
        if total_stock < 0:
            return jsonify({"ok": False, "error": "Stock quantity cannot be negative."}), 400
        base_q = total_stock // len(sizes_list) if sizes_list else 0
        rem = total_stock % len(sizes_list) if sizes_list else 0
        for idx, sz in enumerate(sizes_list):
            size_stock_map[sz] = base_q + (1 if idx < rem else 0)
    else:
        return jsonify({"ok": False, "error": "Provide size_stock or stock to update inventory."}), 400

    sold_out_list = [sz for sz in sizes_list if size_stock_map.get(sz, 0) <= 0]

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        UPDATE products
        SET stock = ?,
            sizes_json = ?,
            size_stock_json = ?,
            sold_out_sizes_json = ?
        WHERE id = ?
    """, (total_stock, json.dumps(sizes_list), json.dumps(size_stock_map), json.dumps(sold_out_list), pid))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "id": pid,
        "stock": total_stock,
        "size_stock": size_stock_map,
        "sold_out_sizes": sold_out_list,
        "message": f"Inventory updated for '{prod['name']}' (Total: {total_stock} units)."
    })

@app.route("/api/admin/upload-image", methods=["POST"])
def api_admin_upload_image():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    allowed_exts = {".jpg", ".jpeg", ".png", ".webp"}
    allowed_mimes = {"image/jpeg", "image/jpg", "image/pjpeg", "image/png", "image/webp"}
    max_bytes = MAX_UPLOAD_FILE_BYTES  # 5 MiB per file
    raw_bytes = None
    orig_filename = ""
    declared_mime = ""

    if "file" in request.files or "image" in request.files:
        f = request.files.get("file") or request.files.get("image")
        orig_filename = f.filename or ""
        declared_mime = str(getattr(f, "mimetype", "") or getattr(f, "content_type", "") or "").split(";")[0].strip().lower()
        raw_bytes = f.read()
    elif request.is_json:
        body = request.get_json(silent=True) or {}
        orig_filename = str(body.get("filename", "kurti.jpg")).strip()
        raw_data_url = str(body.get("data_url") or body.get("data") or "").strip()
        data_url = raw_data_url
        if raw_data_url.lower().startswith("data:") and "," in raw_data_url:
            header_part, data_url = raw_data_url.split(",", 1)
            mime_part = header_part[5:].split(";")[0].strip().lower()
            if mime_part:
                declared_mime = mime_part
        elif "," in raw_data_url:
            data_url = raw_data_url.split(",", 1)[1]
        if data_url:
            try:
                raw_bytes = base64.b64decode(data_url)
            except Exception:
                return jsonify({"ok": False, "error": "Invalid base64 image payload."}), 400

    if not raw_bytes:
        return jsonify({"ok": False, "error": "No image file provided."}), 400
    if len(raw_bytes) > max_bytes:
        return jsonify({"ok": False, "error": "Image file exceeds 5MB limit."}), 413

    clean_orig_name = os.path.basename(str(orig_filename or "").replace("\\", "/"))
    _, ext = os.path.splitext(clean_orig_name.lower())
    if ext not in allowed_exts:
        return jsonify({"ok": False, "error": "Only .jpg, .jpeg, .png, and .webp images are allowed."}), 400

    if declared_mime and declared_mime not in ("application/octet-stream", "binary/octet-stream"):
        if declared_mime not in allowed_mimes:
            return jsonify({"ok": False, "error": "Unsupported image MIME type."}), 400

    # Verify image magic bytes and enforce extension/MIME consistency to prevent disguised uploads
    detected_mime, matching_exts, _ = detect_image_magic_and_mime(raw_bytes)
    if not detected_mime:
        return jsonify({"ok": False, "error": "Uploaded file is not a valid JPEG, PNG, or WebP image."}), 400
    if ext not in matching_exts:
        return jsonify({
            "ok": False,
            "error": f"File extension '{ext}' does not match detected image content ({detected_mime})."
        }), 400
    if declared_mime and declared_mime in allowed_mimes:
        norm_decl = "image/jpeg" if declared_mime in ("image/jpg", "image/pjpeg") else declared_mime
        if norm_decl != detected_mime:
            return jsonify({
                "ok": False,
                "error": f"Declared MIME type '{declared_mime}' does not match image magic bytes ({detected_mime})."
            }), 400

    safe_stem = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in os.path.splitext(clean_orig_name)[0]).strip("-") or "kurti"
    safe_stem = safe_stem[:32].lower()
    unique_name = f"{safe_stem}-{secrets.token_hex(6)}{ext}"

    storage_cfg = get_supabase_storage_config()
    storage_backed = False
    if storage_cfg["enabled"]:
        try:
            _supabase_storage_upload(unique_name, raw_bytes, detected_mime)
            storage_backed = True
        except Exception:
            return jsonify({
                "ok": False,
                "error": "Failed to persist uploaded image to cloud storage. No changes were saved."
            }), 502

    try:
        uploads_dir = ensure_upload_dir()
        dest_path = os.path.realpath(os.path.join(uploads_dir, unique_name))
        if not dest_path.startswith(uploads_dir + os.sep):
            return jsonify({"ok": False, "error": "Invalid upload destination."}), 400
        with open(dest_path, "wb") as out_f:
            out_f.write(raw_bytes)
    except Exception:
        if not storage_backed:
            return jsonify({"ok": False, "error": "Failed to write uploaded image."}), 500

    rel_path = f"assets/uploads/{unique_name}"
    return jsonify({
        "ok": True,
        "image_path": rel_path,
        "storage_backed": storage_backed,
        "message": "Product image uploaded successfully."
    })

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
        dtype = str(data.get("discount_type", "percentage")).strip().lower()
        if dtype not in ("percentage", "fixed"):
            conn.close()
            return jsonify({"ok": False, "error": "Discount type must be 'percentage' or 'fixed'."}), 400
        try:
            val = int(data.get("discount_value", 0))
            min_ord = int(data.get("min_order_value", data.get("min_order", 0)) or 0)
            max_disc = int(data.get("max_discount", 0) or 0)
            limit = int(data.get("usage_limit", 1000) or 1000)
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"ok": False, "error": "Coupon numeric values must be valid integers."}), 400

        start_dt = str(data.get("start_date", "")).strip()
        exp = str(data.get("expiry_date", "2028-12-31")).strip()
        raw_cats = data.get("applicable_categories", "")
        if isinstance(raw_cats, list):
            app_cats = ", ".join(str(x).strip() for x in raw_cats if str(x).strip())
        else:
            app_cats = str(raw_cats or "").strip()
        if app_cats.lower() == "all":
            app_cats = ""

        raw_prods = data.get("applicable_products", "")
        if isinstance(raw_prods, list):
            app_prods = ", ".join(str(x).strip() for x in raw_prods if str(x).strip())
        else:
            app_prods = str(raw_prods or "").strip()
        if app_prods.lower() == "all":
            app_prods = ""

        is_auto = 1 if (data.get("is_auto_apply") or data.get("auto_apply")) else 0
        if "is_active" in data:
            is_act = 0 if data.get("is_active") is False else 1
        elif "active" in data:
            is_act = 0 if data.get("active") is False else 1
        else:
            is_act = 1
        desc = str(data.get("description", "")).strip()

        if not code or val <= 0:
            conn.close()
            return jsonify({"ok": False, "error": "Valid code and positive discount value required."}), 400
        if dtype == "percentage" and val > 95:
            conn.close()
            return jsonify({"ok": False, "error": "Percentage discount cannot exceed 95%."}), 400
        if min_ord < 0 or max_disc < 0 or limit < 0:
            conn.close()
            return jsonify({"ok": False, "error": "Minimum order, max discount, and usage limit must be non-negative."}), 400

        c.execute("""
            INSERT INTO coupons (
                code, discount_type, discount_value, min_order_value, max_discount,
                start_date, expiry_date, usage_limit, applicable_categories,
                applicable_products, is_auto_apply, is_active, description, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                is_active=excluded.is_active,
                description=excluded.description
        """, (code, dtype, val, min_ord, max_disc, start_dt, exp, limit, app_cats, app_prods, is_auto, is_act, desc, datetime.now().isoformat()))
        conn.commit()

    c.execute("SELECT * FROM coupons ORDER BY created_at DESC")
    rows = []
    for r in c.fetchall():
        d = dict(r)
        d["times_used"] = d.get("used_count", 0)
        d["active"] = bool(d.get("is_active", 1))
        d["min_order"] = d.get("min_order_value", 0)
        d["auto_apply"] = bool(d.get("is_auto_apply", 0))
        rows.append(d)
    conn.close()
    return jsonify({"ok": True, "coupons": rows})

@app.route("/api/admin/coupons/toggle", methods=["POST"])
def api_admin_coupon_toggle():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    code = str(data.get("code", "")).strip().upper()
    if not code:
        return jsonify({"ok": False, "error": "Coupon code is required."}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE coupons SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE code = ?", (code,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"Coupon {code} status toggled."})

@app.route("/api/admin/coupons/<code>", methods=["DELETE"])
def api_admin_coupon_delete(code):
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    clean_code = str(code or "").strip().upper()
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM coupons WHERE code = ?", (clean_code,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"Coupon {clean_code} deleted."})

@app.route("/api/admin/settings", methods=["GET", "POST"])
def api_admin_settings():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()

    forbidden_setting_keys = {
        "admin_passkey_hash", "admin_passkey_salt",
        "admin_secret_key", "admin_passkey", "admin_password",
        "razorpay_key_secret", "supabase_service_role_key",
        "supabase_service_key", "database_url"
    }

    if request.method == "POST":
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            conn.close()
            return jsonify({"ok": False, "error": "Invalid JSON object payload."}), 400
        if "new_admin_passkey" in data:
            new_pk = str(data.pop("new_admin_passkey") or "").strip()
            if new_pk:
                if len(new_pk) < 8:
                    conn.close()
                    return jsonify({"ok": False, "error": "New admin passkey must be at least 8 characters."}), 400
                pk_hash, pk_salt = hash_password(new_pk)
                c.execute(
                    "INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    ("admin_passkey_hash", pk_hash),
                )
                c.execute(
                    "INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    ("admin_passkey_salt", pk_salt),
                )

        if "announcement_text" in data and "announcements" not in data:
            txt = str(data["announcement_text"]).strip()
            data["announcements"] = [x.strip() for x in txt.split("|") if x.strip()] if txt else DEFAULT_ANNOUNCEMENTS
        if "standard_shipping_fee" in data and "shipping_fee" not in data:
            data["shipping_fee"] = data["standard_shipping_fee"]

        for num_key in ("shipping_fee", "free_shipping_threshold", "gst_percentage", "return_window_days"):
            if num_key in data and data[num_key] is not None and str(data[num_key]).strip() != "":
                try:
                    num_val = int(data[num_key])
                except (ValueError, TypeError):
                    conn.close()
                    return jsonify({"ok": False, "error": f"'{num_key}' must be a valid integer."}), 400
                if num_val < 0 or (num_key == "gst_percentage" and num_val > 100):
                    conn.close()
                    return jsonify({"ok": False, "error": f"'{num_key}' has an out-of-range value."}), 400
                data[num_key] = num_val

        for k, v in data.items():
            if k in forbidden_setting_keys:
                continue
            val_str = json.dumps(v) if isinstance(v, (list, dict)) else str(v)
            c.execute(
                "INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (k, val_str),
            )
        conn.commit()

    c.execute("SELECT key, value FROM site_settings")
    rows = c.fetchall()
    conn.close()

    cfg = load_config()
    settings = {
        "store_name": cfg.get("store_name", "Matra Naari"),
        "store_description": cfg.get("store_description", "Modern Kurtis Rooted in Craft"),
        "support_phone": cfg.get("support_phone", "+91 88493 66915"),
        "support_email": cfg.get("support_email", "hello@naari.in"),
        "free_shipping_threshold": cfg.get("free_shipping_threshold", 999),
        "shipping_fee": cfg.get("shipping_fee", 99),
        "standard_shipping_fee": cfg.get("shipping_fee", 99),
        "cod_enabled": cfg.get("cod_enabled", True),
        "sales_enabled": cfg.get("sales_enabled", True),
        "gst_percentage": cfg.get("gst_percentage", 5),
        "return_window_days": cfg.get("return_window_days", 7),
        "courier_provider": cfg.get("courier_provider", "Indian Postal Circle / Standard Courier")
    }
    for r in rows:
        if r["key"] in forbidden_setting_keys:
            continue
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
        d["return_id"] = d.get("id", "")
        d["status"] = normalize_return_status(d.get("status")) or "requested"
        d["request_type"] = d.get("action_type", "return")
        d["details"] = d.get("notes", "")
        rows.append(d)
    conn.close()
    return jsonify({"ok": True, "returns": rows})

@app.route("/api/admin/returns/status", methods=["POST"])
def api_admin_return_status():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    ret_id = str(data.get("return_id") or data.get("id") or "").strip()
    raw_status_val = data.get("status", "")
    raw_status = str(raw_status_val if raw_status_val is not None else "")
    notes = str(data.get("notes", "")).strip()

    if not ret_id or not raw_status.strip():
        return jsonify({"ok": False, "error": "Return ID and status required."}), 400

    if raw_status != raw_status.strip():
        return jsonify({"ok": False, "error": f"Invalid return status '{raw_status}'."}), 400

    target_status = normalize_return_status(raw_status)
    if not target_status:
        return jsonify({"ok": False, "error": f"Invalid return status '{raw_status}'."}), 400

    conn = get_db()
    conn.isolation_level = None
    c = conn.cursor()
    try:
        c.execute("BEGIN IMMEDIATE")
        lock_clause = _for_update_clause(c)
        c.execute(f"SELECT * FROM return_requests WHERE id = ?{lock_clause}", (ret_id,))
        existing_ret = c.fetchone()
        if not existing_ret:
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": "Return request not found."}), 404

        ret_dict = dict(existing_ret)
        current_status = normalize_return_status(ret_dict.get("status")) or "requested"
        allowed_next = ALLOWED_RETURN_TRANSITIONS.get(current_status, set())
        if target_status not in allowed_next:
            c.execute("ROLLBACK")
            conn.close()
            return jsonify({
                "ok": False,
                "error": f"Invalid return status transition from '{current_status}' to '{target_status}'."
            }), 400

        c.execute("SELECT order_status, payment_method, payment_status FROM orders WHERE id = ?", (ret_dict.get("order_id", ""),))
        ord_row = c.fetchone()
        if ord_row and target_status != "rejected":
            ord_status = str(ord_row["order_status"] or "").strip().lower()
            pay_method = str(ord_row["payment_method"] or "cod").strip().lower()
            pay_status = str(ord_row["payment_status"] or "").strip().lower()
            if ord_status == "cancelled" or ord_status == "pending_payment" or (pay_method == "razorpay" and pay_status != "paid"):
                c.execute("ROLLBACK")
                conn.close()
                return jsonify({
                    "ok": False,
                    "error": "Cannot approve or advance a return request for a cancelled or unpaid order."
                }), 400

        now_iso = datetime.now().isoformat()
        c.execute("""
            UPDATE return_requests
            SET status = ?,
                notes = COALESCE(NULLIF(?, ''), notes),
                updated_at = ?
            WHERE id = ?
        """, (target_status, notes, now_iso, ret_id))
        c.execute("COMMIT")
    except Exception:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        conn.close()
        return jsonify({"ok": False, "error": "Failed to update return request status."}), 500

    conn.close()

    return jsonify({
        "ok": True,
        "id": ret_id,
        "return_id": ret_id,
        "status": target_status,
        "message": f"Return request {ret_id} updated to '{target_status}'."
    })

# ================= Static Assets & HTML Routing =================

PUBLIC_HTML_PAGES = {
    "index.html",
    "shop.html",
    "product.html",
    "cart.html",
    "checkout.html",
    "order-confirmation.html",
    "account.html",
    "admin.html",
    "story.html",
    "contact.html",
}
PUBLIC_ROUTE_SLUGS = {page[:-5] for page in PUBLIC_HTML_PAGES}
PUBLIC_ROOT_FILES = {"favicon.png"}
PUBLIC_ASSET_DIRS = {"assets", "images"}
ALLOWED_PUBLIC_ASSET_EXTS = (
    ".jpg", ".jpeg", ".png", ".webp", ".gif", ".svg", ".ico",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".map"
)

FORBIDDEN_FILES = {
    "config.json", "config.local.json", "server.py", "test_checkout_flow.py",
    "test_admin_portal.py", "test_new_features.py", "test_postgres_migration.py",
    "test_supabase_integration.py", "setup_supabase_env.py", "migrate_sqlite_to_supabase.py",
    "provision_supabase_storage.py", "audit_live_render.py",
    ".env", ".env.local", ".env.example", "Procfile", "requirements.txt", "runtime.txt",
    "Dockerfile", ".gitignore", "gh"
}
FORBIDDEN_EXTS = (
    ".db", ".sqlite", ".sqlite3", ".py", ".pyc", ".pyo", ".pyd",
    ".env", ".log", ".bak", ".backup", ".old", ".orig", ".save",
    ".swp", ".tmp", ".sh", ".sql", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"
)
FORBIDDEN_DIRS = {"data", ".git", ".pytest_cache", "__pycache__", ".system_generated", "scratch"}
ASSET_EXTS = ALLOWED_PUBLIC_ASSET_EXTS + (".json",)


def _is_forbidden_public_path(clean_path):
    if not clean_path or ".." in clean_path or "\\" in clean_path:
        return True
    parts = [p for p in clean_path.split("/") if p]
    if not parts:
        return True
    base_name = parts[-1].lower()
    clean_lower = clean_path.lower()

    # Block any hidden file/directory (.env, .git, .pytest_cache, etc.)
    if any(p.startswith(".") for p in parts):
        return True
    if any(p in FORBIDDEN_DIRS or p.lower() in FORBIDDEN_DIRS for p in parts):
        return True
    if parts[-1] in FORBIDDEN_FILES or base_name in {f.lower() for f in FORBIDDEN_FILES}:
        return True
    if any(clean_lower.endswith(ext) for ext in FORBIDDEN_EXTS):
        return True
    # Block backup, server, config, or test files regardless of suffix (e.g. server.py.address-backup, server.py.security-backup-*)
    is_uploaded_image_path = (
        len(parts) == 3
        and parts[0] == "assets"
        and parts[1] == "uploads"
        and any(base_name.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".webp"))
    )
    if (
        base_name.startswith("server.py")
        or base_name.startswith("config.")
        or ".py." in base_name
        or (not is_uploaded_image_path and ("backup" in base_name or base_name.startswith("test_")))
    ):
        return True
    return False


@app.route("/favicon.ico")
def serve_favicon():
    return send_from_directory(BASE_DIR, "favicon.png", mimetype="image/png")


@app.route("/")
def serve_index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/<path:filename>")
def serve_static_file(filename):
    clean = filename.strip("/")
    if not clean:
        return send_from_directory(BASE_DIR, "index.html")

    parts = [p for p in clean.split("/") if p]

    # 1. Strict security & denylist check first
    if _is_forbidden_public_path(clean):
        return jsonify({"ok": False, "error": "Not Found"}), 404

    # 2. Strict allowlist for root HTML pages & clean route slugs
    #    e.g., /shop, /shop.html, /shop/index.html -> serves root shop.html
    if len(parts) == 1:
        single = parts[0]
        if single in PUBLIC_HTML_PAGES and os.path.isfile(os.path.join(BASE_DIR, single)):
            return send_from_directory(BASE_DIR, single)
        if single in PUBLIC_ROUTE_SLUGS and os.path.isfile(os.path.join(BASE_DIR, single + ".html")):
            return send_from_directory(BASE_DIR, single + ".html")
        if single in PUBLIC_ROOT_FILES and os.path.isfile(os.path.join(BASE_DIR, single)):
            return send_from_directory(BASE_DIR, single)

    if len(parts) == 2 and parts[1] == "index.html" and parts[0] in PUBLIC_ROUTE_SLUGS:
        root_page = parts[0] + ".html"
        if os.path.isfile(os.path.join(BASE_DIR, root_page)):
            return send_from_directory(BASE_DIR, root_page)

    # 3. Strict allowlist for public static asset directories (assets/* and images/* only)
    if parts[0] in PUBLIC_ASSET_DIRS and len(parts) >= 2:
        if any(clean.lower().endswith(ext) for ext in ALLOWED_PUBLIC_ASSET_EXTS):
            if len(parts) == 3 and parts[0] == "assets" and parts[1] == "uploads":
                upload_fname = parts[2]
                if _is_safe_upload_filename(upload_fname):
                    upload_dir_real = os.path.realpath(get_upload_dir())
                    upload_cand = os.path.realpath(os.path.join(upload_dir_real, upload_fname))
                    if upload_cand.startswith(upload_dir_real + os.sep) and os.path.isfile(upload_cand):
                        return send_from_directory(upload_dir_real, upload_fname)
                    legacy_dir_real = os.path.realpath(LEGACY_UPLOAD_DIR)
                    legacy_cand = os.path.realpath(os.path.join(legacy_dir_real, upload_fname))
                    if legacy_cand.startswith(legacy_dir_real + os.sep) and os.path.isfile(legacy_cand):
                        return send_from_directory(legacy_dir_real, upload_fname)
                    remote_bytes, remote_mime = _supabase_storage_download(upload_fname)
                    if remote_bytes is not None and remote_mime:
                        try:
                            cache_dir = ensure_upload_dir()
                            cache_cand = os.path.realpath(os.path.join(cache_dir, upload_fname))
                            if cache_cand.startswith(cache_dir + os.sep) and not os.path.isfile(cache_cand):
                                with open(cache_cand, "wb") as cf:
                                    cf.write(remote_bytes)
                        except Exception:
                            pass
                        return Response(
                            remote_bytes,
                            status=200,
                            mimetype=remote_mime,
                            headers={"Cache-Control": "public, max-age=86400"},
                        )
                return jsonify({"ok": False, "error": f"Asset not found: {clean}"}), 404

            base_abs = os.path.realpath(BASE_DIR)
            target_abs = os.path.realpath(os.path.join(BASE_DIR, clean))
            if target_abs.startswith(base_abs + os.sep) and os.path.isfile(target_abs):
                return send_from_directory(BASE_DIR, clean)
        return jsonify({"ok": False, "error": f"Asset not found: {clean}"}), 404

    # 4. Reject any other file with an extension or multi-segment path with 404 (never fall back to index.html or serve arbitrary root files)
    if "." in parts[-1] or len(parts) > 1 or any(clean.lower().endswith(ext) for ext in ASSET_EXTS):
        return jsonify({"ok": False, "error": "Not Found"}), 404

    return jsonify({"ok": False, "error": "Not Found"}), 404

def main():
    init_db()
    db_display = f"PostgreSQL ({mask_database_url(get_database_url())})" if is_postgres_mode() else f"SQLite ({DB_PATH})"
    print("=" * 60)
    print(f" Matra Naari E-Commerce Platform Server running on port {PORT}")
    print(f" Storefront: http://localhost:{PORT}")
    print(f" API Base URL: http://localhost:{PORT}/api")
    print(f" Admin Dashboard: http://localhost:{PORT}/admin.html")
    print(f" Database: {db_display}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=PORT, debug=False)

if __name__ == "__main__":
    main()
