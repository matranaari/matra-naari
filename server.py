#!/usr/bin/env python3
"""
Naari - E-commerce Backend Server (Flask Edition)
Features:
- Dedicated REST API server for order creation, payments, and order tracking
- Serves static website pages and assets with clean directory routing
- SQLite database persistence for orders
- Server-side Razorpay order creation and cryptographic HMAC-SHA256 signature verification
- Cash on Delivery (COD) order placement
- Full CORS support allowing requests from static frontend servers (e.g. port 8000, 5500)
"""

import os
import sys
import json
import sqlite3
import hmac
import hashlib
import base64
import requests
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
DB_PATH = os.environ.get("DB_PATH", os.path.join(DATA_DIR, "orders.db"))
CONFIG_PATH = os.environ.get("CONFIG_PATH", os.path.join(BASE_DIR, "config.json"))
PORT = int(os.environ.get("PORT", 8000))

# Catalog prices (server-side authoritative pricing to prevent client tampering)
PRODUCT_CATALOG = {
    "straight": {"name": "Gulmohar Straight Kurti", "price": 1299},
    "aline": {"name": "Chandni A-Line Kurti", "price": 1499},
    "anarkali": {"name": "Genda Anarkali", "price": 2499},
    "short": {"name": "Neel Short Kurti", "price": 899},
    "angrakha": {"name": "Tulsi Angrakha", "price": 1799},
    "kaftan": {"name": "Sandhya Kaftan Kurti", "price": 1599},
    "coord": {"name": "Gulabi Kurta Set", "price": 2199},
}

def load_config():
    config = {
        "razorpay_key_id": "",
        "razorpay_key_secret": "",
        "currency": "INR",
        "store_name": "Naari",
        "store_description": "Modern Kurtis Rooted in Craft",
        "support_phone": "+91 88493 66915",
        "support_email": "hello@naari.in"
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                disk_cfg = json.load(f)
                config.update(disk_cfg)
        except Exception as e:
            print(f"[Warning] Error loading config.json: {e}")

    # Production environment variables take precedence over config.json
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

def init_db():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
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
    conn.commit()
    conn.close()

def generate_order_id():
    now_str = datetime.now().strftime("%Y%m%d%H%M%S")
    rand_suffix = os.urandom(3).hex().upper()
    return f"NAARI-{now_str}-{rand_suffix}"

def validate_and_compute_totals(items):
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

        if pid in PRODUCT_CATALOG:
            name = PRODUCT_CATALOG[pid]["name"]
            price = PRODUCT_CATALOG[pid]["price"]
        else:
            name = str(item.get("name") or f"Naari Kurti ({pid})")
            try:
                price = int(item.get("price", 0))
            except (ValueError, TypeError):
                price = 0
            if price <= 0:
                return None, f"Unrecognized product: {pid}"

        item_subtotal = price * qty
        subtotal += item_subtotal

        computed_items.append({
            "id": pid,
            "name": name,
            "color": color,
            "size": size,
            "qty": qty,
            "price": price,
            "subtotal": item_subtotal,
            "image": item.get("image", "assets/hero.jpg")
        })

    if not computed_items:
        return None, "Shopping bag contains no valid items."

    shipping = 0  # Free delivery across India
    total_amount = subtotal + shipping
    return {
        "items": computed_items,
        "subtotal": subtotal,
        "shipping": shipping,
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

# ================= Initialize Flask App =================
app = Flask(__name__, static_folder=BASE_DIR)
app.url_map.strict_slashes = False
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Ensure database schema is created on startup (required for WSGI servers like Gunicorn)
init_db()

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

@app.errorhandler(404)
def handle_404(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": f"API endpoint not found: {request.path}"}), 404
    return send_from_directory(BASE_DIR, "index.html"), 404

@app.errorhandler(405)
def handle_405(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": f"Method {request.method} not allowed on {request.path}"}), 405
    return "Method Not Allowed", 405

@app.errorhandler(500)
def handle_500(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": f"Internal server error: {str(e)}"}), 500
    return "Internal Server Error", 500

# ================= REST API Endpoints =================

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
        "store_name": cfg.get("store_name", "Naari"),
        "currency": cfg.get("currency", "INR"),
        "support_phone": cfg.get("support_phone", "+91 88493 66915"),
        "support_email": cfg.get("support_email", "hello@naari.in")
    })

@app.route("/api/create-order", methods=["POST"])
def api_create_order():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Invalid request body (JSON expected)"}), 400

    cust = data.get("customer", {})
    err = validate_customer_info(cust)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    calc, err = validate_and_compute_totals(data.get("items", []))
    if err:
        return jsonify({"ok": False, "error": err}), 400

    cfg = load_config()
    configured = is_razorpay_configured(cfg)
    order_id = generate_order_id()
    amount_paise = calc["total_amount"] * 100

    if not configured:
        # Development / test mode: create simulated test Razorpay order
        test_rzp_order_id = f"order_test_{os.urandom(6).hex()}"
        now_iso = datetime.now().isoformat()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO orders (
                id, customer_name, customer_email, customer_phone,
                address_line1, address_line2, city, state, pincode,
                payment_method, payment_status, razorpay_order_id,
                subtotal, shipping, total_amount, items_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            test_rzp_order_id,
            calc["subtotal"],
            calc["shipping"],
            calc["total_amount"],
            json.dumps(calc["items"]),
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
            "customer": {
                "name": cust.get("name"),
                "email": cust.get("email"),
                "phone": cust.get("phone")
            }
        })

    # Real Razorpay Order Creation via Razorpay API (Secret stays on server!)
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
            "customer_email": cust.get("email")
        }
    }

    try:
        resp = requests.post(rzp_url, auth=(key_id, key_secret), json=payload, timeout=15)
        if resp.status_code != 200:
            print(f"[Razorpay API Error] HTTP {resp.status_code}: {resp.text}")
            return jsonify({
                "ok": False,
                "error": f"Razorpay API error ({resp.status_code}). Please verify your Razorpay API keys in config.json."
            }), 400
        rzp_res = resp.json()
        razorpay_order_id = rzp_res.get("id")
    except Exception as e:
        print(f"[Razorpay Network Error]: {e}")
        return jsonify({
            "ok": False,
            "error": "Unable to connect to Razorpay. Please check your internet connection."
        }), 502

    # Save to SQLite
    now_iso = datetime.now().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO orders (
            id, customer_name, customer_email, customer_phone,
            address_line1, address_line2, city, state, pincode,
            payment_method, payment_status, razorpay_order_id,
            subtotal, shipping, total_amount, items_json,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        razorpay_order_id,
        calc["subtotal"],
        calc["shipping"],
        calc["total_amount"],
        json.dumps(calc["items"]),
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
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE orders SET payment_status = 'failed', updated_at = ? WHERE id = ? OR razorpay_order_id = ?", (
                datetime.now().isoformat(), order_id, rzp_order_id
            ))
            conn.commit()
            conn.close()
            return jsonify({"ok": False, "error": "Cryptographic payment signature verification failed"}), 400

    # Verification successful -> update order to paid in DB
    now_iso = datetime.now().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        UPDATE orders
        SET payment_status = 'paid',
            razorpay_payment_id = ?,
            razorpay_signature = ?,
            updated_at = ?
        WHERE id = ? OR razorpay_order_id = ?
    """, (rzp_payment_id or "pay_simulated_success", rzp_signature or "sig_simulated_valid", now_iso, order_id, rzp_order_id))
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

    cust = data.get("customer", {})
    err = validate_customer_info(cust)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    calc, err = validate_and_compute_totals(data.get("items", []))
    if err:
        return jsonify({"ok": False, "error": err}), 400

    order_id = generate_order_id()
    now_iso = datetime.now().isoformat()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO orders (
            id, customer_name, customer_email, customer_phone,
            address_line1, address_line2, city, state, pincode,
            payment_method, payment_status,
            subtotal, shipping, total_amount, items_json,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        calc["subtotal"],
        calc["shipping"],
        calc["total_amount"],
        json.dumps(calc["items"]),
        now_iso,
        now_iso
    ))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "order_id": order_id,
        "status": "cod_confirmed",
        "total_amount": calc["total_amount"]
    })

@app.route("/api/order-details", methods=["GET"])
def api_order_details():
    order_id = request.args.get("order_id", "").strip()
    if not order_id:
        return jsonify({"ok": False, "error": "Order ID is required"}), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT id, customer_name, customer_email, customer_phone,
               address_line1, address_line2, city, state, pincode,
               payment_method, payment_status, razorpay_payment_id,
               subtotal, shipping, total_amount, items_json, created_at
        FROM orders WHERE id = ? OR razorpay_order_id = ?
    """, (order_id, order_id))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": f"Order not found: {order_id}"}), 404

    order_dict = dict(row)
    order_dict["items"] = json.loads(order_dict.pop("items_json", "[]"))
    return jsonify({"ok": True, "order": order_dict})

FORBIDDEN_FILES = {
    "config.json", "server.py", "test_checkout_flow.py", ".env",
    "Procfile", "requirements.txt", "runtime.txt", "Dockerfile", ".gitignore"
}
FORBIDDEN_EXTS = (".db", ".sqlite", ".sqlite3", ".py", ".env", ".log", ".bak", ".sh")
FORBIDDEN_DIRS = {"data", ".git", ".system_generated", "scratch"}

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
    
    # Direct file match
    if os.path.isfile(target):
        return send_from_directory(BASE_DIR, clean)

    # Directory match with index.html (e.g. checkout/ -> checkout/index.html)
    if os.path.isdir(target):
        sub_index = os.path.join(target, "index.html")
        if os.path.isfile(sub_index):
            return send_from_directory(target, "index.html")

    # .html suffix match (e.g. /checkout -> /checkout.html)
    if os.path.isfile(target + ".html"):
        return send_from_directory(BASE_DIR, clean + ".html")

    return send_from_directory(BASE_DIR, "index.html")

def main():
    init_db()
    print("=" * 55)
    print(f" Naari E-Commerce API & Backend Server running on port {PORT}")
    print(f" API Base URL: http://localhost:{PORT}")
    print(f" Database: {DB_PATH}")
    print("=" * 55)
    app.run(host="0.0.0.0", port=PORT, debug=False)

if __name__ == "__main__":
    main()
