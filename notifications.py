#!/usr/bin/env python3
"""
Matra Naari — Transactional Email & WhatsApp Order Notification Engine
======================================================================
Handles post-order confirmation notifications after an order is durably
persisted and (for online payments) cryptographically verified:
  1. Customer Order Confirmation Email (Branded HTML + Plain Text)
  2. Business Owner New-Order Alert Email (to matranaari@gmail.com)
  3. Customer WhatsApp Order Confirmation (Meta WhatsApp Cloud API Utility Template)

Key Security, Reliability & Accounting Guarantees:
- Triggered ONLY after committed order persistence:
  * COD orders: after `orders` row is committed with `order_status='confirmed'`.
  * Razorpay orders: ONLY after server-side HMAC-SHA256 verification and DB commit
    (`payment_status='paid'`, `order_status='confirmed'`). Never triggered on
    `pending_payment`, failed, or abandoned checkouts.
- Strict Payment Status Honesty:
  * COD orders explicitly state that payment is pending collection on delivery
    unless verified collection is recorded.
  * Razorpay orders require verified `payment_status='paid'` and `razorpay_payment_id`.
- Separate Per-Channel State & Idempotency (`order_notifications` table):
  * Tracks `customer_email`, `owner_email`, and `customer_whatsapp` independently
    with a unique constraint on `(order_id, channel, event_type)`.
  * Prevents duplicate emails or WhatsApp messages on repeated API calls or retries.
  * Bounded retry attempts (`max_attempts = 3`) with safe failure isolation so
    provider outages never fail checkout or duplicate orders.
- Privacy & Credential Safety:
  * Stores only masked recipient identifiers (`a***a@example.com`, `+91******6915`)
    in logs and delivery tracking tables.
  * Rejects raw personal Gmail passwords; uses authenticated domain sender
    (`orders@matranaari.com`) with `Reply-To: matranaari@gmail.com`.
"""

import datetime
import html
import json
import os
import re
import secrets
import time
from datetime import timezone, timedelta
import requests

IST = timezone(timedelta(hours=5, minutes=30))

OFFICIAL_BUSINESS_EMAIL = "matranaari@gmail.com"
OFFICIAL_WHATSAPP_E164 = "+918849366915"
OFFICIAL_WHATSAPP_WA_ID = "918849366915"
OFFICIAL_WHATSAPP_DISPLAY = "+91 88493 66915"
OFFICIAL_WHATSAPP_URL = "https://wa.me/918849366915"
DEFAULT_AUTHENTICATED_SENDER = "Matra Naari <orders@matranaari.com>"

MAX_NOTIFICATION_ATTEMPTS = 3

# Pluggable transport hooks for isolated automated testing (never used in production unless set by tests)
_TEST_EMAIL_TRANSPORT = None
_TEST_WHATSAPP_TRANSPORT = None


def set_test_transports(email_fn=None, whatsapp_fn=None):
    global _TEST_EMAIL_TRANSPORT, _TEST_WHATSAPP_TRANSPORT
    _TEST_EMAIL_TRANSPORT = email_fn
    _TEST_WHATSAPP_TRANSPORT = whatsapp_fn


def mask_email(email_str: str) -> str:
    s = str(email_str or "").strip()
    if "@" not in s:
        return "***"
    local, domain = s.split("@", 1)
    if len(local) <= 2:
        masked_local = local[0] + "***" if local else "***"
    else:
        masked_local = f"{local[0]}***{local[-1]}"
    return f"{masked_local}@{domain}"


def mask_phone(phone_str: str) -> str:
    digits = re.sub(r"\D", "", str(phone_str or ""))
    if len(digits) >= 10:
        last4 = digits[-4:]
        return f"+91******{last4}"
    return "+91**********"


def normalize_indian_whatsapp_recipient(phone_str: str) -> str:
    """
    Normalizes a 10-digit Indian mobile number to Meta Cloud API wa_id format ('91XXXXXXXXXX').
    Returns '' if invalid.
    """
    digits = re.sub(r"\D", "", str(phone_str or ""))
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    elif digits.startswith("0") and len(digits) == 11:
        digits = digits[1:]
    if len(digits) == 10 and digits[0] in ("6", "7", "8", "9"):
        return f"91{digits}"
    return ""


def format_ist_timestamp(raw_iso: str = "") -> str:
    s = str(raw_iso or "").strip()
    if s:
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=IST)
            else:
                dt = dt.astimezone(IST)
            return dt.strftime("%d %b %Y, %I:%M:%S %p IST")
        except Exception:
            pass
    return datetime.datetime.now(IST).strftime("%d %b %Y, %I:%M:%S %p IST")


def get_notification_config() -> dict:
    """
    Loads notification provider settings strictly from environment variables.
    Never exposes API keys or tokens in public responses or logs.
    """
    email_provider = (os.environ.get("EMAIL_PROVIDER") or "resend").strip().lower()
    resend_api_key = (os.environ.get("RESEND_API_KEY") or "").strip()
    brevo_api_key = (os.environ.get("BREVO_API_KEY") or "").strip()

    from_addr = (os.environ.get("EMAIL_FROM_ADDRESS") or DEFAULT_AUTHENTICATED_SENDER).strip()
    reply_to = (os.environ.get("EMAIL_REPLY_TO") or OFFICIAL_BUSINESS_EMAIL).strip()
    owner_email = (os.environ.get("OWNER_NOTIFICATION_EMAIL") or OFFICIAL_BUSINESS_EMAIL).strip()

    # Security check: Never allow personal @gmail.com as the authenticated From header
    # on transactional cloud providers (DMARC/SPF will reject or land in spam).
    from_lower = from_addr.lower()
    if "@gmail.com" in from_lower or "@googlemail.com" in from_lower:
        from_addr = DEFAULT_AUTHENTICATED_SENDER

    wa_enabled_env = (os.environ.get("WHATSAPP_ENABLED") or "false").strip().lower()
    whatsapp_enabled = bool(
        _TEST_WHATSAPP_TRANSPORT is not None
        or wa_enabled_env in ("1", "true", "yes", "on")
    )
    wa_provider = (os.environ.get("WHATSAPP_PROVIDER") or "meta_cloud").strip().lower()
    wa_token = (os.environ.get("WHATSAPP_ACCESS_TOKEN") or "").strip()
    wa_phone_id = (os.environ.get("WHATSAPP_PHONE_NUMBER_ID") or "").strip()
    wa_template = (os.environ.get("WHATSAPP_TEMPLATE_NAME") or "matra_naari_order_confirmation").strip()
    wa_lang = (os.environ.get("WHATSAPP_TEMPLATE_LANG") or "en").strip()
    wa_sender_number = (os.environ.get("WHATSAPP_BUSINESS_NUMBER") or OFFICIAL_WHATSAPP_E164).strip()

    allowed_raw = (os.environ.get("NOTIFICATION_ALLOWED_RECIPIENTS") or "").strip()
    allowed_recipients = {
        x.strip().lower() for x in allowed_raw.split(",") if x.strip()
    }

    email_configured = bool(
        _TEST_EMAIL_TRANSPORT is not None
        or (email_provider == "resend" and resend_api_key)
        or (email_provider == "brevo" and brevo_api_key)
    )
    whatsapp_configured = bool(
        whatsapp_enabled
        and (
            _TEST_WHATSAPP_TRANSPORT is not None
            or (wa_provider == "meta_cloud" and wa_token and wa_phone_id)
        )
    )

    return {
        "email_provider": email_provider,
        "email_configured": email_configured,
        "resend_api_key": resend_api_key,
        "brevo_api_key": brevo_api_key,
        "from_address": from_addr,
        "reply_to": reply_to,
        "owner_email": owner_email,
        "whatsapp_enabled": whatsapp_enabled,
        "whatsapp_provider": wa_provider,
        "whatsapp_configured": whatsapp_configured,
        "whatsapp_access_token": wa_token,
        "whatsapp_phone_number_id": wa_phone_id,
        "whatsapp_template_name": wa_template,
        "whatsapp_template_lang": wa_lang,
        "whatsapp_sender_number": wa_sender_number,
        "allowed_recipients": allowed_recipients,
        "required_email_env_vars_present": {
            "EMAIL_PROVIDER": bool((os.environ.get("EMAIL_PROVIDER") or "").strip()),
            "RESEND_API_KEY": bool(resend_api_key),
            "EMAIL_FROM_ADDRESS": bool((os.environ.get("EMAIL_FROM_ADDRESS") or "").strip()),
            "EMAIL_REPLY_TO": bool((os.environ.get("EMAIL_REPLY_TO") or "").strip()),
            "OWNER_NOTIFICATION_EMAIL": bool((os.environ.get("OWNER_NOTIFICATION_EMAIL") or "").strip()),
        },
    }


def classify_verified_order_payment(order_dict: dict) -> dict:
    """
    Strictly evaluates payment method and verified payment status:
    - COD orders are NEVER marked as paid unless verified collection is recorded.
    - Razorpay orders are ONLY marked as paid when `payment_status == 'paid'` AND
      a real `razorpay_payment_id` is present (never on `pending_payment` or `pay_test_`).
    """
    pay_method = str(order_dict.get("payment_method") or "cod").strip().lower()
    pay_status = str(order_dict.get("payment_status") or "").strip().lower()
    ord_status = str(order_dict.get("order_status") or "confirmed").strip().lower()
    rzp_pay_id = str(order_dict.get("razorpay_payment_id") or "").strip()
    total_amt = int(float(order_dict.get("total_amount") or 0))

    if pay_method == "razorpay":
        is_verified_paid = (
            pay_status in ("paid", "captured", "verified")
            and bool(rzp_pay_id)
            and not rzp_pay_id.startswith("pay_test_")
            and ord_status != "pending_payment"
        )
        if is_verified_paid:
            return {
                "method_label": "Razorpay Online Payment",
                "is_verified_paid": True,
                "eligible_for_confirmation": True,
                "status_badge": f"PAID & VERIFIED (Ref: {rzp_pay_id})",
                "status_detail": (
                    f"Online payment of ₹{total_amt:,} has been cryptographically verified "
                    f"(Razorpay Payment ID: {rzp_pay_id})."
                ),
                "wa_payment_label": f"Razorpay Online (Paid & Verified — {rzp_pay_id})",
            }
        return {
            "method_label": "Razorpay Online Payment",
            "is_verified_paid": False,
            "eligible_for_confirmation": False,
            "status_badge": f"PAYMENT UNVERIFIED ({pay_status or 'pending'})",
            "status_detail": "Online payment has not been verified yet.",
            "wa_payment_label": "Razorpay Online (Unverified)",
        }

    # Cash on Delivery (COD)
    is_cod_collected = pay_status in ("paid", "cod_collected", "collected", "payment_received", "settled")
    eligible = ord_status not in ("pending_payment", "cancelled", "failed")
    if is_cod_collected:
        return {
            "method_label": "Cash on Delivery (COD)",
            "is_verified_paid": True,
            "eligible_for_confirmation": eligible,
            "status_badge": "PAID — COD Collection Verified",
            "status_detail": f"COD payment of ₹{total_amt:,} has been verified as collected.",
            "wa_payment_label": "Cash on Delivery (Paid — Collection Verified)",
        }

    return {
        "method_label": "Cash on Delivery (COD)",
        "is_verified_paid": False,
        "eligible_for_confirmation": eligible,
        "status_badge": f"Payment Pending Collection on Delivery (₹{total_amt:,})",
        "status_detail": (
            f"Payment of ₹{total_amt:,} is pending collection at the time of delivery. "
            "Please keep the exact amount or UPI ready upon arrival."
        ),
        "wa_payment_label": f"Cash on Delivery (Pending Collection on Delivery: ₹{total_amt:,})",
    }


def _format_full_delivery_address(order_dict: dict) -> str:
    house_no = str(order_dict.get("house_no") or "").strip()
    street_area = str(order_dict.get("street_area") or "").strip()
    addr1 = str(order_dict.get("address_line1") or "").strip()
    addr2 = str(order_dict.get("address_line2") or "").strip()
    city = str(order_dict.get("city") or "").strip()
    state = str(order_dict.get("state") or "").strip()
    pincode = str(order_dict.get("pincode") or "").strip()

    parts = []
    for p in [addr1 or f"{house_no}, {street_area}".strip(", "), addr2, city, state, pincode]:
        clean_p = str(p or "").strip()
        if clean_p and clean_p not in parts:
            parts.append(clean_p)
    return ", ".join(parts) or "Not Recorded"


def _parse_order_items(order_dict: dict) -> list:
    raw = order_dict.get("items")
    if raw is None:
        raw = order_dict.get("items_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = []
    if not isinstance(raw, list):
        return []
    return [it for it in raw if isinstance(it, dict)]


def build_customer_confirmation_email(order_dict: dict) -> dict:
    """
    Builds the branded Matra Naari cream & burgundy HTML + plain-text email for the customer.
    """
    oid = str(order_dict.get("id") or order_dict.get("order_id") or "").strip()
    cust_name = str(order_dict.get("customer_name") or "Valued Customer").strip()
    ist_time = format_ist_timestamp(order_dict.get("created_at") or "")
    items = _parse_order_items(order_dict)
    subtotal = int(float(order_dict.get("subtotal") or 0))
    discount = int(float(order_dict.get("discount_amount") or 0))
    coupon = str(order_dict.get("coupon_code") or "").strip()
    shipping = int(float(order_dict.get("shipping") or 0))
    total_amount = int(float(order_dict.get("total_amount") or 0))
    full_addr = _format_full_delivery_address(order_dict)
    pay_info = classify_verified_order_payment(order_dict)

    item_rows_html = []
    item_lines_text = []
    for it in items:
        pname = html.escape(str(it.get("name") or "Kurti").strip())
        sz = html.escape(str(it.get("size") or "M").strip())
        col = html.escape(str(it.get("color") or "Standard").strip())
        qty = int(it.get("qty") or it.get("quantity") or 1)
        price = int(float(it.get("price") or 0))
        line_total = int(float(it.get("subtotal") or (price * qty)))
        item_rows_html.append(f"""
          <tr>
            <td style="padding:12px 8px;border-bottom:1px solid #E6DEC8;font-family:'Manrope',Arial,sans-serif;font-size:14px;color:#231917;">
              <strong>{pname}</strong><br/>
              <span style="font-size:12px;color:#6E5A56;">Size: {sz} &middot; Color: {col}</span>
            </td>
            <td align="center" style="padding:12px 8px;border-bottom:1px solid #E6DEC8;font-family:'Manrope',Arial,sans-serif;font-size:14px;color:#231917;">{qty}</td>
            <td align="right" style="padding:12px 8px;border-bottom:1px solid #E6DEC8;font-family:'Manrope',Arial,sans-serif;font-size:14px;color:#231917;">&#8377;{price:,}</td>
            <td align="right" style="padding:12px 8px;border-bottom:1px solid #E6DEC8;font-family:'Manrope',Arial,sans-serif;font-size:14px;font-weight:600;color:#231917;">&#8377;{line_total:,}</td>
          </tr>
        """)
        item_lines_text.append(f"- {it.get('name', 'Kurti')} (Size: {sz}, Color: {col}) x {qty} @ ₹{price:,} = ₹{line_total:,}")

    discount_html = ""
    if discount > 0:
        cp_label = f" ({html.escape(coupon)})" if coupon else ""
        discount_html = f"""
          <tr>
            <td colspan="3" align="right" style="padding:6px 8px;font-size:13px;color:#2E6B47;">Discount{cp_label}:</td>
            <td align="right" style="padding:6px 8px;font-size:13px;font-weight:600;color:#2E6B47;">-&#8377;{discount:,}</td>
          </tr>
        """

    shipping_str = "FREE" if shipping == 0 else f"&#8377;{shipping:,}"
    badge_bg = "#E9F8ED" if pay_info["is_verified_paid"] else "#FDF6E7"
    badge_fg = "#165B33" if pay_info["is_verified_paid"] else "#7A4B12"

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Order Confirmation — {html.escape(oid)}</title>
</head>
<body style="margin:0;padding:0;background-color:#FAF6F0;font-family:'Manrope',Arial,sans-serif;color:#231917;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#FAF6F0;padding:28px 12px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#FFFDF9;border:1px solid #E6DEC8;">
          <!-- Header -->
          <tr>
            <td align="center" style="background-color:#6B2D31;padding:28px 24px;color:#FAF6F0;">
              <div style="font-family:'Cormorant Garamond',Georgia,serif;font-size:30px;font-weight:600;letter-spacing:1.5px;color:#FAF6F0;">MATRA NAARI</div>
              <div style="font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#E6DEC8;margin-top:4px;">Woven with Meaning</div>
            </td>
          </tr>
          <!-- Greeting & Summary -->
          <tr>
            <td style="padding:28px 24px;">
              <p style="margin:0 0 8px 0;font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#6B2D31;font-weight:600;">Order Confirmation</p>
              <h1 style="margin:0 0 12px 0;font-family:'Cormorant Garamond',Georgia,serif;font-size:26px;color:#231917;">Thank you for your order, {html.escape(cust_name)}!</h1>
              <p style="margin:0 0 20px 0;font-size:14px;line-height:1.6;color:#5A4946;">
                Your order <strong>{html.escape(oid)}</strong> has been received and confirmed. Below are your complete order and payment verification details.
              </p>

              <!-- Order Meta Box -->
              <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#FAF6F0;border:1px solid #E6DEC8;padding:16px;margin-bottom:24px;">
                <tr>
                  <td style="font-size:13px;color:#5A4946;padding:4px 0;"><strong>Order ID:</strong> {html.escape(oid)}</td>
                  <td align="right" style="font-size:13px;color:#5A4946;padding:4px 0;"><strong>Order Date (IST):</strong> {html.escape(ist_time)}</td>
                </tr>
                <tr>
                  <td style="font-size:13px;color:#5A4946;padding:4px 0;"><strong>Payment Method:</strong> {html.escape(pay_info['method_label'])}</td>
                  <td align="right" style="font-size:13px;color:#5A4946;padding:4px 0;"><strong>Order Status:</strong> Confirmed</td>
                </tr>
                <tr>
                  <td colspan="2" style="padding-top:10px;">
                    <div style="background-color:{badge_bg};color:{badge_fg};padding:10px 12px;font-size:12px;font-weight:600;border-radius:2px;">
                      Verified Payment Status: {html.escape(pay_info['status_badge'])}<br/>
                      <span style="font-weight:400;">{html.escape(pay_info['status_detail'])}</span>
                    </div>
                  </td>
                </tr>
              </table>

              <!-- Items Table -->
              <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin-bottom:20px;">
                <thead>
                  <tr style="background-color:#FAF6F0;">
                    <th align="left" style="padding:10px 8px;border-bottom:2px solid #6B2D31;font-size:12px;text-transform:uppercase;color:#6B2D31;">Product</th>
                    <th align="center" style="padding:10px 8px;border-bottom:2px solid #6B2D31;font-size:12px;text-transform:uppercase;color:#6B2D31;">Qty</th>
                    <th align="right" style="padding:10px 8px;border-bottom:2px solid #6B2D31;font-size:12px;text-transform:uppercase;color:#6B2D31;">Price</th>
                    <th align="right" style="padding:10px 8px;border-bottom:2px solid #6B2D31;font-size:12px;text-transform:uppercase;color:#6B2D31;">Total</th>
                  </tr>
                </thead>
                <tbody>
                  {''.join(item_rows_html)}
                  <tr>
                    <td colspan="3" align="right" style="padding:10px 8px 4px 8px;font-size:13px;color:#5A4946;">Subtotal:</td>
                    <td align="right" style="padding:10px 8px 4px 8px;font-size:13px;color:#231917;">&#8377;{subtotal:,}</td>
                  </tr>
                  {discount_html}
                  <tr>
                    <td colspan="3" align="right" style="padding:4px 8px;font-size:13px;color:#5A4946;">Shipping Charges:</td>
                    <td align="right" style="padding:4px 8px;font-size:13px;color:#231917;">{shipping_str}</td>
                  </tr>
                  <tr>
                    <td colspan="3" align="right" style="padding:10px 8px;border-top:1px solid #E6DEC8;font-size:15px;font-weight:700;color:#6B2D31;">Final Order Amount:</td>
                    <td align="right" style="padding:10px 8px;border-top:1px solid #E6DEC8;font-size:16px;font-weight:700;color:#6B2D31;">&#8377;{total_amount:,}</td>
                  </tr>
                </tbody>
              </table>

              <!-- Delivery Address -->
              <div style="background-color:#FAF6F0;border:1px solid #E6DEC8;padding:14px 16px;margin-bottom:24px;">
                <div style="font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#6B2D31;font-weight:600;margin-bottom:4px;">Delivery Address</div>
                <div style="font-size:13px;color:#231917;line-height:1.5;">
                  <strong>{html.escape(cust_name)}</strong><br/>
                  {html.escape(full_addr)}
                </div>
              </div>

              <!-- Support Footer -->
              <div style="border-top:1px solid #E6DEC8;padding-top:18px;font-size:13px;color:#5A4946;line-height:1.6;">
                <strong>Need Assistance?</strong><br/>
                WhatsApp Support: <a href="{OFFICIAL_WHATSAPP_URL}" style="color:#6B2D31;font-weight:600;text-decoration:underline;">{OFFICIAL_WHATSAPP_DISPLAY}</a><br/>
                Email Support: <a href="mailto:{OFFICIAL_BUSINESS_EMAIL}" style="color:#6B2D31;font-weight:600;text-decoration:underline;">{OFFICIAL_BUSINESS_EMAIL}</a><br/>
                Website: <a href="https://matranaari.com" style="color:#6B2D31;text-decoration:underline;">https://matranaari.com</a>
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    text_body = (
        f"MATRA NAARI — Woven with Meaning\n"
        f"Order Confirmation: {oid}\n\n"
        f"Dear {cust_name},\n"
        f"Thank you for shopping with Matra Naari! Your order {oid} is confirmed.\n\n"
        f"Order ID: {oid}\n"
        f"Order Date (IST): {ist_time}\n"
        f"Payment Method: {pay_info['method_label']}\n"
        f"Verified Payment Status: {pay_info['status_badge']}\n"
        f"{pay_info['status_detail']}\n\n"
        f"Items Ordered:\n" + "\n".join(item_lines_text) + "\n\n"
        f"Subtotal: ₹{subtotal:,}\n"
        + (f"Discount: -₹{discount:,}\n" if discount > 0 else "")
        + f"Shipping: {'FREE' if shipping == 0 else f'₹{shipping:,}'}\n"
        f"Final Order Amount: ₹{total_amount:,}\n\n"
        f"Delivery Address:\n{cust_name}\n{full_addr}\n\n"
        f"Customer Support:\n"
        f"WhatsApp: {OFFICIAL_WHATSAPP_DISPLAY} ({OFFICIAL_WHATSAPP_URL})\n"
        f"Email: {OFFICIAL_BUSINESS_EMAIL}\n"
    )

    return {
        "subject": f"Order Confirmed: {oid} — Matra Naari",
        "html": html_body,
        "text": text_body,
        "payment_info": pay_info,
    }


def has_explicit_whatsapp_consent(order_dict: dict) -> bool:
    """
    Returns True ONLY when the order record contains explicit opt-in consent (1 / True).
    Existing or new orders without explicit consent (None, 0, False, '', etc.) are
    NEVER treated as opted in.
    """
    if not isinstance(order_dict, dict):
        return False
    raw = order_dict.get("whatsapp_opt_in")
    if raw is True or raw == 1:
        return True
    if isinstance(raw, str) and raw.strip().lower() in ("1", "true", "yes", "on"):
        return True
    return False


def build_owner_new_order_email(order_dict: dict) -> dict:
    """
    Builds the new-order alert email sent to the business owner (matranaari@gmail.com).
    """
    oid = str(order_dict.get("id") or order_dict.get("order_id") or "").strip()
    cust_name = str(order_dict.get("customer_name") or "").strip()
    cust_phone = str(order_dict.get("customer_phone") or "").strip()
    cust_email = str(order_dict.get("customer_email") or "").strip()
    ist_time = format_ist_timestamp(order_dict.get("created_at") or "")
    items = _parse_order_items(order_dict)
    total_amount = int(float(order_dict.get("total_amount") or 0))
    subtotal = int(float(order_dict.get("subtotal") or 0))
    discount = int(float(order_dict.get("discount_amount") or 0))
    shipping = int(float(order_dict.get("shipping") or 0))
    full_addr = _format_full_delivery_address(order_dict)
    pay_info = classify_verified_order_payment(order_dict)
    wa_opt_in = has_explicit_whatsapp_consent(order_dict)

    items_html = []
    items_text = []
    for it in items:
        pname = html.escape(str(it.get("name") or "Kurti").strip())
        sz = html.escape(str(it.get("size") or "M").strip())
        col = html.escape(str(it.get("color") or "Standard").strip())
        qty = int(it.get("qty") or it.get("quantity") or 1)
        price = int(float(it.get("price") or 0))
        items_html.append(
            f"<li><strong>{pname}</strong> — Size: {sz}, Color: {col} &times; <strong>{qty}</strong> (&#8377;{price:,} each)</li>"
        )
        items_text.append(f"- {it.get('name', 'Kurti')} | Size: {sz} | Color: {col} | Qty: {qty} | ₹{price:,}")

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"/><title>New Order Alert — {html.escape(oid)}</title></head>
<body style="margin:0;padding:20px;background-color:#FAF6F0;font-family:'Manrope',Arial,sans-serif;color:#231917;">
  <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#FFFDF9;border:1px solid #E6DEC8;padding:24px;">
    <tr>
      <td>
        <div style="background:#6B2D31;color:#FAF6F0;padding:16px 20px;font-family:'Cormorant Garamond',Georgia,serif;font-size:22px;font-weight:600;">
          Matra Naari — New Order Alert ({html.escape(oid)})
        </div>
        <div style="padding:20px 4px;font-size:14px;line-height:1.6;">
          <p><strong>Order ID:</strong> {html.escape(oid)}<br/>
          <strong>Order Date &amp; Time (IST):</strong> {html.escape(ist_time)}<br/>
          <strong>Total Order Amount:</strong> &#8377;{total_amount:,} (Subtotal: &#8377;{subtotal:,}, Discount: &#8377;{discount:,}, Shipping: &#8377;{shipping:,})<br/>
          <strong>Payment Method:</strong> {html.escape(pay_info['method_label'])}<br/>
          <strong>Verified Payment Status:</strong> <strong>{html.escape(pay_info['status_badge'])}</strong></p>

          <hr style="border:none;border-top:1px solid #E6DEC8;margin:16px 0;"/>
          <p><strong>Customer Details:</strong><br/>
          Name: {html.escape(cust_name)}<br/>
          Phone: <a href="tel:+91{html.escape(cust_phone)}">+91 {html.escape(cust_phone)}</a> (<a href="https://wa.me/91{html.escape(cust_phone)}">Chat on WhatsApp</a>)<br/>
          Email: <a href="mailto:{html.escape(cust_email)}">{html.escape(cust_email)}</a><br/>
          WhatsApp Opt-In Consent: {'Yes (Opted In)' if wa_opt_in else 'No (Opted Out)'}</p>

          <p><strong>Delivery Address:</strong><br/>
          {html.escape(full_addr)}</p>

          <p><strong>Products Ordered:</strong></p>
          <ul>{''.join(items_html)}</ul>
        </div>
      </td>
    </tr>
  </table>
</body>
</html>"""

    text_body = (
        f"[MATRA NAARI NEW ORDER ALERT]\n"
        f"Order ID: {oid}\n"
        f"Order Date & Time (IST): {ist_time}\n"
        f"Total Amount: ₹{total_amount:,}\n"
        f"Payment Method: {pay_info['method_label']}\n"
        f"Verified Payment Status: {pay_info['status_badge']}\n\n"
        f"Customer: {cust_name}\n"
        f"Phone: +91 {cust_phone}\n"
        f"Email: {cust_email}\n"
        f"WhatsApp Opt-In: {'Yes' if wa_opt_in else 'No'}\n\n"
        f"Delivery Address:\n{full_addr}\n\n"
        f"Items:\n" + "\n".join(items_text) + "\n"
    )

    return {
        "subject": f"[New Order] {oid} — ₹{total_amount:,} ({pay_info['method_label']})",
        "html": html_body,
        "text": text_body,
    }


def build_whatsapp_order_template_payload(order_dict: dict, cfg: dict = None) -> dict:
    """
    Constructs the official Meta WhatsApp Business Cloud API Utility Template payload.
    Template parameters:
      {{1}} Customer Name
      {{2}} Order ID
      {{3}} Final Order Amount (INR)
      {{4}} Payment Method & Verified Status
      {{5}} Order Confirmation Status
      {{6}} Official Customer Support Contact
    """
    if cfg is None:
        cfg = get_notification_config()
    oid = str(order_dict.get("id") or order_dict.get("order_id") or "").strip()
    cust_name = str(order_dict.get("customer_name") or "Valued Customer").strip()
    total_amount = int(float(order_dict.get("total_amount") or 0))
    wa_to = normalize_indian_whatsapp_recipient(order_dict.get("customer_phone") or "")
    pay_info = classify_verified_order_payment(order_dict)

    return {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": wa_to,
        "type": "template",
        "template": {
            "name": cfg["whatsapp_template_name"],
            "language": {"code": cfg["whatsapp_template_lang"]},
            "components": [
                {
                    "type": "body",
                    "parameters": [
                        {"type": "text", "text": cust_name},
                        {"type": "text", "text": oid},
                        {"type": "text", "text": f"₹{total_amount:,}"},
                        {"type": "text", "text": pay_info["wa_payment_label"]},
                        {"type": "text", "text": "Confirmed"},
                        {"type": "text", "text": f"{OFFICIAL_WHATSAPP_DISPLAY} / {OFFICIAL_BUSINESS_EMAIL}"},
                    ],
                }
            ],
        },
    }


def _is_recipient_allowed(recipient: str, cfg: dict) -> bool:
    allowed = cfg.get("allowed_recipients") or set()
    if not allowed:
        return True
    clean = str(recipient or "").strip().lower()
    digits = re.sub(r"\D", "", clean)
    if clean in allowed:
        return True
    if digits and (digits in allowed or digits[-10:] in allowed or f"+{digits}" in allowed):
        return True
    return False


def _normalize_transport_result(res) -> tuple:
    if isinstance(res, dict):
        ok = bool(res.get("ok"))
        msg_id = str(res.get("message_id") or res.get("id") or "")
        err = str(res.get("error") or "")
        return ok, msg_id, err
    if isinstance(res, (tuple, list)):
        if len(res) >= 3:
            return bool(res[0]), str(res[1] or ""), str(res[2] or "")
        if len(res) == 2:
            return bool(res[0]), str(res[1] or ""), ""
    return bool(res), "", ""


def _send_email_once(to_email: str, subject: str, html_body: str, text_body: str, cfg: dict) -> tuple:
    """
    Dispatches a single transactional email via the configured provider (or test transport).
    Returns (ok: bool, provider_message_id: str, error_summary: str).
    """
    if not _is_recipient_allowed(to_email, cfg):
        return False, "", "Recipient not in NOTIFICATION_ALLOWED_RECIPIENTS test allowlist"

    if _TEST_EMAIL_TRANSPORT is not None:
        try:
            res = _TEST_EMAIL_TRANSPORT(
                to_email=to_email,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
                from_address=cfg["from_address"],
                reply_to=cfg["reply_to"],
            )
        except TypeError:
            res = _TEST_EMAIL_TRANSPORT(to_email, subject, html_body, text_body, cfg)
        return _normalize_transport_result(res)

    if not cfg["email_configured"]:
        return False, "", "Email provider credentials not configured"

    provider = cfg["email_provider"]
    try:
        if provider == "resend":
            resp = requests.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {cfg['resend_api_key']}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": cfg["from_address"],
                    "to": [to_email],
                    "reply_to": cfg["reply_to"],
                    "subject": subject,
                    "html": html_body,
                    "text": text_body,
                },
                timeout=10,
            )
            if resp.status_code in (200, 201, 202):
                data = resp.json() if resp.content else {}
                return True, str(data.get("id") or "resend-ok"), ""
            return False, "", f"Resend HTTP {resp.status_code}"

        if provider == "brevo":
            sender_name = "Matra Naari"
            sender_email = cfg["from_address"]
            if "<" in sender_email and ">" in sender_email:
                sender_name = sender_email.split("<", 1)[0].strip() or "Matra Naari"
                sender_email = sender_email.split("<", 1)[1].split(">", 1)[0].strip()
            resp = requests.post(
                "https://api.brevo.com/v3/smtp/email",
                headers={
                    "api-key": cfg["brevo_api_key"],
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={
                    "sender": {"name": sender_name, "email": sender_email},
                    "to": [{"email": to_email}],
                    "replyTo": {"email": cfg["reply_to"]},
                    "subject": subject,
                    "htmlContent": html_body,
                    "textContent": text_body,
                },
                timeout=10,
            )
            if resp.status_code in (200, 201, 202):
                data = resp.json() if resp.content else {}
                return True, str(data.get("messageId") or "brevo-ok"), ""
            return False, "", f"Brevo HTTP {resp.status_code}"

        return False, "", f"Unsupported email provider: {provider}"
    except Exception as exc:
        return False, "", f"Email transport error: {type(exc).__name__}"


def _send_whatsapp_once(order_dict: dict, cfg: dict) -> tuple:
    """
    Dispatches a single WhatsApp utility template message via Meta WhatsApp Cloud API (or test transport).
    Returns (ok: bool, provider_message_id: str, error_summary: str).
    """
    wa_to = normalize_indian_whatsapp_recipient(order_dict.get("customer_phone") or "")
    if not wa_to:
        return False, "", "Invalid Indian mobile number for WhatsApp"

    if not _is_recipient_allowed(wa_to, cfg):
        return False, "", "Recipient not in NOTIFICATION_ALLOWED_RECIPIENTS test allowlist"

    payload = build_whatsapp_order_template_payload(order_dict, cfg=cfg)

    if _TEST_WHATSAPP_TRANSPORT is not None:
        try:
            res = _TEST_WHATSAPP_TRANSPORT(
                to_wa_id=wa_to,
                payload=payload,
                sender_number=cfg["whatsapp_sender_number"],
            )
        except TypeError:
            res = _TEST_WHATSAPP_TRANSPORT(f"+{wa_to}", payload, cfg)
        return _normalize_transport_result(res)

    if not cfg["whatsapp_configured"]:
        return False, "", "WhatsApp Cloud API credentials not configured"

    try:
        url = f"https://graph.facebook.com/v21.0/{cfg['whatsapp_phone_number_id']}/messages"
        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {cfg['whatsapp_access_token']}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=10,
        )
        if resp.status_code in (200, 201):
            data = resp.json() if resp.content else {}
            msgs = data.get("messages") or []
            msg_id = str(msgs[0].get("id")) if (isinstance(msgs, list) and msgs) else "wamid-ok"
            return True, msg_id, ""
        return False, "", f"WhatsApp Cloud API HTTP {resp.status_code}"
    except Exception as exc:
        return False, "", f"WhatsApp transport error: {type(exc).__name__}"


def _dispatch_channel_with_idempotency(
    get_db_fn,
    order_id: str,
    channel: str,
    event_type: str,
    recipient_masked: str,
    provider_name: str,
    is_configured: bool,
    send_callable,
    max_attempts: int = MAX_NOTIFICATION_ATTEMPTS,
    skip_reason: str = "",
) -> dict:
    """
    Idempotently records and executes a single notification channel (`customer_email`,
    `owner_email`, or `customer_whatsapp`) with bounded retries (`max_attempts`).
    Never re-sends an already-sent notification and never raises exceptions to the caller.
    """
    now_iso = datetime.datetime.now().isoformat()
    conn = get_db_fn()
    c = conn.cursor()
    try:
        c.execute(
            """
            SELECT id, status, attempts, max_attempts, provider_message_id, error_summary
            FROM order_notifications
            WHERE order_id = ? AND channel = ? AND event_type = ?
            """,
            (order_id, channel, event_type),
        )
        existing = c.fetchone()
        if existing:
            ex = dict(existing)
            if ex["status"] == "sent":
                conn.close()
                att = int(ex.get("attempts") or 1)
                return {
                    "channel": channel,
                    "status": "already_sent",
                    "attempts": att,
                    "attempt_count": att,
                    "provider_message_id": ex.get("provider_message_id") or "",
                }
            if skip_reason and ex["status"] == skip_reason:
                conn.close()
                att = int(ex.get("attempts") or 0)
                return {
                    "channel": channel,
                    "status": skip_reason,
                    "attempts": att,
                    "attempt_count": att,
                    "provider_message_id": "",
                }
            if int(ex.get("attempts") or 0) >= int(ex.get("max_attempts") or max_attempts):
                conn.close()
                att = int(ex.get("attempts") or max_attempts)
                return {
                    "channel": channel,
                    "status": "max_attempts_exceeded",
                    "attempts": att,
                    "attempt_count": att,
                    "error": ex.get("error_summary") or "Max attempts reached",
                }
            notif_id = ex["id"]
            current_attempts = int(ex.get("attempts") or 0)
        else:
            notif_id = f"ntf_{secrets.token_hex(6)}"
            current_attempts = 0
            initial_status = skip_reason if skip_reason else ("pending" if is_configured else "skipped_unconfigured")
            c.execute(
                """
                INSERT INTO order_notifications (
                    id, order_id, channel, event_type, recipient_masked,
                    provider, status, attempts, max_attempts,
                    provider_message_id, error_summary, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    notif_id,
                    order_id,
                    channel,
                    event_type,
                    recipient_masked,
                    provider_name,
                    initial_status,
                    0,
                    max_attempts,
                    "",
                    "",
                    now_iso,
                    now_iso,
                ),
            )
            conn.commit()
            if skip_reason or not is_configured:
                conn.close()
                return {
                    "channel": channel,
                    "status": initial_status,
                    "attempts": 0,
                    "attempt_count": 0,
                    "provider_message_id": "",
                }
    except Exception as db_exc:
        try:
            conn.close()
        except Exception:
            pass
        return {
            "channel": channel,
            "status": "failed",
            "attempts": 0,
            "attempt_count": 0,
            "error": f"DB tracking error: {type(db_exc).__name__}",
        }
    conn.close()

    # If skipped or unconfigured on a pre-existing row
    if skip_reason:
        conn2 = get_db_fn()
        c2 = conn2.cursor()
        c2.execute(
            "UPDATE order_notifications SET status = ?, updated_at = ? WHERE id = ?",
            (skip_reason, datetime.datetime.now().isoformat(), notif_id),
        )
        conn2.commit()
        conn2.close()
        return {"channel": channel, "status": skip_reason, "attempts": current_attempts, "attempt_count": current_attempts}

    if not is_configured:
        conn2 = get_db_fn()
        c2 = conn2.cursor()
        c2.execute(
            "UPDATE order_notifications SET status = 'skipped_unconfigured', updated_at = ? WHERE id = ?",
            (datetime.datetime.now().isoformat(), notif_id),
        )
        conn2.commit()
        conn2.close()
        return {"channel": channel, "status": "skipped_unconfigured", "attempts": current_attempts, "attempt_count": current_attempts}

    # Execute 1 bounded attempt per invocation so checkout never blocks on repeated timeouts
    current_attempts += 1
    try:
        ok, msg_id, err_str = send_callable()
    except Exception as call_exc:
        ok, msg_id, err_str = False, "", f"Exception: {type(call_exc).__name__}"

    succeeded = bool(ok)
    last_err = "" if succeeded else str(err_str or "Provider send failed")[:240]

    final_status = "sent" if succeeded else "failed"
    try:
        conn3 = get_db_fn()
        c3 = conn3.cursor()
        c3.execute(
            """
            UPDATE order_notifications
            SET status = ?,
                attempts = ?,
                provider = ?,
                provider_message_id = ?,
                error_summary = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                final_status,
                current_attempts,
                provider_name,
                msg_id if succeeded else "",
                last_err,
                datetime.datetime.now().isoformat(),
                notif_id,
            ),
        )
        conn3.commit()
        conn3.close()
    except Exception:
        pass

    if not succeeded:
        print(
            f"[Notification Warning] order_id={order_id} channel={channel} status=failed "
            f"attempts={current_attempts}/{max_attempts} recipient={recipient_masked} error={last_err}",
            flush=True,
        )

    return {
        "channel": channel,
        "status": final_status,
        "attempts": current_attempts,
        "attempt_count": current_attempts,
        "provider_message_id": msg_id if succeeded else "",
        "error": last_err,
    }


MAX_ORDER_NOTIFICATION_AGE_HOURS = 24


def _is_historical_order(order_dict: dict, max_age_hours: int = MAX_ORDER_NOTIFICATION_AGE_HOURS) -> bool:
    """
    Safety guard: returns True if the order's `created_at` timestamp is older than
    `max_age_hours` (default 24h), ensuring historical orders can never accidentally
    receive confirmation emails or WhatsApp messages.
    """
    raw_created = str(order_dict.get("created_at") or "").strip()
    if not raw_created:
        return False
    try:
        s = raw_created[:-1] + "+00:00" if raw_created.endswith("Z") else raw_created
        dt = datetime.datetime.fromisoformat(s)
        now = datetime.datetime.now(dt.tzinfo) if dt.tzinfo else datetime.datetime.now()
        age_seconds = (now - dt).total_seconds()
        return age_seconds > (max_age_hours * 3600)
    except Exception:
        return False


def enqueue_order_confirmation_notifications(
    order_dict: dict,
    cursor=None,
    get_db_fn=None,
    max_attempts: int = MAX_NOTIFICATION_ATTEMPTS,
) -> bool:
    """
    Durably registers `order_notifications` rows (`customer_email`, `owner_email`,
    `customer_whatsapp`) with `status='pending'` (or `skipped_*`) inside the caller's
    database transaction (`cursor`) or via `get_db_fn`.
    Because this runs inside the same atomic transaction (`COMMIT`) that confirms the
    order in `POST /api/create-cod-order` and `POST /api/verify-payment`, notification
    jobs cannot be lost even if Render restarts immediately after `COMMIT`.
    Historical orders (`created_at` > 24h old) or ineligible orders are never enqueued.
    """
    if not isinstance(order_dict, dict):
        return False
    order_id = str(order_dict.get("id") or order_dict.get("order_id") or "").strip()
    if not order_id:
        return False
    if _is_historical_order(order_dict):
        return False
    pay_info = classify_verified_order_payment(order_dict)
    if not pay_info["eligible_for_confirmation"]:
        return False

    cfg = get_notification_config()
    cust_email = str(order_dict.get("customer_email") or "").strip()
    cust_phone = str(order_dict.get("customer_phone") or "").strip()
    owner_email = cfg["owner_email"]
    wa_opt_in = has_explicit_whatsapp_consent(order_dict)
    wa_norm = normalize_indian_whatsapp_recipient(cust_phone)

    if not _is_recipient_allowed(cust_email, cfg):
        cust_email_status = "blocked_not_in_allowlist"
    elif not cfg["email_configured"]:
        cust_email_status = "skipped_unconfigured"
    else:
        cust_email_status = "pending"

    if not _is_recipient_allowed(owner_email, cfg):
        owner_email_status = "blocked_not_in_allowlist"
    elif not cfg["email_configured"]:
        owner_email_status = "skipped_unconfigured"
    else:
        owner_email_status = "pending"

    if not cfg["whatsapp_enabled"]:
        wa_status = "skipped_whatsapp_disabled"
    elif not wa_opt_in:
        wa_status = "skipped_no_consent"
    elif not _is_recipient_allowed(wa_norm, cfg):
        wa_status = "blocked_not_in_allowlist"
    elif not cfg["whatsapp_configured"]:
        wa_status = "skipped_unconfigured"
    else:
        wa_status = "pending"

    now_iso = datetime.datetime.now().isoformat()
    rows_to_enqueue = [
        ("customer_email", mask_email(cust_email), cfg["email_provider"], cust_email_status),
        ("owner_email", mask_email(owner_email), cfg["email_provider"], owner_email_status),
        ("customer_whatsapp", mask_phone(cust_phone), cfg["whatsapp_provider"], wa_status),
    ]

    owns_conn = cursor is None
    conn = None
    try:
        if owns_conn:
            if get_db_fn is None:
                return False
            conn = get_db_fn()
            c = conn.cursor()
        else:
            c = cursor

        for channel, recipient_masked, provider_name, initial_status in rows_to_enqueue:
            notif_id = f"ntf_{secrets.token_hex(6)}"
            c.execute(
                """
                INSERT INTO order_notifications (
                    id, order_id, channel, event_type, recipient_masked,
                    provider, status, attempts, max_attempts,
                    provider_message_id, error_summary, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (order_id, channel, event_type) DO NOTHING
                """,
                (
                    notif_id,
                    order_id,
                    channel,
                    "order_confirmed",
                    recipient_masked,
                    provider_name,
                    initial_status,
                    0,
                    max_attempts,
                    "",
                    "",
                    now_iso,
                    now_iso,
                ),
            )
        if owns_conn and conn is not None:
            conn.commit()
            conn.close()
        return True
    except Exception:
        if owns_conn and conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        return False


def trigger_order_confirmation_notifications(get_db_fn, order_id: str) -> dict:
    """
    Main entry point called ONLY after an order is committed in the database:
    - Fetches the persisted order record from `orders`.
    - Rejects historical orders (`created_at` > 24h old) so past orders can never be messaged.
    - Verifies that the order is eligible for confirmation (e.g. rejects `pending_payment`,
      `cancelled`, `failed`, or unverified Razorpay orders).
    - Independently dispatches and tracks:
        1. `customer_email`
        2. `owner_email` (to `matranaari@gmail.com`)
        3. `customer_whatsapp` (disabled until `WHATSAPP_ENABLED=true` and Meta setup is complete)
    - Never raises exceptions so checkout cannot fail due to notification errors.
    """
    try:
        conn = get_db_fn()
        c = conn.cursor()
        c.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
        row = c.fetchone()
        conn.close()
        if not row:
            return {"ok": False, "order_id": order_id, "reason": "order_not_found"}

        order_dict = dict(row)
        if _is_historical_order(order_dict):
            return {
                "ok": False,
                "order_id": order_id,
                "reason": "historical_order_skipped",
                "created_at": order_dict.get("created_at"),
            }

        pay_info = classify_verified_order_payment(order_dict)
        if not pay_info["eligible_for_confirmation"]:
            return {
                "ok": False,
                "order_id": order_id,
                "reason": "order_not_eligible_or_payment_unverified",
                "payment_status": order_dict.get("payment_status"),
                "order_status": order_dict.get("order_status"),
            }

        cfg = get_notification_config()
        cust_email = str(order_dict.get("customer_email") or "").strip()
        cust_phone = str(order_dict.get("customer_phone") or "").strip()
        owner_email = cfg["owner_email"]
        wa_opt_in = has_explicit_whatsapp_consent(order_dict)

        cust_email_pkg = build_customer_confirmation_email(order_dict)
        owner_email_pkg = build_owner_new_order_email(order_dict)

        # 1. Customer Confirmation Email
        cust_email_skip = "" if _is_recipient_allowed(cust_email, cfg) else "blocked_not_in_allowlist"
        res_cust_email = _dispatch_channel_with_idempotency(
            get_db_fn=get_db_fn,
            order_id=order_id,
            channel="customer_email",
            event_type="order_confirmed",
            recipient_masked=mask_email(cust_email),
            provider_name=cfg["email_provider"],
            is_configured=cfg["email_configured"],
            send_callable=lambda: _send_email_once(
                to_email=cust_email,
                subject=cust_email_pkg["subject"],
                html_body=cust_email_pkg["html"],
                text_body=cust_email_pkg["text"],
                cfg=cfg,
            ),
            skip_reason=cust_email_skip,
        )

        # 2. Business Owner New-Order Alert Email (matranaari@gmail.com)
        owner_email_skip = "" if _is_recipient_allowed(owner_email, cfg) else "blocked_not_in_allowlist"
        res_owner_email = _dispatch_channel_with_idempotency(
            get_db_fn=get_db_fn,
            order_id=order_id,
            channel="owner_email",
            event_type="order_confirmed",
            recipient_masked=mask_email(owner_email),
            provider_name=cfg["email_provider"],
            is_configured=cfg["email_configured"],
            send_callable=lambda: _send_email_once(
                to_email=owner_email,
                subject=owner_email_pkg["subject"],
                html_body=owner_email_pkg["html"],
                text_body=owner_email_pkg["text"],
                cfg=cfg,
            ),
            skip_reason=owner_email_skip,
        )

        # 3. Customer WhatsApp Confirmation (disabled until WHATSAPP_ENABLED=true and Meta setup is complete)
        wa_norm = normalize_indian_whatsapp_recipient(cust_phone)
        if not cfg["whatsapp_enabled"]:
            wa_skip = "skipped_whatsapp_disabled"
        elif not wa_opt_in:
            wa_skip = "skipped_no_consent"
        elif not _is_recipient_allowed(wa_norm, cfg):
            wa_skip = "blocked_not_in_allowlist"
        else:
            wa_skip = ""
        res_cust_wa = _dispatch_channel_with_idempotency(
            get_db_fn=get_db_fn,
            order_id=order_id,
            channel="customer_whatsapp",
            event_type="order_confirmed",
            recipient_masked=mask_phone(cust_phone),
            provider_name=cfg["whatsapp_provider"],
            is_configured=cfg["whatsapp_configured"],
            send_callable=lambda: _send_whatsapp_once(order_dict, cfg=cfg),
            skip_reason=wa_skip,
        )

        return {
            "ok": True,
            "order_id": order_id,
            "customer_email": res_cust_email,
            "owner_email": res_owner_email,
            "customer_whatsapp": res_cust_wa,
            "channels": {
                "customer_email": res_cust_email,
                "owner_email": res_owner_email,
                "customer_whatsapp": res_cust_wa,
            },
        }
    except Exception as exc:
        print(f"[Notification Error] Safe catch for order_id={order_id}: {type(exc).__name__}", flush=True)
        return {"ok": False, "order_id": order_id, "reason": type(exc).__name__}


def recover_pending_and_failed_notifications(
    get_db_fn,
    max_age_hours: int = MAX_ORDER_NOTIFICATION_AGE_HOURS,
    batch_limit: int = 25,
) -> dict:
    """
    Safe recovery & retry worker for Render restarts and transient provider errors:
    - Inspects ONLY `order_notifications` rows with `status IN ('pending', 'failed')`
      and `attempts < max_attempts` (historical orders placed prior to this feature
      have no rows in `order_notifications` and are never scanned).
    - Enforces `_is_historical_order(..., max_age_hours=24)`: if any order with a
      pending/failed row is older than 24 hours, marks the row `skipped_historical`
      and never sends a notification.
    - Retries only the pending/failed channel(s) while skipping any channel already
      marked `status = 'sent'` (`already_sent`), preventing duplicate messages.
    """
    recovered_orders = []
    skipped_historical_orders = []
    try:
        conn = get_db_fn()
        c = conn.cursor()
        c.execute(
            """
            SELECT DISTINCT order_id
            FROM order_notifications
            WHERE status IN ('pending', 'failed')
              AND attempts < max_attempts
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (int(batch_limit),),
        )
        rows = c.fetchall()
        candidate_order_ids = [str(r["order_id"] if isinstance(r, dict) or hasattr(r, "keys") else r[0]).strip() for r in rows]
        conn.close()
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "recovered_orders": [], "skipped_historical_orders": []}

    for oid in candidate_order_ids:
        if not oid:
            continue
        try:
            conn = get_db_fn()
            c = conn.cursor()
            c.execute("SELECT * FROM orders WHERE id = ?", (oid,))
            ord_row = c.fetchone()
            if not ord_row:
                c.execute(
                    "UPDATE order_notifications SET status = 'skipped_order_missing', updated_at = ? WHERE order_id = ? AND status IN ('pending', 'failed')",
                    (datetime.datetime.now().isoformat(), oid),
                )
                conn.commit()
                conn.close()
                continue
            ord_dict = dict(ord_row)
            if _is_historical_order(ord_dict, max_age_hours=max_age_hours):
                c.execute(
                    "UPDATE order_notifications SET status = 'skipped_historical', updated_at = ? WHERE order_id = ? AND status IN ('pending', 'failed')",
                    (datetime.datetime.now().isoformat(), oid),
                )
                conn.commit()
                conn.close()
                skipped_historical_orders.append(oid)
                continue
            conn.close()

            res = trigger_order_confirmation_notifications(get_db_fn, oid)
            recovered_orders.append({"order_id": oid, "result": res})
        except Exception:
            pass

    return {
        "ok": True,
        "recovered_count": len(recovered_orders),
        "recovered_orders": recovered_orders,
        "skipped_historical_orders": skipped_historical_orders,
    }


# ======================================================================
# PASSWORDLESS OTP EMAIL & INDIA DLT SMS DELIVERY
# ======================================================================

_TEST_SMS_TRANSPORT = None


def set_test_sms_transport(sms_fn=None):
    global _TEST_SMS_TRANSPORT
    _TEST_SMS_TRANSPORT = sms_fn


def get_sms_otp_config() -> dict:
    """
    Loads India-compatible SMS OTP configuration from environment variables.
    Supports:
      - MSG91 V5 OTP API (`SMS_PROVIDER=msg91`, requires `SMS_API_KEY` + `SMS_DLT_TEMPLATE_ID`)
      - Fast2SMS BulkV2 (`SMS_PROVIDER=fast2sms`, supports `SMS_ROUTE=dlt` with `SMS_DLT_TEMPLATE_ID` or `SMS_ROUTE=otp`)
      - 2Factor.in Transactional OTP (`SMS_PROVIDER=twofactor`, requires `SMS_API_KEY` + optional `SMS_DLT_TEMPLATE_ID` template name)
    IMPORTANT: Remains disabled by default until `SMS_OTP_ENABLED=true` and valid provider
    credentials are explicitly configured. Never simulates OTP verification in production.
    """
    sms_enabled_raw = (os.environ.get("SMS_OTP_ENABLED") or "false").strip().lower()
    sms_flag_enabled = sms_enabled_raw in ("1", "true", "yes", "on")
    sms_provider = (os.environ.get("SMS_PROVIDER") or "msg91").strip().lower()
    sms_route = (os.environ.get("SMS_ROUTE") or "dlt").strip().lower()
    sms_api_key = (os.environ.get("SMS_API_KEY") or "").strip()
    sms_sender_id = (os.environ.get("SMS_SENDER_ID") or "MTRNRI").strip()
    sms_dlt_template_id = (os.environ.get("SMS_DLT_TEMPLATE_ID") or "").strip()
    sms_dlt_entity_id = (os.environ.get("SMS_DLT_ENTITY_ID") or "").strip()

    requires_dlt_template = not (
        (sms_provider == "fast2sms" and sms_route == "otp")
        or sms_provider == "twofactor"
    )
    has_template_Requirement = bool(sms_dlt_template_id) or not requires_dlt_template

    missing_requirements = []
    if not sms_flag_enabled:
        missing_requirements.append("SMS_OTP_ENABLED=true")
    if not sms_api_key:
        missing_requirements.append("SMS_API_KEY")
    if requires_dlt_template and not sms_dlt_template_id:
        missing_requirements.append("SMS_DLT_TEMPLATE_ID")

    is_configured = bool(
        _TEST_SMS_TRANSPORT is not None
        or (
            sms_flag_enabled
            and bool(sms_api_key)
            and has_template_Requirement
            and sms_provider in ("msg91", "fast2sms", "twofactor")
        )
    )
    return {
        "sms_otp_enabled": is_configured,
        "sms_flag_enabled": sms_flag_enabled,
        "sms_provider": sms_provider,
        "sms_route": sms_route,
        "sms_sender_id": sms_sender_id,
        "sms_api_key_configured": bool(sms_api_key or _TEST_SMS_TRANSPORT is not None),
        "sms_dlt_template_configured": bool(sms_dlt_template_id or _TEST_SMS_TRANSPORT is not None),
        "sms_dlt_entity_configured": bool(sms_dlt_entity_id),
        "missing_requirements": [] if _TEST_SMS_TRANSPORT is not None else missing_requirements,
        "sms_api_key": sms_api_key,
        "sms_dlt_template_id": sms_dlt_template_id,
        "sms_dlt_entity_id": sms_dlt_entity_id,
    }


def send_otp_email(
    to_email: str,
    otp_code: str,
    purpose: str = "customer_login",
    expires_minutes: int = 5,
) -> dict:
    """
    Sends a branded Quiet Luxury Matra Naari customer verification code email via Resend.
    Never logs or returns the OTP value. Never used for Admin login (Admin is password-only).
    """
    cfg = get_notification_config()
    clean_email = str(to_email or "").strip().lower()
    if "@" not in clean_email or "." not in clean_email:
        return {"ok": False, "error": "Invalid recipient email address"}

    if purpose == "link_contact":
        subject = "Matra Naari — Verify Your Contact Details"
        heading = "Verify Contact Update"
        intro = "Enter the 6-digit verification code below to confirm and link this email address to your Matra Naari account."
    else:
        subject = "Your Matra Naari Sign-In Verification Code"
        heading = "Sign In to Matra Naari"
        intro = "Enter the 6-digit verification code below to securely access your Matra Naari account. No password is required."

    safe_code = html.escape(str(otp_code or "").strip())
    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{html.escape(subject)}</title>
</head>
<body style="margin:0;padding:0;background-color:#F7F4EE;font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#292725;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#F7F4EE;padding:32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:520px;background-color:#FFFFFF;border:1px solid #E6DED5;border-radius:12px;overflow:hidden;">
          <tr>
            <td style="background-color:#542C34;padding:24px 32px;text-align:center;">
              <div style="font-size:11px;letter-spacing:0.22em;text-transform:uppercase;color:#F7F4EE;opacity:0.85;margin-bottom:4px;">MATRA NAARI</div>
              <div style="font-size:20px;font-weight:700;color:#FFFFFF;letter-spacing:0.02em;">{html.escape(heading)}</div>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#292725;">
                {html.escape(intro)}
              </p>
              <div style="background-color:#F7F4EE;border:1px solid #E6DED5;border-radius:10px;padding:22px 16px;text-align:center;margin:24px 0;">
                <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.16em;color:#706963;margin-bottom:8px;">One-Time Verification Code</div>
                <div style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:32px;font-weight:700;letter-spacing:0.28em;color:#542C34;padding-left:0.28em;">
                  {safe_code}
                </div>
                <div style="font-size:12px;color:#706963;margin-top:10px;">
                  Valid for <strong>{int(expires_minutes)} minutes</strong> &middot; Single-use only
                </div>
              </div>
              <p style="margin:0;font-size:12px;line-height:1.5;color:#706963;">
                For your security, never share this code with anyone. Matra Naari staff will never ask for your verification code over phone, SMS, or WhatsApp. If you did not request this code, you can safely ignore this email.
              </p>
            </td>
          </tr>
          <tr>
            <td style="background-color:#FAF8F4;border-top:1px solid #E6DED5;padding:16px 32px;text-align:center;font-size:11px;color:#706963;">
              &copy; 2026 Matra Naari &middot; <a href="https://matranaari.com" style="color:#542C34;text-decoration:none;">matranaari.com</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    text_body = (
        f"MATRA NAARI — {heading}\n\n"
        f"{intro}\n\n"
        f"Your 6-digit verification code is: {otp_code}\n\n"
        f"Valid for {int(expires_minutes)} minutes (single-use only).\n"
        f"Never share this code with anyone. If you did not request this code, please ignore this email.\n"
    )

    ok, msg_id, err = _send_email_once(clean_email, subject, html_body, text_body, cfg)
    return {
        "ok": bool(ok),
        "provider_message_id": msg_id,
        "error": err,
        "recipient_masked": mask_email(clean_email),
    }


def send_otp_sms(
    phone_str: str,
    otp_code: str,
    purpose: str = "customer_login",
    expires_minutes: int = 5,
) -> dict:
    """
    Dispatches a 6-digit SMS OTP to a 10-digit Indian mobile number (+91) via an
    India-compatible SMS gateway (MSG91 / Fast2SMS / 2Factor.in) or isolated test transport.
    Never sends or simulates SMS when SMS_OTP_ENABLED is false.
    """
    wa_id = normalize_indian_whatsapp_recipient(phone_str)
    if not wa_id:
        return {"ok": False, "error": "Please enter a valid 10-digit Indian mobile number."}
    phone_10 = wa_id[2:]
    sms_cfg = get_sms_otp_config()

    if _TEST_SMS_TRANSPORT is not None:
        try:
            res = _TEST_SMS_TRANSPORT(
                phone=phone_10,
                e164=f"+91{phone_10}",
                otp_code=otp_code,
                purpose=purpose,
                sender_id=sms_cfg["sms_sender_id"],
                dlt_template_id=sms_cfg["sms_dlt_template_id"],
            )
            ok, msg_id, err = _normalize_transport_result(res)
            return {
                "ok": bool(ok),
                "provider_message_id": msg_id,
                "error": err,
                "recipient_masked": mask_phone(phone_10),
            }
        except Exception as exc:
            return {"ok": False, "error": f"SMS test transport error: {type(exc).__name__}"}

    if not sms_cfg["sms_otp_enabled"]:
        return {
            "ok": False,
            "phone_otp_unavailable": True,
            "error": "Mobile SMS OTP is not enabled yet. Please sign in using Email OTP.",
        }

    provider = sms_cfg["sms_provider"]
    try:
        if provider == "msg91":
            resp = requests.post(
                "https://control.msg91.com/api/v5/otp",
                headers={
                    "authkey": sms_cfg["sms_api_key"],
                    "Content-Type": "application/json",
                },
                json={
                    "template_id": sms_cfg["sms_dlt_template_id"],
                    "mobile": f"91{phone_10}",
                    "otp": str(otp_code),
                    "otp_expiry": int(expires_minutes),
                },
                timeout=10,
            )
            if resp.status_code in (200, 201, 202):
                data = resp.json() if resp.content else {}
                if str(data.get("type", "")).lower() == "success" or resp.status_code == 200:
                    return {
                        "ok": True,
                        "provider_message_id": str(data.get("request_id") or "msg91-ok"),
                        "error": "",
                        "recipient_masked": mask_phone(phone_10),
                    }
            return {"ok": False, "error": f"SMS gateway returned HTTP {resp.status_code}"}

        if provider == "fast2sms":
            route_mode = sms_cfg.get("sms_route") or ("dlt" if sms_cfg.get("sms_dlt_template_id") else "otp")
            if route_mode == "otp" and not sms_cfg.get("sms_dlt_template_id"):
                payload = {
                    "route": "otp",
                    "variables_values": str(otp_code),
                    "flash": 0,
                    "numbers": phone_10,
                }
            else:
                payload = {
                    "route": "dlt",
                    "sender_id": sms_cfg["sms_sender_id"],
                    "message": sms_cfg["sms_dlt_template_id"],
                    "variables_values": f"{otp_code}|{expires_minutes} mins",
                    "flash": 0,
                    "numbers": phone_10,
                }
            resp = requests.post(
                "https://www.fast2sms.com/dev/bulkV2",
                headers={
                    "authorization": sms_cfg["sms_api_key"],
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=10,
            )
            if resp.status_code in (200, 201, 202):
                data = resp.json() if resp.content else {}
                if data.get("return") is True:
                    return {
                        "ok": True,
                        "provider_message_id": str(data.get("request_id") or "fast2sms-ok"),
                        "error": "",
                        "recipient_masked": mask_phone(phone_10),
                    }
            return {"ok": False, "error": f"SMS gateway returned HTTP {resp.status_code}"}

        if provider == "twofactor":
            tmpl_part = f"/{sms_cfg['sms_dlt_template_id']}" if sms_cfg.get("sms_dlt_template_id") else ""
            url = f"https://2factor.in/API/V1/{sms_cfg['sms_api_key']}/SMS/+91{phone_10}/{otp_code}{tmpl_part}"
            resp = requests.get(url, timeout=10)
            if resp.status_code in (200, 201):
                data = resp.json() if resp.content else {}
                if str(data.get("Status", "")).lower() == "success":
                    return {
                        "ok": True,
                        "provider_message_id": str(data.get("Details") or "2factor-ok"),
                        "error": "",
                        "recipient_masked": mask_phone(phone_10),
                    }
            return {"ok": False, "error": f"SMS gateway returned HTTP {resp.status_code}"}

        return {"ok": False, "error": f"Unsupported SMS provider: {provider}"}
    except Exception as exc:
        return {"ok": False, "error": f"SMS transport error: {type(exc).__name__}"}

