import hashlib
import hmac
import json
import os
import re
from flask import Flask, jsonify, request
import requests

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
TARGET_GROUPS_RAW = os.getenv("TARGET_GROUPS", "-1005842100073").strip()
IVAS_WEBHOOK_SECRET = os.getenv("IVAS_WEBHOOK_SECRET", "").strip()
PORT = int(os.getenv("PORT", "8080"))

# Opsional: isi link URL kalau mau tombol biru NUMBER & DISKUSI muncul
NUMBER_URL = os.getenv("NUMBER_URL", "").strip()
DISKUSI_URL = os.getenv("DISKUSI_URL", "").strip()

# Ubah ke True kalau sudah tahu format signature IVAS yang exact
VERIFY_SIGNATURE = False

COUNTRY_FLAGS = {
    "256": "🇺🇬",
    "223": "🇲🇱",
    "593": "🇪🇨",
    "62": "🇮🇩",
    "243": "🇨🇩",
}


def get_target_groups():
    return [g.strip() for g in TARGET_GROUPS_RAW.split(",") if g.strip()]


def verify_signature(raw_body: bytes, headers) -> bool:
    if not VERIFY_SIGNATURE or not IVAS_WEBHOOK_SECRET:
        return True

    sig = (
        headers.get("X-IVAS-Signature")
        or headers.get("X-Ivas-Signature")
        or headers.get("X-Signature-256")
        or headers.get("X-Signature")
        or ""
    ).strip()

    if not sig:
        return False

    if sig.startswith("sha256="):
        sig = sig.split("=", 1)[1].strip()

    expected_hex = hmac.new(
        IVAS_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected_hex.lower(), sig.lower())


def find_first_value(obj, keys):
    if isinstance(obj, dict):
        for k in keys:
            if k in obj and obj[k] not in (None, ""):
                return str(obj[k]).strip()
        for v in obj.values():
            found = find_first_value(v, keys)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_first_value(item, keys)
            if found:
                return found
    return None


def extract_otp(text: str) -> str:
    if not text:
        return "-"

    match_dash = re.search(r"\b(\d{3}-\d{3})\b", text)
    if match_dash:
        return match_dash.group(1)

    match_code_label = re.search(
        r"(?:code|otp|pin)[^\d]{0,15}(\d{3}[-\s]?\d{3}|\d{4,8})",
        text,
        re.IGNORECASE,
    )
    if match_code_label:
        return match_code_label.group(1)

    match_digits = re.search(r"\b(\d{4,8})\b", text)
    if match_digits:
        return match_digits.group(1)

    return "-"


def detect_app(text: str) -> str:
    low = (text or "").lower()
    if "whatsapp" in low:
        return "WA"
    if "instagram" in low or "ig" in low:
        return "IG"
    if "telegram" in low:
        return "TG"
    if "facebook" in low or "fb" in low:
        return "FB"
    if "tiktok" in low:
        return "TT"
    return "SMS"


def detect_flag_and_mask(number_str: str):
    digits = re.sub(r"\D", "", number_str or "")
    flag = "🌐"
    for code, fl in COUNTRY_FLAGS.items():
        if digits.startswith(code):
            flag = fl
            break

    if len(digits) >= 8:
        masked = f"{digits[:5]} 💀 {digits[-4:]}"
    elif digits:
        masked = digits
    else:
        masked = "-"
    return flag, masked


def build_card_payload(payload):
    if isinstance(payload, dict):
        sender = (
            find_first_value(payload, ["from", "sender", "cli", "originator", "source"])
            or "-"
        )
        recipient = (
            find_first_value(
                payload,
                ["to", "recipient", "did", "number", "phone", "msisdn", "destination"],
            )
            or sender
        )
        body = (
            find_first_value(
                payload,
                ["message", "text", "body", "sms", "content", "otp"],
            )
            or ""
        )
    else:
        recipient = "-"
        body = str(payload)

    otp_code = extract_otp(body)
    app_tag = detect_app(body)
    flag, masked_num = detect_flag_and_mask(recipient)

    summary_line = f"{flag}  {app_tag}  {masked_num}"

    row_bottom = []
    if NUMBER_URL:
        row_bottom.append({"text": "NUMBER ↗", "url": NUMBER_URL})
    if DISKUSI_URL:
        row_bottom.append({"text": "DISKUSI ↗", "url": DISKUSI_URL})

    inline_keyboard = []
    if otp_code != "-":
        inline_keyboard.append([
            {
                "text": f"📋 {otp_code}",
                "copy_text": {"text": otp_code},
            }
        ])
    if row_bottom:
        inline_keyboard.append(row_bottom)

    reply_markup = {"inline_keyboard": inline_keyboard} if inline_keyboard else None
    return summary_line, reply_markup


def send_telegram_message(chat_id: str, text: str, reply_markup=None):
    if not BOT_TOKEN:
        return False, "BOT_TOKEN is missing"

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    body = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }
    if reply_markup:
        body["reply_markup"] = reply_markup

    resp = requests.post(url, json=body, timeout=15)

    # Fallback kalau Telegram versi/klien menolak copy_text
    if resp.status_code != 200 and reply_markup:
        fallback_rows = []
        for row in reply_markup.get("inline_keyboard", []):
            new_row = []
            for btn in row:
                if "url" in btn:
                    new_row.append({"text": btn["text"], "url": btn["url"]})
                elif "copy_text" in btn:
                    new_row.append({
                        "text": btn["text"],
                        "callback_data": f"otp:{btn['copy_text']['text'][:32]}",
                    })
            if new_row:
                fallback_rows.append(new_row)
        body["reply_markup"] = {"inline_keyboard": fallback_rows}
        resp = requests.post(url, json=body, timeout=15)

    return resp.ok, resp.text


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "service": "SpdrV2"}), 200


@app.route("/webhook/ivas", methods=["POST"])
def webhook_ivas():
    raw_body = request.get_data() or b""
    headers_dict = {k: v for k, v in request.headers.items()}

    print("[IVAS-DEBUG] Headers:", json.dumps(headers_dict, ensure_ascii=False), flush=True)
    print("[IVAS-DEBUG] Raw body:", raw_body.decode("utf-8", errors="replace"), flush=True)

    if not verify_signature(raw_body, request.headers):
        print("[AUTH-ERR] Invalid signature", flush=True)
        return jsonify({"error": "invalid signature", "ok": False}), 401

    if request.is_json:
        payload = request.get_json(silent=True) or {}
    elif request.form:
        payload = request.form.to_dict()
    else:
        raw_text = raw_body.decode("utf-8", errors="replace").strip()
        try:
            payload = json.loads(raw_text) if raw_text else {}
        except Exception:
            payload = raw_text

    message_text, reply_markup = build_card_payload(payload)
    groups = get_target_groups()

    if not groups:
        return jsonify({"error": "no target groups configured", "ok": False}), 400

    results = []
    for gid in groups:
        ok, info = send_telegram_message(gid, message_text, reply_markup)
        print(f"[TG-SEND] group={gid} ok={ok} info={info}", flush=True)
        results.append({"group": gid, "ok": ok})

    all_ok = all(r["ok"] for r in results)
    return jsonify({"ok": all_ok, "results": results}), (200 if all_ok else 500)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
    
