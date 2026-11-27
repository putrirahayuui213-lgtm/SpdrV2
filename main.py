from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import os
import re
import time
from flask import Flask, jsonify, request
import requests
from requests.adapters import HTTPAdapter

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
TARGET_GROUPS_RAW = os.getenv("TARGET_GROUPS", "-1005842100073").strip()
IVAS_WEBHOOK_SECRET = os.getenv("IVAS_WEBHOOK_SECRET", "").strip()
PORT = int(os.getenv("PORT", "8080"))

# Ubah ke True kalau sudah tahu format signature IVAS yang exact
VERIFY_SIGNATURE = False

COUNTRY_INFO = {
    "256": ("🇺🇬", "Uganda", "UG"),
    "223": ("🇲🇱", "Mali", "ML"),
    "593": ("🇪🇨", "Ecuador", "EC"),
    "243": ("🇨🇩", "DR Congo", "CD"),
    "62": ("🇮🇩", "Indonesia", "ID"),
}

_tg_session = requests.Session()
_tg_session.mount(
    "https://",
    HTTPAdapter(pool_connections=4, pool_maxsize=10, max_retries=0),
)


def list_groups():
    groups = []
    for item in TARGET_GROUPS_RAW.split(","):
        val = item.strip()
        if not val:
            continue
        try:
            groups.append(int(val))
        except ValueError:
            groups.append(val)
    return groups


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


def detect_country_meta(num_str: str):
    digits = re.sub(r"\D", "", num_str or "")
    for code, info in COUNTRY_INFO.items():
        if digits.startswith(code):
            return info
    return ("🌐", "Unknown", "INTL")


def escape_html(text: str) -> str:
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def build_otp_message(
    otp: str,
    svc: dict,
    flag: str,
    country: str,
    region_code: str,
    masked_num: str,
    sms_text: str = "",
) -> str:
    raw_num = re.sub(r"\D", "", str(masked_num))

    # Masking nomor telepon & tebelin
    if len(raw_num) >= 8:
        phone_formatted = f"<b>{raw_num[:4]}•🕷️•{raw_num[-4:]}</b>"
    else:
        phone_formatted = f"<b>{escape_html(raw_num or str(masked_num))}</b>"

    prefix = raw_num[:6] if len(raw_num) >= 6 else raw_num
    clean_sms = escape_html(sms_text.replace("<#>", "").strip())

    # Baris 1: Header, Baris 2: Prefix, Baris 3: Isi SMS
    return (
        f"¤ {flag} <b>{escape_html(region_code)}</b> ¤ {phone_formatted} ¤\n"
        f"<b>Prefix:</b> <tg-spoiler>{escape_html(prefix)}</tg-spoiler>\n"
        f"<blockquote>{clean_sms}</blockquote>"
    )


def _tg_post(chat_id, text, reply_markup=None, retries=3):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup

    for attempt in range(retries):
        try:
            r = _tg_session.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json=payload,
                timeout=10,
            )
            data = r.json()
            if data.get("ok"):
                return True
            if r.status_code == 429:
                wait = data.get("parameters", {}).get("retry_after", 5)
                time.sleep(wait + 1)
                continue

            # Fallback kalau reply_markup / tag HTML ditolak Telegram
            if reply_markup and attempt == 0:
                clean_kb = {
                    "inline_keyboard": [
                        [
                            {k: v for k, v in btn.items() if k != "style"}
                            for btn in row
                        ]
                        for row in reply_markup.get("inline_keyboard", [])
                    ]
                }
                payload["reply_markup"] = clean_kb
                continue

            print(
                f"[TG-ERR] chat {chat_id}: {data.get('description', '?')}",
                flush=True,
            )
            return False
        except Exception as e:
            if attempt == retries - 1:
                print(f"[TG-ERR] chat {chat_id}: {e}", flush=True)
            else:
                time.sleep(1.5 ** (attempt + 1))
    return False


def tg_send_msg(chat_id: int, text: str):
    _tg_post(chat_id, text)


def tg_send_otp(otp: str, msg_text: str):
    rows = []
    if otp and otp != "-":
        rows.append([
            {
                "text": f"📩 {otp}",
                "copy_text": {"text": otp},
            }
        ])
    rows.append([
        {
            "text": "📁 All Files",
            "url": "https://t.me/matchaappp",
        }
    ])
    kb = {"inline_keyboard": rows}

    targets = list_groups()

    def _send_one(cid):
        ok = _tg_post(cid, msg_text, reply_markup=kb)
        print(f"[TG-SEND] chat={cid} ok={ok}", flush=True)

    if len(targets) == 1:
        _send_one(targets[0])
    elif targets:
        with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
            list(pool.map(_send_one, targets))


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
        sms_text = (
            find_first_value(
                payload,
                ["message", "text", "body", "sms", "content", "otp"],
            )
            or ""
        )
    else:
        recipient = "-"
        sms_text = str(payload)

    otp = extract_otp(sms_text)
    flag, country, region_code = detect_country_meta(recipient)
    msg_text = build_otp_message(
        otp=otp,
        svc={},
        flag=flag,
        country=country,
        region_code=region_code,
        masked_num=recipient,
        sms_text=sms_text,
    )

    tg_send_otp(otp, msg_text)
    return jsonify({"ok": True, "otp": otp}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
    
