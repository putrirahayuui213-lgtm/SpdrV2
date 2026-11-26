import hashlib
import hmac
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN")
IVAS_WEBHOOK_SECRET = os.getenv("IVAS_WEBHOOK_SECRET", "")
TARGET_GROUPS = [
    int(x.strip())
    for x in os.getenv("TARGET_GROUPS", "-1005842100073").split(",")
    if x.strip()
]

# --- 1. Telegram Session & Sender ---
_tg_session = requests.Session()
_tg_session.mount(
    "https://",
    requests.adapters.HTTPAdapter(
        pool_connections=4,
        pool_maxsize=10,
        max_retries=0,
    ),
)


def _log(tag: str, msg: str):
    print(f"[{tag}] {msg}", flush=True)


def list_groups() -> list[int]:
    return TARGET_GROUPS


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
            _log("TG-ERR", f"chat {chat_id}: {data.get('description', '?')}")
            return False
        except Exception as e:
            if attempt == retries - 1:
                _log("TG-ERR", f"chat {chat_id}: {e}")
            else:
                time.sleep(1.5 ** (attempt + 1))
    return False


def tg_send_otp(otp: str, msg_text: str):
    kb = {
        "inline_keyboard": [
            [
                {
                    "text": f"📩 {otp}",
                    "copy_text": {"text": otp},
                    "style": "primary",
                }
            ],
            [
                {
                    "text": "📁 All Files",
                    "url": "https://t.me/matchaappp",
                    "style": "success",
                }
            ],
        ]
    }

    targets = list_groups()

    def _send_one(cid):
        _tg_post(cid, msg_text, reply_markup=kb)

    if len(targets) == 1:
        _send_one(targets[0])
    elif targets:
        with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
            list(pool.map(_send_one, targets))


# --- 2. Template Pesan ---
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

    if len(raw_num) >= 8:
        phone_formatted = f"<b>{raw_num[:4]}•🕷️•{raw_num[-4:]}</b>"
    else:
        phone_formatted = f"<b>{raw_num}</b>"

    prefix = raw_num[:6] if len(raw_num) >= 6 else raw_num
    clean_sms = sms_text.replace("<#>", "").strip()

    return (
        f"¤ {flag} <b>{region_code}</b> ¤ {phone_formatted} ¤\n"
        f"<b>Prefix:</b> <tg-spoiler>{prefix}</tg-spoiler>\n"
        f"<blockquote>{clean_sms}</blockquote>"
    )


# --- 3. Helper OTP & Region ---
def extract_otp(sms_text: str) -> str:
    if not sms_text:
        return "----"
    m = re.search(r"\b(?:[A-Z]-)?(\d{4,8})\b", sms_text)
    if m:
        return m.group(0) if "-" in m.group(0) else m.group(1)
    return "----"


COUNTRY_MAP = {
    "MOZAMBIQUE": ("🇲🇿", "MZ"),
    "INDONESIA": ("🇮🇩", "ID"),
    "MALI": ("🇲🇱", "ML"),
    "CONGO": ("🇨🇩", "CD"),
    "DRC": ("🇨🇩", "CD"),
}


def resolve_region(range_name: str, number: str) -> tuple[str, str, str]:
    upper_range = (range_name or "").upper()
    for name, (flag, code) in COUNTRY_MAP.items():
        if name in upper_range:
            return flag, name.title(), code

    first_word = (range_name or "").strip().split(" ")[0].upper()
    if first_word:
        return "🌍", first_word.title(), first_word[:2]

    digits = re.sub(r"\D", "", str(number))
    return "🌍", "Unknown", digits[:2] or "XX"


# --- 4. Webhook Verification & Endpoint ---
def verify_signature(raw_body: bytes, sig_header: str, secret: str) -> bool:
    if not secret:
        return True
    if not sig_header:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    provided = sig_header.replace("sha256=", "").strip()
    return hmac.compare_digest(expected, provided)


@app.route("/webhook/ivas", methods=["POST"])
def ivas_webhook():
    raw_body = request.get_data()
    sig_header = request.headers.get("X-IVAS-Signature", "")
    event_name = request.headers.get("X-IVAS-Event", "")

    if not verify_signature(raw_body, sig_header, IVAS_WEBHOOK_SECRET):
        _log("AUTH-ERR", "Invalid signature")
        return jsonify({"ok": False, "error": "invalid signature"}), 401

    try:
        body = json.loads(raw_body.decode("utf-8"))
    except Exception:
        return jsonify({"ok": False, "error": "invalid json"}), 400

    event = body.get("event") or event_name
    data = body.get("data") or {}

    if event and event != "message.received":
        return jsonify({"ok": True, "ignored_event": event}), 200

    sms_text = str(data.get("message", ""))
    number = str(data.get("number", ""))
    range_name = str(data.get("range_name", ""))
    source = str(data.get("source", "SMS"))

    otp = extract_otp(sms_text)
    flag, country, region_code = resolve_region(range_name, number)

    msg_text = build_otp_message(
        otp=otp,
        svc={"source": source, "raw": data},
        flag=flag,
        country=country,
        region_code=region_code,
        masked_num=number,
        sms_text=sms_text,
    )

    tg_send_otp(otp, msg_text)
    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
