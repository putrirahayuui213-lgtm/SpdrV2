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

VERIFY_SIGNATURE = False

COUNTRY_INFO = {
    "212": ("🇲🇦", "Morocco", "MA"),
    "213": ("🇩🇿", "Algeria", "DZ"),
    "216": ("🇹🇳", "Tunisia", "TN"),
    "221": ("🇸🇳", "Senegal", "SN"),
    "223": ("🇲🇱", "Mali", "ML"),
    "225": ("🇨🇮", "Cote d'Ivoire", "CI"),
    "226": ("🇧🇫", "Burkina Faso", "BF"),
    "229": ("🇧🇯", "Benin", "BJ"),
    "233": ("🇬🇭", "Ghana", "GH"),
    "234": ("🇳🇬", "Nigeria", "NG"),
    "237": ("🇨🇲", "Cameroon", "CM"),
    "243": ("🇨🇩", "DR Congo", "CD"),
    "250": ("🇷🇼", "Rwanda", "RW"),
    "251": ("🇪🇹", "Ethiopia", "ET"),
    "254": ("🇰🇪", "Kenya", "KE"),
    "255": ("🇹🇿", "Tanzania", "TZ"),
    "256": ("🇺🇬", "Uganda", "UG"),
    "260": ("🇿🇲", "Zambia", "ZM"),
    "263": ("🇿🇼", "Zimbabwe", "ZW"),
    "593": ("🇪🇨", "Ecuador", "EC"),
    "855": ("🇰🇭", "Cambodia", "KH"),
    "856": ("🇱🇦", "Laos", "LA"),
    "880": ("🇧🇩", "Bangladesh", "BD"),
    "966": ("🇸🇦", "Saudi Arabia", "SA"),
    "971": ("🇦🇪", "UAE", "AE"),
    "20": ("🇪🇬", "Egypt", "EG"),
    "27": ("🇿🇦", "South Africa", "ZA"),
    "33": ("🇫🇷", "France", "FR"),
    "34": ("🇪🇸", "Spain", "ES"),
    "44": ("🇬🇧", "United Kingdom", "GB"),
    "49": ("🇩🇪", "Germany", "DE"),
    "55": ("🇧🇷", "Brazil", "BR"),
    "60": ("🇲🇾", "Malaysia", "MY"),
    "62": ("🇮🇩", "Indonesia", "ID"),
    "63": ("🇵🇭", "Philippines", "PH"),
    "65": ("🇸🇬", "Singapore", "SG"),
    "66": ("🇹🇭", "Thailand", "TH"),
    "84": ("🇻🇳", "Vietnam", "VN"),
    "90": ("🇹🇷", "Turkey", "TR"),
    "91": ("🇮🇳", "India", "IN"),
    "92": ("🇵🇰", "Pakistan", "PK"),
    "1": ("🇺🇸", "USA / Canada", "US"),
    "7": ("🇷🇺", "Russia / KZ", "RU"),
}

APP_INFO = [
    (("tiktok",), "🎵", "TT"),
    (("whatsapp", "wa"), "💬", "WA"),
    (("instagram", "ig"), "📸", "IG"),
    (("telegram", "tg"), "✈️", "TG"),
    (("facebook", "fb", "meta"), "📘", "FB"),
    (("google", "gmail", "youtube"), "🔴", "GOO"),
    (("twitter", "x.com"), "✖️", "X"),
    (("dana",), "💙", "DANA"),
    (("ovo",), "💜", "OVO"),
    (("gopay", "gojek"), "🟢", "GOPAY"),
    (("shopee",), "🧡", "SPX"),
]

_tg_session = requests.Session()
_tg_session.mount(
    "https://",
    HTTPAdapter(pool_connections=8, pool_maxsize=16, max_retries=0),
)

# Worker background biar webhook langsung balas 200 OK tanpa nunggu Telegram
_bg_executor = ThreadPoolExecutor(max_workers=8)


def _log(tag: str, msg: str, color: str = ""):
    print(f"[{tag}] {msg}", flush=True)


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
    for code in sorted(COUNTRY_INFO.keys(), key=len, reverse=True):
        if digits.startswith(code):
            return COUNTRY_INFO[code]
    return ("🌐", "Unknown", "INTL")


def detect_app_meta(sms_text: str, sender: str = ""):
    bracket_match = re.search(r"\[([^\[\]]{2,25})\]", sms_text or "")
    haystack = f"{bracket_match.group(1) if bracket_match else ''} {sender} {sms_text}".lower()

    for keywords, icon, tag in APP_INFO:
        if any(re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", haystack) for kw in keywords):
            return icon, tag

    if bracket_match:
        raw_tag = re.sub(r"[^A-Za-z0-9]", "", bracket_match.group(1)).upper()[:6]
        if raw_tag:
            return "📱", raw_tag

    return "📩", "SMS"


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
    app_icon, app_tag = detect_app_meta(clean_sms, str((svc or {}).get("sender", "")))

    return (
        f"¤ {flag} <b>{region_code}</b> • {app_icon} <b>{app_tag}</b> ¤ {phone_formatted} ¤\n"
        f"<b>Prefix:</b> <tg-spoiler>{prefix}</tg-spoiler>\n"
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
                timeout=8,
            )
            data = r.json()
            if data.get("ok"):
                return True
            if r.status_code == 429:
                wait = data.get("parameters", {}).get("retry_after", 3)
                time.sleep(wait + 0.5)
                continue
            _log("TG-ERR", f"chat {chat_id}: {data.get('description', '?')}")
            return False
        except Exception as e:
            if attempt == retries - 1:
                _log("TG-ERR", f"chat {chat_id}: {e}")
            else:
                time.sleep(1.0 * (attempt + 1))
    return False


def tg_send_otp(otp: str, msg_text: str):
    kb = {
        "inline_keyboard": [
            [
                {
                    "text": f"📩 {otp}",
                    "copy_text": {
                        "text": otp
                    },
                    "style": "primary"
                }
            ],
            [
                {
                    "text": "📁 All Files",
                    "url": "https://t.me/matchaappp",
                    "style": "success"
                }
            ]
        ]
    }

    for cid in list_groups():
        _tg_post(cid, msg_text, reply_markup=kb)


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "service": "SpdrV2"}), 200


@app.route("/webhook/ivas", methods=["POST"])
def webhook_ivas():
    raw_body = request.get_data() or b""

    if not verify_signature(raw_body, request.headers):
        _log("AUTH-ERR", "Invalid signature")
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
        sender = "-"
        recipient = "-"
        sms_text = str(payload)

    otp = extract_otp(sms_text)
    flag, country, region_code = detect_country_meta(recipient)
    msg_text = build_otp_message(
        otp=otp,
        svc={"sender": sender},
        flag=flag,
        country=country,
        region_code=region_code,
        masked_num=recipient,
        sms_text=sms_text,
    )

    # Lempar ke background biar IVAS langsung dapat 200 OK instan
    _bg_executor.submit(tg_send_otp, otp, msg_text)
    return jsonify({"ok": True, "otp": otp}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
    
