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
IVAS_SECRETS_RAW = os.getenv("IVAS_SECRETS", "").strip()
PORT = int(os.getenv("PORT", "8080"))

# Ubah ke True kalau sudah tahu format signature IVAS yang exact
VERIFY_SIGNATURE = False

# Urutkan dari kode terpanjang ke terpendek agar prefix tidak tertukar
COUNTRY_INFO = {
    "1242": ("🇧🇸", "Bahamas", "BS"),
    "1246": ("🇧🇧", "Barbados", "BB"),
    "1268": ("🇦🇬", "Antigua & Barbuda", "AG"),
    "1876": ("🇯🇲", "Jamaica", "JM"),
    "1868": ("🇹🇹", "Trinidad & Tobago", "TT"),
    "212": ("🇲🇦", "Morocco", "MA"),
    "213": ("🇩🇿", "Algeria", "DZ"),
    "216": ("🇹🇳", "Tunisia", "TN"),
    "218": ("🇱🇾", "Libya", "LY"),
    "220": ("🇬🇲", "Gambia", "GM"),
    "221": ("🇸🇳", "Senegal", "SN"),
    "222": ("🇲🇷", "Mauritania", "MR"),
    "223": ("🇲🇱", "Mali", "ML"),
    "224": ("🇬🇳", "Guinea", "GN"),
    "225": ("🇨🇮", "Cote d'Ivoire", "CI"),
    "226": ("🇧🇫", "Burkina Faso", "BF"),
    "227": ("🇳🇪", "Niger", "NE"),
    "228": ("🇹🇬", "Togo", "TG"),
    "229": ("🇧🇯", "Benin", "BJ"),
    "230": ("🇲🇺", "Mauritius", "MU"),
    "231": ("🇱🇷", "Liberia", "LR"),
    "232": ("🇸🇱", "Sierra Leone", "SL"),
    "233": ("🇬🇭", "Ghana", "GH"),
    "234": ("🇳🇬", "Nigeria", "NG"),
    "235": ("🇹🇩", "Chad", "TD"),
    "236": ("🇨🇫", "Central African Rep.", "CF"),
    "237": ("🇨🇲", "Cameroon", "CM"),
    "238": ("🇨🇻", "Cape Verde", "CV"),
    "239": ("🇸🇹", "Sao Tome & Principe", "ST"),
    "240": ("🇬🇶", "Equatorial Guinea", "GQ"),
    "241": ("🇬🇦", "Gabon", "GA"),
    "242": ("🇨🇬", "Congo", "CG"),
    "243": ("🇨🇩", "DR Congo", "CD"),
    "244": ("🇦🇴", "Angola", "AO"),
    "245": ("🇬🇼", "Guinea-Bissau", "GW"),
    "248": ("🇸🇨", "Seychelles", "SC"),
    "249": ("🇸🇩", "Sudan", "SD"),
    "250": ("🇷🇼", "Rwanda", "RW"),
    "251": ("🇪🇹", "Ethiopia", "ET"),
    "252": ("🇸🇴", "Somalia", "SO"),
    "253": ("🇩🇯", "Djibouti", "DJ"),
    "254": ("🇰🇪", "Kenya", "KE"),
    "255": ("🇹🇿", "Tanzania", "TZ"),
    "256": ("🇺🇬", "Uganda", "UG"),
    "257": ("🇧🇮", "Burundi", "BI"),
    "258": ("🇲🇿", "Mozambique", "MZ"),
    "260": ("🇿🇲", "Zambia", "ZM"),
    "261": ("🇲🇬", "Madagascar", "MG"),
    "263": ("🇿🇼", "Zimbabwe", "ZW"),
    "264": ("🇳🇦", "Namibia", "NA"),
    "265": ("🇲🇼", "Malawi", "MW"),
    "266": ("🇱🇸", "Lesotho", "LS"),
    "267": ("🇧🇼", "Botswana", "BW"),
    "268": ("🇸🇿", "Eswatini", "SZ"),
    "269": ("🇰🇲", "Comoros", "KM"),
    "351": ("🇵🇹", "Portugal", "PT"),
    "352": ("🇱🇺", "Luxembourg", "LU"),
    "353": ("🇮🇪", "Ireland", "IE"),
    "354": ("🇮🇸", "Iceland", "IS"),
    "355": ("🇦🇱", "Albania", "AL"),
    "356": ("🇲🇹", "Malta", "MT"),
    "357": ("🇨🇾", "Cyprus", "CY"),
    "358": ("🇫🇮", "Finland", "FI"),
    "359": ("🇧🇬", "Bulgaria", "BG"),
    "370": ("🇱🇹", "Lithuania", "LT"),
    "371": ("🇱🇻", "Latvia", "LV"),
    "372": ("🇪🇪", "Estonia", "EE"),
    "373": ("🇲🇩", "Moldova", "MD"),
    "374": ("🇦🇲", "Armenia", "AM"),
    "375": ("🇧🇾", "Belarus", "BY"),
    "380": ("🇺🇦", "Ukraine", "UA"),
    "381": ("🇷🇸", "Serbia", "RS"),
    "385": ("🇭🇷", "Croatia", "HR"),
    "386": ("🇸🇮", "Slovenia", "SI"),
    "420": ("🇨🇿", "Czechia", "CZ"),
    "421": ("🇸🇰", "Slovakia", "SK"),
    "501": ("🇧🇿", "Belize", "BZ"),
    "502": ("🇬🇹", "Guatemala", "GT"),
    "503": ("🇸🇻", "El Salvador", "SV"),
    "504": ("🇭🇳", "Honduras", "HN"),
    "505": ("🇳🇮", "Nicaragua", "NI"),
    "506": ("🇨🇷", "Costa Rica", "CR"),
    "507": ("🇵🇦", "Panama", "PA"),
    "509": ("🇭🇹", "Haiti", "HT"),
    "591": ("🇧🇴", "Bolivia", "BO"),
    "592": ("🇬🇾", "Guyana", "GY"),
    "593": ("🇪🇨", "Ecuador", "EC"),
    "595": ("🇵🇾", "Paraguay", "PY"),
    "597": ("🇸🇷", "Suriname", "SR"),
    "598": ("🇺🇾", "Uruguay", "UY"),
    "673": ("🇧🇳", "Brunei", "BN"),
    "675": ("🇵🇬", "Papua New Guinea", "PG"),
    "852": ("🇭🇰", "Hong Kong", "HK"),
    "853": ("🇲🇴", "Macau", "MO"),
    "855": ("🇰🇭", "Cambodia", "KH"),
    "856": ("🇱🇦", "Laos", "LA"),
    "880": ("🇧🇩", "Bangladesh", "BD"),
    "886": ("🇹🇼", "Taiwan", "TW"),
    "960": ("🇲🇻", "Maldives", "MV"),
    "961": ("🇱🇧", "Lebanon", "LB"),
    "962": ("🇯🇴", "Jordan", "JO"),
    "963": ("🇸🇾", "Syria", "SY"),
    "964": ("🇮🇶", "Iraq", "IQ"),
    "965": ("🇰🇼", "Kuwait", "KW"),
    "966": ("🇸🇦", "Saudi Arabia", "SA"),
    "967": ("🇾🇪", "Yemen", "YE"),
    "968": ("🇴🇲", "Oman", "OM"),
    "970": ("🇵🇸", "Palestine", "PS"),
    "971": ("🇦🇪", "UAE", "AE"),
    "972": ("🇮🇱", "Israel", "IL"),
    "973": ("🇧🇭", "Bahrain", "BH"),
    "974": ("🇶🇦", "Qatar", "QA"),
    "975": ("🇧🇹", "Bhutan", "BT"),
    "976": ("🇲🇳", "Mongolia", "MN"),
    "977": ("🇳🇵", "Nepal", "NP"),
    "992": ("🇹🇯", "Tajikistan", "TJ"),
    "993": ("🇹🇲", "Turkmenistan", "TM"),
    "994": ("🇦🇿", "Azerbaijan", "AZ"),
    "995": ("🇬🇪", "Georgia", "GE"),
    "996": ("🇰🇬", "Kyrgyzstan", "KG"),
    "998": ("🇺🇿", "Uzbekistan", "UZ"),
    "20": ("🇪🇬", "Egypt", "EG"),
    "27": ("🇿🇦", "South Africa", "ZA"),
    "30": ("🇬🇷", "Greece", "GR"),
    "31": ("🇳🇱", "Netherlands", "NL"),
    "32": ("🇧🇪", "Belgium", "BE"),
    "33": ("🇫🇷", "France", "FR"),
    "34": ("🇪🇸", "Spain", "ES"),
    "36": ("🇭🇺", "Hungary", "HU"),
    "39": ("🇮🇹", "Italy", "IT"),
    "40": ("🇷🇴", "Romania", "RO"),
    "41": ("🇨🇭", "Switzerland", "CH"),
    "43": ("🇦🇹", "Austria", "AT"),
    "44": ("🇬🇧", "United Kingdom", "GB"),
    "45": ("🇩🇰", "Denmark", "DK"),
    "46": ("🇸🇪", "Sweden", "SE"),
    "47": ("🇳🇴", "Norway", "NO"),
    "48": ("🇵🇱", "Poland", "PL"),
    "49": ("🇩🇪", "Germany", "DE"),
    "51": ("🇵🇪", "Peru", "PE"),
    "52": ("🇲🇽", "Mexico", "MX"),
    "53": ("🇨🇺", "Cuba", "CU"),
    "54": ("🇦🇷", "Argentina", "AR"),
    "55": ("🇧🇷", "Brazil", "BR"),
    "56": ("🇨🇱", "Chile", "CL"),
    "57": ("🇨🇴", "Colombia", "CO"),
    "58": ("🇻🇪", "Venezuela", "VE"),
    "60": ("🇲🇾", "Malaysia", "MY"),
    "61": ("🇦🇺", "Australia", "AU"),
    "62": ("🇮🇩", "Indonesia", "ID"),
    "63": ("🇵🇭", "Philippines", "PH"),
    "64": ("🇳🇿", "New Zealand", "NZ"),
    "65": ("🇸🇬", "Singapore", "SG"),
    "66": ("🇹🇭", "Thailand", "TH"),
    "81": ("🇯🇵", "Japan", "JP"),
    "82": ("🇰🇷", "South Korea", "KR"),
    "84": ("🇻🇳", "Vietnam", "VN"),
    "86": ("🇨🇳", "China", "CN"),
    "90": ("🇹🇷", "Turkey", "TR"),
    "91": ("🇮🇳", "India", "IN"),
    "92": ("🇵🇰", "Pakistan", "PK"),
    "93": ("🇦🇫", "Afghanistan", "AF"),
    "94": ("🇱🇰", "Sri Lanka", "LK"),
    "95": ("🇲🇲", "Myanmar", "MM"),
    "98": ("🇮🇷", "Iran", "IR"),
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
    HTTPAdapter(pool_connections=4, pool_maxsize=10, max_retries=0),
)


def _log(tag: str, msg: str, color: str = ""):
    print(f"[{tag}] {msg}", flush=True)


def get_all_secrets():
    secrets = []
    seen = set()
    raw_items = []

    if IVAS_SECRETS_RAW:
        try:
            parsed = json.loads(IVAS_SECRETS_RAW)
            if isinstance(parsed, dict):
                raw_items.extend(str(v).strip() for v in parsed.values())
            elif isinstance(parsed, list):
                raw_items.extend(str(v).strip() for v in parsed)
            else:
                raw_items.extend(s.strip() for s in IVAS_SECRETS_RAW.split(","))
        except Exception:
            raw_items.extend(s.strip() for s in IVAS_SECRETS_RAW.split(","))

    if IVAS_WEBHOOK_SECRET:
        raw_items.append(IVAS_WEBHOOK_SECRET)

    for item in raw_items:
        if item and item not in seen:
            seen.add(item)
            secrets.append(item)
    return secrets


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
    secrets = get_all_secrets()
    if not VERIFY_SIGNATURE or not secrets:
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

    for secret in secrets:
        expected_hex = hmac.new(
            secret.encode("utf-8"),
            raw_body,
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(expected_hex.lower(), sig.lower()):
            return True

    return False


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

    # Masking nomor telepon & tebelin
    if len(raw_num) >= 8:
        phone_formatted = f"<b>{raw_num[:4]}•🕷️•{raw_num[-4:]}</b>"
    else:
        phone_formatted = f"<b>{raw_num}</b>"

    prefix = raw_num[:6] if len(raw_num) >= 6 else raw_num
    clean_sms = sms_text.replace("<#>", "").strip()
    app_icon, app_tag = detect_app_meta(clean_sms, str((svc or {}).get("sender", "")))

    # Baris 1: Header + App, Baris 2: Prefix, Baris 3: Isi SMS
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


def tg_send_msg(chat_id: int, text: str):
    _tg_post(chat_id, text)


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

    targets = list_groups()

    def _send_one(cid):
        _tg_post(
            cid,
            msg_text,
            reply_markup=kb
        )

    if len(targets) == 1:
        _send_one(targets[0])
    elif targets:
        with ThreadPoolExecutor(
            max_workers=min(8, len(targets))
        ) as pool:
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

    tg_send_otp(otp, msg_text)
    return jsonify({"ok": True, "otp": otp}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
