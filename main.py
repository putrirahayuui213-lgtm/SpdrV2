import hashlib
import hmac
import json
import os
from flask import Flask, jsonify, request
import requests

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
TARGET_GROUPS_RAW = os.getenv("TARGET_GROUPS", "-1005842100073").strip()
IVAS_WEBHOOK_SECRET = os.getenv("IVAS_WEBHOOK_SECRET", "").strip()
PORT = int(os.getenv("PORT", "8080"))

# Ubah ke True kalau sudah tahu format signature IVAS yang exact
VERIFY_SIGNATURE = False


def get_target_groups():
    groups = []
    for item in TARGET_GROUPS_RAW.split(","):
        chat_id = item.strip()
        if chat_id:
            groups.append(chat_id)
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


def extract_message_text(payload) -> str:
    if isinstance(payload, dict):
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload

        event_name = (
            payload.get("event")
            or payload.get("type")
            or data.get("event")
            or "webhook.event"
        )
        sender = (
            data.get("from")
            or data.get("sender")
            or data.get("cli")
            or data.get("number")
            or "-"
        )
        recipient = (
            data.get("to")
            or data.get("recipient")
            or data.get("did")
            or "-"
        )
        body = (
            data.get("message")
            or data.get("text")
            or data.get("body")
            or data.get("sms")
            or data.get("otp")
        )

        if body:
            return (
                f"📩 *IVAS Event:* `{event_name}`\n"
                f"📱 *From:* `{sender}`\n"
                f"📥 *To:* `{recipient}`\n"
                f"💬 *Message:*\n`{body}`"
            )

        pretty = json.dumps(payload, indent=2, ensure_ascii=False)
        if len(pretty) > 3500:
            pretty = pretty[:3500] + "\n... (truncated)"
        return f"📩 *IVAS Webhook Payload:*\n```json\n{pretty}\n```"

    text = str(payload)
    if len(text) > 3500:
        text = text[:3500] + "\n... (truncated)"
    return f"📩 *IVAS Raw Payload:*\n```\n{text}\n```"


def send_telegram_message(chat_id: str, text: str):
    if not BOT_TOKEN:
        return False, "BOT_TOKEN is missing"

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    resp = requests.post(
        url,
        json={
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        },
        timeout=15,
    )
    if resp.status_code != 200:
        # Fallback tanpa Markdown kalau ada karakter spesial yang bikin parse error
        resp = requests.post(
            url,
            json={
                "chat_id": chat_id,
                "text": text.replace("*", "").replace("`", ""),
                "disable_web_page_preview": True,
            },
            timeout=15,
        )
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

    message_text = extract_message_text(payload)
    groups = get_target_groups()

    if not groups:
        return jsonify({"error": "no target groups configured", "ok": False}), 400

    results = []
    for gid in groups:
        ok, info = send_telegram_message(gid, message_text)
        print(f"[TG-SEND] group={gid} ok={ok} info={info}", flush=True)
        results.append({"group": gid, "ok": ok})

    all_ok = all(r["ok"] for r in results)
    return jsonify({"ok": all_ok, "results": results}), (200 if all_ok else 500)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
    
