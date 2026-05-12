"""
device/app.py  —  IoMT Device Sender (PC 1)
============================================
UPDATED:
  - Device generates its own ECDSA keypair locally (private key never leaves)
  - POST /auth to gateway once at startup → gets session_token + kyber_public_key
  - hmac_token removed from per-packet payload
  - vitals_hash removed from per-packet payload
  - Session token used for all subsequent packets
  - Re-auth automatically if 401 received
"""

import os, json, base64, threading, requests
from flask import Flask, render_template, request, redirect, url_for

import paho.mqtt.client as mqtt

from crypto_engine_device import (
    build_packet, set_gateway_kyber_public,
    seen_nonces, generate_ecdsa_keypair,
    get_ecdsa_public_key_pem
)
from auth import make_auth_token, DEVICE_KEYS, generate_token

app = Flask(__name__)
app.secret_key = "device-secret-2026"

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:5000").rstrip("/")
MQTT_BROKER = os.environ.get("MQTT_BROKER", "127.0.0.1")
MQTT_PORT   = int(os.environ.get("MQTT_PORT", 1883))
MQTT_TOPIC  = "iomt/packets"

# ── Device state ──────────────────────────────────────────────────────────────

# ECDSA keypair generated locally — private key never transmitted
_device_priv, _device_pub = generate_ecdsa_keypair()

_session_token  = None
_session_expiry = None
_authed         = False
_mqtt_connected = False

# ── MQTT client ───────────────────────────────────────────────────────────────

_mqtt_client = mqtt.Client(
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    client_id=f"iomt-device-{os.getpid()}"
)

def _on_connect(client, userdata, connect_flags, reason_code, properties):
    global _mqtt_connected
    _mqtt_connected = reason_code == 0
    if reason_code == 0:
        print(f"[MQTT] ✓ Connected to broker {MQTT_BROKER}:{MQTT_PORT}")
    else:
        print(f"[MQTT] ✗ Connect failed, reason_code={reason_code}")

def _on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    global _mqtt_connected
    _mqtt_connected = False

_mqtt_client.on_connect    = _on_connect
_mqtt_client.on_disconnect = _on_disconnect

def _mqtt_thread():
    try:
        _mqtt_client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
        _mqtt_client.loop_forever()
    except Exception as e:
        print(f"[MQTT] ✗ Cannot connect to {MQTT_BROKER}:{MQTT_PORT} — {e}")

threading.Thread(target=_mqtt_thread, daemon=True).start()

# ── Auth — one-time handshake ─────────────────────────────────────────────────

def do_auth(gateway_url: str, device_id: str) -> dict:
    """
    POST /auth to gateway:
      - sends device_id, hmac_token (one-time), ecdsa_public_key
      - receives session_token + kyber_public_key
      - stores session_token and sets gateway Kyber public key
    """
    global _session_token, _session_expiry, _authed, GATEWAY_URL
    GATEWAY_URL = gateway_url.rstrip("/")

    from datetime import datetime, timezone
    import secrets as sec

    timestamp  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce      = sec.token_hex(8)
    hmac_token = make_auth_token(device_id, timestamp, nonce)
    pub_key_b64 = get_ecdsa_public_key_pem(_device_pub)

    r = requests.post(f"{GATEWAY_URL}/auth", json={
        "device_id":        device_id,
        "timestamp":        timestamp,
        "nonce":            nonce,
        "hmac_token":       hmac_token,
        "ecdsa_public_key": pub_key_b64,
    }, timeout=6)

    if r.status_code != 200:
        raise Exception(f"Auth failed: {r.json().get('error', r.text)}")

    data = r.json()
    _session_token  = data["session_token"]
    _session_expiry = data["expiry"]
    _authed         = True

    # Kyber public key arrives in the auth response (authenticated channel)
    kyber_pub = base64.b64decode(data["kyber_public_key"])
    set_gateway_kyber_public(kyber_pub)

    print(f"[AUTH] ✓ Authenticated. Session expires: {_session_expiry}")
    return data

# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("device.html",
                           gateway_url=GATEWAY_URL,
                           mqtt_broker=MQTT_BROKER,
                           mqtt_port=MQTT_PORT,
                           mqtt_connected=_mqtt_connected,
                           fetched=_authed,
                           result=request.args.get("result"),
                           status=request.args.get("status"),
                           reason=request.args.get("reason", ""),
                           pkt_id=request.args.get("pkt_id", ""),
                           err=request.args.get("err"))


@app.route("/fetch-keys", methods=["POST"])
def do_fetch():
    """Renamed to auth but keeping the route for UI compatibility."""
    gw        = request.form.get("gateway_url", GATEWAY_URL)
    device_id = request.form.get("device_id", "IOMT-DEV-00423").strip()
    try:
        do_auth(gw, device_id)
        return redirect(url_for("index") + "?result=fetched")
    except Exception as e:
        return redirect(url_for("index") + f"?err=Auth failed: {e}")


@app.route("/send", methods=["POST"])
def send():
    global _session_token, _authed

    if not _authed or _session_token is None:
        return redirect(url_for("index") + "?err=Authenticate with gateway first")

    if not _mqtt_connected:
        return redirect(url_for("index") +
                        f"?err=MQTT broker not connected ({MQTT_BROKER}:{MQTT_PORT})")

    action     = request.form.get("action", "normal")
    device_id  = request.form.get("device_id", "IOMT-DEV-00423").strip()
    patient_id = request.form.get("patient_id", "PAT-9981").strip()
    vitals = {
        "heart_rate":     int(request.form.get("heart_rate", 82)),
        "spo2":           int(request.form.get("spo2", 97)),
        "temperature":    float(request.form.get("temperature", 36.7)),
        "blood_pressure": request.form.get("blood_pressure", "120/80"),
    }

    packet = build_packet(device_id, patient_id, vitals, _device_priv, _session_token)

    # ── Attack simulations ────────────────────────────────────────────────────
    if action == "tamper":
        raw = base64.b64decode(packet["encrypted_data"])
        packet["encrypted_data"] = base64.b64encode(
            bytes([raw[0] ^ 0xFF]) + raw[1:]
        ).decode()

    elif action == "replay":
        # Reuse an old nonce — gateway nonce check catches this
        if seen_nonces:
            packet["nonce"]      = next(iter(seen_nonces))
            packet["signature"]  = packet["signature"]  # signature now invalid too

    elif action == "expired":
        # Ancient timestamp — gateway drift check catches this
        packet["timestamp"]  = "2020-01-01T00:00:00Z"

    elif action == "baddevice":
        # Unknown session — gateway session lookup fails
        packet["session_token"] = "invalid-session-token-000"

    elif action == "forged":
        # Random signature — ECDSA verify fails
        import secrets as sec
        packet["signature"]  = base64.b64encode(sec.token_bytes(64)).decode()

    # ── Publish via MQTT ──────────────────────────────────────────────────────
    try:
        payload = json.dumps(packet)
        info    = _mqtt_client.publish(MQTT_TOPIC, payload, qos=1)
        info.wait_for_publish(timeout=5)
        seen_nonces.add(packet["nonce"])
        return redirect(url_for("index") +
                        "?result=sent&status=PUBLISHED"
                        "&reason=Encrypted+packet+sent+via+MQTT"
                        "&pkt_id=mqtt-ok")
    except Exception as e:
        return redirect(url_for("index") + f"?err=MQTT publish failed: {e}")


if __name__ == "__main__":
    print(f"\n{'='*55}")
    print("  IoMT Device Sender  —  PC 1")
    print(f"  UI          : http://localhost:5001/")
    print(f"  Gateway URL : {GATEWAY_URL}")
    print(f"  MQTT Broker : {MQTT_BROKER}:{MQTT_PORT}")
    print(f"  MQTT Topic  : {MQTT_TOPIC}")
    print(f"  Note: Run /fetch-keys (Auth) before sending packets")
    print(f"{'='*55}\n")
    app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=False)