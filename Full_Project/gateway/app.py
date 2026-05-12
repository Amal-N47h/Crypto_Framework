"""
gateway/app.py  —  IoMT Gateway (PC 2)
=======================================
UPDATED:
  - POST /auth  — one-time device authentication → issues session token
                  receives device ECDSA public key, stores in DB
                  returns session_token + kyber_public_key
  - Removed GET /kyber-pubkey  (now inside /auth response)
  - Removed GET /device-privkey (device generates its own keys now)
  - MQTT handler uses session token lookup instead of per-packet HMAC
  - verify_packet() receives device public key loaded from DB
  - _auth_nonces separate from seen_nonces (packet nonces)
"""

import uuid, json, base64, threading, os, hmac, hashlib, secrets
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for

import paho.mqtt.client as mqtt

from auth import (init_registry, get_all_devices, get_device,
                  set_device_status, verify_device, DEVICE_KEYS)
from crypto_engine import (verify_packet, get_gateway_kyber_public,
                            seen_nonces, load_public_key_from_pem)
from database import (init_db, save_packet, save_alert,
                      get_all_packets, get_all_alerts,
                      get_stats, get_metrics, clear_all,
                      save_session, get_session, get_all_sessions)

app = Flask(__name__)
app.secret_key = "gateway-secret-2026"

MQTT_BROKER       = os.environ.get("MQTT_BROKER", "127.0.0.1")
MQTT_PORT         = int(os.environ.get("MQTT_PORT", 1883))
MQTT_TOPIC        = "iomt/packets"
SESSION_SECRET    = os.urandom(32)
SESSION_TTL_HOURS = 24

# Separate nonce sets — auth nonces must not collide with packet nonces
_auth_nonces = set()

init_db()
init_registry()

# ── Session token helpers ──────────────────────────────────────────────────────

def _make_session_token(device_id: str, expiry: str) -> str:
    message = f"{device_id}{expiry}".encode()
    return hmac.new(SESSION_SECRET, message, hashlib.sha256).hexdigest()


def _validate_session(session_token: str) -> tuple:
    """
    Returns (ok, device_id, ecdsa_public_key_b64, reason)
    Checks: token exists in DB, not expired, device still ACTIVE.
    """
    session = get_session(session_token)
    if session is None:
        return False, None, None, "Invalid or expired session token"

    try:
        expiry = datetime.fromisoformat(session["expiry"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expiry:
            return False, None, None, "Session expired — re-authenticate"
    except Exception:
        return False, None, None, "Invalid session expiry format"

    device = get_device(session["device_id"])
    if device is None:
        return False, None, None, "Device no longer registered"
    if device["status"] == "BLOCKED":
        return False, None, None, "Device is blocked"
    if device["status"] == "SUSPENDED":
        return False, None, None, "Device is suspended"

    return True, session["device_id"], session["ecdsa_public_key"], "OK"


# ── Shared packet processor ────────────────────────────────────────────────────

def _process_packet(packet: dict):
    packet_id = str(uuid.uuid4())[:8]

    # Step 1 — session token validation
    session_token = packet.get("session_token", "")
    ok, device_id, pub_key_b64, reason = _validate_session(session_token)

    if not ok:
        metrics = {"attack_type": "INVALID_SESSION", "total_ms": 0,
                   "hmac_ms": 0, "hash_ms": 0, "ecdsa_ms": 0,
                   "kyber_ms": 0, "aes_ms": 0, "encrypt_ms": 0, "latency_ms": 0}
        save_packet(packet_id, packet, "INVALID_DEVICE", reason, None, metrics)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        save_alert(packet_id, packet.get("device_id", "?"),
                   "INVALID_DEVICE", reason, ts, "INVALID_SESSION")
        return packet_id, "INVALID_DEVICE", reason

    # Step 2 — load device ECDSA public key from DB
    try:
        device_pub = load_public_key_from_pem(pub_key_b64)
    except Exception as e:
        return packet_id, "INVALID_DEVICE", f"Cannot load device public key: {e}"

    # Step 3 — full cryptographic verification
    result  = verify_packet(packet, device_public_key=device_pub)
    status  = result["status"]
    reason  = result["reason"]
    metrics = result.get("metrics", {})

    save_packet(packet_id, packet, status, reason, result["vitals"], metrics)

    if status != "VALID":
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        save_alert(packet_id, device_id,
                   status, reason, ts, metrics.get("attack_type", ""))

    return packet_id, status, reason


# ── MQTT subscriber ────────────────────────────────────────────────────────────

def _on_mqtt_connect(client, userdata, connect_flags, reason_code, properties):
    if reason_code == 0:
        client.subscribe(MQTT_TOPIC, qos=1)
        print(f"[MQTT] ✓ Gateway subscribed to '{MQTT_TOPIC}' on {MQTT_BROKER}:{MQTT_PORT}")
    else:
        print(f"[MQTT] ✗ Broker connection failed, reason_code={reason_code}")


def _on_mqtt_message(client, userdata, msg):
    try:
        packet = json.loads(msg.payload.decode("utf-8"))
        packet_id, status, reason = _process_packet(packet)
        print(f"[MQTT] ← packet {packet_id} | {status}: {reason}")
    except Exception as e:
        print(f"[MQTT] Error processing message: {e}")


def _start_mqtt():
    import time as _time
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"iomt-gateway-{os.getpid()}"
    )
    client.on_connect = _on_mqtt_connect
    client.on_message = _on_mqtt_message
    while True:
        try:
            client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            client.loop_forever()
        except Exception as e:
            print(f"[MQTT] ✗ Cannot connect to {MQTT_BROKER}:{MQTT_PORT} — {e}")
            print(f"[MQTT] Retrying in 5s...")
            _time.sleep(5)


threading.Thread(target=_start_mqtt, daemon=True).start()


# ── POST /auth — one-time device authentication ────────────────────────────────

@app.route("/auth", methods=["POST"])
def auth():
    """
    One-time HMAC auth → issue session token + return Kyber public key.

    Request:  { device_id, timestamp, nonce, hmac_token, ecdsa_public_key }
    Response: { session_token, expiry, kyber_public_key }
    """
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    required = ["device_id", "timestamp", "nonce", "hmac_token", "ecdsa_public_key"]
    missing  = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    # Full HMAC device verification using dedicated auth nonce set
    ok, reason, attack_type = verify_device(
        device_id=data["device_id"],
        timestamp=data["timestamp"],
        nonce=data["nonce"],
        token=data["hmac_token"],
        seen_nonces=_auth_nonces,   # ← separate from packet nonces
    )

    if not ok:
        return jsonify({"error": reason, "attack_type": attack_type}), 401

    # Generate session token
    expiry        = (datetime.now(timezone.utc) +
                     timedelta(hours=SESSION_TTL_HOURS)
                     ).strftime("%Y-%m-%dT%H:%M:%SZ")
    session_token = _make_session_token(data["device_id"], expiry)

    # Store session with device ECDSA public key
    save_session(
        session_token=session_token,
        device_id=data["device_id"],
        ecdsa_public_key=data["ecdsa_public_key"],
        expiry=expiry,
    )

    print(f"[AUTH] ✓ Device {data['device_id']} authenticated. "
          f"Session expires: {expiry}")

    return jsonify({
        "session_token":    session_token,
        "expiry":           expiry,
        "kyber_public_key": base64.b64encode(get_gateway_kyber_public()).decode(),
    })


# ── HTTP packet endpoint (fallback) ───────────────────────────────────────────

@app.route("/packet", methods=["POST"])
def receive_packet():
    try:
        packet    = request.get_json(force=True)
        packet_id, status, reason = _process_packet(packet)
        return jsonify({"packet_id": packet_id, "status": status, "reason": reason})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    import sqlite3
    DB = "iomt_web.db"
    c2 = sqlite3.connect(DB).cursor()

    def _q(sql):
        return c2.execute(sql).fetchone()[0] or 0

    total   = _q("SELECT COUNT(*) FROM packets")
    valid   = _q("SELECT COUNT(*) FROM packets WHERE status='VALID'")
    alerts  = _q("SELECT COUNT(*) FROM alerts")
    invalid = total - valid
    dr      = round((alerts / invalid * 100) if invalid > 0 else 100.0, 1)

    timings = {}
    for f in ["hmac_ms", "hash_ms", "ecdsa_ms", "kyber_ms",
              "aes_ms", "encrypt_ms", "total_ms", "latency_ms"]:
        r = c2.execute(
            f"SELECT AVG({f}), MIN({f}), MAX({f}) FROM packets WHERE {f}>0"
        ).fetchone()
        timings[f] = {
            "avg": round(r[0] or 0, 3),
            "min": round(r[1] or 0, 3),
            "max": round(r[2] or 0, 3),
        }

    rows = c2.execute(
        """SELECT timestamp, total_ms, encrypt_ms, latency_ms, kyber_ms, aes_ms
           FROM packets WHERE status='VALID' ORDER BY id DESC LIMIT 30"""
    ).fetchall()
    history = [
        {"timestamp": r[0], "total_ms": r[1], "encrypt_ms": r[2],
         "latency_ms": r[3], "kyber_ms": r[4], "aes_ms": r[5]}
        for r in reversed(rows)
    ]

    metrics = {
        "total": total, "valid": valid, "invalid": invalid,
        "alerts": alerts, "detection_rate": dr,
        "timings": timings, "history": history,
    }

    return render_template("dashboard.html",
                           packets=get_all_packets(),
                           stats=get_stats(),
                           metrics=metrics)


@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html",
                           alerts=get_all_alerts(),
                           stats=get_stats())


@app.route("/devices")
def devices():
    return render_template("devices.html",
                           devices=get_all_devices(),
                           stats=get_stats())


# ── Device management ──────────────────────────────────────────────────────────

@app.route("/device/suspend", methods=["POST"])
def suspend_device():
    did = request.form.get("device_id", "")
    set_device_status(did, "SUSPENDED", "Manually suspended via dashboard")
    return redirect(url_for("devices"))


@app.route("/device/unblock", methods=["POST"])
def unblock_device():
    did = request.form.get("device_id", "")
    set_device_status(did, "ACTIVE", "Reactivated via dashboard")
    return redirect(url_for("devices"))


@app.route("/api/metrics")
def api_metrics():
    return jsonify(get_metrics())


@app.route("/reset", methods=["POST"])
def reset():
    clear_all()
    seen_nonces.clear()
    _auth_nonces.clear()
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  IoMT Gateway  —  PC 2")
    print(f"  Dashboard : http://0.0.0.0:5000/")
    print(f"  Auth      : POST http://0.0.0.0:5000/auth")
    print(f"  MQTT      : '{MQTT_TOPIC}' via {MQTT_BROKER}:{MQTT_PORT}")
    print("=" * 55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)