# IoMT Crypto Project


## Project Structure

```text
Crypto_Project/
│
├── gateway/
│   ├── app.py
│   ├── auth.py
│   ├── crypto_engine.py
│   ├── database.py
│   ├── attack_simulator.py
│   ├── crypto_engine_device_sim.py
│   ├── templates/
│   └── *.db
│
└── device/
    ├── app.py
    ├── auth.py
    ├── crypto_engine_device.py
    └── templates/
```

---

# Requirements

## Python

Use Python 3.10+

Check version:

```bash
python --version
```

---

# Install Dependencies

Install dependencies separately for both gateway and device environments.

```bash
pip install flask requests paho-mqtt cryptography kyber-py
```

---

# Install MQTT Broker

This project uses MQTT for communication.

## Ubuntu / Debian

```bash
sudo apt update
sudo apt install mosquitto mosquitto-clients
```

Start broker:

```bash
sudo systemctl start mosquitto
sudo systemctl enable mosquitto
```

Check status:

```bash
sudo systemctl status mosquitto
```

Default broker:

```text
127.0.0.1:1883
```

---

# Running the Project

You need 2 terminals.

---

# 1. Start Gateway

Open terminal:

```bash
cd Crypto_Project/gateway
python app.py
```

Gateway runs at:

```text
http://127.0.0.1:5000
```

Dashboard:

```text
http://127.0.0.1:5000/dashboard
```

---

# 2. Start Device

Open second terminal:

```bash
cd Crypto_Project/device
python app.py
```

Device UI:

```text
http://127.0.0.1:5001
```

---

# Workflow

1. Device generates ECDSA keypair
2. Device authenticates with gateway
3. Gateway returns:
   - session token
   - Kyber public key
4. Device sends signed MQTT packets
5. Gateway verifies:
   - signature
   - nonce
   - session token
6. Packets stored in SQLite database

---

# MQTT Configuration

Default settings:

```python
MQTT_BROKER = "127.0.0.1"
MQTT_PORT   = 1883
MQTT_TOPIC  = "iomt/packets"
```

You can override using environment variables.

Example:

```bash
export MQTT_BROKER=192.168.1.10
```

---

# Database Files

Gateway creates:

- `iomt_web.db`
- `device_registry.db`

These store:

- device registry
- packets
- alerts
- session tokens
- metrics

---

# Features

## Gateway

- Device authentication
- Session management
- Packet verification
- Alert logging
- Device status control
- Metrics dashboard

## Device

- Local ECDSA key generation
- Secure authentication
- MQTT packet publishing
- Automatic re-authentication

