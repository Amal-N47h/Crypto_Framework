import hashlib
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Optional

DB_NAME = "secure_iomt.db"
DB_PATH = Path(__file__).with_name(DB_NAME)

# Allow this module to import the sibling crypto_AmalNath package when db.py
# is run directly from the crypto_fuadharis folder.
ISSUE_DIR = Path(__file__).resolve().parents[1]
if str(ISSUE_DIR) not in sys.path:
    sys.path.insert(0, str(ISSUE_DIR))

from crypto_AmalNath.hybrid_encrypt import build_packet as build_hybrid_packet


def _connect():
    return sqlite3.connect(DB_PATH)


def _to_bytes(value: Any, field_name: str, allow_none: bool = False) -> Optional[bytes]:
    if value is None:
        if allow_none:
            return None
        raise ValueError(f"{field_name} is required")

    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")

    export_key = getattr(value, "export_key", None)
    if callable(export_key):
        return _to_bytes(export_key(format="PEM"), field_name)

    public_bytes = getattr(value, "public_bytes", None)
    if callable(public_bytes):
        try:
            from cryptography.hazmat.primitives import serialization
        except ImportError as exc:
            raise TypeError(
                f"{field_name} key object requires cryptography to serialize"
            ) from exc

        return public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    raise TypeError(f"{field_name} must be bytes, str, or a serializable key object")


def generate_hash(data: Any) -> str:
    return hashlib.sha256(_to_bytes(data, "data")).hexdigest()


def init_db():
    conn = _connect()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS secure_sensor_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        iv BLOB NOT NULL,
        encrypted_data BLOB NOT NULL,
        ephemeral_public_key BLOB,
        hash TEXT NOT NULL
    )
    """)

    cursor.execute("PRAGMA table_info(secure_sensor_data)")
    columns = {row[1] for row in cursor.fetchall()}
    if "ephemeral_public_key" not in columns:
        cursor.execute(
            "ALTER TABLE secure_sensor_data ADD COLUMN ephemeral_public_key BLOB"
        )

    # Indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_id ON secure_sensor_data(device_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON secure_sensor_data(timestamp)")

    conn.commit()
    conn.close()


def insert_record(
    device_id: str,
    iv: Any,
    encrypted_data: Any,
    ephemeral_public_key: Any = None,
) -> int:
    init_db()

    iv_bytes = _to_bytes(iv if iv is not None else b"", "iv")
    encrypted_bytes = _to_bytes(encrypted_data, "encrypted_data")
    public_key_bytes = _to_bytes(
        ephemeral_public_key,
        "ephemeral_public_key",
        allow_none=True,
    )
    data_hash = generate_hash(encrypted_bytes)

    conn = _connect()
    cursor = conn.cursor()

    timestamp = int(time.time())

    cursor.execute("""
    INSERT INTO secure_sensor_data (
        device_id,
        timestamp,
        iv,
        encrypted_data,
        ephemeral_public_key,
        hash
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        device_id,
        timestamp,
        iv_bytes,
        encrypted_bytes,
        public_key_bytes,
        data_hash,
    ))

    record_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return record_id


def insert_hybrid_packet(
    device_id: str,
    packet: Mapping[str, Any],
    iv: Any = b"",
) -> int:
    if "encrypted_data" not in packet:
        raise ValueError("Hybrid packet is missing encrypted_data")
    if "ephemeral_public_key" not in packet:
        raise ValueError("Hybrid packet is missing ephemeral_public_key")

    return insert_record(
        device_id=device_id,
        iv=packet.get("iv", iv),
        encrypted_data=packet["encrypted_data"],
        ephemeral_public_key=packet["ephemeral_public_key"],
    )


def read_and_verify(record_id: int):
    init_db()

    conn = _connect()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT device_id, timestamp, iv, encrypted_data, ephemeral_public_key, hash
    FROM secure_sensor_data
    WHERE id = ?
    """, (record_id,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        print("Record not found")
        return None

    device_id, timestamp, iv, encrypted_data, ephemeral_public_key, stored_hash = row

    recalculated_hash = generate_hash(encrypted_data)

    if recalculated_hash != stored_hash:
        print("⚠️ TAMPERING DETECTED!")
        return None

    print("✅ Data integrity verified")

    packet = build_hybrid_packet(encrypted_data, ephemeral_public_key)
    packet.update({
        "device_id": device_id,
        "timestamp": timestamp,
        "iv": iv,
        "hash": stored_hash,
    })

    return packet


def get_records_by_device(device_id: str):
    init_db()

    conn = _connect()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, timestamp FROM secure_sensor_data
    WHERE device_id = ?
    """, (device_id,))

    results = cursor.fetchall()
    conn.close()
    return results


if __name__ == "__main__":
    init_db()

    demo_packet = build_hybrid_packet(
        encrypted_data=b"encrypted_sample_data",
        ephemeral_public_key=b"demo_ephemeral_public_key",
    )
    inserted_id = insert_hybrid_packet(
        device_id="device_001",
        packet=demo_packet,
        iv=b'1234567890123456',
    )

    read_and_verify(inserted_id)
