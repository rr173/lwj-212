import json
from app.database import get_db
from app.models import FieldDef
from app.utils import validate_hex, hex_to_bytes, shannon_entropy

DEMO_TEMPLATE_NAME = "Demo: FEED Protocol"

DEMO_TEMPLATE_FIELDS = [
    FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="uint16_be"),
    FieldDef(name="version", length_rule="fixed", length_value=1, data_type="uint8"),
    FieldDef(name="msg_type", length_rule="fixed", length_value=1, data_type="uint8"),
    FieldDef(name="payload_len", length_rule="fixed", length_value=2, data_type="uint16_be"),
    FieldDef(name="payload", length_rule="ref", length_ref_field="payload_len", data_type="bytes"),
    FieldDef(name="crc16", length_rule="fixed", length_value=2, data_type="uint16_be"),
]

DEMO_SAMPLES = [
    {
        "name": "Sensor Data - Temperature",
        "hex_data": "feed010100041020a1b2c9a3",
        "note": "msg_type=0x01 (sensor), 4-byte payload with temperature reading",
    },
    {
        "name": "Sensor Data - Humidity",
        "hex_data": "feed010100081020304050607080c3d4",
        "note": "msg_type=0x01 (sensor), 8-byte payload with humidity reading",
    },
    {
        "name": "Sensor Data - Short Payload",
        "hex_data": "feed010100021020e5f6",
        "note": "msg_type=0x01 (sensor), 2-byte payload",
    },
    {
        "name": "Command - Reset",
        "hex_data": "feed01020003aabbccddee",
        "note": "msg_type=0x02 (command), 3-byte payload with reset instruction",
    },
    {
        "name": "Command - Config",
        "hex_data": "feed01020006aabbccddeeff7738",
        "note": "msg_type=0x02 (command), 6-byte payload with configuration data",
    },
    {
        "name": "Truncated - Missing CRC",
        "hex_data": "feed010100041020",
        "note": "INTENTIONALLY TRUNCATED - payload_len says 4 bytes but only 2 present and no CRC, demonstrates parse_error",
    },
]


async def seed_if_empty():
    db = await get_db()
    try:
        rows = await db.execute_fetchall("SELECT id FROM templates WHERE name = ?", (DEMO_TEMPLATE_NAME,))
        if rows:
            return

        fields_json = json.dumps([f.model_dump() for f in DEMO_TEMPLATE_FIELDS])
        description = "2-byte magic 0xFEED + 1-byte version + 1-byte msg_type + 2-byte payload_len (BE) + variable payload + 2-byte CRC16"
        cursor = await db.execute(
            "INSERT INTO templates (name, description, fields_json) VALUES (?, ?, ?)",
            (DEMO_TEMPLATE_NAME, description, fields_json),
        )
        template_id = cursor.lastrowid
        await db.execute(
            """
            INSERT INTO template_versions (template_id, version, name, description, fields_json)
            VALUES (?, 1, ?, ?, ?)
            """,
            (template_id, DEMO_TEMPLATE_NAME, description, fields_json),
        )

        for sample in DEMO_SAMPLES:
            cleaned = validate_hex(sample["hex_data"])
            data = hex_to_bytes(cleaned)
            byte_length = len(data)
            entropy = shannon_entropy(data)
            await db.execute(
                "INSERT INTO samples (name, hex_data, byte_length, entropy, note) VALUES (?, ?, ?, ?, ?)",
                (sample["name"], cleaned, byte_length, entropy, sample["note"]),
            )

        await db.commit()
    finally:
        await db.close()
