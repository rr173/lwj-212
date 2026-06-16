import json
from app.database import get_db
from app.models import FieldDef
from app.utils import validate_hex, hex_to_bytes, shannon_entropy
from app.parser import parse_message

DEMO_TEMPLATE_NAME = "Demo: FEED Protocol"
DEMO_SESSION_NAME = "Demo: FEED Protocol Conversation (8 frames)"

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

DEMO_SESSION_FRAMES = [
    {
        "hex_data": "feed010100040000001a1234",
        "direction": "request",
        "relative_timestamp_ms": 0,
        "description": "Req 1: Sensor Read Request (msg_type=0x01, temp=26)",
    },
    {
        "hex_data": "feed018100080000001a000004b25678",
        "direction": "response",
        "relative_timestamp_ms": 120,
        "description": "Resp 1: Sensor Read Response (msg_type=0x81, temp=26, humidity=1202)",
    },
    {
        "hex_data": "feed010200020100aabb",
        "direction": "request",
        "relative_timestamp_ms": 350,
        "description": "Req 2: Reset Command (msg_type=0x02, code=256)",
    },
    {
        "hex_data": "feed0182000100ccdd",
        "direction": "response",
        "relative_timestamp_ms": 520,
        "description": "Resp 2: Reset ACK (msg_type=0x82, status=0)",
    },
    {
        "hex_data": "feed0103000648656c6c6f00eeff",
        "direction": "request",
        "relative_timestamp_ms": 780,
        "description": "Req 3: Config Set (msg_type=0x03, payload='Hello')",
    },
    {
        "hex_data": "feed018300040000000199aa",
        "direction": "response",
        "relative_timestamp_ms": 1050,
        "description": "Resp 3: Config ACK (msg_type=0x83, result=1)",
    },
    {
        "hex_data": "feed01840004ffffffff0001",
        "direction": "response",
        "relative_timestamp_ms": 1500,
        "description": "Unsolicited: Event Push (msg_type=0x84, event_id=-1)",
    },
    {
        "hex_data": "feed010100040000001bbbcc",
        "direction": "request",
        "relative_timestamp_ms": 1900,
        "description": "Req 4: Unanswered Sensor Request (msg_type=0x01, temp=27)",
    },
]


async def seed_if_empty():
    db = await get_db()
    try:
        rows = await db.execute_fetchall("SELECT id FROM templates WHERE name = ?", (DEMO_TEMPLATE_NAME,))
        if rows:
            template_id = rows[0]["id"]
            fp_rows = await db.execute_fetchall(
                "SELECT id FROM fingerprints WHERE template_id = ? AND offset = 0 AND expected_hex = 'feed'",
                (template_id,),
            )
            if not fp_rows:
                await db.execute(
                    """
                    INSERT INTO fingerprints (template_id, offset, expected_hex, match_type, mask_hex)
                    VALUES (?, 0, 'feed', 'exact', NULL)
                    """,
                    (template_id,),
                )
        else:
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

            await db.execute(
                """
                INSERT INTO fingerprints (template_id, offset, expected_hex, match_type, mask_hex)
                VALUES (?, 0, 'feed', 'exact', NULL)
                """,
                (template_id,),
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

        sm_rows = await db.execute_fetchall(
            "SELECT id FROM state_machines WHERE template_id = ?", (template_id,)
        )
        if not sm_rows:
            sm_cur = await db.execute(
                """
                INSERT INTO state_machines (template_id, name, description)
                VALUES (?, ?, ?)
                """,
                (
                    template_id,
                    "Demo: FEED Protocol State Machine",
                    "Demonstrates a simple 3-state protocol lifecycle: idle -> active -> closed, triggered by msg_type field.",
                ),
            )
            state_machine_id = sm_cur.lastrowid

            idle_cur = await db.execute(
                "INSERT INTO sm_states (state_machine_id, name, state_type) VALUES (?, ?, 'initial')",
                (state_machine_id, "idle"),
            )
            idle_id = idle_cur.lastrowid

            active_cur = await db.execute(
                "INSERT INTO sm_states (state_machine_id, name, state_type) VALUES (?, ?, 'intermediate')",
                (state_machine_id, "active"),
            )
            active_id = active_cur.lastrowid

            closed_cur = await db.execute(
                "INSERT INTO sm_states (state_machine_id, name, state_type) VALUES (?, ?, 'terminal')",
                (state_machine_id, "closed"),
            )
            closed_id = closed_cur.lastrowid

            await db.execute(
                """
                INSERT INTO sm_transitions 
                (state_machine_id, from_state_id, to_state_id, trigger_field, trigger_value, direction_constraint)
                VALUES (?, ?, ?, 'msg_type', '1', 'both')
                """,
                (state_machine_id, idle_id, active_id),
            )

            await db.execute(
                """
                INSERT INTO sm_transitions 
                (state_machine_id, from_state_id, to_state_id, trigger_field, trigger_value, direction_constraint)
                VALUES (?, ?, ?, 'msg_type', '2', 'both')
                """,
                (state_machine_id, active_id, closed_id),
            )

        s_rows = await db.execute_fetchall(
            "SELECT id FROM sessions WHERE name = ?", (DEMO_SESSION_NAME,)
        )
        if s_rows:
            await db.commit()
            return

        v_rows = await db.execute_fetchall(
            "SELECT MAX(version) as max_version FROM template_versions WHERE template_id = ?",
            (template_id,),
        )
        latest_version = v_rows[0]["max_version"] or 1

        tv_rows = await db.execute_fetchall(
            "SELECT fields_json FROM template_versions WHERE template_id = ? AND version = ?",
            (template_id, latest_version),
        )
        template_fields = [FieldDef(**f) for f in json.loads(tv_rows[0]["fields_json"])]

        cursor = await db.execute(
            "INSERT INTO sessions (name, template_id, template_version, note) VALUES (?, ?, ?, ?)",
            (
                DEMO_SESSION_NAME,
                template_id,
                latest_version,
                "Demonstrates request-response pairing: 3 complete pairs + 1 unanswered request + 1 unsolicited push.",
            ),
        )
        session_id = cursor.lastrowid

        for idx, frame in enumerate(DEMO_SESSION_FRAMES):
            seq = idx + 1
            cleaned = validate_hex(frame["hex_data"])
            data = hex_to_bytes(cleaned)
            byte_length = len(data)
            direction = frame["direction"]
            ts = frame["relative_timestamp_ms"]

            parse_result = parse_message(
                data,
                template_fields,
                template_id,
                0,
                latest_version,
            )
            parse_result.sample_id = 0
            parse_result_json = json.dumps(parse_result.model_dump())

            await db.execute(
                """
                INSERT INTO session_frames (session_id, seq, hex_data, byte_length, direction, relative_timestamp_ms, parse_result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    seq,
                    cleaned,
                    byte_length,
                    direction,
                    ts,
                    parse_result_json,
                ),
            )

        await db.commit()
    finally:
        await db.close()
