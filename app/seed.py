import json
import hashlib
import hmac
import time
from app.database import get_db
from app.models import FieldDef
from app.utils import validate_hex, hex_to_bytes, shannon_entropy, bytes_to_hex
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

        await _seed_firmware_demo(db)
        await _seed_ota_demo(db)
        await _seed_iot_device_alerts_demo(db)
        await _seed_config_template_demo(db)
    finally:
        await db.close()


def _sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _generate_esp32_firmware_v10() -> bytes:
    data = bytearray(256)
    for i in range(64):
        data[i] = 0xB0 + (i % 16)
    for i in range(64, 160):
        data[i] = 0x10 + ((i - 64) % 32)
    for i in range(160, 208):
        data[i] = 0xC0 + ((i - 160) % 16)
    for i in range(208, 256):
        data[i] = 0xFF
    return bytes(data)


def _generate_esp32_firmware_v11() -> bytes:
    data = bytearray(_generate_esp32_firmware_v10())
    data[165] = 0xAA
    data[166] = 0xBB
    data[170] = 0xCC
    data[180] = 0xDD
    data[190] = 0xEE
    return bytes(data)


def _generate_esp32_firmware_v20() -> bytes:
    data = bytearray(_generate_esp32_firmware_v10())
    for i in range(0, 64):
        data[i] = 0xD0 + (i % 16)
    for i in range(64, 160):
        data[i] = 0x20 + ((i - 64) % 32)
    return bytes(data)


DEMO_DEVICE_MODEL = "ESP32-DevKit"
PRESET_SIGNING_KEY_HEX = "0123456789abcdef"
PRESET_KEY_ID = "esp32-prod-key-2024"


def _compute_hmac_sha256(data: bytes, key_hex: str) -> str:
    key = bytes.fromhex(key_hex)
    return hmac.new(key, data, hashlib.sha256).hexdigest()


DEMO_FIRMWARE_SEGMENTS = [
    {"name": "bootloader", "start": 0, "end": 64, "type": "bootloader"},
    {"name": "kernel", "start": 64, "end": 160, "type": "kernel"},
    {"name": "config", "start": 160, "end": 208, "type": "config"},
    {"name": "padding", "start": 208, "end": 256, "type": "padding"},
]
DEMO_FIRMWARE_VERSIONS = [
    ("v1.0", "ESP32 Firmware v1.0", _generate_esp32_firmware_v10),
    ("v1.1", "ESP32 Firmware v1.1", _generate_esp32_firmware_v11),
    ("v2.0", "ESP32 Firmware v2.0", _generate_esp32_firmware_v20),
]


async def _seed_firmware_demo(db):
    rows = await db.execute_fetchall(
        "SELECT id FROM firmwares WHERE device_model = ?", (DEMO_DEVICE_MODEL,)
    )
    if rows:
        return

    firmware_ids = {}
    firmware_data = {}
    for version, name, gen_fn in DEMO_FIRMWARE_VERSIONS:
        data = gen_fn()
        hex_data = bytes_to_hex(data)
        byte_length = len(data)
        sha256 = _sha256_hash(data)
        entropy = shannon_entropy(data)

        cursor = await db.execute(
            """
            INSERT INTO firmwares (name, version, device_model, hex_data, byte_length, sha256_hash, entropy)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (name, version, DEMO_DEVICE_MODEL, hex_data, byte_length, sha256, entropy),
        )
        firmware_id = cursor.lastrowid
        firmware_ids[version] = firmware_id
        firmware_data[version] = data

        for seg in DEMO_FIRMWARE_SEGMENTS:
            await db.execute(
                """
                INSERT INTO firmware_segments (firmware_id, name, start_offset, end_offset, segment_type)
                VALUES (?, ?, ?, ?, ?)
                """,
                (firmware_id, seg["name"], seg["start"], seg["end"], seg["type"]),
            )

    for version in ["v1.0", "v1.1"]:
        fid = firmware_ids[version]
        data = firmware_data[version]
        sig_hex = _compute_hmac_sha256(data, PRESET_SIGNING_KEY_HEX)
        await db.execute(
            """
            INSERT INTO firmware_signatures (firmware_id, algorithm, signature_hex, key_id)
            VALUES (?, 'hmac-sha256', ?, ?)
            """,
            (fid, sig_hex, PRESET_KEY_ID),
        )

    await db.commit()


OTA_PRESET_DEVICES = [
    {"device_sn": "ESP32-PROD-001", "device_model": "ESP32-DevKit", "firmware_version": "v1.0", "group_tag": "prod", "online_status": "online"},
    {"device_sn": "ESP32-PROD-002", "device_model": "ESP32-DevKit", "firmware_version": "v1.0", "group_tag": "prod", "online_status": "online"},
    {"device_sn": "ESP32-PROD-003", "device_model": "ESP32-DevKit", "firmware_version": "v1.0", "group_tag": "prod", "online_status": "online"},
    {"device_sn": "ESP32-PROD-004", "device_model": "ESP32-DevKit", "firmware_version": "v1.0", "group_tag": "prod", "online_status": "online"},
    {"device_sn": "ESP32-PROD-005", "device_model": "ESP32-DevKit", "firmware_version": "v1.0", "group_tag": "prod", "online_status": "online"},
    {"device_sn": "ESP32-PROD-006", "device_model": "ESP32-DevKit", "firmware_version": "v1.1", "group_tag": "prod", "online_status": "online"},
    {"device_sn": "ESP32-PROD-007", "device_model": "ESP32-DevKit", "firmware_version": "v1.1", "group_tag": "prod", "online_status": "online"},
    {"device_sn": "ESP32-PROD-008", "device_model": "ESP32-DevKit", "firmware_version": "v1.1", "group_tag": "prod", "online_status": "online"},
    {"device_sn": "ESP32-TEST-001", "device_model": "ESP32-DevKit", "firmware_version": "v1.0", "group_tag": "test", "online_status": "online"},
    {"device_sn": "ESP32-TEST-002", "device_model": "ESP32-DevKit", "firmware_version": "v1.0", "group_tag": "test", "online_status": "offline"},
]


async def _seed_ota_demo(db):
    existing = await db.execute_fetchall("SELECT id FROM ota_devices LIMIT 1")
    if existing:
        return

    device_ids = []
    for dev in OTA_PRESET_DEVICES:
        cursor = await db.execute(
            "INSERT INTO ota_devices (device_sn, device_model, firmware_version, group_tag, online_status) "
            "VALUES (?, ?, ?, ?, ?)",
            (dev["device_sn"], dev["device_model"], dev["firmware_version"],
             dev["group_tag"], dev["online_status"]),
        )
        device_ids.append(cursor.lastrowid)

    eligible_ids = device_ids[:5]

    cursor = await db.execute(
        "INSERT INTO ota_plans (name, target_version, device_model, filter_group, filter_version_min, "
        "filter_version_max, strategy, batch_size, batch_interval, failure_threshold, rollback_version, "
        "status, total_devices) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("ESP32-DevKit v2.0 Upgrade", "v2.0", "ESP32-DevKit", "prod", "v1.0", "v1.0",
         "batch", 2, 5, 0.5, "v1.0", "pending", len(eligible_ids)),
    )
    plan_id = cursor.lastrowid

    for did in eligible_ids:
        await db.execute(
            "INSERT INTO ota_plan_devices (plan_id, device_id, target_version) VALUES (?, ?, ?)",
            (plan_id, did, "v2.0"),
        )

    await db.commit()


IOT_V1_MODEL = "ESP32-DevKit v1.0"
IOT_V2_MODEL = "ESP32-DevKit v2.0"


def _generate_iot_devices():
    devices = []
    for i in range(1, 11):
        devices.append({
            "device_sn": f"IOT-V1-{i:03d}",
            "device_model": IOT_V1_MODEL,
            "firmware_version": "v1.0",
            "online_status": "online",
        })
    for i in range(1, 11):
        devices.append({
            "device_sn": f"IOT-V2-{i:03d}",
            "device_model": IOT_V2_MODEL,
            "firmware_version": "v2.0",
            "online_status": "online",
        })
    return devices


def _generate_iot_alerts(now_ts: int):
    alerts = []
    two_hours_ago = now_ts - 2 * 3600
    thirty_min_ago = now_ts - 30 * 60

    v1_devices = [f"IOT-V1-{i:03d}" for i in range(1, 11)]
    v2_devices = [f"IOT-V2-{i:03d}" for i in range(1, 11)]

    # 3 devices have sensor_error + comm_timeout + memory_overflow within 10 minutes window -> correlation pattern
    corr_devices = v1_devices[6:9]
    corr_base_ts = two_hours_ago + 30 * 60
    for dev in corr_devices:
        alerts.append({
            "device_sn": dev,
            "alert_type": "sensor_error",
            "severity": "medium",
            "timestamp": corr_base_ts,
            "extra_info": "temperature sensor out of range",
        })
        alerts.append({
            "device_sn": dev,
            "alert_type": "comm_timeout",
            "severity": "medium",
            "timestamp": corr_base_ts + 60,
            "extra_info": "MQTT broker timeout 5s",
        })
        alerts.append({
            "device_sn": dev,
            "alert_type": "memory_overflow",
            "severity": "low",
            "timestamp": corr_base_ts + 120,
            "extra_info": "heap usage 92%",
        })

    # 6 v1.0 devices report firmware_checksum_fail concentrated in last 30 min -> spread pattern (6/10=60% > 30%)
    spread_devices = v1_devices[:6]
    for dev_idx, dev in enumerate(spread_devices):
        for report_i in range(4):
            ts = thirty_min_ago + dev_idx * 30 + report_i * 60
            alerts.append({
                "device_sn": dev,
                "alert_type": "firmware_checksum_fail",
                "severity": "high",
                "timestamp": ts,
                "extra_info": f"CRC mismatch at sector {0x1000 + report_i * 0x1000:x}",
            })

    # Scattered alerts in 2-hour window to fill up to ~50
    # Some random memory_overflow on v2 devices
    v2_memory_devs = v2_devices[:3]
    for dev_idx, dev in enumerate(v2_memory_devs):
        for report_i in range(2):
            ts = two_hours_ago + dev_idx * 200 + report_i * 1800
            alerts.append({
                "device_sn": dev,
                "alert_type": "memory_overflow",
                "severity": "low",
                "timestamp": ts,
                "extra_info": f"heap {80 + report_i * 5}%",
            })

    # Some random sensor_error
    v1_sensor_devs = v1_devices[9:] + v2_devices[5:8]
    for dev_idx, dev in enumerate(v1_sensor_devs):
        for report_i in range(2):
            ts = two_hours_ago + 300 + dev_idx * 350 + report_i * 2400
            alerts.append({
                "device_sn": dev,
                "alert_type": "sensor_error",
                "severity": "low",
                "timestamp": ts,
                "extra_info": "ADC noise spike",
            })

    # A few comm_timeout
    v_comm_devs = v2_devices[8:] + v1_devices[:1]
    for dev_idx, dev in enumerate(v_comm_devs):
        for report_i in range(2):
            ts = two_hours_ago + 15 * 60 + dev_idx * 400 + report_i * 3000
            alerts.append({
                "device_sn": dev,
                "alert_type": "comm_timeout",
                "severity": "medium",
                "timestamp": ts,
                "extra_info": "packet loss > 10%",
            })

    alerts.sort(key=lambda a: a["timestamp"])
    if len(alerts) > 50:
        alerts = alerts[:50]
    return alerts


async def _seed_iot_device_alerts_demo(db):
    existing_devs = await db.execute_fetchall("SELECT id FROM iot_devices LIMIT 1")
    if existing_devs:
        return

    now_ts = int(time.time())
    iot_devices = _generate_iot_devices()
    for dev in iot_devices:
        await db.execute(
            "INSERT INTO iot_devices (device_sn, device_model, firmware_version, online_status) "
            "VALUES (?, ?, ?, ?)",
            (dev["device_sn"], dev["device_model"], dev["firmware_version"], dev["online_status"]),
        )

    iot_alerts = _generate_iot_alerts(now_ts)
    for alert in iot_alerts:
        dedup_key = f"{alert['device_sn']}|{alert['alert_type']}|{alert['timestamp']}"
        try:
            await db.execute(
                """
                INSERT INTO iot_alerts (device_sn, alert_type, severity, timestamp, extra_info, dedup_key)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["device_sn"],
                    alert["alert_type"],
                    alert["severity"],
                    alert["timestamp"],
                    alert["extra_info"],
                    dedup_key,
                ),
            )
        except Exception:
            pass

    await db.commit()


CFG_DEMO_TEMPLATE_NAME = "ESP32-DevKit"
CFG_DEMO_DEVICE_MODEL = "ESP32-DevKit"

CFG_DEMO_ITEMS = [
    {"key_name": "sample_rate", "value_type": "int", "default_value": "10", "constraint_min": 1, "constraint_max": 1000, "constraint_max_length": None},
    {"key_name": "report_interval", "value_type": "int", "default_value": "60", "constraint_min": 5, "constraint_max": 3600, "constraint_max_length": None},
    {"key_name": "temp_threshold", "value_type": "float", "default_value": "35.5", "constraint_min": -40, "constraint_max": 85, "constraint_max_length": None},
    {"key_name": "device_name", "value_type": "string", "default_value": "ESP32-Device", "constraint_min": None, "constraint_max": None, "constraint_max_length": 32},
    {"key_name": "debug_mode", "value_type": "bool", "default_value": "false", "constraint_min": None, "constraint_max": None, "constraint_max_length": None},
]

CFG_DEMO_DEVICES = [
    {"device_sn": "ESP32-CFG-001", "overrides": {}},
    {"device_sn": "ESP32-CFG-002", "overrides": {}},
    {"device_sn": "ESP32-CFG-003", "overrides": {"sample_rate": "20"}},
    {"device_sn": "ESP32-CFG-004", "overrides": {"sample_rate": "20"}},
    {"device_sn": "ESP32-CFG-005", "overrides": {}},
]


async def _seed_config_template_demo(db):
    existing = await db.execute_fetchall(
        "SELECT id FROM cfg_templates WHERE name = ?", (CFG_DEMO_TEMPLATE_NAME,)
    )
    if existing:
        return

    cursor = await db.execute(
        "INSERT INTO cfg_templates (name, device_model) VALUES (?, ?)",
        (CFG_DEMO_TEMPLATE_NAME, CFG_DEMO_DEVICE_MODEL),
    )
    template_id = cursor.lastrowid

    item_ids = {}
    for item in CFG_DEMO_ITEMS:
        cursor = await db.execute(
            "INSERT INTO cfg_template_items (template_id, key_name, value_type, default_value, constraint_min, constraint_max, constraint_max_length) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (template_id, item["key_name"], item["value_type"], item["default_value"],
             item["constraint_min"], item["constraint_max"], item["constraint_max_length"]),
        )
        item_ids[item["key_name"]] = cursor.lastrowid

    for dev in CFG_DEMO_DEVICES:
        cursor = await db.execute(
            "INSERT INTO cfg_devices (device_sn, template_id) VALUES (?, ?)",
            (dev["device_sn"], template_id),
        )
        device_id = cursor.lastrowid

        for item in CFG_DEMO_ITEMS:
            value = dev["overrides"].get(item["key_name"], item["default_value"])
            await db.execute(
                "INSERT INTO cfg_device_values (device_id, item_id, value) VALUES (?, ?, ?)",
                (device_id, item_ids[item["key_name"]], value),
            )

    await db.commit()
