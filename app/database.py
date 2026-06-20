import aiosqlite
import os
import json

DB_PATH = os.environ.get("DB_PATH", "/data/protocol_workbench.db")

CREATE_SAMPLES_TABLE = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    hex_data TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    entropy REAL NOT NULL,
    note TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

CREATE_TEMPLATES_TABLE = """
CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    fields_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

CREATE_TEMPLATE_VERSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS template_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER NOT NULL,
    version INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    fields_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(template_id, version),
    FOREIGN KEY (template_id) REFERENCES templates (id) ON DELETE CASCADE
)
"""

CREATE_SESSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    template_id INTEGER NOT NULL,
    template_version INTEGER NOT NULL,
    note TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES templates (id) ON DELETE CASCADE,
    FOREIGN KEY (template_id, template_version) REFERENCES template_versions (template_id, version) ON DELETE CASCADE
)
"""

CREATE_SESSION_FRAMES_TABLE = """
CREATE TABLE IF NOT EXISTS session_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    hex_data TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('request', 'response')),
    relative_timestamp_ms INTEGER NOT NULL,
    parse_result_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(session_id, seq),
    FOREIGN KEY (session_id) REFERENCES sessions (id) ON DELETE CASCADE
)
"""

CREATE_SESSION_FRAMES_TS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_session_frames_ts ON session_frames (session_id, relative_timestamp_ms)
"""

CREATE_SESSION_FRAMES_DIRECTION_INDEX = """
CREATE INDEX IF NOT EXISTS idx_session_frames_direction ON session_frames (session_id, direction)
"""

CREATE_FINGERPRINTS_TABLE = """
CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    expected_hex TEXT NOT NULL,
    match_type TEXT NOT NULL CHECK(match_type IN ('exact', 'mask')),
    mask_hex TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES templates (id) ON DELETE CASCADE
)
"""

CREATE_FINGERPRINTS_TEMPLATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_fingerprints_template ON fingerprints (template_id)
"""

CREATE_STATE_MACHINES_TABLE = """
CREATE TABLE IF NOT EXISTS state_machines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES templates (id) ON DELETE CASCADE,
    UNIQUE(template_id)
)
"""

CREATE_SM_STATES_TABLE = """
CREATE TABLE IF NOT EXISTS sm_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state_machine_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    state_type TEXT NOT NULL CHECK(state_type IN ('initial', 'intermediate', 'terminal')),
    FOREIGN KEY (state_machine_id) REFERENCES state_machines (id) ON DELETE CASCADE,
    UNIQUE(state_machine_id, name)
)
"""

CREATE_SM_STATES_SM_INDEX = """
CREATE INDEX IF NOT EXISTS idx_sm_states_sm ON sm_states (state_machine_id)
"""

CREATE_SM_TRANSITIONS_TABLE = """
CREATE TABLE IF NOT EXISTS sm_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state_machine_id INTEGER NOT NULL,
    from_state_id INTEGER NOT NULL,
    to_state_id INTEGER NOT NULL,
    trigger_field TEXT NOT NULL,
    trigger_value TEXT NOT NULL,
    direction_constraint TEXT NOT NULL CHECK(direction_constraint IN ('request', 'response', 'both')),
    FOREIGN KEY (state_machine_id) REFERENCES state_machines (id) ON DELETE CASCADE,
    FOREIGN KEY (from_state_id) REFERENCES sm_states (id) ON DELETE CASCADE,
    FOREIGN KEY (to_state_id) REFERENCES sm_states (id) ON DELETE CASCADE
)
"""

CREATE_SM_TRANSITIONS_SM_INDEX = """
CREATE INDEX IF NOT EXISTS idx_sm_transitions_sm ON sm_transitions (state_machine_id)
"""

CREATE_SM_TRANSITIONS_FROM_INDEX = """
CREATE INDEX IF NOT EXISTS idx_sm_transitions_from ON sm_transitions (state_machine_id, from_state_id)
"""

CREATE_FRAGMENT_GROUPS_TABLE = """
CREATE TABLE IF NOT EXISTS fragment_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    template_id INTEGER NOT NULL,
    template_version INTEGER NOT NULL DEFAULT 1,
    reassembly_strategy TEXT NOT NULL CHECK(reassembly_strategy IN ('sequential', 'length_prefix')),
    note TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES templates (id) ON DELETE CASCADE
)
"""

CREATE_FRAGMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS fragments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    seq_num INTEGER NOT NULL,
    sample_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(group_id, seq_num),
    FOREIGN KEY (group_id) REFERENCES fragment_groups (id) ON DELETE CASCADE,
    FOREIGN KEY (sample_id) REFERENCES samples (id) ON DELETE CASCADE
)
"""

CREATE_FRAGMENTS_GROUP_INDEX = """
CREATE INDEX IF NOT EXISTS idx_fragments_group ON fragments (group_id, seq_num)
"""

CREATE_ALERT_RULES_TABLE = """
CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('info', 'warning', 'critical')),
    expression_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES templates (id) ON DELETE CASCADE,
    UNIQUE(template_id, name)
)
"""

CREATE_ALERT_RULES_TEMPLATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_alert_rules_template ON alert_rules (template_id)
"""

CREATE_FIRMWARES_TABLE = """
CREATE TABLE IF NOT EXISTS firmwares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    device_model TEXT,
    hex_data TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    sha256_hash TEXT NOT NULL,
    entropy REAL NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(device_model, version)
)
"""

CREATE_FIRMWARES_DEVICE_MODEL_INDEX = """
CREATE INDEX IF NOT EXISTS idx_firmwares_device_model ON firmwares (device_model)
"""

CREATE_FIRMWARES_NAME_INDEX = """
CREATE INDEX IF NOT EXISTS idx_firmwares_name ON firmwares (name)
"""

CREATE_FIRMWARE_SEGMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS firmware_segments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firmware_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    start_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    segment_type TEXT NOT NULL CHECK(segment_type IN ('bootloader', 'kernel', 'filesystem', 'config', 'padding')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (firmware_id) REFERENCES firmwares (id) ON DELETE CASCADE
)
"""

CREATE_FIRMWARE_SEGMENTS_FIRMWARE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_firmware_segments_firmware ON firmware_segments (firmware_id)
"""

CREATE_FIRMWARE_SIGNATURES_TABLE = """
CREATE TABLE IF NOT EXISTS firmware_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firmware_id INTEGER NOT NULL,
    algorithm TEXT NOT NULL CHECK(algorithm IN ('hmac-sha256', 'ed25519')),
    signature_hex TEXT NOT NULL CHECK(LENGTH(signature_hex) <= 256),
    key_id TEXT NOT NULL CHECK(LENGTH(key_id) <= 64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(firmware_id),
    FOREIGN KEY (firmware_id) REFERENCES firmwares (id) ON DELETE CASCADE
)
"""

CREATE_FIRMWARE_SIGNATURES_FIRMWARE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_firmware_signatures_firmware ON firmware_signatures (firmware_id)
"""

CREATE_OTA_DEVICES_TABLE = """
CREATE TABLE IF NOT EXISTS ota_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_sn TEXT NOT NULL UNIQUE,
    device_model TEXT NOT NULL,
    firmware_version TEXT NOT NULL,
    group_tag TEXT NOT NULL DEFAULT '',
    online_status TEXT NOT NULL CHECK(online_status IN ('online', 'offline')) DEFAULT 'online',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

CREATE_OTA_DEVICES_SN_INDEX = """
CREATE INDEX IF NOT EXISTS idx_ota_devices_sn ON ota_devices (device_sn)
"""

CREATE_OTA_DEVICES_MODEL_INDEX = """
CREATE INDEX IF NOT EXISTS idx_ota_devices_model ON ota_devices (device_model)
"""

CREATE_OTA_DEVICES_GROUP_INDEX = """
CREATE INDEX IF NOT EXISTS idx_ota_devices_group ON ota_devices (group_tag)
"""

CREATE_OTA_PLANS_TABLE = """
CREATE TABLE IF NOT EXISTS ota_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_version TEXT NOT NULL,
    device_model TEXT NOT NULL,
    filter_group TEXT DEFAULT '',
    filter_version_min TEXT DEFAULT '',
    filter_version_max TEXT DEFAULT '',
    strategy TEXT NOT NULL CHECK(strategy IN ('full', 'batch')),
    batch_size INTEGER DEFAULT 0,
    batch_interval INTEGER DEFAULT 0,
    failure_threshold REAL NOT NULL,
    rollback_version TEXT DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('pending', 'running', 'paused', 'paused_failure_rate', 'completed')) DEFAULT 'pending',
    current_batch INTEGER DEFAULT 0,
    total_devices INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

CREATE_OTA_PLAN_DEVICES_TABLE = """
CREATE TABLE IF NOT EXISTS ota_plan_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'upgrading', 'success', 'failed', 'skipped_offline', 'pending_rollback')) DEFAULT 'pending',
    target_version TEXT NOT NULL,
    failure_reason TEXT DEFAULT '',
    batch_number INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plan_id) REFERENCES ota_plans (id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES ota_devices (id) ON DELETE CASCADE,
    UNIQUE(plan_id, device_id)
)
"""

CREATE_OTA_PLAN_DEVICES_PLAN_INDEX = """
CREATE INDEX IF NOT EXISTS idx_ota_plan_devices_plan ON ota_plan_devices (plan_id)
"""

CREATE_OTA_PLAN_DEVICES_DEVICE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_ota_plan_devices_device ON ota_plan_devices (device_id)
"""

CREATE_OTA_PLAN_DEVICES_STATUS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_ota_plan_devices_status ON ota_plan_devices (plan_id, status)
"""

CREATE_IOT_DEVICES_TABLE = """
CREATE TABLE IF NOT EXISTS iot_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_sn TEXT NOT NULL UNIQUE,
    device_model TEXT NOT NULL,
    firmware_version TEXT NOT NULL DEFAULT '',
    online_status TEXT NOT NULL CHECK(online_status IN ('online', 'offline')) DEFAULT 'online',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

CREATE_IOT_DEVICES_SN_INDEX = """
CREATE INDEX IF NOT EXISTS idx_iot_devices_sn ON iot_devices (device_sn)
"""

CREATE_IOT_DEVICES_MODEL_INDEX = """
CREATE INDEX IF NOT EXISTS idx_iot_devices_model ON iot_devices (device_model)
"""

CREATE_IOT_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS iot_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_sn TEXT NOT NULL,
    alert_type TEXT NOT NULL CHECK(alert_type IN ('sensor_error', 'comm_timeout', 'firmware_checksum_fail', 'memory_overflow', 'reboot_loop')),
    severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    timestamp INTEGER NOT NULL,
    extra_info TEXT DEFAULT '',
    dedup_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(dedup_key)
)
"""

CREATE_IOT_ALERTS_DEVICE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_iot_alerts_device ON iot_alerts (device_sn)
"""

CREATE_IOT_ALERTS_TYPE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_iot_alerts_type ON iot_alerts (alert_type)
"""

CREATE_IOT_ALERTS_SEVERITY_INDEX = """
CREATE INDEX IF NOT EXISTS idx_iot_alerts_severity ON iot_alerts (severity)
"""

CREATE_IOT_ALERTS_TS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_iot_alerts_ts ON iot_alerts (timestamp)
"""

CREATE_CFG_TEMPLATES_TABLE = """
CREATE TABLE IF NOT EXISTS cfg_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    device_model TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

CREATE_CFG_TEMPLATES_MODEL_INDEX = """
CREATE INDEX IF NOT EXISTS idx_cfg_templates_model ON cfg_templates (device_model)
"""

CREATE_CFG_TEMPLATE_ITEMS_TABLE = """
CREATE TABLE IF NOT EXISTS cfg_template_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER NOT NULL,
    key_name TEXT NOT NULL,
    value_type TEXT NOT NULL CHECK(value_type IN ('int', 'float', 'string', 'bool')),
    default_value TEXT NOT NULL,
    constraint_min REAL,
    constraint_max REAL,
    constraint_max_length INTEGER,
    FOREIGN KEY (template_id) REFERENCES cfg_templates (id) ON DELETE CASCADE,
    UNIQUE(template_id, key_name)
)
"""

CREATE_CFG_TEMPLATE_ITEMS_TEMPLATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_cfg_template_items_template ON cfg_template_items (template_id)
"""

CREATE_CFG_DEVICES_TABLE = """
CREATE TABLE IF NOT EXISTS cfg_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_sn TEXT NOT NULL UNIQUE,
    template_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES cfg_templates (id) ON DELETE CASCADE
)
"""

CREATE_CFG_DEVICES_SN_INDEX = """
CREATE INDEX IF NOT EXISTS idx_cfg_devices_sn ON cfg_devices (device_sn)
"""

CREATE_CFG_DEVICES_TEMPLATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_cfg_devices_template ON cfg_devices (template_id)
"""

CREATE_CFG_DEVICE_VALUES_TABLE = """
CREATE TABLE IF NOT EXISTS cfg_device_values (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(device_id, item_id),
    FOREIGN KEY (device_id) REFERENCES cfg_devices (id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES cfg_template_items (id) ON DELETE CASCADE
)
"""

CREATE_CFG_DEVICE_VALUES_DEVICE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_cfg_device_values_device ON cfg_device_values (device_id)
"""

CREATE_CFG_CHANGE_HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS cfg_change_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    old_value TEXT NOT NULL,
    new_value TEXT NOT NULL,
    changed_by TEXT NOT NULL DEFAULT '',
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES cfg_devices (id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES cfg_template_items (id) ON DELETE CASCADE
)
"""

CREATE_CFG_CHANGE_HISTORY_DEVICE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_cfg_change_history_device ON cfg_change_history (device_id)
"""

CREATE_CFG_CHANGE_HISTORY_CHANGED_AT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_cfg_change_history_changed_at ON cfg_change_history (changed_at)
"""

CREATE_BASELINE_SNAPSHOTS_TABLE = """
CREATE TABLE IF NOT EXISTS baseline_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER NOT NULL,
    template_version INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    sample_count INTEGER NOT NULL,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    fields_stats_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES templates (id) ON DELETE CASCADE
)
"""

CREATE_BASELINE_SNAPSHOTS_TEMPLATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_baseline_snapshots_template ON baseline_snapshots (template_id, created_at DESC)
"""

CREATE_SEQUENCE_PATTERNS_TABLE = """
CREATE TABLE IF NOT EXISTS sequence_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    step_count INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

CREATE_SEQUENCE_PATTERN_STEPS_TABLE = """
CREATE TABLE IF NOT EXISTS sequence_pattern_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id INTEGER NOT NULL,
    step_index INTEGER NOT NULL,
    template_id INTEGER NOT NULL,
    template_version INTEGER NOT NULL,
    constraints_json TEXT NOT NULL,
    gap_type TEXT NOT NULL CHECK(gap_type IN ('adjacent', 'max_n', 'unlimited')),
    gap_max_n INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(pattern_id, step_index),
    FOREIGN KEY (pattern_id) REFERENCES sequence_patterns (id) ON DELETE CASCADE
)
"""

CREATE_SEQUENCE_PATTERN_STEPS_PATTERN_INDEX = """
CREATE INDEX IF NOT EXISTS idx_seq_pattern_steps_pattern ON sequence_pattern_steps (pattern_id, step_index)
"""

CREATE_SAMPLE_TAGS_TABLE = """
CREATE TABLE IF NOT EXISTS sample_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    pattern_id INTEGER,
    pattern_name TEXT,
    step_index INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sample_id) REFERENCES samples (id) ON DELETE CASCADE
)
"""

CREATE_SAMPLE_TAGS_SAMPLE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_sample_tags_sample ON sample_tags (sample_id)
"""

CREATE_SAMPLE_TAGS_TAG_INDEX = """
CREATE INDEX IF NOT EXISTS idx_sample_tags_tag ON sample_tags (tag)
"""


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys = ON")
    return db


async def migrate_templates_to_versions():
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM templates WHERE id NOT IN (SELECT DISTINCT template_id FROM template_versions)"
        )
        for row in rows:
            await db.execute(
                """
                INSERT INTO template_versions (template_id, version, name, description, fields_json, created_at)
                VALUES (?, 1, ?, ?, ?, ?)
                """,
                (row["id"], row["name"], row["description"], row["fields_json"], row["created_at"]),
            )
        await db.commit()
    finally:
        await db.close()


async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = await get_db()
    try:
        await db.execute(CREATE_SAMPLES_TABLE)
        await db.execute(CREATE_TEMPLATES_TABLE)
        await db.execute(CREATE_TEMPLATE_VERSIONS_TABLE)
        await db.execute(CREATE_SESSIONS_TABLE)
        await db.execute(CREATE_SESSION_FRAMES_TABLE)
        await db.execute(CREATE_SESSION_FRAMES_TS_INDEX)
        await db.execute(CREATE_SESSION_FRAMES_DIRECTION_INDEX)
        await db.execute(CREATE_FINGERPRINTS_TABLE)
        await db.execute(CREATE_FINGERPRINTS_TEMPLATE_INDEX)
        await db.execute(CREATE_STATE_MACHINES_TABLE)
        await db.execute(CREATE_SM_STATES_TABLE)
        await db.execute(CREATE_SM_STATES_SM_INDEX)
        await db.execute(CREATE_SM_TRANSITIONS_TABLE)
        await db.execute(CREATE_SM_TRANSITIONS_SM_INDEX)
        await db.execute(CREATE_SM_TRANSITIONS_FROM_INDEX)
        await db.execute(CREATE_FRAGMENT_GROUPS_TABLE)
        await db.execute(CREATE_FRAGMENTS_TABLE)
        await db.execute(CREATE_FRAGMENTS_GROUP_INDEX)
        await db.execute(CREATE_ALERT_RULES_TABLE)
        await db.execute(CREATE_ALERT_RULES_TEMPLATE_INDEX)
        await db.execute(CREATE_FIRMWARES_TABLE)
        await db.execute(CREATE_FIRMWARES_DEVICE_MODEL_INDEX)
        await db.execute(CREATE_FIRMWARES_NAME_INDEX)
        await db.execute(CREATE_FIRMWARE_SEGMENTS_TABLE)
        await db.execute(CREATE_FIRMWARE_SEGMENTS_FIRMWARE_INDEX)
        await db.execute(CREATE_FIRMWARE_SIGNATURES_TABLE)
        await db.execute(CREATE_FIRMWARE_SIGNATURES_FIRMWARE_INDEX)
        await db.execute(CREATE_OTA_DEVICES_TABLE)
        await db.execute(CREATE_OTA_DEVICES_SN_INDEX)
        await db.execute(CREATE_OTA_DEVICES_MODEL_INDEX)
        await db.execute(CREATE_OTA_DEVICES_GROUP_INDEX)
        await db.execute(CREATE_OTA_PLANS_TABLE)
        await db.execute(CREATE_OTA_PLAN_DEVICES_TABLE)
        await db.execute(CREATE_OTA_PLAN_DEVICES_PLAN_INDEX)
        await db.execute(CREATE_OTA_PLAN_DEVICES_DEVICE_INDEX)
        await db.execute(CREATE_OTA_PLAN_DEVICES_STATUS_INDEX)
        await db.execute(CREATE_IOT_DEVICES_TABLE)
        await db.execute(CREATE_IOT_DEVICES_SN_INDEX)
        await db.execute(CREATE_IOT_DEVICES_MODEL_INDEX)
        await db.execute(CREATE_IOT_ALERTS_TABLE)
        await db.execute(CREATE_IOT_ALERTS_DEVICE_INDEX)
        await db.execute(CREATE_IOT_ALERTS_TYPE_INDEX)
        await db.execute(CREATE_IOT_ALERTS_SEVERITY_INDEX)
        await db.execute(CREATE_IOT_ALERTS_TS_INDEX)
        await db.execute(CREATE_CFG_TEMPLATES_TABLE)
        await db.execute(CREATE_CFG_TEMPLATES_MODEL_INDEX)
        await db.execute(CREATE_CFG_TEMPLATE_ITEMS_TABLE)
        await db.execute(CREATE_CFG_TEMPLATE_ITEMS_TEMPLATE_INDEX)
        await db.execute(CREATE_CFG_DEVICES_TABLE)
        await db.execute(CREATE_CFG_DEVICES_SN_INDEX)
        await db.execute(CREATE_CFG_DEVICES_TEMPLATE_INDEX)
        await db.execute(CREATE_CFG_DEVICE_VALUES_TABLE)
        await db.execute(CREATE_CFG_DEVICE_VALUES_DEVICE_INDEX)
        await db.execute(CREATE_CFG_CHANGE_HISTORY_TABLE)
        await db.execute(CREATE_CFG_CHANGE_HISTORY_DEVICE_INDEX)
        await db.execute(CREATE_CFG_CHANGE_HISTORY_CHANGED_AT_INDEX)
        await db.execute(CREATE_BASELINE_SNAPSHOTS_TABLE)
        await db.execute(CREATE_BASELINE_SNAPSHOTS_TEMPLATE_INDEX)
        await db.execute(CREATE_SEQUENCE_PATTERNS_TABLE)
        await db.execute(CREATE_SEQUENCE_PATTERN_STEPS_TABLE)
        await db.execute(CREATE_SEQUENCE_PATTERN_STEPS_PATTERN_INDEX)
        await db.execute(CREATE_SAMPLE_TAGS_TABLE)
        await db.execute(CREATE_SAMPLE_TAGS_SAMPLE_INDEX)
        await db.execute(CREATE_SAMPLE_TAGS_TAG_INDEX)
        await db.commit()
    finally:
        await db.close()
    await migrate_templates_to_versions()
