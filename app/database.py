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
        await db.commit()
    finally:
        await db.close()
    await migrate_templates_to_versions()
