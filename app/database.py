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
        await db.commit()
    finally:
        await db.close()
    await migrate_templates_to_versions()
