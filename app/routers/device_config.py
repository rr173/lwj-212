from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from app.database import get_db
from app.routers.config_templates import _validate_value

router = APIRouter(prefix="/api/cfg/devices", tags=["device-config"])


class DeviceRegister(BaseModel):
    device_sn: str
    template_id: int


class DeviceConfigValue(BaseModel):
    key_name: str
    value_type: str
    value: str
    constraint_min: Optional[float] = None
    constraint_max: Optional[float] = None
    constraint_max_length: Optional[int] = None


class DeviceConfigOut(BaseModel):
    device_id: int
    device_sn: str
    template_id: int
    config: list[DeviceConfigValue]


class DeviceListItem(BaseModel):
    device_id: int
    device_sn: str
    template_id: int
    created_at: str


class ValueUpdate(BaseModel):
    key_name: str
    new_value: str
    changed_by: str = ""


class ChangeHistoryEntry(BaseModel):
    id: int
    device_id: int
    key_name: str
    old_value: str
    new_value: str
    changed_by: str
    changed_at: str


@router.post("", response_model=DeviceConfigOut, status_code=201)
async def register_device(body: DeviceRegister):
    if not body.device_sn.strip():
        raise HTTPException(status_code=400, detail="device_sn cannot be empty")

    db = await get_db()
    try:
        tpl_row = await db.execute_fetchall("SELECT id FROM cfg_templates WHERE id = ?", (body.template_id,))
        if not tpl_row:
            raise HTTPException(status_code=404, detail="template not found")

        existing = await db.execute_fetchall("SELECT id FROM cfg_devices WHERE device_sn = ?", (body.device_sn.strip(),))
        if existing:
            raise HTTPException(status_code=400, detail=f"device_sn '{body.device_sn}' already exists")

        cursor = await db.execute(
            "INSERT INTO cfg_devices (device_sn, template_id) VALUES (?, ?)",
            (body.device_sn.strip(), body.template_id),
        )
        device_id = cursor.lastrowid

        item_rows = await db.execute_fetchall(
            "SELECT * FROM cfg_template_items WHERE template_id = ? ORDER BY id",
            (body.template_id,),
        )

        for item in item_rows:
            await db.execute(
                "INSERT INTO cfg_device_values (device_id, item_id, value) VALUES (?, ?, ?)",
                (device_id, item["id"], item["default_value"]),
            )

        await db.commit()

        device_row = await db.execute_fetchall("SELECT * FROM cfg_devices WHERE id = ?", (device_id,))
        value_rows = await db.execute_fetchall(
            "SELECT dv.value, ti.* FROM cfg_device_values dv "
            "JOIN cfg_template_items ti ON dv.item_id = ti.id "
            "WHERE dv.device_id = ? ORDER BY ti.id",
            (device_id,),
        )
    finally:
        await db.close()

    d = device_row[0]
    return DeviceConfigOut(
        device_id=d["id"],
        device_sn=d["device_sn"],
        template_id=d["template_id"],
        config=[
            DeviceConfigValue(
                key_name=vr["key_name"],
                value_type=vr["value_type"],
                value=vr["value"],
                constraint_min=vr["constraint_min"],
                constraint_max=vr["constraint_max"],
                constraint_max_length=vr["constraint_max_length"],
            )
            for vr in value_rows
        ],
    )


@router.get("", response_model=list[DeviceListItem])
async def list_devices(
    template_id: Optional[int] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        query = "SELECT * FROM cfg_devices WHERE 1=1"
        params: list = []
        if template_id is not None:
            query += " AND template_id = ?"
            params.append(template_id)
        query += " ORDER BY id ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = await db.execute_fetchall(query, params)
    finally:
        await db.close()

    return [
        DeviceListItem(
            device_id=r["id"],
            device_sn=r["device_sn"],
            template_id=r["template_id"],
            created_at=r["created_at"] or "",
        )
        for r in rows
    ]


@router.get("/{device_id}", response_model=DeviceConfigOut)
async def get_device_config(device_id: int):
    db = await get_db()
    try:
        device_row = await db.execute_fetchall("SELECT * FROM cfg_devices WHERE id = ?", (device_id,))
        if not device_row:
            raise HTTPException(status_code=404, detail="device not found")

        value_rows = await db.execute_fetchall(
            "SELECT dv.value, ti.* FROM cfg_device_values dv "
            "JOIN cfg_template_items ti ON dv.item_id = ti.id "
            "WHERE dv.device_id = ? ORDER BY ti.id",
            (device_id,),
        )
    finally:
        await db.close()

    d = device_row[0]
    return DeviceConfigOut(
        device_id=d["id"],
        device_sn=d["device_sn"],
        template_id=d["template_id"],
        config=[
            DeviceConfigValue(
                key_name=vr["key_name"],
                value_type=vr["value_type"],
                value=vr["value"],
                constraint_min=vr["constraint_min"],
                constraint_max=vr["constraint_max"],
                constraint_max_length=vr["constraint_max_length"],
            )
            for vr in value_rows
        ],
    )


@router.put("/{device_id}/value")
async def update_device_value(device_id: int, body: ValueUpdate):
    db = await get_db()
    try:
        device_row = await db.execute_fetchall("SELECT * FROM cfg_devices WHERE id = ?", (device_id,))
        if not device_row:
            raise HTTPException(status_code=404, detail="device not found")

        item_row = await db.execute_fetchall(
            "SELECT ti.* FROM cfg_template_items ti WHERE ti.template_id = ? AND ti.key_name = ?",
            (device_row[0]["template_id"], body.key_name),
        )
        if not item_row:
            raise HTTPException(status_code=404, detail=f"key_name '{body.key_name}' not found in template")

        item = item_row[0]
        err = _validate_value(body.new_value, item["value_type"], item["constraint_min"], item["constraint_max"], item["constraint_max_length"])
        if err:
            raise HTTPException(status_code=400, detail=f"validation failed: {err}")

        val_row = await db.execute_fetchall(
            "SELECT * FROM cfg_device_values WHERE device_id = ? AND item_id = ?",
            (device_id, item["id"]),
        )
        if not val_row:
            raise HTTPException(status_code=404, detail="config value not found for this device")

        old_value = val_row[0]["value"]
        if old_value == body.new_value:
            return {"message": "value unchanged", "device_id": device_id, "key_name": body.key_name, "value": body.new_value}

        await db.execute(
            "UPDATE cfg_device_values SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE device_id = ? AND item_id = ?",
            (body.new_value, device_id, item["id"]),
        )

        await db.execute(
            "INSERT INTO cfg_change_history (device_id, item_id, old_value, new_value, changed_by) VALUES (?, ?, ?, ?, ?)",
            (device_id, item["id"], old_value, body.new_value, body.changed_by),
        )

        await db.commit()
    finally:
        await db.close()

    return {
        "device_id": device_id,
        "key_name": body.key_name,
        "old_value": old_value,
        "new_value": body.new_value,
        "changed_by": body.changed_by,
    }


@router.get("/{device_id}/history", response_model=list[ChangeHistoryEntry])
async def get_change_history(
    device_id: int,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        device_row = await db.execute_fetchall("SELECT id FROM cfg_devices WHERE id = ?", (device_id,))
        if not device_row:
            raise HTTPException(status_code=404, detail="device not found")

        rows = await db.execute_fetchall(
            "SELECT ch.*, ti.key_name FROM cfg_change_history ch "
            "JOIN cfg_template_items ti ON ch.item_id = ti.id "
            "WHERE ch.device_id = ? ORDER BY ch.changed_at DESC, ch.id DESC LIMIT ? OFFSET ?",
            (device_id, limit, offset),
        )
    finally:
        await db.close()

    return [
        ChangeHistoryEntry(
            id=r["id"],
            device_id=r["device_id"],
            key_name=r["key_name"],
            old_value=r["old_value"],
            new_value=r["new_value"],
            changed_by=r["changed_by"] or "",
            changed_at=r["changed_at"] or "",
        )
        for r in rows
    ]
