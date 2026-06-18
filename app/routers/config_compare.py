from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from app.database import get_db

router = APIRouter(prefix="/api/cfg/compare", tags=["config-compare"])


class DiffEntry(BaseModel):
    key_name: str
    left_value: str
    right_value: str


class OnlyInEntry(BaseModel):
    key_name: str
    value: str
    side: str


class DeviceVsDeviceResult(BaseModel):
    left_device_id: int
    left_device_sn: str
    right_device_id: int
    right_device_sn: str
    differences: list[DiffEntry]
    only_in_left: list[OnlyInEntry]
    only_in_right: list[OnlyInEntry]


class DeviceVsTemplateResult(BaseModel):
    device_id: int
    device_sn: str
    template_id: int
    template_name: str
    differences: list[DiffEntry]
    only_in_device: list[OnlyInEntry]
    only_in_template: list[OnlyInEntry]


@router.get("/devices", response_model=DeviceVsDeviceResult)
async def compare_devices(
    left_device_id: int = Query(..., description="First device ID"),
    right_device_id: int = Query(..., description="Second device ID"),
):
    db = await get_db()
    try:
        left_dev = await db.execute_fetchall("SELECT * FROM cfg_devices WHERE id = ?", (left_device_id,))
        if not left_dev:
            raise HTTPException(status_code=404, detail=f"device {left_device_id} not found")
        right_dev = await db.execute_fetchall("SELECT * FROM cfg_devices WHERE id = ?", (right_device_id,))
        if not right_dev:
            raise HTTPException(status_code=404, detail=f"device {right_device_id} not found")

        left_vals = await db.execute_fetchall(
            "SELECT ti.key_name, dv.value FROM cfg_device_values dv "
            "JOIN cfg_template_items ti ON dv.item_id = ti.id "
            "WHERE dv.device_id = ? ORDER BY ti.key_name",
            (left_device_id,),
        )
        right_vals = await db.execute_fetchall(
            "SELECT ti.key_name, dv.value FROM cfg_device_values dv "
            "JOIN cfg_template_items ti ON dv.item_id = ti.id "
            "WHERE dv.device_id = ? ORDER BY ti.key_name",
            (right_device_id,),
        )
    finally:
        await db.close()

    left_map = {r["key_name"]: r["value"] for r in left_vals}
    right_map = {r["key_name"]: r["value"] for r in right_vals}

    all_keys = set(left_map.keys()) | set(right_map.keys())
    differences = []
    only_in_left = []
    only_in_right = []

    for key in sorted(all_keys):
        in_left = key in left_map
        in_right = key in right_map
        if in_left and in_right:
            if left_map[key] != right_map[key]:
                differences.append(DiffEntry(key_name=key, left_value=left_map[key], right_value=right_map[key]))
        elif in_left:
            only_in_left.append(OnlyInEntry(key_name=key, value=left_map[key], side="left"))
        else:
            only_in_right.append(OnlyInEntry(key_name=key, value=right_map[key], side="right"))

    return DeviceVsDeviceResult(
        left_device_id=left_dev[0]["id"],
        left_device_sn=left_dev[0]["device_sn"],
        right_device_id=right_dev[0]["id"],
        right_device_sn=right_dev[0]["device_sn"],
        differences=differences,
        only_in_left=only_in_left,
        only_in_right=only_in_right,
    )


@router.get("/device-template", response_model=DeviceVsTemplateResult)
async def compare_device_template(
    device_id: int = Query(..., description="Device ID"),
    template_id: int = Query(..., description="Template ID"),
):
    db = await get_db()
    try:
        dev = await db.execute_fetchall("SELECT * FROM cfg_devices WHERE id = ?", (device_id,))
        if not dev:
            raise HTTPException(status_code=404, detail=f"device {device_id} not found")
        tpl = await db.execute_fetchall("SELECT * FROM cfg_templates WHERE id = ?", (template_id,))
        if not tpl:
            raise HTTPException(status_code=404, detail=f"template {template_id} not found")

        device_vals = await db.execute_fetchall(
            "SELECT ti.key_name, dv.value FROM cfg_device_values dv "
            "JOIN cfg_template_items ti ON dv.item_id = ti.id "
            "WHERE dv.device_id = ? ORDER BY ti.key_name",
            (device_id,),
        )
        template_items = await db.execute_fetchall(
            "SELECT key_name, default_value FROM cfg_template_items WHERE template_id = ? ORDER BY key_name",
            (template_id,),
        )
    finally:
        await db.close()

    device_map = {r["key_name"]: r["value"] for r in device_vals}
    template_map = {r["key_name"]: r["default_value"] for r in template_items}

    all_keys = set(device_map.keys()) | set(template_map.keys())
    differences = []
    only_in_device = []
    only_in_template = []

    for key in sorted(all_keys):
        in_dev = key in device_map
        in_tpl = key in template_map
        if in_dev and in_tpl:
            if device_map[key] != template_map[key]:
                differences.append(DiffEntry(key_name=key, left_value=device_map[key], right_value=template_map[key]))
        elif in_dev:
            only_in_device.append(OnlyInEntry(key_name=key, value=device_map[key], side="device"))
        else:
            only_in_template.append(OnlyInEntry(key_name=key, value=template_map[key], side="template"))

    return DeviceVsTemplateResult(
        device_id=dev[0]["id"],
        device_sn=dev[0]["device_sn"],
        template_id=tpl[0]["id"],
        template_name=tpl[0]["name"],
        differences=differences,
        only_in_device=only_in_device,
        only_in_template=only_in_template,
    )
