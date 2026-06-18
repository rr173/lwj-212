from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.database import get_db
from app.routers.config_templates import _validate_value

router = APIRouter(prefix="/api/cfg/batch", tags=["batch-push"])

MAX_DEVICES_PER_BATCH = 200


class BatchPushItem(BaseModel):
    key_name: str
    new_value: str


class BatchPushRequest(BaseModel):
    template_id: int
    values: list[BatchPushItem]
    changed_by: str = ""


class DeviceChangeDetail(BaseModel):
    device_id: int
    device_sn: str
    changes: list[dict]


class BatchPushResult(BaseModel):
    success: bool
    success_count: int
    failed_devices: list[dict]
    details: list[DeviceChangeDetail]


@router.post("/push", response_model=BatchPushResult)
async def batch_push(body: BatchPushRequest):
    db = await get_db()
    try:
        tpl_row = await db.execute_fetchall("SELECT * FROM cfg_templates WHERE id = ?", (body.template_id,))
        if not tpl_row:
            raise HTTPException(status_code=404, detail="template not found")

        item_rows = await db.execute_fetchall(
            "SELECT * FROM cfg_template_items WHERE template_id = ? ORDER BY id",
            (body.template_id,),
        )
        items_by_key = {ir["key_name"]: ir for ir in item_rows}

        for v in body.values:
            if v.key_name not in items_by_key:
                raise HTTPException(status_code=400, detail=f"key_name '{v.key_name}' not found in template")

        device_rows = await db.execute_fetchall(
            "SELECT * FROM cfg_devices WHERE template_id = ? ORDER BY id",
            (body.template_id,),
        )
        if len(device_rows) > MAX_DEVICES_PER_BATCH:
            raise HTTPException(status_code=400, detail=f"template has {len(device_rows)} devices, exceeding max batch size of {MAX_DEVICES_PER_BATCH}")

        failed_devices: list[dict] = []
        device_item_values: dict[int, dict[int, str]] = {}

        for dr in device_rows:
            val_rows = await db.execute_fetchall(
                "SELECT item_id, value FROM cfg_device_values WHERE device_id = ?",
                (dr["id"],),
            )
            current_vals = {vr["item_id"]: vr["value"] for vr in val_rows}
            device_item_values[dr["id"]] = current_vals

        for dr in device_rows:
            for v in body.values:
                item = items_by_key[v.key_name]
                err = _validate_value(v.new_value, item["value_type"], item["constraint_min"], item["constraint_max"], item["constraint_max_length"])
                if err:
                    failed_devices.append({
                        "device_id": dr["id"],
                        "device_sn": dr["device_sn"],
                        "key_name": v.key_name,
                        "reason": err,
                    })

        if failed_devices:
            return BatchPushResult(
                success=False,
                success_count=0,
                failed_devices=failed_devices,
                details=[],
            )

        details: list[DeviceChangeDetail] = []

        for dr in device_rows:
            device_changes = []
            for v in body.values:
                item = items_by_key[v.key_name]
                old_value = device_item_values[dr["id"]].get(item["id"], "")

                if old_value == v.new_value:
                    device_changes.append({
                        "key_name": v.key_name,
                        "old_value": old_value,
                        "new_value": v.new_value,
                        "changed": False,
                    })
                    continue

                await db.execute(
                    "UPDATE cfg_device_values SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE device_id = ? AND item_id = ?",
                    (v.new_value, dr["id"], item["id"]),
                )

                await db.execute(
                    "INSERT INTO cfg_change_history (device_id, item_id, old_value, new_value, changed_by) VALUES (?, ?, ?, ?, ?)",
                    (dr["id"], item["id"], old_value, v.new_value, body.changed_by),
                )

                device_changes.append({
                    "key_name": v.key_name,
                    "old_value": old_value,
                    "new_value": v.new_value,
                    "changed": True,
                })

            details.append(DeviceChangeDetail(
                device_id=dr["id"],
                device_sn=dr["device_sn"],
                changes=device_changes,
            ))

        await db.commit()
    finally:
        await db.close()

    success_count = sum(1 for d in details if any(c.get("changed") for c in d.changes))

    return BatchPushResult(
        success=True,
        success_count=success_count,
        failed_devices=[],
        details=details,
    )
