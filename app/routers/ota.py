import asyncio
import logging
from fastapi import APIRouter, HTTPException, Query
from app.ota_models import (
    DeviceCreate, DeviceBatchCreate, DeviceOut,
    PlanCreate, PlanOut,
    DeviceReport, PlanDashboard, PlanDeviceOut,
)
from app.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ota", tags=["ota"])

_background_tasks: dict[int, asyncio.Task] = {}


def _parse_version(version_str: str) -> tuple:
    cleaned = version_str.strip().lstrip("vV")
    parts = []
    for part in cleaned.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(part)
    return tuple(parts)


def _version_in_range(version: str, min_ver: str, max_ver: str) -> bool:
    v = _parse_version(version)
    if min_ver:
        if v < _parse_version(min_ver):
            return False
    if max_ver:
        if v > _parse_version(max_ver):
            return False
    return True


def _check_failure_threshold(failed_count: int, pushed_count: int, threshold: float) -> bool:
    if pushed_count == 0:
        return False
    return (failed_count / pushed_count) > threshold


async def _push_batch(plan_id: int):
    try:
        db = await get_db()
        try:
            plan_row = await db.execute_fetchall(
                "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
            )
            if not plan_row:
                return
            plan = plan_row[0]

            if plan["status"] != "running":
                return

            if plan["strategy"] == "full":
                pending_devices = await db.execute_fetchall(
                    "SELECT pd.id, pd.device_id, d.online_status FROM ota_plan_devices pd "
                    "JOIN ota_devices d ON pd.device_id = d.id "
                    "WHERE pd.plan_id = ? AND pd.status = 'pending'",
                    (plan_id,),
                )
                batch_num = 1
                for pd in pending_devices:
                    online_status = str(pd["online_status"] or "").strip().lower()
                    if online_status == "offline":
                        await db.execute(
                            "UPDATE ota_plan_devices SET status = 'skipped_offline', batch_number = ? WHERE id = ?",
                            (batch_num, pd["id"]),
                        )
                    else:
                        await db.execute(
                            "UPDATE ota_plan_devices SET status = 'upgrading', batch_number = ? WHERE id = ?",
                            (batch_num, pd["id"]),
                        )
                await db.execute(
                    "UPDATE ota_plans SET current_batch = 1 WHERE id = ?", (plan_id,)
                )
                await db.commit()

                await _check_plan_completion(plan_id)
            else:
                task = asyncio.create_task(_push_next_batch(plan_id))
                _background_tasks[plan_id] = task
        finally:
            await db.close()
    except Exception as e:
        logger.error(f"Error in _push_batch for plan {plan_id}: {e}")


async def _push_next_batch(plan_id: int):
    try:
        db = await get_db()
        try:
            plan_row = await db.execute_fetchall(
                "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
            )
            if not plan_row:
                return
            plan = plan_row[0]

            if plan["status"] != "running":
                return

            batch_size = int(plan["batch_size"]) if plan["batch_size"] else 1
            if batch_size < 1:
                batch_size = 1
            if batch_size > 100:
                batch_size = 100

            pending_devices = await db.execute_fetchall(
                "SELECT pd.id, pd.device_id, d.online_status FROM ota_plan_devices pd "
                "JOIN ota_devices d ON pd.device_id = d.id "
                "WHERE pd.plan_id = ? AND pd.status = 'pending' "
                "ORDER BY pd.id "
                "LIMIT ?",
                (plan_id, batch_size),
            )

            if not pending_devices:
                await _check_plan_completion(plan_id)
                return

            batch_num = int(plan["current_batch"]) + 1

            for pd in pending_devices:
                online_status = str(pd["online_status"] or "").strip().lower()
                if online_status == "offline":
                    await db.execute(
                        "UPDATE ota_plan_devices SET status = 'skipped_offline', batch_number = ? WHERE id = ?",
                        (batch_num, pd["id"]),
                    )
                else:
                    await db.execute(
                        "UPDATE ota_plan_devices SET status = 'upgrading', batch_number = ? WHERE id = ?",
                        (batch_num, pd["id"]),
                    )

            await db.execute(
                "UPDATE ota_plans SET current_batch = ? WHERE id = ?",
                (batch_num, plan_id),
            )
            await db.commit()

            logger.info(
                f"Plan {plan_id} batch {batch_num}: pushed {len(pending_devices)} devices "
                f"(batch_size={batch_size})"
            )
        finally:
            await db.close()

        await asyncio.sleep(0)

        remaining_db = await get_db()
        try:
            remaining = await remaining_db.execute_fetchall(
                "SELECT id FROM ota_plan_devices WHERE plan_id = ? AND status = 'pending'",
                (plan_id,),
            )
        finally:
            await remaining_db.close()

        if remaining:
            interval = int(plan["batch_interval"]) if plan["batch_interval"] else 0
            logger.info(f"Plan {plan_id}: waiting {interval}s before next batch")
            await asyncio.sleep(interval)
            await asyncio.sleep(0)

            status_db = await get_db()
            try:
                plan_check = await status_db.execute_fetchall(
                    "SELECT status FROM ota_plans WHERE id = ?", (plan_id,)
                )
            finally:
                await status_db.close()

            if plan_check and str(plan_check[0]["status"]).strip() == "running":
                next_task = asyncio.create_task(_push_next_batch(plan_id))
                _background_tasks[plan_id] = next_task
            else:
                logger.info(f"Plan {plan_id}: stopped before next batch")
        else:
            await _check_plan_completion(plan_id)
    except asyncio.CancelledError:
        logger.info(f"Plan {plan_id}: batch task cancelled")
        raise
    except Exception as e:
        logger.error(f"Error in _push_next_batch for plan {plan_id}: {e}", exc_info=True)


async def _check_plan_completion(plan_id: int):
    db = await get_db()
    try:
        stats = await _get_plan_stats(db, plan_id)
        if stats["pending_count"] == 0 and stats["upgrading_count"] == 0:
            plan_row = await db.execute_fetchall(
                "SELECT status FROM ota_plans WHERE id = ?", (plan_id,)
            )
            if plan_row and plan_row[0]["status"] in ("running",):
                await db.execute(
                    "UPDATE ota_plans SET status = 'completed' WHERE id = ?",
                    (plan_id,),
                )
                await db.commit()
    finally:
        await db.close()


async def _get_plan_stats(db, plan_id: int) -> dict:
    rows = await db.execute_fetchall(
        "SELECT status, COUNT(*) as cnt FROM ota_plan_devices WHERE plan_id = ? GROUP BY status",
        (plan_id,),
    )
    counts = {}
    for r in rows:
        counts[r["status"]] = r["cnt"]

    total = sum(counts.values())
    pushed = counts.get("upgrading", 0) + counts.get("success", 0) + counts.get("failed", 0) + counts.get("skipped_offline", 0)
    success_count = counts.get("success", 0)
    failed_count = counts.get("failed", 0)
    pending_count = counts.get("pending", 0)
    upgrading_count = counts.get("upgrading", 0)
    skipped_count = counts.get("skipped_offline", 0)
    pending_rollback_count = counts.get("pending_rollback", 0)

    failure_rate = round(failed_count / pushed, 4) if pushed > 0 else 0.0

    return {
        "total": total,
        "pushed": pushed,
        "success_count": success_count,
        "failed_count": failed_count,
        "pending_count": pending_count,
        "upgrading_count": upgrading_count,
        "skipped_count": skipped_count,
        "pending_rollback_count": pending_rollback_count,
        "failure_rate": failure_rate,
    }


async def _check_and_handle_failure_threshold(plan_id: int):
    db = await get_db()
    try:
        plan_row = await db.execute_fetchall(
            "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
        )
        if not plan_row:
            return
        plan = plan_row[0]

        stats = await _get_plan_stats(db, plan_id)

        if plan["status"] == "running" and _check_failure_threshold(
            stats["failed_count"], stats["pushed"], plan["failure_threshold"]
        ):
            await db.execute(
                "UPDATE ota_plans SET status = 'paused_failure_rate' WHERE id = ?",
                (plan_id,),
            )
            await db.commit()

            if plan_id in _background_tasks:
                _background_tasks[plan_id].cancel()
                del _background_tasks[plan_id]
    finally:
        await db.close()


@router.post("/devices", response_model=DeviceOut, status_code=201)
async def register_device(body: DeviceCreate):
    db = await get_db()
    try:
        existing = await db.execute_fetchall(
            "SELECT id FROM ota_devices WHERE device_sn = ?", (body.device_sn,)
        )
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"device_sn '{body.device_sn}' already exists",
            )

        cursor = await db.execute(
            "INSERT INTO ota_devices (device_sn, device_model, firmware_version, group_tag, online_status) "
            "VALUES (?, ?, ?, ?, ?)",
            (body.device_sn, body.device_model, body.firmware_version, body.group_tag, body.online_status),
        )
        await db.commit()
        device_id = cursor.lastrowid

        row = await db.execute_fetchall(
            "SELECT * FROM ota_devices WHERE id = ?", (device_id,)
        )
    finally:
        await db.close()

    r = row[0]
    return DeviceOut(
        id=r["id"],
        device_sn=r["device_sn"],
        device_model=r["device_model"],
        firmware_version=r["firmware_version"],
        group_tag=r["group_tag"],
        online_status=r["online_status"],
        created_at=r["created_at"] or "",
    )


@router.post("/devices/batch", status_code=201)
async def batch_register_devices(body: DeviceBatchCreate):
    db = await get_db()
    try:
        existing_sns = set()
        for dev in body.devices:
            existing = await db.execute_fetchall(
                "SELECT id FROM ota_devices WHERE device_sn = ?", (dev.device_sn,)
            )
            if existing:
                existing_sns.add(dev.device_sn)

        if existing_sns:
            raise HTTPException(
                status_code=400,
                detail=f"duplicate device_sn: {', '.join(sorted(existing_sns))}",
            )

        dup_sns = []
        seen = set()
        for dev in body.devices:
            if dev.device_sn in seen:
                dup_sns.append(dev.device_sn)
            seen.add(dev.device_sn)
        if dup_sns:
            raise HTTPException(
                status_code=400,
                detail=f"duplicate device_sn in request: {', '.join(sorted(set(dup_sns)))}",
            )

        created = []
        for dev in body.devices:
            cursor = await db.execute(
                "INSERT INTO ota_devices (device_sn, device_model, firmware_version, group_tag, online_status) "
                "VALUES (?, ?, ?, ?, ?)",
                (dev.device_sn, dev.device_model, dev.firmware_version, dev.group_tag, dev.online_status),
            )
            device_id = cursor.lastrowid
            row = await db.execute_fetchall(
                "SELECT * FROM ota_devices WHERE id = ?", (device_id,)
            )
            r = row[0]
            created.append(DeviceOut(
                id=r["id"],
                device_sn=r["device_sn"],
                device_model=r["device_model"],
                firmware_version=r["firmware_version"],
                group_tag=r["group_tag"],
                online_status=r["online_status"],
                created_at=r["created_at"] or "",
            ))
        await db.commit()
    finally:
        await db.close()

    return {"created_count": len(created), "devices": created}


@router.get("/devices", response_model=list[DeviceOut])
async def list_devices(
    device_model: str = Query(default=None),
    group_tag: str = Query(default=None),
    online_status: str = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        query = "SELECT * FROM ota_devices WHERE 1=1"
        params = []

        if device_model:
            query += " AND device_model = ?"
            params.append(device_model)
        if group_tag:
            query += " AND group_tag = ?"
            params.append(group_tag)
        if online_status:
            query += " AND online_status = ?"
            params.append(online_status)

        query += " ORDER BY id ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = await db.execute_fetchall(query, params)
    finally:
        await db.close()

    return [
        DeviceOut(
            id=r["id"],
            device_sn=r["device_sn"],
            device_model=r["device_model"],
            firmware_version=r["firmware_version"],
            group_tag=r["group_tag"],
            online_status=r["online_status"],
            created_at=r["created_at"] or "",
        )
        for r in rows
    ]


@router.get("/devices/{device_id}", response_model=DeviceOut)
async def get_device(device_id: int):
    db = await get_db()
    try:
        row = await db.execute_fetchall(
            "SELECT * FROM ota_devices WHERE id = ?", (device_id,)
        )
    finally:
        await db.close()

    if not row:
        raise HTTPException(status_code=404, detail="device not found")

    r = row[0]
    return DeviceOut(
        id=r["id"],
        device_sn=r["device_sn"],
        device_model=r["device_model"],
        firmware_version=r["firmware_version"],
        group_tag=r["group_tag"],
        online_status=r["online_status"],
        created_at=r["created_at"] or "",
    )


@router.post("/plans", response_model=PlanOut, status_code=201)
async def create_plan(body: PlanCreate):
    if body.strategy == "batch":
        if body.batch_size < 1 or body.batch_size > 100:
            raise HTTPException(
                status_code=400,
                detail="batch_size must be between 1 and 100",
            )
    if body.failure_threshold < 0.01 or body.failure_threshold > 1.0:
        raise HTTPException(
            status_code=400,
            detail="failure_threshold must be between 0.01 and 1.0",
        )

    db = await get_db()
    try:
        await db.execute("BEGIN IMMEDIATE")

        query = "SELECT * FROM ota_devices WHERE device_model = ?"
        params: list = [body.device_model]

        if body.filter_group:
            query += " AND group_tag = ?"
            params.append(body.filter_group)

        candidates = await db.execute_fetchall(query, params)

        eligible_devices = []
        for dev in candidates:
            if body.filter_version_min or body.filter_version_max:
                if not _version_in_range(
                    str(dev["firmware_version"] or ""),
                    body.filter_version_min,
                    body.filter_version_max,
                ):
                    continue
            eligible_devices.append(dev)

        if len(eligible_devices) > 1000:
            raise HTTPException(
                status_code=400,
                detail=f"eligible devices ({len(eligible_devices)}) exceed maximum of 1000 per plan",
            )

        cursor = await db.execute(
            "INSERT INTO ota_plans (name, target_version, device_model, filter_group, filter_version_min, filter_version_max, "
            "strategy, batch_size, batch_interval, failure_threshold, rollback_version, total_devices) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                body.name, body.target_version, body.device_model,
                body.filter_group, body.filter_version_min, body.filter_version_max,
                body.strategy, body.batch_size, body.batch_interval,
                body.failure_threshold, body.rollback_version, len(eligible_devices),
            ),
        )
        plan_id = cursor.lastrowid

        for dev in eligible_devices:
            await db.execute(
                "INSERT OR IGNORE INTO ota_plan_devices (plan_id, device_id, target_version) VALUES (?, ?, ?)",
                (plan_id, dev["id"], body.target_version),
            )

        await db.commit()

        row = await db.execute_fetchall(
            "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
        )
    except HTTPException:
        await db.rollback()
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating plan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"failed to create plan: {e}")
    finally:
        await db.close()

    r = row[0]
    return PlanOut(
        id=r["id"],
        name=r["name"],
        target_version=r["target_version"],
        device_model=r["device_model"],
        filter_group=r["filter_group"] or "",
        filter_version_min=r["filter_version_min"] or "",
        filter_version_max=r["filter_version_max"] or "",
        strategy=r["strategy"],
        batch_size=r["batch_size"],
        batch_interval=r["batch_interval"],
        failure_threshold=r["failure_threshold"],
        rollback_version=r["rollback_version"] or "",
        status=r["status"],
        current_batch=r["current_batch"],
        total_devices=r["total_devices"],
        created_at=r["created_at"] or "",
    )


@router.get("/plans", response_model=list[PlanOut])
async def list_plans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM ota_plans ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
    finally:
        await db.close()

    return [
        PlanOut(
            id=r["id"],
            name=r["name"],
            target_version=r["target_version"],
            device_model=r["device_model"],
            filter_group=r["filter_group"] or "",
            filter_version_min=r["filter_version_min"] or "",
            filter_version_max=r["filter_version_max"] or "",
            strategy=r["strategy"],
            batch_size=r["batch_size"],
            batch_interval=r["batch_interval"],
            failure_threshold=r["failure_threshold"],
            rollback_version=r["rollback_version"] or "",
            status=r["status"],
            current_batch=r["current_batch"],
            total_devices=r["total_devices"],
            created_at=r["created_at"] or "",
        )
        for r in rows
    ]


@router.get("/plans/{plan_id}", response_model=PlanOut)
async def get_plan(plan_id: int):
    db = await get_db()
    try:
        row = await db.execute_fetchall(
            "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
        )
    finally:
        await db.close()

    if not row:
        raise HTTPException(status_code=404, detail="plan not found")

    r = row[0]
    return PlanOut(
        id=r["id"],
        name=r["name"],
        target_version=r["target_version"],
        device_model=r["device_model"],
        filter_group=r["filter_group"] or "",
        filter_version_min=r["filter_version_min"] or "",
        filter_version_max=r["filter_version_max"] or "",
        strategy=r["strategy"],
        batch_size=r["batch_size"],
        batch_interval=r["batch_interval"],
        failure_threshold=r["failure_threshold"],
        rollback_version=r["rollback_version"] or "",
        status=r["status"],
        current_batch=r["current_batch"],
        total_devices=r["total_devices"],
        created_at=r["created_at"] or "",
    )


@router.post("/plans/{plan_id}/start")
async def start_plan(plan_id: int):
    db = await get_db()
    try:
        row = await db.execute_fetchall(
            "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
        )
        if not row:
            raise HTTPException(status_code=404, detail="plan not found")

        plan = row[0]
        if plan["status"] != "pending":
            raise HTTPException(
                status_code=400,
                detail=f"plan cannot be started: current status is '{plan['status']}'",
            )

        await db.execute(
            "UPDATE ota_plans SET status = 'running' WHERE id = ?", (plan_id,)
        )
        await db.commit()
    finally:
        await db.close()

    task = asyncio.create_task(_push_batch(plan_id))
    _background_tasks[plan_id] = task

    return {"message": "plan started", "plan_id": plan_id}


@router.post("/plans/{plan_id}/pause")
async def pause_plan(plan_id: int):
    db = await get_db()
    try:
        row = await db.execute_fetchall(
            "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
        )
        if not row:
            raise HTTPException(status_code=404, detail="plan not found")

        plan = row[0]
        if plan["status"] != "running":
            raise HTTPException(
                status_code=400,
                detail=f"plan cannot be paused: current status is '{plan['status']}'",
            )

        await db.execute(
            "UPDATE ota_plans SET status = 'paused' WHERE id = ?", (plan_id,)
        )
        await db.commit()
    finally:
        await db.close()

    if plan_id in _background_tasks:
        _background_tasks[plan_id].cancel()
        del _background_tasks[plan_id]

    return {"message": "plan paused", "plan_id": plan_id}


@router.post("/plans/{plan_id}/resume")
async def resume_plan(plan_id: int):
    db = await get_db()
    try:
        row = await db.execute_fetchall(
            "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
        )
        if not row:
            raise HTTPException(status_code=404, detail="plan not found")

        plan = row[0]
        if plan["status"] not in ("paused", "paused_failure_rate"):
            raise HTTPException(
                status_code=400,
                detail=f"plan cannot be resumed: current status is '{plan['status']}'",
            )

        await db.execute(
            "UPDATE ota_plans SET status = 'running' WHERE id = ?", (plan_id,)
        )
        await db.commit()
    finally:
        await db.close()

    if plan["strategy"] == "batch":
        task = asyncio.create_task(_push_next_batch(plan_id))
        _background_tasks[plan_id] = task
    else:
        task = asyncio.create_task(_push_batch(plan_id))
        _background_tasks[plan_id] = task

    return {"message": "plan resumed", "plan_id": plan_id}


@router.post("/plans/{plan_id}/report")
async def device_report(plan_id: int, body: DeviceReport):
    db = await get_db()
    try:
        plan_row = await db.execute_fetchall(
            "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
        )
        if not plan_row:
            raise HTTPException(status_code=404, detail="plan not found")

        plan = plan_row[0]

        pd_row = await db.execute_fetchall(
            "SELECT * FROM ota_plan_devices WHERE plan_id = ? AND device_id = ?",
            (plan_id, body.device_id),
        )
        if not pd_row:
            raise HTTPException(
                status_code=404,
                detail=f"device {body.device_id} not found in plan {plan_id}",
            )

        pd = pd_row[0]
        if pd["status"] != "upgrading":
            raise HTTPException(
                status_code=400,
                detail=f"device is not in 'upgrading' state, current state: '{pd['status']}'",
            )

        if body.success:
            await db.execute(
                "UPDATE ota_plan_devices SET status = 'success' WHERE id = ?",
                (pd["id"],),
            )
            await db.execute(
                "UPDATE ota_devices SET firmware_version = ? WHERE id = ?",
                (plan["target_version"], body.device_id),
            )
        else:
            await db.execute(
                "UPDATE ota_plan_devices SET status = 'failed', failure_reason = ? WHERE id = ?",
                (body.failure_reason, pd["id"]),
            )

        await db.commit()
    finally:
        await db.close()

    await _check_and_handle_failure_threshold(plan_id)
    await _check_plan_completion(plan_id)

    return {
        "plan_id": plan_id,
        "device_id": body.device_id,
        "result": "success" if body.success else "failed",
    }


@router.post("/plans/{plan_id}/rollback")
async def rollback_plan(plan_id: int):
    db = await get_db()
    try:
        plan_row = await db.execute_fetchall(
            "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
        )
        if not plan_row:
            raise HTTPException(status_code=404, detail="plan not found")

        plan = plan_row[0]

        if plan["status"] not in ("paused", "paused_failure_rate"):
            raise HTTPException(
                status_code=400,
                detail="rollback is only available for paused plans",
            )

        if not plan["rollback_version"]:
            raise HTTPException(
                status_code=400,
                detail="no rollback version specified for this plan",
            )

        target_rows = await db.execute_fetchall(
            "SELECT * FROM ota_plan_devices WHERE plan_id = ? AND status IN ('upgrading', 'failed')",
            (plan_id,),
        )

        rollback_count = 0
        for pd in target_rows:
            await db.execute(
                "UPDATE ota_plan_devices SET status = 'pending_rollback', target_version = ? WHERE id = ?",
                (plan["rollback_version"], pd["id"]),
            )
            rollback_count += 1

        await db.commit()
    finally:
        await db.close()

    return {
        "plan_id": plan_id,
        "rollback_version": plan["rollback_version"],
        "rollback_device_count": rollback_count,
    }


@router.get("/plans/{plan_id}/dashboard", response_model=PlanDashboard)
async def plan_dashboard(plan_id: int):
    db = await get_db()
    try:
        plan_row = await db.execute_fetchall(
            "SELECT * FROM ota_plans WHERE id = ?", (plan_id,)
        )
        if not plan_row:
            raise HTTPException(status_code=404, detail="plan not found")

        plan = plan_row[0]
        stats = await _get_plan_stats(db, plan_id)
    finally:
        await db.close()

    return PlanDashboard(
        plan_id=plan_id,
        plan_name=plan["name"],
        status=plan["status"],
        total_devices=stats["total"],
        pushed_count=stats["pushed"],
        success_count=stats["success_count"],
        failed_count=stats["failed_count"],
        pending_count=stats["pending_count"],
        upgrading_count=stats["upgrading_count"],
        skipped_count=stats["skipped_count"],
        pending_rollback_count=stats["pending_rollback_count"],
        failure_rate=stats["failure_rate"],
        current_batch=plan["current_batch"],
    )


@router.get("/plans/{plan_id}/devices", response_model=list[PlanDeviceOut])
async def list_plan_devices(
    plan_id: int,
    status: str = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        plan_row = await db.execute_fetchall(
            "SELECT id FROM ota_plans WHERE id = ?", (plan_id,)
        )
        if not plan_row:
            raise HTTPException(status_code=404, detail="plan not found")

        query = (
            "SELECT pd.*, d.device_sn, d.device_model, d.firmware_version, d.group_tag, d.online_status "
            "FROM ota_plan_devices pd JOIN ota_devices d ON pd.device_id = d.id "
            "WHERE pd.plan_id = ?"
        )
        params: list = [plan_id]

        if status:
            query += " AND pd.status = ?"
            params.append(status)

        query += " ORDER BY pd.id ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = await db.execute_fetchall(query, params)
    finally:
        await db.close()

    return [
        PlanDeviceOut(
            id=r["id"],
            plan_id=r["plan_id"],
            device_id=r["device_id"],
            device_sn=r["device_sn"],
            device_model=r["device_model"],
            firmware_version=r["firmware_version"],
            group_tag=r["group_tag"],
            online_status=r["online_status"],
            status=r["status"],
            target_version=r["target_version"],
            failure_reason=r["failure_reason"] or "",
            batch_number=r["batch_number"],
        )
        for r in rows
    ]
