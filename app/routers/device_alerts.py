import time
from collections import defaultdict
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from app.database import get_db
from app.models import (
    ALERT_TYPES,
    ALERT_SEVERITIES,
    SEVERITY_RANK,
    THIRTY_DAYS_SECONDS,
    MAX_WINDOW_SECONDS,
    MAX_BATCH_ALERTS,
    AlertAggregationEntry,
    AlertAggregationResult,
    AlertBatchSubmitResult,
    IoTAlertBatchCreate,
    IoTAlertCreate,
    IoTAlertOut,
    IoTDeviceOut,
    PatternAnalysisResult,
    PatternMatch,
    PatternMatchCorrelation,
    PatternMatchSpike,
    PatternMatchSpread,
    UpgradeDecisionResult,
    UpgradeRecommendation,
)

router = APIRouter(prefix="/api/device-alerts", tags=["device-alerts"])


def _validate_time_window(start_ts: int, end_ts: int) -> None:
    if start_ts <= 0 or end_ts <= 0:
        raise HTTPException(status_code=400, detail="timestamps must be positive Unix seconds")
    if start_ts >= end_ts:
        raise HTTPException(status_code=400, detail="window_start must be less than window_end")
    if (end_ts - start_ts) > MAX_WINDOW_SECONDS:
        raise HTTPException(status_code=400, detail="time window cannot exceed 7 days")


def _cutoff_ts() -> int:
    return int(time.time()) - THIRTY_DAYS_SECONDS


def _severity_name_for_rank(rank: int) -> str:
    for name, r in SEVERITY_RANK.items():
        if r == rank:
            return name
    return "low"


# ---------------- Devices ----------------

@router.get("/devices", response_model=list[IoTDeviceOut])
async def list_devices(
    device_model: Optional[str] = Query(default=None, description="Filter by device model"),
    online_status: Optional[str] = Query(default=None, description="Filter by online/offline"),
):
    db = await get_db()
    try:
        sql = "SELECT * FROM iot_devices WHERE 1=1"
        params: list = []
        if device_model:
            sql += " AND device_model = ?"
            params.append(device_model)
        if online_status:
            if online_status not in ("online", "offline"):
                raise HTTPException(status_code=400, detail="online_status must be 'online' or 'offline'")
            sql += " AND online_status = ?"
            params.append(online_status)
        sql += " ORDER BY id ASC"
        rows = await db.execute_fetchall(sql, params)
    finally:
        await db.close()

    return [
        IoTDeviceOut(
            id=r["id"],
            device_sn=r["device_sn"],
            device_model=r["device_model"],
            firmware_version=r["firmware_version"] or "",
            online_status=r["online_status"],
            created_at=r["created_at"] or "",
        )
        for r in rows
    ]


# ---------------- Alert Submission ----------------

@router.post("/submit", response_model=AlertBatchSubmitResult)
async def submit_alerts(body: IoTAlertBatchCreate):
    if len(body.alerts) > MAX_BATCH_ALERTS:
        raise HTTPException(
            status_code=400,
            detail=f"maximum {MAX_BATCH_ALERTS} alerts per batch",
        )

    submitted = 0
    deduplicated = 0
    rejected = 0
    errors: list[str] = []
    cutoff = _cutoff_ts()

    db = await get_db()
    try:
        await db.execute("BEGIN")
        for idx, alert in enumerate(body.alerts):
            if alert.alert_type not in ALERT_TYPES:
                rejected += 1
                errors.append(f"alert[{idx}]: invalid alert_type '{alert.alert_type}'")
                continue
            if alert.severity not in ALERT_SEVERITIES:
                rejected += 1
                errors.append(f"alert[{idx}]: invalid severity '{alert.severity}'")
                continue
            if not alert.device_sn.strip():
                rejected += 1
                errors.append(f"alert[{idx}]: device_sn cannot be empty")
                continue
            if alert.timestamp < cutoff:
                rejected += 1
                errors.append(f"alert[{idx}]: timestamp older than 30 days")
                continue

            second_bucket = alert.timestamp
            dedup_key = f"{alert.device_sn}|{alert.alert_type}|{second_bucket}"

            try:
                cursor = await db.execute(
                    """
                    INSERT INTO iot_alerts (device_sn, alert_type, severity, timestamp, extra_info, dedup_key)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.device_sn.strip(),
                        alert.alert_type,
                        alert.severity,
                        alert.timestamp,
                        alert.extra_info or "",
                        dedup_key,
                    ),
                )
                if cursor.lastrowid:
                    submitted += 1
            except Exception as e:
                if "UNIQUE constraint failed" in str(e) or "dedup_key" in str(e).lower():
                    deduplicated += 1
                else:
                    rejected += 1
                    errors.append(f"alert[{idx}]: db error - {e}")
        await db.commit()
    finally:
        await db.close()

    return AlertBatchSubmitResult(
        submitted=submitted,
        deduplicated=deduplicated,
        rejected=rejected,
        errors=errors,
    )


# ---------------- Alert Query ----------------

@router.get("/alerts", response_model=list[IoTAlertOut])
async def query_alerts(
    device_sn: Optional[str] = Query(default=None, description="Filter by device SN"),
    alert_type: Optional[str] = Query(default=None, description="Filter by alert type"),
    severity: Optional[str] = Query(default=None, description="Filter by severity"),
    time_start: Optional[int] = Query(default=None, description="Start timestamp (inclusive), Unix seconds"),
    time_end: Optional[int] = Query(default=None, description="End timestamp (inclusive), Unix seconds"),
    limit: int = Query(default=200, ge=1, le=1000, description="Max records to return"),
    offset: int = Query(default=0, ge=0),
):
    if alert_type and alert_type not in ALERT_TYPES:
        raise HTTPException(status_code=400, detail=f"invalid alert_type, must be one of {ALERT_TYPES}")
    if severity and severity not in ALERT_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"invalid severity, must be one of {ALERT_SEVERITIES}")

    cutoff = _cutoff_ts()
    effective_start = max(time_start or 0, cutoff)

    db = await get_db()
    try:
        sql = [
            "SELECT a.*, d.device_model AS device_model",
            "FROM iot_alerts a LEFT JOIN iot_devices d ON a.device_sn = d.device_sn",
            "WHERE a.timestamp >= ?",
        ]
        params: list = [effective_start]

        if time_end is not None:
            sql.append("AND a.timestamp <= ?")
            params.append(time_end)
        if device_sn:
            sql.append("AND a.device_sn = ?")
            params.append(device_sn)
        if alert_type:
            sql.append("AND a.alert_type = ?")
            params.append(alert_type)
        if severity:
            sql.append("AND a.severity = ?")
            params.append(severity)

        sql.append("ORDER BY a.timestamp DESC, a.id DESC LIMIT ? OFFSET ?")
        params.extend([limit, offset])

        rows = await db.execute_fetchall(" ".join(sql), params)
    finally:
        await db.close()

    return [
        IoTAlertOut(
            id=r["id"],
            device_sn=r["device_sn"],
            device_model=r["device_model"] if "device_model" in r.keys() else None,
            alert_type=r["alert_type"],
            severity=r["severity"],
            timestamp=r["timestamp"],
            extra_info=r["extra_info"] or "",
            created_at=r["created_at"] or "",
        )
        for r in rows
    ]


# ---------------- Alert Aggregation ----------------

@router.get("/aggregate", response_model=AlertAggregationResult)
async def aggregate_alerts(
    window_start: int = Query(..., description="Window start timestamp, Unix seconds"),
    window_end: int = Query(..., description="Window end timestamp, Unix seconds"),
    device_model: Optional[str] = Query(default=None, description="Optional device model filter"),
):
    _validate_time_window(window_start, window_end)
    cutoff = _cutoff_ts()
    effective_start = max(window_start, cutoff)

    db = await get_db()
    try:
        sql = [
            "SELECT a.*, d.device_model AS device_model",
            "FROM iot_alerts a LEFT JOIN iot_devices d ON a.device_sn = d.device_sn",
            "WHERE a.timestamp >= ? AND a.timestamp <= ?",
        ]
        params: list = [effective_start, window_end]
        if device_model:
            sql.append("AND d.device_model = ?")
            params.append(device_model)
        rows = await db.execute_fetchall(" ".join(sql), params)
    finally:
        await db.close()

    groups: dict[str, dict] = {}
    for r in rows:
        at = r["alert_type"]
        if at not in groups:
            groups[at] = {
                "count": 0,
                "devices": set(),
                "max_sev_rank": 0,
                "first": r["timestamp"],
                "last": r["timestamp"],
            }
        g = groups[at]
        g["count"] += 1
        g["devices"].add(r["device_sn"])
        sev_rank = SEVERITY_RANK.get(r["severity"], 1)
        if sev_rank > g["max_sev_rank"]:
            g["max_sev_rank"] = sev_rank
        if r["timestamp"] < g["first"]:
            g["first"] = r["timestamp"]
        if r["timestamp"] > g["last"]:
            g["last"] = r["timestamp"]

    entries = [
        AlertAggregationEntry(
            alert_type=at,
            count=g["count"],
            device_count=len(g["devices"]),
            max_severity=_severity_name_for_rank(g["max_sev_rank"]),
            first_seen=g["first"],
            last_seen=g["last"],
        )
        for at, g in groups.items()
    ]
    entries.sort(key=lambda e: (-e.count, e.alert_type))

    total = sum(e.count for e in entries)
    return AlertAggregationResult(
        window_start=window_start,
        window_end=window_end,
        device_model_filter=device_model,
        total_alerts=total,
        aggregations=entries,
    )


# ---------------- Pattern Analysis ----------------

@router.get("/patterns", response_model=PatternAnalysisResult)
async def analyze_patterns(
    window_start: int = Query(..., description="Window start timestamp, Unix seconds"),
    window_end: int = Query(..., description="Window end timestamp, Unix seconds"),
):
    _validate_time_window(window_start, window_end)
    now = int(time.time())
    cutoff = _cutoff_ts()
    effective_start = max(window_start, cutoff)

    matches: list[PatternMatch] = []

    db = await get_db()
    try:
        # ---------- Load all alerts in window ----------
        window_rows = await db.execute_fetchall(
            """
            SELECT a.*, d.device_model AS device_model
            FROM iot_alerts a LEFT JOIN iot_devices d ON a.device_sn = d.device_sn
            WHERE a.timestamp >= ? AND a.timestamp <= ?
            """,
            (effective_start, window_end),
        )

        # ---------- Spike detection ----------
        SPIKE_THRESHOLD = 5.0
        last_hour_start = max(window_end - 3600, cutoff)
        prev_24h_end = last_hour_start
        prev_24h_start = max(prev_24h_end - 24 * 3600, cutoff)

        if prev_24h_end > prev_24h_start:
            last_hour_rows = await db.execute_fetchall(
                "SELECT alert_type, COUNT(*) as cnt FROM iot_alerts WHERE timestamp >= ? AND timestamp < ? GROUP BY alert_type",
                (last_hour_start, window_end + 1),
            )
            prev_24h_rows = await db.execute_fetchall(
                "SELECT alert_type, COUNT(*) as cnt FROM iot_alerts WHERE timestamp >= ? AND timestamp < ? GROUP BY alert_type",
                (prev_24h_start, prev_24h_end),
            )

            lh_counts = {r["alert_type"]: r["cnt"] for r in last_hour_rows}
            p24_counts = {r["alert_type"]: r["cnt"] for r in prev_24h_rows}

            all_types_in_scope = set(lh_counts.keys()) | set(p24_counts.keys())
            for at in all_types_in_scope:
                lh = lh_counts.get(at, 0)
                p24 = p24_counts.get(at, 0)
                p24_avg = p24 / 24.0
                if p24_avg > 0 and lh >= SPIKE_THRESHOLD * p24_avg:
                    matches.append(
                        PatternMatchSpike(
                            pattern_type="spike",
                            alert_type=at,
                            last_hour_count=lh,
                            prev_24h_avg=round(p24_avg, 3),
                            ratio=round(lh / p24_avg, 3),
                        )
                    )
                elif p24_avg == 0 and lh > 0:
                    matches.append(
                        PatternMatchSpike(
                            pattern_type="spike",
                            alert_type=at,
                            last_hour_count=lh,
                            prev_24h_avg=0.0,
                            ratio=999.0,
                        )
                    )

        # ---------- Spread detection ----------
        SPREAD_THRESHOLD = 0.3
        all_device_rows = await db.execute_fetchall(
            "SELECT device_model, device_sn FROM iot_devices ORDER BY device_model, id"
        )
        model_total: dict[str, set[str]] = defaultdict(set)
        for r in all_device_rows:
            model_total[r["device_model"]].add(r["device_sn"])

        model_alert_devices: dict[tuple[str, str], set[str]] = defaultdict(set)
        for r in window_rows:
            dm = r["device_model"] or "unknown"
            model_alert_devices[(dm, r["alert_type"])].add(r["device_sn"])

        for (dm, at), devs in model_alert_devices.items():
            total = len(model_total.get(dm, set()))
            if total == 0:
                continue
            ratio = len(devs) / total
            if ratio >= SPREAD_THRESHOLD:
                matches.append(
                    PatternMatchSpread(
                        pattern_type="spread",
                        alert_type=at,
                        device_model=dm,
                        affected_devices=len(devs),
                        total_devices=total,
                        ratio=round(ratio, 3),
                        affected_device_sns=sorted(devs),
                    )
                )

        # ---------- Correlation detection ----------
        CORR_WINDOW_SEC = 10 * 60
        CORR_MIN_TYPES = 2
        device_alerts: dict[str, list[tuple[int, str]]] = defaultdict(list)
        for r in window_rows:
            device_alerts[r["device_sn"]].append((r["timestamp"], r["alert_type"]))

        device_model_map: dict[str, str] = {r["device_sn"]: (r["device_model"] or "unknown") for r in all_device_rows}

        for ds, events in device_alerts.items():
            events.sort()
            n = len(events)
            matched_already = False
            for i in range(n):
                window_types: set[str] = set()
                window_types.add(events[i][1])
                for j in range(i + 1, n):
                    if events[j][0] - events[i][0] > CORR_WINDOW_SEC:
                        break
                    window_types.add(events[j][1])
                if len(window_types) > CORR_MIN_TYPES:
                    matches.append(
                        PatternMatchCorrelation(
                            pattern_type="correlation",
                            device_sn=ds,
                            device_model=device_model_map.get(ds, "unknown"),
                            alert_types=sorted(window_types),
                        )
                    )
                    matched_already = True
                    break
                if matched_already:
                    break
    finally:
        await db.close()

    return PatternAnalysisResult(
        window_start=window_start,
        window_end=window_end,
        matches=matches,
    )


# ---------------- Upgrade Decision ----------------

@router.get("/decision", response_model=UpgradeDecisionResult)
async def upgrade_decision(
    window_start: int = Query(..., description="Window start timestamp, Unix seconds"),
    window_end: int = Query(..., description="Window end timestamp, Unix seconds"),
):
    pattern_result = await analyze_patterns(window_start, window_end)
    matches = pattern_result.matches

    recommendations: list[UpgradeRecommendation] = []

    has_emergency_fw_spread = False
    emergency_devices: set[str] = set()
    emergency_reasons: list[str] = []

    has_reboot_spike = False
    reboot_spike_reasons: list[str] = []

    monitor_patterns: list[str] = []
    monitor_devices: set[str] = set()
    monitor_reasons: list[str] = []

    for m in matches:
        if isinstance(m, PatternMatchSpread):
            if m.alert_type == "firmware_checksum_fail":
                has_emergency_fw_spread = True
                emergency_devices.update(m.affected_device_sns)
                emergency_reasons.append(
                    f"firmware_checksum_fail扩散: 型号{m.device_model}受影响设备{m.affected_devices}/{m.total_devices} "
                    f"({int(m.ratio*100)}%)"
                )
            else:
                monitor_patterns.append(f"spread:{m.alert_type}@{m.device_model}")
                monitor_devices.update(m.affected_device_sns)
                monitor_reasons.append(
                    f"{m.alert_type}扩散: {m.device_model} {m.affected_devices}/{m.total_devices}"
                )
        elif isinstance(m, PatternMatchSpike):
            if m.alert_type == "reboot_loop":
                has_reboot_spike = True
                reboot_spike_reasons.append(
                    f"reboot_loop突增: 最近1小时{m.last_hour_count}条, 前24h均值{m.prev_24h_avg}, 倍数{m.ratio}x"
                )
            else:
                monitor_patterns.append(f"spike:{m.alert_type}")
                monitor_reasons.append(
                    f"{m.alert_type}突增: {m.last_hour_count}条 vs 均值{m.prev_24h_avg} ({m.ratio}x)"
                )
        elif isinstance(m, PatternMatchCorrelation):
            monitor_patterns.append(f"correlation:{m.device_sn}")
            monitor_devices.add(m.device_sn)
            monitor_reasons.append(
                f"{m.device_sn}关联告警: 10分钟内出现{len(m.alert_types)}种告警类型({','.join(m.alert_types)})"
            )

    if has_emergency_fw_spread:
        recommendations.append(
            UpgradeRecommendation(
                recommendation_type="emergency_firmware_upgrade",
                priority="high",
                reason="; ".join(emergency_reasons),
                device_sns=sorted(emergency_devices),
                triggered_patterns=[p for p in monitor_patterns if "firmware_checksum_fail" in p] + ["spread:firmware_checksum_fail"],
            )
        )

    if has_reboot_spike:
        recommendations.append(
            UpgradeRecommendation(
                recommendation_type="upgrade_after_investigation",
                priority="medium",
                reason="; ".join(reboot_spike_reasons),
                device_sns=sorted(monitor_devices),
                triggered_patterns=["spike:reboot_loop"],
            )
        )

    if monitor_reasons:
        filtered_reasons = [r for r in monitor_reasons if "firmware_checksum_fail扩散" not in r]
        filtered_patterns = [p for p in monitor_patterns if "firmware_checksum_fail" not in p]
        if filtered_reasons or filtered_patterns:
            recommendations.append(
                UpgradeRecommendation(
                    recommendation_type="monitor_only",
                    priority="low",
                    reason="; ".join(filtered_reasons) if filtered_reasons else "检测到其他模式",
                    device_sns=sorted(monitor_devices - emergency_devices),
                    triggered_patterns=filtered_patterns,
                )
            )

    return UpgradeDecisionResult(
        window_start=window_start,
        window_end=window_end,
        recommendations=recommendations,
    )
