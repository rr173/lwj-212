import json
import math
from collections import Counter
from fastapi import APIRouter, HTTPException
from app.models import (
    FieldDef,
    ParseResult,
    BaselineCreateRequest,
    BaselineSnapshotOut,
    BaselineSnapshotDetailOut,
    BaselineTrainResult,
    AnomalyDetectRequest,
    AnomalyDetectResult,
    FieldDeviationDetail,
    BatchDetectRequest,
    BatchDetectResult,
    BatchDetectItem,
    BatchDetectSummary,
    BaselineCompareRequest,
    BaselineCompareResult,
    NumericFieldStats,
    BytesFieldStats,
    NumericFieldDrift,
    BytesFieldDrift,
    NUMERIC_FIELD_TYPES,
    BYTES_FIELD_TYPES,
    TOP_FREQUENCY_COUNT,
    MIN_TRAIN_SAMPLES,
    MAX_TRAIN_SAMPLES,
    MAX_BATCH_DETECT_SAMPLES,
    ANOMALY_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    NUMERIC_FIELD_WEIGHT,
    LENGTH_FIELD_WEIGHT,
    RARE_VALUE_PENALTY,
    PARSE_ERROR_PENALTY,
)
from app.database import get_db
from app.utils import hex_to_bytes, validate_hex
from app.parser import parse_message

router = APIRouter(prefix="/api/baselines", tags=["baselines"])


async def _get_template_fields(template_id: int, version: int | None = None):
    db = await get_db()
    try:
        if version is not None:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
                (template_id, version),
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail="template version not found")
            actual_version = version
        else:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM templates WHERE id = ?", (template_id,)
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail="template not found")
            v_rows = await db.execute_fetchall(
                "SELECT MAX(version) as max_version FROM template_versions WHERE template_id = ?",
                (template_id,),
            )
            actual_version = v_rows[0]["max_version"] or 1
    finally:
        await db.close()

    fields = [FieldDef(**f) for f in json.loads(t_rows[0]["fields_json"])]
    return fields, actual_version


async def _fetch_samples(sample_ids: list[int]) -> list[dict]:
    if not sample_ids:
        return []
    db = await get_db()
    try:
        placeholders = ",".join("?" for _ in sample_ids)
        rows = await db.execute_fetchall(
            f"SELECT id, name, hex_data FROM samples WHERE id IN ({placeholders})",
            sample_ids,
        )
    finally:
        await db.close()
    return [{"id": r["id"], "name": r["name"], "hex_data": r["hex_data"]} for r in rows]


async def _get_baseline(baseline_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM baseline_snapshots WHERE id = ?",
            (baseline_id,),
        )
        if not rows:
            raise HTTPException(status_code=404, detail="baseline not found")
        row = rows[0]
        fields_stats = json.loads(row["fields_stats_json"])
    finally:
        await db.close()
    return row, fields_stats


def _compute_numeric_stats(field_name: str, values: list[float]) -> NumericFieldStats:
    n = len(values)
    if n == 0:
        return NumericFieldStats(
            field_name=field_name,
            sample_count=0,
            mean=0.0,
            std_dev=0.0,
            min_value=0.0,
            max_value=0.0,
        )
    mean = sum(values) / n
    if n == 1:
        variance = 0.0
    else:
        variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    std_dev = math.sqrt(variance)
    return NumericFieldStats(
        field_name=field_name,
        sample_count=n,
        mean=round(mean, 6),
        std_dev=round(std_dev, 6),
        min_value=min(values),
        max_value=max(values),
    )


def _compute_bytes_stats(field_name: str, values: list[tuple[str, int]]) -> BytesFieldStats:
    n = len(values)
    if n == 0:
        return BytesFieldStats(
            field_name=field_name,
            sample_count=0,
            length_mean=0.0,
            length_std_dev=0.0,
            length_min=0,
            length_max=0,
            top_values=[],
        )
    lengths = [v[1] for v in values]
    length_mean = sum(lengths) / n
    if n == 1:
        length_variance = 0.0
    else:
        length_variance = sum((l - length_mean) ** 2 for l in lengths) / (n - 1)
    length_std_dev = math.sqrt(length_variance)

    val_counter = Counter(v[0] for v in values)
    top_items = val_counter.most_common(TOP_FREQUENCY_COUNT)
    top_values = [{"value": val, "count": cnt} for val, cnt in top_items]

    return BytesFieldStats(
        field_name=field_name,
        sample_count=n,
        length_mean=round(length_mean, 6),
        length_std_dev=round(length_std_dev, 6),
        length_min=min(lengths),
        length_max=max(lengths),
        top_values=top_values,
    )


@router.post("/train", response_model=BaselineTrainResult)
async def train_baseline(body: BaselineCreateRequest):
    if len(body.sample_ids) < MIN_TRAIN_SAMPLES:
        raise HTTPException(
            status_code=400,
            detail=f"at least {MIN_TRAIN_SAMPLES} samples required for training",
        )
    if len(body.sample_ids) > MAX_TRAIN_SAMPLES:
        raise HTTPException(
            status_code=400,
            detail=f"maximum {MAX_TRAIN_SAMPLES} samples allowed for training",
        )

    fields, actual_version = await _get_template_fields(body.template_id, body.template_version)
    field_defs_by_name = {f.name: f for f in fields}

    sample_map = await _fetch_samples(body.sample_ids)
    found_ids = {s["id"] for s in sample_map}
    missing_ids = [sid for sid in body.sample_ids if sid not in found_ids]
    if missing_ids:
        raise HTTPException(
            status_code=404,
            detail=f"samples not found: {missing_ids}",
        )

    raw_by_id: dict[int, bytes] = {}
    for s in sample_map:
        raw_by_id[s["id"]] = hex_to_bytes(s["hex_data"])

    numeric_values: dict[str, list[float]] = {}
    bytes_values: dict[str, list[tuple[str, int]]] = {}
    for f in fields:
        if f.data_type in NUMERIC_FIELD_TYPES:
            numeric_values[f.name] = []
        elif f.data_type in BYTES_FIELD_TYPES:
            bytes_values[f.name] = []

    skipped_ids: list[int] = []
    trained_ids: list[int] = []

    for sid in body.sample_ids:
        raw = raw_by_id[sid]
        result = parse_message(raw, fields, body.template_id, sid, actual_version)

        has_error = any(f.status == "parse_error" for f in result.fields)
        if has_error:
            skipped_ids.append(sid)
            continue

        trained_ids.append(sid)
        parsed_by_name = {f.name: f for f in result.fields if f.status == "ok"}

        for f_name in numeric_values:
            pf = parsed_by_name.get(f_name)
            if pf and pf.value is not None:
                try:
                    numeric_values[f_name].append(float(pf.value))
                except (ValueError, TypeError):
                    pass

        for f_name in bytes_values:
            pf = parsed_by_name.get(f_name)
            if pf and pf.value is not None:
                bytes_values[f_name].append((pf.value, pf.length))

    if len(trained_ids) < MIN_TRAIN_SAMPLES:
        raise HTTPException(
            status_code=400,
            detail=f"only {len(trained_ids)} valid samples after skipping parse errors, need at least {MIN_TRAIN_SAMPLES}",
        )

    fields_stats_list: list[dict] = []
    for f in fields:
        if f.data_type in NUMERIC_FIELD_TYPES:
            stats = _compute_numeric_stats(f.name, numeric_values[f.name])
            fields_stats_list.append(stats.model_dump())
        elif f.data_type in BYTES_FIELD_TYPES:
            stats = _compute_bytes_stats(f.name, bytes_values[f.name])
            fields_stats_list.append(stats.model_dump())

    fields_stats_json = json.dumps(fields_stats_list)

    db = await get_db()
    try:
        cursor = await db.execute(
            """
            INSERT INTO baseline_snapshots 
            (template_id, template_version, name, description, sample_count, skipped_count, fields_stats_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                body.template_id,
                actual_version,
                body.name,
                body.description,
                len(trained_ids),
                len(skipped_ids),
                fields_stats_json,
            ),
        )
        baseline_id = cursor.lastrowid

        row = await db.execute_fetchall(
            "SELECT created_at FROM baseline_snapshots WHERE id = ?",
            (baseline_id,),
        )
        created_at = row[0]["created_at"]

        await db.commit()
    finally:
        await db.close()

    return BaselineTrainResult(
        baseline_id=baseline_id,
        template_id=body.template_id,
        template_version=actual_version,
        total_samples=len(body.sample_ids),
        trained_samples=len(trained_ids),
        skipped_samples=len(skipped_ids),
        skipped_sample_ids=skipped_ids,
        created_at=created_at,
    )


@router.get("/{baseline_id}", response_model=BaselineSnapshotDetailOut)
async def get_baseline(baseline_id: int):
    row, fields_stats_raw = await _get_baseline(baseline_id)

    fields_stats = []
    for fs in fields_stats_raw:
        if fs.get("field_type") == "numeric":
            fields_stats.append(NumericFieldStats(**fs))
        elif fs.get("field_type") == "bytes":
            fields_stats.append(BytesFieldStats(**fs))

    return BaselineSnapshotDetailOut(
        id=row["id"],
        template_id=row["template_id"],
        template_version=row["template_version"],
        name=row["name"],
        description=row["description"],
        sample_count=row["sample_count"],
        skipped_count=row["skipped_count"],
        created_at=row["created_at"],
        fields_stats=fields_stats,
    )


@router.get("/template/{template_id}", response_model=list[BaselineSnapshotOut])
async def list_baselines_by_template(template_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM baseline_snapshots WHERE template_id = ? ORDER BY created_at DESC",
            (template_id,),
        )
    finally:
        await db.close()

    return [
        BaselineSnapshotOut(
            id=r["id"],
            template_id=r["template_id"],
            template_version=r["template_version"],
            name=r["name"],
            description=r["description"],
            sample_count=r["sample_count"],
            skipped_count=r["skipped_count"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


@router.delete("/{baseline_id}")
async def delete_baseline(baseline_id: int):
    db = await get_db()
    try:
        await db.execute(
            "DELETE FROM baseline_snapshots WHERE id = ?",
            (baseline_id,),
        )
        await db.commit()
    finally:
        await db.close()
    return {"status": "ok", "deleted_id": baseline_id}


def _compute_z_score(value: float, mean: float, std_dev: float) -> float:
    if std_dev == 0:
        if value == mean:
            return 0.0
        else:
            return 10.0
    return (value - mean) / std_dev


def _detect_anomaly_for_fields(
    parse_result: ParseResult,
    fields_stats: list[dict],
) -> tuple[list[FieldDeviationDetail], float]:
    stats_by_name: dict[str, dict] = {fs["field_name"]: fs for fs in fields_stats}
    parsed_by_name: dict[str, object] = {f.name: f for f in parse_result.fields}

    deviations: list[FieldDeviationDetail] = []
    total_score = 0.0
    total_weight = 0.0

    for field_name, stats in stats_by_name.items():
        pf = parsed_by_name.get(field_name)
        field_type = stats.get("field_type", "numeric")

        if pf is None:
            deviations.append(
                FieldDeviationDetail(
                    field_name=field_name,
                    field_type=field_type,
                    value=None,
                    z_score=None,
                    length_z_score=None,
                    is_rare_value=False,
                    deviation_score=0.0,
                )
            )
            continue

        if pf.status == "parse_error":
            deviation_score = PARSE_ERROR_PENALTY
            weight = NUMERIC_FIELD_WEIGHT if field_type == "numeric" else LENGTH_FIELD_WEIGHT
            deviations.append(
                FieldDeviationDetail(
                    field_name=field_name,
                    field_type=field_type,
                    value=pf.value,
                    z_score=None,
                    length_z_score=None,
                    is_rare_value=False,
                    deviation_score=round(deviation_score * weight, 4),
                )
            )
            total_score += deviation_score * weight
            total_weight += weight
            continue

        if pf.value is None:
            deviations.append(
                FieldDeviationDetail(
                    field_name=field_name,
                    field_type=field_type,
                    value=None,
                    z_score=None,
                    length_z_score=None,
                    is_rare_value=False,
                    deviation_score=0.0,
                )
            )
            continue

        if field_type == "numeric":
            try:
                val = float(pf.value)
            except (ValueError, TypeError):
                deviations.append(
                    FieldDeviationDetail(
                        field_name=field_name,
                        field_type=field_type,
                        value=pf.value,
                        z_score=None,
                        length_z_score=None,
                        is_rare_value=False,
                        deviation_score=0.0,
                    )
                )
                continue

            z_score = _compute_z_score(val, stats["mean"], stats["std_dev"])
            deviation_score = abs(z_score) * NUMERIC_FIELD_WEIGHT

            deviations.append(
                FieldDeviationDetail(
                    field_name=field_name,
                    field_type=field_type,
                    value=pf.value,
                    z_score=round(z_score, 4),
                    length_z_score=None,
                    is_rare_value=False,
                    deviation_score=round(deviation_score, 4),
                )
            )
            total_score += deviation_score
            total_weight += NUMERIC_FIELD_WEIGHT

        elif field_type == "bytes":
            length_z_score = _compute_z_score(
                float(pf.length), stats["length_mean"], stats["length_std_dev"]
            )
            length_score = abs(length_z_score) * LENGTH_FIELD_WEIGHT

            top_values = {item["value"] for item in stats.get("top_values", [])}
            is_rare = pf.value not in top_values

            rare_penalty = RARE_VALUE_PENALTY if is_rare else 0.0
            deviation_score = length_score + rare_penalty

            deviations.append(
                FieldDeviationDetail(
                    field_name=field_name,
                    field_type=field_type,
                    value=pf.value,
                    z_score=None,
                    length_z_score=round(length_z_score, 4),
                    is_rare_value=is_rare,
                    deviation_score=round(deviation_score, 4),
                )
            )
            total_score += deviation_score
            total_weight += LENGTH_FIELD_WEIGHT

    overall_score = total_score / total_weight if total_weight > 0 else 0.0
    overall_score = round(overall_score, 4)

    return deviations, overall_score


def _classify_level(score: float) -> str:
    if score >= ANOMALY_THRESHOLD:
        return "anomaly"
    elif score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    else:
        return "normal"


@router.post("/detect", response_model=AnomalyDetectResult)
async def detect_anomaly(body: AnomalyDetectRequest):
    if body.sample_id is None and body.hex_data is None:
        raise HTTPException(
            status_code=400,
            detail="either sample_id or hex_data must be provided",
        )

    row, fields_stats = await _get_baseline(body.baseline_id)
    template_id = row["template_id"]
    template_version = row["template_version"]

    fields, _ = await _get_template_fields(template_id, template_version)

    if body.sample_id is not None:
        sample_map = await _fetch_samples([body.sample_id])
        if not sample_map:
            raise HTTPException(status_code=404, detail="sample not found")
        hex_data = sample_map[0]["hex_data"]
    else:
        try:
            hex_data = validate_hex(body.hex_data)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid hex data: {e}")

    raw = hex_to_bytes(hex_data)
    parse_result = parse_message(raw, fields, template_id, body.sample_id or 0, template_version)

    deviations, overall_score = _detect_anomaly_for_fields(parse_result, fields_stats)
    level = _classify_level(overall_score)

    return AnomalyDetectResult(
        baseline_id=body.baseline_id,
        sample_id=body.sample_id,
        template_id=template_id,
        template_version=template_version,
        overall_score=overall_score,
        level=level,
        field_deviations=deviations,
        parse_result=parse_result,
    )


@router.post("/batch-detect", response_model=BatchDetectResult)
async def batch_detect_anomaly(body: BatchDetectRequest):
    if len(body.sample_ids) > MAX_BATCH_DETECT_SAMPLES:
        raise HTTPException(
            status_code=400,
            detail=f"maximum {MAX_BATCH_DETECT_SAMPLES} samples allowed for batch detection",
        )

    row, fields_stats = await _get_baseline(body.baseline_id)
    template_id = row["template_id"]
    template_version = row["template_version"]

    fields, _ = await _get_template_fields(template_id, template_version)

    sample_map = await _fetch_samples(body.sample_ids)
    found_ids = {s["id"] for s in sample_map}
    missing_ids = [sid for sid in body.sample_ids if sid not in found_ids]
    if missing_ids:
        raise HTTPException(
            status_code=404,
            detail=f"samples not found: {missing_ids}",
        )

    sample_by_id = {s["id"]: s for s in sample_map}
    results: list[BatchDetectItem] = []

    anomaly_count = 0
    suspicious_count = 0
    normal_count = 0
    total_score = 0.0
    max_score = -1.0
    max_score_sample_id = None

    for sid in body.sample_ids:
        sample = sample_by_id[sid]
        raw = hex_to_bytes(sample["hex_data"])
        parse_result = parse_message(raw, fields, template_id, sid, template_version)

        deviations, overall_score = _detect_anomaly_for_fields(parse_result, fields_stats)
        level = _classify_level(overall_score)

        if level == "anomaly":
            anomaly_count += 1
        elif level == "suspicious":
            suspicious_count += 1
        else:
            normal_count += 1

        total_score += overall_score
        if overall_score > max_score:
            max_score = overall_score
            max_score_sample_id = sid

        top_devs = sorted(deviations, key=lambda d: d.deviation_score, reverse=True)[:5]

        results.append(
            BatchDetectItem(
                sample_id=sid,
                sample_name=sample["name"],
                overall_score=overall_score,
                level=level,
                top_deviations=top_devs,
            )
        )

    results.sort(key=lambda r: r.overall_score, reverse=True)
    total_samples = len(body.sample_ids)
    avg_score = round(total_score / total_samples, 4) if total_samples > 0 else 0.0

    summary = BatchDetectSummary(
        total_samples=total_samples,
        anomaly_count=anomaly_count,
        suspicious_count=suspicious_count,
        normal_count=normal_count,
        avg_score=avg_score,
        max_score=round(max_score, 4) if max_score >= 0 else 0.0,
        max_score_sample_id=max_score_sample_id,
    )

    return BatchDetectResult(
        baseline_id=body.baseline_id,
        summary=summary,
        results=results,
    )


@router.post("/compare", response_model=BaselineCompareResult)
async def compare_baselines(body: BaselineCompareRequest):
    row_a, stats_a_raw = await _get_baseline(body.baseline_a_id)
    row_b, stats_b_raw = await _get_baseline(body.baseline_b_id)

    if row_a["template_id"] != row_b["template_id"]:
        raise HTTPException(
            status_code=400,
            detail="both baselines must be associated with the same template",
        )

    template_id = row_a["template_id"]
    template_version = max(row_a["template_version"], row_b["template_version"])

    stats_a_by_name = {s["field_name"]: s for s in stats_a_raw}
    stats_b_by_name = {s["field_name"]: s for s in stats_b_raw}

    all_field_names = set(stats_a_by_name.keys()) | set(stats_b_by_name.keys())

    field_drifts: list[dict] = []
    significant_count = 0
    moderate_count = 0
    stable_count = 0

    for field_name in sorted(all_field_names):
        sa = stats_a_by_name.get(field_name)
        sb = stats_b_by_name.get(field_name)

        if sa is None or sb is None:
            continue

        field_type = sa.get("field_type", "numeric")

        if field_type == "numeric":
            mean_a = sa["mean"]
            mean_b = sb["mean"]
            std_a = sa["std_dev"]
            std_b = sb["std_dev"]

            mean_shift = mean_b - mean_a
            if std_a == 0:
                mean_shift_std_units = 0.0 if mean_shift == 0 else 10.0
            else:
                mean_shift_std_units = abs(mean_shift) / std_a

            if std_a == 0 and std_b == 0:
                std_change_ratio = 1.0
            elif std_a == 0:
                std_change_ratio = float("inf") if std_b > 0 else 1.0
            else:
                std_change_ratio = std_b / std_a

            if mean_shift_std_units >= 2.0:
                drift_level = "significant"
                significant_count += 1
            elif mean_shift_std_units >= 1.0:
                drift_level = "moderate"
                moderate_count += 1
            else:
                drift_level = "stable"
                stable_count += 1

            field_drifts.append(
                NumericFieldDrift(
                    field_name=field_name,
                    mean_a=mean_a,
                    mean_b=mean_b,
                    mean_shift=round(mean_shift, 6),
                    mean_shift_std_units=round(mean_shift_std_units, 4),
                    std_dev_a=std_a,
                    std_dev_b=std_b,
                    std_dev_change_ratio=round(std_change_ratio, 4) if std_change_ratio != float("inf") else float("inf"),
                    drift_level=drift_level,
                ).model_dump()
            )

        elif field_type == "bytes":
            len_mean_a = sa["length_mean"]
            len_mean_b = sb["length_mean"]
            len_std_a = sa["length_std_dev"]

            if len_std_a == 0:
                len_shift_std_units = 0.0 if len_mean_b == len_mean_a else 10.0
            else:
                len_shift_std_units = abs(len_mean_b - len_mean_a) / len_std_a

            top_a_vals = {item["value"] for item in sa.get("top_values", [])}
            top_b_vals = {item["value"] for item in sb.get("top_values", [])}
            overlap = top_a_vals & top_b_vals
            overlap_count = len(overlap)
            union_count = len(top_a_vals | top_b_vals)
            overlap_ratio = overlap_count / union_count if union_count > 0 else 0.0

            if len_shift_std_units >= 2.0 or overlap_ratio < 0.3:
                drift_level = "significant"
                significant_count += 1
            elif len_shift_std_units >= 1.0 or overlap_ratio < 0.6:
                drift_level = "moderate"
                moderate_count += 1
            else:
                drift_level = "stable"
                stable_count += 1

            field_drifts.append(
                BytesFieldDrift(
                    field_name=field_name,
                    length_mean_a=len_mean_a,
                    length_mean_b=len_mean_b,
                    length_mean_shift_std_units=round(len_shift_std_units, 4),
                    top_values_a=sorted(list(top_a_vals)),
                    top_values_b=sorted(list(top_b_vals)),
                    overlap_count=overlap_count,
                    overlap_ratio=round(overlap_ratio, 4),
                    drift_level=drift_level,
                ).model_dump()
            )

    return BaselineCompareResult(
        baseline_a_id=body.baseline_a_id,
        baseline_b_id=body.baseline_b_id,
        template_id=template_id,
        template_version=template_version,
        sample_count_a=row_a["sample_count"],
        sample_count_b=row_b["sample_count"],
        significant_drift_count=significant_count,
        moderate_drift_count=moderate_count,
        stable_count=stable_count,
        field_drifts=field_drifts,
    )
