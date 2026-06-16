import json
from collections import Counter
from fastapi import APIRouter, HTTPException
from app.models import (
    ByteHeatmapRequest,
    ByteHeatmapEntry,
    ByteHeatmapResult,
    FieldMutationRequest,
    FieldMutationEntry,
    FieldMutationResult,
    FixedHeaderRequest,
    FixedHeaderRegion,
    FixedHeaderResult,
    FieldDef,
)
from app.database import get_db
from app.utils import hex_to_bytes
from app.parser import parse_message

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


async def _fetch_samples(sample_ids: list[int]) -> list[dict]:
    if not sample_ids:
        return []
    db = await get_db()
    try:
        placeholders = ",".join("?" for _ in sample_ids)
        rows = await db.execute_fetchall(
            f"SELECT id, hex_data FROM samples WHERE id IN ({placeholders})",
            sample_ids,
        )
    finally:
        await db.close()
    return [{"id": r["id"], "hex_data": r["hex_data"]} for r in rows]


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


@router.post("/byte-heatmap", response_model=ByteHeatmapResult)
async def byte_heatmap(body: ByteHeatmapRequest):
    sample_map = await _fetch_samples(body.sample_ids)

    found_ids = {s["id"] for s in sample_map}
    missing_ids = [sid for sid in body.sample_ids if sid not in found_ids]
    if missing_ids:
        raise HTTPException(
            status_code=404,
            detail=f"samples not found: {missing_ids}",
        )

    raw_samples: dict[int, bytes] = {}
    lengths: dict[int, int] = {}
    for s in sample_map:
        raw = hex_to_bytes(s["hex_data"])
        raw_samples[s["id"]] = raw
        lengths[s["id"]] = len(raw)

    max_len = max(lengths.values()) if lengths else 0
    total = len(raw_samples)

    heatmap: list[ByteHeatmapEntry] = []
    for offset in range(max_len):
        values: list[int] = []
        missing = 0
        for sid in body.sample_ids:
            raw = raw_samples[sid]
            if offset < len(raw):
                values.append(raw[offset])
            else:
                missing += 1

        counter = Counter(values)
        unique_count = len(counter)
        mode_val_int, mode_count = counter.most_common(1)[0] if counter else (0, 0)
        is_fixed = unique_count == 1 and len(values) == total

        heatmap.append(
            ByteHeatmapEntry(
                offset=offset,
                unique_count=unique_count,
                mode_value=f"0x{mode_val_int:02x}",
                mode_count=mode_count,
                is_fixed=is_fixed,
                total_samples=total,
                missing_count=missing,
            )
        )

    return ByteHeatmapResult(
        sample_ids=body.sample_ids,
        max_length=max_len,
        sample_lengths=lengths,
        total_samples=total,
        heatmap=heatmap,
    )


@router.post("/field-mutation", response_model=FieldMutationResult)
async def field_mutation(body: FieldMutationRequest):
    fields, actual_version = await _get_template_fields(body.template_id, body.template_version)
    field_order = [f.name for f in fields]

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

    field_values: dict[str, list[str]] = {name: [] for name in field_order}
    skipped_ids: list[int] = []
    analyzed_ids: list[int] = []

    for sid in body.sample_ids:
        raw = raw_by_id[sid]
        result = parse_message(raw, fields, body.template_id, sid, actual_version)

        has_error = any(f.status == "parse_error" for f in result.fields)
        if has_error:
            skipped_ids.append(sid)
            continue

        analyzed_ids.append(sid)
        parsed_by_name = {f.name: f for f in result.fields}
        for name in field_order:
            pf = parsed_by_name.get(name)
            if pf and pf.value is not None:
                field_values[name].append(pf.value)
            else:
                field_values[name].append("")

    total_analyzed = len(analyzed_ids)
    mutation_entries: list[FieldMutationEntry] = []

    for name in field_order:
        vals = field_values[name]
        if not vals:
            mutation_entries.append(
                FieldMutationEntry(
                    field_name=name,
                    unique_count=0,
                    mode_value=None,
                    mode_count=0,
                    distribution={},
                    mutation_rate=1.0,
                    total_samples=0,
                )
            )
            continue

        counter = Counter(vals)
        unique_count = len(counter)
        mode_val, mode_count = counter.most_common(1)[0]
        distribution = {v: c for v, c in counter.items()}
        mutation_rate = round((total_analyzed - mode_count) / total_analyzed, 4) if total_analyzed > 0 else 0.0

        mutation_entries.append(
            FieldMutationEntry(
                field_name=name,
                unique_count=unique_count,
                mode_value=mode_val,
                mode_count=mode_count,
                distribution=distribution,
                mutation_rate=mutation_rate,
                total_samples=total_analyzed,
            )
        )

    return FieldMutationResult(
        template_id=body.template_id,
        template_version=actual_version,
        sample_ids=analyzed_ids,
        skipped_count=len(skipped_ids),
        skipped_ids=skipped_ids,
        total_analyzed=total_analyzed,
        fields=mutation_entries,
    )


@router.post("/fixed-header-detection", response_model=FixedHeaderResult)
async def fixed_header_detection(body: FixedHeaderRequest):
    sample_map = await _fetch_samples(body.sample_ids)

    found_ids = {s["id"] for s in sample_map}
    missing_ids = [sid for sid in body.sample_ids if sid not in found_ids]
    if missing_ids:
        raise HTTPException(
            status_code=404,
            detail=f"samples not found: {missing_ids}",
        )

    raw_samples: dict[int, bytes] = {}
    for s in sample_map:
        raw_samples[s["id"]] = hex_to_bytes(s["hex_data"])

    max_len = max(len(raw) for raw in raw_samples.values()) if raw_samples else 0
    total = len(raw_samples)

    fixed_mask: list[bool] = []
    fixed_values: list[int] = []
    for offset in range(max_len):
        values: list[int] = []
        for sid in body.sample_ids:
            raw = raw_samples[sid]
            if offset < len(raw):
                values.append(raw[offset])

        if len(values) == total and len(set(values)) == 1:
            fixed_mask.append(True)
            fixed_values.append(values[0])
        else:
            fixed_mask.append(False)
            fixed_values.append(0)

    regions: list[FixedHeaderRegion] = []
    i = 0
    while i < len(fixed_mask):
        if fixed_mask[i]:
            start = i
            while i < len(fixed_mask) and fixed_mask[i]:
                i += 1
            end = i - 1
            region_len = end - start + 1
            if region_len >= body.min_length:
                region_bytes = bytes(fixed_values[start : end + 1])
                regions.append(
                    FixedHeaderRegion(
                        start_offset=start,
                        end_offset=end,
                        length=region_len,
                        fixed_hex=region_bytes.hex(),
                    )
                )
        else:
            i += 1

    return FixedHeaderResult(
        sample_ids=body.sample_ids,
        total_samples=total,
        max_length=max_len,
        regions=regions,
    )
