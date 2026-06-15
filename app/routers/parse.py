import json
from collections import Counter
from fastapi import APIRouter, HTTPException, Query
from app.models import (
    BatchValidateRequest,
    BatchValidateResult,
    CompareRequest,
    CompareResult,
    FieldDef,
    FieldDiffValue,
    FieldDiffOnly,
    ParsedField,
    ParseResult,
)
from app.database import get_db
from app.utils import hex_to_bytes
from app.parser import parse_message

router = APIRouter(prefix="/api/parse", tags=["parse"])


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


async def _get_sample_data(sample_id: int):
    db = await get_db()
    try:
        s_rows = await db.execute_fetchall(
            "SELECT * FROM samples WHERE id = ?", (sample_id,)
        )
    finally:
        await db.close()

    if not s_rows:
        raise HTTPException(status_code=404, detail=f"sample {sample_id} not found")

    return hex_to_bytes(s_rows[0]["hex_data"])


@router.post("/{template_id}/{sample_id}", response_model=ParseResult)
async def parse_single(
    template_id: int,
    sample_id: int,
    version: int | None = Query(default=None, ge=1, description="Template version number, uses latest if not specified"),
):
    fields, actual_version = await _get_template_fields(template_id, version)
    raw = await _get_sample_data(sample_id)
    return parse_message(raw, fields, template_id, sample_id, actual_version)


def _compare_results(result_a: ParseResult, result_b: ParseResult) -> CompareResult:
    a_fields = {f.name: f for f in result_a.fields}
    b_fields = {f.name: f for f in result_b.fields}

    different_fields: list[FieldDiffValue] = []
    only_a_fields: list[FieldDiffOnly] = []
    only_b_fields: list[FieldDiffOnly] = []

    all_field_names = set(a_fields.keys()) | set(b_fields.keys())

    for name in sorted(all_field_names):
        a_field = a_fields.get(name)
        b_field = b_fields.get(name)

        if a_field is not None and b_field is not None:
            has_parse_error = (
                a_field.status == "parse_error" or b_field.status == "parse_error"
            )
            values_differ = (
                a_field.value != b_field.value
                or a_field.status != b_field.status
                or has_parse_error
            )
            if values_differ:
                different_fields.append(
                    FieldDiffValue(
                        field_name=name,
                        a_value=a_field.value,
                        b_value=b_field.value,
                        a_hex=a_field.hex,
                        b_hex=b_field.hex,
                        a_status=a_field.status,
                        b_status=b_field.status,
                        has_parse_error=has_parse_error,
                    )
                )
        elif a_field is not None:
            only_a_fields.append(
                FieldDiffOnly(
                    field_name=name,
                    value=a_field.value,
                    hex=a_field.hex,
                    status=a_field.status,
                    error=a_field.error,
                )
            )
        elif b_field is not None:
            only_b_fields.append(
                FieldDiffOnly(
                    field_name=name,
                    value=b_field.value,
                    hex=b_field.hex,
                    status=b_field.status,
                    error=b_field.error,
                )
            )

    return CompareResult(
        template_id=result_a.template_id,
        template_version=result_a.template_version,
        sample_a_id=result_a.sample_id,
        sample_b_id=result_b.sample_id,
        different_fields=different_fields,
        only_a_fields=only_a_fields,
        only_b_fields=only_b_fields,
        parse_result_a=result_a,
        parse_result_b=result_b,
    )


@router.post("/compare", response_model=CompareResult)
async def compare_samples(body: CompareRequest):
    fields, actual_version = await _get_template_fields(body.template_id, body.template_version)

    raw_a = await _get_sample_data(body.sample_a_id)
    raw_b = await _get_sample_data(body.sample_b_id)

    result_a = parse_message(raw_a, fields, body.template_id, body.sample_a_id, actual_version)
    result_b = parse_message(raw_b, fields, body.template_id, body.sample_b_id, actual_version)

    return _compare_results(result_a, result_b)


@router.post("/batch", response_model=BatchValidateResult)
async def batch_validate(body: BatchValidateRequest):
    fields, actual_version = await _get_template_fields(body.template_id, body.template_version)

    results: list[ParseResult] = []
    field_errors: Counter = Counter()

    for sid in body.sample_ids:
        try:
            raw = await _get_sample_data(sid)
        except HTTPException:
            missing_result = ParseResult(
                template_id=body.template_id,
                sample_id=sid,
                template_version=actual_version,
                fields=[
                    ParsedField(
                        name="__sample__",
                        hex="",
                        offset=0,
                        length=0,
                        status="parse_error",
                        error=f"sample id {sid} not found",
                    )
                ],
                coverage_percent=0.0,
                covered_bytes=0,
                total_bytes=0,
                uncovered_ranges=[],
            )
            field_errors["__sample_missing__"] += 1
            results.append(missing_result)
            continue

        result = parse_message(raw, fields, body.template_id, sid, actual_version)
        results.append(result)

        for pf in result.fields:
            if pf.status == "parse_error":
                field_errors[pf.name] += 1

    success_count = sum(
        1 for r in results if all(f.status != "parse_error" for f in r.fields)
    )
    total = len(results)
    avg_coverage = (
        round(sum(r.coverage_percent for r in results) / total, 2) if total > 0 else 0
    )

    ranking = [
        {"field_name": name, "error_count": count}
        for name, count in field_errors.most_common()
    ]

    return BatchValidateResult(
        template_id=body.template_id,
        template_version=actual_version,
        total_samples=total,
        success_count=success_count,
        success_rate=round(success_count / total * 100, 2) if total > 0 else 0,
        avg_coverage=avg_coverage,
        field_error_ranking=ranking,
        details=results,
    )
