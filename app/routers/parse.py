import json
from collections import Counter
from fastapi import APIRouter, HTTPException
from app.models import (
    BatchValidateRequest,
    BatchValidateResult,
    FieldDef,
    ParsedField,
    ParseResult,
)
from app.database import get_db
from app.utils import hex_to_bytes
from app.parser import parse_message

router = APIRouter(prefix="/api/parse", tags=["parse"])


@router.post("/{template_id}/{sample_id}", response_model=ParseResult)
async def parse_single(template_id: int, sample_id: int):
    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT * FROM templates WHERE id = ?", (template_id,)
        )
        s_rows = await db.execute_fetchall(
            "SELECT * FROM samples WHERE id = ?", (sample_id,)
        )
    finally:
        await db.close()

    if not t_rows:
        raise HTTPException(status_code=404, detail="template not found")
    if not s_rows:
        raise HTTPException(status_code=404, detail="sample not found")

    fields = [FieldDef(**f) for f in json.loads(t_rows[0]["fields_json"])]
    raw = hex_to_bytes(s_rows[0]["hex_data"])

    return parse_message(raw, fields, template_id, sample_id)


@router.post("/batch", response_model=BatchValidateResult)
async def batch_validate(body: BatchValidateRequest):
    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT * FROM templates WHERE id = ?", (body.template_id,)
        )
    finally:
        await db.close()

    if not t_rows:
        raise HTTPException(status_code=404, detail="template not found")

    fields = [FieldDef(**f) for f in json.loads(t_rows[0]["fields_json"])]

    results: list[ParseResult] = []
    field_errors: Counter = Counter()

    for sid in body.sample_ids:
        db2 = await get_db()
        try:
            s_rows = await db2.execute_fetchall(
                "SELECT * FROM samples WHERE id = ?", (sid,)
            )
        finally:
            await db2.close()

        if not s_rows:
            missing_result = ParseResult(
                template_id=body.template_id,
                sample_id=sid,
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

        raw = hex_to_bytes(s_rows[0]["hex_data"])
        result = parse_message(raw, fields, body.template_id, sid)
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
        total_samples=total,
        success_count=success_count,
        success_rate=round(success_count / total * 100, 2) if total > 0 else 0,
        avg_coverage=avg_coverage,
        field_error_ranking=ranking,
        details=results,
    )
