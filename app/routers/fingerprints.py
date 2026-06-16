import json
from fastapi import APIRouter, HTTPException
from app.models import (
    FingerprintCreate,
    FingerprintOut,
    RecognizeRequest,
    RecognizeResult,
    RecognizedTemplate,
    SmartParseRequest,
    SmartParseResult,
    ParseResult,
    FieldDef,
)
from app.database import get_db
from app.utils import validate_hex, hex_to_bytes
from app.fingerprint import (
    validate_fingerprint,
    match_template_fingerprints,
    sort_recognized_templates,
    MAX_FINGERPRINTS_PER_TEMPLATE,
)
from app.parser import parse_message

router = APIRouter(prefix="/api/fingerprints", tags=["fingerprints"])


@router.post("/template/{template_id}", response_model=FingerprintOut, status_code=201)
async def add_fingerprint(template_id: int, body: FingerprintCreate):
    try:
        validate_fingerprint(body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    expected_hex_clean = validate_hex(body.expected_hex).lower()
    mask_hex_clean = validate_hex(body.mask_hex).lower() if body.mask_hex else None

    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT id FROM templates WHERE id = ?", (template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        count_rows = await db.execute_fetchall(
            "SELECT COUNT(*) as cnt FROM fingerprints WHERE template_id = ?",
            (template_id,),
        )
        current_count = count_rows[0]["cnt"]
        if current_count >= MAX_FINGERPRINTS_PER_TEMPLATE:
            raise HTTPException(
                status_code=400,
                detail=f"maximum {MAX_FINGERPRINTS_PER_TEMPLATE} fingerprints per template",
            )

        cursor = await db.execute(
            """
            INSERT INTO fingerprints (template_id, offset, expected_hex, match_type, mask_hex)
            VALUES (?, ?, ?, ?, ?)
            """,
            (template_id, body.offset, expected_hex_clean, body.match_type, mask_hex_clean),
        )
        fingerprint_id = cursor.lastrowid
        await db.commit()

        rows = await db.execute_fetchall(
            "SELECT * FROM fingerprints WHERE id = ?", (fingerprint_id,)
        )
    finally:
        await db.close()

    r = rows[0]
    return FingerprintOut(
        id=r["id"],
        template_id=r["template_id"],
        offset=r["offset"],
        expected_hex=r["expected_hex"],
        match_type=r["match_type"],
        mask_hex=r["mask_hex"],
        created_at=r["created_at"] or "",
    )


@router.delete("/{fingerprint_id}", status_code=204)
async def delete_fingerprint(fingerprint_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT id FROM fingerprints WHERE id = ?", (fingerprint_id,)
        )
        if not rows:
            raise HTTPException(status_code=404, detail="fingerprint not found")

        await db.execute("DELETE FROM fingerprints WHERE id = ?", (fingerprint_id,))
        await db.commit()
    finally:
        await db.close()


@router.get("/template/{template_id}", response_model=list[FingerprintOut])
async def list_fingerprints(template_id: int):
    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT id FROM templates WHERE id = ?", (template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        rows = await db.execute_fetchall(
            "SELECT * FROM fingerprints WHERE template_id = ? ORDER BY id ASC",
            (template_id,),
        )
    finally:
        await db.close()

    results = []
    for r in rows:
        results.append(
            FingerprintOut(
                id=r["id"],
                template_id=r["template_id"],
                offset=r["offset"],
                expected_hex=r["expected_hex"],
                match_type=r["match_type"],
                mask_hex=r["mask_hex"],
                created_at=r["created_at"] or "",
            )
        )
    return results


@router.post("/recognize", response_model=RecognizeResult)
async def recognize_protocol(body: RecognizeRequest):
    try:
        hex_clean = validate_hex(body.hex_data)
        data = hex_to_bytes(hex_clean)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    db = await get_db()
    try:
        template_rows = await db.execute_fetchall(
            """
            SELECT t.id, t.name, COUNT(f.id) as fp_count
            FROM templates t
            JOIN fingerprints f ON f.template_id = t.id
            GROUP BY t.id
            HAVING fp_count > 0
            ORDER BY t.id
            """
        )

        recognized = []
        for t_row in template_rows:
            template_id = t_row["id"]
            template_name = t_row["name"]

            fp_rows = await db.execute_fetchall(
                "SELECT * FROM fingerprints WHERE template_id = ?",
                (template_id,),
            )
            fingerprints = [
                {
                    "offset": r["offset"],
                    "expected_hex": r["expected_hex"],
                    "match_type": r["match_type"],
                    "mask_hex": r["mask_hex"],
                }
                for r in fp_rows
            ]

            matched, is_full_match = match_template_fingerprints(data, fingerprints)

            if matched > 0:
                recognized.append(
                    RecognizedTemplate(
                        template_id=template_id,
                        template_name=template_name,
                        total_rules=len(fingerprints),
                        matched_rules=matched,
                        is_full_match=is_full_match,
                    )
                )
    finally:
        await db.close()

    sorted_results = sort_recognized_templates(recognized)
    return RecognizeResult(matches=sorted_results)


async def _get_latest_template_version(template_id: int) -> tuple[list[FieldDef], int]:
    db = await get_db()
    try:
        v_rows = await db.execute_fetchall(
            "SELECT MAX(version) as max_version FROM template_versions WHERE template_id = ?",
            (template_id,),
        )
        latest_version = v_rows[0]["max_version"] or 1

        tv_rows = await db.execute_fetchall(
            "SELECT fields_json FROM template_versions WHERE template_id = ? AND version = ?",
            (template_id, latest_version),
        )
        fields = [FieldDef(**f) for f in json.loads(tv_rows[0]["fields_json"])]
    finally:
        await db.close()

    return fields, latest_version


@router.post("/smart-parse", response_model=SmartParseResult)
async def smart_parse(body: SmartParseRequest):
    try:
        hex_clean = validate_hex(body.hex_data)
        data = hex_to_bytes(hex_clean)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    recognize_result = await recognize_protocol(RecognizeRequest(hex_data=body.hex_data))
    matches = recognize_result.matches

    if not matches:
        return SmartParseResult(
            status="failed",
            message="无法识别协议",
        )

    full_matches = [m for m in matches if m.is_full_match]

    if len(full_matches) == 1:
        template_id = full_matches[0].template_id
        fields, version = await _get_latest_template_version(template_id)
        parse_result = parse_message(data, fields, template_id, 0, version)
        return SmartParseResult(
            status="success",
            parse_result=parse_result,
        )

    return SmartParseResult(
        status="ambiguous",
        candidates=matches,
    )
