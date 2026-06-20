import json
import re
from collections import Counter
from fastapi import APIRouter, HTTPException, Query
from app.models import (
    COMPARE_OPS,
    FieldConstraint,
    GAP_TYPES,
    NUMERIC_FIELD_TYPES,
    PatternAnnotateRequest,
    PatternAnnotateResult,
    PatternCreate,
    PatternDetailOut,
    PatternMatchHit,
    PatternMatchResult,
    PatternOut,
    PatternSearchRequest,
    PatternSearchResult,
    PatternStepOut,
    SampleTagOut,
    SampleOut,
    FieldDef,
)
from app.database import get_db
from app.utils import hex_to_bytes
from app.parser import parse_message
from app.models import ParseResult, ParsedField

router = APIRouter(prefix="/api/sequence-patterns", tags=["sequence-patterns"])

REF_PATTERN = re.compile(r"^\$(\d+)\.([a-zA-Z_][a-zA-Z0-9_]*)$")


async def _get_template_fields(template_id: int, version: int | None = None):
    db = await get_db()
    try:
        if version is not None:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
                (template_id, version),
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail=f"template version {version} for template {template_id} not found")
            actual_version = version
        else:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM templates WHERE id = ?", (template_id,)
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail=f"template {template_id} not found")
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

    return s_rows[0], hex_to_bytes(s_rows[0]["hex_data"])


def _validate_ref(ref: str, current_step_index: int, total_steps: int) -> tuple[int, str] | None:
    m = REF_PATTERN.match(ref)
    if not m:
        return None
    ref_step = int(m.group(1))
    ref_field = m.group(2)
    if ref_step < 1 or ref_step >= current_step_index:
        return None
    if ref_step > total_steps:
        return None
    return ref_step, ref_field


def _validate_pattern_create(pattern: PatternCreate) -> list[str]:
    errors = []

    if len(pattern.steps) < 2:
        errors.append("pattern must have at least 2 steps")
    if len(pattern.steps) > 10:
        errors.append("pattern can have at most 10 steps")

    step_fields_map: dict[int, dict[str, FieldDef]] = {}

    for i, step in enumerate(pattern.steps, start=1):
        step_errors: list[str] = []

        if step.gap_type not in GAP_TYPES:
            step_errors.append(f"step {i}: invalid gap_type '{step.gap_type}'")

        if step.gap_type == "max_n":
            if step.gap_max_n is None:
                step_errors.append(f"step {i}: gap_max_n must be set when gap_type is 'max_n'")
            elif step.gap_max_n < 1 or step.gap_max_n > 100:
                step_errors.append(f"step {i}: gap_max_n must be between 1 and 100")
        else:
            if step.gap_max_n is not None:
                step_errors.append(f"step {i}: gap_max_n should not be set when gap_type is '{step.gap_type}'")

        for j, constraint in enumerate(step.constraints, start=1):
            if constraint.op not in COMPARE_OPS:
                step_errors.append(f"step {i} constraint {j}: invalid op '{constraint.op}'")

            has_value = constraint.value is not None
            has_ref = constraint.ref is not None

            if not has_value and not has_ref:
                step_errors.append(f"step {i} constraint {j}: must specify either 'value' or 'ref'")
            elif has_value and has_ref:
                step_errors.append(f"step {i} constraint {j}: cannot specify both 'value' and 'ref'")

            if has_ref:
                ref_info = _validate_ref(constraint.ref, i, len(pattern.steps))
                if ref_info is None:
                    step_errors.append(
                        f"step {i} constraint {j}: invalid ref '{constraint.ref}'. "
                        f"Must be $N.field where N is a previous step number (1 to {i - 1})"
                    )
                else:
                    if constraint.op in ("gt", "lt", "gte", "lte"):
                        ref_step_idx, ref_field_name = ref_info
                        if ref_step_idx in step_fields_map:
                            ref_field_def = step_fields_map[ref_step_idx].get(ref_field_name)
                            if ref_field_def and ref_field_def.data_type not in NUMERIC_FIELD_TYPES:
                                step_errors.append(
                                    f"step {i} constraint {j}: op '{constraint.op}' requires numeric field, "
                                    f"but step {ref_step_idx} field '{ref_field_name}' is '{ref_field_def.data_type}'"
                                )

        errors.extend(step_errors)

    return errors


@router.post("", response_model=PatternDetailOut, status_code=201)
async def create_pattern(body: PatternCreate):
    validation_errors = _validate_pattern_create(body)
    if validation_errors:
        raise HTTPException(status_code=400, detail="; ".join(validation_errors))

    step_template_versions: list[int] = []
    for step in body.steps:
        _, actual_version = await _get_template_fields(step.template_id, step.template_version)
        step_template_versions.append(actual_version)

    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO sequence_patterns (name, step_count) VALUES (?, ?)",
            (body.name, len(body.steps)),
        )
        pattern_id = cursor.lastrowid

        for i, step in enumerate(body.steps, start=1):
            constraints_dicts = [c.model_dump() for c in step.constraints]
            constraints_json = json.dumps(constraints_dicts)
            await db.execute(
                """
                INSERT INTO sequence_pattern_steps
                (pattern_id, step_index, template_id, template_version, constraints_json, gap_type, gap_max_n)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pattern_id,
                    i,
                    step.template_id,
                    step_template_versions[i - 1],
                    constraints_json,
                    step.gap_type,
                    step.gap_max_n,
                ),
            )

        await db.commit()

        pattern_rows = await db.execute_fetchall(
            "SELECT * FROM sequence_patterns WHERE id = ?", (pattern_id,)
        )
        step_rows = await db.execute_fetchall(
            "SELECT * FROM sequence_pattern_steps WHERE pattern_id = ? ORDER BY step_index ASC",
            (pattern_id,),
        )
    finally:
        await db.close()

    pattern_row = pattern_rows[0]
    steps_out = []
    for sr in step_rows:
        constraints = [FieldConstraint(**c) for c in json.loads(sr["constraints_json"])]
        steps_out.append(
            PatternStepOut(
                id=sr["id"],
                pattern_id=sr["pattern_id"],
                step_index=sr["step_index"],
                template_id=sr["template_id"],
                template_version=sr["template_version"],
                constraints=constraints,
                gap_type=sr["gap_type"],
                gap_max_n=sr["gap_max_n"],
            )
        )

    return PatternDetailOut(
        id=pattern_row["id"],
        name=pattern_row["name"],
        steps=steps_out,
        created_at=pattern_row["created_at"] or "",
    )


@router.get("", response_model=list[PatternOut])
async def list_patterns(
    name: str = Query(default=None, description="search by name (fuzzy)"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        if name:
            rows = await db.execute_fetchall(
                "SELECT * FROM sequence_patterns WHERE name LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (f"%{name}%", limit, offset),
            )
        else:
            rows = await db.execute_fetchall(
                "SELECT * FROM sequence_patterns ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
    finally:
        await db.close()

    return [
        PatternOut(
            id=r["id"],
            name=r["name"],
            step_count=r["step_count"],
            created_at=r["created_at"] or "",
        )
        for r in rows
    ]


@router.get("/{pattern_id}", response_model=PatternDetailOut)
async def get_pattern(pattern_id: int):
    db = await get_db()
    try:
        pattern_rows = await db.execute_fetchall(
            "SELECT * FROM sequence_patterns WHERE id = ?", (pattern_id,)
        )
        if not pattern_rows:
            raise HTTPException(status_code=404, detail="pattern not found")
        step_rows = await db.execute_fetchall(
            "SELECT * FROM sequence_pattern_steps WHERE pattern_id = ? ORDER BY step_index ASC",
            (pattern_id,),
        )
    finally:
        await db.close()

    pattern_row = pattern_rows[0]
    steps_out = []
    for sr in step_rows:
        constraints = [FieldConstraint(**c) for c in json.loads(sr["constraints_json"])]
        steps_out.append(
            PatternStepOut(
                id=sr["id"],
                pattern_id=sr["pattern_id"],
                step_index=sr["step_index"],
                template_id=sr["template_id"],
                template_version=sr["template_version"],
                constraints=constraints,
                gap_type=sr["gap_type"],
                gap_max_n=sr["gap_max_n"],
            )
        )

    return PatternDetailOut(
        id=pattern_row["id"],
        name=pattern_row["name"],
        steps=steps_out,
        created_at=pattern_row["created_at"] or "",
    )


@router.delete("/{pattern_id}", status_code=204)
async def delete_pattern(pattern_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT id FROM sequence_patterns WHERE id = ?", (pattern_id,)
        )
        if not rows:
            raise HTTPException(status_code=404, detail="pattern not found")

        await db.execute("DELETE FROM sequence_patterns WHERE id = ?", (pattern_id,))
        await db.commit()
    finally:
        await db.close()


def _parsed_fields_to_dict(parse_result: ParseResult) -> dict[str, dict]:
    result = {}
    for pf in parse_result.fields:
        result[pf.name] = {
            "value": pf.value,
            "status": pf.status,
            "hex": pf.hex,
            "length": pf.length,
        }
    return result


def _get_numeric_field_value(field_dict: dict) -> float | int | None:
    if field_dict is None or field_dict.get("status") != "ok" or field_dict.get("value") is None:
        return None
    try:
        val = field_dict["value"]
        if isinstance(val, (int, float)):
            return val
        return float(val)
    except (ValueError, TypeError):
        return None


def _get_any_field_value(field_dict: dict) -> str | int | float | None:
    if field_dict is None or field_dict.get("status") != "ok":
        return None
    return field_dict.get("value")


def _compare_values(
    op: str,
    current_val: str | int | float | None,
    target_val: str | int | float | None,
    is_numeric_op: bool,
) -> bool:
    if current_val is None or target_val is None:
        return False

    if is_numeric_op:
        try:
            cur = float(current_val)
            tgt = float(target_val)
        except (ValueError, TypeError):
            return False
        if op == "eq":
            return cur == tgt
        elif op == "ne":
            return cur != tgt
        elif op == "gt":
            return cur > tgt
        elif op == "lt":
            return cur < tgt
        elif op == "gte":
            return cur >= tgt
        elif op == "lte":
            return cur <= tgt
    else:
        cur_str = str(current_val)
        tgt_str = str(target_val)
        if op == "eq":
            return cur_str == tgt_str
        elif op == "ne":
            return cur_str != tgt_str
        else:
            return False
    return False


def _check_step_constraints(
    step: PatternStepOut,
    parsed_fields: dict[str, dict],
    step_fields_map: dict[int, FieldDef],
    prev_matches: dict[int, dict[str, dict]],
) -> bool:
    is_numeric_op = False

    for constraint in step.constraints:
        current_field_dict = parsed_fields.get(constraint.field)

        if constraint.op in ("gt", "lt", "gte", "lte"):
            is_numeric_op = True

        if constraint.ref is not None:
            m = REF_PATTERN.match(constraint.ref)
            if not m:
                return False
            ref_step_idx = int(m.group(1))
            ref_field_name = m.group(2)

            if ref_step_idx not in prev_matches:
                return False
            ref_parsed = prev_matches[ref_step_idx]
            ref_field_dict = ref_parsed.get(ref_field_name)
            if is_numeric_op:
                cur_val = _get_numeric_field_value(current_field_dict)
                tgt_val = _get_numeric_field_value(ref_field_dict)
            else:
                cur_val = _get_any_field_value(current_field_dict)
                tgt_val = _get_any_field_value(ref_field_dict)
            if not _compare_values(constraint.op, cur_val, tgt_val, is_numeric_op):
                return False
        else:
            if is_numeric_op:
                cur_val = _get_numeric_field_value(current_field_dict)
                try:
                    tgt_val = float(constraint.value) if constraint.value is not None else None
                except (ValueError, TypeError):
                    return False
            else:
                cur_val = _get_any_field_value(current_field_dict)
                tgt_val = constraint.value
            if not _compare_values(constraint.op, cur_val, tgt_val, is_numeric_op):
                return False

    return True


def _check_gap_constraint(
    step: PatternStepOut,
    prev_position: int,
    current_position: int,
) -> bool:
    if step.gap_type == "adjacent":
        return current_position == prev_position + 1
    elif step.gap_type == "max_n":
        max_gap = step.gap_max_n or 0
        return 0 < (current_position - prev_position) <= max_gap + 1
    elif step.gap_type == "unlimited":
        return current_position > prev_position
    return False


async def _load_pattern_steps(pattern_id: int) -> tuple[str, list[PatternStepOut]]:
    db = await get_db()
    try:
        pattern_rows = await db.execute_fetchall(
            "SELECT * FROM sequence_patterns WHERE id = ?", (pattern_id,)
        )
        if not pattern_rows:
            raise HTTPException(status_code=404, detail="pattern not found")
        pattern_name = pattern_rows[0]["name"]

        step_rows = await db.execute_fetchall(
            "SELECT * FROM sequence_pattern_steps WHERE pattern_id = ? ORDER BY step_index ASC",
            (pattern_id,),
        )
    finally:
        await db.close()

    steps = []
    for sr in step_rows:
        constraints = [FieldConstraint(**c) for c in json.loads(sr["constraints_json"])]
        steps.append(
            PatternStepOut(
                id=sr["id"],
                pattern_id=sr["pattern_id"],
                step_index=sr["step_index"],
                template_id=sr["template_id"],
                template_version=sr["template_version"],
                constraints=constraints,
                gap_type=sr["gap_type"],
                gap_max_n=sr["gap_max_n"],
            )
        )

    return pattern_name, steps


async def _parse_sample_with_template(
    sample_id: int, template_id: int, template_version: int
) -> ParseResult | None:
    try:
        sample_row, raw = await _get_sample_data(sample_id)
    except HTTPException:
        return None

    try:
        fields, _ = await _get_template_fields(template_id, template_version)
    except HTTPException:
        return None

    return parse_message(raw, fields, template_id, sample_id, template_version)


@router.post("/search", response_model=PatternSearchResult)
async def search_pattern(body: PatternSearchRequest):
    pattern_name, steps = await _load_pattern_steps(body.pattern_id)
    if len(steps) < 2:
        raise HTTPException(status_code=400, detail="pattern must have at least 2 steps")

    n_samples = len(body.sample_ids)

    db = await get_db()
    try:
        placeholders = ",".join("?" * n_samples)
        existing_rows = await db.execute_fetchall(
            f"SELECT id FROM samples WHERE id IN ({placeholders})",
            body.sample_ids,
        )
        existing_ids = {r["id"] for r in existing_rows}
    finally:
        await db.close()

    skipped_sample_ids = [sid for sid in body.sample_ids if sid not in existing_ids]

    parsed_cache: dict[tuple[int, int, int], ParseResult | None] = {}

    async def _get_parsed(sid: int, tid: int, tv: int) -> ParseResult | None:
        key = (sid, tid, tv)
        if key not in parsed_cache:
            parsed_cache[key] = await _parse_sample_with_template(sid, tid, tv)
        return parsed_cache[key]

    matches: list[PatternMatchResult] = []
    hit_id_counter = 0

    async def _bt(
        step_idx: int,
        current_position: int,
        current_hits: list[PatternMatchHit],
        prev_parsed: dict[int, dict[str, dict]],
    ):
        nonlocal hit_id_counter

        if step_idx > len(steps):
            hit_id_counter += 1
            matches.append(
                PatternMatchResult(
                    hit_id=hit_id_counter,
                    hits=list(current_hits),
                )
            )
            return

        step = steps[step_idx - 1]
        start_pos = current_position + 1 if current_hits else 0

        for pos in range(start_pos, n_samples):
            sample_id = body.sample_ids[pos]
            if sample_id not in existing_ids:
                continue

            if step_idx > 1 and current_position >= 0:
                should_break = False
                if not _check_gap_constraint(step, current_position, pos):
                    if step.gap_type == "adjacent" and pos > current_position + 1:
                        should_break = True
                    elif step.gap_type == "max_n":
                        max_gap = step.gap_max_n or 0
                        if pos - current_position > max_gap + 1:
                            should_break = True
                    if should_break:
                        break
                    continue

            parse_result = await _get_parsed(sample_id, step.template_id, step.template_version)

            if parse_result is None:
                continue

            has_parse_errors = any(f.status == "parse_error" for f in parse_result.fields)
            if has_parse_errors and step.constraints:
                continue

            parsed_fields = _parsed_fields_to_dict(parse_result)

            step_fields_map: dict[int, FieldDef] = {}
            if not _check_step_constraints(step, parsed_fields, step_fields_map, prev_parsed):
                continue

            current_hits.append(
                PatternMatchHit(
                    step_index=step_idx,
                    sample_id=sample_id,
                    sample_position=pos,
                )
            )
            new_prev_parsed = dict(prev_parsed)
            new_prev_parsed[step_idx] = parsed_fields

            await _bt(step_idx + 1, pos, current_hits, new_prev_parsed)

            current_hits.pop()

    await _bt(1, -1, [], {})

    return PatternSearchResult(
        pattern_id=body.pattern_id,
        pattern_name=pattern_name,
        total_samples=n_samples,
        match_count=len(matches),
        skipped_sample_ids=skipped_sample_ids,
        matches=matches,
    )


@router.post("/annotate", response_model=PatternAnnotateResult)
async def annotate_pattern(body: PatternAnnotateRequest):
    pattern_name, steps = await _load_pattern_steps(body.pattern_id)

    search_result = await search_pattern(
        PatternSearchRequest(pattern_id=body.pattern_id, sample_ids=body.sample_ids)
    )

    db = await get_db()
    try:
        tagged_samples: set[int] = set()
        tags_created = 0

        for match in search_result.matches:
            for hit in match.hits:
                tag_text = f"{pattern_name}-步骤{hit.step_index}"

                existing = await db.execute_fetchall(
                    "SELECT id FROM sample_tags WHERE sample_id = ? AND tag = ?",
                    (hit.sample_id, tag_text),
                )
                if existing:
                    continue

                cursor = await db.execute(
                    """
                    INSERT INTO sample_tags (sample_id, tag, pattern_id, pattern_name, step_index)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (hit.sample_id, tag_text, body.pattern_id, pattern_name, hit.step_index),
                )
                if cursor.lastrowid:
                    tags_created += 1
                    tagged_samples.add(hit.sample_id)

        await db.commit()
    finally:
        await db.close()

    return PatternAnnotateResult(
        pattern_id=body.pattern_id,
        pattern_name=pattern_name,
        total_samples=len(body.sample_ids),
        match_count=search_result.match_count,
        skipped_sample_ids=search_result.skipped_sample_ids,
        tagged_sample_count=len(tagged_samples),
        tags_created=tags_created,
    )


@router.get("/tags/sample/{sample_id}", response_model=list[SampleTagOut])
async def get_sample_tags(sample_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM sample_tags WHERE sample_id = ? ORDER BY id ASC",
            (sample_id,),
        )
    finally:
        await db.close()

    return [
        SampleTagOut(
            id=r["id"],
            sample_id=r["sample_id"],
            tag=r["tag"],
            pattern_id=r["pattern_id"],
            pattern_name=r["pattern_name"],
            step_index=r["step_index"],
            created_at=r["created_at"] or "",
        )
        for r in rows
    ]


@router.delete("/tags/{tag_id}", status_code=204)
async def delete_sample_tag(tag_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT id FROM sample_tags WHERE id = ?", (tag_id,)
        )
        if not rows:
            raise HTTPException(status_code=404, detail="tag not found")
        await db.execute("DELETE FROM sample_tags WHERE id = ?", (tag_id,))
        await db.commit()
    finally:
        await db.close()


@router.get("/samples/by-tag", response_model=list[SampleOut])
async def list_samples_by_tag(
    tag: str = Query(..., description="tag to filter by"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            """
            SELECT DISTINCT s.*
            FROM samples s
            JOIN sample_tags t ON t.sample_id = s.id
            WHERE t.tag = ?
            ORDER BY s.id DESC
            LIMIT ? OFFSET ?
            """,
            (tag, limit, offset),
        )
    finally:
        await db.close()

    sample_ids = [r["id"] for r in rows]

    db2 = await get_db()
    try:
        if sample_ids:
            placeholders = ",".join("?" * len(sample_ids))
            tag_rows = await db2.execute_fetchall(
                f"SELECT sample_id, tag FROM sample_tags WHERE sample_id IN ({placeholders}) ORDER BY id ASC",
                sample_ids,
            )
        else:
            tag_rows = []
    finally:
        await db2.close()

    tags_map: dict[int, list[str]] = {sid: [] for sid in sample_ids}
    for tr in tag_rows:
        tags_map[tr["sample_id"]].append(tr["tag"])

    return [
        SampleOut(
            id=r["id"],
            name=r["name"],
            hex_data=r["hex_data"],
            byte_length=r["byte_length"],
            entropy=r["entropy"],
            note=r["note"] or "",
            created_at=r["created_at"] or "",
            tags=tags_map.get(r["id"], []),
        )
        for r in rows
    ]


@router.get("/tags/all", response_model=list[dict])
async def list_all_tags():
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            """
            SELECT tag, pattern_id, pattern_name, COUNT(*) as sample_count
            FROM sample_tags
            GROUP BY tag, pattern_id, pattern_name
            ORDER BY tag ASC
            """
        )
    finally:
        await db.close()

    return [
        {
            "tag": r["tag"],
            "pattern_id": r["pattern_id"],
            "pattern_name": r["pattern_name"],
            "sample_count": r["sample_count"],
        }
        for r in rows
    ]
