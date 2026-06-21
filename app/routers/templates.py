import json
from fastapi import APIRouter, HTTPException, Query
from app.models import (
    TemplateCreate, TemplateOut, TemplateUpdate, FieldDef, TemplateVersionOut,
    TemplateVersionSummary, FullFieldsResult, TemplateDiffResult,
    MigrationPrepareRequest, MigrationPrepareResult, MigrationExecuteRequest,
    MigrationExecuteResult, MigrationTaskStatus, MAX_CHILD_TEMPLATES, ParseResult
)
from app.database import get_db
from app.utils import (
    merge_template_fields, compare_templates, validate_inheritance_constraints,
    validate_no_grandchildren, json_to_fields, fields_to_json, get_full_fields_internal
)
from app.parser import parse_message
from app.utils import hex_to_bytes

router = APIRouter(prefix="/api/templates", tags=["templates"])


def detect_circular_dependency(fields: list[FieldDef]) -> str | None:
    name_to_idx: dict[str, int] = {}
    for i, f in enumerate(fields):
        name_to_idx[f.name] = i

    adj: dict[int, list[int]] = {i: [] for i in range(len(fields))}
    for i, f in enumerate(fields):
        if f.length_rule == "ref" and f.length_ref_field:
            if f.length_ref_field in name_to_idx:
                adj[name_to_idx[f.length_ref_field]].append(i)
        if f.condition_field:
            if f.condition_field in name_to_idx:
                adj[name_to_idx[f.condition_field]].append(i)

    WHITE, GRAY, BLACK = 0, 1, 2
    color = [WHITE] * len(fields)

    def dfs(node: int) -> bool:
        color[node] = GRAY
        for neighbor in adj[node]:
            if color[neighbor] == GRAY:
                return True
            if color[neighbor] == WHITE and dfs(neighbor):
                return True
        color[node] = BLACK
        return False

    for i in range(len(fields)):
        if color[i] == WHITE:
            if dfs(i):
                return fields[i].name
    return None


def validate_fields(fields: list[FieldDef], parent_fields: list[FieldDef] | None = None) -> None:
    if not fields:
        raise HTTPException(status_code=400, detail="template must have at least one field")

    all_fields = (parent_fields or []) + fields
    field_names = [f.name for f in all_fields]
    child_field_names = [f.name for f in fields]

    if len(child_field_names) != len(set(child_field_names)):
        raise HTTPException(status_code=400, detail="duplicate field names are not allowed")

    name_set = set(field_names)
    for i, f in enumerate(fields):
        pos_in_all = len(parent_fields or []) + i

        if f.length_rule == "fixed" and (f.length_value is None or f.length_value <= 0):
            raise HTTPException(
                status_code=400,
                detail=f"field '{f.name}': fixed length_rule requires a positive length_value",
            )
        if f.length_rule == "ref":
            if not f.length_ref_field:
                raise HTTPException(
                    status_code=400,
                    detail=f"field '{f.name}': ref length_rule requires length_ref_field",
                )
            if f.length_ref_field not in name_set:
                raise HTTPException(
                    status_code=400,
                    detail=f"field '{f.name}': references unknown field '{f.length_ref_field}'",
                )
            ref_idx = field_names.index(f.length_ref_field)
            if ref_idx >= pos_in_all:
                raise HTTPException(
                    status_code=400,
                    detail=f"field '{f.name}': length_ref_field '{f.length_ref_field}' must appear before this field",
                )
        if f.length_rule == "until" and not f.until_byte:
            raise HTTPException(
                status_code=400,
                detail=f"field '{f.name}': until length_rule requires until_byte (hex, e.g. '00')",
            )
        if f.condition_field:
            if f.condition_field not in name_set:
                raise HTTPException(
                    status_code=400,
                    detail=f"field '{f.name}': condition_field '{f.condition_field}' not found",
                )
            cond_idx = field_names.index(f.condition_field)
            if cond_idx >= pos_in_all:
                raise HTTPException(
                    status_code=400,
                    detail=f"field '{f.name}': condition_field '{f.condition_field}' must appear before this field",
                )

    cycle_field = detect_circular_dependency(all_fields)
    if cycle_field:
        raise HTTPException(
            status_code=400,
            detail=f"circular dependency detected involving field '{cycle_field}'",
        )


async def get_child_template_count(db, parent_template_id: int) -> int:
    rows = await db.execute_fetchall(
        "SELECT COUNT(*) as cnt FROM templates WHERE parent_template_id = ?",
        (parent_template_id,)
    )
    return rows[0]["cnt"] if rows else 0


async def get_template_and_fields(db, template_id: int, version: int | None = None):
    if version is not None:
        t_rows = await db.execute_fetchall(
            "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
            (template_id, version),
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template version not found")
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
        version = v_rows[0]["max_version"] or 1

    fields = json_to_fields(t_rows[0]["fields_json"])
    parent_template_id = t_rows[0]["parent_template_id"] if "parent_template_id" in t_rows[0].keys() else None

    return fields, version, parent_template_id, t_rows[0]


@router.post("", response_model=TemplateOut, status_code=201)
async def create_template(body: TemplateCreate):
    db = await get_db()
    try:
        parent_template_id = body.parent_template_id
        parent_fields = None

        if parent_template_id is not None:
            p_rows = await db.execute_fetchall(
                "SELECT * FROM templates WHERE id = ?", (parent_template_id,)
            )
            if not p_rows:
                raise HTTPException(status_code=404, detail=f"parent template {parent_template_id} not found")

            if p_rows[0]["parent_template_id"] is not None:
                ok, err = validate_no_grandchildren(True)
                if not ok:
                    raise HTTPException(status_code=400, detail=err)

            child_count = await get_child_template_count(db, parent_template_id)
            parent_fields = json_to_fields(p_rows[0]["fields_json"])

            ok, err = validate_inheritance_constraints(
                parent_template_id, body.fields, parent_fields, child_count
            )
            if not ok:
                raise HTTPException(status_code=400, detail=err)

        validate_fields(body.fields, parent_fields)

        fields_json = fields_to_json(body.fields)

        cursor = await db.execute(
            "INSERT INTO templates (name, description, fields_json, parent_template_id) VALUES (?, ?, ?, ?)",
            (body.name, body.description, fields_json, parent_template_id),
        )
        template_id = cursor.lastrowid

        await db.execute(
            """
            INSERT INTO template_versions (template_id, version, name, description, fields_json, parent_template_id)
            VALUES (?, 1, ?, ?, ?, ?)
            """,
            (template_id, body.name, body.description, fields_json, parent_template_id),
        )
        await db.commit()

        child_count = await get_child_template_count(db, parent_template_id) if parent_template_id else 0
    finally:
        await db.close()

    return TemplateOut(
        id=template_id,
        name=body.name,
        description=body.description,
        fields=body.fields,
        parent_template_id=parent_template_id,
        child_template_count=child_count,
        created_at="",
    )


@router.put("/{template_id}", response_model=TemplateVersionOut)
async def update_template(template_id: int, body: TemplateUpdate):
    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT * FROM templates WHERE id = ?", (template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        parent_template_id = t_rows[0]["parent_template_id"] if "parent_template_id" in t_rows[0].keys() else None
        parent_fields = None

        if parent_template_id is not None:
            p_rows = await db.execute_fetchall(
                "SELECT * FROM templates WHERE id = ?", (parent_template_id,)
            )
            if p_rows:
                parent_fields = json_to_fields(p_rows[0]["fields_json"])
                child_count = await get_child_template_count(db, parent_template_id)
                ok, err = validate_inheritance_constraints(
                    parent_template_id, body.fields, parent_fields, child_count,
                    check_child_limit=False
                )
                if not ok:
                    raise HTTPException(status_code=400, detail=err)

        validate_fields(body.fields, parent_fields)

        v_rows = await db.execute_fetchall(
            "SELECT MAX(version) as max_version FROM template_versions WHERE template_id = ?",
            (template_id,),
        )
        new_version = (v_rows[0]["max_version"] or 0) + 1

        template_name = t_rows[0]["name"]
        description = body.description if body.description is not None else t_rows[0]["description"]
        fields_json = fields_to_json(body.fields)

        await db.execute(
            "UPDATE templates SET description = ?, fields_json = ? WHERE id = ?",
            (description, fields_json, template_id),
        )

        cursor = await db.execute(
            """
            INSERT INTO template_versions (template_id, version, name, description, fields_json, parent_template_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (template_id, new_version, template_name, description, fields_json, parent_template_id),
        )
        version_id = cursor.lastrowid
        await db.commit()

        v_rows = await db.execute_fetchall(
            "SELECT * FROM template_versions WHERE id = ?", (version_id,)
        )
        v_row = v_rows[0]
    finally:
        await db.close()

    fields = json_to_fields(v_row["fields_json"])
    return TemplateVersionOut(
        id=v_row["id"],
        template_id=v_row["template_id"],
        version=v_row["version"],
        name=v_row["name"],
        description=v_row["description"] or "",
        fields=fields,
        parent_template_id=v_row["parent_template_id"] if "parent_template_id" in v_row.keys() else None,
        created_at=v_row["created_at"] or "",
    )


@router.delete("/{template_id}", status_code=204)
async def delete_template(template_id: int):
    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT * FROM templates WHERE id = ?", (template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        child_count = await get_child_template_count(db, template_id)
        if child_count > 0:
            raise HTTPException(
                status_code=400,
                detail=f"cannot delete template: it has {child_count} child template(s) depending on it. "
                       f"Delete the child templates first."
            )

        await db.execute("DELETE FROM templates WHERE id = ?", (template_id,))
        await db.commit()
    finally:
        await db.close()


@router.get("/{template_id}/full-fields", response_model=FullFieldsResult)
async def get_full_fields(
    template_id: int,
    version: int | None = Query(default=None, ge=1, description="Template version, uses latest if not specified"),
):
    result = await get_full_fields_internal(template_id, version)
    return FullFieldsResult(
        template_id=template_id,
        template_version=result["template_version"],
        parent_template_id=result["parent_template_id"],
        parent_template_version=result["parent_template_version"],
        fields=result["fields"],
        total_fields=result["total_fields"],
        inherited_fields=result["inherited_fields"],
        overridden_fields=result["overridden_fields"],
        new_fields=result["new_fields"],
    )


@router.get("/{template_id}/diff/{other_template_id}", response_model=TemplateDiffResult)
async def diff_templates(
    template_id: int,
    other_template_id: int,
    version_a: int | None = Query(default=None, ge=1, description="Version for template A"),
    version_b: int | None = Query(default=None, ge=1, description="Version for template B"),
):
    result_a = await get_full_fields_internal(template_id, version_a)
    result_b = await get_full_fields_internal(other_template_id, version_b)

    only_a, only_b, modified, same_count = compare_templates(
        result_a["fields"], result_b["fields"]
    )

    return TemplateDiffResult(
        template_a_id=template_id,
        template_a_version=result_a["template_version"],
        template_b_id=other_template_id,
        template_b_version=result_b["template_version"],
        only_a=only_a,
        only_b=only_b,
        modified=modified,
        same_fields=same_count,
        total_diff_fields=len(only_a) + len(only_b) + len(modified),
    )


@router.post("/migration/prepare", response_model=MigrationPrepareResult)
async def prepare_migration(body: MigrationPrepareRequest):
    if body.source_template_id == body.target_template_id:
        raise HTTPException(
            status_code=400,
            detail="source and target templates must be different"
        )

    db = await get_db()
    try:
        for tid in [body.source_template_id, body.target_template_id]:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM templates WHERE id = ?", (tid,)
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail=f"template {tid} not found")

        source_result = await get_full_fields_internal(body.source_template_id)
        target_result = await get_full_fields_internal(body.target_template_id)

        cache_rows = await db.execute_fetchall(
            """
            SELECT DISTINCT sample_id FROM parse_cache
            WHERE template_id = ?
            """,
            (body.source_template_id,)
        )
        sample_ids = [row["sample_id"] for row in cache_rows]

        s_rows = await db.execute_fetchall(
            "SELECT id FROM samples WHERE id IN ({seq})".format(
                seq=",".join("?" * len(sample_ids)) if sample_ids else "0"
            ),
            sample_ids if sample_ids else (),
        )
        existing_sample_ids = {row["id"] for row in s_rows}

        cursor = await db.execute(
            """
            INSERT INTO migration_tasks
            (source_template_id, target_template_id, source_template_version, target_template_version,
             total_samples, status)
            VALUES (?, ?, ?, ?, ?, 'pending')
            """,
            (
                body.source_template_id, body.target_template_id,
                source_result["template_version"], target_result["template_version"],
                len(existing_sample_ids)
            ),
        )
        task_id = cursor.lastrowid

        if existing_sample_ids:
            await db.execute(
                """
                UPDATE parse_cache SET needs_reparse = 1
                WHERE template_id = ?
                  AND sample_id IN ({seq})
                """.format(seq=",".join("?" * len(existing_sample_ids))),
                (body.source_template_id,) + tuple(existing_sample_ids)
            )

        await db.commit()
    finally:
        await db.close()

    return MigrationPrepareResult(
        migration_task_id=task_id,
        source_template_id=body.source_template_id,
        target_template_id=body.target_template_id,
        total_samples_marked=len(existing_sample_ids),
    )


@router.post("/migration/execute", response_model=MigrationExecuteResult)
async def execute_migration(body: MigrationExecuteRequest):
    db = await get_db()
    try:
        task_rows = await db.execute_fetchall(
            "SELECT * FROM migration_tasks WHERE id = ?",
            (body.migration_task_id,)
        )
        if not task_rows:
            raise HTTPException(status_code=404, detail="migration task not found")

        task = task_rows[0]
        if task["status"] == "running":
            raise HTTPException(status_code=400, detail="migration task is already running")
        if task["status"] == "completed":
            raise HTTPException(status_code=400, detail="migration task is already completed")

        await db.execute(
            "UPDATE migration_tasks SET status = 'running', started_at = CURRENT_TIMESTAMP WHERE id = ?",
            (body.migration_task_id,)
        )
        await db.commit()

        target_result = await get_full_fields_internal(task["target_template_id"])
        target_fields = target_result["fields"]
        target_version = target_result["template_version"]

        cache_rows = await db.execute_fetchall(
            """
            SELECT pc.* FROM parse_cache pc
            WHERE pc.template_id = ? AND pc.needs_reparse = 1
            ORDER BY pc.id
            """,
            (task["source_template_id"],)
        )

        success_count = 0
        failed_count = 0
        skipped_count = 0

        for cache_row in cache_rows:
            sample_id = cache_row["sample_id"]
            try:
                s_rows = await db.execute_fetchall(
                    "SELECT hex_data FROM samples WHERE id = ?", (sample_id,)
                )
                if not s_rows:
                    skipped_count += 1
                    continue

                raw = hex_to_bytes(s_rows[0]["hex_data"])
                parse_result = parse_message(
                    raw, target_fields, task["target_template_id"],
                    sample_id, target_version
                )
                parse_result_json = json.dumps(parse_result.model_dump())

                await db.execute(
                    """
                    INSERT OR REPLACE INTO parse_cache
                    (sample_id, template_id, template_version, parse_result_json, needs_reparse, created_at)
                    VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
                    """,
                    (
                        sample_id, task["target_template_id"], target_version,
                        parse_result_json
                    )
                )

                await db.execute(
                    "UPDATE parse_cache SET needs_reparse = 0 WHERE id = ?",
                    (cache_row["id"],)
                )

                success_count += 1
            except Exception as e:
                failed_count += 1
                print(f"Failed to reparse sample {sample_id}: {e}")

        await db.execute(
            """
            UPDATE migration_tasks
            SET status = 'completed', success_count = ?, failed_count = ?,
                skipped_count = ?, completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (success_count, failed_count, skipped_count, body.migration_task_id)
        )
        await db.commit()
    finally:
        await db.close()

    return MigrationExecuteResult(
        migration_task_id=body.migration_task_id,
        total_samples=success_count + failed_count + skipped_count,
        success_count=success_count,
        failed_count=failed_count,
        skipped_count=skipped_count,
        completed=True,
    )


@router.get("/migration/{task_id}", response_model=MigrationTaskStatus)
async def get_migration_status(task_id: int):
    db = await get_db()
    try:
        task_rows = await db.execute_fetchall(
            "SELECT * FROM migration_tasks WHERE id = ?", (task_id,)
        )
        if not task_rows:
            raise HTTPException(status_code=404, detail="migration task not found")

        task = task_rows[0]
    finally:
        await db.close()

    return MigrationTaskStatus(
        id=task["id"],
        source_template_id=task["source_template_id"],
        target_template_id=task["target_template_id"],
        source_template_version=task["source_template_version"],
        target_template_version=task["target_template_version"],
        status=task["status"],
        total_samples=task["total_samples"],
        success_count=task["success_count"],
        failed_count=task["failed_count"],
        skipped_count=task["skipped_count"],
        created_at=task["created_at"] or "",
        started_at=task["started_at"] or None,
        completed_at=task["completed_at"] or None,
    )


@router.get("/{template_id}/versions", response_model=list[TemplateVersionSummary])
async def list_template_versions(template_id: int):
    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT * FROM templates WHERE id = ?", (template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        rows = await db.execute_fetchall(
            "SELECT * FROM template_versions WHERE template_id = ? ORDER BY version DESC",
            (template_id,),
        )
    finally:
        await db.close()

    results = []
    for r in rows:
        fields = json_to_fields(r["fields_json"])
        results.append(
            TemplateVersionSummary(
                version=r["version"],
                name=r["name"],
                description=r["description"] or "",
                created_at=r["created_at"] or "",
                field_count=len(fields),
            )
        )
    return results


@router.get("/{template_id}/versions/{version}", response_model=TemplateVersionOut)
async def get_template_version(template_id: int, version: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
            (template_id, version),
        )
    finally:
        await db.close()

    if not rows:
        raise HTTPException(status_code=404, detail="template version not found")

    r = rows[0]
    fields = json_to_fields(r["fields_json"])
    return TemplateVersionOut(
        id=r["id"],
        template_id=r["template_id"],
        version=r["version"],
        name=r["name"],
        description=r["description"] or "",
        fields=fields,
        parent_template_id=r["parent_template_id"] if "parent_template_id" in r.keys() else None,
        created_at=r["created_at"] or "",
    )


@router.get("", response_model=list[TemplateOut])
async def list_templates(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM templates ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

        results = []
        for r in rows:
            fields = json_to_fields(r["fields_json"])
            parent_template_id = r["parent_template_id"] if "parent_template_id" in r.keys() else None
            child_count = await get_child_template_count(db, r["id"])
            results.append(
                TemplateOut(
                    id=r["id"],
                    name=r["name"],
                    description=r["description"] or "",
                    fields=fields,
                    parent_template_id=parent_template_id,
                    child_template_count=child_count,
                    created_at=r["created_at"] or "",
                )
            )
    finally:
        await db.close()

    return results


@router.get("/{template_id}", response_model=TemplateOut)
async def get_template(template_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM templates WHERE id = ?", (template_id,)
        )
        if not rows:
            raise HTTPException(status_code=404, detail="template not found")

        r = rows[0]
        fields = json_to_fields(r["fields_json"])
        parent_template_id = r["parent_template_id"] if "parent_template_id" in r.keys() else None
        child_count = await get_child_template_count(db, template_id)
    finally:
        await db.close()

    return TemplateOut(
        id=r["id"],
        name=r["name"],
        description=r["description"] or "",
        fields=fields,
        parent_template_id=parent_template_id,
        child_template_count=child_count,
        created_at=r["created_at"] or "",
    )
