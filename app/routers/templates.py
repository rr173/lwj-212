import json
from fastapi import APIRouter, HTTPException, Query
from app.models import TemplateCreate, TemplateOut, FieldDef
from app.database import get_db

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


@router.post("", response_model=TemplateOut, status_code=201)
async def create_template(body: TemplateCreate):
    if not body.fields:
        raise HTTPException(status_code=400, detail="template must have at least one field")

    field_names = [f.name for f in body.fields]
    if len(field_names) != len(set(field_names)):
        raise HTTPException(status_code=400, detail="duplicate field names are not allowed")

    name_set = set(field_names)
    for i, f in enumerate(body.fields):
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
            if ref_idx >= i:
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
            if cond_idx >= i:
                raise HTTPException(
                    status_code=400,
                    detail=f"field '{f.name}': condition_field '{f.condition_field}' must appear before this field",
                )

    cycle_field = detect_circular_dependency(body.fields)
    if cycle_field:
        raise HTTPException(
            status_code=400,
            detail=f"circular dependency detected involving field '{cycle_field}'",
        )

    fields_json = json.dumps([f.model_dump() for f in body.fields])

    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO templates (name, description, fields_json) VALUES (?, ?, ?)",
            (body.name, body.description, fields_json),
        )
        await db.commit()
        template_id = cursor.lastrowid
    finally:
        await db.close()

    return TemplateOut(
        id=template_id,
        name=body.name,
        description=body.description,
        fields=body.fields,
        created_at="",
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
    finally:
        await db.close()

    results = []
    for r in rows:
        fields = [FieldDef(**f) for f in json.loads(r["fields_json"])]
        results.append(
            TemplateOut(
                id=r["id"],
                name=r["name"],
                description=r["description"] or "",
                fields=fields,
                created_at=r["created_at"] or "",
            )
        )
    return results


@router.get("/{template_id}", response_model=TemplateOut)
async def get_template(template_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM templates WHERE id = ?", (template_id,)
        )
    finally:
        await db.close()

    if not rows:
        raise HTTPException(status_code=404, detail="template not found")

    r = rows[0]
    fields = [FieldDef(**f) for f in json.loads(r["fields_json"])]
    return TemplateOut(
        id=r["id"],
        name=r["name"],
        description=r["description"] or "",
        fields=fields,
        created_at=r["created_at"] or "",
    )
