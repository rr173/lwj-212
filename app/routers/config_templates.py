import re
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from app.database import get_db

router = APIRouter(prefix="/api/cfg/templates", tags=["config-templates"])

MAX_ITEMS_PER_TEMPLATE = 50
KEY_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{1,64}$')
INT_MIN = -2147483648
INT_MAX = 2147483647
STRING_MAX_LENGTH = 1024


class ConfigItemCreate(BaseModel):
    key_name: str
    value_type: str
    default_value: str
    constraint_min: Optional[float] = None
    constraint_max: Optional[float] = None
    constraint_max_length: Optional[int] = None


class TemplateCreate(BaseModel):
    name: str
    device_model: str
    items: list[ConfigItemCreate] = Field(..., max_length=50)


class ConfigItemOut(BaseModel):
    id: int
    key_name: str
    value_type: str
    default_value: str
    constraint_min: Optional[float] = None
    constraint_max: Optional[float] = None
    constraint_max_length: Optional[int] = None


class TemplateOut(BaseModel):
    id: int
    name: str
    device_model: str
    items: list[ConfigItemOut]
    created_at: str


def _validate_value(value_str: str, value_type: str, constraint_min=None, constraint_max=None, constraint_max_length=None) -> str:
    if value_type == 'int':
        try:
            v = int(value_str)
        except (ValueError, TypeError):
            return f"value '{value_str}' is not a valid int"
        if v < INT_MIN or v > INT_MAX:
            return f"int value {v} out of range ({INT_MIN} to {INT_MAX})"
        if constraint_min is not None and v < constraint_min:
            return f"int value {v} below minimum {constraint_min}"
        if constraint_max is not None and v > constraint_max:
            return f"int value {v} above maximum {constraint_max}"
    elif value_type == 'float':
        try:
            v = float(value_str)
        except (ValueError, TypeError):
            return f"value '{value_str}' is not a valid float"
        if v < INT_MIN or v > INT_MAX:
            return f"float value {v} out of representable range"
        if constraint_min is not None and v < constraint_min:
            return f"float value {v} below minimum {constraint_min}"
        if constraint_max is not None and v > constraint_max:
            return f"float value {v} above maximum {constraint_max}"
        rounded = round(v, 6)
        if rounded != v:
            return f"float value {v} exceeds 6 decimal places precision"
    elif value_type == 'string':
        max_len = constraint_max_length if constraint_max_length is not None else STRING_MAX_LENGTH
        if len(value_str) > max_len:
            return f"string length {len(value_str)} exceeds maximum {max_len}"
        if len(value_str) > STRING_MAX_LENGTH:
            return f"string length {len(value_str)} exceeds absolute maximum {STRING_MAX_LENGTH}"
    elif value_type == 'bool':
        if value_str.lower() not in ('true', 'false'):
            return f"value '{value_str}' is not a valid bool (true/false)"
    else:
        return f"invalid value_type '{value_type}'"
    return ""


def _validate_item_constraints(item: ConfigItemCreate) -> str:
    if item.value_type not in ('int', 'float', 'string', 'bool'):
        return f"invalid value_type '{item.value_type}'"
    if item.value_type in ('int', 'float'):
        if item.constraint_min is not None and item.constraint_max is not None:
            if item.constraint_min >= item.constraint_max:
                return f"constraint_min ({item.constraint_min}) must be less than constraint_max ({item.constraint_max})"
    if item.value_type == 'string':
        if item.constraint_max_length is not None and item.constraint_max_length < 0:
            return f"constraint_max_length cannot be negative"
        if item.constraint_max_length is not None and item.constraint_max_length > STRING_MAX_LENGTH:
            return f"constraint_max_length {item.constraint_max_length} exceeds absolute maximum {STRING_MAX_LENGTH}"
    if item.value_type == 'bool':
        if item.constraint_min is not None or item.constraint_max is not None or item.constraint_max_length is not None:
            return "bool type does not support constraints"
    return _validate_value(item.default_value, item.value_type, item.constraint_min, item.constraint_max, item.constraint_max_length)


@router.post("", response_model=TemplateOut, status_code=201)
async def create_template(body: TemplateCreate):
    if len(body.items) > MAX_ITEMS_PER_TEMPLATE:
        raise HTTPException(status_code=400, detail=f"template cannot have more than {MAX_ITEMS_PER_TEMPLATE} items")

    key_names = set()
    for item in body.items:
        if not KEY_NAME_PATTERN.match(item.key_name):
            raise HTTPException(status_code=400, detail=f"key_name '{item.key_name}' must match pattern [a-zA-Z0-9_] and be 1-64 chars")
        if item.key_name in key_names:
            raise HTTPException(status_code=400, detail=f"duplicate key_name '{item.key_name}' in template")
        key_names.add(item.key_name)

        err = _validate_item_constraints(item)
        if err:
            raise HTTPException(status_code=400, detail=f"item '{item.key_name}': {err}")

    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO cfg_templates (name, device_model) VALUES (?, ?)",
            (body.name, body.device_model),
        )
        template_id = cursor.lastrowid

        for item in body.items:
            await db.execute(
                "INSERT INTO cfg_template_items (template_id, key_name, value_type, default_value, constraint_min, constraint_max, constraint_max_length) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (template_id, item.key_name, item.value_type, item.default_value,
                 item.constraint_min, item.constraint_max, item.constraint_max_length),
            )
        await db.commit()

        row = await db.execute_fetchall("SELECT * FROM cfg_templates WHERE id = ?", (template_id,))
        item_rows = await db.execute_fetchall("SELECT * FROM cfg_template_items WHERE template_id = ? ORDER BY id", (template_id,))
    finally:
        await db.close()

    r = row[0]
    return TemplateOut(
        id=r["id"],
        name=r["name"],
        device_model=r["device_model"],
        items=[
            ConfigItemOut(
                id=ir["id"],
                key_name=ir["key_name"],
                value_type=ir["value_type"],
                default_value=ir["default_value"],
                constraint_min=ir["constraint_min"],
                constraint_max=ir["constraint_max"],
                constraint_max_length=ir["constraint_max_length"],
            )
            for ir in item_rows
        ],
        created_at=r["created_at"] or "",
    )


@router.get("", response_model=list[TemplateOut])
async def list_templates(
    device_model: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        query = "SELECT * FROM cfg_templates WHERE 1=1"
        params: list = []
        if device_model:
            query += " AND device_model = ?"
            params.append(device_model)
        query += " ORDER BY id ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = await db.execute_fetchall(query, params)

        result = []
        for r in rows:
            item_rows = await db.execute_fetchall(
                "SELECT * FROM cfg_template_items WHERE template_id = ? ORDER BY id",
                (r["id"],),
            )
            result.append(TemplateOut(
                id=r["id"],
                name=r["name"],
                device_model=r["device_model"],
                items=[
                    ConfigItemOut(
                        id=ir["id"],
                        key_name=ir["key_name"],
                        value_type=ir["value_type"],
                        default_value=ir["default_value"],
                        constraint_min=ir["constraint_min"],
                        constraint_max=ir["constraint_max"],
                        constraint_max_length=ir["constraint_max_length"],
                    )
                    for ir in item_rows
                ],
                created_at=r["created_at"] or "",
            ))
    finally:
        await db.close()

    return result


@router.get("/{template_id}", response_model=TemplateOut)
async def get_template(template_id: int):
    db = await get_db()
    try:
        row = await db.execute_fetchall("SELECT * FROM cfg_templates WHERE id = ?", (template_id,))
        if not row:
            raise HTTPException(status_code=404, detail="template not found")
        item_rows = await db.execute_fetchall(
            "SELECT * FROM cfg_template_items WHERE template_id = ? ORDER BY id",
            (template_id,),
        )
    finally:
        await db.close()

    r = row[0]
    return TemplateOut(
        id=r["id"],
        name=r["name"],
        device_model=r["device_model"],
        items=[
            ConfigItemOut(
                id=ir["id"],
                key_name=ir["key_name"],
                value_type=ir["value_type"],
                default_value=ir["default_value"],
                constraint_min=ir["constraint_min"],
                constraint_max=ir["constraint_max"],
                constraint_max_length=ir["constraint_max_length"],
            )
            for ir in item_rows
        ],
        created_at=r["created_at"] or "",
    )
