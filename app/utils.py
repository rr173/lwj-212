import math
import json
from collections import Counter
from typing import Optional
from fastapi import HTTPException
from app.models import FieldDef, FieldDefDiff, FieldAttributeDiff, MAX_CHILD_TEMPLATES
from app.database import get_db


def validate_hex(hex_str: str) -> str:
    cleaned = hex_str.strip().lower()
    if not cleaned:
        raise ValueError("hex string is empty")
    if len(cleaned) % 2 != 0:
        raise ValueError("hex string has odd length")
    if not all(c in "0123456789abcdef" for c in cleaned):
        raise ValueError("hex string contains invalid characters")
    return cleaned


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def merge_template_fields(
    parent_fields: list[FieldDef],
    child_fields: list[FieldDef]
) -> tuple[list[FieldDef], int, int, int]:
    child_field_names = {f.name for f in child_fields}
    parent_field_names = {f.name for f in parent_fields}

    overridden_fields = parent_field_names & child_field_names
    new_fields = child_field_names - parent_field_names
    inherited_fields = parent_field_names - overridden_fields

    merged_fields: list[FieldDef] = []
    child_field_map = {f.name: f for f in child_fields}

    for parent_field in parent_fields:
        if parent_field.name in child_field_map:
            merged_fields.append(child_field_map[parent_field.name])
        else:
            merged_fields.append(parent_field)

    for child_field in child_fields:
        if child_field.name not in parent_field_names:
            merged_fields.append(child_field)

    return merged_fields, len(inherited_fields), len(overridden_fields), len(new_fields)


def compare_field_defs(a: FieldDef, b: FieldDef) -> list[FieldAttributeDiff]:
    diffs: list[FieldAttributeDiff] = []
    attributes = [
        "length_rule", "length_value", "length_ref_field",
        "until_byte", "data_type", "condition_field", "condition_value"
    ]

    for attr in attributes:
        a_val = getattr(a, attr)
        b_val = getattr(b, attr)
        if a_val != b_val:
            diffs.append(FieldAttributeDiff(
                attribute=attr,
                a_value=str(a_val) if a_val is not None else None,
                b_value=str(b_val) if b_val is not None else None
            ))

    return diffs


def compare_templates(
    fields_a: list[FieldDef],
    fields_b: list[FieldDef]
) -> tuple[list[FieldDef], list[FieldDef], list[FieldDefDiff], int]:
    a_map = {f.name: f for f in fields_a}
    b_map = {f.name: f for f in fields_b}

    a_names = set(a_map.keys())
    b_names = set(b_map.keys())

    only_a_names = a_names - b_names
    only_b_names = b_names - a_names
    common_names = a_names & b_names

    only_a = [a_map[name] for name in sorted(only_a_names)]
    only_b = [b_map[name] for name in sorted(only_b_names)]

    modified: list[FieldDefDiff] = []
    same_count = 0

    for name in sorted(common_names):
        a_field = a_map[name]
        b_field = b_map[name]
        attr_diffs = compare_field_defs(a_field, b_field)
        if attr_diffs:
            modified.append(FieldDefDiff(
                field_name=name,
                diff_type="modified",
                a_def=a_field,
                b_def=b_field,
                modified_attributes=attr_diffs
            ))
        else:
            same_count += 1

    return only_a, only_b, modified, same_count


def validate_inheritance_constraints(
    parent_template_id: Optional[int],
    child_fields: list[FieldDef],
    parent_fields: Optional[list[FieldDef]] = None,
    existing_child_count: int = 0
) -> tuple[bool, Optional[str]]:
    if parent_template_id is None:
        return True, None

    if existing_child_count >= MAX_CHILD_TEMPLATES:
        return False, f"parent template already has {MAX_CHILD_TEMPLATES} child templates, maximum allowed"

    if parent_fields is not None:
        parent_names = {f.name for f in parent_fields}
        child_names = {f.name for f in child_fields}
        for name in child_names:
            if name in parent_names:
                child_field = next(f for f in child_fields if f.name == name)
                parent_field = next(f for f in parent_fields if f.name == name)
                if child_field.name != parent_field.name:
                    return False, f"field name mismatch for '{name}': must exactly match parent field name"

    return True, None


def validate_no_grandchildren(parent_has_parent: bool) -> tuple[bool, Optional[str]]:
    if parent_has_parent:
        return False, "multi-level inheritance is not supported: parent template cannot have its own parent"
    return True, None


def fields_to_json(fields: list[FieldDef]) -> str:
    return json.dumps([f.model_dump() for f in fields])


def json_to_fields(json_str: str) -> list[FieldDef]:
    return [FieldDef(**f) for f in json.loads(json_str)]


async def get_full_fields_internal(template_id: int, version: int | None = None):
    db = await get_db()
    try:
        if version is not None:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
                (template_id, version),
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail="template version not found")
            child_fields = json_to_fields(t_rows[0]["fields_json"])
            child_version = version
            parent_template_id = t_rows[0]["parent_template_id"] if "parent_template_id" in t_rows[0].keys() else None
        else:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM templates WHERE id = ?", (template_id,)
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail="template not found")
            child_fields = json_to_fields(t_rows[0]["fields_json"])
            parent_template_id = t_rows[0]["parent_template_id"] if "parent_template_id" in t_rows[0].keys() else None
            v_rows = await db.execute_fetchall(
                "SELECT MAX(version) as max_version FROM template_versions WHERE template_id = ?",
                (template_id,),
            )
            child_version = v_rows[0]["max_version"] or 1

        parent_fields = None
        parent_version = None

        if parent_template_id is not None:
            p_rows = await db.execute_fetchall(
                "SELECT * FROM templates WHERE id = ?", (parent_template_id,)
            )
            if not p_rows:
                raise HTTPException(status_code=404, detail=f"parent template {parent_template_id} not found")

            pv_rows = await db.execute_fetchall(
                "SELECT MAX(version) as max_version FROM template_versions WHERE template_id = ?",
                (parent_template_id,),
            )
            parent_version = pv_rows[0]["max_version"] or 1
            parent_fields = json_to_fields(p_rows[0]["fields_json"])

            merged_fields, inherited_count, overridden_count, new_count = merge_template_fields(
                parent_fields, child_fields
            )
        else:
            merged_fields = child_fields
            inherited_count = 0
            overridden_count = 0
            new_count = len(child_fields)

        return {
            "fields": merged_fields,
            "template_version": child_version,
            "parent_template_id": parent_template_id,
            "parent_template_version": parent_version,
            "inherited_fields": inherited_count,
            "overridden_fields": overridden_count,
            "new_fields": new_count,
            "total_fields": len(merged_fields),
        }
    finally:
        await db.close()
