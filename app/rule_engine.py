import json
from typing import Any
from app.models import (
    ConditionCompare,
    ConditionExpr,
    ConditionLogical,
    FieldDef,
    NUMERIC_TYPES,
    STRING_TYPES,
)

MAX_NESTING_DEPTH = 3
MAX_RULES_PER_TEMPLATE = 20


def _data_type_category(data_type: str) -> str:
    if data_type in NUMERIC_TYPES:
        return "numeric"
    if data_type in STRING_TYPES:
        return "string"
    return "unknown"


def _validate_compare(
    cond: ConditionCompare,
    field_map: dict[str, FieldDef],
    path: str = "",
) -> list[str]:
    errors = []
    p = path or "condition"

    if cond.field not in field_map:
        errors.append(f"{p}: field '{cond.field}' does not exist in template")
        return errors

    field_def = field_map[cond.field]
    field_cat = _data_type_category(field_def.data_type)

    if field_cat == "string" and cond.op not in ("==", "!="):
        errors.append(
            f"{p}: field '{cond.field}' is {field_def.data_type}, only '==' or '!=' are allowed"
        )

    if cond.field_ref is not None:
        if cond.value is not None:
            errors.append(f"{p}: cannot specify both 'value' and 'field_ref'")
        if cond.field_ref not in field_map:
            errors.append(f"{p}: field_ref '{cond.field_ref}' does not exist in template")
            return errors
        ref_def = field_map[cond.field_ref]
        ref_cat = _data_type_category(ref_def.data_type)
        if field_cat != ref_cat:
            errors.append(
                f"{p}: cross-field comparison requires compatible types — "
                f"'{cond.field}' is {field_def.data_type} but "
                f"'{cond.field_ref}' is {ref_def.data_type}"
            )
        if field_cat == "string" and cond.op not in ("==", "!="):
            errors.append(
                f"{p}: cross-field string comparison only supports '==' or '!='"
            )
    else:
        if cond.value is None:
            errors.append(f"{p}: must specify either 'value' or 'field_ref'")
        else:
            if field_cat == "numeric":
                try:
                    float(cond.value)
                except (ValueError, TypeError):
                    errors.append(
                        f"{p}: field '{cond.field}' is numeric but value '{cond.value}' is not a number"
                    )

    return errors


def _validate_expression(
    expr: ConditionExpr,
    field_map: dict[str, FieldDef],
    depth: int = 0,
    path: str = "",
) -> list[str]:
    if depth > MAX_NESTING_DEPTH:
        return [f"{path or 'expression'}: exceeds max nesting depth of {MAX_NESTING_DEPTH}"]

    errors = []

    if isinstance(expr, ConditionCompare):
        errors.extend(_validate_compare(expr, field_map, path))
    elif isinstance(expr, ConditionLogical):
        p = path or expr.type
        if expr.type == "not":
            if len(expr.conditions) != 1:
                errors.append(f"{p}: 'not' requires exactly 1 sub-condition")
            for i, sub in enumerate(expr.conditions):
                errors.extend(
                    _validate_expression(sub, field_map, depth + 1, f"{p}.not[{i}]")
                )
        else:
            if len(expr.conditions) < 2:
                errors.append(f"{p}: '{expr.type}' requires at least 2 sub-conditions")
            for i, sub in enumerate(expr.conditions):
                errors.extend(
                    _validate_expression(sub, field_map, depth + 1, f"{p}.{expr.type}[{i}]")
                )

    return errors


def validate_rule_expression(
    expression: ConditionExpr,
    template_fields: list[FieldDef],
) -> list[str]:
    field_map = {f.name: f for f in template_fields}
    return _validate_expression(expression, field_map)


def _coerce_numeric(value: Any) -> float | int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    try:
        s = str(value)
        if "." in s:
            return float(s)
        return int(s)
    except (ValueError, TypeError):
        return None


def _resolve_field_value(
    field_name: str,
    parsed_fields: dict[str, dict],
    field_defs: dict[str, FieldDef],
) -> tuple[Any, str | None]:
    pf = parsed_fields.get(field_name)
    if pf is None or pf.get("status") != "ok":
        return None, None
    raw_value = pf.get("value")
    if raw_value is None:
        return None, None
    fd = field_defs.get(field_name)
    if fd is None:
        return str(raw_value), "string"
    cat = _data_type_category(fd.data_type)
    if cat == "numeric":
        return _coerce_numeric(raw_value), "numeric"
    return str(raw_value), "string"


def _apply_op(a: Any, b: Any, op: str, category: str) -> bool | None:
    if a is None or b is None:
        return None
    if category == "numeric":
        a_num = _coerce_numeric(a)
        b_num = _coerce_numeric(b)
        if a_num is None or b_num is None:
            return None
        if op == "==":
            return a_num == b_num
        if op == "!=":
            return a_num != b_num
        if op == ">":
            return a_num > b_num
        if op == "<":
            return a_num < b_num
        if op == ">=":
            return a_num >= b_num
        if op == "<=":
            return a_num <= b_num
    else:
        a_str = str(a)
        b_str = str(b)
        if op == "==":
            return a_str == b_str
        if op == "!=":
            return a_str != b_str
    return None


def _evaluate_compare(
    cond: ConditionCompare,
    parsed_fields: dict[str, dict],
    field_defs: dict[str, FieldDef],
) -> bool | None:
    left_val, left_cat = _resolve_field_value(cond.field, parsed_fields, field_defs)
    if left_val is None:
        return None

    if cond.field_ref is not None:
        right_val, right_cat = _resolve_field_value(cond.field_ref, parsed_fields, field_defs)
        if right_val is None:
            return None
        if left_cat != right_cat:
            return None
        return _apply_op(left_val, right_val, cond.op, left_cat)
    else:
        fd = field_defs.get(cond.field)
        cat = _data_type_category(fd.data_type) if fd else left_cat
        return _apply_op(left_val, cond.value, cond.op, cat)


def evaluate_expression(
    expr: ConditionExpr,
    parsed_fields: dict[str, dict],
    field_defs: dict[str, FieldDef],
) -> bool | None:
    if isinstance(expr, ConditionCompare):
        return _evaluate_compare(expr, parsed_fields, field_defs)
    elif isinstance(expr, ConditionLogical):
        if expr.type == "not":
            sub = evaluate_expression(expr.conditions[0], parsed_fields, field_defs) if len(expr.conditions) > 0 else None
            if sub is None:
                return None
            return not sub
        elif expr.type == "and":
            all_true = True
            for sub in expr.conditions:
                r = evaluate_expression(sub, parsed_fields, field_defs)
                if r is None or r is False:
                    if r is None:
                        return None
                    all_true = False
            return all_true
        elif expr.type == "or":
            any_true = False
            has_none = False
            for sub in expr.conditions:
                r = evaluate_expression(sub, parsed_fields, field_defs)
                if r is None:
                    has_none = True
                elif r is True:
                    any_true = True
            if any_true:
                return True
            if has_none:
                return None
            return False
    return None


def _describe_compare(cond: ConditionCompare, field_defs: dict[str, FieldDef]) -> str:
    if cond.field_ref is not None:
        return f"{cond.field} {cond.op} {cond.field_ref}"
    return f"{cond.field} {cond.op} {cond.value!r}"


def evaluate_with_trace(
    expr: ConditionExpr,
    parsed_fields: dict[str, dict],
    field_defs: dict[str, FieldDef],
) -> tuple[bool | None, list[tuple[str, bool | None]]]:
    trace: list[tuple[str, bool | None]] = []
    result = _eval_trace(expr, parsed_fields, field_defs, trace)
    return result, trace


def _eval_trace(
    expr: ConditionExpr,
    parsed_fields: dict[str, dict],
    field_defs: dict[str, FieldDef],
    trace: list[tuple[str, bool | None]],
) -> bool | None:
    if isinstance(expr, ConditionCompare):
        r = _evaluate_compare(expr, parsed_fields, field_defs)
        trace.append((_describe_compare(expr, field_defs), r))
        return r
    elif isinstance(expr, ConditionLogical):
        if expr.type == "not":
            if len(expr.conditions) > 0:
                sub = _eval_trace(expr.conditions[0], parsed_fields, field_defs, trace)
                result = None if sub is None else not sub
            else:
                result = None
            trace.append((f"NOT(...)", result))
            return result
        elif expr.type in ("and", "or"):
            sub_results = []
            for sub in expr.conditions:
                sub_results.append(_eval_trace(sub, parsed_fields, field_defs, trace))
            if expr.type == "and":
                if any(r is None for r in sub_results):
                    result = None
                else:
                    result = all(sub_results)
            else:
                if any(r is True for r in sub_results):
                    result = True
                elif any(r is None for r in sub_results):
                    result = None
                else:
                    result = False
            trace.append((f"{expr.type.upper()}(...)", result))
            return result
    return None


def expression_to_dict(expr: ConditionExpr) -> dict:
    if isinstance(expr, ConditionCompare):
        d = {"type": "compare", "field": expr.field, "op": expr.op}
        if expr.field_ref is not None:
            d["field_ref"] = expr.field_ref
        else:
            d["value"] = expr.value
        return d
    elif isinstance(expr, ConditionLogical):
        return {
            "type": expr.type,
            "conditions": [expression_to_dict(c) for c in expr.conditions],
        }
    return {}


def dict_to_expression(data: dict) -> ConditionExpr:
    t = data.get("type", "compare")
    if t == "compare":
        return ConditionCompare(**data)
    elif t in ("and", "or", "not"):
        sub = [dict_to_expression(c) for c in data.get("conditions", [])]
        return ConditionLogical(type=t, conditions=sub)
    return ConditionCompare(**data)
