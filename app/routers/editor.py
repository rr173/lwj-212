from fastapi import APIRouter, HTTPException
from app.models import (
    ValidateFieldsRequest,
    ValidateFieldsResult,
    FieldValidationDetail,
    AssembleRequest,
    AssembleResult,
    SampleEditRequest,
    SampleEditResult,
    FieldDiffEntry,
    BatchMutateRequest,
    BatchMutateResult,
    MutatedSampleOut,
    FieldDef,
)
from app.editor import (
    validate_field_value,
    assemble_message,
    generate_mutation_value,
    get_template_fields,
    get_sample_hex,
    save_sample,
    NUMERIC_TYPES,
)
from app.parser import parse_message
from app.utils import hex_to_bytes

router = APIRouter(prefix="/api/editor", tags=["editor"])


def _validate_modifications(
    fields: list[FieldDef],
    modifications: list,
) -> list[FieldValidationDetail]:
    field_map = {f.name: f for f in fields}
    details: list[FieldValidationDetail] = []
    for mod in modifications:
        field_def = field_map.get(mod.field_name)
        if field_def is None:
            details.append(
                FieldValidationDetail(
                    field_name=mod.field_name,
                    valid=False,
                    error=f"field '{mod.field_name}' not found in template",
                )
            )
            continue
        valid, error = validate_field_value(field_def, mod.new_value)
        details.append(
            FieldValidationDetail(
                field_name=mod.field_name,
                valid=valid,
                error=error,
            )
        )
    return details


@router.post("/validate", response_model=ValidateFieldsResult)
async def validate_fields(body: ValidateFieldsRequest):
    fields, actual_version, _ = await get_template_fields(body.template_id, body.template_version)
    if fields is None:
        raise HTTPException(status_code=404, detail="template not found")

    details = _validate_modifications(fields, body.modifications)
    all_valid = all(d.valid for d in details)

    return ValidateFieldsResult(
        template_id=body.template_id,
        template_version=actual_version,
        all_valid=all_valid,
        details=details,
    )


@router.post("/assemble", response_model=AssembleResult)
async def assemble_message_endpoint(body: AssembleRequest):
    fields, actual_version, _ = await get_template_fields(body.template_id, body.template_version)
    if fields is None:
        raise HTTPException(status_code=404, detail="template not found")

    field_map = {f.name: f for f in fields}
    missing_fields = [f.name for f in fields if f.name not in body.field_values]
    if missing_fields:
        raise HTTPException(
            status_code=400,
            detail=f"missing field values: {', '.join(missing_fields)}",
        )

    extra_fields = [k for k in body.field_values if k not in field_map]
    if extra_fields:
        raise HTTPException(
            status_code=400,
            detail=f"unknown fields: {', '.join(extra_fields)}",
        )

    for f in fields:
        val = body.field_values.get(f.name)
        if val is not None:
            valid, error = validate_field_value(f, val)
            if not valid:
                raise HTTPException(
                    status_code=400,
                    detail=f"field '{f.name}': {error}",
                )

    try:
        msg_bytes, encoding_details = assemble_message(fields, body.field_values)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return AssembleResult(
        template_id=body.template_id,
        template_version=actual_version,
        hex_data=msg_bytes.hex(),
        byte_length=len(msg_bytes),
        field_encodings=encoding_details,
    )


@router.post("/sample-edit", response_model=SampleEditResult)
async def edit_sample(body: SampleEditRequest):
    fields, actual_version, _ = await get_template_fields(body.template_id, body.template_version)
    if fields is None:
        raise HTTPException(status_code=404, detail="template not found")

    original_hex = await get_sample_hex(body.sample_id)
    if original_hex is None:
        raise HTTPException(status_code=404, detail=f"sample {body.sample_id} not found")

    raw = hex_to_bytes(original_hex)
    parse_result = parse_message(raw, fields, body.template_id, body.sample_id, actual_version)

    parse_error_fields = set()
    for pf in parse_result.fields:
        if pf.status == "parse_error":
            parse_error_fields.add(pf.name)

    modification_map = {m.field_name: m.new_value for m in body.modifications}

    unresolved_errors = parse_error_fields - set(modification_map.keys())
    if unresolved_errors:
        raise HTTPException(
            status_code=400,
            detail=f"fields with parse errors must be given new values: {', '.join(sorted(unresolved_errors))}",
        )

    current_values: dict[str, str] = {}
    for pf in parse_result.fields:
        if pf.status == "ok" and pf.value is not None:
            current_values[pf.name] = pf.value

    for field_def in fields:
        if field_def.name in modification_map:
            current_values[field_def.name] = modification_map[field_def.name]
        elif field_def.name not in current_values:
            if field_def.name in modification_map:
                current_values[field_def.name] = modification_map[field_def.name]

    missing = [f.name for f in fields if f.name not in current_values]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"cannot determine values for fields: {', '.join(missing)}",
        )

    try:
        msg_bytes, encoding_details = assemble_message(fields, current_values)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    modified_hex = msg_bytes.hex()

    field_diffs: list[FieldDiffEntry] = []
    original_values: dict[str, str] = {}
    original_hex_map: dict[str, str] = {}
    for pf in parse_result.fields:
        if pf.status == "ok":
            original_values[pf.name] = pf.value or ""
            original_hex_map[pf.name] = pf.hex
        else:
            original_values[pf.name] = None
            original_hex_map[pf.name] = pf.hex or ""

    modified_values: dict[str, str] = {}
    modified_hex_map: dict[str, str] = {}
    for ed in encoding_details:
        if not ed.skipped:
            modified_values[ed.field_name] = ed.value
            modified_hex_map[ed.field_name] = ed.hex

    for field_def in fields:
        orig_val = original_values.get(field_def.name)
        mod_val = modified_values.get(field_def.name)
        orig_h = original_hex_map.get(field_def.name, "")
        mod_h = modified_hex_map.get(field_def.name, "")
        changed = (orig_val != mod_val) or (orig_h != mod_h)
        field_diffs.append(
            FieldDiffEntry(
                field_name=field_def.name,
                original_value=orig_val,
                modified_value=mod_val,
                original_hex=orig_h,
                modified_hex=mod_h,
                changed=changed,
            )
        )

    reparsed = parse_message(msg_bytes, fields, body.template_id, body.sample_id, actual_version)

    return SampleEditResult(
        sample_id=body.sample_id,
        template_id=body.template_id,
        template_version=actual_version,
        original_hex=original_hex,
        modified_hex=modified_hex,
        field_diffs=field_diffs,
        parse_result=reparsed,
    )


@router.post("/batch-mutate", response_model=BatchMutateResult)
async def batch_mutate(body: BatchMutateRequest):
    fields, actual_version, template_name = await get_template_fields(body.template_id, body.template_version)
    if fields is None:
        raise HTTPException(status_code=404, detail="template not found")

    field_map = {f.name: f for f in fields}
    missing = [f.name for f in fields if f.name not in body.base_values]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"missing base values for fields: {', '.join(missing)}",
        )

    for rule in body.rules:
        if rule.target_field not in field_map:
            raise HTTPException(
                status_code=400,
                detail=f"mutation target field '{rule.target_field}' not found in template",
            )
        if rule.mutation_type == "increment" and rule.start_value is None:
            raise HTTPException(
                status_code=400,
                detail=f"increment mutation for field '{rule.target_field}' requires start_value",
            )
        if rule.mutation_type == "enumerate" and not rule.value_list:
            raise HTTPException(
                status_code=400,
                detail=f"enumerate mutation for field '{rule.target_field}' requires value_list",
            )

    rule_map = {r.target_field: r for r in body.rules}

    generated: list[MutatedSampleOut] = []

    for i in range(body.count):
        current_values = dict(body.base_values)

        for field_name, rule in rule_map.items():
            field_def = field_map[field_name]
            new_val = generate_mutation_value(rule, field_def.data_type, i)
            current_values[field_name] = new_val

        try:
            msg_bytes, _ = assemble_message(fields, current_values)
        except ValueError as e:
            continue

        hex_data = msg_bytes.hex()
        mutation_desc = ", ".join(
            f"{fn}={current_values[fn]}" for fn in rule_map if fn in current_values
        )
        name = f"[edit] {template_name}-{','.join(rule_map.keys())}-{i + 1:03d}"
        note = f"batch mutate: {mutation_desc}"

        sample_id = await save_sample(name, hex_data, note)

        mutations = {fn: current_values[fn] for fn in rule_map if fn in current_values}
        generated.append(
            MutatedSampleOut(
                sample_id=sample_id,
                name=name,
                hex_data=hex_data,
                mutations=mutations,
            )
        )

    return BatchMutateResult(
        template_id=body.template_id,
        template_version=actual_version,
        total_generated=len(generated),
        samples=generated,
    )
