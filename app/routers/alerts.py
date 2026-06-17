import json
from collections import Counter
from fastapi import APIRouter, HTTPException
from app.models import (
    AlertRuleCreate,
    AlertRuleOut,
    ConditionExpr,
    ConditionEvaluation,
    CriticalAlertDetail,
    DetectAlertsRequest,
    DetectAlertsResult,
    DryRunRequest,
    DryRunResult,
    FieldDef,
    ParseResult,
    ScanAlertsRequest,
    ScanAlertsResult,
    TriggeredAlert,
)
from app.database import get_db
from app.rule_engine import (
    MAX_RULES_PER_TEMPLATE,
    dict_to_expression,
    evaluate_expression,
    evaluate_with_trace,
    expression_to_dict,
    validate_rule_expression,
)
from app.utils import hex_to_bytes
from app.parser import parse_message
from app.fingerprint import (
    match_template_fingerprints,
    sort_recognized_templates,
)
from app.models import RecognizedTemplate

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


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


async def _recognize_template_by_sample(sample_id: int) -> tuple[int, list[FieldDef], int]:
    raw = await _get_sample_data(sample_id)

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

            matched, is_full_match = match_template_fingerprints(raw, fingerprints)

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
    if not sorted_results:
        raise HTTPException(status_code=400, detail="cannot auto-recognize template for this sample, please specify template_id")

    full_matches = [t for t in sorted_results if t.is_full_match]
    if len(full_matches) != 1:
        raise HTTPException(status_code=400, detail="ambiguous template recognition, please specify template_id explicitly")

    template_id = full_matches[0].template_id
    fields, version = await _get_template_fields(template_id)
    return template_id, fields, version


def _parsed_fields_to_dict(parse_result: ParseResult) -> dict[str, dict]:
    result = {}
    for pf in parse_result.fields:
        result[pf.name] = {
            "value": pf.value,
            "status": pf.status,
            "hex": pf.hex,
        }
    return result


def _collect_field_values_for_alert(
    expression: ConditionExpr,
    parsed_fields: dict[str, dict],
    field_defs: dict[str, FieldDef],
) -> dict[str, str | int | float | None]:
    values: dict[str, str | int | float | None] = {}

    def walk(expr: ConditionExpr):
        from app.models import ConditionCompare, ConditionLogical
        if isinstance(expr, ConditionCompare):
            if expr.field not in values:
                pf = parsed_fields.get(expr.field)
                if pf is not None and pf.get("status") == "ok":
                    fd = field_defs.get(expr.field)
                    raw = pf.get("value")
                    if fd and fd.data_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
                        try:
                            values[expr.field] = int(raw) if raw is not None else None
                        except (ValueError, TypeError):
                            values[expr.field] = raw
                    else:
                        values[expr.field] = raw
                else:
                    values[expr.field] = None
            if expr.field_ref and expr.field_ref not in values:
                pf = parsed_fields.get(expr.field_ref)
                if pf is not None and pf.get("status") == "ok":
                    fd = field_defs.get(expr.field_ref)
                    raw = pf.get("value")
                    if fd and fd.data_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
                        try:
                            values[expr.field_ref] = int(raw) if raw is not None else None
                        except (ValueError, TypeError):
                            values[expr.field_ref] = raw
                    else:
                        values[expr.field_ref] = raw
                else:
                    values[expr.field_ref] = None
        elif isinstance(expr, ConditionLogical):
            for sub in expr.conditions:
                walk(sub)

    walk(expression)
    return values


@router.post("/rules", response_model=AlertRuleOut, status_code=201)
async def create_alert_rule(body: AlertRuleCreate):
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="rule name cannot be empty")

    fields, _ = await _get_template_fields(body.template_id)
    errors = validate_rule_expression(body.expression, fields)
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))

    expression_dict = expression_to_dict(body.expression)
    expression_json = json.dumps(expression_dict)

    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT id FROM templates WHERE id = ?", (body.template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        count_rows = await db.execute_fetchall(
            "SELECT COUNT(*) as cnt FROM alert_rules WHERE template_id = ?",
            (body.template_id,),
        )
        current_count = count_rows[0]["cnt"]
        if current_count >= MAX_RULES_PER_TEMPLATE:
            raise HTTPException(
                status_code=400,
                detail=f"maximum {MAX_RULES_PER_TEMPLATE} rules per template",
            )

        try:
            cursor = await db.execute(
                """
                INSERT INTO alert_rules (template_id, name, severity, expression_json)
                VALUES (?, ?, ?, ?)
                """,
                (body.template_id, body.name, body.severity, expression_json),
            )
        except Exception as e:
            if "UNIQUE constraint failed" in str(e):
                raise HTTPException(
                    status_code=400,
                    detail=f"rule name '{body.name}' already exists for this template",
                )
            raise
        rule_id = cursor.lastrowid
        await db.commit()

        rows = await db.execute_fetchall(
            "SELECT * FROM alert_rules WHERE id = ?", (rule_id,)
        )
    finally:
        await db.close()

    r = rows[0]
    return AlertRuleOut(
        id=r["id"],
        template_id=r["template_id"],
        name=r["name"],
        severity=r["severity"],
        expression=json.loads(r["expression_json"]),
        created_at=r["created_at"] or "",
    )


@router.get("/rules/template/{template_id}", response_model=list[AlertRuleOut])
async def list_alert_rules(template_id: int):
    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT id FROM templates WHERE id = ?", (template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        rows = await db.execute_fetchall(
            "SELECT * FROM alert_rules WHERE template_id = ? ORDER BY id ASC",
            (template_id,),
        )
    finally:
        await db.close()

    results = []
    for r in rows:
        results.append(
            AlertRuleOut(
                id=r["id"],
                template_id=r["template_id"],
                name=r["name"],
                severity=r["severity"],
                expression=json.loads(r["expression_json"]),
                created_at=r["created_at"] or "",
            )
        )
    return results


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_alert_rule(rule_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT id FROM alert_rules WHERE id = ?", (rule_id,)
        )
        if not rows:
            raise HTTPException(status_code=404, detail="alert rule not found")

        await db.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
        await db.commit()
    finally:
        await db.close()


@router.post("/detect", response_model=DetectAlertsResult)
async def detect_alerts(body: DetectAlertsRequest):
    auto_recognized = body.template_id is None
    if body.template_id is not None:
        template_id = body.template_id
        fields, version = await _get_template_fields(template_id)
    else:
        template_id, fields, version = await _recognize_template_by_sample(body.sample_id)

    raw = await _get_sample_data(body.sample_id)
    parse_result = parse_message(raw, fields, template_id, body.sample_id, version)

    if auto_recognized:
        parse_errors = [f for f in parse_result.fields if f.status == "parse_error"]
        if parse_errors:
            error_fields = [f"'{f.name}'" for f in parse_errors]
            raise HTTPException(
                status_code=400,
                detail=(
                    f"auto-recognized template (id={template_id}, version={version}) "
                    f"failed to parse {len(parse_errors)} field(s): {', '.join(error_fields)}. "
                    f"This may indicate a template version mismatch. "
                    f"Please specify template_id and optionally template_version explicitly."
                ),
            )

    parsed_fields_dict = _parsed_fields_to_dict(parse_result)
    field_defs_dict = {f.name: f for f in fields}

    db = await get_db()
    try:
        rule_rows = await db.execute_fetchall(
            "SELECT * FROM alert_rules WHERE template_id = ? ORDER BY id ASC",
            (template_id,),
        )
    finally:
        await db.close()

    triggered: list[TriggeredAlert] = []
    for r in rule_rows:
        expr_dict = json.loads(r["expression_json"])
        expr = dict_to_expression(expr_dict)
        result = evaluate_expression(expr, parsed_fields_dict, field_defs_dict)
        if result is True:
            field_values = _collect_field_values_for_alert(expr, parsed_fields_dict, field_defs_dict)
            triggered.append(
                TriggeredAlert(
                    rule_id=r["id"],
                    rule_name=r["name"],
                    severity=r["severity"],
                    field_values=field_values,
                )
            )

    return DetectAlertsResult(
        sample_id=body.sample_id,
        template_id=template_id,
        template_version=version,
        parse_result=parse_result,
        triggered_alerts=triggered,
    )


@router.post("/scan", response_model=ScanAlertsResult)
async def scan_alerts(body: ScanAlertsRequest):
    template_id = body.template_id
    fields, version = await _get_template_fields(template_id)
    field_defs_dict = {f.name: f for f in fields}

    db = await get_db()
    try:
        rule_rows = await db.execute_fetchall(
            "SELECT * FROM alert_rules WHERE template_id = ? ORDER BY id ASC",
            (template_id,),
        )
    finally:
        await db.close()

    rules = []
    for r in rule_rows:
        rules.append({
            "id": r["id"],
            "name": r["name"],
            "severity": r["severity"],
            "expression": dict_to_expression(json.loads(r["expression_json"])),
        })

    samples_with_alerts = 0
    rule_trigger_count: Counter = Counter()
    severity_count: Counter = Counter({"info": 0, "warning": 0, "critical": 0})
    critical_details: list[CriticalAlertDetail] = []
    skipped_sample_ids: list[int] = []
    processed_count = 0

    for sid in body.sample_ids:
        try:
            raw = await _get_sample_data(sid)
        except HTTPException:
            skipped_sample_ids.append(sid)
            continue

        processed_count += 1
        parse_result = parse_message(raw, fields, template_id, sid, version)
        parsed_fields_dict = _parsed_fields_to_dict(parse_result)

        sample_triggered = False
        for rule in rules:
            result = evaluate_expression(rule["expression"], parsed_fields_dict, field_defs_dict)
            if result is True:
                sample_triggered = True
                rule_trigger_count[rule["name"]] += 1
                severity_count[rule["severity"]] += 1

                if rule["severity"] == "critical":
                    field_values = _collect_field_values_for_alert(
                        rule["expression"], parsed_fields_dict, field_defs_dict
                    )
                    critical_details.append(
                        CriticalAlertDetail(
                            sample_id=sid,
                            rule_name=rule["name"],
                            field_values=field_values,
                        )
                    )

        if sample_triggered:
            samples_with_alerts += 1

    ranking = [
        {"rule_name": name, "trigger_count": count}
        for name, count in rule_trigger_count.most_common()
    ]

    return ScanAlertsResult(
        template_id=template_id,
        template_version=version,
        total_samples=len(body.sample_ids),
        processed_samples=processed_count,
        skipped_sample_ids=skipped_sample_ids,
        samples_with_alerts=samples_with_alerts,
        rule_trigger_ranking=ranking,
        severity_stats=dict(severity_count),
        critical_alerts=critical_details,
    )


@router.post("/dry-run", response_model=DryRunResult)
async def dry_run_rule(body: DryRunRequest):
    auto_recognized = body.template_id is None
    if body.template_id is not None:
        template_id = body.template_id
        fields, version = await _get_template_fields(template_id)
    else:
        template_id, fields, version = await _recognize_template_by_sample(body.sample_id)

    errors = validate_rule_expression(body.expression, fields)
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))

    raw = await _get_sample_data(body.sample_id)
    parse_result = parse_message(raw, fields, template_id, body.sample_id, version)

    if auto_recognized:
        parse_errors = [f for f in parse_result.fields if f.status == "parse_error"]
        if parse_errors:
            error_fields = [f"'{f.name}'" for f in parse_errors]
            raise HTTPException(
                status_code=400,
                detail=(
                    f"auto-recognized template (id={template_id}, version={version}) "
                    f"failed to parse {len(parse_errors)} field(s): {', '.join(error_fields)}. "
                    f"This may indicate a template version mismatch. "
                    f"Please specify template_id and optionally template_version explicitly."
                ),
            )

    parsed_fields_dict = _parsed_fields_to_dict(parse_result)
    field_defs_dict = {f.name: f for f in fields}

    triggered, trace = evaluate_with_trace(body.expression, parsed_fields_dict, field_defs_dict)

    evaluations = [
        ConditionEvaluation(description=desc, result=res)
        for desc, res in trace
    ]

    field_values = _collect_field_values_for_alert(body.expression, parsed_fields_dict, field_defs_dict)

    return DryRunResult(
        sample_id=body.sample_id,
        template_id=template_id,
        template_version=version,
        triggered=bool(triggered),
        field_values=field_values,
        evaluations=evaluations,
    )
