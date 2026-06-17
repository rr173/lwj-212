import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.models import (
    ConditionCompare,
    ConditionLogical,
    AlertRuleCreate,
    FieldDef,
)
from app.rule_engine import (
    validate_rule_expression,
    evaluate_expression,
    evaluate_with_trace,
    expression_to_dict,
    dict_to_expression,
    MAX_NESTING_DEPTH,
    MAX_RULES_PER_TEMPLATE,
)


def run_tests():
    demo_fields = [
        FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="uint16_be"),
        FieldDef(name="version", length_rule="fixed", length_value=1, data_type="uint8"),
        FieldDef(name="msg_type", length_rule="fixed", length_value=1, data_type="uint8"),
        FieldDef(name="payload_len", length_rule="fixed", length_value=2, data_type="uint16_be"),
        FieldDef(name="payload", length_rule="ref", length_ref_field="payload_len", data_type="bytes"),
        FieldDef(name="crc16", length_rule="fixed", length_value=2, data_type="uint16_be"),
    ]

    passed = 0
    failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS: {name}")
        else:
            failed += 1
            print(f"  FAIL: {name}")

    print("=== Test 1: Validate single field compare (numeric) ===")
    expr1 = ConditionCompare(field="version", op="==", value=1)
    errs = validate_rule_expression(expr1, demo_fields)
    check("valid numeric compare no errors", len(errs) == 0)

    print("=== Test 2: Validate field does not exist ===")
    expr2 = ConditionCompare(field="nonexistent", op="==", value=1)
    errs = validate_rule_expression(expr2, demo_fields)
    check("invalid field has error", len(errs) > 0)

    print("=== Test 3: bytes type only supports ==/!=")
    expr3 = ConditionCompare(field="payload", op=">", value="00")
    errs = validate_rule_expression(expr3, demo_fields)
    check("bytes with > is rejected", len(errs) > 0)
    expr3b = ConditionCompare(field="payload", op="==", value="aabb")
    errs = validate_rule_expression(expr3b, demo_fields)
    check("bytes with == is allowed", len(errs) == 0)

    print("=== Test 4: cross-field compatible types ===")
    expr4 = ConditionCompare(field="version", op=">", field_ref="msg_type")
    errs = validate_rule_expression(expr4, demo_fields)
    check("numeric-numeric cross-field allowed", len(errs) == 0)

    print("=== Test 5: cross-field incompatible types ===")
    expr5 = ConditionCompare(field="version", op="==", field_ref="payload")
    errs = validate_rule_expression(expr5, demo_fields)
    check("numeric-bytes cross-field rejected", len(errs) > 0)

    print("=== Test 6: AND with two conditions ===")
    expr6 = ConditionLogical(
        type="and",
        conditions=[
            ConditionCompare(field="version", op="==", value=1),
            ConditionCompare(field="payload_len", op=">", value=256),
        ],
    )
    errs = validate_rule_expression(expr6, demo_fields)
    check("AND expression valid", len(errs) == 0)

    print("=== Test 7: NOT requires exactly 1 sub ===")
    expr7 = ConditionLogical(
        type="not",
        conditions=[
            ConditionCompare(field="version", op="==", value=1),
            ConditionCompare(field="version", op="==", value=2),
        ],
    )
    errs = validate_rule_expression(expr7, demo_fields)
    check("NOT with 2 subs rejected", len(errs) > 0)

    print("=== Test 8: Exceeds max nesting depth ===")
    deep = ConditionCompare(field="version", op="==", value=1)
    for _ in range(MAX_NESTING_DEPTH + 2):
        deep = ConditionLogical(type="not", conditions=[deep])
    errs = validate_rule_expression(deep, demo_fields)
    check("exceeds depth rejected", len(errs) > 0)

    print("=== Test 9: Evaluate simple true ===")
    parsed = {
        "version": {"value": "1", "status": "ok"},
        "payload_len": {"value": "300", "status": "ok"},
    }
    field_defs = {f.name: f for f in demo_fields}
    expr9 = ConditionCompare(field="version", op="==", value=1)
    r = evaluate_expression(expr9, parsed, field_defs)
    check("version==1 is True", r is True)

    print("=== Test 10: Evaluate numeric comparison ===")
    expr10 = ConditionCompare(field="payload_len", op=">", value=256)
    r = evaluate_expression(expr10, parsed, field_defs)
    check("payload_len>256 with 300 is True", r is True)

    print("=== Test 11: Null field (parse_error) ===")
    parsed_null = {"version": {"value": None, "status": "parse_error"}}
    expr11 = ConditionCompare(field="version", op="==", value=1)
    r = evaluate_expression(expr11, parsed_null, field_defs)
    check("parse_error field evaluates to None (not triggered)", r is None)

    print("=== Test 12: AND with both true ===")
    expr12 = ConditionLogical(
        type="and",
        conditions=[
            ConditionCompare(field="version", op="==", value=1),
            ConditionCompare(field="payload_len", op=">", value=256),
        ],
    )
    r = evaluate_expression(expr12, parsed, field_defs)
    check("version==1 AND payload_len>256 with values 1,300 is True", r is True)

    print("=== Test 13: AND with one false ===")
    parsed2 = {
        "version": {"value": "1", "status": "ok"},
        "payload_len": {"value": "100", "status": "ok"},
    }
    r = evaluate_expression(expr12, parsed2, field_defs)
    check("AND with payload_len=100 is False", r is False)

    print("=== Test 14: OR with one true ===")
    expr14 = ConditionLogical(
        type="or",
        conditions=[
            ConditionCompare(field="version", op="==", value=2),
            ConditionCompare(field="payload_len", op=">", value=256),
        ],
    )
    r = evaluate_expression(expr14, parsed, field_defs)
    check("OR with one true is True", r is True)

    print("=== Test 15: NOT inversion ===")
    expr15 = ConditionLogical(
        type="not",
        conditions=[ConditionCompare(field="version", op="==", value=2)],
    )
    r = evaluate_expression(expr15, parsed, field_defs)
    check("NOT version==2 with version=1 is True", r is True)

    print("=== Test 16: Cross-field compare ===")
    parsed16 = {
        "version": {"value": "2", "status": "ok"},
        "msg_type": {"value": "1", "status": "ok"},
    }
    expr16 = ConditionCompare(field="version", op=">", field_ref="msg_type")
    r = evaluate_expression(expr16, parsed16, field_defs)
    check("version(2) > msg_type(1) cross-field is True", r is True)

    print("=== Test 17: expression_to_dict roundtrip ===")
    d = expression_to_dict(expr12)
    back = dict_to_expression(d)
    r = evaluate_expression(back, parsed, field_defs)
    check("roundtrip preserves logic", r is True)

    print("=== Test 18: evaluate_with_trace ===")
    r, trace = evaluate_with_trace(expr12, parsed, field_defs)
    check("trace result is True", r is True)
    check("trace has 3 entries (2 compares + AND)", len(trace) == 3)

    print(f"\n=== RESULTS: {passed} passed, {failed} failed ===")
    return failed == 0


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
