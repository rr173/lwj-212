import sys
sys.path.insert(0, '/Users/chengjie/bytedance/newcj/lwj-212')

from app.models import FieldDef
from app.fuzz import _generate_message
from app.parser import parse_message

print("=" * 60)
print("TEST: 复杂模板 - 三种策略对比")
print("=" * 60)

fields_complex = [
    FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="uint16_be"),
    FieldDef(name="version", length_rule="fixed", length_value=1, data_type="uint8"),
    FieldDef(name="msg_type", length_rule="fixed", length_value=1, data_type="uint8"),
    FieldDef(name="payload_len", length_rule="fixed", length_value=2, data_type="uint16_be"),
    FieldDef(name="payload", length_rule="ref", length_ref_field="payload_len", data_type="bytes"),
    FieldDef(name="crc16", length_rule="fixed", length_value=2, data_type="uint16_be"),
]

for strategy in ["normal", "boundary", "malformed"]:
    print(f"\n--- {strategy.upper()} ---")
    errors = 0
    coverages = []
    for i in range(20):
        msg_bytes, notes = _generate_message(fields_complex, strategy)
        result = parse_message(msg_bytes, fields_complex, 1, i, 1)
        has_error = any(f.status == "parse_error" for f in result.fields)
        cov = result.coverage_percent
        coverages.append(cov)
        if has_error or cov < 100:
            err_str = "ERROR" if has_error else "OK"
            note_str = str(notes) if notes else ""
            print(f"  #{i+1:2d}: {err_str:5s} len={len(msg_bytes):4d}B  cov={cov:.1f}%  {note_str}")
            if has_error:
                for f in result.fields:
                    if f.status == "parse_error":
                        print(f"        - {f.name}: {f.error}")
        if has_error:
            errors += 1

    print(f"  Summary: {errors}/20 errors ({errors/20*100:.0f}%), "
          f"cov min={min(coverages):.1f}% max={max(coverages):.1f}% avg={sum(coverages)/20:.1f}%")

print()
print("=" * 60)
print("TEST: 条件字段模板 - 正常策略覆盖率")
print("=" * 60)

fields_conditional = [
    FieldDef(name="header", length_rule="fixed", length_value=2, data_type="uint16_be"),
    FieldDef(name="type", length_rule="fixed", length_value=1, data_type="uint8"),
    FieldDef(name="length", length_rule="fixed", length_value=1, data_type="uint8"),
    FieldDef(name="data", length_rule="ref", length_ref_field="length", data_type="bytes",
             condition_field="type", condition_value="1"),
    FieldDef(name="crc", length_rule="fixed", length_value=2, data_type="uint16_be"),
]

errors = 0
low_cov = 0
coverages = []
for i in range(30):
    msg_bytes, notes = _generate_message(fields_conditional, "normal")
    result = parse_message(msg_bytes, fields_conditional, 1, i, 1)
    has_error = any(f.status == "parse_error" for f in result.fields)
    cov = result.coverage_percent
    coverages.append(cov)
    if has_error:
        errors += 1
    if cov < 100:
        low_cov += 1
    if has_error or cov < 100:
        err_str = "ERROR" if has_error else "LOW_COV"
        print(f"  #{i+1:2d}: {err_str:8s} len={len(msg_bytes):3d}B  cov={cov:.1f}%  notes={notes}")
        if has_error:
            for f in result.fields:
                if f.status == "parse_error":
                    print(f"        - {f.name}: {f.error}")

print(f"\n  Summary: {errors} errors, {low_cov} low coverage ({low_cov/30*100:.0f}%)")
print(f"  Coverage: min={min(coverages):.1f}% max={max(coverages):.1f}% avg={sum(coverages)/30:.1f}%")
