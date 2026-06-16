import sys
import os
sys.path.insert(0, '/Users/chengjie/bytedance/newcj/lwj-212')

from app.models import FieldDef
from app.fuzz import _generate_message
from app.parser import parse_message

# 测试1: 单字段模板的畸形报文测试
print("=" * 60)
print("TEST 1: 单uint8字段 - 畸形策略")
print("=" * 60)

fields_single = [
    FieldDef(name="value", length_rule="fixed", length_value=1, data_type="uint8"),
]

malformed_count = 0
ok_count = 0
for i in range(20):
    msg_bytes, notes = _generate_message(fields_single, "malformed")
    result = parse_message(msg_bytes, fields_single, 1, i, 1)
    has_error = any(f.status == "parse_error" for f in result.fields)
    has_error_str = "ERROR" if has_error else "OK"
    coverage = result.coverage_percent
    print(f"  #{i+1:2d}: {has_error_str:5s}  len={len(msg_bytes):3d}B  coverage={coverage:.1f}%  notes={notes}")
    if has_error:
        malformed_count += 1
    else:
        ok_count += 1

print(f"\n  Result: {malformed_count} errors, {ok_count} success")
print(f"  Error rate: {malformed_count/20*100:.1f}%")

print()
print("=" * 60)
print("TEST 2: 复杂模板 - 正常策略的覆盖率")
print("=" * 60)

fields_complex = [
    FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="uint16_be"),
    FieldDef(name="version", length_rule="fixed", length_value=1, data_type="uint8"),
    FieldDef(name="msg_type", length_rule="fixed", length_value=1, data_type="uint8"),
    FieldDef(name="payload_len", length_rule="fixed", length_value=2, data_type="uint16_be"),
    FieldDef(name="payload", length_rule="ref", length_ref_field="payload_len", data_type="bytes"),
    FieldDef(name="crc16", length_rule="fixed", length_value=2, data_type="uint16_be"),
]

coverages = []
error_count = 0
for i in range(20):
    msg_bytes, notes = _generate_message(fields_complex, "normal")
    result = parse_message(msg_bytes, fields_complex, 1, i, 1)
    has_error = any(f.status == "parse_error" for f in result.fields)
    cov = result.coverage_percent
    coverages.append(cov)
    has_error_str = "ERROR" if has_error else "OK"
    if cov < 100 or has_error:
        print(f"  #{i+1:2d}: {has_error_str:5s}  len={len(msg_bytes):4d}B  coverage={cov:.1f}%  notes={notes}")
        # 打印详细的字段解析结果
        for f in result.fields:
            print(f"      - {f.name}: {f.status}, len={f.length}, offset={f.offset}")
    if has_error:
        error_count += 1

print(f"\n  Min coverage: {min(coverages):.1f}%")
print(f"  Max coverage: {max(coverages):.1f}%")
print(f"  Avg coverage: {sum(coverages)/len(coverages):.1f}%")
print(f"  Errors: {error_count}/{len(coverages)}")

low_cov = [c for c in coverages if c < 100]
print(f"  Below 100% coverage count: {len(low_cov)}")
