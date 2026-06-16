import sys
import asyncio
sys.path.insert(0, '/Users/chengjie/bytedance/newcj/lwj-212')

from app.models import FieldDef, FuzzStrategyDistribution
from app.fuzz import generate_and_validate

print("=" * 60)
print("INTEGRATION TEST: generate_and_validate")
print("=" * 60)

fields_complex = [
    FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="uint16_be"),
    FieldDef(name="version", length_rule="fixed", length_value=1, data_type="uint8"),
    FieldDef(name="msg_type", length_rule="fixed", length_value=1, data_type="uint8"),
    FieldDef(name="payload_len", length_rule="fixed", length_value=2, data_type="uint16_be"),
    FieldDef(name="payload", length_rule="ref", length_ref_field="payload_len", data_type="bytes"),
    FieldDef(name="crc16", length_rule="fixed", length_value=2, data_type="uint16_be"),
]

async def test_with_template_fields(template_id, fields, name):
    print(f"\n>>> Testing: {name}")
    print(f"    Template ID: {template_id}, Fields: {[f.name for f in fields]}")
    
    try:
        report = await generate_and_validate(
            template_id=template_id,
            count=20,
            strategy_distribution=FuzzStrategyDistribution(
                normal=0.3, boundary=0.3, malformed=0.4
            ),
            template_version=1,
            _override_fields=fields,
        )
        
        print(f"\n    Total generated: {report.total_generated}")
        print(f"    Template: {report.template_name} v{report.template_version}")
        
        for s in report.strategy_stats:
            strat = s.strategy.upper()
            print(f"\n    [{strat}]")
            print(f"      Total:   {s.total}")
            print(f"      Success: {s.success_count} ({s.success_rate:.1f}%)")
            print(f"      Failed:  {s.total - s.success_count} ({100 - s.success_rate:.1f}%)")
            print(f"      Coverage: avg={s.avg_coverage:.1f}% min={s.min_coverage:.1f}% max={s.max_coverage:.1f}%")
        
        if report.template_defects:
            print(f"\n    ⚠️  Template Defects: {len(report.template_defects)}")
            for d in report.template_defects[:5]:
                print(f"      - {d.field_name}: {d.error}")
        else:
            print(f"\n    ✓ No template defects")
        
        if report.field_error_ranking:
            print(f"\n    Top error fields:")
            for i, e in enumerate(report.field_error_ranking[:5], 1):
                print(f"      {i}. {e.field_name}: {e.error_count} errors")
        
        print(f"\n    ✓ Test passed")
        return True
        
    except Exception as e:
        print(f"\n    ✗ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    all_passed = True
    
    # Test 1: Single uint8 (simple template)
    fields_single = [
        FieldDef(name="value", length_rule="fixed", length_value=1, data_type="uint8", order=1),
    ]
    passed = await test_with_template_fields(1, fields_single, "Single uint8 field")
    if not passed:
        all_passed = False
    
    print()
    print("-" * 60)
    
    # Test 2: Complex template with ref field
    passed = await test_with_template_fields(2, fields_complex, "Complex template with ref")
    if not passed:
        all_passed = False
    
    print()
    print("=" * 60)
    if all_passed:
        print("ALL TESTS PASSED ✓")
    else:
        print("SOME TESTS FAILED ✗")
    print("=" * 60)
    
    return all_passed

if __name__ == "__main__":
    result = asyncio.run(main())
    sys.exit(0 if result else 1)
