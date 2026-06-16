import json
import urllib.request

req = urllib.request.Request(
    "http://localhost:8000/api/fuzz/generate",
    data=json.dumps({
        "template_id": 1,
        "count": 20,
        "strategy_distribution": {
            "normal": 0.3,
            "boundary": 0.3,
            "malformed": 0.4
        }
    }).encode(),
    headers={"Content-Type": "application/json"}
)

with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read())

print("=" * 60)
print("FUZZ TEST REPORT (After Fix)")
print("=" * 60)
print(f"\nTemplate: {data['template_name']} (ID: {data['template_id']}, v{data['template_version']})")
print(f"Total samples: {data['total_generated']}")

print("\n" + "-" * 60)
print("STRATEGY STATISTICS")
print("-" * 60)
for s in data["strategy_stats"]:
    strategy = s["strategy"].upper()
    print(f"\n  ▸ {strategy}:")
    print(f"    Total:      {s['total']}")
    print(f"    Success:    {s['success_count']} ({s['success_rate']:.1f}%)")
    print(f"    Failed:     {s['total'] - s['success_count']} ({100 - s['success_rate']:.1f}%)")
    print(f"    Coverage:   avg={s['avg_coverage']:.1f}%, min={s['min_coverage']:.1f}%, max={s['max_coverage']:.1f}%")

print("\n" + "-" * 60)
print("COVERAGE OVERVIEW")
print("-" * 60)
c = data["coverage_overview"]
print(f"  Min:     {c['min']:.1f}%")
print(f"  Max:     {c['max']:.1f}%")
print(f"  Average: {c['avg']:.1f}%")

if data["field_error_ranking"]:
    print("\n" + "-" * 60)
    print("PARSE ERROR RANKING (Top fields)")
    print("-" * 60)
    for i, e in enumerate(data["field_error_ranking"][:10], 1):
        print(f"  {i:2d}. {e['field_name']}: {e['error_count']} errors")

print("\n" + "-" * 60)
print("TEMPLATE DEFECTS")
print("-" * 60)
if data["template_defects"]:
    print(f"\n  ⚠️  {len(data['template_defects'])} DEFECTS DETECTED!")
    seen_fields = set()
    for d in data["template_defects"]:
        if d["field_name"] not in seen_fields:
            seen_fields.add(d["field_name"])
            print(f"\n  - Field: {d['field_name']}")
            print(f"    Error: {d['error']}")
            count = sum(1 for x in data["template_defects"] if x["field_name"] == d["field_name"])
            print(f"    Affected samples: {count}")
else:
    print("\n  ✓ No template defects found")
    print("    (All normal samples parsed successfully with 100% coverage)")

print("\n" + "=" * 60)
