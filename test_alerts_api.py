import sys
import os
import json
import urllib.request
import urllib.error

BASE = "http://localhost:8000"


def req(method, path, data=None):
    url = BASE + path
    body = None
    headers = {}
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r) as resp:
            raw = resp.read()
            if not raw:
                return resp.status, None
            return resp.status, json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read()
        if not raw:
            return e.code, None
        return e.code, json.loads(raw.decode("utf-8"))


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")


passed = 0
failed = 0

print("=== Test 1: Root endpoint shows version 1.6.0 ===")
status, data = req("GET", "/")
check("status 200", status == 200)
check("version is 1.6.0", data.get("version") == "1.6.0")
check("alert features listed", any("Alert rule engine" in f for f in data.get("features", [])))

print("\n=== Test 2: List templates (seed should have FEED template) ===")
status, templates = req("GET", "/api/templates")
check("status 200", status == 200)
check("at least 1 template", len(templates) >= 1)
template_id = templates[0]["id"]
check(f"using template_id={template_id}", True)

print("\n=== Test 3: List samples (seed should have samples) ===")
status, samples = req("GET", "/api/samples")
check("status 200", status == 200)
check("at least 5 samples", len(samples) >= 5)
sample_ids = [s["id"] for s in samples]
print(f"  sample_ids: {sample_ids}")

print("\n=== Test 4: Create alert rule - 'version=1 AND payload_len>256' critical ===")
rule_body = {
    "template_id": template_id,
    "name": "Version 1 oversized payload",
    "severity": "critical",
    "expression": {
        "type": "and",
        "conditions": [
            {"type": "compare", "field": "version", "op": "==", "value": 1},
            {"type": "compare", "field": "payload_len", "op": ">", "value": 256},
        ],
    },
}
status, data = req("POST", "/api/alerts/rules", rule_body)
print(f"  response: status={status}, data={data}")
check("status 201", status == 201)
check("rule name matches", data.get("name") == "Version 1 oversized payload")
check("severity critical", data.get("severity") == "critical")
rule_id = data.get("id")
check(f"rule_id={rule_id}", rule_id is not None)

print("\n=== Test 5: Create alert rule - invalid field rejected ===")
bad_rule = {
    "template_id": template_id,
    "name": "Bad rule",
    "severity": "warning",
    "expression": {"type": "compare", "field": "nonexistent", "op": "==", "value": 1},
}
status, data = req("POST", "/api/alerts/rules", bad_rule)
check("status 400", status == 400)

print("\n=== Test 6: Create alert rule - bytes type with > rejected ===")
bad_rule2 = {
    "template_id": template_id,
    "name": "Bad rule bytes",
    "severity": "info",
    "expression": {"type": "compare", "field": "payload", "op": ">", "value": "00"},
}
status, data = req("POST", "/api/alerts/rules", bad_rule2)
check("status 400", status == 400)

print("\n=== Test 7: Create alert rule - cross-field compare ===")
rule_body2 = {
    "template_id": template_id,
    "name": "msg_type exceeds version",
    "severity": "warning",
    "expression": {
        "type": "compare",
        "field": "msg_type",
        "op": ">",
        "field_ref": "version",
    },
}
status, data = req("POST", "/api/alerts/rules", rule_body2)
check("status 201", status == 201)

print("\n=== Test 8: List rules ===")
status, rules = req("GET", f"/api/alerts/rules/template/{template_id}")
check("status 200", status == 200)
check("2 rules exist", len(rules) == 2)

print("\n=== Test 9: Detect alerts for sensor short sample (should NOT trigger any rule) ===")
short_sample_id = sample_ids[3]
status, data = req("POST", "/api/alerts/detect", {"sample_id": short_sample_id, "template_id": template_id})
check("status 200", status == 200)
check("0 alerts triggered", len(data.get("triggered_alerts", [])) == 0)

print("\n=== Test 10: Dry-run first rule against sample with large payload (8 bytes payload) ===")
large_sample_id = sample_ids[1]
dry_run_body = {
    "sample_id": large_sample_id,
    "template_id": template_id,
    "expression": {
        "type": "and",
        "conditions": [
            {"type": "compare", "field": "version", "op": "==", "value": 1},
            {"type": "compare", "field": "payload_len", "op": ">", "value": 4},
        ],
    },
}
status, data = req("POST", "/api/alerts/dry-run", dry_run_body)
check("status 200", status == 200)
check("triggered is True", data.get("triggered") is True)
check("evaluations present", len(data.get("evaluations", [])) >= 3)
for ev in data.get("evaluations", []):
    print(f"    {ev['description']}: {ev['result']}")

print("\n=== Test 11: Detect alerts for sensor temp sample - rule 'payload_len>256' should NOT trigger (4 < 256) ===")
sensor_sample_id = sample_ids[5]
status, data = req("POST", "/api/alerts/detect", {"sample_id": sensor_sample_id, "template_id": template_id})
check("status 200", status == 200)
triggered_names = [a["rule_name"] for a in data.get("triggered_alerts", [])]
check("0 critical alerts (payload 4 < 256)", "Version 1 oversized payload" not in triggered_names)

print("\n=== Test 12: Create a more sensitive rule (payload_len > 4) and detect ===")
sensitive_rule = {
    "template_id": template_id,
    "name": "Sensitive payload check",
    "severity": "info",
    "expression": {"type": "compare", "field": "payload_len", "op": ">", "value": 4},
}
status, data = req("POST", "/api/alerts/rules", sensitive_rule)
check("status 201", status == 201)

status, data = req("POST", "/api/alerts/detect", {"sample_id": large_sample_id, "template_id": template_id})
check("status 200", status == 200)
triggered = data.get("triggered_alerts", [])
print(f"  triggered_alerts: {[(a['rule_name'], a['severity']) for a in triggered]}")
check("at least 1 alert triggered", len(triggered) >= 1)
check("field_values present in alert", "field_values" in triggered[0])

print("\n=== Test 13: Batch scan multiple samples ===")
scan_body = {
    "sample_ids": sample_ids,
    "template_id": template_id,
}
status, data = req("POST", "/api/alerts/scan", scan_body)
check("status 200", status == 200)
check("total_samples correct", data.get("total_samples") == len(sample_ids))
check("samples_with_alerts > 0", data.get("samples_with_alerts", 0) > 0)
check("rule_trigger_ranking present", len(data.get("rule_trigger_ranking", [])) > 0)
check("severity_stats has all 3 keys", all(k in data.get("severity_stats", {}) for k in ["info", "warning", "critical"]))

print("\n=== Test 14: Delete a rule ===")
status, _ = req("DELETE", f"/api/alerts/rules/{rule_id}")
check("status 204", status == 204)
status, rules = req("GET", f"/api/alerts/rules/template/{template_id}")
check("now 2 rules remain", len(rules) == 2)

print("\n=== Test 15: Duplicate rule name rejected ===")
dup_rule = {
    "template_id": template_id,
    "name": "Sensitive payload check",
    "severity": "info",
    "expression": {"type": "compare", "field": "version", "op": "==", "value": 1},
}
status, data = req("POST", "/api/alerts/rules", dup_rule)
check("status 400 for duplicate", status == 400)

print(f"\n=== INTEGRATION RESULTS: {passed} passed, {failed} failed ===")
sys.exit(0 if failed == 0 else 1)
