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

print("=== Setup: Get template and samples ===")
status, templates = req("GET", "/api/templates")
template_id = templates[0]["id"]
status, samples = req("GET", "/api/samples")
sample_ids = [s["id"] for s in samples]
print(f"  template_id={template_id}, sample_ids={sample_ids}")

print("\n=== Test 1: Batch scan with 2 non-existent sample IDs ===")
fake_ids = [9999, 8888]
scan_body = {
    "sample_ids": sample_ids[:3] + fake_ids,
    "template_id": template_id,
}
status, data = req("POST", "/api/alerts/scan", scan_body)
check("status 200", status == 200)
check(f"total_samples = {3 + 2}", data.get("total_samples") == 5)
check(f"processed_samples = 3", data.get("processed_samples") == 3)
check(f"skipped_sample_ids = {fake_ids}", sorted(data.get("skipped_sample_ids", [])) == sorted(fake_ids))
print(f"  total_samples={data.get('total_samples')}, processed_samples={data.get('processed_samples')}, skipped={data.get('skipped_sample_ids')}")

print("\n=== Test 2: Explicit template_id with parse_error sample (truncated) should work normally ===")
# 样本ID=6是"Truncated - Missing CRC"，有parse_error字段
truncated_sample_id = sample_ids[0]
status, data = req("POST", "/api/alerts/detect", {"sample_id": truncated_sample_id, "template_id": template_id})
check("status 200 with explicit template_id", status == 200)
check("parse_error fields treated as null (no false positives)", len(data.get("triggered_alerts", [])) == 0)

print("\n=== Test 3: Auto-recognize with parse_error sample should FAIL with 400 ===")
status, data = req("POST", "/api/alerts/detect", {"sample_id": truncated_sample_id})
check("status 400", status == 400)
check("error mentions template version mismatch", "template version mismatch" in data.get("detail", ""))
print(f"  error detail: {data.get('detail', '')}")

print("\n=== Test 4: Auto-recognize dry-run with parse_error sample should FAIL with 400 ===")
dry_run_body = {
    "sample_id": truncated_sample_id,
    "expression": {"type": "compare", "field": "version", "op": "==", "value": 1},
}
status, data = req("POST", "/api/alerts/dry-run", dry_run_body)
check("status 400 for dry-run auto-recognize parse_error", status == 400)
check("error mentions template version mismatch", "template version mismatch" in data.get("detail", ""))

print("\n=== Test 5: Auto-recognize with good sample should work ===")
good_sample_id = sample_ids[-1]
status, data = req("POST", "/api/alerts/detect", {"sample_id": good_sample_id})
check("status 200 for good sample auto-recognize", status == 200)
check("parse_result has no errors", all(f["status"] != "parse_error" for f in data.get("parse_result", {}).get("fields", [])))

print("\n=== Test 6: Explicit template_id + version with parse_error should work ===")
status, data = req("POST", "/api/alerts/detect", {"sample_id": truncated_sample_id, "template_id": template_id})
check("status 200 explicit template_id even with parse errors", status == 200)

print("\n=== Test 7: Dry-run with explicit template_id on parse_error sample works ===")
dry_run_body2 = {
    "sample_id": truncated_sample_id,
    "template_id": template_id,
    "expression": {"type": "compare", "field": "version", "op": "==", "value": 1},
}
status, data = req("POST", "/api/alerts/dry-run", dry_run_body2)
check("status 200 explicit template_id dry-run with parse_error", status == 200)

print(f"\n=== RESULTS: {passed} passed, {failed} failed ===")
sys.exit(0 if failed == 0 else 1)
