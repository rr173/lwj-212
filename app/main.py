from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.database import init_db
from app.seed import seed_if_empty
from app.routers import samples, templates, parse, sessions, fuzz, fingerprints, analysis, state_machines, fragments, alerts, firmware, segment_clustering, ota, device_alerts, config_templates, device_config, batch_push, config_compare, baselines, editor, sequence_patterns


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await seed_if_empty()
    yield


app = FastAPI(
    title="Binary Protocol Parsing Workbench",
    description="Define protocol templates and parse binary message samples into structured fields. Includes session recording, playback, request-response pairing, protocol fuzz testing, fragment reassembly, alert rule engine, firmware signature integrity verification chain, IoT device alert aggregation & upgrade decision engine, and device configuration template & batch deployment service.",
    version="1.11.0",
    lifespan=lifespan,
)

app.include_router(samples.router)
app.include_router(templates.router)
app.include_router(parse.router)
app.include_router(sessions.router)
app.include_router(fuzz.router)
app.include_router(fingerprints.router)
app.include_router(analysis.router)
app.include_router(state_machines.router)
app.include_router(fragments.router)
app.include_router(alerts.router)
app.include_router(firmware.router)
app.include_router(segment_clustering.router)
app.include_router(ota.router)
app.include_router(device_alerts.router)
app.include_router(config_templates.router)
app.include_router(device_config.router)
app.include_router(batch_push.router)
app.include_router(config_compare.router)
app.include_router(baselines.router)
app.include_router(editor.router)
app.include_router(sequence_patterns.router)


@app.get("/")
async def root():
    return {
        "service": "Binary Protocol Parsing Workbench",
        "version": "1.12.0",
        "docs": "/docs",
        "features": [
            "Protocol template management with versioning",
            "Single message parsing & batch validation",
            "Session recording (multi-frame conversations)",
            "Request-response pairing",
            "Session statistics",
            "WebSocket session playback (with speed control & seek)",
            "Protocol fuzz testing (auto-generate normal/boundary/malformed messages)",
            "Protocol fingerprint library & automatic identification",
            "Smart parsing (auto-recognize protocol and parse)",
            "Byte heatmap & field mutation analysis for batch samples",
            "Protocol state machine definition & management",
            "Session compliance validation against state machines",
            "Automatic state machine inference from sessions",
            "Fragment reassembly & packet defragmentation",
            "Auto-detection of optimal fragment order",
            "Alert rule engine — define field-based anomaly detection rules",
            "Cross-field & logical rule conditions (AND/OR/NOT)",
            "Single-sample alert detection & batch scan with severity ranking",
            "Rule dry-run test with per-condition evaluation trace",
            "IoT Firmware diff analysis — upload firmware with hex string",
            "Firmware metadata: auto-calc byte length, SHA256, Shannon entropy",
            "Firmware segment annotation (bootloader/kernel/filesystem/config/padding)",
            "Auto-detection of padding segments (64+ consecutive same bytes)",
            "Byte-level firmware diff analysis with change intervals",
            "Structured change summary with segment-level aggregation",
            "Bootloader change detection with high-risk marking",
            "Batch version evolution analysis across all firmware versions",
            "Preloaded demo: ESP32-DevKit with 3 versions (v1.0/v1.1/v2.0)",
            "Firmware signature management: bind signature records (hmac-sha256/ed25519) to firmware",
            "Firmware integrity verification interface with detailed failure info",
            "Diff analysis with pre-verification integrity check chain",
            "Signature chain audit per device model with anomaly detection",
            "Preloaded ESP32 demo: v1.0/v1.1 signed with hmac-sha256, v2.0 unsigned",
            "Entropy-based firmware segmentation: sliding window Shannon entropy with inflection point detection",
            "Byte frequency fingerprint matching: ARM/x86 code, UTF-8 text, zero-fill, random data pattern recognition",
            "Cross-firmware segment mapping: compare segment fingerprints across firmware versions, detect homologous segments",
            "IoT OTA Upgrade Plan Management: device registration, upgrade plan creation, batch execution, failure threshold monitoring, rollback strategy",
            "IoT Device Alert Aggregation & Upgrade Decision Engine: batch alert submission with per-second dedup",
            "Alert list query with device/type/severity/time filters, 30-day retention",
            "Window-based alert aggregation grouped by type with count/devices/severity/time metrics",
            "Pattern detection: spike (5x avg), spread (30% device model), correlation (2+ types in 10min)",
            "Upgrade recommendation: emergency firmware upgrade, post-investigation upgrade, monitor only",
            "Preloaded 20 IoT devices (10x ESP32 v1.0 + 10x v2.0) and 50 demo alerts with pre-built patterns",
            "Device Configuration Template Management: create templates bound to device models with typed config items and constraints",
            "Config item validation: int/float/string/bool types with range/length constraints, default value validation on creation",
            "Device config instances: auto-initialized from template defaults, per-item modification with validation",
            "Config change history: full audit trail (who/when/what from/to) with per-device query",
            "Batch deployment: push config changes to all devices using a template, pre-check all-or-nothing",
            "Config comparison: device-vs-device diff and device-vs-template deviation analysis",
            "Preloaded ESP32-DevKit config template with 5 items and 5 bound devices (2 with modified sample_rate)",
            "Traffic baseline learning & anomaly detection — auto-learn normal patterns from historical samples",
            "Per-field statistical baseline: numeric fields (mean/std), bytes/ascii fields (length mean/std + top-20 frequent values)",
            "Z-score based anomaly scoring with weighted average (numeric weight 1.0, length weight 0.5, rare value +2.0 penalty)",
            "Three-level classification: normal (<1.5), suspicious (1.5-3.0), anomaly (>=3.0)",
            "Batch detection with results sorted by anomaly score and statistical summary",
            "Baseline comparison — drift detection across two snapshots (mean shift >2 std = significant drift)",
            "Pre-trained demo baseline on FEED protocol samples (excluding truncated one)",
            "Protocol message editor & reassembler — field value editing with type validation",
            "Message assembly: encode all fields into binary message per template definition",
            "Ref length fields auto-overwritten with actual referenced field byte length",
            "Until-type fields auto-append terminator byte on assembly",
            "Conditional fields skipped when condition not met during assembly",
            "Sample-based editing: parse sample, modify fields, reassemble with field-level diff",
            "Batch mutation: increment/random/enumerate field value variations, auto-save as samples",
        ],
    }
