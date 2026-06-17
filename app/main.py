from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.database import init_db
from app.seed import seed_if_empty
from app.routers import samples, templates, parse, sessions, fuzz, fingerprints, analysis, state_machines, fragments, alerts, firmware, segment_clustering, ota


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await seed_if_empty()
    yield


app = FastAPI(
    title="Binary Protocol Parsing Workbench",
    description="Define protocol templates and parse binary message samples into structured fields. Includes session recording, playback, request-response pairing, protocol fuzz testing, fragment reassembly, alert rule engine, and firmware signature integrity verification chain.",
    version="1.8.0",
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


@app.get("/")
async def root():
    return {
        "service": "Binary Protocol Parsing Workbench",
        "version": "1.8.0",
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
        ],
    }
