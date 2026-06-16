from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.database import init_db
from app.seed import seed_if_empty
from app.routers import samples, templates, parse, sessions, fuzz


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await seed_if_empty()
    yield


app = FastAPI(
    title="Binary Protocol Parsing Workbench",
    description="Define protocol templates and parse binary message samples into structured fields. Includes session recording, playback, request-response pairing, and protocol fuzz testing.",
    version="1.2.0",
    lifespan=lifespan,
)

app.include_router(samples.router)
app.include_router(templates.router)
app.include_router(parse.router)
app.include_router(sessions.router)
app.include_router(fuzz.router)


@app.get("/")
async def root():
    return {
        "service": "Binary Protocol Parsing Workbench",
        "version": "1.2.0",
        "docs": "/docs",
        "features": [
            "Protocol template management with versioning",
            "Single message parsing & batch validation",
            "Session recording (multi-frame conversations)",
            "Request-response pairing",
            "Session statistics",
            "WebSocket session playback (with speed control & seek)",
            "Protocol fuzz testing (auto-generate normal/boundary/malformed messages)",
        ],
    }
