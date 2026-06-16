import json
import asyncio
from collections import Counter, defaultdict
from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from typing import Optional
from app.models import (
    SessionCreate,
    SessionOut,
    FrameCreate,
    FrameOut,
    SessionPair,
    SessionPairView,
    SessionStats,
    FieldValueDistribution,
    ParseResult,
    FieldDef,
)
from app.database import get_db
from app.utils import validate_hex, hex_to_bytes, shannon_entropy
from app.parser import parse_message

router = APIRouter(prefix="/api/sessions", tags=["sessions"])

MAX_FRAMES_PER_SESSION = 1000
MAX_HEX_LENGTH = 64 * 1024 * 2


async def _get_template_fields(template_id: int, version: Optional[int] = None):
    db = await get_db()
    try:
        if version is not None:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
                (template_id, version),
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail="template version not found")
            actual_version = version
        else:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM templates WHERE id = ?", (template_id,)
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail="template not found")
            v_rows = await db.execute_fetchall(
                "SELECT MAX(version) as max_version FROM template_versions WHERE template_id = ?",
                (template_id,),
            )
            actual_version = v_rows[0]["max_version"] or 1
            t_rows = await db.execute_fetchall(
                "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
                (template_id, actual_version),
            )
    finally:
        await db.close()

    fields = [FieldDef(**f) for f in json.loads(t_rows[0]["fields_json"])]
    return fields, actual_version


def _row_to_frame_out(row, parse_result: Optional[ParseResult] = None) -> FrameOut:
    return FrameOut(
        id=row["id"],
        session_id=row["session_id"],
        seq=row["seq"],
        hex_data=row["hex_data"],
        byte_length=row["byte_length"],
        direction=row["direction"],
        relative_timestamp_ms=row["relative_timestamp_ms"],
        parse_result=parse_result,
    )


def _parse_result_from_json(json_str: Optional[str]) -> Optional[ParseResult]:
    if not json_str:
        return None
    try:
        data = json.loads(json_str)
        return ParseResult(**data)
    except Exception:
        return None


async def _get_session_or_404(session_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        )
    finally:
        await db.close()
    if not rows:
        raise HTTPException(status_code=404, detail="session not found")
    return rows[0]


@router.post("", response_model=SessionOut, status_code=201)
async def create_session(body: SessionCreate):
    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT * FROM templates WHERE id = ?", (body.template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        v_rows = await db.execute_fetchall(
            "SELECT MAX(version) as max_version FROM template_versions WHERE template_id = ?",
            (body.template_id,),
        )
        latest_version = v_rows[0]["max_version"] or 1

        cursor = await db.execute(
            "INSERT INTO sessions (name, template_id, template_version, note) VALUES (?, ?, ?, ?)",
            (body.name, body.template_id, latest_version, body.note),
        )
        session_id = cursor.lastrowid
        await db.commit()

        s_rows = await db.execute_fetchall(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        )
        s_row = s_rows[0]

        f_count = await db.execute_fetchall(
            "SELECT COUNT(*) as cnt FROM session_frames WHERE session_id = ?",
            (session_id,),
        )
        frame_count = f_count[0]["cnt"]
    finally:
        await db.close()

    return SessionOut(
        id=s_row["id"],
        name=s_row["name"],
        template_id=s_row["template_id"],
        template_version=s_row["template_version"],
        note=s_row["note"] or "",
        frame_count=frame_count,
        created_at=s_row["created_at"] or "",
    )


@router.get("", response_model=list[SessionOut])
async def list_sessions(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM sessions ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        session_ids = [r["id"] for r in rows]
        frame_counts = {}
        if session_ids:
            placeholders = ",".join("?" * len(session_ids))
            count_rows = await db.execute_fetchall(
                f"SELECT session_id, COUNT(*) as cnt FROM session_frames WHERE session_id IN ({placeholders}) GROUP BY session_id",
                session_ids,
            )
            for cr in count_rows:
                frame_counts[cr["session_id"]] = cr["cnt"]
    finally:
        await db.close()

    return [
        SessionOut(
            id=r["id"],
            name=r["name"],
            template_id=r["template_id"],
            template_version=r["template_version"],
            note=r["note"] or "",
            frame_count=frame_counts.get(r["id"], 0),
            created_at=r["created_at"] or "",
        )
        for r in rows
    ]


@router.get("/{session_id}", response_model=SessionOut)
async def get_session(session_id: int):
    s_row = await _get_session_or_404(session_id)
    db = await get_db()
    try:
        f_count = await db.execute_fetchall(
            "SELECT COUNT(*) as cnt FROM session_frames WHERE session_id = ?",
            (session_id,),
        )
        frame_count = f_count[0]["cnt"]
    finally:
        await db.close()

    return SessionOut(
        id=s_row["id"],
        name=s_row["name"],
        template_id=s_row["template_id"],
        template_version=s_row["template_version"],
        note=s_row["note"] or "",
        frame_count=frame_count,
        created_at=s_row["created_at"] or "",
    )


@router.post("/{session_id}/frames", response_model=FrameOut, status_code=201)
async def append_frame(session_id: int, body: FrameCreate):
    s_row = await _get_session_or_404(session_id)

    try:
        cleaned = validate_hex(body.hex_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if len(cleaned) > MAX_HEX_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"hex data exceeds maximum size of 64KB ({len(cleaned) // 2} bytes)",
        )

    if body.relative_timestamp_ms < 0:
        raise HTTPException(status_code=400, detail="relative_timestamp_ms must be >= 0")

    data = hex_to_bytes(cleaned)
    byte_length = len(data)

    db = await get_db()
    try:
        count_rows = await db.execute_fetchall(
            "SELECT COUNT(*) as cnt FROM session_frames WHERE session_id = ?",
            (session_id,),
        )
        current_count = count_rows[0]["cnt"]
        if current_count >= MAX_FRAMES_PER_SESSION:
            raise HTTPException(
                status_code=400,
                detail=f"session exceeds maximum frame count of {MAX_FRAMES_PER_SESSION}",
            )

        if current_count > 0:
            last_rows = await db.execute_fetchall(
                "SELECT relative_timestamp_ms FROM session_frames WHERE session_id = ? ORDER BY seq DESC LIMIT 1",
                (session_id,),
            )
            last_ts = last_rows[0]["relative_timestamp_ms"]
            if body.relative_timestamp_ms <= last_ts:
                raise HTTPException(
                    status_code=400,
                    detail=f"relative_timestamp_ms must be strictly increasing (last was {last_ts})",
                )

        new_seq = current_count + 1

        fields, _ = await _get_template_fields(
            s_row["template_id"], s_row["template_version"]
        )
        parse_result = parse_message(
            data,
            fields,
            s_row["template_id"],
            0,
            s_row["template_version"],
        )
        parse_result.sample_id = 0
        parse_result_json = json.dumps(parse_result.model_dump())

        cursor = await db.execute(
            """
            INSERT INTO session_frames (session_id, seq, hex_data, byte_length, direction, relative_timestamp_ms, parse_result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                new_seq,
                cleaned,
                byte_length,
                body.direction,
                body.relative_timestamp_ms,
                parse_result_json,
            ),
        )
        frame_id = cursor.lastrowid
        await db.commit()

        rows = await db.execute_fetchall(
            "SELECT * FROM session_frames WHERE id = ?", (frame_id,)
        )
        row = rows[0]
    finally:
        await db.close()

    return _row_to_frame_out(row, parse_result)


@router.get("/{session_id}/frames", response_model=list[FrameOut])
async def list_frames(
    session_id: int,
    direction: Optional[str] = Query(default=None, description="Filter by direction: request or response"),
    from_ms: Optional[int] = Query(default=None, ge=0, description="Start of time range (inclusive)"),
    to_ms: Optional[int] = Query(default=None, ge=0, description="End of time range (inclusive)"),
    include_parse_result: bool = Query(default=True, description="Include parse result in response"),
):
    await _get_session_or_404(session_id)

    query = "SELECT * FROM session_frames WHERE session_id = ?"
    params = [session_id]

    if direction:
        if direction not in ("request", "response"):
            raise HTTPException(status_code=400, detail="direction must be 'request' or 'response'")
        query += " AND direction = ?"
        params.append(direction)

    if from_ms is not None:
        query += " AND relative_timestamp_ms >= ?"
        params.append(from_ms)

    if to_ms is not None:
        query += " AND relative_timestamp_ms <= ?"
        params.append(to_ms)

    query += " ORDER BY seq ASC"

    db = await get_db()
    try:
        rows = await db.execute_fetchall(query, params)
    finally:
        await db.close()

    return [
        _row_to_frame_out(
            r,
            _parse_result_from_json(r["parse_result_json"]) if include_parse_result else None,
        )
        for r in rows
    ]


@router.get("/{session_id}/frames/{frame_id}", response_model=FrameOut)
async def get_frame(session_id: int, frame_id: int):
    await _get_session_or_404(session_id)
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM session_frames WHERE id = ? AND session_id = ?",
            (frame_id, session_id),
        )
    finally:
        await db.close()

    if not rows:
        raise HTTPException(status_code=404, detail="frame not found")

    row = rows[0]
    return _row_to_frame_out(row, _parse_result_from_json(row["parse_result_json"]))


def _compute_pairs(frames: list[FrameOut]) -> tuple[list[SessionPair], list[FrameOut]]:
    pairs: list[SessionPair] = []
    orphan_frames: list[FrameOut] = []
    pair_id_counter = 0

    pending_request: Optional[FrameOut] = None

    for frame in frames:
        if frame.direction == "request":
            if pending_request is not None:
                pair_id_counter += 1
                pairs.append(
                    SessionPair(
                        pair_id=pair_id_counter,
                        request_frame=pending_request,
                        response_frame=None,
                        status="unanswered",
                        response_delay_ms=None,
                    )
                )
            pending_request = frame
        else:
            if pending_request is not None:
                pair_id_counter += 1
                pairs.append(
                    SessionPair(
                        pair_id=pair_id_counter,
                        request_frame=pending_request,
                        response_frame=frame,
                        status="complete",
                        response_delay_ms=frame.relative_timestamp_ms - pending_request.relative_timestamp_ms,
                    )
                )
                pending_request = None
            else:
                pair_id_counter += 1
                pairs.append(
                    SessionPair(
                        pair_id=pair_id_counter,
                        request_frame=None,
                        response_frame=frame,
                        status="unsolicited",
                        response_delay_ms=None,
                    )
                )

    if pending_request is not None:
        pair_id_counter += 1
        pairs.append(
            SessionPair(
                pair_id=pair_id_counter,
                request_frame=pending_request,
                response_frame=None,
                status="unanswered",
                response_delay_ms=None,
            )
        )

    return pairs, orphan_frames


@router.get("/{session_id}/pairs", response_model=SessionPairView)
async def get_session_pairs(session_id: int):
    s_row = await _get_session_or_404(session_id)
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM session_frames WHERE session_id = ? ORDER BY seq ASC",
            (session_id,),
        )
    finally:
        await db.close()

    frames = [
        _row_to_frame_out(r, _parse_result_from_json(r["parse_result_json"]))
        for r in rows
    ]

    pairs, orphans = _compute_pairs(frames)

    return SessionPairView(
        session_id=session_id,
        pairs=pairs,
        orphan_frames=orphans,
    )


@router.get("/{session_id}/stats", response_model=SessionStats)
async def get_session_stats(session_id: int):
    s_row = await _get_session_or_404(session_id)
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM session_frames WHERE session_id = ? ORDER BY seq ASC",
            (session_id,),
        )
    finally:
        await db.close()

    frames = [
        _row_to_frame_out(r, _parse_result_from_json(r["parse_result_json"]))
        for r in rows
    ]

    total_frames = len(frames)
    request_count = sum(1 for f in frames if f.direction == "request")
    response_count = sum(1 for f in frames if f.direction == "response")

    pairs, _ = _compute_pairs(frames)
    complete_pairs = [p for p in pairs if p.status == "complete"]
    delays = []
    for p in complete_pairs:
        if p.response_delay_ms is not None:
            delays.append(p.response_delay_ms)

    avg_delay = None
    max_delay = None
    if len(delays) > 0:
        try:
            avg_delay = round(sum(delays) / len(delays), 2)
            max_delay = max(delays)
        except (ZeroDivisionError, ValueError):
            pass

    unanswered_count = sum(1 for p in pairs if p.status == "unanswered")
    unsolicited_count = sum(1 for p in pairs if p.status == "unsolicited")

    field_counters: dict[str, Counter] = defaultdict(Counter)

    for frame in frames:
        pr = frame.parse_result
        if pr is None:
            continue
        for field in pr.fields:
            if field.status == "ok" and field.value is not None:
                counter = field_counters[field.name]
                counter[str(field.value)] += 1

    field_distributions = [
        FieldValueDistribution(field_name=name, values=dict(counter))
        for name, counter in sorted(field_counters.items())
    ]

    return SessionStats(
        session_id=session_id,
        total_frames=total_frames,
        request_count=request_count,
        response_count=response_count,
        avg_response_delay_ms=avg_delay,
        max_response_delay_ms=max_delay,
        unanswered_count=unanswered_count,
        unsolicited_count=unsolicited_count,
        field_distributions=field_distributions,
    )


async def _fetch_frames_for_playback(session_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM session_frames WHERE session_id = ? ORDER BY seq ASC",
            (session_id,),
        )
    finally:
        await db.close()

    return [
        _row_to_frame_out(r, _parse_result_from_json(r["parse_result_json"]))
        for r in rows
    ]


@router.websocket("/{session_id}/playback")
async def session_playback(
    websocket: WebSocket,
    session_id: int,
    speed: float = Query(default=1.0, ge=0.25, le=10.0, description="Playback speed multiplier"),
):
    await websocket.accept()

    try:
        await _get_session_or_404(session_id)
    except HTTPException as e:
        await websocket.close(code=4004, reason=e.detail)
        return

    frames = await _fetch_frames_for_playback(session_id)

    await websocket.send_json({
        "type": "session_info",
        "session_id": session_id,
        "total_frames": len(frames),
        "total_duration_ms": frames[-1].relative_timestamp_ms if frames else 0,
    })

    started = False
    paused = False
    stopped = False
    current_idx = 0
    current_speed = speed
    pending_seek: Optional[int] = None
    pause_event = asyncio.Event()
    pause_event.set()

    playback_task: Optional[asyncio.Task] = None

    async def process_seek(target_ms: int):
        nonlocal current_idx, pending_seek
        pending_seek = None
        current_idx = 0
        for i, f in enumerate(frames):
            if f.relative_timestamp_ms >= target_ms:
                current_idx = i
                break
        await websocket.send_json({
            "type": "seek_complete",
            "target_ms": target_ms,
            "frame_index": current_idx,
        })

    async def run_playback():
        nonlocal current_idx, current_speed, pending_seek, stopped

        while not stopped:
            if not started:
                await asyncio.sleep(0.05)
                continue

            if pending_seek is not None:
                await process_seek(pending_seek)
                continue

            if paused:
                await pause_event.wait()
                continue

            if current_idx >= len(frames):
                await websocket.send_json({"type": "playback_complete"})
                break

            if pending_seek is not None:
                continue

            frame = frames[current_idx]
            next_frame = frames[current_idx + 1] if current_idx + 1 < len(frames) else None

            await websocket.send_json({
                "type": "frame",
                "frame_index": current_idx,
                "data": FrameOut.model_validate(frame).model_dump(mode="json"),
            })

            if pending_seek is not None:
                current_idx += 1
                continue

            if next_frame is not None:
                interval_ms = next_frame.relative_timestamp_ms - frame.relative_timestamp_ms
                sleep_s = (interval_ms / 1000.0) / current_speed

                sleep_remaining = sleep_s
                while sleep_remaining > 0 and not stopped and pending_seek is None:
                    chunk = min(sleep_remaining, 0.02)
                    try:
                        await asyncio.wait_for(pause_event.wait(), timeout=chunk)
                    except asyncio.TimeoutError:
                        pass
                    sleep_remaining -= chunk

                if pending_seek is not None:
                    current_idx += 1
                    continue
                if stopped:
                    break

                current_idx += 1
            else:
                current_idx += 1

    playback_task = asyncio.create_task(run_playback())

    try:
        while not stopped:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=1.0)
                action = data.get("action")

                if action == "start":
                    if not started:
                        started = True
                        await websocket.send_json({
                            "type": "started",
                            "frame_index": current_idx,
                            "speed": current_speed,
                        })
                    else:
                        await websocket.send_json({
                            "type": "error",
                            "message": "playback already started",
                        })

                elif action == "pause":
                    if not started:
                        await websocket.send_json({
                            "type": "error",
                            "message": "playback not started, send 'start' first",
                        })
                    elif not paused:
                        paused = True
                        pause_event.clear()
                        await websocket.send_json({"type": "paused", "frame_index": current_idx})

                elif action == "resume":
                    if not started:
                        await websocket.send_json({
                            "type": "error",
                            "message": "playback not started, send 'start' first",
                        })
                    elif paused:
                        paused = False
                        pause_event.set()
                        await websocket.send_json({"type": "resumed", "frame_index": current_idx})

                elif action == "seek":
                    seek_ms = data.get("seek_to_ms", 0)
                    if isinstance(seek_ms, int) and seek_ms >= 0:
                        if started and not paused:
                            pending_seek = seek_ms
                            pause_event.set()
                        else:
                            await process_seek(seek_ms)

                elif action == "set_speed":
                    new_speed = data.get("speed", 1.0)
                    if isinstance(new_speed, (int, float)) and 0.25 <= new_speed <= 10.0:
                        current_speed = float(new_speed)
                        pause_event.set()
                        await websocket.send_json({
                            "type": "speed_changed",
                            "speed": current_speed,
                        })

                elif action == "stop":
                    stopped = True
                    pause_event.set()
                    if playback_task and not playback_task.done():
                        try:
                            await asyncio.wait_for(playback_task, timeout=1.0)
                        except Exception:
                            playback_task.cancel()
                    await websocket.send_json({"type": "stopped"})
                    break

                else:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"unknown action: {action}",
                    })

            except asyncio.TimeoutError:
                if playback_task and playback_task.done():
                    break
                continue

    except WebSocketDisconnect:
        stopped = True
        pause_event.set()
        if playback_task and not playback_task.done():
            playback_task.cancel()
    except Exception as e:
        stopped = True
        pause_event.set()
        if playback_task and not playback_task.done():
            playback_task.cancel()
        try:
            await websocket.close(code=4000, reason=str(e))
        except Exception:
            pass
