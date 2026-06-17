import hashlib
from fastapi import APIRouter, HTTPException, Query
from typing import Literal
from app.models import (
    FirmwareCreate, FirmwareOut, FirmwareDetailOut,
    SegmentCreate, SegmentOut,
    DiffRequest, DiffReport, DiffInterval,
    ChangeSummary, SegmentChangeSummary,
    BatchCompareRequest, BatchCompareResult, VersionEvolutionEntry,
    AutoPaddingResult,
    MAX_FIRMWARE_SIZE, PADDING_THRESHOLD,
)
from app.database import get_db
from app.utils import validate_hex, hex_to_bytes, shannon_entropy, bytes_to_hex

router = APIRouter(prefix="/api/firmware", tags=["firmware"])


def _segments_overlap(s1_start: int, s1_end: int, s2_start: int, s2_end: int) -> bool:
    return not (s1_end <= s2_start or s2_end <= s1_start)


def _find_segment_for_offset(offset: int, segments: list) -> dict | None:
    for seg in segments:
        if seg["start_offset"] <= offset < seg["end_offset"]:
            return seg
    return None


def _sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_version(version_str: str) -> tuple:
    cleaned = version_str.strip().lstrip("vV")
    parts = []
    for part in cleaned.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(part)
    return tuple(parts)


def _compare_versions(v1: str, v2: str) -> int:
    p1 = _parse_version(v1)
    p2 = _parse_version(v2)
    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


@router.post("", response_model=FirmwareOut, status_code=201)
async def create_firmware(body: FirmwareCreate):
    try:
        cleaned = validate_hex(body.hex_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    data = hex_to_bytes(cleaned)
    byte_length = len(data)

    if byte_length > MAX_FIRMWARE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"firmware exceeds maximum size of {MAX_FIRMWARE_SIZE} bytes ({byte_length} bytes)",
        )

    sha256 = _sha256_hash(data)
    entropy = shannon_entropy(data)

    db = await get_db()
    try:
        existing = await db.execute_fetchall(
            "SELECT id FROM firmwares WHERE device_model = ? AND version = ?",
            (body.device_model, body.version),
        )
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"version {body.version} already exists for device model {body.device_model}",
            )

        cursor = await db.execute(
            """
            INSERT INTO firmwares (name, version, device_model, hex_data, byte_length, sha256_hash, entropy)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (body.name, body.version, body.device_model, cleaned, byte_length, sha256, entropy),
        )
        await db.commit()
        firmware_id = cursor.lastrowid

        row = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE id = ?", (firmware_id,)
        )
    finally:
        await db.close()

    r = row[0]
    return FirmwareOut(
        id=r["id"],
        name=r["name"],
        version=r["version"],
        device_model=r["device_model"],
        byte_length=r["byte_length"],
        sha256_hash=r["sha256_hash"],
        entropy=r["entropy"],
        created_at=r["created_at"] or "",
    )


@router.get("", response_model=list[FirmwareOut])
async def list_firmwares(
    device_model: str = Query(default=None, description="filter by device model"),
    name: str = Query(default=None, description="search by name (fuzzy)"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        query = "SELECT * FROM firmwares WHERE 1=1"
        params = []

        if device_model:
            query += " AND device_model = ?"
            params.append(device_model)
        if name:
            query += " AND name LIKE ?"
            params.append(f"%{name}%")

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = await db.execute_fetchall(query, params)
    finally:
        await db.close()

    return [
        FirmwareOut(
            id=r["id"],
            name=r["name"],
            version=r["version"],
            device_model=r["device_model"],
            byte_length=r["byte_length"],
            sha256_hash=r["sha256_hash"],
            entropy=r["entropy"],
            created_at=r["created_at"] or "",
        )
        for r in rows
    ]


@router.get("/{firmware_id}", response_model=FirmwareDetailOut)
async def get_firmware(firmware_id: int):
    db = await get_db()
    try:
        row = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE id = ?", (firmware_id,)
        )
        if not row:
            raise HTTPException(status_code=404, detail="firmware not found")

        seg_rows = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ? ORDER BY start_offset",
            (firmware_id,),
        )
    finally:
        await db.close()

    r = row[0]
    segments = [
        SegmentOut(
            id=s["id"],
            firmware_id=s["firmware_id"],
            name=s["name"],
            start_offset=s["start_offset"],
            end_offset=s["end_offset"],
            segment_type=s["segment_type"],
            length=s["end_offset"] - s["start_offset"],
            created_at=s["created_at"] or "",
        )
        for s in seg_rows
    ]

    return FirmwareDetailOut(
        id=r["id"],
        name=r["name"],
        version=r["version"],
        device_model=r["device_model"],
        byte_length=r["byte_length"],
        sha256_hash=r["sha256_hash"],
        entropy=r["entropy"],
        hex_data=r["hex_data"],
        segments=segments,
        created_at=r["created_at"] or "",
    )


@router.delete("/{firmware_id}", status_code=204)
async def delete_firmware(firmware_id: int):
    db = await get_db()
    try:
        row = await db.execute_fetchall(
            "SELECT id FROM firmwares WHERE id = ?", (firmware_id,)
        )
        if not row:
            raise HTTPException(status_code=404, detail="firmware not found")

        await db.execute("DELETE FROM firmwares WHERE id = ?", (firmware_id,))
        await db.commit()
    finally:
        await db.close()


@router.post("/{firmware_id}/segments", response_model=SegmentOut, status_code=201)
async def create_segment(firmware_id: int, body: SegmentCreate):
    db = await get_db()
    try:
        fw_row = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE id = ?", (firmware_id,)
        )
        if not fw_row:
            raise HTTPException(status_code=404, detail="firmware not found")

        fw = fw_row[0]
        fw_length = fw["byte_length"]

        if body.end_offset <= body.start_offset:
            raise HTTPException(
                status_code=400,
                detail="end_offset must be greater than start_offset",
            )

        if body.start_offset < 0 or body.end_offset > fw_length:
            raise HTTPException(
                status_code=400,
                detail=f"segment offsets out of range: firmware length is {fw_length} bytes",
            )

        existing_segs = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ?",
            (firmware_id,),
        )

        for seg in existing_segs:
            if _segments_overlap(
                body.start_offset, body.end_offset,
                seg["start_offset"], seg["end_offset"],
            ):
                raise HTTPException(
                    status_code=400,
                    detail=f"segment overlaps with existing segment '{seg['name']}' ({seg['start_offset']}-{seg['end_offset']})",
                )

        cursor = await db.execute(
            """
            INSERT INTO firmware_segments (firmware_id, name, start_offset, end_offset, segment_type)
            VALUES (?, ?, ?, ?, ?)
            """,
            (firmware_id, body.name, body.start_offset, body.end_offset, body.segment_type),
        )
        await db.commit()
        segment_id = cursor.lastrowid

        seg_row = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE id = ?", (segment_id,)
        )
    finally:
        await db.close()

    s = seg_row[0]
    return SegmentOut(
        id=s["id"],
        firmware_id=s["firmware_id"],
        name=s["name"],
        start_offset=s["start_offset"],
        end_offset=s["end_offset"],
        segment_type=s["segment_type"],
        length=s["end_offset"] - s["start_offset"],
        created_at=s["created_at"] or "",
    )


@router.get("/{firmware_id}/segments", response_model=list[SegmentOut])
async def list_segments(firmware_id: int):
    db = await get_db()
    try:
        fw_row = await db.execute_fetchall(
            "SELECT id FROM firmwares WHERE id = ?", (firmware_id,)
        )
        if not fw_row:
            raise HTTPException(status_code=404, detail="firmware not found")

        seg_rows = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ? ORDER BY start_offset",
            (firmware_id,),
        )
    finally:
        await db.close()

    return [
        SegmentOut(
            id=s["id"],
            firmware_id=s["firmware_id"],
            name=s["name"],
            start_offset=s["start_offset"],
            end_offset=s["end_offset"],
            segment_type=s["segment_type"],
            length=s["end_offset"] - s["start_offset"],
            created_at=s["created_at"] or "",
        )
        for s in seg_rows
    ]


@router.delete("/{firmware_id}/segments/{segment_id}", status_code=204)
async def delete_segment(firmware_id: int, segment_id: int):
    db = await get_db()
    try:
        seg_row = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE id = ? AND firmware_id = ?",
            (segment_id, firmware_id),
        )
        if not seg_row:
            raise HTTPException(status_code=404, detail="segment not found")

        await db.execute("DELETE FROM firmware_segments WHERE id = ?", (segment_id,))
        await db.commit()
    finally:
        await db.close()


@router.post("/{firmware_id}/segments/auto-padding", response_model=AutoPaddingResult)
async def auto_detect_padding(firmware_id: int):
    db = await get_db()
    try:
        fw_row = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE id = ?", (firmware_id,)
        )
        if not fw_row:
            raise HTTPException(status_code=404, detail="firmware not found")

        fw = fw_row[0]
        data = hex_to_bytes(fw["hex_data"])
        fw_length = len(data)

        existing_segs = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ?",
            (firmware_id,),
        )

        padding_regions = []
        i = 0
        while i < fw_length:
            current_byte = data[i]
            run_length = 1
            j = i + 1
            while j < fw_length and data[j] == current_byte:
                run_length += 1
                j += 1

            if run_length >= PADDING_THRESHOLD:
                overlaps = False
                for seg in existing_segs:
                    if _segments_overlap(i, i + run_length, seg["start_offset"], seg["end_offset"]):
                        overlaps = True
                        break

                if not overlaps:
                    padding_regions.append((i, i + run_length, current_byte))

            i = j

        created_segments = []
        for idx, (start, end, byte_val) in enumerate(padding_regions):
            seg_name = f"padding_{idx + 1}_0x{byte_val:02x}"
            cursor = await db.execute(
                """
                INSERT INTO firmware_segments (firmware_id, name, start_offset, end_offset, segment_type)
                VALUES (?, ?, ?, ?, 'padding')
                """,
                (firmware_id, seg_name, start, end),
            )
            seg_id = cursor.lastrowid

            seg_row = await db.execute_fetchall(
                "SELECT * FROM firmware_segments WHERE id = ?", (seg_id,)
            )
            s = seg_row[0]
            created_segments.append(
                SegmentOut(
                    id=s["id"],
                    firmware_id=s["firmware_id"],
                    name=s["name"],
                    start_offset=s["start_offset"],
                    end_offset=s["end_offset"],
                    segment_type=s["segment_type"],
                    length=s["end_offset"] - s["start_offset"],
                    created_at=s["created_at"] or "",
                )
            )

        await db.commit()
    finally:
        await db.close()

    return AutoPaddingResult(
        firmware_id=firmware_id,
        detected_segments=created_segments,
    )


def _do_diff_analysis(
    data_a: bytes, data_b: bytes,
    segs_a: list, segs_b: list,
) -> tuple[int, int, int, int, list[DiffInterval]]:
    len_a = len(data_a)
    len_b = len(data_b)
    min_len = min(len_a, len_b)
    max_len = max(len_a, len_b)

    same_bytes = 0
    different_bytes = 0
    diff_intervals = []

    i = 0
    while i < min_len:
        if data_a[i] == data_b[i]:
            same_bytes += 1
            i += 1
        else:
            diff_start = i
            while i < min_len and data_a[i] != data_b[i]:
                different_bytes += 1
                i += 1
            diff_len = i - diff_start

            preview_len = min(16, diff_len)
            old_preview = bytes_to_hex(data_a[diff_start:diff_start + preview_len])
            new_preview = bytes_to_hex(data_b[diff_start:diff_start + preview_len])

            seg = _find_segment_for_offset(diff_start, segs_a) or _find_segment_for_offset(diff_start, segs_b)

            diff_intervals.append(
                DiffInterval(
                    start_offset=diff_start,
                    length=diff_len,
                    old_hex_preview=old_preview,
                    new_hex_preview=new_preview,
                    region_type="modified",
                    segment_name=seg["name"] if seg else None,
                    segment_type=seg["segment_type"] if seg else None,
                )
            )

    added_bytes = 0
    removed_bytes = 0

    if len_b > len_a:
        added_start = len_a
        added_bytes = len_b - len_a
        preview_len = min(16, added_bytes)
        seg = _find_segment_for_offset(added_start, segs_b)
        diff_intervals.append(
            DiffInterval(
                start_offset=added_start,
                length=added_bytes,
                old_hex_preview=None,
                new_hex_preview=bytes_to_hex(data_b[added_start:added_start + preview_len]),
                region_type="added",
                segment_name=seg["name"] if seg else None,
                segment_type=seg["segment_type"] if seg else None,
            )
        )
    elif len_a > len_b:
        removed_start = len_b
        removed_bytes = len_a - len_b
        preview_len = min(16, removed_bytes)
        seg = _find_segment_for_offset(removed_start, segs_a)
        diff_intervals.append(
            DiffInterval(
                start_offset=removed_start,
                length=removed_bytes,
                old_hex_preview=bytes_to_hex(data_a[removed_start:removed_start + preview_len]),
                new_hex_preview=None,
                region_type="removed",
                segment_name=seg["name"] if seg else None,
                segment_type=seg["segment_type"] if seg else None,
            )
        )

    return same_bytes, different_bytes, added_bytes, removed_bytes, diff_intervals


@router.post("/diff", response_model=DiffReport)
async def compare_firmwares(body: DiffRequest):
    db = await get_db()
    try:
        fw_a_row = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE id = ?", (body.firmware_a_id,)
        )
        if not fw_a_row:
            raise HTTPException(status_code=404, detail="firmware A not found")

        fw_b_row = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE id = ?", (body.firmware_b_id,)
        )
        if not fw_b_row:
            raise HTTPException(status_code=404, detail="firmware B not found")

        fw_a = fw_a_row[0]
        fw_b = fw_b_row[0]

        if fw_a["device_model"] != fw_b["device_model"]:
            raise HTTPException(
                status_code=400,
                detail=f"cannot compare different device models: {fw_a['device_model']} vs {fw_b['device_model']}",
            )

        segs_a = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ? ORDER BY start_offset",
            (body.firmware_a_id,),
        )
        segs_b = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ? ORDER BY start_offset",
            (body.firmware_b_id,),
        )
    finally:
        await db.close()

    data_a = hex_to_bytes(fw_a["hex_data"])
    data_b = hex_to_bytes(fw_b["hex_data"])

    same_bytes, different_bytes, added_bytes, removed_bytes, diff_intervals = _do_diff_analysis(
        data_a, data_b, segs_a, segs_b
    )

    max_total = max(len(data_a), len(data_b))
    same_percent = round((same_bytes / max_total) * 100, 2) if max_total > 0 else 0.0
    different_percent = round((different_bytes / max_total) * 100, 2) if max_total > 0 else 0.0

    return DiffReport(
        firmware_a_id=body.firmware_a_id,
        firmware_b_id=body.firmware_b_id,
        firmware_a_name=fw_a["name"],
        firmware_b_name=fw_b["name"],
        firmware_a_version=fw_a["version"],
        firmware_b_version=fw_b["version"],
        device_model=fw_a["device_model"],
        total_bytes_a=len(data_a),
        total_bytes_b=len(data_b),
        same_bytes=same_bytes,
        same_percent=same_percent,
        different_bytes=different_bytes,
        different_percent=different_percent,
        added_bytes=added_bytes,
        removed_bytes=removed_bytes,
        diff_intervals=diff_intervals,
    )


@router.post("/diff/summary", response_model=ChangeSummary)
async def get_change_summary(body: DiffRequest):
    db = await get_db()
    try:
        fw_a_row = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE id = ?", (body.firmware_a_id,)
        )
        if not fw_a_row:
            raise HTTPException(status_code=404, detail="firmware A not found")

        fw_b_row = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE id = ?", (body.firmware_b_id,)
        )
        if not fw_b_row:
            raise HTTPException(status_code=404, detail="firmware B not found")

        fw_a = fw_a_row[0]
        fw_b = fw_b_row[0]

        if fw_a["device_model"] != fw_b["device_model"]:
            raise HTTPException(
                status_code=400,
                detail=f"cannot compare different device models: {fw_a['device_model']} vs {fw_b['device_model']}",
            )

        segs_a = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ? ORDER BY start_offset",
            (body.firmware_a_id,),
        )
        segs_b = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ? ORDER BY start_offset",
            (body.firmware_b_id,),
        )
    finally:
        await db.close()

    data_a = hex_to_bytes(fw_a["hex_data"])
    data_b = hex_to_bytes(fw_b["hex_data"])

    same_bytes, different_bytes, added_bytes, removed_bytes, diff_intervals = _do_diff_analysis(
        data_a, data_b, segs_a, segs_b
    )

    max_total = max(len(data_a), len(data_b))
    overall_change_rate = round(
        ((different_bytes + added_bytes + removed_bytes) / max_total) * 100, 2
    ) if max_total > 0 else 0.0

    len_a = len(data_a)
    len_b = len(data_b)

    all_segments = {}
    for seg in segs_a:
        seg_start = seg["start_offset"]
        seg_end = seg["end_offset"]
        actual_end_a = min(seg_end, len_a)
        all_segments[seg["name"]] = {
            "name": seg["name"],
            "type": seg["segment_type"],
            "start_a": seg_start,
            "end_a": seg_end,
            "actual_end_a": actual_end_a,
            "start_b": None,
            "end_b": None,
            "actual_end_b": None,
            "changed": 0,
        }
    for seg in segs_b:
        seg_start = seg["start_offset"]
        seg_end = seg["end_offset"]
        actual_end_b = min(seg_end, len_b)
        if seg["name"] in all_segments:
            all_segments[seg["name"]]["start_b"] = seg_start
            all_segments[seg["name"]]["end_b"] = seg_end
            all_segments[seg["name"]]["actual_end_b"] = actual_end_b
        else:
            all_segments[seg["name"]] = {
                "name": seg["name"],
                "type": seg["segment_type"],
                "start_a": None,
                "end_a": None,
                "actual_end_a": None,
                "start_b": seg_start,
                "end_b": seg_end,
                "actual_end_b": actual_end_b,
                "changed": 0,
            }

    for interval in diff_intervals:
        iv_start = interval.start_offset
        iv_end = interval.start_offset + interval.length
        for seg_name, seg_info in all_segments.items():
            union_start = min(
                seg_info["start_a"] if seg_info["start_a"] is not None else float('inf'),
                seg_info["start_b"] if seg_info["start_b"] is not None else float('inf'),
            )
            union_end = max(
                seg_info["end_a"] if seg_info["end_a"] is not None else 0,
                seg_info["end_b"] if seg_info["end_b"] is not None else 0,
            )
            overlap_start = max(iv_start, union_start)
            overlap_end = min(iv_end, union_end)
            if overlap_start < overlap_end:
                seg_info["changed"] += overlap_end - overlap_start

    segment_changes = []
    has_bootloader_change = False
    has_config_change = False

    for seg_name, seg_info in sorted(all_segments.items(), key=lambda x: (
        min(x[1]["start_a"] if x[1]["start_a"] is not None else float('inf'),
            x[1]["start_b"] if x[1]["start_b"] is not None else float('inf'))
    )):
        union_start = min(
            seg_info["start_a"] if seg_info["start_a"] is not None else float('inf'),
            seg_info["start_b"] if seg_info["start_b"] is not None else float('inf'),
        )
        union_end = max(
            seg_info["end_a"] if seg_info["end_a"] is not None else 0,
            seg_info["end_b"] if seg_info["end_b"] is not None else 0,
        )
        display_start = union_start
        display_end = union_end
        display_length = display_end - display_start

        actual_end_a = seg_info.get("actual_end_a")
        actual_end_b = seg_info.get("actual_end_b")

        a_start = seg_info["start_a"] if seg_info["start_a"] is not None else union_start
        a_end = actual_end_a if actual_end_a is not None else a_start
        b_start = seg_info["start_b"] if seg_info["start_b"] is not None else union_start
        b_end = actual_end_b if actual_end_b is not None else b_start

        range_union_start = min(a_start, b_start)
        range_union_end = max(a_end, b_end)
        effective_length = max(0, range_union_end - range_union_start)

        if effective_length > 0:
            change_density = round(min(seg_info["changed"] / effective_length, 1.0), 4)
        else:
            change_density = 0.0

        segment_changes.append(
            SegmentChangeSummary(
                segment_name=seg_info["name"],
                segment_type=seg_info["type"],
                start_offset=display_start,
                end_offset=display_end,
                total_length=display_length,
                changed_bytes=seg_info["changed"],
                change_density=change_density,
            )
        )
        if seg_info["type"] == "bootloader" and seg_info["changed"] > 0:
            has_bootloader_change = True
        if seg_info["type"] == "config" and seg_info["changed"] > 0:
            has_config_change = True

    return ChangeSummary(
        firmware_a_id=body.firmware_a_id,
        firmware_b_id=body.firmware_b_id,
        firmware_a_version=fw_a["version"],
        firmware_b_version=fw_b["version"],
        overall_change_rate=overall_change_rate,
        segment_changes=segment_changes,
        has_bootloader_change=has_bootloader_change,
        has_config_change=has_config_change,
        high_risk=has_bootloader_change,
    )


@router.post("/batch-compare", response_model=BatchCompareResult)
async def batch_compare_device_model(body: BatchCompareRequest):
    db = await get_db()
    try:
        fw_rows = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE device_model = ?",
            (body.device_model,),
        )
        if not fw_rows:
            raise HTTPException(
                status_code=404,
                detail=f"no firmwares found for device model {body.device_model}",
            )
        if len(fw_rows) < 2:
            raise HTTPException(
                status_code=400,
                detail=f"need at least 2 firmware versions for batch compare, found {len(fw_rows)}",
            )

        sorted_fws = sorted(fw_rows, key=lambda x: _parse_version(x["version"]))

        all_segments = {}
        for fw in sorted_fws:
            segs = await db.execute_fetchall(
                "SELECT * FROM firmware_segments WHERE firmware_id = ? ORDER BY start_offset",
                (fw["id"],),
            )
            all_segments[fw["id"]] = segs
    finally:
        await db.close()

    evolution = []
    versions = [fw["version"] for fw in sorted_fws]

    for i in range(len(sorted_fws) - 1):
        fw_a = sorted_fws[i]
        fw_b = sorted_fws[i + 1]

        data_a = hex_to_bytes(fw_a["hex_data"])
        data_b = hex_to_bytes(fw_b["hex_data"])
        segs_a = all_segments[fw_a["id"]]
        segs_b = all_segments[fw_b["id"]]

        same_bytes, different_bytes, added_bytes, removed_bytes, diff_intervals = _do_diff_analysis(
            data_a, data_b, segs_a, segs_b
        )

        max_total = max(len(data_a), len(data_b))
        change_rate = round(
            ((different_bytes + added_bytes + removed_bytes) / max_total) * 100, 2
        ) if max_total > 0 else 0.0

        changed_bytes = different_bytes + added_bytes + removed_bytes

        seg_changes = {}
        all_segs_local = {}
        for seg in segs_a:
            all_segs_local[seg["name"]] = {
                "start_a": seg["start_offset"],
                "end_a": seg["end_offset"],
                "start_b": None,
                "end_b": None,
                "type": seg["segment_type"],
            }
        for seg in segs_b:
            if seg["name"] in all_segs_local:
                all_segs_local[seg["name"]]["start_b"] = seg["start_offset"]
                all_segs_local[seg["name"]]["end_b"] = seg["end_offset"]
            else:
                all_segs_local[seg["name"]] = {
                    "start_a": None,
                    "end_a": None,
                    "start_b": seg["start_offset"],
                    "end_b": seg["end_offset"],
                    "type": seg["segment_type"],
                }

        has_bootloader_change = False
        for interval in diff_intervals:
            iv_start = interval.start_offset
            iv_end = interval.start_offset + interval.length
            for seg_name, seg_info in all_segs_local.items():
                union_start = min(
                    seg_info["start_a"] if seg_info["start_a"] is not None else float('inf'),
                    seg_info["start_b"] if seg_info["start_b"] is not None else float('inf'),
                )
                union_end = max(
                    seg_info["end_a"] if seg_info["end_a"] is not None else 0,
                    seg_info["end_b"] if seg_info["end_b"] is not None else 0,
                )
                overlap_start = max(iv_start, union_start)
                overlap_end = min(iv_end, union_end)
                if overlap_start < overlap_end:
                    seg_changes[seg_name] = seg_changes.get(seg_name, 0) + (overlap_end - overlap_start)
                    if seg_info["type"] == "bootloader":
                        has_bootloader_change = True

        main_segments = sorted(seg_changes.keys(), key=lambda k: seg_changes[k], reverse=True)[:3]

        evolution.append(
            VersionEvolutionEntry(
                from_version=fw_a["version"],
                to_version=fw_b["version"],
                from_firmware_id=fw_a["id"],
                to_firmware_id=fw_b["id"],
                change_rate=change_rate,
                changed_bytes=changed_bytes,
                main_changed_segments=main_segments,
                has_bootloader_change=has_bootloader_change,
                high_risk=has_bootloader_change,
            )
        )

    return BatchCompareResult(
        device_model=body.device_model,
        version_count=len(sorted_fws),
        versions=versions,
        evolution=evolution,
    )
