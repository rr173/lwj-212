import math
from collections import Counter
from fastapi import APIRouter, HTTPException, Query
from app.database import get_db
from app.utils import validate_hex, hex_to_bytes, shannon_entropy, bytes_to_hex
from app.models import (
    EntropySegmentRequest, EntropySegment, EntropySegmentResult,
    ByteFingerprintRequest, SegmentFingerprint, ByteFingerprintResult,
    CrossFirmwareMapRequest, SegmentMapping, CrossFirmwareMapResult,
    ENTROPY_INFLECTION_THRESHOLD, HOMOLOGOUS_SIMILARITY_THRESHOLD,
)

router = APIRouter(prefix="/api/firmware", tags=["segment-clustering"])

_ARM_PATTERN = Counter()
for b in range(0xE0, 0xF0):
    _ARM_PATTERN[b] = 10
for b in range(0x00, 0x100):
    if b not in _ARM_PATTERN:
        _ARM_PATTERN[b] = 1

_X86_PATTERN = Counter()
for b in [0x48, 0x89, 0x8B, 0x83, 0x85, 0x0F, 0xE8, 0xFF, 0x50, 0x53, 0x55, 0x57, 0x5B, 0x5D, 0xC3, 0xC7]:
    _X86_PATTERN[b] = 10
for b in range(0x00, 0x100):
    if b not in _X86_PATTERN:
        _X86_PATTERN[b] = 1

_UTF8_TEXT_PATTERN = Counter()
for b in range(0x20, 0x7F):
    _UTF8_TEXT_PATTERN[b] = 10
for b in [0x0A, 0x0D, 0x09]:
    _UTF8_TEXT_PATTERN[b] = 8
for b in range(0x00, 0x100):
    if b not in _UTF8_TEXT_PATTERN:
        _UTF8_TEXT_PATTERN[b] = 0

_ZERO_FILL_PATTERN = Counter({0x00: 100})
for b in range(0x01, 0x100):
    _ZERO_FILL_PATTERN[b] = 0

_RANDOM_DATA_PATTERN = Counter()
for b in range(0x00, 0x100):
    _RANDOM_DATA_PATTERN[b] = 1

BUILTIN_PATTERNS = {
    "arm_code": _ARM_PATTERN,
    "x86_code": _X86_PATTERN,
    "utf8_text": _UTF8_TEXT_PATTERN,
    "zero_fill": _ZERO_FILL_PATTERN,
    "random_data": _RANDOM_DATA_PATTERN,
}


def _sliding_window_entropy(data: bytes, window_size: int) -> list[float]:
    length = len(data)
    if length == 0:
        return []
    if window_size >= length:
        return [shannon_entropy(data)]
    entropies = []
    for i in range(length - window_size + 1):
        window = data[i:i + window_size]
        entropies.append(shannon_entropy(window))
    return entropies


def _find_inflection_points(entropies: list[float], threshold: float) -> list[int]:
    if len(entropies) < 2:
        return []
    points = []
    for i in range(1, len(entropies)):
        diff = abs(entropies[i] - entropies[i - 1])
        if diff > threshold:
            points.append(i)
    return points


def _entropy_label(avg_entropy: float) -> str:
    if avg_entropy > 7.0:
        return "可能加密或压缩"
    elif avg_entropy < 1.0:
        return "padding或空白"
    else:
        return "代码或结构化数据"


def _compute_byte_frequency(data: bytes) -> list[float]:
    length = len(data)
    if length == 0:
        return [0.0] * 256
    counts = Counter(data)
    return [counts.get(b, 0) / length for b in range(256)]


def _cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot_product / (norm_a * norm_b)


def _match_byte_fingerprint(freq: list[float]) -> tuple[str, int]:
    best_pattern = "unknown"
    best_sim = 0.0
    for pattern_name, pattern_counter in BUILTIN_PATTERNS.items():
        pattern_freq = [pattern_counter.get(b, 0) for b in range(256)]
        sim = _cosine_similarity(freq, pattern_freq)
        if sim > best_sim:
            best_sim = sim
            best_pattern = pattern_name
    confidence = min(100, max(0, int(round(best_sim * 100))))
    return best_pattern, confidence


@router.post("/{firmware_id}/entropy-segments", response_model=EntropySegmentResult)
async def entropy_segmentation(
    firmware_id: int,
    body: EntropySegmentRequest = EntropySegmentRequest(),
):
    db = await get_db()
    try:
        fw_row = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE id = ?", (firmware_id,)
        )
        if not fw_row:
            raise HTTPException(status_code=404, detail="firmware not found")
    finally:
        await db.close()

    data = hex_to_bytes(fw_row[0]["hex_data"])
    total_bytes = len(data)

    if total_bytes == 0:
        return EntropySegmentResult(
            firmware_id=firmware_id,
            window_size=body.window_size,
            total_bytes=0,
            segment_count=0,
            segments=[],
        )

    window_size = min(body.window_size, total_bytes)
    entropies = _sliding_window_entropy(data, window_size)

    if not entropies:
        return EntropySegmentResult(
            firmware_id=firmware_id,
            window_size=body.window_size,
            total_bytes=total_bytes,
            segment_count=0,
            segments=[],
        )

    inflection_indices = _find_inflection_points(entropies, ENTROPY_INFLECTION_THRESHOLD)

    boundaries = [0]
    for idx in inflection_indices:
        boundary = idx + window_size // 2
        if boundary > boundaries[-1]:
            boundaries.append(boundary)
    if boundaries[-1] < total_bytes:
        boundaries.append(total_bytes)

    segments: list[EntropySegment] = []
    for i in range(len(boundaries) - 1):
        start = boundaries[i]
        end = boundaries[i + 1]
        seg_data = data[start:end]
        avg_ent = shannon_entropy(seg_data) if seg_data else 0.0
        label = _entropy_label(avg_ent)
        segments.append(
            EntropySegment(
                start_offset=start,
                end_offset=end,
                avg_entropy=round(avg_ent, 4),
                label=label,
            )
        )

    return EntropySegmentResult(
        firmware_id=firmware_id,
        window_size=body.window_size,
        total_bytes=total_bytes,
        segment_count=len(segments),
        segments=segments,
    )


@router.post("/{firmware_id}/byte-fingerprint", response_model=ByteFingerprintResult)
async def byte_fingerprint_analysis(
    firmware_id: int,
    use_entropy_segments: bool = Query(default=False, description="use entropy segmentation results if no annotated segments exist"),
    window_size: int = Query(default=32, ge=8, le=256, description="window size for entropy segmentation fallback"),
):
    db = await get_db()
    try:
        fw_row = await db.execute_fetchall(
            "SELECT * FROM firmwares WHERE id = ?", (firmware_id,)
        )
        if not fw_row:
            raise HTTPException(status_code=404, detail="firmware not found")

        seg_rows = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ? ORDER BY start_offset",
            (firmware_id,),
        )
    finally:
        await db.close()

    data = hex_to_bytes(fw_row[0]["hex_data"])
    total_bytes = len(data)

    segment_defs: list[tuple[str, int, int]] = []
    if seg_rows:
        for seg in seg_rows:
            segment_defs.append((seg["name"], seg["start_offset"], seg["end_offset"]))
    elif use_entropy_segments:
        window_size = min(window_size, total_bytes) if total_bytes > 0 else window_size
        entropies = _sliding_window_entropy(data, window_size) if total_bytes > 0 else []
        if entropies:
            inflection_indices = _find_inflection_points(entropies, ENTROPY_INFLECTION_THRESHOLD)
            boundaries = [0]
            for idx in inflection_indices:
                boundary = idx + window_size // 2
                if boundary > boundaries[-1]:
                    boundaries.append(boundary)
            if boundaries[-1] < total_bytes:
                boundaries.append(total_bytes)
            for i in range(len(boundaries) - 1):
                start = boundaries[i]
                end = boundaries[i + 1]
                seg_data = data[start:end]
                avg_ent = shannon_entropy(seg_data) if seg_data else 0.0
                label = _entropy_label(avg_ent)
                seg_name = f"entropy_seg_{i + 1}"
                segment_defs.append((seg_name, start, end))
        else:
            if total_bytes > 0:
                segment_defs.append(("entropy_seg_1", 0, total_bytes))
    else:
        if total_bytes > 0:
            segment_defs.append(("full_firmware", 0, total_bytes))

    fingerprints: list[SegmentFingerprint] = []
    for seg_name, start, end in segment_defs:
        seg_data = data[start:end]
        if not seg_data:
            fingerprints.append(
                SegmentFingerprint(
                    segment_name=seg_name,
                    start_offset=start,
                    end_offset=end,
                    best_match="empty",
                    confidence=0,
                )
            )
            continue
        freq = _compute_byte_frequency(seg_data)
        best_match, confidence = _match_byte_fingerprint(freq)
        fingerprints.append(
            SegmentFingerprint(
                segment_name=seg_name,
                start_offset=start,
                end_offset=end,
                best_match=best_match,
                confidence=confidence,
            )
        )

    return ByteFingerprintResult(
        firmware_id=firmware_id,
        segment_count=len(fingerprints),
        fingerprints=fingerprints,
    )


@router.post("/cross-firmware-map", response_model=CrossFirmwareMapResult)
async def cross_firmware_mapping(body: CrossFirmwareMapRequest):
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
                detail=f"cross-firmware mapping requires same device model: {fw_a['device_model']} vs {fw_b['device_model']}",
            )

        segs_a_rows = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ? ORDER BY start_offset",
            (body.firmware_a_id,),
        )
        segs_b_rows = await db.execute_fetchall(
            "SELECT * FROM firmware_segments WHERE firmware_id = ? ORDER BY start_offset",
            (body.firmware_b_id,),
        )
    finally:
        await db.close()

    data_a = hex_to_bytes(fw_a["hex_data"])
    data_b = hex_to_bytes(fw_b["hex_data"])

    def _build_seg_info(seg_rows, data):
        result = []
        for seg in seg_rows:
            seg_data = data[seg["start_offset"]:seg["end_offset"]]
            freq = _compute_byte_frequency(seg_data) if seg_data else [0.0] * 256
            result.append({
                "name": seg["name"],
                "start": seg["start_offset"],
                "end": seg["end_offset"],
                "freq": freq,
            })
        return result

    segs_a = _build_seg_info(segs_a_rows, data_a)
    segs_b = _build_seg_info(segs_b_rows, data_b)

    if not segs_a or not segs_b:
        return CrossFirmwareMapResult(
            firmware_a_id=body.firmware_a_id,
            firmware_b_id=body.firmware_b_id,
            device_model=fw_a["device_model"] or "",
            total_pairs=0,
            mappings=[],
        )

    name_to_b = {s["name"]: s for s in segs_b}
    used_b = set()
    mappings: list[SegmentMapping] = []

    for seg_a in segs_a:
        matched_seg_b = None
        if seg_a["name"] in name_to_b:
            matched_seg_b = name_to_b[seg_a["name"]]
        else:
            best_dist = float('inf')
            for seg_b in segs_b:
                if seg_b["name"] in used_b:
                    continue
                dist_a = (seg_a["start"] + seg_a["end"]) / 2
                dist_b = (seg_b["start"] + seg_b["end"]) / 2
                dist = abs(dist_a - dist_b)
                if dist < best_dist:
                    best_dist = dist
                    matched_seg_b = seg_b

        if matched_seg_b is None:
            continue

        sim = _cosine_similarity(seg_a["freq"], matched_seg_b["freq"])
        sim_percent = round(sim * 100, 2)
        is_homologous = sim_percent > HOMOLOGOUS_SIMILARITY_THRESHOLD

        mappings.append(
            SegmentMapping(
                segment_a_name=seg_a["name"],
                segment_b_name=matched_seg_b["name"],
                similarity_percent=sim_percent,
                is_homologous=is_homologous,
            )
        )
        used_b.add(matched_seg_b["name"])

    return CrossFirmwareMapResult(
        firmware_a_id=body.firmware_a_id,
        firmware_b_id=body.firmware_b_id,
        device_model=fw_a["device_model"] or "",
        total_pairs=len(mappings),
        mappings=mappings,
    )
