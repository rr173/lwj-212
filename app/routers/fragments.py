import json
import struct
from itertools import permutations
from fastapi import APIRouter, HTTPException, Query

from app.models import (
    DetectCandidate,
    DetectRequest,
    DetectResult,
    FieldDef,
    FragmentAddRequest,
    FragmentContribution,
    FragmentGroupCreate,
    FragmentGroupDetailOut,
    FragmentGroupOut,
    FragmentOut,
    ParseResult,
    ReassembleResult,
)
from app.database import get_db
from app.utils import hex_to_bytes, bytes_to_hex
from app.parser import parse_message

router = APIRouter(prefix="/api/fragment-groups", tags=["fragments"])

MAX_FRAGMENTS_PER_GROUP = 20
MAX_REASSEMBLED_SIZE = 64 * 1024
MAX_DETECT_SAMPLES_FULL_PERM = 6


async def _get_template_fields(template_id: int, version: int | None = None):
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
    finally:
        await db.close()

    fields = [FieldDef(**f) for f in json.loads(t_rows[0]["fields_json"])]
    return fields, actual_version


async def _get_sample_bytes(sample_id: int) -> bytes | None:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT hex_data FROM samples WHERE id = ?", (sample_id,)
        )
    finally:
        await db.close()
    if not rows:
        return None
    return hex_to_bytes(rows[0]["hex_data"])


@router.post("", response_model=FragmentGroupOut, status_code=201)
async def create_fragment_group(body: FragmentGroupCreate):
    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT id FROM templates WHERE id = ?", (body.template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        if body.template_version is not None:
            v_rows = await db.execute_fetchall(
                "SELECT version FROM template_versions WHERE template_id = ? AND version = ?",
                (body.template_id, body.template_version),
            )
            if not v_rows:
                raise HTTPException(status_code=404, detail="template version not found")
            actual_version = body.template_version
        else:
            v_rows = await db.execute_fetchall(
                "SELECT MAX(version) as max_version FROM template_versions WHERE template_id = ?",
                (body.template_id,),
            )
            actual_version = v_rows[0]["max_version"] or 1

        cursor = await db.execute(
            """
            INSERT INTO fragment_groups (name, template_id, template_version, reassembly_strategy, note)
            VALUES (?, ?, ?, ?, ?)
            """,
            (body.name, body.template_id, actual_version, body.reassembly_strategy, body.note),
        )
        await db.commit()
        group_id = cursor.lastrowid
    finally:
        await db.close()

    return FragmentGroupOut(
        id=group_id,
        name=body.name,
        template_id=body.template_id,
        template_version=actual_version,
        reassembly_strategy=body.reassembly_strategy,
        note=body.note,
        fragment_count=0,
        created_at="",
    )


@router.get("", response_model=list[FragmentGroupOut])
async def list_fragment_groups(
    name: str = Query(default=None, description="search by name (fuzzy)"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        if name:
            rows = await db.execute_fetchall(
                """
                SELECT fg.*, COUNT(f.id) as fragment_count
                FROM fragment_groups fg
                LEFT JOIN fragments f ON f.group_id = fg.id
                WHERE fg.name LIKE ?
                GROUP BY fg.id
                ORDER BY fg.id DESC LIMIT ? OFFSET ?
                """,
                (f"%{name}%", limit, offset),
            )
        else:
            rows = await db.execute_fetchall(
                """
                SELECT fg.*, COUNT(f.id) as fragment_count
                FROM fragment_groups fg
                LEFT JOIN fragments f ON f.group_id = fg.id
                GROUP BY fg.id
                ORDER BY fg.id DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
    finally:
        await db.close()

    return [
        FragmentGroupOut(
            id=r["id"],
            name=r["name"],
            template_id=r["template_id"],
            template_version=r["template_version"],
            reassembly_strategy=r["reassembly_strategy"],
            note=r["note"] or "",
            fragment_count=r["fragment_count"],
            created_at=r["created_at"] or "",
        )
        for r in rows
    ]


@router.get("/{group_id}", response_model=FragmentGroupDetailOut)
async def get_fragment_group(group_id: int):
    db = await get_db()
    try:
        g_rows = await db.execute_fetchall(
            "SELECT * FROM fragment_groups WHERE id = ?", (group_id,)
        )
        if not g_rows:
            raise HTTPException(status_code=404, detail="fragment group not found")

        f_rows = await db.execute_fetchall(
            """
            SELECT f.*, s.name as sample_name, s.byte_length as sample_byte_length
            FROM fragments f
            LEFT JOIN samples s ON s.id = f.sample_id
            WHERE f.group_id = ?
            ORDER BY f.seq_num ASC
            """,
            (group_id,),
        )
    finally:
        await db.close()

    g = g_rows[0]
    fragments = [
        FragmentOut(
            id=r["id"],
            group_id=r["group_id"],
            seq_num=r["seq_num"],
            sample_id=r["sample_id"],
            sample_name=r["sample_name"] if r["sample_name"] else None,
            sample_byte_length=r["sample_byte_length"] if r["sample_byte_length"] else None,
            created_at=r["created_at"] or "",
        )
        for r in f_rows
    ]

    return FragmentGroupDetailOut(
        id=g["id"],
        name=g["name"],
        template_id=g["template_id"],
        template_version=g["template_version"],
        reassembly_strategy=g["reassembly_strategy"],
        note=g["note"] or "",
        fragments=fragments,
        created_at=g["created_at"] or "",
    )


@router.delete("/{group_id}", status_code=204)
async def delete_fragment_group(group_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT id FROM fragment_groups WHERE id = ?", (group_id,)
        )
        if not rows:
            raise HTTPException(status_code=404, detail="fragment group not found")
        await db.execute("DELETE FROM fragment_groups WHERE id = ?", (group_id,))
        await db.commit()
    finally:
        await db.close()
    return None


@router.post("/{group_id}/fragments", response_model=FragmentOut, status_code=201)
async def add_fragment(group_id: int, body: FragmentAddRequest):
    db = await get_db()
    try:
        g_rows = await db.execute_fetchall(
            "SELECT id FROM fragment_groups WHERE id = ?", (group_id,)
        )
        if not g_rows:
            raise HTTPException(status_code=404, detail="fragment group not found")

        count_rows = await db.execute_fetchall(
            "SELECT COUNT(*) as cnt FROM fragments WHERE group_id = ?", (group_id,)
        )
        current_count = count_rows[0]["cnt"]
        if current_count >= MAX_FRAGMENTS_PER_GROUP:
            raise HTTPException(
                status_code=400,
                detail=f"fragment group cannot exceed {MAX_FRAGMENTS_PER_GROUP} fragments",
            )

        s_rows = await db.execute_fetchall(
            "SELECT id, name, byte_length FROM samples WHERE id = ?", (body.sample_id,)
        )
        if not s_rows:
            raise HTTPException(status_code=404, detail=f"sample {body.sample_id} not found")

        existing_rows = await db.execute_fetchall(
            "SELECT seq_num FROM fragments WHERE group_id = ? AND seq_num = ?",
            (group_id, body.seq_num),
        )
        if existing_rows:
            raise HTTPException(
                status_code=409,
                detail=f"fragment with seq_num {body.seq_num} already exists in this group",
            )

        cursor = await db.execute(
            "INSERT INTO fragments (group_id, seq_num, sample_id) VALUES (?, ?, ?)",
            (group_id, body.seq_num, body.sample_id),
        )
        await db.commit()
        fragment_id = cursor.lastrowid
    finally:
        await db.close()

    sample = s_rows[0]
    return FragmentOut(
        id=fragment_id,
        group_id=group_id,
        seq_num=body.seq_num,
        sample_id=body.sample_id,
        sample_name=sample["name"],
        sample_byte_length=sample["byte_length"],
        created_at="",
    )


@router.delete("/{group_id}/fragments/{seq_num}", status_code=204)
async def remove_fragment(group_id: int, seq_num: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT id FROM fragments WHERE group_id = ? AND seq_num = ?",
            (group_id, seq_num),
        )
        if not rows:
            raise HTTPException(status_code=404, detail="fragment not found")
        await db.execute(
            "DELETE FROM fragments WHERE group_id = ? AND seq_num = ?",
            (group_id, seq_num),
        )
        await db.commit()
    finally:
        await db.close()
    return None


def _validate_sequence_continuity(seq_nums: list[int]) -> None:
    if not seq_nums:
        return
    sorted_nums = sorted(seq_nums)
    expected = 1
    for n in sorted_nums:
        if n != expected:
            raise HTTPException(
                status_code=400,
                detail=f"fragment sequence is not continuous: expected seq {expected}, found {n}",
            )
        expected += 1


@router.post("/{group_id}/reassemble", response_model=ReassembleResult)
async def reassemble_fragments(group_id: int):
    db = await get_db()
    try:
        g_rows = await db.execute_fetchall(
            "SELECT * FROM fragment_groups WHERE id = ?", (group_id,)
        )
        if not g_rows:
            raise HTTPException(status_code=404, detail="fragment group not found")
        group = g_rows[0]

        f_rows = await db.execute_fetchall(
            """
            SELECT f.*, s.hex_data as sample_hex, s.byte_length as sample_byte_length
            FROM fragments f
            LEFT JOIN samples s ON s.id = f.sample_id
            WHERE f.group_id = ?
            ORDER BY f.seq_num ASC
            """,
            (group_id,),
        )

        missing_seqs: list[int] = []
        valid_fragments = []
        for r in f_rows:
            if r["sample_hex"] is None:
                missing_seqs.append(r["seq_num"])
            else:
                valid_fragments.append(r)

        if missing_seqs:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "some fragment samples are missing or deleted",
                    "missing_seq_nums": missing_seqs,
                },
            )

        all_seq_nums = [r["seq_num"] for r in f_rows]
        _validate_sequence_continuity(all_seq_nums)

        template_id = group["template_id"]
        template_version = group["template_version"]
        t_rows = await db.execute_fetchall(
            "SELECT fields_json FROM template_versions WHERE template_id = ? AND version = ?",
            (template_id, template_version),
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template version not found")
        fields = [FieldDef(**f) for f in json.loads(t_rows[0]["fields_json"])]
    finally:
        await db.close()

    strategy = group["reassembly_strategy"]

    if strategy == "sequential":
        assembled_bytes, contributions, damaged = _reassemble_sequential(valid_fragments)
    elif strategy == "length_prefix":
        assembled_bytes, contributions, damaged = _reassemble_length_prefix(valid_fragments)
    else:
        raise HTTPException(status_code=400, detail=f"unknown strategy: {strategy}")

    if len(assembled_bytes) > MAX_REASSEMBLED_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"reassembled message exceeds 64KB limit ({len(assembled_bytes)} bytes)",
        )

    parse_result = parse_message(
        assembled_bytes,
        fields,
        template_id,
        0,
        template_version,
    )

    return ReassembleResult(
        group_id=group_id,
        reassembled_hex=bytes_to_hex(assembled_bytes),
        total_bytes=len(assembled_bytes),
        parse_result=parse_result,
        fragment_contributions=[
            FragmentContribution(
                seq_num=c["seq_num"],
                sample_id=c["sample_id"],
                start_offset=c["start_offset"],
                end_offset=c["end_offset"],
                is_damaged=c.get("is_damaged", False),
                damage_reason=c.get("damage_reason"),
            )
            for c in contributions
        ],
        damaged_fragments=damaged,
    )


def _reassemble_sequential(fragments: list) -> tuple[bytes, list[dict], list[int]]:
    parts: list[bytes] = []
    contributions: list[dict] = []
    damaged: list[int] = []
    offset = 0

    for frag in fragments:
        data = hex_to_bytes(frag["sample_hex"])
        start = offset
        end = offset + len(data) - 1
        parts.append(data)
        contributions.append({
            "seq_num": frag["seq_num"],
            "sample_id": frag["sample_id"],
            "start_offset": start,
            "end_offset": end,
            "is_damaged": False,
        })
        offset += len(data)

    return b"".join(parts), contributions, damaged


def _reassemble_length_prefix(fragments: list) -> tuple[bytes, list[dict], list[int]]:
    parts: list[bytes] = []
    contributions: list[dict] = []
    damaged: list[int] = []
    offset = 0

    for frag in fragments:
        data = hex_to_bytes(frag["sample_hex"])
        if len(data) < 2:
            damaged.append(frag["seq_num"])
            contributions.append({
                "seq_num": frag["seq_num"],
                "sample_id": frag["sample_id"],
                "start_offset": offset,
                "end_offset": offset - 1,
                "is_damaged": True,
                "damage_reason": "fragment too short for length prefix",
            })
            continue

        payload_len = struct.unpack(">H", data[:2])[0]
        remaining = len(data) - 2

        if payload_len > remaining:
            damaged.append(frag["seq_num"])
            payload_data = data[2:]
            start = offset
            end = offset + len(payload_data) - 1 if payload_data else offset - 1
            parts.append(payload_data)
            contributions.append({
                "seq_num": frag["seq_num"],
                "sample_id": frag["sample_id"],
                "start_offset": start,
                "end_offset": end,
                "is_damaged": True,
                "damage_reason": f"length prefix says {payload_len} bytes but only {remaining} available",
            })
            if payload_data:
                offset += len(payload_data)
        else:
            payload_data = data[2 : 2 + payload_len]
            start = offset
            end = offset + len(payload_data) - 1
            parts.append(payload_data)
            contributions.append({
                "seq_num": frag["seq_num"],
                "sample_id": frag["sample_id"],
                "start_offset": start,
                "end_offset": end,
                "is_damaged": False,
            })
            offset += len(payload_data)

    return b"".join(parts), contributions, damaged


@router.post("/detect", response_model=DetectResult)
async def detect_best_order(body: DetectRequest):
    fields, actual_version = await _get_template_fields(body.template_id, body.template_version)

    sample_data: dict[int, bytes] = {}
    for sid in body.sample_ids:
        data = await _get_sample_bytes(sid)
        if data is None:
            raise HTTPException(status_code=404, detail=f"sample {sid} not found")
        sample_data[sid] = data

    sample_ids = list(body.sample_ids)

    if len(sample_ids) > MAX_DETECT_SAMPLES_FULL_PERM:
        sample_ids = sample_ids[:MAX_DETECT_SAMPLES_FULL_PERM]

    all_perms = list(permutations(sample_ids))

    candidates: list[DetectCandidate] = []
    for perm in all_perms:
        data_list = [sample_data[sid] for sid in perm]
        assembled = b"".join(data_list)

        if len(assembled) > MAX_REASSEMBLED_SIZE:
            continue

        parse_result = parse_message(
            assembled,
            fields,
            body.template_id,
            0,
            actual_version,
        )

        candidates.append(
            DetectCandidate(
                order=list(perm),
                coverage_percent=parse_result.coverage_percent,
                parse_result=parse_result,
                reassembled_hex=bytes_to_hex(assembled),
            )
        )

    if not candidates:
        raise HTTPException(status_code=400, detail="no valid reassembly candidates")

    candidates.sort(key=lambda c: c.coverage_percent, reverse=True)
    best = candidates[0]

    return DetectResult(
        template_id=body.template_id,
        template_version=actual_version,
        total_samples=len(body.sample_ids),
        candidates_attempted=len(candidates),
        best_candidate=best,
        all_candidates=candidates,
    )
