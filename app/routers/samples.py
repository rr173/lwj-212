from fastapi import APIRouter, HTTPException, Query
from app.models import SampleCreate, SampleOut
from app.database import get_db
from app.utils import validate_hex, hex_to_bytes, shannon_entropy

router = APIRouter(prefix="/api/samples", tags=["samples"])

MAX_HEX_LENGTH = 64 * 1024 * 2


async def _load_tags_for_samples(sample_ids: list[int]) -> dict[int, list[str]]:
    if not sample_ids:
        return {}
    db = await get_db()
    try:
        placeholders = ",".join("?" * len(sample_ids))
        rows = await db.execute_fetchall(
            f"SELECT sample_id, tag FROM sample_tags WHERE sample_id IN ({placeholders}) ORDER BY id ASC",
            sample_ids,
        )
    finally:
        await db.close()

    tags_map: dict[int, list[str]] = {sid: [] for sid in sample_ids}
    for r in rows:
        tags_map[r["sample_id"]].append(r["tag"])
    return tags_map


def _row_to_sample_out(row, tags: list[str] | None = None) -> SampleOut:
    return SampleOut(
        id=row["id"],
        name=row["name"],
        hex_data=row["hex_data"],
        byte_length=row["byte_length"],
        entropy=row["entropy"],
        note=row["note"] or "",
        created_at=row["created_at"] or "",
        tags=tags or [],
    )


@router.post("", response_model=SampleOut, status_code=201)
async def create_sample(body: SampleCreate):
    try:
        cleaned = validate_hex(body.hex_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if len(cleaned) > MAX_HEX_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"hex data exceeds maximum size of 64KB ({len(cleaned) // 2} bytes)",
        )

    data = hex_to_bytes(cleaned)
    byte_length = len(data)
    entropy = shannon_entropy(data)

    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO samples (name, hex_data, byte_length, entropy, note) VALUES (?, ?, ?, ?, ?)",
            (body.name, cleaned, byte_length, entropy, body.note),
        )
        await db.commit()
        sample_id = cursor.lastrowid
    finally:
        await db.close()

    return _row_to_sample_out(
        {
            "id": sample_id,
            "name": body.name,
            "hex_data": cleaned,
            "byte_length": byte_length,
            "entropy": entropy,
            "note": body.note,
            "created_at": "",
        },
        tags=[],
    )


@router.get("", response_model=list[SampleOut])
async def list_samples(
    name: str = Query(default=None, description="search by name (fuzzy)"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        if name:
            rows = await db.execute_fetchall(
                "SELECT * FROM samples WHERE name LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (f"%{name}%", limit, offset),
            )
        else:
            rows = await db.execute_fetchall(
                "SELECT * FROM samples ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
    finally:
        await db.close()

    sample_ids = [r["id"] for r in rows]
    tags_map = await _load_tags_for_samples(sample_ids)

    return [_row_to_sample_out(r, tags_map.get(r["id"], [])) for r in rows]


@router.get("/{sample_id}", response_model=SampleOut)
async def get_sample(sample_id: int):
    db = await get_db()
    try:
        row = await db.execute_fetchall(
            "SELECT * FROM samples WHERE id = ?", (sample_id,)
        )
    finally:
        await db.close()

    if not row:
        raise HTTPException(status_code=404, detail="sample not found")

    r = row[0]
    tags_map = await _load_tags_for_samples([sample_id])
    return _row_to_sample_out(r, tags_map.get(sample_id, []))
