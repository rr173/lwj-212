import struct
import random
import json
from app.models import (
    FieldDef,
    FieldValidationDetail,
    FieldEncodingDetail,
    FieldDiffEntry,
    ParseResult,
)
from app.database import get_db
from app.parser import parse_message
from app.utils import hex_to_bytes, shannon_entropy, validate_hex

NUMERIC_TYPES = {"uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"}

TYPE_RANGES = {
    "uint8": (0, 255),
    "uint16_be": (0, 65535),
    "uint16_le": (0, 65535),
    "uint32_be": (0, 4294967295),
    "uint32_le": (0, 4294967295),
}

TYPE_SIZES = {
    "uint8": 1,
    "uint16_be": 2,
    "uint16_le": 2,
    "uint32_be": 4,
    "uint32_le": 4,
}


def validate_field_value(field_def: FieldDef, value: str) -> tuple[bool, str]:
    data_type = field_def.data_type

    if data_type in NUMERIC_TYPES:
        try:
            int_val = int(value)
        except (ValueError, TypeError):
            return False, f"value '{value}' is not a valid integer for {data_type}"
        min_val, max_val = TYPE_RANGES[data_type]
        if int_val < min_val or int_val > max_val:
            return False, f"value {int_val} out of range for {data_type} ({min_val}-{max_val})"
        return True, ""

    if data_type == "ascii":
        try:
            encoded = value.encode("ascii")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return False, "value contains non-ASCII characters"
        for ch in value:
            if ord(ch) < 0x20 or ord(ch) > 0x7E:
                return False, f"character '{ch}' (0x{ord(ch):02x}) is not a printable ASCII character"
        return True, ""

    if data_type == "bytes":
        try:
            cleaned = value.strip().lower()
            if len(cleaned) % 2 != 0:
                return False, "hex string has odd length"
            if not all(c in "0123456789abcdef" for c in cleaned):
                return False, "hex string contains invalid characters"
            bytes.fromhex(cleaned)
        except (ValueError, TypeError):
            return False, "invalid hex string for bytes type"
        return True, ""

    return False, f"unknown data type: {data_type}"


def encode_field_value(field_def: FieldDef, value: str) -> bytes:
    data_type = field_def.data_type

    if data_type in NUMERIC_TYPES:
        int_val = int(value)
        if data_type == "uint8":
            return struct.pack(">B", int_val & 0xFF)
        elif data_type == "uint16_be":
            return struct.pack(">H", int_val & 0xFFFF)
        elif data_type == "uint16_le":
            return struct.pack("<H", int_val & 0xFFFF)
        elif data_type == "uint32_be":
            return struct.pack(">I", int_val & 0xFFFFFFFF)
        elif data_type == "uint32_le":
            return struct.pack("<I", int_val & 0xFFFFFFFF)

    if data_type == "ascii":
        return value.encode("ascii")

    if data_type == "bytes":
        cleaned = value.strip().lower()
        return bytes.fromhex(cleaned)

    return b""


def _condition_matches(
    field_def: FieldDef,
    resolved_values: dict[str, object],
    resolved_types: dict[str, str],
) -> bool:
    if not field_def.condition_field or not field_def.condition_value:
        return True

    cond_val = resolved_values.get(field_def.condition_field)
    if cond_val is None:
        return False

    cond_type = resolved_types.get(field_def.condition_field, "")
    if cond_type in NUMERIC_TYPES:
        try:
            cond_expected = int(field_def.condition_value)
            return int(cond_val) == cond_expected
        except (ValueError, TypeError):
            return False
    else:
        return str(cond_val) == field_def.condition_value


def assemble_message(
    fields: list[FieldDef],
    field_values: dict[str, str],
) -> tuple[bytes, list[FieldEncodingDetail]]:
    ref_target_map: dict[str, FieldDef] = {}
    for f in fields:
        if f.length_rule == "ref" and f.length_ref_field:
            ref_target_map[f.length_ref_field] = f

    pre_encoded: dict[str, bytes] = {}

    for field_def in fields:
        if field_def.length_rule == "ref" and field_def.length_ref_field:
            value = field_values.get(field_def.name)
            if value is None:
                raise ValueError(f"missing value for field '{field_def.name}'")
            valid, error = validate_field_value(field_def, value)
            if not valid:
                raise ValueError(f"field '{field_def.name}': {error}")
            encoded = encode_field_value(field_def, value)
            if field_def.length_rule == "until" and field_def.until_byte:
                try:
                    terminator = int(field_def.until_byte, 16)
                except (ValueError, TypeError):
                    terminator = 0x00
                if not encoded or encoded[-1] != terminator:
                    encoded = encoded + bytes([terminator])
            pre_encoded[field_def.name] = encoded

    length_overrides: dict[str, str] = {}
    for length_field_name, ref_field_def in ref_target_map.items():
        ref_encoded = pre_encoded.get(ref_field_def.name)
        actual_len = len(ref_encoded) if ref_encoded is not None else 0
        length_overrides[length_field_name] = str(actual_len)

    resolved_values: dict[str, object] = {}
    resolved_types: dict[str, str] = {}
    encoded_parts: list[bytes] = []
    encoding_details: list[FieldEncodingDetail] = []

    for field_def in fields:
        if not _condition_matches(field_def, resolved_values, resolved_types):
            encoding_details.append(
                FieldEncodingDetail(
                    field_name=field_def.name,
                    data_type=field_def.data_type,
                    value="",
                    hex="",
                    byte_length=0,
                    skipped=True,
                )
            )
            continue

        value = field_values.get(field_def.name)
        if value is None:
            raise ValueError(f"missing value for field '{field_def.name}'")

        if field_def.name in length_overrides:
            value = length_overrides[field_def.name]

        valid, error = validate_field_value(field_def, value)
        if not valid:
            raise ValueError(f"field '{field_def.name}': {error}")

        if field_def.name in pre_encoded:
            encoded = pre_encoded[field_def.name]
        else:
            encoded = encode_field_value(field_def, value)

        if field_def.length_rule == "until" and field_def.until_byte:
            try:
                terminator = int(field_def.until_byte, 16)
            except (ValueError, TypeError):
                terminator = 0x00
            if not encoded or encoded[-1] != terminator:
                encoded = encoded + bytes([terminator])

        if field_def.data_type in NUMERIC_TYPES:
            resolved_values[field_def.name] = int(value)
        elif field_def.data_type == "ascii":
            resolved_values[field_def.name] = value
        elif field_def.data_type == "bytes":
            resolved_values[field_def.name] = value.strip().lower()
        resolved_types[field_def.name] = field_def.data_type

        encoding_details.append(
            FieldEncodingDetail(
                field_name=field_def.name,
                data_type=field_def.data_type,
                value=value,
                hex=encoded.hex(),
                byte_length=len(encoded),
            )
        )
        encoded_parts.append(encoded)

    return b"".join(encoded_parts), encoding_details


def generate_mutation_value(
    rule,
    data_type: str,
    iteration: int,
) -> str:
    if rule.mutation_type == "increment":
        start = 0
        if rule.start_value is not None:
            start = int(rule.start_value)
        result = start + iteration
        if data_type in NUMERIC_TYPES:
            _, max_val = TYPE_RANGES[data_type]
            result = result % (max_val + 1)
        return str(result)

    elif rule.mutation_type == "random":
        if data_type in NUMERIC_TYPES:
            _, max_val = TYPE_RANGES[data_type]
            return str(random.randint(0, max_val))
        elif data_type == "ascii":
            length = random.randint(1, 32)
            chars = [chr(random.randint(0x20, 0x7E)) for _ in range(length)]
            return "".join(chars)
        elif data_type == "bytes":
            length = random.randint(1, 32)
            return os_urandom_hex(length)
        return "0"

    elif rule.mutation_type == "enumerate":
        if rule.value_list and iteration < len(rule.value_list):
            return rule.value_list[iteration]
        if rule.value_list:
            return rule.value_list[iteration % len(rule.value_list)]
        return "0"

    return "0"


def os_urandom_hex(length: int) -> str:
    import os
    return os.urandom(length).hex()


async def get_template_fields(template_id: int, version: int | None = None):
    db = await get_db()
    try:
        if version is not None:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
                (template_id, version),
            )
            if not t_rows:
                return None, None, None
            actual_version = version
        else:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM templates WHERE id = ?", (template_id,)
            )
            if not t_rows:
                return None, None, None
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

    template_name = t_rows[0]["name"]
    fields = [FieldDef(**f) for f in json.loads(t_rows[0]["fields_json"])]
    return fields, actual_version, template_name


async def get_sample_hex(sample_id: int) -> str:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT hex_data FROM samples WHERE id = ?", (sample_id,)
        )
    finally:
        await db.close()
    if not rows:
        return None
    return rows[0]["hex_data"]


async def save_sample(name: str, hex_data: str, note: str = "") -> int:
    data = hex_to_bytes(hex_data)
    byte_length = len(data)
    entropy = shannon_entropy(data)
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO samples (name, hex_data, byte_length, entropy, note) VALUES (?, ?, ?, ?, ?)",
            (name, hex_data, byte_length, entropy, note),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()
