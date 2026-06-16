import struct
import random
import os
from collections import Counter
from typing import Literal
from app.models import (
    FieldDef,
    ParseResult,
    FuzzGeneratedSample,
    FuzzStrategyStats,
    FuzzTemplateDefect,
    FuzzReport,
)
from app.parser import parse_message
from app.utils import hex_to_bytes, shannon_entropy
from app.database import get_db
import json


def _type_max_value(data_type: str) -> int:
    max_map = {
        "uint8": 0xFF,
        "uint16_be": 0xFFFF,
        "uint16_le": 0xFFFF,
        "uint32_be": 0xFFFFFFFF,
        "uint32_le": 0xFFFFFFFF,
    }
    return max_map.get(data_type, 0)


def _type_size(data_type: str) -> int | None:
    size_map = {
        "uint8": 1,
        "uint16_be": 2,
        "uint16_le": 2,
        "uint32_be": 4,
        "uint32_le": 4,
    }
    return size_map.get(data_type)


def _encode_value(value: int, data_type: str) -> bytes:
    if data_type == "uint8":
        return struct.pack(">B", value & 0xFF)
    elif data_type == "uint16_be":
        return struct.pack(">H", value & 0xFFFF)
    elif data_type == "uint16_le":
        return struct.pack("<H", value & 0xFFFF)
    elif data_type == "uint32_be":
        return struct.pack(">I", value & 0xFFFFFFFF)
    elif data_type == "uint32_le":
        return struct.pack("<I", value & 0xFFFFFFFF)
    return b""


def _generate_numeric_value(
    data_type: str,
    strategy: Literal["normal", "boundary", "malformed"],
    min_val: int | None = None,
    max_val: int | None = None,
) -> int:
    type_max = _type_max_value(data_type)

    if strategy == "normal":
        actual_min = min_val if min_val is not None else 1
        actual_max = max_val if max_val is not None else max(1, type_max - 1)
        return random.randint(actual_min, actual_max)

    elif strategy == "boundary":
        choices = [0, type_max]
        if min_val is not None:
            choices.append(min_val)
        if max_val is not None:
            choices.append(max_val)
        return random.choice(choices)

    elif strategy == "malformed":
        if random.random() < 0.5:
            return type_max + 1
        else:
            return -1


def _generate_bytes(
    length: int,
    strategy: Literal["normal", "boundary", "malformed"],
) -> bytes:
    if strategy == "normal":
        return os.urandom(max(1, length))
    elif strategy == "boundary":
        if length == 0:
            return b""
        return os.urandom(length)
    elif strategy == "malformed":
        if random.random() < 0.3:
            return b"\x00" * length
        elif random.random() < 0.3:
            return b"\xff" * length
        else:
            return os.urandom(length)


def _generate_ascii(
    length: int,
    strategy: Literal["normal", "boundary", "malformed"],
) -> bytes:
    if strategy == "normal":
        chars = bytes(random.randint(0x20, 0x7E) for _ in range(max(1, length)))
        return chars
    elif strategy == "boundary":
        if length == 0:
            return b""
        return bytes(random.randint(0x20, 0x7E) for _ in range(length))
    elif strategy == "malformed":
        if random.random() < 0.5:
            return bytes(random.randint(0x00, 0xFF) for _ in range(length))
        else:
            return b"\x00" * length


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
    if cond_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
        try:
            cond_expected = int(field_def.condition_value)
            return cond_val == cond_expected
        except ValueError:
            return False
    else:
        return str(cond_val) == field_def.condition_value


def _get_condition_expected_value(
    field_def: FieldDef,
    resolved_types: dict[str, str],
) -> object:
    if not field_def.condition_field or not field_def.condition_value:
        return None

    cond_type = resolved_types.get(field_def.condition_field, "")
    if cond_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
        try:
            return int(field_def.condition_value)
        except ValueError:
            return field_def.condition_value
    return field_def.condition_value


def _determine_field_length(
    field_def: FieldDef,
    resolved_values: dict[str, object],
    strategy: Literal["normal", "boundary", "malformed"],
    malformed_ref_override: dict[str, int] | None = None,
) -> int:
    if field_def.length_rule == "fixed":
        type_size = _type_size(field_def.data_type)
        if type_size is not None:
            return type_size
        return field_def.length_value or 0

    elif field_def.length_rule == "ref":
        ref_field = field_def.length_ref_field
        if malformed_ref_override and ref_field in malformed_ref_override:
            return malformed_ref_override[ref_field]
        ref_val = resolved_values.get(ref_field)
        if ref_val is None:
            return 0
        if isinstance(ref_val, int):
            return max(0, ref_val)
        return 0

    elif field_def.length_rule == "until":
        if strategy == "boundary":
            return random.choice([1, 64, 256])
        elif strategy == "malformed":
            return random.choice([0, 1024, 4096])
        return random.randint(4, 64)

    return 0


def _generate_field_value(
    field_def: FieldDef,
    field_len: int,
    strategy: Literal["normal", "boundary", "malformed"],
) -> tuple[bytes, object]:
    data_type = field_def.data_type

    if data_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
        if strategy == "malformed":
            if random.random() < 0.3:
                value = _generate_numeric_value(data_type, "malformed")
                encoded = _encode_value(value, data_type)
                return encoded, value & _type_max_value(data_type)
        value = _generate_numeric_value(data_type, strategy)
        encoded = _encode_value(value, data_type)
        return encoded, value

    elif data_type == "ascii":
        encoded = _generate_ascii(field_len, strategy)
        try:
            value = encoded.decode("ascii")
        except UnicodeDecodeError:
            value = encoded.hex()
        return encoded, value

    elif data_type == "bytes":
        encoded = _generate_bytes(field_len, strategy)
        return encoded, encoded.hex()

    encoded = _generate_bytes(field_len, strategy)
    return encoded, encoded.hex()


def _generate_message(
    fields: list[FieldDef],
    strategy: Literal["normal", "boundary", "malformed"],
) -> tuple[bytes, dict[str, str]]:
    resolved_values: dict[str, object] = {}
    resolved_types: dict[str, str] = {}
    generated_parts: list[bytes] = []
    malformed_ref_override: dict[str, int] = {}
    generated_notes: dict[str, str] = {}
    field_offsets: list[int] = []

    conditional_fields = [
        (i, f) for i, f in enumerate(fields)
        if f.condition_field and f.condition_value
    ]

    ref_fields = [
        f for f in fields
        if f.length_rule == "ref" and f.length_ref_field
    ]
    ref_targets = {f.length_ref_field for f in ref_fields if f.length_ref_field}

    malformed_type: str | None = None
    malformed_target_idx: int | None = None
    if strategy == "malformed" and fields:
        hard_malformed = []
        soft_malformed = []

        hard_malformed.append("empty")
        hard_malformed.append("truncate_mid")

        if ref_fields:
            hard_malformed.append("ref_overflow")
            soft_malformed.append("ref_underflow")

        if conditional_fields:
            hard_malformed.append("condition_contradiction")

        soft_malformed.append("trailing_bytes")

        if random.random() < 0.75:
            malformed_type = random.choice(hard_malformed)
        else:
            malformed_type = random.choice(soft_malformed)

        if malformed_type == "empty":
            generated_notes["_global"] = "empty message"
            return b"", generated_notes

        elif malformed_type == "truncate_mid":
            malformed_target_idx = random.randint(0, len(fields) - 1)
        elif malformed_type in ("ref_overflow", "ref_underflow") and ref_fields:
            ref_target_field = random.choice([f for f in fields if f.name in ref_targets])
            for i, f in enumerate(fields):
                if f.name == ref_target_field.name:
                    malformed_target_idx = i
                    break
        elif malformed_type == "condition_contradiction" and conditional_fields:
            malformed_target_idx = random.choice([i for i, _ in conditional_fields])
        elif malformed_type == "trailing_bytes":
            malformed_target_idx = None

    condition_satisfied_map: dict[int, bool] = {}
    for idx, f in conditional_fields:
        if strategy == "normal":
            condition_satisfied_map[idx] = random.random() < 0.5
        elif strategy == "boundary":
            condition_satisfied_map[idx] = random.choice([True, False])
        elif strategy == "malformed":
            if malformed_type == "condition_contradiction" and idx == malformed_target_idx:
                condition_satisfied_map[idx] = True
            else:
                condition_satisfied_map[idx] = random.choice([True, False])

    current_offset = 0
    for idx, field_def in enumerate(fields):
        is_conditional = field_def.condition_field and field_def.condition_value
        will_include = True

        if is_conditional:
            if strategy == "malformed" and malformed_type == "condition_contradiction" and idx == malformed_target_idx:
                will_include = True
                cond_field = field_def.condition_field
                cond_type = resolved_types.get(cond_field, "")
                expected_val = _get_condition_expected_value(field_def, resolved_types)

                if expected_val is not None and cond_field in resolved_values:
                    current_val = resolved_values[cond_field]
                    if current_val == expected_val:
                        if cond_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
                            max_val = _type_max_value(cond_type)
                            if int(expected_val) < max_val:
                                new_val = int(expected_val) + 1
                            else:
                                new_val = max(0, int(expected_val) - 1)
                            resolved_values[cond_field] = new_val
                            for i, part in enumerate(generated_parts):
                                if i == [j for j, f in enumerate(fields) if f.name == cond_field][0]:
                                    generated_parts[i] = _encode_value(new_val, cond_type)
                                    break
                        generated_notes[field_def.name] = "condition contradiction: field present but condition value does not match"
                    else:
                        if cond_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
                            resolved_values[cond_field] = int(expected_val)
                            for i, part in enumerate(generated_parts):
                                if i == [j for j, f in enumerate(fields) if f.name == cond_field][0]:
                                    generated_parts[i] = _encode_value(int(expected_val), cond_type)
                                    break
                        generated_notes[field_def.name] = "condition contradiction: field present and condition value matches (field should be absent)"
            else:
                will_include = condition_satisfied_map.get(idx, True)
                if will_include:
                    cond_field = field_def.condition_field
                    cond_type = resolved_types.get(cond_field, "")
                    expected_val = _get_condition_expected_value(field_def, resolved_types)
                    if expected_val is not None and cond_field in resolved_values:
                        if cond_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
                            resolved_values[cond_field] = int(expected_val)
                            for i, part in enumerate(generated_parts):
                                if i == [j for j, f in enumerate(fields) if f.name == cond_field][0]:
                                    generated_parts[i] = _encode_value(int(expected_val), cond_type)
                                    break
                else:
                    cond_field = field_def.condition_field
                    cond_type = resolved_types.get(cond_field, "")
                    expected_val = _get_condition_expected_value(field_def, resolved_types)
                    if expected_val is not None and cond_field in resolved_values:
                        current_val = resolved_values[cond_field]
                        if cond_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
                            max_val = _type_max_value(cond_type)
                            if int(expected_val) < max_val:
                                new_val = int(expected_val) + 1
                            else:
                                new_val = max(0, int(expected_val) - 1)
                            resolved_values[cond_field] = new_val
                            for i, part in enumerate(generated_parts):
                                if i == [j for j, f in enumerate(fields) if f.name == cond_field][0]:
                                    generated_parts[i] = _encode_value(new_val, cond_type)
                                    break
                    continue

        if not will_include:
            continue

        field_is_ref_target = field_def.name in ref_targets
        field_is_ref = field_def.length_rule == "ref" and field_def.length_ref_field

        if field_is_ref_target:
            actual_payload_len = None
            ref_field_def = None
            for f in fields[idx + 1:]:
                if f.length_rule == "ref" and f.length_ref_field == field_def.name:
                    ref_field_def = f
                    break

            if strategy == "normal":
                if ref_field_def is not None:
                    actual_payload_len = random.randint(1, min(64, _type_max_value(field_def.data_type) or 64))
                    declared_len = actual_payload_len
                    malformed_ref_override[field_def.name] = actual_payload_len
            elif strategy == "boundary":
                if ref_field_def is not None:
                    max_val = _type_max_value(field_def.data_type) or 255
                    choices = [0, 1, max_val, max(1, max_val // 2)]
                    actual_payload_len = random.choice(choices)
                    if random.random() < 0.3:
                        declared_len = actual_payload_len
                    else:
                        declared_len = min(max_val, actual_payload_len + random.randint(1, 5))
                    malformed_ref_override[field_def.name] = actual_payload_len
            elif strategy == "malformed":
                if malformed_type == "ref_overflow" and ref_field_def is not None:
                    max_val = _type_max_value(field_def.data_type) or 255
                    declared_len = max_val
                    actual_payload_len = max(0, random.randint(0, max(0, max_val - 50)))
                    malformed_ref_override[field_def.name] = actual_payload_len
                    generated_notes[field_def.name] = f"ref overflow: declared={declared_len}, actual={actual_payload_len}"
                elif malformed_type == "ref_underflow" and ref_field_def is not None:
                    max_val = _type_max_value(field_def.data_type) or 255
                    actual_payload_len = random.randint(20, min(100, max_val))
                    declared_len = max(0, actual_payload_len - random.randint(5, 15))
                    malformed_ref_override[field_def.name] = actual_payload_len
                    generated_notes[field_def.name] = f"ref underflow: declared={declared_len}, actual={actual_payload_len} (trailing bytes expected)"
                elif ref_field_def is not None:
                    max_val = _type_max_value(field_def.data_type) or 255
                    actual_payload_len = random.randint(0, min(100, max_val))
                    declared_len = actual_payload_len
                    malformed_ref_override[field_def.name] = actual_payload_len

            if ref_field_def is not None and actual_payload_len is not None:
                if field_def.data_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
                    max_val = _type_max_value(field_def.data_type)
                    declared_len = min(max(0, declared_len), max_val)
                    encoded = _encode_value(declared_len, field_def.data_type)
                    field_offsets.append(current_offset)
                    generated_parts.append(encoded)
                    resolved_values[field_def.name] = declared_len
                    resolved_types[field_def.name] = field_def.data_type
                    current_offset += len(encoded)
                    continue

        field_len = _determine_field_length(
            field_def, resolved_values, strategy, malformed_ref_override
        )

        if strategy == "boundary" and field_def.length_rule in ("fixed", "ref"):
            if field_def.data_type == "bytes" or field_def.data_type == "ascii":
                if random.random() < 0.3:
                    field_len = 0
                elif random.random() < 0.3:
                    field_len = min(field_len, 1024) if field_len > 0 else 256

        encoded, value = _generate_field_value(field_def, field_len, strategy)

        if strategy == "malformed" and malformed_type == "truncate_mid" and idx == malformed_target_idx:
            truncate_at = random.randint(0, max(0, len(encoded) - 1))
            if truncate_at == 0:
                encoded = b""
                generated_notes["_global"] = f"truncated before field '{field_def.name}' (0 bytes available)"
            else:
                encoded = encoded[:truncate_at]
                generated_notes["_global"] = f"truncated inside field '{field_def.name}' ({truncate_at}/{field_len} bytes)"
            field_offsets.append(current_offset)
            generated_parts.append(encoded)
            final_bytes = b"".join(generated_parts)
            return final_bytes, generated_notes

        field_offsets.append(current_offset)
        generated_parts.append(encoded)
        resolved_values[field_def.name] = value
        resolved_types[field_def.name] = field_def.data_type
        current_offset += len(encoded)

    final_bytes = b"".join(generated_parts)

    if strategy == "malformed" and malformed_type == "trailing_bytes":
        extra = random.randint(1, 50)
        final_bytes = final_bytes + os.urandom(extra)
        generated_notes["_global"] = f"extra trailing bytes (+{extra} bytes)"

    return final_bytes, generated_notes


async def _save_sample(
    db,
    name: str,
    hex_data: str,
    strategy: str,
    notes: dict[str, str],
) -> int:
    data = hex_to_bytes(hex_data)
    byte_length = len(data)
    entropy = shannon_entropy(data)

    note_parts = [f"fuzz_strategy={strategy}"]
    for k, v in notes.items():
        if k != "_global":
            note_parts.append(f"{k}: {v}")
    if "_global" in notes:
        note_parts.append(notes["_global"])
    note = "; ".join(note_parts)

    cursor = await db.execute(
        "INSERT INTO samples (name, hex_data, byte_length, entropy, note) VALUES (?, ?, ?, ?, ?)",
        (name, hex_data, byte_length, entropy, note),
    )
    return cursor.lastrowid


async def _get_template_info(template_id: int, version: int | None = None):
    db = await get_db()
    try:
        if version is not None:
            t_rows = await db.execute_fetchall(
                "SELECT tv.*, t.name as template_name FROM template_versions tv JOIN templates t ON tv.template_id = t.id WHERE tv.template_id = ? AND tv.version = ?",
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

            tv_rows = await db.execute_fetchall(
                "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
                (template_id, actual_version),
            )
            t_rows = tv_rows
    finally:
        await db.close()

    template_name = t_rows[0]["name"]
    fields = [FieldDef(**f) for f in json.loads(t_rows[0]["fields_json"])]
    return fields, actual_version, template_name


async def generate_and_validate(
    template_id: int,
    count: int,
    strategy_distribution: dict[str, float] | None = None,
    template_version: int | None = None,
) -> FuzzReport:
    if count > 100:
        count = 100

    if strategy_distribution is None:
        strategy_distribution = {
            "normal": 0.4,
            "boundary": 0.3,
            "malformed": 0.3,
        }

    total = sum(strategy_distribution.values())
    if abs(total - 1.0) > 0.01:
        raise ValueError("strategy_distribution must sum to 1.0")

    fields, actual_version, template_name = await _get_template_info(template_id, template_version)
    if fields is None:
        raise ValueError("template not found")

    strategies: list[Literal["normal", "boundary", "malformed"]] = []
    for strategy, weight in strategy_distribution.items():
        num = max(1, int(round(count * weight)))
        strategies.extend([strategy] * num)

    while len(strategies) > count:
        strategies.pop()
    while len(strategies) < count:
        strategies.append("normal")

    random.shuffle(strategies)

    db = await get_db()
    try:
        generated_samples: list[FuzzGeneratedSample] = []
        parse_results: list[tuple[str, ParseResult, str]] = []

        for i, strategy in enumerate(strategies):
            msg_bytes, notes = _generate_message(fields, strategy)
            hex_data = msg_bytes.hex()
            name = f"[fuzz] {template_name}-{strategy}-{i + 1:03d}"

            sample_id = await _save_sample(db, name, hex_data, strategy, notes)

            parse_result = parse_message(
                msg_bytes, fields, template_id, sample_id, actual_version
            )

            sample = FuzzGeneratedSample(
                sample_id=sample_id,
                name=name,
                hex_data=hex_data,
                strategy=strategy,
                parse_result=parse_result,
            )
            generated_samples.append(sample)
            parse_results.append((strategy, parse_result, hex_data))

        await db.commit()

        strategy_stats_map: dict[str, dict] = {}
        all_results: list[ParseResult] = []
        field_errors: Counter = Counter()
        template_defects: list[FuzzTemplateDefect] = []

        for strategy in ["normal", "boundary", "malformed"]:
            strategy_results = [
                (pr, hex_data)
                for s, pr, hex_data in parse_results
                if s == strategy
            ]
            if not strategy_results:
                continue

            total_strategy = len(strategy_results)
            success_count = sum(
                1 for pr, _ in strategy_results
                if all(f.status != "parse_error" for f in pr.fields)
            )
            coverages = [pr.coverage_percent for pr, _ in strategy_results]

            strategy_stats_map[strategy] = {
                "strategy": strategy,
                "total": total_strategy,
                "success_count": success_count,
                "success_rate": round(success_count / total_strategy * 100, 2),
                "avg_coverage": round(sum(coverages) / total_strategy, 2),
                "min_coverage": round(min(coverages), 2),
                "max_coverage": round(max(coverages), 2),
            }

            for pr, hex_data in strategy_results:
                all_results.append(pr)
                for f in pr.fields:
                    if f.status == "parse_error":
                        field_errors[f.name] += 1

                if strategy == "normal":
                    sample = next(
                        s for s in generated_samples
                        if s.sample_id == pr.sample_id
                    )

                    error_fields = [f for f in pr.fields if f.status == "parse_error"]
                    for ef in error_fields:
                        template_defects.append(
                            FuzzTemplateDefect(
                                sample_name=sample.name,
                                sample_id=sample.sample_id,
                                field_name=ef.name,
                                error=ef.error or "",
                                hex_data=hex_data,
                            )
                        )

                    if pr.coverage_percent < 100.0:
                        uncovered_desc = ", ".join(
                            f"[{r[0]}-{r[1]}]" for r in pr.uncovered_ranges
                        ) if pr.uncovered_ranges else "unknown"
                        template_defects.append(
                            FuzzTemplateDefect(
                                sample_name=sample.name,
                                sample_id=sample.sample_id,
                                field_name="_coverage",
                                error=f"coverage only {pr.coverage_percent:.1f}% (uncovered ranges: {uncovered_desc})",
                                hex_data=hex_data,
                            )
                        )

        strategy_stats = [
            FuzzStrategyStats(**stats)
            for stats in strategy_stats_map.values()
        ]

        all_coverages = [pr.coverage_percent for pr in all_results] if all_results else [0]
        coverage_overview = {
            "min": round(min(all_coverages), 2),
            "max": round(max(all_coverages), 2),
            "avg": round(sum(all_coverages) / len(all_coverages), 2) if all_coverages else 0,
        }

        ranking = [
            {"field_name": name, "error_count": count}
            for name, count in field_errors.most_common()
        ]

        return FuzzReport(
            template_id=template_id,
            template_version=actual_version,
            template_name=template_name,
            total_generated=len(generated_samples),
            strategy_stats=strategy_stats,
            field_error_ranking=ranking,
            coverage_overview=coverage_overview,
            template_defects=template_defects,
            samples=generated_samples,
        )
    finally:
        await db.close()
