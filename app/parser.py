import struct
from app.models import FieldDef, ParsedField, ParseResult


def _decode_value(data: bytes, data_type: str) -> str:
    if data_type == "uint8":
        return str(data[0])
    elif data_type == "uint16_be":
        return str(struct.unpack(">H", data)[0])
    elif data_type == "uint16_le":
        return str(struct.unpack("<H", data)[0])
    elif data_type == "uint32_be":
        return str(struct.unpack(">I", data)[0])
    elif data_type == "uint32_le":
        return str(struct.unpack("<I", data)[0])
    elif data_type == "ascii":
        try:
            return data.decode("ascii")
        except UnicodeDecodeError:
            return data.hex()
    elif data_type == "bytes":
        return data.hex()
    else:
        return data.hex()


def _type_size(data_type: str) -> int | None:
    size_map = {
        "uint8": 1,
        "uint16_be": 2,
        "uint16_le": 2,
        "uint32_be": 4,
        "uint32_le": 4,
    }
    return size_map.get(data_type)


def parse_message(
    raw: bytes, fields: list[FieldDef], template_id: int, sample_id: int, template_version: int = 1
) -> ParseResult:
    offset = 0
    total_len = len(raw)
    parsed_fields: list[ParsedField] = []
    resolved_values: dict[str, object] = {}
    resolved_types: dict[str, str] = {}
    covered: list[tuple[int, int]] = []

    for field_def in fields:
        if field_def.condition_field and field_def.condition_value:
            cond_val = resolved_values.get(field_def.condition_field)
            cond_type = resolved_types.get(field_def.condition_field, "")
            if cond_val is None:
                parsed_fields.append(
                    ParsedField(
                        name=field_def.name,
                        hex="",
                        offset=offset,
                        length=0,
                        status="skipped",
                        error=f"condition_field '{field_def.condition_field}' not yet resolved",
                    )
                )
                continue

            if cond_type in ("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le"):
                try:
                    cond_expected = int(field_def.condition_value)
                except ValueError:
                    parsed_fields.append(
                        ParsedField(
                            name=field_def.name,
                            hex="",
                            offset=offset,
                            length=0,
                            status="skipped",
                            error=f"condition_value '{field_def.condition_value}' is not a valid integer",
                        )
                    )
                    continue
                if cond_val != cond_expected:
                    continue
            else:
                cond_str = str(cond_val)
                if cond_str != field_def.condition_value:
                    continue

        field_len: int | None = None
        if field_def.length_rule == "fixed":
            type_size = _type_size(field_def.data_type)
            if type_size is not None:
                field_len = type_size
            else:
                field_len = field_def.length_value
        elif field_def.length_rule == "ref":
            ref_val = resolved_values.get(field_def.length_ref_field)
            if ref_val is None:
                parsed_fields.append(
                    ParsedField(
                        name=field_def.name,
                        hex="",
                        offset=offset,
                        length=0,
                        status="parse_error",
                        error=f"length_ref_field '{field_def.length_ref_field}' not resolved",
                    )
                )
                continue
            field_len = ref_val
        elif field_def.length_rule == "until":
            until_byte_val: int | None = None
            try:
                until_byte_val = int(field_def.until_byte, 16)
            except (ValueError, TypeError):
                parsed_fields.append(
                    ParsedField(
                        name=field_def.name,
                        hex="",
                        offset=offset,
                        length=0,
                        status="parse_error",
                        error=f"invalid until_byte '{field_def.until_byte}'",
                    )
                )
                continue

            end_idx = offset
            found = False
            while end_idx < total_len:
                if raw[end_idx] == until_byte_val:
                    found = True
                    break
                end_idx += 1

            if not found:
                parsed_fields.append(
                    ParsedField(
                        name=field_def.name,
                        hex="",
                        offset=offset,
                        length=0,
                        status="parse_error",
                        error=f"terminator byte '{field_def.until_byte}' not found",
                    )
                )
                continue
            field_len = end_idx - offset + 1

        if field_len is None or field_len <= 0:
            parsed_fields.append(
                ParsedField(
                    name=field_def.name,
                    hex="",
                    offset=offset,
                    length=0,
                    status="parse_error",
                    error="could not determine field length",
                )
            )
            continue

        if offset + field_len > total_len:
            available = total_len - offset
            partial_hex = raw[offset:total_len].hex() if available > 0 else ""
            parsed_fields.append(
                ParsedField(
                    name=field_def.name,
                    hex=partial_hex,
                    offset=offset,
                    length=field_len,
                    status="parse_error",
                    error=f"field extends beyond message boundary (need {field_len} bytes, {available} available)",
                )
            )
            if available > 0:
                covered.append((offset, total_len - 1))
            offset = total_len
            continue

        field_bytes = raw[offset : offset + field_len]
        hex_str = field_bytes.hex()

        try:
            value = _decode_value(field_bytes, field_def.data_type)
            parsed_fields.append(
                ParsedField(
                    name=field_def.name,
                    hex=hex_str,
                    value=value,
                    offset=offset,
                    length=field_len,
                    status="ok",
                )
            )
            covered.append((offset, offset + field_len - 1))

            if field_def.data_type in (
                "uint8",
                "uint16_be",
                "uint16_le",
                "uint32_be",
                "uint32_le",
            ):
                resolved_values[field_def.name] = int(value)
            elif field_def.data_type == "ascii":
                resolved_values[field_def.name] = value
            elif field_def.data_type == "bytes":
                resolved_values[field_def.name] = value
            resolved_types[field_def.name] = field_def.data_type

        except Exception as e:
            parsed_fields.append(
                ParsedField(
                    name=field_def.name,
                    hex=hex_str,
                    offset=offset,
                    length=field_len,
                    status="parse_error",
                    error=str(e),
                )
            )
            covered.append((offset, offset + field_len - 1))

        offset += field_len

    covered_bytes = sum(end - start + 1 for start, end in covered)
    coverage_percent = round((covered_bytes / total_len * 100) if total_len > 0 else 0, 2)

    uncovered_ranges = _compute_uncovered(covered, total_len)

    return ParseResult(
        template_id=template_id,
        sample_id=sample_id,
        template_version=template_version,
        fields=parsed_fields,
        coverage_percent=coverage_percent,
        covered_bytes=covered_bytes,
        total_bytes=total_len,
        uncovered_ranges=uncovered_ranges,
    )


def _compute_uncovered(
    covered: list[tuple[int, int]], total_len: int
) -> list[list[int]]:
    if not covered or total_len == 0:
        if total_len > 0:
            return [[0, total_len - 1]]
        return []

    sorted_covered = sorted(covered)
    merged = [sorted_covered[0]]
    for start, end in sorted_covered[1:]:
        if start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    uncovered = []
    prev_end = -1
    for start, end in merged:
        if start > prev_end + 1:
            uncovered.append([prev_end + 1, start - 1])
        prev_end = end
    if prev_end < total_len - 1:
        uncovered.append([prev_end + 1, total_len - 1])

    return uncovered
