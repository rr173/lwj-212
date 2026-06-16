from app.utils import validate_hex, hex_to_bytes
from app.models import FingerprintCreate, RecognizedTemplate


MAX_FINGERPRINTS_PER_TEMPLATE = 10


def validate_fingerprint(fp: FingerprintCreate) -> None:
    if fp.offset < 0:
        raise ValueError("offset must be non-negative")

    expected_clean = validate_hex(fp.expected_hex)
    if not expected_clean:
        raise ValueError("expected_hex cannot be empty")

    if fp.match_type not in ("exact", "mask"):
        raise ValueError("match_type must be 'exact' or 'mask'")

    if fp.match_type == "mask":
        if not fp.mask_hex:
            raise ValueError("mask_hex is required for mask match_type")
        mask_clean = validate_hex(fp.mask_hex)
        if len(mask_clean) != len(expected_clean):
            raise ValueError("mask_hex length must match expected_hex length")


def match_single_fingerprint(data: bytes, offset: int, expected_hex: str,
                             match_type: str, mask_hex: str | None) -> bool:
    expected = bytes.fromhex(expected_hex)
    expected_len = len(expected)

    if offset + expected_len > len(data):
        return False

    actual = data[offset:offset + expected_len]

    if match_type == "exact":
        return actual == expected
    elif match_type == "mask":
        mask = bytes.fromhex(mask_hex)
        masked_actual = bytes(a & m for a, m in zip(actual, mask))
        return masked_actual == expected

    return False


def match_template_fingerprints(data: bytes, fingerprints: list[dict]) -> tuple[int, bool]:
    matched = 0
    total = len(fingerprints)

    for fp in fingerprints:
        if match_single_fingerprint(
            data,
            fp["offset"],
            fp["expected_hex"],
            fp["match_type"],
            fp.get("mask_hex"),
        ):
            matched += 1

    is_full_match = (matched == total and total > 0)
    return matched, is_full_match


def sort_recognized_templates(templates: list[RecognizedTemplate]) -> list[RecognizedTemplate]:
    full_matches = [t for t in templates if t.is_full_match]
    partial_matches = [t for t in templates if not t.is_full_match]

    full_matches.sort(key=lambda x: (-x.total_rules, -x.matched_rules, x.template_id))
    partial_matches.sort(key=lambda x: (-x.matched_rules, -x.total_rules, x.template_id))

    if len(full_matches) == 1:
        full_matches[0].confidence = 100

    return full_matches + partial_matches
