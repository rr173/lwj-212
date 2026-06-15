import math
from collections import Counter


def validate_hex(hex_str: str) -> str:
    cleaned = hex_str.strip().lower()
    if not cleaned:
        raise ValueError("hex string is empty")
    if len(cleaned) % 2 != 0:
        raise ValueError("hex string has odd length")
    if not all(c in "0123456789abcdef" for c in cleaned):
        raise ValueError("hex string contains invalid characters")
    return cleaned


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()
