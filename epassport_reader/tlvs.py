"""BER-TLV helpers and ICAO Doc 9303 tag names.

Provides a small, self-contained DER/BER TLV parser (multi-byte tags and
long-form lengths) plus lookup tables mapping the ICAO 9303 tag numbers used
by the Logical Data Structure to human readable names.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# TLV encoding / decoding
# ---------------------------------------------------------------------------


def _read_ber_tag(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a BER tag (supports the multi-byte 0x1F form). Returns (tag, off)."""
    if offset >= len(data):
        raise ValueError("truncated BER tag")
    b = data[offset]
    offset += 1
    tag = b
    if (b & 0x1F) == 0x1F:
        while offset < len(data):
            b2 = data[offset]
            offset += 1
            tag = (tag << 8) | b2
            if not (b2 & 0x80):
                break
    return tag, offset


def _value_end(data: bytes, offset: int) -> Tuple[int, int]:
    """Given ``offset`` at the length byte, return ``(value_start, value_end)``.

    Supports definite lengths and BER **indefinite** lengths (0x80 ... EOC).
    Indefinite-length constructs are common in real ICAO CMS SODs, so the
    reader accepts them rather than failing with a strict-DER error.
    """
    if offset >= len(data):
        raise ValueError("missing length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return offset, offset + first
    if first == 0x80:
        i = offset
        while i + 1 < len(data):
            if data[i] == 0x00 and data[i + 1] == 0x00:
                return offset, i + 2
            try:
                _t, _s, _e = read_der_tlv(data, i)
            except ValueError:
                break
            i = _e
        return offset, len(data)
    count = first & 0x7F
    if count > 4 or offset + count > len(data):
        raise ValueError("truncated long-form length")
    length = int.from_bytes(data[offset : offset + count], "big")
    value_start = offset + count
    return value_start, value_start + length


def read_der_tlv(data: bytes, offset: int = 0) -> Tuple[int, int, int]:
    """Read one (tag, value_start, value_end) TLV from ``data`` at ``offset``.

    For indefinite-length values ``value_end`` is just past the EOC, so the
    value slice ``data[value_start:value_end]`` includes the trailing ``00 00``
    terminator (which parses back as an empty 0x00 child and is ignored by
    callers).
    """
    tag, offset = _read_ber_tag(data, offset)
    start, end = _value_end(data, offset)
    if end > len(data):
        raise ValueError("TLV value extends beyond buffer")
    return tag, start, end


def parse_tlvs(data: bytes) -> List[Tuple[int, bytes]]:
    """Parse a sequence of concatenated TLVs into a list of (tag, value)."""
    out: List[Tuple[int, bytes]] = []
    i = 0
    while i < len(data):
        tag, start, end = read_der_tlv(data, i)
        out.append((tag, data[start:end]))
        i = end
    return out


def tlv(tag: int, value: bytes) -> bytes:
    """Encode a TLV with minimal (short or long form) length bytes."""
    if tag <= 0xFF:
        tag_bytes = bytes([tag])
    else:
        tag_bytes = tag.to_bytes((tag.bit_length() + 7) // 8, "big")
    n = len(value)
    if n < 0x80:
        return tag_bytes + bytes([n]) + value
    if n <= 0xFF:
        return tag_bytes + bytes([0x81, n]) + value
    return tag_bytes + bytes([0x82, (n >> 8) & 0xFF, n & 0xFF]) + value


def find_first(data: bytes, wanted: int) -> Optional[bytes]:
    """Return the value of the first TLV with the given tag (or None)."""
    for tag, value in parse_tlvs(data):
        if tag == wanted:
            return value
    return None


def parse_fci_size(fci: bytes) -> Optional[int]:
    """Extract the EF size from an FCI (0x6F) / FCP (0x62) SELECT response.

    The size lives in the proprietary data tag 0x80 inside 0x6F/0x62/0x64.
    """
    for outer_tag, outer_value in parse_tlvs(fci):
        if outer_tag in (0x6F, 0x62, 0x64, 0x61):
            size = find_first(outer_value, 0x80)
            if size is not None and len(size) >= 1:
                return int.from_bytes(size, "big")
    # fall back to a top level 0x80
    size = find_first(fci, 0x80)
    if size is not None and len(size) >= 1:
        return int.from_bytes(size, "big")
    return None


# ---------------------------------------------------------------------------
# ICAO Doc 9303 tag -> name tables
# ---------------------------------------------------------------------------

DATA_GROUP_TAGS: Dict[int, Tuple[str, str]] = {
    0x60: ("EF.COM", "COM"),
    0x61: ("DG1", "MRZ data"),
    0x75: ("DG2", "Biometric data (face)"),
    0x63: ("DG3", "Biometric data (fingerprint)"),
    0x76: ("DG4", "Biometric data (iris)"),
    0x65: ("DG5", "Displayed portrait"),
    0x66: ("DG6", "Reserved for future use"),
    0x67: ("DG7", "Displayed signature"),
    0x68: ("DG8", "Data features"),
    0x69: ("DG9", "Structure features"),
    0x6A: ("DG10", "Substance features"),
    0x6B: ("DG11", "Additional personal detail"),
    0x6C: ("DG12", "Additional document detail"),
    0x6D: ("DG13", "Optional detail"),
    0x6E: ("DG14", "Security options (RFU)"),
    0x6F: ("DG15", "Active authentication public key"),
    0x77: ("SOD", "Document security object"),
}

DATA_GROUP_TAG_TO_FID: Dict[int, int] = {
    0x61: 0x0101,
    0x75: 0x0102,
    0x63: 0x0103,
    0x76: 0x0104,
    0x65: 0x0105,
    0x66: 0x0106,
    0x67: 0x0107,
    0x68: 0x0108,
    0x69: 0x0109,
    0x6A: 0x010A,
    0x6B: 0x010B,
    0x6C: 0x010C,
    0x6D: 0x010D,
    0x6E: 0x010E,
    0x6F: 0x010F,
    0x77: 0x011D,
    0x60: 0x011E,
}

# LDS tag -> ICAO data-group number (1..15) as used by EF.SOD hash values
DATA_GROUP_TAG_TO_NUM: Dict[int, int] = {
    0x61: 1,
    0x75: 2,
    0x63: 3,
    0x76: 4,
    0x65: 5,
    0x66: 6,
    0x67: 7,
    0x68: 8,
    0x69: 9,
    0x6A: 10,
    0x6B: 11,
    0x6C: 12,
    0x6D: 13,
    0x6E: 14,
    0x6F: 15,
}

# Field tags inside the data groups (ICAO 9303 Part 3, 6.4.x)
FIELD_TAG_NAMES: Dict[int, str] = {
    0x02: "Version",
    0x5C: "Tag list",
    0x5F01: "LDS version",
    0x5F0E: "Full name of holder",
    0x5F0F: "Personal number",
    0x5F10: "Sex",
    0x5F11: "Other name",
    0x5F16: "Other ID number",
    0x5F17: "Other ID number (add.)",
    0x5F19: "Issuing authority",
    0x5F1B: "Personal summary",
    0x5F1E: "Profession",
    0x5F1F: "Additional personal detail",
    0x5F20: "Telephone number",
    0x5F21: "Title",
    0x5F22: "Personal data (custom)",
    0x5F23: "Date of issue",
    0x5F24: "Date of expiry",
    0x5F25: "Issuing authority",
    0x5F26: "Other information",
    0x5F27: "Endorsements",
    0x5F28: "Issuing state / organization",
    0x5F29: "Document type",
    0x5F2A: "Document number",
    0x5F2B: "Father's name",
    0x5F2C: "Mother's name",
    0x5F2D: "Other names",
    0x5F2E: "Face image information",
    0x5F36: "Unicode version",
    0x5F43: "Image of signature",
    0x5F57: "Additional detail",
    0x7F61: "Face image record",
    0x7F60: "Facial record data",
    0x7F4E: "CVC body",
    0x7F49: "Public key",
    0x7F4C: "Authorization",
}

# Data groups that carry human-readable text tables (generic TLV display)
TEXT_DG_TAGS = (0x6B, 0x6C, 0x6D, 0x68, 0x69, 0x6A)


def data_group_name(tag: int) -> str:
    entry = DATA_GROUP_TAGS.get(tag)
    if entry:
        return f"{entry[0]} - {entry[1]}"
    return f"Tag {tag:02X}"


def field_name(tag: int) -> str:
    return FIELD_TAG_NAMES.get(tag, f"Tag {tag:02X}")
