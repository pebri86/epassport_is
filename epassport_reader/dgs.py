"""Parsers for the ICAO 9303 Logical Data Structure (LDS) data groups.

Turn the raw EF bytes retrieved from the passport into readable structures:

* DG1  -> the machine readable zone (MRZ), fully decoded
* DG2  -> the face portrait (ISO 19794-5 template or raw JPEG)
* DG7  -> the displayed signature image
* DG11/DG12/DG13 -> additional personal / document / optional details
* EF.COM -> the data-group tag list
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .tlvs import field_name, parse_tlvs, read_der_tlv

# ---------------------------------------------------------------------------
# generic helpers
# ---------------------------------------------------------------------------


def _clean_text(raw: bytes) -> str:
    """Decode bytes to a printable string, replacing '<' with spaces."""
    text = raw.decode("latin-1", errors="replace")
    out = []
    for ch in text:
        if ch == "<":
            out.append(" ")
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append(" ")
    return "".join(out).strip()


def _unwrap_outer(data: bytes, expected_tag: int) -> bytes:
    """Strip the outer LDS tag (e.g. 0x61 for DG1) and return its value."""
    if len(data) >= 2 and data[0] == expected_tag:
        try:
            tag, start, end = read_der_tlv(data, 0)
            if tag == expected_tag:
                return data[start:end]
        except ValueError:
            pass
    return data


def _unwrap_single_tlv(content: bytes) -> bytes:
    """If ``content`` is exactly one TLV whose value fills it, return the value.

    Used for the DG1 that wraps the MRZ in a 0x5F1F object.
    """
    if len(content) < 4:
        return content
    try:
        tag, start, end = read_der_tlv(content, 0)
        if end == len(content):
            return content[start:end]
    except ValueError:
        pass
    return content


def _find_nested(data: bytes, wanted_tag: int, depth: int = 0) -> Optional[bytes]:
    """Recursively search nested TLVs for ``wanted_tag`` and return its value.

    Best-effort: subtrees that fail to parse (e.g. embedded binary image
    data) are skipped rather than raising.
    """
    if depth > 6:
        return None
    try:
        items = parse_tlvs(data)
    except ValueError:
        return None
    for tag, value in items:
        if tag == wanted_tag:
            return value
        if depth < 6:
            found = _find_nested(value, wanted_tag, depth + 1)
            if found is not None:
                return found
    return None


# ---------------------------------------------------------------------------
# image extraction
# ---------------------------------------------------------------------------


def extract_image_bytes(content: bytes) -> Tuple[Optional[bytes], Optional[str]]:
    """Locate the embedded portrait/signature image inside a DG value.

    Scans for a JPEG (``FF D8`` .. ``FF D9``) or a JPEG 2000 codestream
    (``FF 4F`` .. ``FF D9``).  Returns ``(image_bytes, format)``.
    """
    # JPEG SOI -> EOI
    idx = content.find(b"\xff\xd8")
    if idx != -1:
        end = content.find(b"\xff\xd9", idx)
        if end != -1:
            return content[idx : end + 2], "JPEG"
    # JPEG 2000 codestream SOC -> EOC
    idx = content.find(b"\xff\x4f")
    if idx != -1:
        end = content.find(b"\xff\xd9", idx)
        if end != -1:
            return content[idx : end + 2], "JPEG2000"
    # JPEG 2000 file format (jp2) signature box
    idx = content.find(b"\x00\x00\x00\x0cjP  \r\n\x87\n")
    if idx != -1:
        return content[idx:], "JPEG2000"
    return None, None


# ---------------------------------------------------------------------------
# MRZ parsing
# ---------------------------------------------------------------------------


def format_yymmdd(value: str) -> str:
    """Turn YYMMDD into YYYY-MM-DD (ICAO century heuristic)."""
    if len(value) != 6 or not value.isdigit():
        return value
    yy = int(value[:2])
    year = 1900 + yy if yy >= 70 else 2000 + yy
    return f"{year}-{value[2:4]}-{value[4:6]}"


def parse_mrz(lines: str) -> Dict[str, str]:
    """Decode a TD3 MRZ (two 44-char lines) into labelled fields."""
    text = lines.replace(" ", "<")
    if len(text) < 88:
        text = text.ljust(88, "<")
    text = text[:88]
    line1 = text[:44]
    line2 = text[44:88]

    doc_type = line1[0]
    issuing_state = line1[1:4]
    # Some sample data may place the issuing state at 2-4 instead of
    # 1-3 (leaving index 1 as the '<' filler); recover it if it looks odd.
    if issuing_state.startswith("<"):
        alt = line1[2:5]
        if alt.isalpha():
            issuing_state = alt
    name_field = line1[5:44]

    surname, _, given_field = name_field.partition("<<")
    given_names = " ".join(
        part.replace("<", " ") for part in given_field.split("<") if part.strip()
    )

    doc_number = line2[0:9].replace("<", "")
    doc_number_ck = line2[9]
    nationality = line2[10:13].replace("<", "")
    dob = line2[13:19]
    dob_ck = line2[19]
    sex = line2[20]
    expiry = line2[21:27]
    expiry_ck = line2[27]
    personal_number = line2[28:43].replace("<", "")
    composite_ck = line2[43]

    return {
        "document_type": doc_type,
        "issuing_state": issuing_state,
        "surname": surname.replace("<", " ").strip(),
        "given_names": given_names,
        "document_number": doc_number,
        "document_number_check": doc_number_ck,
        "nationality": nationality,
        "date_of_birth": format_yymmdd(dob),
        "date_of_birth_check": dob_ck,
        "sex": sex,
        "date_of_expiry": format_yymmdd(expiry),
        "date_of_expiry_check": expiry_ck,
        "personal_number": personal_number,
        "composite_check": composite_ck,
        "line1": line1.replace("<", " "),
        "line2": line2.replace("<", " "),
    }


def parse_dg1(data: bytes) -> Dict[str, str]:
    """Parse the raw EF.DG1 bytes into decoded MRZ fields."""
    content = _unwrap_outer(data, 0x61)
    content = _unwrap_single_tlv(content)
    mrz = content.decode("ascii", errors="replace")
    return parse_mrz(mrz)


# ---------------------------------------------------------------------------
# DG2 / DG7 images
# ---------------------------------------------------------------------------


def parse_dg2(data: bytes) -> Dict:
    content = _unwrap_outer(data, 0x75)
    image_bytes, image_format = extract_image_bytes(content)
    info = {
        "tag": "DG2",
        "name": "Biometric data (face)",
        "size": len(data),
        "image_bytes": image_bytes,
        "image_format": image_format,
    }
    # ISO 19794-5 metadata (if present; the face image info 0x5F2E is often
    # nested inside the 0x7F60 facial-record template)
    if content[:2] == b"\x7f\x61":
        face_record = _unwrap_single_tlv(content)
        face_info = _find_nested(face_record, 0x5F2E)
        if face_info is not None:
            info["metadata"] = _parse_face_image_info(face_info)
    return info


def parse_dg7(data: bytes) -> Dict:
    content = _unwrap_outer(data, 0x67)
    image_bytes, image_format = extract_image_bytes(content)
    return {
        "tag": "DG7",
        "name": "Displayed signature",
        "size": len(data),
        "image_bytes": image_bytes,
        "image_format": image_format,
    }


def _parse_face_image_info(value: bytes) -> Dict[str, str]:
    """Best-effort decode of the ISO 19794-5 face image information block.

    The real image dimensions are read by Pillow in the GUI, so only the
    format identifier, version and detected image codec are reported here.
    """
    meta: Dict[str, str] = {}
    if len(value) >= 7 and value[:3] == b"FAC":
        meta["format"] = "ISO 19794-5"
        meta["version"] = value[4:7].decode("latin-1", errors="replace")
    if b"\xff\xd8" in value:
        meta["image_type"] = "JPEG"
    elif b"\xff\x4f" in value:
        meta["image_type"] = "JPEG2000"
    elif len(value) >= 3:
        image_type = value[23:26]
        type_map = {
            b"\x00\x00\x00": "JPEG",
            b"\x00\x00\x01": "JPEG2000",
            b"\x00\x00\x02": "WSQ",
            b"\x00\x00\x03": "JPEG-LS",
        }
        meta["image_type"] = type_map.get(image_type, image_type.hex())
    return meta


# ---------------------------------------------------------------------------
# DG11 / DG12 / DG13 (text tables) and EF.COM
# ---------------------------------------------------------------------------


def parse_text_dg(data: bytes, expected_tag: int) -> List[Dict]:
    """Parse a generic text data group into a list of field records."""
    content = _unwrap_outer(data, expected_tag)
    fields: List[Dict] = []
    for tag, value in parse_tlvs(content):
        if tag == 0x5C:
            continue  # tag list - informational only
        fields.append(
            {
                "tag": f"{tag:04X}",
                "name": field_name(tag),
                "value": _clean_text(value),
            }
        )
    return fields


def parse_com(data: bytes) -> Dict:
    """Parse EF.COM into a dict with the tag list and LDS versions."""
    content = _unwrap_outer(data, 0x60)
    result: Dict[str, object] = {
        "tag_list": [],
        "lds_version": None,
        "unicode_version": None,
    }
    for tag, value in parse_tlvs(content):
        if tag == 0x5C:
            result["tag_list"] = list(value)
        elif tag == 0x5F01:
            result["lds_version"] = _clean_text(value)
        elif tag == 0x5F36:
            result["unicode_version"] = _clean_text(value)
    return result
