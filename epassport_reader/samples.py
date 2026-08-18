"""Load the repository's ``test_data/*.bin`` files as a demo ``PassportData``.

This lets the GUI run without a card reader so the DG parsers and the
JMRTD-style display can be exercised offline.  The files are the
LDS1 data groups shipped in ``test_data/``.
"""

from __future__ import annotations

import os
from typing import Dict, Optional

from .dgs import parse_com, parse_dg1, parse_dg2, parse_dg7, parse_text_dg
from .pa import parse_sod, verify_pa
from .reader import PassportData
from .tlvs import DATA_GROUP_TAG_TO_NUM

DEFAULT_DIR = os.path.join(os.path.dirname(__file__), "..", "test_data")

_SAMPLE_MAP: Dict[int, str] = {
    0x61: "Datagroup1.bin",
    0x75: "Datagroup2.bin",
    0x67: "Datagroup7.bin",
    0x6B: "Datagroup11.bin",
    0x6C: "Datagroup12.bin",
    0x60: "EF_COM.bin",
    0x77: "EF_SOD.bin",
}


def load_sample_data(directory: Optional[str] = None) -> PassportData:
    """Build a ``PassportData`` from the bundled ``test_data`` files."""
    base = os.path.abspath(directory or DEFAULT_DIR)
    pd = PassportData()
    pd.protocol = "sample"
    pd.atr = b""

    for tag, filename in _SAMPLE_MAP.items():
        path = os.path.join(base, filename)
        if not os.path.exists(path):
            pd.errors.append(f"missing sample file {filename}")
            continue
        with open(path, "rb") as fh:
            pd.raw[tag] = fh.read()

    if 0x60 in pd.raw:
        pd.com = parse_com(pd.raw[0x60])
        pd.tag_list = pd.com.get("tag_list", [])

    if 0x61 in pd.raw:
        pd.dg1 = parse_dg1(pd.raw[0x61])
    if 0x75 in pd.raw:
        pd.dg2 = parse_dg2(pd.raw[0x75])
    if 0x67 in pd.raw:
        pd.dg7 = parse_dg7(pd.raw[0x67])
    for tag in (0x6B, 0x6C, 0x6D):
        if tag in pd.raw:
            pd.text_dgs[tag] = parse_text_dg(pd.raw[tag], tag)

    if 0x77 in pd.raw:
        pd.sod_info = parse_sod(pd.raw[0x77])
        if pd.sod_info.get("parse_error"):
            pd.sod_info["parse_error"] = (
                "The bundled test_data/EF_SOD.bin is a truncated placeholder "
                "(not a valid CMS SignedData), so Passive Authentication is "
                "unavailable in the offline demo. Use a real or personalized "
                "document for PA."
            )
        dg_map = {
            DATA_GROUP_TAG_TO_NUM.get(tag, tag): raw
            for tag, raw in pd.raw.items()
            if tag not in (0x60, 0x77)
        }
        pd.pa_result = verify_pa(pd.sod_info, dg_map, eac_required_dgs={3, 4})

    return pd
