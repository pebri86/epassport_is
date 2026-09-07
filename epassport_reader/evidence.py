"""Cryptographic-evidence helpers for the EACv2 coverage report.

Only *fingerprints* of secret/derived material are ever emitted, never the
raw key bytes.  Everything here depends only on the standard library.
"""

from __future__ import annotations

import hashlib
from typing import List, Optional


def fingerprint(data: bytes, algo: str = "SHA-256") -> str:
    """One-way fingerprint of ``data`` (no key material is ever output)."""
    h = hashlib.new(algo.replace("-", "").lower())
    h.update(data)
    return f"{algo}:{h.hexdigest()}"


def oid_arcs(oid: bytes) -> List[int]:
    """Decode a DER/BER OID content (no tag/length) into its arc list."""
    if not oid:
        return []
    arcs = []
    value = 0
    first = True
    for byte in oid:
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            if first:
                arcs.append(value // 40)
                arcs.append(value % 40)
                first = False
            else:
                arcs.append(value)
            value = 0
    return arcs


def oid_dotted(oid: bytes) -> str:
    return ".".join(str(a) for a in oid_arcs(oid))


# id-CA-ECDH-AES-CBC-CMAC-* (EAC v2 CA key-agreement family) by AES size.
_CA_OID_BITS = {
    bytes.fromhex("04007F00070202030202"): 128,  # ...3.2.2
    bytes.fromhex("04007F00070202030204"): 256,  # ...3.2.4
    bytes.fromhex("04007F00070202040206"): 256,  # ...4.2.6 (alt encoding)
}


def ca_key_bits_of(oid: bytes) -> Optional[int]:
    """Map a CA key-agreement OID to its AES session-key size (128/256)."""
    return _CA_OID_BITS.get(oid)


def pace_mapping_of(oid: bytes) -> str:
    """Return the PACE mapping ('GM' / 'IM') advertised by a PACE OID."""
    arcs = oid_arcs(oid)
    # ... id-PACE-ECDH/DH: last arc is the AES/DES key size, the arc before it
    # selects the mapping: 2 = Generic Mapping (GM), 4 = Integrated Mapping (IM).
    if len(arcs) >= 2 and arcs[-2] == 4:
        return "IM"
    if len(arcs) >= 2 and arcs[-2] == 2:
        return "GM"
    return "?"


def short(value: bytes, prefix: int = 6) -> str:
    """Short hex prefix for non-secret debug values (e.g. a decrypted nonce)."""
    return value[:prefix].hex().upper()
