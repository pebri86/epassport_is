"""Chip Authentication key carrier (EF.DG14) and Card Access (EF.CardAccess) parsing.

Per ICAO Doc 9303 Part 3 / TR-03110, the chip's static Chip-Authentication
public key is stored in **EF.DG14** (tag ``0x6E``, FID ``0x010E``) as a
``ChipAuthenticationPublicKeyInfo`` SecurityInfo. EF.CardAccess (MF, FID
``0x011C``) is read *before* authentication to detect which protocols (PACE,
BAC) and parameters (password type, key length, domain parameters) the chip
supports, so the terminal can auto-select the strongest available protocol.

    SecurityInfos ::= SET OF SecurityInfo
    SecurityInfo ::= SEQUENCE {
        protocol OBJECT IDENTIFIER,            -- id-PK-DH (Chip Authentication)
        subjectPublicKey [1] OCTET STRING,     -- 04||X||Y (65-byte point)
        keyId [2] OCTET STRING OPTIONAL }

    PACEInfo ::= SEQUENCE {
        protocol OBJECT IDENTIFIER,
        version INTEGER OPTIONAL,
        parameterId INTEGER OPTIONAL,          -- 12 = P-256
        [1] ... OPTIONAL                       -- required data / password type
    }
"""

from __future__ import annotations

from typing import Dict, List, NamedTuple, Optional, Tuple

from .tlvs import parse_tlvs, read_der_tlv

# id-PK-DH (Chip Authentication) OID 0.4.0.127.0.7.2.2.3.1.2
CHIP_AUTH_OID = bytes.fromhex("04007F00070202030102")

# id-PK-ECDH (Chip Authentication Public Key Info) OID 0.4.0.127.0.7.2.2.1.2
CHIP_AUTH_PK_ECDH_OID = bytes.fromhex("04007F000702020102")

# id-EC-Domain-parameter / "standardizedDomainParameter" 0.4.0.127.0.7.1.2
OID_STD_DOMAIN_PARAM = bytes.fromhex("04007F00070102")

# id-CA (Chip Authentication, no key agreement) OID 0.4.0.127.0.7.2.2.4.2.2
CHIP_AUTH_INFO_OID = bytes.fromhex("04007F00070202040202")

# id-CA-ECDH-AES-CBC-CMAC-128 / -256 (ICAO Doc 9303-11) -> CA session key bits.
CA_ECDH_CMAC_128 = bytes.fromhex("04007F00070202030202")
CA_ECDH_CMAC_256 = bytes.fromhex("04007F00070202030204")
_CA_OID_TO_BITS = {CA_ECDH_CMAC_128: 128, CA_ECDH_CMAC_256: 256}

# ---------------------------------------------------------------------------
# PACE protocol OIDs (ICAO Doc 9303 / BSI TR-03110)
# ---------------------------------------------------------------------------

# GM = Generic Mapping, IM = Integrated Mapping
PACE_ECDH_GM_AES_CBC_CMAC_128 = bytes.fromhex("04007F00070202040202")
PACE_ECDH_GM_AES_CBC_CMAC_192 = bytes.fromhex("04007F00070202040204")
PACE_ECDH_GM_AES_CBC_CMAC_256 = bytes.fromhex("04007F00070202040206")
PACE_ECDH_GM_3DES_CBC_CBC = bytes.fromhex("04007F00070202040102")
PACE_ECDH_IM_AES_CBC_CMAC_128 = bytes.fromhex("04007F00070202040402")
PACE_ECDH_IM_AES_CBC_CMAC_192 = bytes.fromhex("04007F00070202040404")
PACE_ECDH_IM_AES_CBC_CMAC_256 = bytes.fromhex("04007F00070202040406")
PACE_ECDH_IM_3DES_CBC_CBC = bytes.fromhex("04007F00070202040302")
PACE_DH_GM_AES_CBC_CMAC_128 = bytes.fromhex("04007F00070202040201")
PACE_DH_GM_AES_CBC_CMAC_192 = bytes.fromhex("04007F00070202040203")
PACE_DH_GM_AES_CBC_CMAC_256 = bytes.fromhex("04007F00070202040205")
PACE_DH_IM_AES_CBC_CMAC_128 = bytes.fromhex("04007F00070202040401")
PACE_DH_IM_AES_CBC_CMAC_192 = bytes.fromhex("04007F00070202040403")
PACE_DH_IM_AES_CBC_CMAC_256 = bytes.fromhex("04007F00070202040405")
PACE_CAM_AES_CBC_CMAC_128 = bytes.fromhex("04007F00070202040502")

_PACE_OID_NAMES = {
    PACE_ECDH_GM_AES_CBC_CMAC_128: "PACE-ECDH-GM-AES-CBC-CMAC-128",
    PACE_ECDH_GM_AES_CBC_CMAC_192: "PACE-ECDH-GM-AES-CBC-CMAC-192",
    PACE_ECDH_GM_AES_CBC_CMAC_256: "PACE-ECDH-GM-AES-CBC-CMAC-256",
    PACE_ECDH_GM_3DES_CBC_CBC: "PACE-ECDH-GM-3DES-CBC-CBC",
    PACE_ECDH_IM_AES_CBC_CMAC_128: "PACE-ECDH-IM-AES-CBC-CMAC-128",
    PACE_ECDH_IM_AES_CBC_CMAC_192: "PACE-ECDH-IM-AES-CBC-CMAC-192",
    PACE_ECDH_IM_AES_CBC_CMAC_256: "PACE-ECDH-IM-AES-CBC-CMAC-256",
    PACE_ECDH_IM_3DES_CBC_CBC: "PACE-ECDH-IM-3DES-CBC-CBC",
    PACE_DH_GM_AES_CBC_CMAC_128: "PACE-DH-GM-AES-CBC-CMAC-128",
    PACE_DH_GM_AES_CBC_CMAC_192: "PACE-DH-GM-AES-CBC-CMAC-192",
    PACE_DH_GM_AES_CBC_CMAC_256: "PACE-DH-GM-AES-CBC-CMAC-256",
    PACE_DH_IM_AES_CBC_CMAC_128: "PACE-DH-IM-AES-CBC-CMAC-128",
    PACE_DH_IM_AES_CBC_CMAC_192: "PACE-DH-IM-AES-CBC-CMAC-192",
    PACE_DH_IM_AES_CBC_CMAC_256: "PACE-DH-IM-AES-CBC-CMAC-256",
}

# PACE OIDs that use ECDH (the only kind we currently implement).
_PACE_ECDH_OIDS = frozenset(
    {
        PACE_ECDH_GM_AES_CBC_CMAC_128,
        PACE_ECDH_GM_AES_CBC_CMAC_192,
        PACE_ECDH_GM_AES_CBC_CMAC_256,
        PACE_ECDH_GM_3DES_CBC_CBC,
        PACE_ECDH_IM_AES_CBC_CMAC_128,
        PACE_ECDH_IM_AES_CBC_CMAC_192,
        PACE_ECDH_IM_AES_CBC_CMAC_256,
        PACE_ECDH_IM_3DES_CBC_CBC,
    }
)

# Well-known EAC SecurityInfo protocol OIDs -> human-readable name.
_SECURITY_INFO_OIDS = {
    bytes.fromhex("04007F00070202030102"): "Chip Authentication public key (id-PK-DH)",
    bytes.fromhex(
        "04007F00070202020101"
    ): "Chip Authentication key agreement (id-PK-DH-3DES)",
    bytes.fromhex(
        "04007F00070202040101"
    ): "Chip Authentication key agreement (id-CA-3DES)",
    bytes.fromhex(
        "04007F00070202020102"
    ): "Chip Authentication key agreement (id-PK-DH-AES)",
    bytes.fromhex(
        "04007F00070202040102"
    ): "Chip Authentication key agreement (id-CA-AES)",
    bytes.fromhex("04007F00070202020202"): "Chip Authentication mapping (id-PK-ECDH)",
    bytes.fromhex("04007F00070202040202"): "Chip Authentication mapping (id-CA-ECDH)",
    bytes.fromhex("04007F00070202040204"): "Chip Authentication key agreement (id-CA-ECDH-AES-CBC-CMAC-192)",
    bytes.fromhex("04007F00070202040206"): "Chip Authentication key agreement (id-CA-ECDH-AES-CBC-CMAC-256)",
    bytes.fromhex("04007F00070202040404"): "Chip Authentication key agreement (id-CA-ECDH-IM-AES-CBC-CMAC-192)",
    bytes.fromhex("04007F00070202040406"): "Chip Authentication key agreement (id-CA-ECDH-IM-AES-CBC-CMAC-256)",
    # User DG14 OID (0x31 tag variant): maps to id-CA-ECDH-AES-CBC-CMAC-256
    bytes.fromhex("04007F00070202030204"): "Chip Authentication key agreement (id-CA-ECDH-AES-CBC-CMAC-256)",
    # Brainpool CA OIDs (added for broader support)
    bytes.fromhex("04007F00070202040208"): "Chip Authentication key agreement (id-CA-ECDH-AES-CBC-CMAC-128-Brainpool)",
    bytes.fromhex("04007F00070202040210"): "Chip Authentication key agreement (id-CA-ECDH-AES-CBC-CMAC-192-Brainpool)",
    bytes.fromhex("04007F00070202040212"): "Chip Authentication key agreement (id-CA-ECDH-AES-CBC-CMAC-256-Brainpool)",
    **_PACE_OID_NAMES,
}


def oid_name(oid: bytes) -> str:
    return _SECURITY_INFO_OIDS.get(oid, "OID " + oid.hex(":").upper())


TAG_SEQUENCE = 0x30
TAG_OID = 0x06
# tag 0x02 is used for INTEGER keyId in standard SecurityInfo structures.
TAG_KEY_ID = 0x02

# EF.CardSecurity custom public-key tags (applet-specific, non-standard).
TAG_AA_PUBLIC_KEY = 0x5F2C
TAG_CA_PUBLIC_KEY = 0x5F2D
TAG_CAR = 0x42

# subjectPublicKey is context [1] (0x81) by default; accept any tag whose value
# is a 65-byte uncompressed point so slightly different tag assignments parse.
_POINT_CANDIDATE_TAGS = (0x81, 0x86)

# EC named-curve OIDs (DER OID content, no tag/length) that a
# ChipAuthenticationPublicKeyInfo AlgorithmIdentifier may carry instead of an
# INTEGER standardized-domain-parameter id -> ICAO parameter id (curve).
_NAMED_CURVE_OID_TO_PARAM_ID = {
    bytes.fromhex("2A8648CE3D030107"): 12,  # prime256v1 (NIST P-256)
    bytes.fromhex("2B2403030208010107"): 13,  # brainpoolP256r1
    bytes.fromhex("2B81040022"): 16,  # secp384r1 (NIST P-384)
    bytes.fromhex("2B81040023"): 17,  # secp521r1 (NIST P-521)
}

# ECDH Chip-Authentication key-agreement protocol OIDs (the id-CA-ECDH-AES-CBC-CMAC
# family used to select the CA suite / AES key size in an MSE:Set AT).
_CA_ECDH_AGREEMENT_OIDS = frozenset(
    {
        bytes.fromhex("04007F00070202030202"),  # id-CA-ECDH-AES-CBC-CMAC-128
        bytes.fromhex("04007F00070202030204"),  # id-CA-ECDH-AES-CBC-CMAC-256
    }
)


class ChipAuthData(NamedTuple):
    """Chip Authentication key material parsed from EF.DG14."""

    chip_public_key: bytes  # 65-byte uncompressed EC point (04 || X || Y)
    public_key_ref: bytes  # keyId, used as the TA MSE DO83 reference
    parameter_id: Optional[int] = None  # standardized domain parameter id (curve)
    ca_key_bits: Optional[int] = None  # 128 or 256 (CA AES session key length)


# Named-curve OIDs found in the CA SPKI AlgorithmIdentifier -> ICAO domain
# parameter id (matches epassport_reader.pace.PARAM_ID_TO_EC).
_NAMED_CURVE_OID_TO_PARAM = {
    bytes.fromhex("2A8648CE3D030107"): 12,  # secp256r1 / prime256v1 (NIST P-256)
    bytes.fromhex("2B2403030208010107"): 13,  # brainpoolP256r1
    bytes.fromhex("2B81040022"): 16,  # secp384r1
    bytes.fromhex("2B81040023"): 17,  # secp521r1
}


def _is_point(value: bytes) -> bool:
    return len(value) == 65 and value[0] == 0x04


def _named_curve_param_id(data: bytes) -> Optional[int]:
    """Map the EC named-curve OID inside an AlgorithmIdentifier to a param id."""
    if not data:
        return None
    try:
        for tag, value in parse_tlvs(data):
            if tag == TAG_OID:
                pid = _NAMED_CURVE_OID_TO_PARAM_ID.get(value)
                if pid is not None:
                    return pid
            if tag & 0x20:
                pid = _named_curve_param_id(value)
                if pid is not None:
                    return pid
    except (ValueError, IndexError):
        pass
    return None


def _extract_spki(spki_content: bytes) -> Tuple[Optional[bytes], Optional[int]]:
    """Extract ``(point, parameter_id)`` from an EC SubjectPublicKeyInfo.

    Handles the SPKI layout used by EF.DG14:
    ``SEQUENCE { AlgorithmIdentifier(SEQUENCE { OID, INTEGER paramId | OID namedCurve }), BIT STRING <point> }``.
    Returns the 65-byte uncompressed point and the standardized domain parameter
    id (curve reference), either of which may be absent.
    """
    point = None
    param_id = None
    for tag, value in parse_tlvs(spki_content):
        if tag == TAG_SEQUENCE:
            for atag, avalue in parse_tlvs(value):
                if atag == TAG_KEY_ID and param_id is None:
                    v = int.from_bytes(avalue, "big")
                    if v:
                        param_id = v
                elif (
                    atag == TAG_OID
                    and avalue in _NAMED_CURVE_OID_TO_PARAM
                    and param_id is None
                ):
                    param_id = _NAMED_CURVE_OID_TO_PARAM[avalue]
        elif tag == 0x03 and value and value[0] == 0x00 and _is_point(value[1:]):
            point = value[1:]  # BIT STRING: 00 <point>
    return point, param_id


def _parse_security_info(body: bytes) -> Optional[Tuple[bytes, bytes, Optional[int], Optional[bytes]]]:
    """Parse one ``SecurityInfo`` sequence; return CA data if it is a chip key.

    Returns ``(point, key_id, parameter_id, protocol_oid)`` or ``None``.
    """
    point = None
    key_id = None
    param_id = None
    protocol_oid = None
    has_chip_auth_oid = False

    for tag, value in parse_tlvs(body):
        if tag == TAG_OID and value in (CHIP_AUTH_OID, CHIP_AUTH_PK_ECDH_OID):
            has_chip_auth_oid = True
            protocol_oid = value
        elif tag in _POINT_CANDIDATE_TAGS and _is_point(value):
            point = value
        elif tag == TAG_KEY_ID and not key_id:
            key_id = value
        elif tag == TAG_SEQUENCE:
            sp, spid = _extract_spki(value)
            if sp:
                point = sp
            if spid:
                param_id = spid

    if not has_chip_auth_oid or point is None:
        return None
    return point, key_id or b"", param_id, protocol_oid


def _ca_agreement_fields(body: bytes) -> Tuple[Optional[bytes], bytes]:
    """Return the CA key-agreement OID and keyId of one SecurityInfo body."""
    oid = None
    key_id = b""
    try:
        for tag, value in parse_tlvs(body):
            if tag == TAG_OID:
                if value in _CA_ECDH_AGREEMENT_OIDS:
                    oid = value
            elif tag == TAG_KEY_ID:
                # ChipAuthenticationInfo is (OID, version, keyId): the last
                # INTEGER is the key reference used for keyId matching.
                key_id = value
    except (ValueError, IndexError):
        pass
    return oid, key_id


def _unwrap_security_infos(body: bytes) -> bytes:
    """Unwrap one enclosing ``SET OF`` / ``SEQUENCE OF`` SecurityInfos node.

    ICAO 9303-11 defines ``SecurityInfos ::= SET OF SecurityInfo``, so a DG14 /
    CardSecurity blob is often a single SET (0x31) — or, in some encoders, a
    SEQUENCE (0x30) — whose content is the list of SecurityInfo SEQUENCEs.
    This returns the inner content when ``body`` is exactly such a wrapper,
    otherwise ``body`` unchanged (already a flat SecurityInfo list).
    """
    try:
        cand = list(parse_tlvs(body))
    except Exception:
        return body
    if len(cand) == 1 and cand[0][0] in (TAG_SET, TAG_SEQUENCE):
        try:
            inner = list(parse_tlvs(cand[0][1]))
        except Exception:
            return body
        if any(t == TAG_SEQUENCE for t, _ in inner):
            return cand[0][1]
    return body


def _ca_key_bits_of(body: bytes) -> Optional[int]:
    """Return the CA AES key size (128/256) advertised by one SecurityInfo body."""
    for tag, value in parse_tlvs(body):
        if tag == TAG_OID and value in _CA_OID_TO_BITS:
            return _CA_OID_TO_BITS[value]
        if tag == TAG_SEQUENCE:
            for itag, ivalue in parse_tlvs(value):
                if itag == TAG_OID and ivalue in _CA_OID_TO_BITS:
                    return _CA_OID_TO_BITS[ivalue]
    return None


def parse_chip_auth_data(raw: bytes) -> Optional[ChipAuthData]:
    """Parse EF.DG14 into Chip-Authentication key material.

    DG14 is ``6E <len> <SecurityInfos>`` where
    ``SecurityInfos ::= SET OF SecurityInfo`` (some encoders use a flat
    ``SEQUENCE OF``), so the chip key is found by unwrapping the SecurityInfos
    node (``6E > SecurityInfos > SecurityInfo > fields``). Returns ``None`` when
    the file does not carry a chip CA public key.
    """
    if not raw:
        return None

    # Strip the outer LDS tag 0x6E so the SecurityInfos SET is at the top.
    if raw[0] == 0x6E:
        try:
            tag, start, end = read_der_tlv(raw, 0)
            if tag == 0x6E:
                raw = raw[start:end]
        except ValueError:
            pass

    raw = _unwrap_security_infos(raw)

    key_data = None
    ca_bits = None

    for tag, value in parse_tlvs(raw):  # SecurityInfo SEQUENCEs
        if tag != TAG_SEQUENCE:
            continue
        # the SecurityInfo may be one or two SEQUENCE levels deep
        inner_tags = (TAG_SEQUENCE,)
        if tag == TAG_SET:
            inner_tags = (TAG_SEQUENCE, TAG_SET)
        for inner_tag, inner_value in parse_tlvs(value):
            if inner_tag == TAG_SEQUENCE:
                if ca_bits is None:
                    ca_bits = _ca_key_bits_of(inner_value)
                if key_data is None:
                    key_data = _parse_security_info(inner_value)
        if ca_bits is None:
            ca_bits = _ca_key_bits_of(value)
        if key_data is None:
            key_data = _parse_security_info(value)
        if key_data is not None and ca_bits is not None:
            break

    if key_data is None:
        return None
    point, key_id, param_id, _protocol_oid = key_data
    return ChipAuthData(point, key_id, param_id, ca_bits)


def _extract_security_info(body: bytes) -> Dict[str, object]:
    """Extract the OID / keyId / public key / version of one SecurityInfo.

    Used to summarise the ``SecurityInfos`` carried by EF.CardSecurity for
    display (protocol, key reference and, for a Chip-Authentication public
    key, the 65-byte public key point).
    """
    oid = None
    point = None
    key_id = None
    version = None
    try:
        for tag, value in parse_tlvs(body):
            if tag == TAG_OID:
                oid = value
            elif tag in _POINT_CANDIDATE_TAGS and _is_point(value):
                point = value
            elif tag == TAG_KEY_ID and key_id is None:
                key_id = value
            elif tag == 0x01 and version is None and len(value) == 1:
                version = value[0]
    except Exception:
        # Fallback: scan raw bytes for known tags when TLV parsing fails.
        i = 0
        while i + 1 < len(body):
            tag = body[i]
            i += 1
            if i >= len(body):
                break
            first = body[i]
            i += 1
            if first < 0x80:
                length = first
            elif first == 0x81:
                if i >= len(body):
                    break
                length = body[i]
                i += 1
            elif first == 0x82:
                if i + 1 >= len(body):
                    break
                length = int.from_bytes(body[i : i + 2], "big")
                i += 2
            else:
                break
            if i + length > len(body):
                break
            value = body[i : i + length]
            i += length
            if tag == TAG_OID:
                oid = value
            elif tag in _POINT_CANDIDATE_TAGS and _is_point(value):
                point = value
            elif tag == TAG_KEY_ID and key_id is None:
                key_id = value
            elif tag == 0x01 and version is None and len(value) == 1:
                version = value[0]
    return {
        "oid": oid,
        "protocol": oid_name(oid) if oid else "unknown",
        "public_key": point,
        "key_id": key_id,
        "version": version,
    }


def parse_card_security(raw: bytes) -> Dict[str, object]:
    """Parse EF.CardSecurity (MF, 0x011D) ``SecurityInfos`` into a summary.

    Supports three encodings:

    1. Applet-specific flat TLV encoding: the first two bytes are the FID
       ``0x011D`` (not a BER tag), followed by a length byte and the
       content.  The content contains ``5F2C`` (Active Authentication
       public key) and/or ``5F2D`` (Chip Authentication public key) TLVs,
       each holding the 65-byte uncompressed EC point.
    2. Standard ``SecurityInfos ::= SEQUENCE OF SecurityInfo`` (same as
       EF.DG14), where each SecurityInfo is a SEQUENCE containing a protocol
       OID and optional fields.  The outer SEQUENCE may use indefinite
       length encoding (0x80), in which case parsing stops at the EOC
       marker.
    3. Nested CMS-style structure (observed on some real cards): the outer
       SEQUENCE contains a digest-algorithm OID and a ``[0]`` wrapper that
       nests SecurityInfo objects inside OCTET STRING / context-tagged
       wrappers.  The parser recursively descends into these wrappers to
       locate protocol OIDs and public keys.

    Returns a dict with ``raw_len`` and a list of ``infos`` (one entry per
    security object: protocol name, keyId, and, for a public key, the key
    bytes).
    """
    infos: list = []
    errors: list = []
    if not raw:
        return {"raw_len": 0, "infos": infos}
    try:
        body = raw
        if len(body) >= 2 and body[0] == 0x01 and body[1] == 0x1D:
            if body[2] == 0x81:
                content_len = body[3]
                body = body[4 : 4 + content_len]
            else:
                content_len = body[2]
                body = body[3 : 3 + content_len]

        # If the body starts with 0x77, it is actually an EF.SOD (CMS
        # SignedData), not EF.CardSecurity.  Return a clear note instead
        # of failing with a generic parse error.
        if body and body[0] == 0x77:
            return {
                "raw_len": len(raw),
                "infos": [
                    {
                        "protocol": "EF.SOD content (not EF.CardSecurity)",
                        "_parse_error": None,
                    }
                ],
            }

        flat_infos = _parse_card_security_flat(body)
        if flat_infos:
            infos.extend(flat_infos)
        else:
            _parse_security_infos_tolerant(body, infos)

        valid_infos = [info for info in infos if not info.get("_parse_error")]
        if not valid_infos:
            _parse_card_security_deep(body, infos)

        # Deduplicate: keep first occurrence of each protocol, and for
        # public-key entries keep first occurrence of each (protocol, key).
        # If the same protocol appears once without a key and once with a
        # key, keep the one with the key.
        seen_protocols = set()
        best: dict = {}
        for info in infos:
            protocol = info.get("protocol")
            if not protocol:
                continue
            pub_key = info.get("public_key")
            if pub_key:
                key = (protocol, pub_key)
                if key not in seen_protocols:
                    seen_protocols.add(key)
                    best[protocol] = info
            else:
                if protocol not in best:
                    best[protocol] = info
        infos[:] = list(best.values())
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc))
    if not infos:
        infos.append({"_parse_error": "no SecurityInfo SEQUENCE found"})
    return {"raw_len": len(raw), "infos": infos}


def _parse_card_security_deep(body: bytes, infos: list) -> None:
    """Recursively scan nested wrappers for protocol OIDs and public keys."""
    try:
        _scan_for_security_info(body, infos, depth=0)
    except Exception:
        pass


def _scan_for_security_info(
    data: bytes, infos: list, depth: int = 0, last_protocol: Optional[str] = None
) -> None:
    """Recursively scan data for SecurityInfo patterns."""
    if depth > 12 or len(data) < 4:
        return

    i = 0
    current_protocol = last_protocol
    while i < len(data) - 3:
        try:
            tag, start, end = read_der_tlv(data, i)
        except Exception:
            i += 1
            continue

        value = data[start:end]

        # Detect protocol OIDs (0x06 followed by known OID bytes).
        if tag == 0x06 and len(value) >= 6:
            oid_hex = value.hex()
            protocol = _oid_to_protocol(oid_hex)
            if protocol and "Digest" not in protocol and "Algorithm" not in protocol:
                current_protocol = protocol
                # Create an info entry for this protocol immediately.
                infos.append(
                    {
                        "protocol": protocol,
                        "key_id": b"",
                        "version": None,
                    }
                )

        # Detect BIT STRING public keys (0x03) that aren't inside a known
        # container - associate with the nearest preceding protocol OID.
        if tag == 0x03 and len(value) >= 66 and value[0] == 0x00:
            pub_key = value[1:]  # strip unused-bits byte
            if len(pub_key) == 65 and pub_key[0] == 0x04:
                protocol = current_protocol or _find_previous_oid(data, i)
                if protocol:
                    infos.append(
                        {
                            "protocol": protocol,
                            "public_key": pub_key,
                            "key_id": b"",
                            "version": None,
                        }
                    )

        # Detect OCTET STRINGs that might contain nested SecurityInfo.
        if tag == 0x04 and len(value) >= 20:
            _scan_for_security_info(value, infos, depth + 1, current_protocol)

        # Recurse into constructed TLVs (SEQUENCE, SET, OCTET STRING, and any
        # constructed tag where bit 6 is set).
        if tag in (0x30, 0x31, 0x04) or (tag & 0x20):
            _scan_for_security_info(value, infos, depth + 1, current_protocol)

        i = end


def _find_next_public_key(data: bytes, offset: int) -> Optional[bytes]:
    """Look ahead for the next public key BIT STRING after ``offset``."""
    i = offset
    while i < len(data) - 3:
        try:
            tag, start, end = read_der_tlv(data, i)
        except Exception:
            i += 1
            continue
        if tag == 0x03:
            value = data[start:end]
            if len(value) >= 66 and value[0] == 0x00:
                pub_key = value[1:]
                if len(pub_key) == 65 and pub_key[0] == 0x04:
                    return pub_key
        i = end
    return None


def _find_previous_oid(data: bytes, offset: int) -> Optional[str]:
    """Look backward for the nearest protocol OID before ``offset``."""
    i = 0
    last_oid_hex = None
    while i < offset:
        try:
            tag, start, end = read_der_tlv(data, i)
        except Exception:
            i += 1
            continue
        if tag == 0x06 and (end - start) >= 6:
            last_oid_hex = data[start:end].hex()
        i = end
    if last_oid_hex:
        return _oid_to_protocol(last_oid_hex)
    return None


def _oid_to_protocol(oid_hex: str) -> Optional[str]:
    """Map a DER-encoded OID hex string to a human-readable protocol name."""
    oid_map = {
        "2a8648ce3d0201": "Active Authentication (ecPublicKey)",
        "2a8648ce3d040302": "Active Authentication (ecdsa-with-SHA256)",
        "04007f00070202030102": "Chip Authentication (id-PK-DH)",
        "04007f000702020102": "Chip Authentication (id-PK-ECDH)",
        "04007f00070202030202": "Chip Authentication (id-CA-ECDH-AES-CBC-CMAC-128)",
        "04007f00070202040202": "PACE (id-PACE-ECDH-GM-AES-CBC-CMAC-128)",
        "04007f00070202020202": "Terminal Authentication (id-TA-ECDSA-SHA256)",
        "04007f0007020202": "Terminal Authentication (id-TA)",
        "2a864886f70d010702": "Document Digest (id-Digest with SHA-256)",
        "6086480165030402": "Digest Algorithm (id-SHA-256)",
        "04007f0007030201": "Chip Authentication (id-CA-ECDH-AES-CBC-CMAC-128)",
    }
    return oid_map.get(oid_hex)


def _parse_security_infos_tolerant(body: bytes, infos: list) -> None:
    """Parse SecurityInfos with tolerance for indefinite-length and trailing bytes."""
    i = 0
    while i < len(body):
        # Stop at EOC marker (indefinite-length terminator).
        if i + 1 < len(body) and body[i] == 0x00 and body[i + 1] == 0x00:
            break
        try:
            tag, start, end = read_der_tlv(body, i)
        except Exception:
            break
        if tag != TAG_SEQUENCE:
            i = end
            continue
        try:
            for inner_tag, inner_value in parse_tlvs(body[start:end]):
                if inner_tag == TAG_SEQUENCE:
                    infos.append(_extract_security_info(inner_value))
                    break
        except Exception:
            pass
        i = end


def _parse_card_security_flat(body: bytes) -> List[Dict[str, object]]:
    """Parse the applet-specific flat 0x5F2C / 0x5F2D CardSecurity format."""
    infos: List[Dict[str, object]] = []
    try:
        for tag, value in parse_tlvs(body):
            if tag == TAG_AA_PUBLIC_KEY:
                infos.append(
                    {
                        "protocol": "Active Authentication public key",
                        "public_key": value,
                        "key_id": b"",
                        "version": None,
                    }
                )
            elif tag == TAG_CA_PUBLIC_KEY:
                infos.append(
                    {
                        "protocol": "Chip Authentication public key",
                        "public_key": value,
                        "key_id": b"",
                        "version": None,
                    }
                )
    except Exception:
        pass
    return infos


# ---------------------------------------------------------------------------
# EF.CardAccess parsing (pre‑authentication protocol detection)
# ---------------------------------------------------------------------------

# EF.CardAccess is a SET OF SecurityInfo, stored in the MF at FID 0x011C.
# It is readable without secure messaging so the terminal can decide which
# access protocol to use.
TAG_SET = 0x31

# Standardized domain parameter ids (ICAO Doc 9303 / TR-03110)
PARAM_ID_TO_CURVE = {
    8: "P-192",
    9: "P-224",
    12: "P-256 (secp256r1 / NIST)",
    13: "P-256 (brainpoolP256r1)",
    14: "P-384 (brainpoolP384r1)",
    15: "P-512 (brainpoolP512r1)",
    16: "P-384 (secp384r1 / NIST)",
    17: "P-521 (secp521r1 / NIST)",
}


def _parse_pace_info(body: bytes) -> Optional[Dict[str, object]]:
    """Parse one PACEInfo SEQUENCE, extracting OID / version / parameterId."""
    oid = None
    version = None
    param_id = None
    for tag, value in parse_tlvs(body):
        if tag == TAG_OID:
            oid = value
        elif tag == 0x01 and version is None and len(value) == 1:
            version = value[0]
        elif tag == TAG_KEY_ID and len(value) <= 2:
            val = int.from_bytes(value, "big")
            if val >= 6:
                param_id = val
    if oid is None or oid not in _PACE_OID_NAMES:
        return None
    return {
        "oid": oid,
        "name": _PACE_OID_NAMES.get(oid, oid_name(oid)),
        "version": version,
        "parameter_id": param_id,
        "curve": PARAM_ID_TO_CURVE.get(param_id) if param_id else None,
        "is_ecdh": oid in _PACE_ECDH_OIDS,
    }


class CardAccessInfo(NamedTuple):
    """Result of reading EF.CardAccess before authentication."""

    pace_supported: bool
    pace_info: Optional[Dict[str, object]]
    raw_bytes: bytes


def parse_card_access(raw: bytes) -> CardAccessInfo:
    """Parse EF.CardAccess (MF, 0x011C) to detect PACE support.

    ``EF.CardAccess = SET OF SecurityInfo``.  The function looks for one or
    more PACEInfo entries.  Returns a ``CardAccessInfo`` with a boolean flag
    indicating whether PACE is available and the best matching PACEInfo dict
    (preferring ECDH variants over DH since only ECDH is implemented).
    """
    if not raw:
        return CardAccessInfo(False, None, raw)

    try:
        tlvs = list(parse_tlvs(raw))
    except (ValueError, IndexError):
        return CardAccessInfo(False, None, raw)

    pace_infos: list = []

    # Top level: SET (0x31) containing SEQUENCE OF SecurityInfo
    for tag, value in tlvs:
        if tag not in (TAG_SET, TAG_SEQUENCE):
            continue
        try:
            inner_tlvs = list(parse_tlvs(value))
        except (ValueError, IndexError):
            continue
        for inner_tag, inner_value in inner_tlvs:
            if inner_tag == TAG_SEQUENCE:
                pace = _parse_pace_info(inner_value)
                if pace:
                    pace_infos.append(pace)

    if not pace_infos:
        return CardAccessInfo(False, None, raw)

    # Prefer ECDH variants (the only ones we implement)
    ecdh = [p for p in pace_infos if p["is_ecdh"]]
    best = ecdh[0] if ecdh else pace_infos[0]
    return CardAccessInfo(True, best, raw)


def parse_ef_cvca(raw: bytes) -> Dict[str, object]:
    """Parse EF.CVCA (app-DF, 0x011C): the trust-point CAR list.

    ICAO Doc 9303-11 App. K, Table K-2: a fixed 36-byte transparent file
    holding a sequence of CAR data objects (tag 0x42, most recent first),
    zero-padded.  Returns the list of CARs and the decoded text form.
    """
    result: Dict[str, object] = {
        "raw_len": len(raw),
        "cars": [],
        "cars_text": [],
    }
    i = 0
    while i + 1 < len(raw):
        tag = raw[i]
        length = raw[i + 1]
        if tag != TAG_CAR:
            break
        if i + 2 + length > len(raw):
            break
        car = raw[i + 2 : i + 2 + length]
        result["cars"].append(car)  # type: ignore[attr-defined]
        i += 2 + length
    result["cars_text"] = [c.decode("latin-1", errors="replace") for c in result["cars"]]  # type: ignore[attr-defined]
    return result
