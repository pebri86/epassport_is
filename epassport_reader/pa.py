"""Passive Authentication (PA) - EF.SOD verification.

The Document Security Object (EF.SOD, tag 0x77) is a CMS SignedData.  The
LDS Security Object (carrying the per-data-group hashes) is embedded either
in the signed attributes (common for real e-passports) or as the eContent.

PA checks:

1. the hashes stored in the LDS Security Object match the DGs actually read,
2. the CMS signature over the signed attributes validates against the RSA
   public key of the certificate embedded in the SOD.

The certificate chain back to the CSCA is the issuing state's responsibility
and is reported as metadata, not enforced (no trust store is bundled).
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Tuple

from Crypto.Hash import SHA1, SHA256, SHA384, SHA512
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import pkcs1_15

from .tlvs import read_der_tlv

# OIDs used by the ICAO Document Security Object
OID_LDS_SECURITY_OBJECT = bytes.fromhex("6788010101")  # 2.23.136.1.1.1
OID_SHA1 = bytes.fromhex("2B0E03021A")  # 1.3.14.3.2.26
OID_SHA256 = bytes.fromhex("608648016503040201")  # 2.16.840.1.101.3.4.2.1
OID_SHA384 = bytes.fromhex("608648016503040202")
OID_SHA512 = bytes.fromhex("608648016503040203")

# RSA signature OIDs (rsaEncryption-based, used in SignerInfo.signatureAlgorithm)
OID_SHA1_RSA = bytes.fromhex("2A864886F70D010105")  # sha1WithRSAEncryption
OID_SHA256_RSA = bytes.fromhex("2A864886F70D01010B")  # sha256WithRSAEncryption
OID_SHA384_RSA = bytes.fromhex("2A864886F70D01010C")
OID_SHA512_RSA = bytes.fromhex("2A864886F70D01010D")

OID_ALG_NAMES = {
    OID_SHA1: "SHA-1",
    OID_SHA256: "SHA-256",
    OID_SHA384: "SHA-384",
    OID_SHA512: "SHA-512",
    OID_SHA1_RSA: "SHA-1",
    OID_SHA256_RSA: "SHA-256",
    OID_SHA384_RSA: "SHA-384",
    OID_SHA512_RSA: "SHA-512",
}

_HASH_FACTORY = {
    "SHA-1": SHA1,
    "SHA-256": SHA256,
    "SHA-384": SHA384,
    "SHA-512": SHA512,
}


def _children(data: bytes) -> List[Tuple[int, bytes, bytes]]:
    """Return (tag, raw_bytes_including_tag, value) for the direct children."""
    out: List[Tuple[int, bytes, bytes]] = []
    i = 0
    while i < len(data):
        tag, start, end = read_der_tlv(data, i)
        out.append((tag, data[i:end], data[start:end]))
        i = end
    return out


def _first_oid(seq: bytes) -> Optional[bytes]:
    for tag, _raw, value in _children(seq):
        if tag == 0x06:
            return value
    return None


def _alg_name(oid: Optional[bytes]) -> str:
    if not oid:
        return "unknown"
    return OID_ALG_NAMES.get(bytes(oid), "unknown")


def _hash_bytes(alg_name: str, data: bytes) -> Optional[bytes]:
    factory = _HASH_FACTORY.get(alg_name)
    if factory is None:
        return None
    return factory.new(data).digest()


# ---------------------------------------------------------------------------
# LDS Security Object parsing
# ---------------------------------------------------------------------------


def _parse_lds_security_object(der: bytes) -> Dict:
    result: Dict = {
        "version": None,
        "digest_algorithm": None,
        "dg_hashes": {},
        "lds_version": None,
        "unicode_version": None,
    }
    tag, start, end = read_der_tlv(der, 0)
    if tag == 0x04:
        # eContent wrapped in an explicit OCTET STRING: unwrap it.
        der = der[start:end]
        tag, start, end = read_der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("LDS Security Object is not a SEQUENCE")

    seen_digest = False
    for t, _raw, value in _children(der[start:end]):
        if t == 0x02 and result["version"] is None:
            result["version"] = int.from_bytes(value, "big")
        elif t == 0x30:
            if not seen_digest:
                # first 0x30 after version -> digestAlgorithmIdentifier
                result["digest_algorithm"] = _alg_name(_first_oid(value))
                seen_digest = True
            else:
                # following 0x30 -> dataGroupHashValues
                for dt, _r, dv in _children(value):
                    if dt != 0x30:
                        continue
                    dg_num = None
                    dg_hash = None
                    for ft, _fr, fv in _children(dv):
                        if ft == 0x02:
                            dg_num = int.from_bytes(fv, "big")
                        elif ft == 0x04:
                            dg_hash = fv
                    if dg_num is not None and dg_hash is not None:
                        result["dg_hashes"][dg_num] = dg_hash
        elif t == 0x81:
            result["lds_version"] = value.decode("latin-1", errors="replace")
        elif t == 0x82:
            result["unicode_version"] = value.decode("latin-1", errors="replace")
    return result


def _extract_lds_so_from_attrs(signed_attrs_der: bytes) -> Optional[bytes]:
    """Find the id-ldsSecurityObject attribute and return its OCTET STRING.

    ``signed_attrs_der`` may be either the raw SET content or a full SET TLV.
    """
    data = signed_attrs_der
    if data and data[0] == 0x31:
        _t, _s, _e = read_der_tlv(data, 0)
        data = data[_s:_e]
    for tag, _raw, value in _children(data):
        if tag != 0x30:
            continue
        oid = _first_oid(value)
        if oid != OID_LDS_SECURITY_OBJECT:
            continue
        for st, _sr, sval in _children(value):
            if st != 0x31:  # attrValues: SET
                continue
            for ot, _or, oval in _children(sval):
                if ot == 0x04:
                    return oval
    return None


# ---------------------------------------------------------------------------
# signer info parsing
# ---------------------------------------------------------------------------


def _parse_signer_info(signer_infos_der: bytes, info: Dict) -> None:
    """Extract digest/signature algorithm, signed attrs and signature bytes."""
    for tag, _raw, value in _children(signer_infos_der):
        if tag != 0x30:  # a SignerInfo
            continue
        children = _children(value)
        signed_attrs_seen = False
        sig_alg_idx = 5
        sig_idx = 6
        for t2, _raw2, _ in children:
            if t2 == 0xA0:
                signed_attrs_seen = True
                break
        if signed_attrs_seen:
            sig_alg_idx = 5
            sig_idx = 6
        else:
            sig_alg_idx = 4
            sig_idx = 5
        for idx, (t2, raw2, value2) in enumerate(children, start=1):
            if idx == 3:
                info["digest_algorithm"] = _alg_name(_first_oid(value2))
            elif idx == sig_alg_idx and t2 == 0x30:
                info["signature_algorithm"] = _alg_name(_first_oid(value2))
            elif t2 == 0xA0:
                _at, _as, _ae = read_der_tlv(raw2, 0)
                info["signed_attrs_raw"] = b"\x31" + raw2[_as - 1 : _ae]
            elif idx == sig_idx and t2 == 0x04:
                info["signature_bytes"] = value2
        break  # only the first signer is inspected


# ---------------------------------------------------------------------------
# main SOD parsing
# ---------------------------------------------------------------------------


def parse_sod(data: bytes) -> Dict:
    """Parse EF.SOD; never raises (a ``parse_error`` key is set on failure)."""
    info: Dict = {
        "parse_error": None,
        "digest_algorithm": None,
        "dg_hashes": {},
        "signature_algorithm": None,
        "certificate_subject": None,
        "certificate_present": False,
        "certificate_der": None,
        "signature_bytes": None,
        "signed_attrs_raw": None,
    }
    try:
        sod_content = data
        if len(data) >= 2 and data[0] == 0x77:
            _t, _s, _e = read_der_tlv(data, 0)
            sod_content = data[_s:_e]

        # ``sod_content`` is the outer SEQUENCE; descend into its value so
        # _children() yields the top-level fields (contentType OID, [0] wrapper).
        if sod_content and sod_content[0] == 0x30:
            _t, _s, _e = read_der_tlv(sod_content, 0)
            sod_content = sod_content[_s:_e]

        # Some applets wrap the SignedData in a contentType + [0] IMPLICIT
        # wrapper instead of the standard CMS flat SEQUENCE.  Detect and
        # unwrap that here so the rest of the code can treat the inner
        # SEQUENCE as the SignedData body.
        children = _children(sod_content)
        if children and children[0][0] == 0x06:
            # First child is an OID (contentType).  The SignedData fields
            # should be inside the next child, which is a [0] IMPLICIT
            # SEQUENCE.
            if len(children) >= 2 and children[1][0] == 0xA0:
                sod_content = children[1][2]
                # The [0] wrapper contains a SEQUENCE; unwrap it.
                if sod_content and sod_content[0] == 0x30:
                    _t, _s, _e = read_der_tlv(sod_content, 0)
                    sod_content = sod_content[_s:_e]

        encap = None
        certs = None
        signer_infos = None
        seen_set = 0
        for t, _raw, value in _children(sod_content):
            if t == 0x31:
                seen_set += 1
                if seen_set == 2:
                    signer_infos = value
            elif t == 0x30 and encap is None:
                encap = value
            elif t == 0xA0 and certs is None:
                certs = value

        # certificates (embedded signer certificate)
        if certs is not None:
            for t, _raw, value in _children(certs):
                if t == 0x30:
                    # keep the FULL certificate SEQUENCE (raw, incl. tag+length)
                    # so RSA.import_key can parse the X.509 cert for the
                    # signature check (value alone is only the tbs content).
                    info["certificate_present"] = True
                    info["certificate_der"] = _raw
                    try:
                        key = RSA.import_key(_raw)
                        info["certificate_subject"] = f"RSA {key.size_in_bits()}-bit"
                    except Exception:  # noqa: BLE001
                        try:
                            key = ECC.import_key(_raw)
                            info["certificate_subject"] = f"EC {key.pointQ}"
                        except Exception:  # noqa: BLE001
                            info["certificate_subject"] = "unparseable certificate"
                    break

        # signer info (digest alg, signed attrs, signature)
        if signer_infos is not None:
            _parse_signer_info(signer_infos, info)

        # LDS Security Object: try eContent first, then the signed attributes
        if encap is not None:
            for t, _raw, value in _children(encap):
                if t == 0xA0:
                    try:
                        info.update(_parse_lds_security_object(value))
                    except Exception:
                        pass
                    break
                elif t == 0x30:
                    try:
                        info.update(_parse_lds_security_object(value))
                    except Exception:
                        pass
                    break
        if not info["dg_hashes"] and info["signed_attrs_raw"]:
            lds_so = _extract_lds_so_from_attrs(info["signed_attrs_raw"])
            if lds_so:
                try:
                    info.update(_parse_lds_security_object(lds_so))
                except Exception:
                    pass

        if not info["dg_hashes"]:
            info["parse_error"] = "no data-group hash values found in SOD"
    except Exception as exc:  # noqa: BLE001 - report, do not crash
        info["parse_error"] = f"{type(exc).__name__}: {exc}"
    return info


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------


def verify_pa(
    sod_info: Dict,
    dg_raw_map: Dict[int, bytes],
    eac_required_dgs: Optional[set] = None,
) -> Dict:
    """Verify read DGs against the SOD hashes and the embedded signature.

    ``dg_raw_map`` maps data-group numbers to the raw EF bytes read from the
    card.

    ``eac_required_dgs`` is the set of DG numbers that require EAC (Terminal
    Authentication) before they can be read.  Missing DGs in this set are
    reported as ``EAC required`` and excluded from the overall PASS/FAIL
    calculation.  Defaults to ``{3, 4}`` (DG3 fingerprints, DG4 iris).
    """
    if eac_required_dgs is None:
        eac_required_dgs = {3, 4}

    result: Dict = {
        "overall": "FAIL",
        "dg_results": {},
        "signature_valid": None,
        "notes": [],
    }

    dg_hashes = sod_info.get("dg_hashes", {})
    digest_alg = sod_info.get("digest_algorithm") or "SHA-1"
    if not dg_hashes:
        result["overall"] = "N/A"
        result["notes"].append("SOD contains no data-group hashes to compare.")
        return result

    for dg_num, stored_hash in sorted(dg_hashes.items()):
        raw = dg_raw_map.get(dg_num)
        if raw is None:
            if dg_num in eac_required_dgs:
                result["dg_results"][dg_num] = {
                    "stored": stored_hash.hex(),
                    "computed": None,
                    "match": None,
                    "status": "EAC required",
                }
            else:
                result["dg_results"][dg_num] = {
                    "stored": stored_hash.hex(),
                    "computed": None,
                    "match": False,
                    "status": "DG not read",
                }
            continue
        computed = _hash_bytes(digest_alg, raw)
        match = computed == stored_hash
        result["dg_results"][dg_num] = {
            "stored": stored_hash.hex(),
            "computed": computed.hex() if computed else None,
            "match": match,
            "status": "OK" if match else "MISMATCH",
        }

    non_eac_results = [
        r
        for dg_num, r in result["dg_results"].items()
        if dg_num not in eac_required_dgs
    ]
    if non_eac_results and all(r["match"] for r in non_eac_results):
        result["overall"] = "PASS"
    else:
        result["overall"] = "FAIL"

    # CMS signature over the signed attributes
    sig = sod_info.get("signature_bytes")
    signed_der = sod_info.get("signed_attrs_raw")
    cert_der = sod_info.get("certificate_der")
    if sig and signed_der and cert_der:
        try:
            key = RSA.import_key(cert_der)
            factory = _HASH_FACTORY.get(
                sod_info.get("signature_algorithm") or digest_alg
            )
            if factory is None:
                result["signature_valid"] = "unavailable algorithm"
                result["notes"].append(
                    f"Unsupported signature hash: {sod_info.get('signature_algorithm')}"
                )
            else:
                pkcs1_15.new(key).verify(factory.new(signed_der), sig)
                result["signature_valid"] = True
                result["notes"].append("CMS signature verified (embedded certificate).")
        except Exception as exc:  # noqa: BLE001
            result["signature_valid"] = False
            result["notes"].append(f"signature verification failed: {exc}")
    elif sig and signed_der:
        result["signature_valid"] = "unverified (no embedded certificate)"
        result["notes"].append("No certificate embedded; signature not checked.")
    else:
        result["signature_valid"] = None
        result["notes"].append("SOD does not expose a verifiable signature here.")

    return result
