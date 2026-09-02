"""Active Authentication (AA) - ICAO Doc 9303 Part 11.

Active Authentication proves the chip holds the private key matching the
public key in **EF.DG15**. It is a challenge-response over the BAC/PACE
secure-messaging session via ``INTERNAL_AUTHENTICATE`` (INS 0x88) with an
8-byte challenge.

Two key types are supported:

* **RSA** (classic ICAO AA): the chip "decrypts" (raw-RSA signs) a 256-byte
  block ``0x6A || m1(234) || SHA1(m1 || m2)(20) || 0xBC``. The terminal
  "encrypts" the signature with the DG15 public key to recover the block,
  checks the ``0x6A``/``0xBC`` frame and verifies ``SHA1(m1 || m2)``.
* **ECDSA** (EC-AA, e.g. the applet on brainpoolP256r1): the chip signs the
  challenge with ECDSA (Java Card ``ALG_ECDSA_SHA`` = SHA-1 or
  ``ALG_ECDSA_SHA_256`` = SHA-256) and returns a **DER** ``SEQUENCE {
  INTEGER r, INTEGER s }`` signature. The terminal recomputes the digest and
  verifies it with the DG15 EC public key using the local curve arithmetic.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Callable, NamedTuple, Optional, Tuple

from Crypto.PublicKey import RSA

from .pace import (
    EC_BRAINPOOL_P256,
    EC_P256,
    EC_P384,
    EC_P521,
    _ec_decode_point,
    _ec_point_add,
    _ec_point_mul,
)
from .sm import SecureMessagingSession
from .tlvs import parse_tlvs, read_der_tlv

SendFn = Callable[[bytes], Tuple[bytes, int]]
LogFn = Callable[[str], None]

INS_INTERNAL_AUTHENTICATE = 0x88
RSA_MODULUS_LENGTH = 256  # RSA-2048 AA block
CHALLENGE_LENGTH = 8

# DER named-curve OIDs (content, no tag/length) -> domain parameters.  Covers
# the NIST/brainpool P-256..P-521 set that ICAO AA and this applet use.  The
# applet's AA key lives on brainpoolP256r1, which pycryptodome cannot import,
# so verification is done with the local curve arithmetic.
_NAMED_CURVE_OIDS = {
    bytes.fromhex("2A8648CE3D030107"): EC_P256,  # prime256v1
    bytes.fromhex("2B2403030208010107"): EC_BRAINPOOL_P256,  # brainpoolP256r1
    bytes.fromhex("2B81040022"): EC_P384,  # secp384r1
    bytes.fromhex("2B81040023"): EC_P521,  # secp521r1
}


class ActiveAuthResult(NamedTuple):
    """Outcome of an Active-Authentication exchange."""

    verified: bool
    challenge: bytes  # m2 (the challenge the terminal sent)
    signature: bytes  # the chip's signature (raw-RSA or ECDSA R||S)
    reason: Optional[str]


def _parse_ec_spki(spki: bytes):
    """Parse an EC SubjectPublicKeyInfo into ``(curve, point)`` or ``None``.

    ``point`` is the 65-byte uncompressed public point.  The curve is
    resolved from the AlgorithmIdentifier named-curve OID.
    """
    try:
        tag, start, end = read_der_tlv(spki, 0)
        if tag != 0x30:
            return None
        curve = None
        point = None
        for ctag, cvalue in parse_tlvs(spki[start:end]):
            if ctag == 0x30:  # AlgorithmIdentifier
                for atag, avalue in parse_tlvs(cvalue):
                    if atag == 0x06 and avalue in _NAMED_CURVE_OIDS:
                        curve = _NAMED_CURVE_OIDS[avalue]
            elif ctag == 0x03 and len(cvalue) == 66 and cvalue[0] == 0x00 and cvalue[1] == 0x04:
                point = cvalue[1:]  # BIT STRING: 00 <point>
        if curve is None or point is None:
            return None
        _ec_decode_point(point, curve)  # validates curve membership
        return curve, point
    except (ValueError, IndexError):
        return None


def parse_dg15_aa_key(dg15: bytes) -> Tuple[str, object]:
    """Parse the EF.DG15 (tag 0x6F -> SPKI) Active-Authentication key.

    Returns ``("RSA", key)`` or ``("EC", (curve, point))`` depending on the
    SPKI algorithm.  The EC public key is returned as ``(ECDomainParams,
    65-byte point)`` so brainpoolP256r1 keys (which pycryptodome cannot
    import) verify with the local curve arithmetic.
    """
    if not dg15 or dg15[0] != 0x6F:
        raise ValueError("DG15 does not start with LDS tag 0x6F")
    tag, start, end = read_der_tlv(dg15, 0)
    if tag != 0x6F or end != len(dg15):
        raise ValueError("Invalid DG15 outer structure")
    spki = dg15[start:end]
    rsa = None
    try:
        rsa = RSA.import_key(spki)  # DER SubjectPublicKeyInfo (RSA)
    except (ValueError, TypeError):
        pass
    if rsa is not None:
        return "RSA", rsa
    ec = _parse_ec_spki(spki)
    if ec is not None:
        return "EC", ec
    raise ValueError("DG15 key format not supported (neither RSA nor EC)")


def do_active_authentication(
    session: SecureMessagingSession,
    send: SendFn,
    challenge: bytes,
    aa_public_key: Tuple[str, object],
    log: Optional[LogFn] = None,
) -> ActiveAuthResult:
    """Run Active Authentication and verify the result.

    ``INTERNAL_AUTHENTICATE`` is sent as a **plain** APDU (not SM-wrapped);
    it only requires an authenticated session (BAC or PACE). ``session`` is
    accepted for API compatibility but not used for wrapping. The DG15 key
    may be RSA or EC (ECDSA AA).
    """
    if log is None:
        log = lambda _m: None
    if len(challenge) != CHALLENGE_LENGTH:
        raise ValueError("AA challenge must be 8 bytes")

    cmd = (
        bytes([0x00, INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, CHALLENGE_LENGTH])
        + challenge
    )
    log(f"AA INTERNAL_AUTHENTICATE -> {cmd.hex(' ').upper()}")
    signature, sw = send(cmd)
    if sw != 0x9000:
        if sw == 0x6982:
            raise RuntimeError(
                "INTERNAL_AUTHENTICATE rejected (6982): the document needs an "
                "Active-Authentication key personalised (--aa-key) and the "
                "session must be authenticated (BAC or PACE)."
            )
        raise RuntimeError(f"INTERNAL_AUTHENTICATE failed: SW={sw:04X}")
    log(f"AA signature ({len(signature)} B) = {signature.hex(' ').upper()}")

    kind, key = aa_public_key
    if kind == "EC":
        return _verify_ecdsa(key, challenge, signature)
    return _verify_rsa(key, challenge, signature)


def _decode_sig(signature: bytes, size: int):
    """Decode an ECDSA signature to ``(r, s)`` or ``None``.

    Accepts the DER form Java Card returns (``SEQUENCE { INTEGER r,
    INTEGER s }``) and the fixed ``R || S`` raw form some signers use.
    """
    der = _decode_der_sig(signature)
    if der is not None:
        return der
    if len(signature) == 2 * size:
        r = int.from_bytes(signature[:size], "big")
        s = int.from_bytes(signature[size:], "big")
        return r, s
    return None


def _decode_der_sig(signature: bytes):
    """Decode a DER-encoded ECDSA signature (Java Card ``ALG_ECDSA_SHA*``)."""
    try:
        tag, start, end = read_der_tlv(signature, 0)
        if tag != 0x30 or end != len(signature):
            return None
        values = []
        for t, v in parse_tlvs(signature[start:end]):
            if t != 0x02:
                return None
            values.append(int.from_bytes(v, "big"))
        if len(values) == 2:
            return values[0], values[1]
    except (ValueError, IndexError):
        pass
    return None


def _ecdsa_verify(curve, q: Tuple[int, int], r: int, s: int, e: int) -> bool:
    """Raw ECDSA signature check over digest integer ``e``."""
    order = curve.n
    w = pow(s, -1, order)
    u1 = (e * w) % order
    u2 = (r * w) % order
    g = (curve.gx, curve.gy)
    pt = _ec_point_add(
        _ec_point_mul(u1, g, curve),
        _ec_point_mul(u2, q, curve),
        curve,
    )
    if pt is None:
        return False
    return pt[0] % order == r


def _verify_ecdsa(key, challenge: bytes, signature: bytes) -> ActiveAuthResult:
    """Verify an ECDSA signature in DER or raw ``R || S`` form.

    Java Card signs with either ``ALG_ECDSA_SHA`` (SHA-1) or
    ``ALG_ECDSA_SHA_256`` (SHA-256); the hash is not signalled by the DG15
    key alone, so both digests are tried.  ``key`` is ``(curve, point)`` as
    returned by :func:`parse_dg15_aa_key`.
    """
    curve, point = key
    q = _ec_decode_point(point, curve)
    size = curve.field_size
    rs = _decode_sig(signature, size)
    if rs is None:
        return ActiveAuthResult(
            False,
            challenge,
            signature,
            "malformed ECDSA signature (neither DER nor fixed R||S)",
        )
    r, s = rs
    order = curve.n
    if not (1 <= r < order and 1 <= s < order):
        return ActiveAuthResult(False, challenge, signature, "ECDSA r/s out of range")

    for digest in (
        hashlib.sha256(challenge).digest(),
        hashlib.sha1(challenge).digest(),
    ):
        e = int.from_bytes(digest, "big") % order
        if _ecdsa_verify(curve, q, r, s, e):
            return ActiveAuthResult(True, challenge, signature, None)
    return ActiveAuthResult(
        False, challenge, signature, "ECDSA signature verification failed"
    )


def _verify_rsa(key, challenge: bytes, signature: bytes) -> ActiveAuthResult:
    """Verify a classic RSA-AA raw-RSA signature."""
    n_bytes = key.size_in_bytes()
    if len(signature) != n_bytes:
        return ActiveAuthResult(
            False,
            challenge,
            signature,
            f"signature is {len(signature)} B, expected " f"{n_bytes}",
        )

    # raw-RSA "encrypt" = m^e mod n recovers the plaintext block (the chip
    # signed by computing m^d mod n, i.e. the private-key operation).
    block = pow(int.from_bytes(signature, "big"), key.e, key.n).to_bytes(n_bytes, "big")

    if block[0] != 0x6A or block[-1] != 0xBC:
        return ActiveAuthResult(
            False, challenge, signature, "AA block framing (0x6A/0xBC) invalid"
        )

    # block layout: 0x6A || m1(234) || SHA1(m1||m2)(20) || 0xBC
    m1 = block[1:235]
    stored_hash = block[235:255]
    computed = hashlib.sha1(m1 + challenge).digest()

    ok = computed == stored_hash
    return ActiveAuthResult(
        ok, challenge, signature, None if ok else "SHA1(m1||m2) mismatch"
    )


def make_aa_challenge() -> bytes:
    """Generate an 8-byte Active-Authentication challenge."""
    return secrets.token_bytes(CHALLENGE_LENGTH)
