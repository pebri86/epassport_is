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
* **ECDSA** (ECDSA-P256 AA, e.g. the applet): the chip signs the challenge
  with ECDSA (Java Card ``ALG_ECDSA_SHA`` = SHA-1) and returns a plain
  ``R || S`` signature. The terminal verifies it with the DG15 EC public key.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Callable, NamedTuple, Optional, Tuple

from Crypto.Hash import SHA1
from Crypto.PublicKey import ECC, RSA
from Crypto.PublicKey.ECC import _curves as _ECC_CURVES

from .sm import SecureMessagingSession
from .tlvs import read_der_tlv

SendFn = Callable[[bytes], Tuple[bytes, int]]
LogFn = Callable[[str], None]

INS_INTERNAL_AUTHENTICATE = 0x88
RSA_MODULUS_LENGTH = 256  # RSA-2048 AA block
CHALLENGE_LENGTH = 8


class ActiveAuthResult(NamedTuple):
    """Outcome of an Active-Authentication exchange."""

    verified: bool
    challenge: bytes  # m2 (the challenge the terminal sent)
    signature: bytes  # the chip's signature (raw-RSA or ECDSA R||S)
    reason: Optional[str]


def parse_dg15_aa_key(dg15: bytes) -> Tuple[str, object]:
    """Parse the EF.DG15 (tag 0x6F -> SPKI) Active-Authentication key.

    Returns ``("RSA", key)`` or ``("EC", key)`` depending on the SPKI
    algorithm. The EC key is a P-256 (or other NIST/brainpool) ECC key.
    """
    if not dg15 or dg15[0] != 0x6F:
        raise ValueError("DG15 does not start with LDS tag 0x6F")
    tag, start, end = read_der_tlv(dg15, 0)
    if tag != 0x6F or end != len(dg15):
        raise ValueError("Invalid DG15 outer structure")
    spki = dg15[start:end]
    try:
        return "RSA", RSA.import_key(spki)  # DER SubjectPublicKeyInfo (RSA)
    except ValueError:
        pass
    try:
        return "EC", ECC.import_key(spki)  # DER SubjectPublicKeyInfo (EC)
    except (ValueError, TypeError):
        pass
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


def _verify_ecdsa(key, challenge: bytes, signature: bytes) -> ActiveAuthResult:
    """Verify an ECDSA-SHA (SHA-1) signature in plain ``R || S`` form.

    Java Card signs with ``ALG_ECDSA_SHA`` (SHA-1) regardless of curve size, so
    pycryptodome's ``DSS`` (which rejects SHA-1 for 256-bit keys) cannot be
    used; verify the signature directly with the curve arithmetic instead.
    """
    curve = _ECC_CURVES[key.pointQ.curve]
    order = int(curve.order)
    size = key.pointQ.size_in_bytes()
    if len(signature) != 2 * size:
        return ActiveAuthResult(
            False,
            challenge,
            signature,
            f"signature is {len(signature)} B, expected {2 * size} B (R||S)",
        )
    r = int.from_bytes(signature[:size], "big")
    s = int.from_bytes(signature[size : 2 * size], "big")
    if not (1 <= r < order and 1 <= s < order):
        return ActiveAuthResult(False, challenge, signature, "ECDSA r/s out of range")

    e = int.from_bytes(SHA1.new(challenge).digest(), "big")
    w = pow(s, -1, order)
    u1 = (e * w) % order
    u2 = (r * w) % order
    point = u1 * curve.G + u2 * key.pointQ
    v = int(point.x) % order
    ok = v == r
    return ActiveAuthResult(
        ok, challenge, signature, None if ok else "ECDSA signature verification failed"
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
