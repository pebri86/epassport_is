"""Chip Authentication (CA) - EAC step 1 (ICAO Doc 9303 Pt 11 / TR-03110).

CA is a single-step key agreement that upgrades the PACE/BAC SM session to
fresh session keys derived from an ECDH shared secret, following the ICAO
standard flow:

1. ``MSE Set AT`` (INS 0x22, P1/P2 = 0x41A4) selects the CA protocol, carrying
   the CA OID (``80 <oid>``) and optional key reference (``84 01 <keyRef>``).
   This runs *under* the established SM session.
2. ``GENERAL AUTHENTICATE`` (INS 0x86, P1/P2 = 0x0000) carries the terminal's
   ephemeral public key in a ``7C { 86 <point> }`` Dynamic Authentication Data
   object, also under SM.
3. Both sides compute the ECDH shared secret and derive the CA SM session keys
   (AES-128: ``KSEnc = SHA1(Z || 0x00000001)``, ``KSMac = SHA1(Z || 0x00000002)``,
   truncated to 16 bytes, no parity adjustment) where Z is the X-coordinate of
   the shared point.
4. The terminal returns a new :class:`SecureMessagingSession` (PACE/AES
   flavour) whose SSC restarts at zero.

The chip's CA public key (and its curve) is read from EF.DG14 by
:func:`epassport_reader.cvc.parse_chip_auth_data`.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Callable, NamedTuple, Optional, Tuple

from .pace import (
    EC_P256,
    _ec_decode_point,
    _ec_encode_point,
    _ec_point_mul,
)
from .sm import SecureMessagingSession

SendFn = Callable[[bytes], Tuple[bytes, int]]
LogFn = Callable[[str], None]

MSE_SET_AT_INS = 0x22
MSE_CA_P1 = 0x41  # set for computation / CA selection
MSE_CA_P2 = 0xA4  # authentication template
GENERAL_AUTH_INS = 0x86

# id-CA-ECDH-AES-CBC-CMAC-128 / -256 (ICAO Doc 9303-11 §6.2.4.2)
CA_OID_CMAC_128 = bytes.fromhex("04007F00070202030202")
CA_OID_CMAC_256 = bytes.fromhex("04007F00070202030204")


def ca_mse_oid(key_bits: int) -> bytes:
    return CA_OID_CMAC_256 if key_bits == 256 else CA_OID_CMAC_128


class ChipAuthResult(NamedTuple):
    """Outcome of a Chip-Authentication exchange.

    ``session`` is the upgraded AES SM session (SSC restarted at zero).
    ``ifd_public`` / ``ifd_scalar`` keep the terminal's ephemeral key so a
    later Terminal-Authentication signature can reuse the same X-coordinate
    that the chip recorded.
    """

    session: SecureMessagingSession
    ifd_public: bytes
    ifd_scalar: int


def derive_ca_keys(shared_secret: bytes, key_bits: int = 256) -> Tuple[bytes, bytes]:
    """Derive ``(KEnc, KMac)`` from the ECDH shared-secret X-coordinate.

    Matches the CA session-key derivation of the chip's ``id-CA-*`` OID:

    * AES-256 (CMAC-256, this applet / EAC v2): ``KSEnc/KSMac =
      SHA-256(Z || 0x0000000X)`` (32 bytes), per ICAO Doc 9303-11 §9.7.x.
    * AES-128 (CMAC-128): ``SHA-1(Z || 0x0000000X)`` truncated to 16 bytes.
    """
    if key_bits == 256:
        kenc = hashlib.sha256(shared_secret + b"\x00\x00\x00\x01").digest()
        kmac = hashlib.sha256(shared_secret + b"\x00\x00\x00\x02").digest()
    else:
        kenc = hashlib.sha1(shared_secret + b"\x00\x00\x00\x01").digest()[:16]
        kmac = hashlib.sha1(shared_secret + b"\x00\x00\x00\x02").digest()[:16]
    return kenc, kmac


def _do_ca_exchange(
    session: SecureMessagingSession,
    send: SendFn,
    chip_public_key: bytes,
    key_ref: bytes,
    log: LogFn,
    curve: object = EC_P256,
    key_bits: int = 256,
) -> ChipAuthResult:
    """Run the ICAO-standard CA exchange against an established SM ``session``."""
    # 1. generate the terminal's ephemeral key pair on the chip's curve
    d_ifd = secrets.randbelow(curve.n - 1) + 1
    g = (curve.gx, curve.gy)
    q_ifd = _ec_encode_point(_ec_point_mul(d_ifd, g, curve), curve)

    # 2. MSE Set AT (0x41A4) selects the CA protocol, under SM
    ref = key_ref[:1] if key_ref else b"\x00"
    ca_oid = ca_mse_oid(key_bits)
    data = b"\x80" + bytes([len(ca_oid)]) + ca_oid + b"\x84\x01" + ref
    cmd = session.wrap_command(0x00, MSE_SET_AT_INS, MSE_CA_P1, MSE_CA_P2, data=data)
    log(f"CA MSE Set AT (0x41A4) -> {cmd.hex(' ').upper()}")
    resp, sw = send(cmd)
    plain, psw = session.unwrap_response(resp, sw)
    log(f"CA MSE response: SW={psw:04X} plain={plain.hex(' ').upper()}")
    if psw != 0x9000:
        raise RuntimeError(f"Chip Authentication MSE Set AT failed: SW={psw:04X}")

    # 3. GENERAL AUTHENTICATE with the terminal's ephemeral key, under SM
    ga = b"\x7c" + bytes([2 + len(q_ifd)]) + b"\x86" + bytes([len(q_ifd)]) + q_ifd
    cmd = session.wrap_command(0x00, GENERAL_AUTH_INS, 0x00, 0x00, data=ga)
    log(f"CA GENERAL AUTHENTICATE -> {cmd.hex(' ').upper()}")
    resp, sw = send(cmd)
    plain, psw = session.unwrap_response(resp, sw)
    log(f"CA GENERAL AUTH response: SW={psw:04X} plain={plain.hex(' ').upper()}")
    if psw != 0x9000:
        raise RuntimeError(
            f"Chip Authentication GENERAL AUTHENTICATE failed: SW={psw:04X}"
        )

    # 4. shared secret Z = X(d_IFD * Q_chip), chip derives d_chip * Q_IFD
    chip_point = _ec_decode_point(chip_public_key, curve)
    shared_point = _ec_point_mul(d_ifd, chip_point, curve)
    if shared_point is None:
        raise RuntimeError("Chip Authentication ECDH produced point at infinity")
    z = shared_point[0].to_bytes(curve.field_size, "big")

    # 5. derive AES CA session keys and start a fresh PACE session (SSC = 0)
    kenc, kmac = derive_ca_keys(z, key_bits)
    log(f"CA KSEnc ({len(kenc) * 8}-bit) = {kenc.hex(' ').upper()}")
    log(f"CA KSMac ({len(kmac) * 8}-bit) = {kmac.hex(' ').upper()}")
    new_session = SecureMessagingSession("PACE", kenc, kmac, b"\x00" * 16)
    # Preserve the IC's PACE ephemeral X (ID_IC for Terminal Authentication);
    # CA re-keys the channel but ID_IC is bound to the PACE session.
    if hasattr(session, "pace_icc_eph_x"):
        new_session.pace_icc_eph_x = session.pace_icc_eph_x
    return ChipAuthResult(new_session, q_ifd, d_ifd)


def do_chip_authentication(
    session: SecureMessagingSession,
    send: SendFn,
    chip_public_key: bytes,
    key_ref: bytes = b"",
    log: Optional[LogFn] = None,
    curve: object = EC_P256,
    key_bits: int = 256,
) -> ChipAuthResult:
    """Perform Chip Authentication over an established SM session.

    ``session`` must be an active BAC or PACE SM session (its own SSC is
    advanced by wrapping the MSE/GENERAL AUTHENTICATE commands and unwrapping
    the responses). The returned :class:`ChipAuthResult.session` replaces it
    for all subsequent commands. ``key_ref`` is the chip's CA key reference
    (from EF.DG14) used in the MSE key-reference tag; empty defaults to 0.
    ``curve`` must match the chip's CA public key domain (from EF.DG14).
    ``key_bits`` (128 or 256) is the CA AES session-key size advertised by the
    chip's ``id-CA-ECDH-AES-CBC-CMAC-*`` OID in EF.DG14.
    """
    if log is None:
        log = lambda _m: None
    return _do_ca_exchange(session, send, chip_public_key, key_ref, log, curve, key_bits)
