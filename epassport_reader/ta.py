"""Terminal Authentication (TA) - EAC step 2 (ICAO Doc 9303 Pt 11 / TR-03110).

Runs over the Chip-Authentication AES SM session, following the ICAO standard
flow (all commands under Secure Messaging):

1. ``MSE Set DST`` (INS 0x22, P1/P2 = 0x81B6) selects the CVCA trust-point by
   its Certification Authority Reference (``83 <CAR>``).
2. ``PSO Verify Certificate`` (INS 0x2A, P1/P2 = 0x00BE) imports the terminal's
   certificate chain (one call per certificate).
3. ``MSE Set AT`` (INS 0x22, P1/P2 = 0x81A4) selects the terminal public key by
   its Certificate Holder Reference (``83 <CHR>``).
4. ``GET CHALLENGE`` (INS 0x84) returns an 8-byte challenge ``r_IC``.
5. ``EXTERNAL AUTHENTICATE`` (INS 0x82) carries the ECDSA-SHA-256 signature over
   ``ID_IC || r_IC || Comp(PKDH,IFD)`` signed with the terminal's private key.

The terminal private key is EC (ECDSA). ``ID_IC`` is the IC's compressed PACE
ephemeral public key (under PACE) or the MRZ document number (under BAC).
``Comp(PKDH,IFD)`` is the X-coordinate of the terminal's Chip-Authentication
ephemeral public key recorded during CA.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Tuple

from .pace import ECPrivateKey, _ecdsa_sign_plain
from .sm import SecureMessagingSession
from .tlvs import parse_tlvs

SendFn = Callable[[bytes], Tuple[bytes, int]]
LogFn = Callable[[str], None]

INS_MSE = 0x22
MSE_DST_P1 = 0x81
MSE_DST_P2 = 0xB6  # select CVCA trust-point
MSE_TA_P1 = 0x81
MSE_TA_P2 = 0xA4  # authentication template / select TA
INS_PSO = 0x2A
PSO_VERIFY_CERT_P1 = 0x00
PSO_VERIFY_CERT_P2 = 0xBE
INS_GET_CHALLENGE = 0x84
INS_EXTERNAL_AUTHENTICATE = 0x82

TAG_CAR = 0x42
TAG_CHR = 0x5F20


def parse_cvc_refs(cvc: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Extract ``(CAR, CHR)`` from a CV certificate (PSO form).

    ``CAR`` (tag 0x42) is the issuer reference (the CVCA CAR for a terminal
    certificate signed directly by the CVCA); ``CHR`` (tag 0x5F20) is the
    certificate holder reference. Returns ``(None, None)`` if absent.
    """
    car = None
    chr_ = None
    for tag, value in parse_tlvs(cvc):
        if tag == 0x7F4E:
            for itag, ivalue in parse_tlvs(value):
                if itag == TAG_CAR:
                    car = ivalue
                elif itag == TAG_CHR:
                    chr_ = ivalue
    return car, chr_


def parse_cvc_chain_refs(
    cert_chain: List[bytes],
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Extract ``(trust_car, terminal_chr)`` from a certificate chain.

    ``trust_car`` is the Certification Authority Reference of the first
    certificate (the CVCA link certificate's issuer CAR - the trust-point CAR
    for MSE Set DST). ``terminal_chr`` is the Certificate Holder Reference of
    the last certificate (the terminal key selected by MSE Set AT).
    """
    if not cert_chain:
        return None, None
    trust_car, _ = parse_cvc_refs(cert_chain[0])
    _, terminal_chr = parse_cvc_refs(cert_chain[-1])
    return trust_car, terminal_chr


def _ecdsa_sign_sha256(ec_key: ECPrivateKey, message: bytes) -> bytes:
    """ECDSA-SHA-256 signature in the plain ``R || S`` form (as the applet verifies).

    ``ec_key`` is an :class:`epassport_reader.pace.ECPrivateKey` carrying the
    terminal scalar and brainpoolP256r1 (or P-256) domain parameters, so this
    runs on the pure-Python curve arithmetic (pycryptodome has no brainpool).
    """
    return _ecdsa_sign_plain(ec_key.d, ec_key.curve, message)


def do_terminal_authentication(
    session: SecureMessagingSession,
    send: SendFn,
    cvca_car: bytes,
    cert_chain: List[bytes],
    terminal_key,
    terminal_chr: bytes,
    id_ic: bytes,
    ca_x_icc: bytes,
    log: Optional[LogFn] = None,
) -> None:
    """Run Terminal Authentication over the CA SM ``session``.

    Args:
        session: the upgraded AES session from Chip Authentication.
        send: raw (data, sw) transmit function.
        cvca_car: the CVCA trust-point Certification Authority Reference (DO83
            value for MSE Set DST).
        cert_chain: the terminal certificate chain, one PSO-form CVC per entry.
            A CVCA link certificate (role CVCA) may be the first entry, followed
            by the terminal certificate(s).
        terminal_key: the terminal's EC private key (matches the certificate).
        terminal_chr: the terminal Certificate Holder Reference (DO83 value for
            MSE Set AT).
        id_ic: the ``ID_IC`` bytes (IC's PACE ephemeral X or MRZ document number).
        ca_x_icc: ``Comp(PKDH,IFD)`` - the X-coordinate of the terminal's CA
            ephemeral public key.
    """
    if log is None:
        log = lambda _m: None

    def sm(cmd: bytes) -> bytes:
        resp, sw = send(cmd)
        plain, psw = session.unwrap_response(resp, sw)
        if psw != 0x9000:
            raise RuntimeError(f"TA command failed: SW={psw:04X}")
        return plain

    # 1. MSE Set DST: select the CVCA trust-point by CAR.
    data = b"\x83" + bytes([len(cvca_car)]) + cvca_car
    cmd = session.wrap_command(0x00, INS_MSE, MSE_DST_P1, MSE_DST_P2, data=data)
    log(f"TA MSE Set DST (0x81B6) -> {cmd.hex(' ').upper()}")
    sm(cmd)

    # 2. PSO Verify Certificate: import the terminal certificate chain.
    for cert in cert_chain:
        cmd = session.wrap_command(
            0x00, INS_PSO, PSO_VERIFY_CERT_P1, PSO_VERIFY_CERT_P2, data=cert
        )
        log(f"TA PSO verify cert -> {cmd.hex(' ').upper()}")
        sm(cmd)

    # 3. MSE Set AT: select the terminal public key by CHR.
    data = b"\x83" + bytes([len(terminal_chr)]) + terminal_chr
    cmd = session.wrap_command(0x00, INS_MSE, MSE_TA_P1, MSE_TA_P2, data=data)
    log(f"TA MSE Set AT (0x81A4) -> {cmd.hex(' ').upper()}")
    sm(cmd)

    # 4. GET CHALLENGE.
    cmd = session.wrap_command(0x00, INS_GET_CHALLENGE, 0x00, 0x00, le=8)
    log(f"TA GET CHALLENGE -> {cmd.hex(' ').upper()}")
    rnd = sm(cmd)
    if len(rnd) != 8:
        raise RuntimeError(f"TA GET CHALLENGE returned {len(rnd)} bytes, expected 8")
    log(f"TA challenge r_IC = {rnd.hex(' ').upper()}")

    # 5. EXTERNAL AUTHENTICATE: ECDSA-SHA-256 over ID_IC || r_IC || Comp(PKDH,IFD).
    message = id_ic + rnd + ca_x_icc
    signature = _ecdsa_sign_sha256(terminal_key, message)
    log(f"TA signature over ID_IC||r_IC||Comp(PKDH,IFD) = {signature.hex(' ').upper()}")
    cmd = session.wrap_command(
        0x00, INS_EXTERNAL_AUTHENTICATE, 0x00, 0x00, data=signature
    )
    log(f"TA EXTERNAL AUTHENTICATE -> {cmd.hex(' ').upper()}")
    sm(cmd)
    log("Terminal Authentication OK")
