"""Basic Access Control (BAC) mutual authentication (ICAO 9303 Pt 11 B.2).

BAC is a 3DES / retail-MAC protocol that derives its keys from the MRZ
information (document number, date of birth, date of expiry, each with its
check digit).  It is the classic, universally supported e-passport access
control and is used when no PACE-capable applet is detected.
"""

from __future__ import annotations

import os
from typing import Callable, Optional

from .crypto import (
    derive_bac_keys,
    derive_bac_session_keys,
    retail_mac,
    tdes_cbc_decrypt,
    tdes_cbc_encrypt,
)
from .sm import SecureMessagingSession

SendFn = Callable[[bytes], tuple]

GET_CHALLENGE = bytes.fromhex("0084000008")
EXTERNAL_AUTH_PREFIX = bytes.fromhex("0082000028")
EXTERNAL_AUTH_LE = bytes.fromhex("28")  # expect 40-byte response (e_icc + m_icc)


def do_bac(
    send: SendFn,
    mrz_info: bytes,
    log: Optional[Callable[[str], None]] = None,
) -> SecureMessagingSession:
    """Run the BAC handshake over ``send`` and return an SM session.

    ``send`` is ``callable(apdu_bytes) -> (response_data, sw)`` where
    ``sw`` is the 2-byte status word as an int.
    """
    if log is None:
        log = lambda _msg: None

    # 1. GET CHALLENGE -> RND.ICC (8 bytes)
    data, sw = send(GET_CHALLENGE)
    if sw != 0x9000 or len(data) != 8:
        raise RuntimeError(f"BAC GET CHALLENGE failed: SW={sw:04X}")
    rnd_icc = data

    kseed, kenc, kmac = derive_bac_keys(mrz_info)
    log(f"BAC KEnc = {kenc.hex(' ').upper()}")
    log(f"BAC KMac = {kmac.hex(' ').upper()}")

    # 2. Build and send E.IFD / M.IFD
    rnd_ifd = os.urandom(8)
    k_ifd = os.urandom(16)
    e_ifd = tdes_cbc_encrypt(kenc, rnd_ifd + rnd_icc + k_ifd)
    m_ifd = retail_mac(kmac, e_ifd)

    data, sw = send(EXTERNAL_AUTH_PREFIX + e_ifd + m_ifd + EXTERNAL_AUTH_LE)
    if sw != 0x9000 or len(data) != 40:
        raise RuntimeError(
            f"BAC EXTERNAL AUTHENTICATE failed: SW={sw:04X}, len={len(data)}"
        )

    # 3. Unwrap E.ICC / M.ICC
    e_icc, m_icc = data[:32], data[32:]
    if retail_mac(kmac, e_icc) != m_icc:
        raise RuntimeError("BAC response MAC verification failed")

    clear = tdes_cbc_decrypt(kenc, e_icc)
    if clear[:8] != rnd_icc or clear[8:16] != rnd_ifd:
        raise RuntimeError("BAC challenge binding mismatch")
    k_icc = clear[16:32]

    # 4. Derive session keys + SSC
    ksenc, ksmac = derive_bac_session_keys(k_icc, k_ifd)
    ssc = rnd_icc[4:] + rnd_ifd[4:]

    log("BAC mutual authentication OK")
    log(f"BAC KSEnc = {ksenc.hex(' ').upper()}")
    log(f"BAC KSMac = {ksmac.hex(' ').upper()}")
    return SecureMessagingSession("BAC", ksenc, ksmac, ssc)
