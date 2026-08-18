"""Cryptographic primitives for ICAO Doc 9303 eMRTD terminal sessions.

Implements everything needed for BAC (3DES / retail-MAC) and PACE
(AES-CMAC / AES-CBC) secure messaging exactly as required by ICAO 9303
Part 11, using only pycryptodome (Crypto.*) as a dependency.

The primitives are kept dependency-light on purpose: the file only uses
``Crypto.Cipher`` and ``Crypto.Hash`` so the rest of the package stays
portable.
"""

from __future__ import annotations

import hashlib
from typing import Tuple

from Crypto.Cipher import AES, DES
from Crypto.Hash import CMAC

# ---------------------------------------------------------------------------
# Padding (ISO/IEC 9797-1 method 2, "80 00 ...")
# ---------------------------------------------------------------------------


def pad80(data: bytes, block_size: int = 8) -> bytes:
    """Append ``0x80`` followed by enough ``0x00`` bytes to align to block."""
    out = data + b"\x80"
    out += b"\x00" * ((-len(out)) % block_size)
    return out


def unpad80(data: bytes) -> bytes:
    """Remove ISO/IEC 9797-1 method 2 padding."""
    i = len(data) - 1
    while i >= 0 and data[i] == 0:
        i -= 1
    if i < 0 or data[i] != 0x80:
        raise ValueError("invalid ISO9797-1 method 2 padding")
    return data[:i]


# ---------------------------------------------------------------------------
# DES / 3DES (2-key EDE2) helpers
# ---------------------------------------------------------------------------


def odd_parity(key: bytes) -> bytes:
    """Force odd parity on every DES key byte (ICAO key derivation)."""
    out = bytearray()
    for b in key:
        v = b & 0xFE
        if v.bit_count() % 2 == 0:
            v |= 1
        out.append(v)
    return bytes(out)


def tdes_ede2_encrypt_block(key: bytes, block: bytes) -> bytes:
    k1, k2 = key[:8], key[8:]
    x = DES.new(k1, DES.MODE_ECB).encrypt(block)
    x = DES.new(k2, DES.MODE_ECB).decrypt(x)
    return DES.new(k1, DES.MODE_ECB).encrypt(x)


def tdes_ede2_decrypt_block(key: bytes, block: bytes) -> bytes:
    k1, k2 = key[:8], key[8:]
    x = DES.new(k1, DES.MODE_ECB).decrypt(block)
    x = DES.new(k2, DES.MODE_ECB).encrypt(x)
    return DES.new(k1, DES.MODE_ECB).decrypt(x)


def tdes_cbc_encrypt(key: bytes, data: bytes, iv: bytes = None) -> bytes:
    if len(data) % 8:
        raise ValueError("3DES CBC input must be block aligned")
    out = bytearray()
    chain = iv if iv is not None else b"\x00" * 8
    for i in range(0, len(data), 8):
        block = bytes(a ^ b for a, b in zip(data[i : i + 8], chain))
        c = tdes_ede2_encrypt_block(key, block)
        out.extend(c)
        chain = c
    return bytes(out)


def tdes_cbc_decrypt(key: bytes, data: bytes, iv: bytes = None) -> bytes:
    if len(data) % 8:
        raise ValueError("3DES CBC input must be block aligned")
    out = bytearray()
    chain = iv if iv is not None else b"\x00" * 8
    for i in range(0, len(data), 8):
        c = data[i : i + 8]
        p = tdes_ede2_decrypt_block(key, c)
        p = bytes(a ^ b for a, b in zip(p, chain))
        out.extend(p)
        chain = c
    return bytes(out)


def retail_mac(key: bytes, data: bytes) -> bytes:
    """ISO/IEC 9797-1 MAC Algorithm 3 (Retail MAC), 8-byte output."""
    padded = pad80(data, 8)
    k1, k2 = key[:8], key[8:]

    state = b"\x00" * 8
    for i in range(0, len(padded), 8):
        block = bytes(a ^ b for a, b in zip(padded[i : i + 8], state))
        state = DES.new(k1, DES.MODE_ECB).encrypt(block)

    state = DES.new(k2, DES.MODE_ECB).decrypt(state)
    return DES.new(k1, DES.MODE_ECB).encrypt(state)


# ---------------------------------------------------------------------------
# AES helpers
# ---------------------------------------------------------------------------


def aes_ecb_encrypt(key: bytes, value: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(value)


def aes_ecb_decrypt(key: bytes, value: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(value)


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(plaintext)


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)


def cmac8(key: bytes, data: bytes) -> bytes:
    """AES-CMAC truncated to 8 bytes (PACE SM integrity)."""
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()[:8]


# ---------------------------------------------------------------------------
# MRZ / key derivation helpers
# ---------------------------------------------------------------------------

MRZ_WEIGHTS = (7, 3, 1)


def check_digit(value: str) -> int:
    """ICAO 9303 check digit (weights 7, 3, 1, mod 10)."""
    total = 0
    for i, ch in enumerate(value):
        if ch.isdigit():
            v = ord(ch) - 48
        elif "A" <= ch <= "Z":
            v = ord(ch) - 65 + 10
        elif ch == "<":
            v = 0
        else:
            raise ValueError(f"bad MRZ character: {ch!r}")
        total += v * MRZ_WEIGHTS[i % 3]
    return total % 10


def normalize_mrz_field(value: str, length: int) -> str:
    """Trim to ``length`` chars, padding with '<' and appending check digit.

    Used to turn the short GUI inputs (e.g. ``A12345678``, ``990922``,
    ``221231``) into the full MRZ sub-fields used for key derivation.
    """
    value = value.replace(" ", "<").upper()
    value = value[:length]
    value = value.ljust(length, "<")
    return value + str(check_digit(value))


def build_mrz_info(doc_number: str, dob: str, expiry: str) -> bytes:
    """Concatenate doc-number/DOB/expiry with check digits (MRZ-information).

    Each input is accepted with or without its trailing check digit:
    a 9-char document number gets one appended, a 10-char one is used as-is.
    """
    doc = doc_number.upper().replace(" ", "<")
    if len(doc) == 9:
        doc += str(check_digit(doc))
    elif len(doc) != 10:
        raise ValueError(
            "document number must be 9 or 10 characters (check digit optional)"
        )

    dob = dob.strip()
    if len(dob) == 6 and dob.isdigit():
        dob += str(check_digit(dob))
    elif len(dob) != 7:
        raise ValueError("date of birth must be YYMMDD (or YYMMDD+check digit)")

    expiry = expiry.strip()
    if len(expiry) == 6 and expiry.isdigit():
        expiry += str(check_digit(expiry))
    elif len(expiry) != 7:
        raise ValueError("date of expiry must be YYMMDD (or YYMMDD+check digit)")

    return (doc + dob + expiry).encode("ascii")


def derive_bac_keys(mrz_info: bytes) -> Tuple[bytes, bytes, bytes]:
    """Derive (kseed, KEnc, KMac) from the MRZ-information per ICAO 9303 Pt 11."""
    kseed = hashlib.sha1(mrz_info).digest()[:16]
    kenc = odd_parity(hashlib.sha1(kseed + b"\x00\x00\x00\x01").digest()[:16])
    kmac = odd_parity(hashlib.sha1(kseed + b"\x00\x00\x00\x02").digest()[:16])
    return kseed, kenc, kmac


def derive_bac_session_keys(kicc: bytes, kifd: bytes) -> Tuple[bytes, bytes]:
    """Derive session KSEnc / KSMac from the XOR of both session key parts."""
    kseed = bytes(a ^ b for a, b in zip(kicc, kifd))
    ksenc = odd_parity(hashlib.sha1(kseed + b"\x00\x00\x00\x01").digest()[:16])
    ksmac = odd_parity(hashlib.sha1(kseed + b"\x00\x00\x00\x02").digest()[:16])
    return ksenc, ksmac


def derive_pace_key(password: bytes) -> bytes:
    """PACE password-mapping key K_PI.

    This matches the PassportApplet PACE implementation in this repository
    (``SHA1(password || 0x00000003)[:16]``).  Real ICAO documents use the
    standard ``K_PI = hash(password || 0x00000003)`` with the same truncation
    for P-256 (16 bytes), so this is interoperable with ICAO PACE-MRZ too.
    """
    return hashlib.sha1(password + b"\x00\x00\x00\x03").digest()[:16]


def derive_pace_key_mrz(mrz_info: bytes) -> bytes:
    """PACE-MRZ password-mapping key K_PI (standard double-hash).

    The ICAO PACE-MRZ key is derived from the MRZ-information as
    ``K_PI = SHA1(SHA1(MRZ_info) || 0x00000003)[0:16]`` (see the applet's
    PersonalizationManager.derivePaceKeyFromMrz and PacePasswordTest).
    ``mrz_info`` must be the 24-byte concatenation of document number, date
    of birth and date of expiry, each with its check digit (build_mrz_info).
    """
    seed = hashlib.sha1(mrz_info).digest()[:20]
    return hashlib.sha1(seed + b"\x00\x00\x00\x03").digest()[:16]


def inc_ssc(ssc: bytearray) -> None:
    """Increment an 8/16 byte send sequence counter in place."""
    for i in range(len(ssc) - 1, -1, -1):
        if ssc[i] == 0xFF:
            ssc[i] = 0
        else:
            ssc[i] += 1
            return
