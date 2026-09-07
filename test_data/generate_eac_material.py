#!/usr/bin/env python3
"""Generate EAC (Terminal Authentication) test material into test_data/.

Produces a self-consistent CVCA -> DV -> IS certificate chain on
**brainpoolP256r1** (matching the applet's Terminal-Authentication domain) so
the terminal can run Terminal Authentication against the applet:

  * cvca_ec_key.pem        - CVCA private key (kept in the issuing env)
  * cvca_selfsigned.cvcert - self-signed CVCA certificate (CAR UTSTCVCA00001)
  * dv_ec_key.pem          - DV private key
  * dv.cvc                 - DV certificate, signed by the CVCA
  * terminal_ec_key.pem    - terminal (IS) private key
  * terminal.cvc           - IS certificate, signed by the DV

Chain used during Terminal Authentication: [dv.cvc, terminal.cvc].  The applet
must be (re)personalized with ``cvca_selfsigned.cvcert`` so the chain verifies
against the card's trust point.

``--link`` additionally generates a **CVCA link-certificate (rotation) kit**,
chained to the SAME CVCA1 key so it works against an already-personalized card:

  * cvca2_ec_key.pem  - new CVCA (CVCA2) private key (brainpoolP256r1)
  * cvca_link.cvc     - link cert: CVCA1 certifies CVCA2's public key
                        (issuer CAR=UTSTCVCA00001, holder CHR=UTSTCVCA00002,
                        role CVCA) -- the first PSO VERIFY rotates the trust
                        point to CVCA2
  * dv2_ec_key.pem / dv2.cvc - DV signed by CVCA2 (CHR UTSDV00002)
  * terminal2_ec_key.pem / terminal2.cvc - IS signed by DV2 (CHR TERM0002)

Rotation chain sent during TA: [cvca_link.cvc, dv2.cvc, terminal2.cvc] with
the terminal key ``terminal2_ec_key.pem``.

The applet's TA verification runs on brainpoolP256r1; pycryptodome cannot
represent brainpool keys, so this tool uses the ``cryptography`` package to
generate the keys and produce the fixed-size plain ``R || S`` ECDSA-SHA-256
signatures the card's ``ECDSAPlainVerifier`` expects.

Usage:
    .venv/bin/python test_data/generate_eac_material.py [--link] [--force]
"""

from __future__ import annotations

import argparse
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# brainpoolP256r1 (RFC 5639) explicit domain parameters, 32 bytes each.
_BP_P = bytes.fromhex(
    "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377")
_BP_A = bytes.fromhex(
    "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9")
_BP_B = bytes.fromhex(
    "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6")
_BP_GX = bytes.fromhex(
    "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262")
_BP_GY = bytes.fromhex(
    "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997")
_BP_N = bytes.fromhex(
    "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7")

FIELD_SIZE = 32   # bytes per coordinate / scalar component on brainpoolP256r1

OID_EC_PUBLIC_KEY = bytes.fromhex("2A8648CE3D0201")
OID_ROLE_CVCA = bytes.fromhex("04007F00070202020201")  # id-RoleOfCVCA
OID_ROLE_DV = bytes.fromhex("04007F00070202020202")    # id-RoleOfDV
OID_ROLE_IS = bytes.fromhex("04007F00070202020203")    # id-RoleOfIS (terminal)

CVCA_CAR = b"UTSTCVCA00001"
CVCA2_CAR = b"UTSTCVCA00002"
DV_CHR = b"UTSDV00001"
DV2_CHR = b"UTSDV00002"
TERMINAL_CHR = b"TERM0001"
TERMINAL2_CHR = b"TERM0002"
DATE_EFF = bytes.fromhex("001A00010001")  # 2026-01-01
DATE_EXP = bytes.fromhex("001E00010001")  # 2030-01-01

# CHAT tag 0x53 carries two bytes: [role category][access rights]. The applet
# derives the certificate type from the category byte's top bits and grants
# DG3/DG4 reads from the access-rights byte (DG3=0x01, DG4=0x02).
ROLE_CVCA = 0xC0   # category byte: top two bits set => CVCA
ROLE_DV = 0x80     # category byte: 0x80 set, 0x40 clear => DV
ROLE_IS = 0x00     # category byte: 0x80 clear => IS
RIGHTS_CVCA = 0xFF
RIGHTS_DV = 0x03
RIGHTS_IS = 0x03   # DG3 + DG4


def _b32(n: int) -> bytes:
    return n.to_bytes(FIELD_SIZE, "big")


def _tlv(tag: int, value: bytes) -> bytes:
    """Minimal BER TLV encoder (multi-byte tags, short/long-form lengths)."""
    tag_bytes = bytes([tag]) if tag <= 0xFF else tag.to_bytes((tag.bit_length() + 7) // 8, "big")
    n = len(value)
    if n < 0x80:
        return tag_bytes + bytes([n]) + value
    if n <= 0xFF:
        return tag_bytes + bytes([0x81, n]) + value
    return tag_bytes + bytes([0x82, (n >> 8) & 0xFF, n & 0xFF]) + value


def _point_from_key(key) -> bytes:
    pub = key.public_key().public_numbers()
    return b"\x04" + _b32(pub.x) + _b32(pub.y)


def _cvc_body(
    car: bytes, chr_: bytes, subject_public_point: bytes, role_oid: bytes, role: int, rights: int
) -> bytes:
    # Public key: only the EC point (tag 86). The applet verifies on its own
    # configured brainpoolP256r1 domain (TrustStore / DomainParameterManager),
    # so the certificate does not need to embed the explicit domain parameters
    # (tags 81-85). Omitting them keeps each certificate ~210 bytes so the SM
    # PSO:VERIFY command fits a short APDU.
    pk = _tlv(0x7F49, _tlv(0x86, subject_public_point))
    chat = _tlv(0x7F4C, _tlv(0x06, role_oid) + _tlv(0x53, bytes([role, rights])))
    return b"".join(
        (
            _tlv(0x5F29, b"\x00"),
            _tlv(0x42, car),
            _tlv(0x5F20, chr_),
            pk,
            _tlv(0x5F25, DATE_EFF),
            _tlv(0x5F24, DATE_EXP),
            chat,
        )
    )


def _der_decode_sig(der: bytes):
    """Decode a DER ECDSA signature into (r, s) integers."""
    assert der[0] == 0x30
    i = 2
    assert der[i] == 0x02
    rl = der[i + 1]
    r = int.from_bytes(der[i + 2:i + 2 + rl], "big")
    i += 2 + rl
    assert der[i] == 0x02
    sl = der[i + 1]
    s = int.from_bytes(der[i + 2:i + 2 + sl], "big")
    return r, s


def _ecdsa_sign_plain(issuer_key, body: bytes) -> bytes:
    """ECDSA-SHA-256 returning fixed 32-byte R || S (card plain form)."""
    der = issuer_key.sign(body, ec.ECDSA(hashes.SHA256()))
    r, s = _der_decode_sig(der)
    return _b32(r) + _b32(s)


def build_cvc(
    issuer_key,
    car: bytes,
    chr_: bytes,
    role_oid: bytes,
    role: int,
    rights: int,
    subject_public_point: bytes,
) -> bytes:
    """Build a PSO-form certificate: ``7F4E <body> 5F37 <sig>``.

    The ECDSA-SHA-256 signature covers the CVCertificateBody *value* (the
    content of the 7F4E element, i.e. tags 5F29..7F4C) — the applet hashes
    ``bodyOffset..bodyOffset+bodyLength``, which excludes the 7F4E tag/len.
    """
    body = _cvc_body(car, chr_, subject_public_point, role_oid, role, rights)
    sig = _ecdsa_sign_plain(issuer_key, body)
    return _tlv(0x7F4E, body) + _tlv(0x5F37, sig)


def build_selfsigned_cvca(cvca_key, car: bytes = CVCA_CAR) -> bytes:
    """Self-signed CVCA certificate (provisioned into the applet as trust point)."""
    return build_cvc(
        cvca_key, car, car, OID_ROLE_CVCA, ROLE_CVCA, RIGHTS_CVCA,
        _point_from_key(cvca_key),
    )


def new_bp_key():
    return ec.generate_private_key(ec.BrainpoolP256R1())


def save_pem(key, path: str) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(
        description="Generate EAC test material (CVCA + DV + IS chain, brainpoolP256r1)."
    )
    parser.add_argument(
        "--link", action="store_true",
        help="also generate the CVCA link-certificate (rotation) kit: CVCA2 + DV2 + terminal2",
    )
    parser.add_argument(
        "--force", action="store_true", help="regenerate keys even if they exist"
    )
    args = parser.parse_args()

    # Reuse existing CVCA key when present so the card's trust point does not
    # have to change on every regeneration.
    def _load(path: str):
        try:
            with open(path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        except OSError:
            return None

    cvca_key = _load(os.path.join(here, "cvca_ec_key.pem")) if not args.force else None
    cvca_key = cvca_key or new_bp_key()
    dv_key = new_bp_key()
    term_key = new_bp_key()

    cvca_cert = build_selfsigned_cvca(cvca_key)
    dv_cvc = build_cvc(
        cvca_key, CVCA_CAR, DV_CHR, OID_ROLE_DV, ROLE_DV, RIGHTS_DV,
        _point_from_key(dv_key),
    )
    terminal_cvc = build_cvc(
        dv_key, DV_CHR, TERMINAL_CHR, OID_ROLE_IS, ROLE_IS, RIGHTS_IS,
        _point_from_key(term_key),
    )

    save_pem(cvca_key, os.path.join(here, "cvca_ec_key.pem"))
    save_pem(dv_key, os.path.join(here, "dv_ec_key.pem"))
    save_pem(term_key, os.path.join(here, "terminal_ec_key.pem"))

    files = {
        "cvca_selfsigned.cvcert": cvca_cert,
        "dv.cvc": dv_cvc,
        "terminal.cvc": terminal_cvc,
    }

    link_note = []
    if args.link:
        # CVCA link certificate: CVCA1 (CAR=UTSTCVCA00001) certifies CVCA2's key.
        # Issuer CAR stays the old reference, holder CHR is the new reference.
        cvca2_key = new_bp_key()
        dv2_key = new_bp_key()
        term2_key = new_bp_key()

        cvca_link = build_cvc(
            cvca_key, CVCA_CAR, CVCA2_CAR, OID_ROLE_CVCA, ROLE_CVCA, RIGHTS_CVCA,
            _point_from_key(cvca2_key),
        )
        dv2_cvc = build_cvc(
            cvca2_key, CVCA2_CAR, DV2_CHR, OID_ROLE_DV, ROLE_DV, RIGHTS_DV,
            _point_from_key(dv2_key),
        )
        terminal2_cvc = build_cvc(
            dv2_key, DV2_CHR, TERMINAL2_CHR, OID_ROLE_IS, ROLE_IS, RIGHTS_IS,
            _point_from_key(term2_key),
        )

        save_pem(cvca2_key, os.path.join(here, "cvca2_ec_key.pem"))
        save_pem(dv2_key, os.path.join(here, "dv2_ec_key.pem"))
        save_pem(term2_key, os.path.join(here, "terminal2_ec_key.pem"))

        files.update(
            {
                "cvca_link.cvc": cvca_link,
                "dv2.cvc": dv2_cvc,
                "terminal2.cvc": terminal2_cvc,
            }
        )
        link_note = [
            f"CVCA2 CAR : {CVCA2_CAR.decode()}",
            f"DV2 CHR   : {DV2_CHR.decode()}",
            f"Terminal2 : {TERMINAL2_CHR.decode()} (rights 0x{RIGHTS_IS:02x})",
            "",
            "Rotation chain for Terminal Authentication (select in order):",
            f"  1. {os.path.join(here, 'cvca_link.cvc')}",
            f"  2. {os.path.join(here, 'dv2.cvc')}",
            f"  3. {os.path.join(here, 'terminal2.cvc')}",
            f"key = {os.path.join(here, 'terminal2_ec_key.pem')}",
        ]

    for name, data in files.items():
        path = os.path.join(here, name)
        with open(path, "wb") as f:
            f.write(data)
        print(f"wrote {os.path.relpath(path)} ({len(data)} B)")

    print(f"\nCVCA CAR    : {CVCA_CAR.decode()}")
    print(f"DV CHR      : {DV_CHR.decode()}")
    print(f"Terminal CHR: {TERMINAL_CHR.decode()} (rights 0x{RIGHTS_IS:02x})")
    print(f"Curve       : brainpoolP256r1")
    print("\nChain for Terminal Authentication (select both .cvc files in order):")
    print(f"  1. {os.path.join(here, 'dv.cvc')}")
    print(f"  2. {os.path.join(here, 'terminal.cvc')}")
    print(f"key = {os.path.join(here, 'terminal_ec_key.pem')}")
    if link_note:
        print()
        print("\n".join(link_note))
    print("\nTo use against the applet, (re)personalize it with:")
    print(f"  {os.path.join(here, 'cvca_selfsigned.cvcert')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
