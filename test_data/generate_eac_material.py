#!/usr/bin/env python3
"""Generate EAC (Terminal Authentication) test material into test_data/.

Produces a self-consistent CVCA + terminal certificate kit on NIST P-256
(secp256r1) so the terminal can run Terminal Authentication against the
applet:

  * cvca_ec_key.pem        - CVCA private key (kept in the issuing env)
  * cvca_selfsigned.cvcert - self-signed CVCA certificate (CAR UTSTCVCA00001)
  * terminal_ec_key.pem    - terminal (IS) private key
  * terminal.cvc           - terminal certificate, signed by the CVCA

The applet must be (re)personalized with the generated
``cvca_selfsigned.cvcert`` so the terminal certificate verifies against the
card's trust point (replace ``test_data/UTSTCVCA00001.selfsigned.cvcert`` and
re-run personalization, or provision the CVCA public key + CAR directly).

``--link`` additionally generates a CVCA link-certificate test kit, chained to
the SAME CVCA1 key so it works against an already-personalized card:

  * cvca2_ec_key.pem   - new CVCA (CVCA2) private key
  * cvca_link.cvc      - link cert: CVCA1 signs CVCA2's public key
                         (CAR=UTSTCVCA00001, CHR=UTSTCVCA00002, role CVCA)
  * terminal2_ec_key.pem - terminal 2 private key
  * terminal2.cvc      - terminal cert: CVCA2 signs terminal 2
                         (CAR=UTSTCVCA00002, CHR=TERM0002, rights DG3+DG4)

To test the link certificate, send the chain [cvca_link.cvc, terminal2.cvc]
during Terminal Authentication (MSE Set DST with UTSTCVCA00001, PSO verify the
link cert, PSO verify terminal2, MSE Set AT TERM0002).

Usage:
    .venv/bin/python test_data/generate_eac_material.py [--link]
"""

from __future__ import annotations

import argparse
import os
import sys

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from epassport_reader.pace import EC_P256  # noqa: E402
from epassport_reader.tlvs import tlv as ber_tlv  # noqa: E402

OID_EC_PUBLIC_KEY = bytes.fromhex("2A8648CE3D0201")
OID_ROLE_CVCA = bytes.fromhex("04007F00070202020201")  # id-RoleOfCVCA
OID_ROLE_IS = bytes.fromhex("04007F00070202020203")  # id-RoleOfIS (terminal)

CVCA_CAR = b"UTSTCVCA00001"
CVCA2_CAR = b"UTSTCVCA00002"
TERMINAL_CHR = b"TERM0001"
TERMINAL2_CHR = b"TERM0002"
DATE_EFF = bytes.fromhex("001A00010001")  # 2026-01-01
DATE_EXP = bytes.fromhex("001E00010001")  # 2030-01-01
RIGHTS = 0x03  # DG3 + DG4


def _b32(n: int) -> bytes:
    return n.to_bytes(EC_P256.field_size, "big")


def _point(x: int, y: int) -> bytes:
    return b"\x04" + _b32(x) + _b32(y)


def _tlv(tag: int, value: bytes) -> bytes:
    return ber_tlv(tag, value)


def _cvc_body(
    car: bytes, chr_: bytes, subject_public_point: bytes, role_oid: bytes, rights: int
) -> bytes:
    pk = _tlv(
        0x7F49,
        b"".join(
            (
                _tlv(0x06, OID_EC_PUBLIC_KEY),
                _tlv(0x81, _b32(EC_P256.p)),
                _tlv(0x82, _b32(EC_P256.a)),
                _tlv(0x83, _b32(EC_P256.b)),
                _tlv(0x84, _point(EC_P256.gx, EC_P256.gy)),
                _tlv(0x85, _b32(EC_P256.n)),
                _tlv(0x86, subject_public_point),
                _tlv(0x87, b"\x01"),
            )
        ),
    )
    chat = _tlv(0x7F4C, _tlv(0x06, role_oid) + _tlv(0x53, bytes([rights])))
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


def build_cvc(
    issuer_key,
    car: bytes,
    chr_: bytes,
    role_oid: bytes,
    rights: int,
    subject_public_point: bytes,
) -> bytes:
    """Build a PSO-form certificate: ``7F4E <body> 5F37 <sig>``."""
    body_tlv = _tlv(
        0x7F4E, _cvc_body(car, chr_, subject_public_point, role_oid, rights)
    )
    signer = DSS.new(issuer_key, "fips-186-3", encoding="binary")
    sig = signer.sign(SHA256.new(body_tlv))
    return body_tlv + _tlv(0x5F37, sig)


def build_selfsigned_cvca(cvca_key, car: bytes = CVCA_CAR) -> bytes:
    """Self-signed CVCA certificate (provisioned into the applet as trust point)."""
    point = (
        b"\x04"
        + cvca_key.pointQ.x.to_bytes(32, "big")
        + cvca_key.pointQ.y.to_bytes(32, "big")
    )
    return build_cvc(cvca_key, car, car, OID_ROLE_CVCA, 0xFF, point)


def load_ec_key_pem(path: str):
    """Load an EC private key from a PEM file, or None if it does not exist."""
    try:
        with open(path, "rb") as f:
            return ECC.import_key(f.read())
    except OSError:
        return None


def ec_point_bytes(key) -> bytes:
    return (
        b"\x04"
        + key.pointQ.x.to_bytes(32, "big")
        + key.pointQ.y.to_bytes(32, "big")
    )


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(
        description="Generate EAC test material (CVCA + terminal certificate kit)."
    )
    parser.add_argument(
        "--link",
        action="store_true",
        help="also generate the CVCA link-certificate kit (CVCA2 + terminal 2)",
    )
    args = parser.parse_args()

    # Reuse the existing CVCA1 key when present so the link certificate chains
    # to the trust point already provisioned on the card.
    cvca_key = load_ec_key_pem(os.path.join(here, "cvca_ec_key.pem"))
    if cvca_key is None:
        cvca_key = ECC.generate(curve="P-256")

    term_key = ECC.generate(curve="P-256")
    term_point = ec_point_bytes(term_key)

    cvca_cert = build_selfsigned_cvca(cvca_key)
    terminal_cvc = build_cvc(
        cvca_key, CVCA_CAR, TERMINAL_CHR, OID_ROLE_IS, RIGHTS, term_point
    )

    files = {
        "cvca_ec_key.pem": cvca_key.export_key(format="PEM"),
        "cvca_selfsigned.cvcert": cvca_cert,
        "terminal_ec_key.pem": term_key.export_key(format="PEM"),
        "terminal.cvc": terminal_cvc,
    }

    link_note = []
    if args.link:
        cvca2_key = ECC.generate(curve="P-256")
        term2_key = ECC.generate(curve="P-256")

        # CVCA link certificate: CVCA1 (CAR=UTSTCVCA00001) certifies CVCA2's key.
        # Issuer CAR stays the old reference, holder CHR is the new reference.
        cvca_link = build_cvc(
            cvca_key, CVCA_CAR, CVCA2_CAR, OID_ROLE_CVCA, 0xFF, ec_point_bytes(cvca2_key)
        )
        # Terminal 2 certificate: signed by CVCA2 (CAR=UTSTCVCA00002).
        terminal2_cvc = build_cvc(
            cvca2_key, CVCA2_CAR, TERMINAL2_CHR, OID_ROLE_IS, RIGHTS,
            ec_point_bytes(term2_key),
        )
        files.update(
            {
                "cvca2_ec_key.pem": cvca2_key.export_key(format="PEM"),
                "cvca_link.cvc": cvca_link,
                "terminal2_ec_key.pem": term2_key.export_key(format="PEM"),
                "terminal2.cvc": terminal2_cvc,
            }
        )
        link_note = [
            f"CVCA2 CAR  : {CVCA2_CAR.decode()}",
            f"Terminal 2 : {TERMINAL2_CHR.decode()} (rights 0x{RIGHTS:02x})",
            "",
            "Chain for Terminal Authentication (GUI: select both .cvc files):",
            f"  1. {os.path.join(here, 'cvca_link.cvc')}",
            f"  2. {os.path.join(here, 'terminal2.cvc')}",
            f"key = {os.path.join(here, 'terminal2_ec_key.pem')}",
        ]

    for name, data in files.items():
        path = os.path.join(here, name)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        print(f"wrote {os.path.relpath(path)} ({len(data)} B)")

    print(f"\nCVCA CAR   : {CVCA_CAR.decode()}")
    print(f"Terminal CHR: {TERMINAL_CHR.decode()}")
    print(f"Rights     : 0x{RIGHTS:02x} (DG3+DG4)")
    if link_note:
        print()
        print("\n".join(link_note))
    print("\nTo use against the applet, (re)personalize it with:")
    print(f"  {os.path.join(here, 'cvca_selfsigned.cvcert')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
