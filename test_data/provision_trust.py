#!/usr/bin/env python3
"""Provision the eMRTD applet's Terminal-Authentication trust point.

Reads the CVCA self-signed certificate (cvca_selfsigned.cvcert), extracts the
Certification Authority Reference (CAR, tag 0x42) and the CVCA public point
(W, tag 0x86), wraps them in the applet's A0 provisioning object and sends a
single plain STORE DATA APDU (00 E2 00 00).

Usage:
    .venv/bin/python test_data/provision_trust.py [--aid A0000002471001]
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smartcard.System import readers  # noqa: E402
from epassport_reader.tlvs import parse_tlvs, tlv  # noqa: E402

EMRTD_AID = bytes.fromhex("A0000002471001")


def extract_cvca_trust(cert: bytes):
    """Return (car, w) from the full 7F21 self-signed CVCA certificate."""
    # Peel the optional 7F21 envelope.
    for tag, value in parse_tlvs(cert):
        if tag == 0x7F21:
            cert = value
    car = None
    w = None
    for tag, value in parse_tlvs(cert):          # top level: 7F4E, 5F37
        if tag == 0x7F4E:
            for t, v in parse_tlvs(value):        # body
                if t == 0x42:
                    car = v
                elif t == 0x7F49:                 # public-key container
                    for t2, v2 in parse_tlvs(v):
                        if t2 == 0x86:
                            w = v2
    if car is None or w is None:
        raise ValueError("CVCA cert missing CAR (0x42) or public point (0x86)")
    return car, w


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", default=os.path.join(here, "cvca_selfsigned.cvcert"))
    args = ap.parse_args()

    with open(args.cert, "rb") as f:
        car, w = extract_cvca_trust(f.read())
    print(f"CAR : {car.decode(errors='replace')}")
    print(f"W   : {w.hex(' ').upper()}")

    obj = tlv(0xA0, tlv(0x42, car) + tlv(0x86, w))
    apdu = b"\x00\xE2\x00\x00" + bytes([len(obj)]) + obj + b"\x00"
    print(f"APDU: {apdu.hex(' ').upper()}")

    conn = readers()[2].createConnection()
    conn.connect()
    # Select the eMRTD applet (pyscard wants a list of ints).
    r, sw1, sw2 = conn.transmit(list(b"\x00\xA4\x04\x00" + bytes([len(EMRTD_AID)]) + EMRTD_AID))
    if sw1 != 0x90:
        raise SystemExit(f"SELECT failed: {sw1:02X}{sw2:02X}")
    r, sw1, sw2 = conn.transmit(list(apdu))
    if sw1 != 0x90:
        raise SystemExit(f"STORE DATA failed: {sw1:02X}{sw2:02X}")
    print("Trust point provisioned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
