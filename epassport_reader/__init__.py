"""epassport_reader - ICAO Doc 9303 eMRTD terminal library.

Modules:
* crypto  - cryptographic primitives (3DES, AES, MACs, key derivation)
* tlvs    - BER-TLV helpers and ICAO tag names
* sm      - secure messaging (BAC 3DES / PACE AES) wrap + unwrap
* bac     - Basic Access Control mutual authentication
* pace    - PACE (GM) mutual authentication
* ca      - EAC Chip Authentication (MSE:Set AT KAT + CA key derivation)
* ta      - EAC Terminal Authentication (MSE, GET CHALLENGE, PSO, EXTERNAL AUTH)
* aa      - Active Authentication (INTERNAL_AUTHENTICATE, EF.DG15)
* cvc     - chip CA public-key carrier (EF.DG14) parsing
* reader  - high-level PC/SC passport reader
* dgs     - data group parsers (DG1 MRZ, images, DG11-13, EF.COM)
* pa      - Passive Authentication (EF.SOD) verification
* samples - load bundled sample data for offline demos
"""

from .cvc import CardAccessInfo
from .reader import EPassportReader, PassportData

__all__ = ["CardAccessInfo", "EPassportReader", "PassportData"]
__version__ = "1.0.0"
