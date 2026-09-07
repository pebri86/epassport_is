"""PACE (Password Authenticated Connection Establishment) - GM mapping.

Implements the PACE handshake exactly as the PassportApplet in this
repository does (see ``simulator/PyPassportFlow.java`` /
``test_pace_sm.py``):

* MSE:Set AT with the PACE OID
* step 1: GET encrypted nonce  -> decrypt with K_PI (from the password)
* step 2: send mapping public key -> receive mapped base point G'
* step 3: send ephemeral public key -> receive card ephemeral key Q.ICC
* step 4: exchange authentication tokens (AES-CMAC)
* SM keys from the shared secret, 16-byte zero SSC

The password is either the MRZ-information (PACE-MRZ) or the CAN
(PACE-CAN).  Both are derived with ``derive_pace_key``.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Callable, NamedTuple, Optional, Tuple

from .crypto import aes_ecb_decrypt, cmac8, derive_pace_key, derive_pace_key_mrz
from .sm import SecureMessagingSession
from .tlvs import parse_tlvs

SendFn = Callable[[bytes], tuple]


class ECDomainParams(NamedTuple):
    """Elliptic curve domain parameters for ECDH operations."""

    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int
    field_size: int  # bytes: 32 for P-256, 48 for P-384, 66 for P-521
    param_id: int = 12  # ICAO parameterId (12=P-256, 13=P-384, 14=P-521)


def _ec_point_add(p1, p2, curve: ECDomainParams):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % curve.p == 0:
            return None
        m = ((3 * x1 * x1 + curve.a) * pow(2 * y1, curve.p - 2, curve.p)) % curve.p
    else:
        m = ((y2 - y1) * pow((x2 - x1) % curve.p, curve.p - 2, curve.p)) % curve.p
    x3 = (m * m - x1 - x2) % curve.p
    y3 = (m * (x1 - x3) - y1) % curve.p
    return x3, y3


def _ec_point_mul(k: int, point, curve: ECDomainParams):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_point_add(result, addend, curve)
        addend = _ec_point_add(addend, addend, curve)
        k >>= 1
    return result


def _ec_encode_point(point, curve: ECDomainParams) -> bytes:
    x, y = point
    return (
        b"\x04"
        + x.to_bytes(curve.field_size, "big")
        + y.to_bytes(curve.field_size, "big")
    )


class ECPrivateKey:
    """A terminal EC signing key (scalar + domain) for Terminal Authentication.

    brainpoolP256r1 (the applet's TA curve) is not representable by
    pycryptodome, so Terminal-Authentication signing runs on the pure-Python
    curve arithmetic below (same domain the Chip-Authentication path uses).
    """

    __slots__ = ("d", "curve")

    def __init__(self, d: int, curve: ECDomainParams):
        self.d = d
        self.curve = curve


_OID_SECP256R1 = bytes.fromhex("2A8648CE3D030107")      # 1.2.840.10045.3.1.7
_OID_BRAINPOOL_P256R1 = bytes.fromhex("2B2403030208010107")  # 1.3.36.3.3.2.8.1.1.7


def _der_children(content: bytes):
    """Parse a DER SEQUENCE value into a list of ``(tag, value)`` TLVs."""
    out = []
    i = 0
    while i < len(content):
        tag = content[i]
        i += 1
        if (tag & 0x1F) == 0x1F:
            while True:
                b = content[i]
                i += 1
                tag = (tag << 8) | b
                if not (b & 0x80):
                    break
        length = content[i]
        i += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(content[i:i + n], "big")
            i += n
        out.append((tag, content[i:i + length]))
        i += length
    return out


def load_ec_private_key(data: bytes) -> ECPrivateKey:
    """Load an EC private key from a PKCS#8 PEM/DER blob.

    pycryptodome cannot import brainpool keys, so this parses the PKCS#8
    ``ECPrivateKey`` directly (curve OID + scalar) and wraps it in an
    :class:`ECPrivateKey`. Supports P-256 and brainpoolP256r1 (the applet's
    Terminal-Authentication curve).
    """
    if b"-----" in data:
        import base64

        b64 = b"".join(
            line for line in data.splitlines() if not line.startswith(b"-----")
        )
        data = base64.b64decode(b64)

    top = _der_children(data)
    if not top or top[0][0] != 0x30:
        raise ValueError("not a PKCS#8 private key")
    outer = top[0][1]
    fields = _der_children(outer)
    if len(fields) < 3 or fields[1][0] != 0x30 or fields[2][0] != 0x04:
        raise ValueError("not an EC PKCS#8 private key")

    alg_children = _der_children(fields[1][1])
    oids = [v for t, v in alg_children if t == 0x06]
    curve = None
    if oids and oids[-1] == _OID_BRAINPOOL_P256R1:
        curve = EC_BRAINPOOL_P256
    elif oids and oids[-1] == _OID_SECP256R1:
        curve = EC_P256
    if curve is None:
        raise ValueError("unsupported EC private key curve")

    def _octet_values(content, acc):
        for t, v in _der_children(content):
            if t == 0x04:
                acc.append(v)
            elif t in (0x30,):
                _octet_values(v, acc)
        return acc

    # The PKCS#8 private-key OCTET STRING wraps an ECPrivateKey SEQUENCE; the
    # scalar is the innermost OCTET STRING whose value is in [1, n).
    candidates = _octet_values(fields[2][1], [])
    d = None
    for v in candidates:
        cand = int.from_bytes(v, "big")
        if 1 <= cand < curve.n:
            d = cand
            break
    if d is None:
        raise ValueError("EC private key missing private scalar")
    return ECPrivateKey(d, curve)


def _ecdsa_sign_plain(d: int, curve: ECDomainParams, message: bytes) -> bytes:
    """ECDSA-SHA-256 signing returning the plain fixed-size ``R || S`` form.

    The applet's ``ECDSAPlainVerifier`` expects R and S as fixed
    ``field_size``-byte big-endian integers (it reassembles them into DER), so
    this mirrors that layout. Produces low-S signatures so the signature is
    accepted regardless of Java Card canonical-signature enforcement.
    """
    n, fs = curve.n, curve.field_size
    g = (curve.gx, curve.gy)
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    half = n >> 1
    while True:
        k = int.from_bytes(secrets.token_bytes(fs), "big") % n
        if k == 0:
            continue
        rp = _ec_point_mul(k, g, curve)
        r = rp[0] % n
        if r == 0:
            continue
        s = (pow(k, -1, n) * (e + r * d)) % n
        if s == 0:
            continue
        if s > half:
            s = n - s
        return r.to_bytes(fs, "big") + s.to_bytes(fs, "big")


def _ec_decode_point(data: bytes, curve: ECDomainParams) -> Tuple[int, int]:
    fs = curve.field_size
    expected = 1 + 2 * fs
    if len(data) != expected or data[0] != 0x04:
        raise ValueError(f"invalid uncompressed {curve.name} point (got {len(data)}B)")
    x = int.from_bytes(data[1 : 1 + fs], "big")
    y = int.from_bytes(data[1 + fs : expected], "big")
    if (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p != 0:
        raise ValueError(f"point is not on {curve.name}")
    return x, y


# ---------------------------------------------------------------------------
# Standardized domain parameters (ICAO Doc 9303 / TR-03110)
# ---------------------------------------------------------------------------

# NIST P-256 (secp256r1)
EC_P256 = ECDomainParams(
    name="P-256",
    p=int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16),
    a=int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
    b=int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16),
    gx=int("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
    gy=int("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16),
    n=int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
    field_size=32,
)
EC_P256_G = (EC_P256.gx, EC_P256.gy)

# Brainpool P256r1 (RFC 5639) - parameterId 13 (ICAO Doc 9303-11 /
# TR-03110: 0x0D = brainpoolP256r1, JMRTD PARAM_ID_ECP_BRAINPOOL_P256_R1).
EC_BRAINPOOL_P256 = ECDomainParams(
    name="brainpoolP256r1",
    p=int("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16),
    a=int("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16),
    b=int("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16),
    gx=int("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16),
    gy=int("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16),
    n=int("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16),
    field_size=32,
    param_id=13,
)
EC_BRAINPOOL_P256_G = (EC_BRAINPOOL_P256.gx, EC_BRAINPOOL_P256.gy)

# NIST P-384 (secp384r1) — parameterId 13
EC_P384 = ECDomainParams(
    name="P-384",
    p=int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        16,
    ),
    a=int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
        16,
    ),
    b=int(
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F"
        "5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        16,
    ),
    gx=int(
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E0"
        "82542A385502F25DBF55296C3A545E3872760AB7",
        16,
    ),
    gy=int(
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113"
        "B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
        16,
    ),
    n=int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81"
        "F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        16,
    ),
    field_size=48,
    param_id=13,
)
EC_P384_G = (EC_P384.gx, EC_P384.gy)

# P-521 (secp521r1) — parameterId 14
EC_P521 = ECDomainParams(
    name="P-521",
    p=int(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    ),
    a=int(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
        16,
    ),
    b=int(
        "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489"
        "918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF"
        "451FD46B503F00",
        16,
    ),
    gx=int(
        "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF"
        "606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF9"
        "7E7E31C2E5BD66",
        16,
    ),
    gy=int(
        "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD"
        "17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088"
        "BE94769FD16650",
        16,
    ),
    n=int(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB"
        "6FB71E91386409",
        16,
    ),
    field_size=66,
    param_id=14,
)
EC_P521_G = (EC_P521.gx, EC_P521.gy)

# parameterId -> curve (ICAO Doc 9303-11 / TR-03110 standardized domain parameters:
# 0x0C=prime256v1, 0x0D=brainpoolP256r1, 0x10=secp384r1, 0x11=secp521r1)
PARAM_ID_TO_EC = {
    12: EC_P256,  # prime256v1 (NIST P-256)
    13: EC_BRAINPOOL_P256,  # brainpoolP256r1
    16: EC_P384,  # secp384r1 (NIST P-384)
    17: EC_P521,  # secp521r1 (NIST P-521)
}

DEFAULT_EC = EC_P256

PACE_OID = bytes.fromhex("04007F00070202040202")

DEFAULT_PACE_OID = PACE_OID  # PACE-ECDH-GM-AES-CBC-CMAC-128

# DO83 password references (ICAO Doc 9303 / TR-03110)
PW_REF_MRZ = b"\x01"  # MRZ
PW_REF_CAN = b"\x02"  # CAN


def _build_mse_set_at(
    pace_oid: bytes,
    pw_ref: bytes = PW_REF_CAN,
    param_id: Optional[int] = None,
) -> bytes:
    data = bytes([0x80, len(pace_oid)]) + pace_oid
    data += b"\x83\x01" + pw_ref
    if param_id is not None:
        # DO84 = standardized domain parameter id (selects the curve)
        data += bytes([0x84, 0x01, param_id & 0xFF])
    return bytes.fromhex("1022C1A4") + bytes([len(data)]) + data


MSE_SET_AT = _build_mse_set_at(PACE_OID)
GET_ENCRYPTED_NONCE = bytes.fromhex("10860000027C00")


def _auth_public_key(pub: bytes, pace_oid: Optional[bytes] = None) -> bytes:
    oid = pace_oid if pace_oid is not None else PACE_OID
    inner = b"\x06\x0a" + oid + b"\x86" + bytes([len(pub)]) + pub
    return b"\x7f\x49" + bytes([len(inner)]) + inner


def _parse_7c(response: bytes, expected_tag: int) -> bytes:
    for tag, value in parse_tlvs(response):
        if tag == 0x7C:
            for inner_tag, inner_value in parse_tlvs(value):
                if inner_tag == expected_tag:
                    return inner_value
    raise RuntimeError(f"GENERAL AUTHENTICATE response missing tag {expected_tag:02X}")


def do_pace(
    send: SendFn,
    password: bytes,
    log: Optional[Callable[[str], None]] = None,
    pace_oid: Optional[bytes] = None,
    pw_ref: Optional[bytes] = None,
    curve: Optional[ECDomainParams] = None,
) -> SecureMessagingSession:
    """Run the PACE-GM handshake over ``send`` and return an SM session.

    ``pace_oid`` is the protocol OID detected from EF.CardAccess.  When
    omitted the default PACE-ECDH-GM-AES-CBC-CMAC-128 OID is used.

    ``pw_ref`` is the DO83 password reference (0x01 MRZ, 0x02 CAN).
    When omitted it defaults to CAN (0x02).  Set to 0x01 for PACE-MRZ.

    ``curve`` is the ECDomainParams selected from the detected
    parameterId.  Defaults to EC_P256 (NIST P-256).
    """
    if log is None:
        log = lambda _msg: None

    ec = curve if curve is not None else DEFAULT_EC
    G = (ec.gx, ec.gy)

    oid = pace_oid if pace_oid is not None else PACE_OID
    ref = pw_ref if pw_ref is not None else PW_REF_CAN
    mse_cmd = _build_mse_set_at(oid, ref, ec.param_id)
    log(f"PACE OID = {oid.hex(':').upper()}  pw_ref = {ref[0]:02X}")
    log(f"PACE curve = {ec.name} (paramId={ec.param_id}, field={ec.field_size}B)")

    data, sw = send(mse_cmd)
    if sw != 0x9000:
        raise RuntimeError(f"MSE:Set AT failed: SW={sw:04X}")

    if ref == PW_REF_MRZ:
        k_pi = derive_pace_key_mrz(password)  # ICAO PACE-MRZ double-hash
    else:
        k_pi = derive_pace_key(password)
    log(f"PACE K_PI = {k_pi.hex(' ').upper()}")

    # step 1: GET ENCRYPTED NONCE (CLA=0x10 for PACE)
    data, sw = send(GET_ENCRYPTED_NONCE)
    if sw != 0x9000:
        raise RuntimeError(f"PACE step 1 (get encrypted nonce) failed: SW={sw:04X}")
    encrypted_nonce = _parse_7c(data, 0x80)
    nonce = aes_ecb_decrypt(k_pi, encrypted_nonce)
    log(f"PACE nonce S = {nonce.hex(' ').upper()}")

    # step 2: send mapping public key (CLA=0x10)
    d_map = secrets.randbelow(ec.n - 1) + 1
    q_ifd_map_enc = _ec_encode_point(_ec_point_mul(d_map, G, ec), ec)
    ga2 = (
        b"\x7c"
        + bytes([2 + len(q_ifd_map_enc)])
        + b"\x81"
        + bytes([len(q_ifd_map_enc)])
        + q_ifd_map_enc
    )
    data, sw = send(b"\x10\x86\x00\x00" + bytes([len(ga2)]) + ga2)
    if sw != 0x9000:
        raise RuntimeError(f"PACE step 2 (mapping) failed: SW={sw:04X}")
    # PACE-GM: the card responds with its mapping public key Y_icc = [y_icc]G (DO 0x82).
    # Derive the mapped generator G' = [s]G + H where H = [d_map]Y_icc (the applet computes the
    # same G' on-card via ALG_EC_PACE_GM with scalar s = the nonce).
    y_icc = _ec_decode_point(_parse_7c(data, 0x82), ec)
    h = _ec_point_mul(d_map, y_icc, ec)
    s_int = int.from_bytes(nonce, "big")
    g_prime = _ec_point_add(_ec_point_mul(s_int, G, ec), h, ec)

    # step 3: send ephemeral public key (CLA=0x10)
    d_ifd = secrets.randbelow(ec.n - 1) + 1
    q_ifd_enc = _ec_encode_point(_ec_point_mul(d_ifd, g_prime, ec), ec)
    ga3 = (
        b"\x7c"
        + bytes([2 + len(q_ifd_enc)])
        + b"\x83"
        + bytes([len(q_ifd_enc)])
        + q_ifd_enc
    )
    data, sw = send(b"\x10\x86\x00\x00" + bytes([len(ga3)]) + ga3)
    if sw != 0x9000:
        raise RuntimeError(f"PACE step 3 (ephemeral key) failed: SW={sw:04X}")
    q_icc = _ec_decode_point(_parse_7c(data, 0x84), ec)

    # derive SM keys from the shared secret
    shared_secret = _ec_point_mul(d_ifd, q_icc, ec)[0].to_bytes(ec.field_size, "big")
    k_enc = hashlib.sha1(shared_secret + b"\x00\x00\x00\x01").digest()[:16]
    k_mac = hashlib.sha1(shared_secret + b"\x00\x00\x00\x02").digest()[:16]
    log(f"PACE KSEnc = {k_enc.hex(' ').upper()}")
    log(f"PACE KSMac = {k_mac.hex(' ').upper()}")

    # step 4: authentication tokens (CLA=0x10)
    # T_PCD = MAC(K_mac, encodePublicKey(Q_ICC)) authenticates the CARD's ephemeral key;
    # T_PICC = MAC(K_mac, encodePublicKey(Q_IFD)) authenticates the TERMINAL's ephemeral key
    # (ICAO Doc 9303-11 / TR-03110, matching the applet's step4).
    terminal_token = cmac8(k_mac, _auth_public_key(_ec_encode_point(q_icc, ec), oid))
    ga4 = (
        b"\x7c"
        + bytes([2 + len(terminal_token)])
        + b"\x85"
        + bytes([len(terminal_token)])
        + terminal_token
    )
    data, sw = send(b"\x10\x86\x00\x00" + bytes([len(ga4)]) + ga4)
    if sw != 0x9000:
        raise RuntimeError(f"PACE step 4 (terminal token) failed: SW={sw:04X}")
    card_token = _parse_7c(data, 0x86)
    expected_card_token = cmac8(k_mac, _auth_public_key(q_ifd_enc, oid))
    if card_token != expected_card_token:
        raise RuntimeError("PACE card authentication token mismatch")

    log("PACE authentication OK")
    session = SecureMessagingSession("PACE", k_enc, k_mac, b"\x00" * 16)
    # Retain the IC's PACE ephemeral public key X-coordinate (Comp(PKDH,IC)),
    # used as ID_IC by Terminal Authentication (ICAO Doc 9303-11 §7.1.2).
    session.pace_icc_eph_x = q_icc[0].to_bytes(ec.field_size, "big")
    return session
