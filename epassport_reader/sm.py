"""Secure messaging (SM) for eMRTD sessions.

A single ``SecureMessagingSession`` wraps / unwraps APDUs for both protocol
flavours used by this repository's PassportApplet and by real ICAO documents:

* ``BAC``  - 3DES-CBC + ISO 9797-1 Retail MAC, 8-byte SSC (ICAO 9303 Pt 11 B.2)
* ``PACE`` - AES-CBC + AES-CMAC, 16-byte SSC (ICAO 9303 Pt 11 D.7 / TR-03110)

The SM envelope follows the standard DO87 (encrypted data), DO97 (command
LE), DO99 (processing status) and DO8E (MAC) structure.
"""

from __future__ import annotations

from typing import Optional, Tuple

from .crypto import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_ecb_encrypt,
    cmac8,
    inc_ssc,
    pad80,
    retail_mac,
    tdes_cbc_decrypt,
    tdes_cbc_encrypt,
    unpad80,
)
from .tlvs import parse_tlvs, tlv

EOF_SW = (0x6282, 0x6B00, 0x6A82)


def _encode_le(le: int) -> bytes:
    if le <= 0xFF:
        return bytes([le & 0xFF])
    return le.to_bytes(2, "big")


def _encode_lc(lc: int) -> bytes:
    if lc <= 0xFF:
        return bytes([lc])
    return b"\x00" + lc.to_bytes(2, "big")


# Largest plaintext block per command when an oversized command is split with
# ISO 7816-4 command chaining. 200 B keeps the wrapped SM body (DO87 + DO8E,
# block-padded) safely below the 255-byte short-APDU Lc limit for both the
# 3DES (8-byte) and AES (16-byte) SM suites.
_CHAIN_PLAINTEXT = 200


def _command_body(apdu: bytes):
    """Split an SM-wrapped command into (header, lc_bytes, body).

    Supports both short (Lc at apdu[4]) and extended-Lc (apdu[4]==0x00, 16-bit
    length at apdu[5:7]) framing, so large commands (e.g. an SM-protected
    Active-Authentication exchange) parse correctly.
    """
    header = bytes(apdu[0:4])
    if apdu[4] == 0x00 and len(apdu) >= 7:
        lc = int.from_bytes(apdu[5:7], "big")
        body = apdu[7 : 7 + lc]
        lc_bytes = apdu[4:7]
    else:
        lc = apdu[4]
        body = apdu[5 : 5 + lc]
        lc_bytes = apdu[4:5]
    return header, lc_bytes, body


class SecureMessagingSession:
    """Wrap / unwrap eMRTD secure-messaging APDUs.

    ``ssc`` is a mutable bytearray that advances on every command/response.
    """

    def __init__(self, protocol: str, kenc: bytes, kmac: bytes, ssc: bytes):
        if protocol not in ("BAC", "PACE"):
            raise ValueError(f"unsupported protocol: {protocol!r}")
        self.protocol = protocol
        self.kenc = kenc
        self.kmac = kmac
        self.ssc = bytearray(ssc)

    # ------------------------------------------------------------------
    # command wrapping
    # ------------------------------------------------------------------

    def wrap_command(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b"",
        le: Optional[int] = None,
    ) -> bytes:
        if self.protocol == "BAC":
            return self._wrap_bac(cla, ins, p1, p2, data, le)
        return self._wrap_pace(cla, ins, p1, p2, data, le)

    def wrap_command_chained(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b"",
        le: Optional[int] = None,
    ):
        """Yield the SM APDU(s) carrying ``data`` via ISO 7816-4 chaining.

        Intended for short-APDU-only cards: when the wrapped command would not
        fit a single short APDU, the data field is split across several command
        APDUs, the CLA chaining bit (0x10) being set on every block but the
        last. Each block is an independent SM command (its own SSC increment
        and MAC); the card reassembles the decrypted DO87 plaintexts and
        processes the command on the final block. ``le`` is carried only on the
        final block.

        This is a generator on purpose: ``wrap_command`` advances the SSC at
        wrap time, so each block must be wrapped only when it is about to be
        sent. Eagerly wrapping the whole chain would pre-advance the SSC past
        the still-unsent blocks and desynchronise the response unwrapping
        (which uses ``SSC + 1``). Send each yielded APDU (and unwrap its
        response) before asking for the next one.
        """
        if len(data) <= _CHAIN_PLAINTEXT:
            yield self.wrap_command(cla, ins, p1, p2, data=data, le=le)
            return

        total = len(data)
        off = 0
        while off < total:
            block = data[off : off + _CHAIN_PLAINTEXT]
            off += len(block)
            last = off >= total
            block_cla = cla if last else (cla | 0x10)
            yield self.wrap_command(
                block_cla,
                ins,
                p1,
                p2,
                data=block,
                le=le if last else None,
            )

    def _wrap_bac(self, cla, ins, p1, p2, data, le) -> bytes:
        inc_ssc(self.ssc)
        header = bytes([cla | 0x0C, ins, p1, p2])
        padded_header = header + b"\x80\x00\x00\x00"
        body = bytearray()

        if data:
            # ICAO 9303 B.4.1: BAC 3DES-CBC uses an all-zero IV.
            ciphertext = tdes_cbc_encrypt(self.kenc, pad80(data))
            do87 = tlv(0x87, b"\x01" + ciphertext)
            body.extend(do87)

        if le is not None:
            do97 = tlv(0x97, _encode_le(le))
            body.extend(do97)

        # ICAO 9303 B.4.1: command MAC is over
        #   SSC || (CLA'||INS||P1||P2 || 80 00 00 00) || DO87 || DO97
        # (no Lc byte in the MAC input)
        m = bytes(self.ssc) + padded_header
        if data:
            m += do87
        if le is not None:
            m += do97

        mac = retail_mac(self.kmac, m)
        do8e = tlv(0x8E, mac)
        body.extend(do8e)

        apdu = header + _encode_lc(len(body)) + bytes(body)
        # SM responses always carry a protected envelope (DO87/DO99/DO8E), so
        # the command must be a case-4 APDU with a transport Le=0x00.  Real
        # chips answer SW=6882 when Le is missing (cf. pypassport's SM classes).
        apdu += b"\x00"
        return apdu

    def _wrap_pace(self, cla, ins, p1, p2, data, le) -> bytes:
        inc_ssc(self.ssc)
        header = bytes([cla | 0x0C, ins, p1, p2])
        body = bytearray()

        if data:
            iv = aes_ecb_encrypt(self.kenc, bytes(self.ssc))
            encrypted = aes_cbc_encrypt(self.kenc, iv, pad80(data, 16))
            body.extend(tlv(0x87, b"\x01" + encrypted))

        if le is not None:
            body.extend(tlv(0x97, _encode_le(le)))

        # ICAO PACE SM: the masked 4-byte header is ISO-padded to 16 bytes
        # (80 00 ...) and then concatenated with the DOs and ISO-padded again
        # (matching the applet's command MAC: pad80(SSC || paddedHeader || DOs)).
        padded_header = header + b"\x80" + b"\x00" * 11
        mac_input = pad80(bytes(self.ssc) + padded_header + bytes(body), 16)
        body.extend(tlv(0x8E, cmac8(self.kmac, mac_input)))

        # Transport Le=0x00: the PACE SM response is always a case-4 envelope
        # (DO87/DO99/DO8E); real chips answer SW=6882 without it.
        return header + _encode_lc(len(body)) + bytes(body) + b"\x00"

    # ------------------------------------------------------------------
    # command unwrapping (card side)
    # ------------------------------------------------------------------

    def unwrap_command(self, apdu: bytes) -> Tuple[bytes, Optional[int]]:
        """Unwrap an SM-protected command as the card would.

        Returns ``(plaintext_data, requested_le)``.  The 4-byte APDU header
        is left in the clear (only the command data field is encrypted), so
        callers read INS/P1/P2 from ``apdu[1:4]`` and the plaintext data from
        the return value.
        """
        if self.protocol == "BAC":
            return self._unwrap_command_bac(apdu)
        return self._unwrap_command_pace(apdu)

    def _unwrap_command_bac(self, apdu) -> Tuple[bytes, Optional[int]]:
        inc_ssc(self.ssc)
        header, lc_bytes, body = _command_body(apdu)
        do87 = None
        do97_le = None
        do8e = None
        for tag, value in parse_tlvs(body):
            if tag == 0x87:
                do87 = value
            elif tag == 0x97:
                do97_le = int.from_bytes(value, "big")
            elif tag == 0x8E:
                do8e = value
            else:
                raise ValueError("unexpected tag in SM command")
        if do8e is None or len(do8e) != 8:
            raise ValueError("SM command missing/invalid DO8E")

        # ICAO 9303 B.4.1: verify MAC over
        #   SSC || (header || 80 00 00 00) || DO87 || DO97
        # (no Lc byte in the MAC input)
        padded_header = header + b"\x80\x00\x00\x00"
        m = bytes(self.ssc) + padded_header
        for tag, value in parse_tlvs(body):
            if tag in (0x87, 0x97):
                m += tlv(tag, value)
        if retail_mac(self.kmac, m) != do8e:
            raise ValueError("command MAC mismatch (BAC)")
        if do87 is None:
            return b"", do97_le
        if not do87 or do87[0] != 0x01:
            raise ValueError("invalid DO87")
        iv = None  # BAC: 3DES-CBC uses all-zero IV
        return unpad80(tdes_cbc_decrypt(self.kenc, do87[1:], iv=iv)), do97_le

    def _unwrap_command_pace(self, apdu) -> Tuple[bytes, Optional[int]]:
        inc_ssc(self.ssc)
        header, _lc_bytes, body = _command_body(apdu)
        mac_data = bytearray(bytes(self.ssc) + header)
        do87 = None
        do97_le = None
        do8e = None
        for tag, value in parse_tlvs(body):
            if tag == 0x87:
                do87 = value
                mac_data.extend(tlv(0x87, value))
            elif tag == 0x97:
                do97_le = int.from_bytes(value, "big")
                mac_data.extend(tlv(0x97, value))
            elif tag == 0x8E:
                do8e = value
            else:
                raise ValueError("unexpected tag in SM command")
        if do8e is None or len(do8e) != 8:
            raise ValueError("SM command missing/invalid DO8E")
        if cmac8(self.kmac, pad80(bytes(mac_data), 16)) != do8e:
            raise ValueError("command MAC mismatch (PACE)")
        if do87 is None:
            return b"", do97_le
        if not do87 or do87[0] != 0x01:
            raise ValueError("invalid DO87")
        iv = aes_ecb_encrypt(self.kenc, bytes(self.ssc))
        return unpad80(aes_cbc_decrypt(self.kenc, iv, do87[1:])), do97_le

    # ------------------------------------------------------------------
    # response wrapping (card side)
    # ------------------------------------------------------------------

    def wrap_response(self, plaintext: bytes, sw: int) -> bytes:
        """Wrap a response as the card would (DO87 + DO99 + DO8E)."""
        if self.protocol == "BAC":
            return self._wrap_response_bac(plaintext, sw)
        return self._wrap_response_pace(plaintext, sw)

    def _wrap_response_bac(self, plaintext, sw) -> bytes:
        inc_ssc(self.ssc)
        body = bytearray()
        if plaintext:
            ciphertext = tdes_cbc_encrypt(self.kenc, pad80(plaintext))
            body.extend(tlv(0x87, b"\x01" + ciphertext))
        body.extend(tlv(0x99, sw.to_bytes(2, "big")))
        m = bytes(self.ssc) + bytes(body)
        body.extend(tlv(0x8E, retail_mac(self.kmac, m)))
        return bytes(body)

    def _wrap_response_pace(self, plaintext, sw) -> bytes:
        inc_ssc(self.ssc)
        body = bytearray()
        if plaintext:
            iv = aes_ecb_encrypt(self.kenc, bytes(self.ssc))
            encrypted = aes_cbc_encrypt(self.kenc, iv, pad80(plaintext, 16))
            body.extend(tlv(0x87, b"\x01" + encrypted))
        body.extend(tlv(0x99, sw.to_bytes(2, "big")))
        mac_input = pad80(bytes(self.ssc) + bytes(body), 16)
        body.extend(tlv(0x8E, cmac8(self.kmac, mac_input)))
        return bytes(body)

    # ------------------------------------------------------------------
    # response unwrapping
    # ------------------------------------------------------------------

    def unwrap_response(
        self, response: bytes, transport_sw: int = 0x9000
    ) -> Tuple[bytes, int]:
        """Unwrap an SM response envelope.

        Returns ``(plaintext, protected_status)``.  ``transport_sw`` is used
        as a fallback status when the envelope has no DO99 (some PACE
        implementations return the status only in the APDU SW).
        """
        if self.protocol == "BAC":
            return self._unwrap_bac(response, transport_sw)
        return self._unwrap_pace(response, transport_sw)

    def _unwrap_bac(self, response, transport_sw) -> Tuple[bytes, int]:
        # A response with no SM data objects is a bare transport error: nothing
        # to verify and no response-side SSC step (keeps the channel in sync).
        if not response or response[0] not in (0x87, 0x99, 0x8E):
            return b"", transport_sw
        before_mac = bytearray()
        do87 = None
        do99 = None
        do8e = None

        for tag, value in parse_tlvs(response):
            encoded = tlv(tag, value)
            if tag == 0x8E:
                do8e = value
                break
            before_mac.extend(encoded)
            if tag == 0x87:
                do87 = value
            elif tag == 0x99:
                do99 = value

        if do8e is None or len(do8e) != 8:
            raise RuntimeError("protected response missing/invalid DO8E")

        response_ssc = bytearray(self.ssc)
        inc_ssc(response_ssc)
        expected = retail_mac(self.kmac, bytes(response_ssc) + bytes(before_mac))
        if expected != do8e:
            raise RuntimeError("response MAC mismatch (BAC)")

        self.ssc[:] = response_ssc

        status = int.from_bytes(do99, "big") if do99 is not None else transport_sw
        if do87 is None:
            return b"", status
        if not do87 or do87[0] != 0x01:
            raise RuntimeError("invalid DO87")

        plain = unpad80(tdes_cbc_decrypt(self.kenc, do87[1:]))
        return plain, status

    def _unwrap_pace(self, response, transport_sw) -> Tuple[bytes, int]:
        # A response with no SM data objects is a bare transport error: nothing
        # to verify and no response-side SSC step (keeps the channel in sync).
        # Real chips can also return an SM envelope (DO99) with an error status;
        # that case falls through and advances the SSC normally.
        if not response or response[0] not in (0x87, 0x99, 0x8E):
            return b"", transport_sw
        before_mac = bytearray()
        do87 = None
        do99 = None
        do8e = None

        for tag, value in parse_tlvs(response):
            encoded = tlv(tag, value)
            if tag == 0x8E:
                do8e = value
                break
            before_mac.extend(encoded)
            if tag == 0x87:
                do87 = value
            elif tag == 0x99:
                do99 = value

        if do8e is None or len(do8e) != 8:
            raise RuntimeError("protected response missing/invalid DO8E")

        response_ssc = bytearray(self.ssc)
        inc_ssc(response_ssc)
        expected = cmac8(self.kmac, pad80(bytes(response_ssc) + bytes(before_mac), 16))
        if expected != do8e:
            raise RuntimeError(
                "response MAC mismatch (PACE): resp_ssc="
                + bytes(response_ssc).hex()
                + " expected="
                + expected.hex()
                + " got="
                + do8e.hex()
            )

        self.ssc[:] = response_ssc

        status = int.from_bytes(do99, "big") if do99 is not None else transport_sw
        if do87 is None:
            return b"", status
        if not do87 or do87[0] != 0x01:
            raise RuntimeError("invalid DO87")

        iv = aes_ecb_encrypt(self.kenc, bytes(response_ssc))
        plain = unpad80(aes_cbc_decrypt(self.kenc, iv, do87[1:]))
        return plain, status
