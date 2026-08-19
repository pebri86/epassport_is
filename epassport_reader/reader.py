"""High-level e-passport reader (PC/SC) built on the BAC/PACE + SM modules.

``EPassportReader`` connects to a card, establishes BAC or PACE secure
messaging, reads EF.COM / EF.SOD / the data groups, the MF-level EF.CardSecurity
security info and returns a ``PassportData`` object with everything parsed for
the GUI.

Reading strategy
----------------
The PassportApplet returns *zero bytes* (protected SW 0x9000) once a READ
BINARY offset reaches the end of the EF, and it does not return an FCI file
size on SELECT.  Real ICAO documents instead answer with 0x6282/0x6B00 past
EOF.  The loop below handles both: it reads 0xDF-byte chunks and stops on an
empty chunk or on an end-of-file status word.
"""

from __future__ import annotations

import sys
from typing import Callable, Dict, List, Optional

from .bac import do_bac
from .ca import do_chip_authentication
from .crypto import build_mrz_info
from .cvc import (
    CardAccessInfo,
    parse_card_access,
    parse_card_security,
    parse_chip_auth_data,
    parse_ef_cvca,
)
from .pace import DEFAULT_EC, PARAM_ID_TO_EC, do_pace
from .dgs import (
    parse_com,
    parse_dg1,
    parse_dg2,
    parse_dg7,
    parse_text_dg,
)
from .pa import parse_sod, verify_pa
from .ta import do_terminal_authentication, parse_cvc_chain_refs
from .tlvs import (
    DATA_GROUP_TAG_TO_FID,
    DATA_GROUP_TAG_TO_NUM,
    DATA_GROUP_TAGS,
    parse_fci_size,
)
from .sm import SecureMessagingSession
from .aa import (
    do_active_authentication,
    make_aa_challenge,
    parse_dg15_aa_key,
)

LogFn = Callable[[str], None]

EMRTD_AID = bytes.fromhex("A0000002471001")
SELECT_APPLET_1 = bytes.fromhex("00A4040007A0000002471001")
SELECT_APPLET_2 = bytes.fromhex("00A4040C07A0000002471001")

READ_CHUNK = 0xDF  # 223 bytes - safely below the applet's BAC cap (buf-37)
EOF_SW = (0x6282, 0x6B00, 0x6A82)


class CardAdapter:
    """Thin pyscard wrapper that turns transmit() into (bytes, sw)."""

    def __init__(self, conn, log: Optional[LogFn] = None):
        self.conn = conn
        self.log = log or (lambda _m: None)

    def send(self, apdu: bytes):
        self.log(f"\u2192 {apdu.hex(' ').upper()}")
        data, sw1, sw2 = self.conn.transmit(list(apdu))
        data = bytes(data)
        sw = (sw1 << 8) | sw2
        self.log(f"\u2190 {data.hex(' ').upper()}  SW={sw:04X}")
        return data, sw


class PassportData:
    """Container for everything read from the passport."""

    def __init__(self) -> None:
        self.atr: Optional[bytes] = None
        self.protocol: Optional[str] = None
        self.raw: Dict[int, bytes] = {}  # tag -> raw EF bytes
        self.com: Optional[Dict] = None
        self.tag_list: List[int] = []
        self.dg1: Optional[Dict] = None
        self.dg2: Optional[Dict] = None
        self.dg7: Optional[Dict] = None
        self.text_dgs: Dict[int, List[Dict]] = {}  # tag -> fields
        self.sod_info: Optional[Dict] = None
        self.pa_result: Optional[Dict] = None
        self.card_security_raw: Optional[bytes] = None
        self.card_security_info: Optional[Dict] = None
        self.cvca_raw: Optional[bytes] = None
        self.cvca_info: Optional[Dict] = None
        self.errors: List[str] = []

    def has(self, tag: int) -> bool:
        return tag in self.raw


class EPassportReader:
    def __init__(
        self,
        protocol: str = "BAC",
        doc_number: str = "",
        dob: str = "",
        expiry: str = "",
        can: Optional[str] = None,
        log: Optional[LogFn] = None,
    ):
        self.protocol = protocol.upper()
        if self.protocol not in ("BAC", "PACE", "HYBRID"):
            raise ValueError(f"protocol must be BAC, PACE or HYBRID, got {protocol!r}")
        self.doc_number = doc_number
        self.dob = dob
        self.expiry = expiry
        self.can = can
        self.log = log or (lambda _m: None)
        self.session: Optional[SecureMessagingSession] = None
        self.card: Optional[CardAdapter] = None
        self.atr: Optional[bytes] = None
        self.pace_oid: Optional[bytes] = None
        self.pace_curve = DEFAULT_EC

    # ------------------------------------------------------------------
    # connection
    # ------------------------------------------------------------------

    def _readers(self):
        from smartcard.System import readers

        return readers()

    def list_readers(self) -> List[str]:
        return [str(r) for r in self._readers()]

    def connect(self, reader_index: int = 0) -> None:
        rs = self._readers()
        if not rs:
            raise RuntimeError("No PC/SC readers found. Is a reader connected?")
        if reader_index >= len(rs):
            raise RuntimeError(
                f"Reader index {reader_index} out of range ({len(rs)} available)"
            )
        reader = rs[reader_index]
        self.log(f"Using reader: {reader}")
        conn = reader.createConnection()
        conn.connect()
        self.atr = bytes(conn.getATR())
        self.log(f"ATR: {self.atr.hex(' ').upper()}")
        self.card = CardAdapter(conn, self.log)

        # select the eMRTD application (by AID)
        data, sw = self.card.send(SELECT_APPLET_1)
        if sw != 0x9000:
            data, sw = self.card.send(SELECT_APPLET_2)
        if sw != 0x9000:
            raise RuntimeError(f"SELECT eMRTD applet failed: SW={sw:04X}")
        self.log("eMRTD application selected")

    # ------------------------------------------------------------------
    # authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        if self.card is None:
            raise RuntimeError("not connected")
        if self.protocol == "BAC":
            mrz_info = build_mrz_info(self.doc_number, self.dob, self.expiry)
            self.log(f"MRZ information: {mrz_info.decode('ascii', 'replace')}")
            self.session = do_bac(self.card.send, mrz_info, self.log)
        elif self.protocol == "HYBRID":
            self.authenticate_hybrid()
        else:
            if self.can:
                password = self.can.encode("ascii")
                pw_ref = b"\x02"
                self.log(f"PACE password: CAN ({len(password)} digits)")
            else:
                password = build_mrz_info(self.doc_number, self.dob, self.expiry)
                pw_ref = b"\x01"
                self.log("PACE password: MRZ information")
            self.session = do_pace(
                self.card.send,
                password,
                self.log,
                pace_oid=self.pace_oid,
                pw_ref=pw_ref,
                curve=self.pace_curve,
            )

    def authenticate_hybrid(self) -> None:
        """Authenticate with a BAC-then-PACE hybrid (ICAO 9303 Supplement).

        Some PACE-only passports require BAC mutual authentication first to
        establish a security context, after which PACE can be initiated.  This
        runs BAC (using the MRZ), then attempts PACE.  The PACE session is used
        for secure messaging if it succeeds, otherwise the BAC session is used.
        """
        if self.card is None:
            raise RuntimeError("not connected")

        # 1. BAC mutual authentication with the MRZ
        mrz_info = build_mrz_info(self.doc_number, self.dob, self.expiry)
        self.log(f"Hybrid: step 1 = BAC mutual authentication")
        self.session = do_bac(self.card.send, mrz_info, self.log)

        # 2. Attempt PACE to upgrade the SM session
        if self.can:
            password = self.can.encode("ascii")
            pw_ref = b"\x02"
            self.log(f"Hybrid: step 2 = PACE with CAN")
        else:
            password = build_mrz_info(self.doc_number, self.dob, self.expiry)
            pw_ref = b"\x01"
            self.log(f"Hybrid: step 2 = PACE with MRZ")
        try:
            pace_session = do_pace(
                self.card.send,
                password,
                self.log,
                pace_oid=self.pace_oid,
                pw_ref=pw_ref,
                curve=self.pace_curve,
            )
            self.session = pace_session
            self.log("Hybrid: PACE SM session established (using PACE)")
        except Exception as exc:  # noqa: BLE001
            self.log(f"Hybrid: PACE failed ({exc}); keeping BAC SM session")

    # EF.DG14 (LDS1): the ICAO-standard carrier for the chip's Chip-Authentication
    # public key (SecurityInfos / ChipAuthenticationPublicKeyInfo).
    CHIP_CA_FID = 0x010E

    def read_chip_auth_data(self):
        """Read the chip's Chip-Authentication key material from the document.

        Like a real passport, the terminal reads the chip's static CA public
        key and key reference from EF.DG14 instead of having them passed in by
        the caller.
        """
        raw = self.read_ef(self.CHIP_CA_FID)
        data = parse_chip_auth_data(raw)
        if data is None:
            raise RuntimeError(
                "chip Chip-Authentication public key not found in EF.DG14"
            )
        self.log(f"chip CA public key read from EF.DG14 ({len(raw)} bytes)")
        return data

    def chip_authentication(self) -> None:
        """Run EAC Chip Authentication over the current SM session.

        The chip's static CA public key is read from EF.DG14 (ICAO standard),
        as a real passport terminal does. On success the reader's ``session``
        is replaced by the upgraded CA 3DES session (SSC restarted at zero);
        the terminal's ephemeral CA public key and the chip's key reference are
        retained so Terminal Authentication can sign X_ICC.
        """
        if self.session is None:
            raise RuntimeError("authentication not completed")
        ca_data = self.read_chip_auth_data()
        curve = (
            PARAM_ID_TO_EC.get(ca_data.parameter_id, DEFAULT_EC)
            if ca_data.parameter_id
            else DEFAULT_EC
        )
        result = do_chip_authentication(
            self.session,
            self.card.send,
            ca_data.chip_public_key,
            ca_data.public_key_ref,
            self.log,
            curve,
        )
        self.session = result.session
        self._ca_ifd_public = result.ifd_public
        self._chip_public_key_ref = ca_data.public_key_ref
        self.log("Chip Authentication OK - session upgraded to CA keys")

    def terminal_authentication(
        self,
        terminal_cvc,
        terminal_key,
    ) -> None:
        """Run EAC Terminal Authentication over the CA session.

        ``terminal_cvc`` is either a single terminal certificate (PSO form,
        ``7F4E ... 5F37 ...``) or a certificate chain of PSO-form CVCs. A chain
        starts with the CVCA link certificate (CAR = the trust-point CAR, role
        CVCA, certifying the new CVCA key) followed by the terminal certificate
        signed by the new CVCA, so the applet updates its trust point before
        importing the terminal key. ``terminal_key`` is the matching EC private
        key of the LAST certificate in the chain. The CVCA trust-point CAR and
        the terminal CHR are taken from the certificates; ``ID_IC`` is the IC's
        PACE ephemeral key X-coordinate (PACE) or the MRZ document number (BAC).
        """
        if self.session is None or not getattr(self, "_ca_ifd_public", None):
            raise RuntimeError("chip_authentication() must run first")
        x_icc = self._ca_ifd_public[1:33]  # 32-byte X-coordinate of Q_IFD

        chain = list(terminal_cvc) if isinstance(terminal_cvc, (list, tuple)) else [terminal_cvc]
        if not chain:
            raise RuntimeError("terminal certificate chain is empty")
        cvca_car, terminal_chr = parse_cvc_chain_refs(chain)
        if not cvca_car or not terminal_chr:
            raise RuntimeError(
                "terminal certificate chain is missing the issuer CAR or holder CHR"
            )

        # ID_IC: IC's PACE ephemeral X under PACE, else the MRZ document number.
        if self.session.protocol == "PACE" and getattr(
            self.session, "pace_icc_eph_x", None
        ):
            id_ic = self.session.pace_icc_eph_x
        else:
            doc = self.doc_number.upper().replace(" ", "<")
            if len(doc) == 9:
                from .crypto import check_digit

                doc += str(check_digit(doc))
            id_ic = doc.encode("ascii")

        do_terminal_authentication(
            self.session,
            self.card.send,
            cvca_car,
            chain,
            terminal_key,
            terminal_chr,
            id_ic,
            x_icc,
            self.log,
        )

    # EF.DG15 (LDS1): the Active-Authentication public key carrier.
    AA_FID = 0x010F

    def active_authentication(self, challenge: bytes = None):
        """Run Active Authentication (AA) over the current SM session.

        Reads the AA public key from EF.DG15, sends ``INTERNAL_AUTHENTICATE``
        with an 8-byte challenge and verifies the chip's raw-RSA signature
        against the DG15 key. AA requires a BAC (mutually-authenticated)
        session and a document personalised with an AA key (``--aa-key``).
        """
        if self.session is None:
            raise RuntimeError("authentication not completed")
        sm = self._sm()
        dg15 = self.read_ef(self.AA_FID)
        self.log(f"EF.DG15 read ({len(dg15)} B) - AA public key")
        aa_key = parse_dg15_aa_key(dg15)
        if challenge is None:
            challenge = make_aa_challenge()
        result = do_active_authentication(
            sm, self.card.send, challenge, aa_key, self.log
        )
        if result.verified:
            self.log("Active Authentication OK - chip holds the AA private key")
        else:
            self.log(f"Active Authentication FAILED: {result.reason}")
        return result

    # ------------------------------------------------------------------
    # EF reading over secure messaging
    # ------------------------------------------------------------------

    def _sm(self) -> SecureMessagingSession:
        if self.session is None:
            raise RuntimeError("authentication not completed")
        return self.session

    def _select_mf(self) -> None:
        """SELECT FILE 3F00 (Master File) over secure messaging.

        Tries both ``P2=0x0C`` (select by DF name) and ``P2=0x00``
        (select by FID from current DF) because some cards only accept
        one variant.  Required before reading MF-level files such as
        EF.CardSecurity.
        """
        sm = self._sm()
        mf_cmds = [
            (0x00, 0xA4, 0x00, 0x0C, b"\x3f\x00"),
            (0x00, 0xA4, 0x00, 0x00, b"\x3f\x00"),
        ]
        for cmd in mf_cmds:
            apdu = sm.wrap_command(*cmd[:4], data=cmd[4])
            data, sw = self.card.send(apdu)
            if sw == 0x9000:
                _, psw = sm.unwrap_response(data, sw)
                if psw == 0x9000:
                    return
                self.log(f"SELECT MF P2={cmd[3]:02X} returned {psw:04X}")
            else:
                self.log(f"SELECT MF P2={cmd[3]:02X} failed: SW={sw:04X}")
        raise RuntimeError("SELECT MF failed with both P2=0x0C and P2=0x00")

    def _restore_lds1_context(self) -> None:
        """Restore the LDS1 eMRTD (app-DF) context after an MF-level access.

        EF.CardSecurity (MF) and EF.SOD (app DF) share FID 0x011D, resolved by
        the current DF context, so after a CardSecurity read the app-DF context
        must be restored or a later ``read_ef(0x011D, mf=False)`` would hit
        EF.CardSecurity again.  The context is switched back with an
        SM-wrapped SELECT-by-name: the plaintext form would be intercepted by
        the Java Card runtime as an applet re-selection, resetting the card's
        EAC state to SELECTED and dropping the BAC/PACE access level.  Failure
        is logged, not raised - the caller can retry or proceed anyway.
        """
        sm = self._sm()
        for p2 in (0x00, 0x0C):
            try:
                sel = sm.wrap_command(0x00, 0xA4, 0x04, p2, data=EMRTD_AID)
                data, sw = self.card.send(sel)
                if sw != 0x9000:
                    self.log(f"restore LDS1 (SM P2={p2:02X}) failed: SW={sw:04X}")
                    continue
                _, psw = sm.unwrap_response(data, sw)
                if psw == 0x9000:
                    return
                self.log(f"restore LDS1 (SM P2={p2:02X}) returned {psw:04X}")
            except Exception as exc:  # noqa: BLE001
                self.log(f"restore LDS1 context failed: {exc}")
        self.log("WARNING: could not restore LDS1 context after MF read")

    # ------------------------------------------------------------------
    # EF.CardAccess (pre-authentication protocol detection)
    # ------------------------------------------------------------------

    def read_card_access(self) -> CardAccessInfo:
        """Read EF.CardAccess from MF without secure messaging.

        ICAO Doc 9303 mandates that EF.CardAccess (FID 0x011C) is readable
        before authentication so the terminal can detect which access
        protocols the chip supports.  The file is a *pre-authentication*
        file that does not require SM.

        Tries three strategies to locate and read the file on real
        passports, falling back gracefully when a strategy is unsupported:

        1. Select by path from MF (ISO 7816-4 P1=0x08)
        2. Select MF, then select EF.CardAccess by FID
        3. Select EF.CardAccess by FID directly from the current DF

        Returns the parsed ``CardAccessInfo`` (pace_supported flag and
        best-matching PACEInfo details).  Always restores the eMRTD
        application context on exit so that authentication can proceed.
        """
        if self.card is None:
            raise RuntimeError("not connected")

        raw: Optional[bytes] = None
        tried_strategies: list = []

        # --- strategy 1: select by path from MF (ISO 7816-4 P1=0x08) ------
        # Path variants: some cards want the MF FID in the path, others don't.
        card_access_fid = self.CARD_ACCESS_FID.to_bytes(2, "big")
        path_variants = [
            bytes.fromhex("3F00") + card_access_fid,  # MF/EF
            card_access_fid,  # just EF (implicit MF)
        ]
        for path_data in path_variants:
            path_cmd = bytes.fromhex("00A4080C") + bytes([len(path_data)]) + path_data
            data, sw = self.card.send(path_cmd)
            tried_strategies.append(
                f"path-from-MF(len={len(path_data)}) -> SW={sw:04X}"
            )
            if sw == 0x9000:
                raw = self._read_card_access_content()
                break
            self.log(
                f"CardAccess: path({path_data.hex(' ').upper()})"
                f" returned SW={sw:04X}"
            )
            # Reset to eMRTD before trying next path variant
            self._restore_emrtd_context()

        # --- strategy 2: select MF, then select EF -----------------------
        if raw is None:
            mf_cmds = [
                bytes.fromhex("00A4000C02") + bytes.fromhex("3F00"),  # no FCI
                bytes.fromhex("00A4000002") + bytes.fromhex("3F00"),  # with FCI
            ]
            mf_ok = False
            for mf_cmd in mf_cmds:
                _data, sw = self.card.send(mf_cmd)
                if sw == 0x9000:
                    mf_ok = True
                    break
                tried_strategies.append(f"select-MF (cmd) -> SW={sw:04X}")

            if mf_ok:
                sel = bytes.fromhex("00A4000C02") + self.CARD_ACCESS_FID.to_bytes(
                    2, "big"
                )
                data, sw = self.card.send(sel)
                if sw == 0x9000:
                    raw = self._read_card_access_content()
                else:
                    tried_strategies.append(f"select-EF via MF -> SW={sw:04X}")
                    self.log(f"CardAccess: select EF via MF returned SW={sw:04X}")

        # --- strategy 3: select by FID directly from current DF ----------
        if raw is None:
            for p2 in (0x0C, 0x00):
                sel = (
                    bytes.fromhex("00A400")
                    + bytes([p2])
                    + bytes.fromhex("02")
                    + self.CARD_ACCESS_FID.to_bytes(2, "big")
                )
                data, sw = self.card.send(sel)
                if sw == 0x9000:
                    raw = self._read_card_access_content()
                    break
                tried_strategies.append(f"select-by-FID(p2={p2:02X}) -> SW={sw:04X}")

        # --- restore eMRTD context ---------------------------------------
        self._restore_emrtd_context()

        if raw is None:
            self.log(f"EF.CardAccess not found (tried: {', '.join(tried_strategies)})")
            return CardAccessInfo(False, None, b"")

        return parse_card_access(raw)

    def read_card_access_raw(self) -> Optional[bytes]:
        """Read EF.CardAccess from MF and return raw bytes (unparsed).

        Uses the same selection strategies as :meth:`read_card_access` but
        returns the raw EF content for export / offline analysis.
        """
        if self.card is None:
            raise RuntimeError("not connected")

        raw: Optional[bytes] = None
        card_access_fid = self.CARD_ACCESS_FID.to_bytes(2, "big")
        path_variants = [
            bytes.fromhex("3F00") + card_access_fid,
            card_access_fid,
        ]
        for path_data in path_variants:
            path_cmd = bytes.fromhex("00A4080C") + bytes([len(path_data)]) + path_data
            data, sw = self.card.send(path_cmd)
            if sw == 0x9000:
                raw = self._read_card_access_content()
                break
            self._restore_emrtd_context()

        if raw is None:
            mf_cmds = [
                bytes.fromhex("00A4000C02") + bytes.fromhex("3F00"),
                bytes.fromhex("00A4000002") + bytes.fromhex("3F00"),
            ]
            for mf_cmd in mf_cmds:
                _data, sw = self.card.send(mf_cmd)
                if sw == 0x9000:
                    break
            sel = bytes.fromhex("00A4000C02") + self.CARD_ACCESS_FID.to_bytes(2, "big")
            data, sw = self.card.send(sel)
            if sw == 0x9000:
                raw = self._read_card_access_content()

        if raw is None:
            for p2 in (0x0C, 0x00):
                sel = (
                    bytes.fromhex("00A400")
                    + bytes([p2])
                    + bytes.fromhex("02")
                    + self.CARD_ACCESS_FID.to_bytes(2, "big")
                )
                data, sw = self.card.send(sel)
                if sw == 0x9000:
                    raw = self._read_card_access_content()
                    break

        self._restore_emrtd_context()
        return raw

    def _read_card_access_content(self) -> bytes:
        """Read the currently-selected EF content into a bytes buffer."""
        buf = bytearray()
        offset = 0
        guard = 0
        while True:
            cmd = bytes.fromhex("00B0") + bytes(
                [
                    (offset >> 8) & 0xFF,
                    offset & 0xFF,
                    READ_CHUNK,
                ]
            )
            data, sw = self.card.send(cmd)
            if sw in EOF_SW:
                break
            if sw != 0x9000:
                if buf and sw in (0x6B00, 0x6700):
                    break
                raise RuntimeError(f"READ BINARY EF.CardAccess @{offset}: SW={sw:04X}")
            if not data:
                break
            buf.extend(data)
            offset += len(data)
            guard += 1
            if guard > 4096:
                raise RuntimeError("EF.CardAccess read did not terminate")
        raw = bytes(buf)
        self.log(f"EF.CardAccess: {len(raw)} bytes (pre-auth)")
        return raw

    def _restore_emrtd_context(self) -> None:
        """Re-select the eMRTD application after an MF-level access.

        Called after reading EF.CardAccess so that the LDS1 context is
        restored and authentication can proceed.  Failure is logged but
        not raised - the caller can retry or proceed anyway.
        """
        data, sw = self.card.send(SELECT_APPLET_1)
        if sw != 0x9000:
            data, sw = self.card.send(SELECT_APPLET_2)
            if sw != 0x9000:
                data, sw = self.card.send(bytes.fromhex("00A4040007") + EMRTD_AID)
        if sw != 0x9000:
            self.log(f"WARNING: re-select eMRTD after CardAccess: SW={sw:04X}")
        else:
            self.log("eMRTD application re-selected")

    def detect_protocol(self) -> CardAccessInfo:
        """Read EF.CardAccess and return the parsed result.

        Convenience method that wraps ``read_card_access``.  The returned
        ``CardAccessInfo.pace_supported`` flag and ``pace_info`` dict tell
        the caller which authentication method to use and which parameters
        (OID, curve) are available.

        When PACE is supported the terminal should prefer PACE over BAC.
        """
        return self.read_card_access()

    # EF.CardAccess (MF, 0x011C): the ICAO pre-authentication file.
    # Readable without secure messaging so the terminal can detect which
    # access protocols (PACE, BAC) the chip supports before authenticating.
    CARD_ACCESS_FID = 0x011C

    # EF.CardSecurity (MF, 0x011D): the ICAO carrier for the chip's security
    # info (ChipAuthentication public key / security capabilities).
    CARD_SECURITY_FID = 0x011D

    def read_card_security(self) -> bytes:
        """Read EF.CardSecurity (MF-level) and return its raw bytes.

        Some cards return EF.SOD content (tag ``0x77``) instead of
        EF.CardSecurity when the MF-level file is not yet accessible
        (e.g. before Terminal Authentication).  In that case a
        ``FileNotFoundError`` is raised so the caller can treat it as
        "not available yet" rather than a successful read.
        """
        raw = self.read_ef(self.CARD_SECURITY_FID, mf=True)
        if raw and raw[0] == 0x77:
            raise FileNotFoundError(
                "EF.CardSecurity not accessible (card returned EF.SOD content)"
            )
        self.log(f"EF.CardSecurity read ({len(raw)} bytes)")
        return raw

    def read_ef(self, fid: int, mf: bool = False) -> bytes:
        sm = self._sm()

        # MF-level files (e.g. EF.CardSecurity) share FIDs with LDS1 files
        # (CardSecurity 0x011D == LDS1 EF.SOD), so the applet resolves them by
        # current DF context. Select the Master File first to reach an MF file.
        if mf:
            self._select_mf()

        fid_bytes = fid.to_bytes(2, "big")

        # SELECT EF (over SM).  After _select_mf() the current DF is MF, so
        # use P2=0x00 (select by FID from current DF) rather than P2=0x0C
        # (select by path from MF).
        p2 = 0x00 if mf else 0x0C
        sel = sm.wrap_command(0x00, 0xA4, 0x00, p2, data=fid_bytes)
        data, sw = self.card.send(sel)
        if sw != 0x9000:
            raise RuntimeError(f"SELECT EF {fid:04X} failed: SW={sw:04X}")
        fci, psw = sm.unwrap_response(data, sw)
        if psw in (0x6A82, 0x6A88, 0x6282):
            raise FileNotFoundError(f"EF {fid:04X} not found ({psw:04X})")
        if psw != 0x9000:
            raise RuntimeError(f"SELECT EF {fid:04X} returned {psw:04X}")

        size = parse_fci_size(fci)  # real passports may provide this

        buf = bytearray()
        offset = 0
        guard = 0
        while True:
            if size is not None and offset >= size:
                break
            le = READ_CHUNK
            if size is not None:
                le = min(le, size - offset)
            if le <= 0:
                break

            cmd = sm.wrap_command(
                0x00, 0xB0, (offset >> 8) & 0xFF, offset & 0xFF, le=le
            )
            data, sw = self.card.send(cmd)
            if sw != 0x9000:
                raise RuntimeError(f"READ BINARY EF {fid:04X} @{offset}: SW={sw:04X}")
            chunk, psw = sm.unwrap_response(data, sw)
            if psw in EOF_SW:
                break  # end of file
            if psw != 0x9000:
                raise RuntimeError(
                    f"READ BINARY EF {fid:04X} @{offset} returned {psw:04X}"
                )
            if not chunk:
                break  # applet returns 0 bytes at EOF
            buf.extend(chunk)
            offset += len(chunk)

            guard += 1
            if guard > 4096 or offset > 128 * 1024:
                raise RuntimeError(f"EF {fid:04X} read did not terminate")

        # EF.SOD (0x011D) and EF.CardSecurity (0x011D) share the FID and are
        # resolved by the current DF context. Restore the LDS1 (app-DF)
        # context after an MF-level read so a later read_ef(0x011D, mf=False)
        # targets EF.SOD again.
        if mf:
            self._restore_lds1_context()

        return bytes(buf)

    # ------------------------------------------------------------------
    # full read
    # ------------------------------------------------------------------

    def read_all(self) -> PassportData:
        if self.card is None or self.session is None:
            raise RuntimeError("connect() and authenticate() first")

        pd = PassportData()
        pd.atr = self.atr
        pd.protocol = self.protocol

        # EF.COM -> which data groups exist
        try:
            com_raw = self.read_ef(0x011E)
            pd.raw[0x60] = com_raw
            pd.com = parse_com(com_raw)
            pd.tag_list = pd.com.get("tag_list", [])
            self.log(f"EF.COM tag list: {[f'{t:02X}' for t in pd.tag_list]}")
        except Exception as exc:  # noqa: BLE001
            pd.errors.append(f"EF.COM: {exc}")
            self.log(f"! EF.COM read failed: {exc}")

        # read each data group listed in EF.COM
        for tag in pd.tag_list:
            fid = DATA_GROUP_TAG_TO_FID.get(tag)
            if fid is None:
                continue
            name = DATA_GROUP_TAGS.get(tag, ("?", ""))[0]
            try:
                raw = self.read_ef(fid)
                pd.raw[tag] = raw
                self.log(f"Read {name} (tag {tag:02X}): {len(raw)} bytes")
            except FileNotFoundError:
                pd.errors.append(f"{name} not found on card")
                self.log(f"! {name} not found")
            except Exception as exc:  # noqa: BLE001
                pd.errors.append(f"{name}: {exc}")
                self.log(f"! {name} read failed: {exc}")

        self._parse(pd)

        # EF.SOD -> passive authentication
        try:
            sod_raw = self.read_ef(0x011D)
            pd.raw[0x77] = sod_raw
            pd.sod_info = parse_sod(sod_raw)
            dg_map = {
                DATA_GROUP_TAG_TO_NUM.get(tag, tag): raw
                for tag, raw in pd.raw.items()
                if tag not in (0x60, 0x77)
            }
            pd.pa_result = verify_pa(pd.sod_info, dg_map, eac_required_dgs={3, 4})
            self.log(
                f"EF.SOD: {len(sod_raw)} bytes, "
                f"{len(pd.sod_info.get('dg_hashes', {}))} DG hashes"
            )
            # DEBUG: dump first bytes to log
            self.log(f"SOD first 200: {sod_raw[:200].hex()}")
            # DEBUG: save raw SOD for inspection
            with open("/tmp/sod.raw", "wb") as f:
                f.write(sod_raw)
        except Exception as exc:  # noqa: BLE001
            pd.errors.append(f"EF.SOD: {exc}")
            self.log(f"! EF.SOD read failed: {exc}")

        # EF.CardSecurity (MF) -> security info. EF.CardSecurity (FID 0x011D)
        # collides with EF.SOD (also 0x011D); the card resolves colliding FIDs
        # by DF context, so this selects the Master File first (see read_ef).
        # EF.CardSecurity is readable once BAC/PACE secure messaging is up, so
        # it is attempted here and read last.
        try:
            cs_raw = self.read_card_security()
            pd.card_security_raw = cs_raw
            pd.card_security_info = parse_card_security(cs_raw)
            self.log(
                f"EF.CardSecurity: {len(cs_raw)} bytes, "
                f"{len(pd.card_security_info['infos'])} SecurityInfos"
            )
            with open("/tmp/cardsecurity.raw", "wb") as f:
                f.write(cs_raw)
        except FileNotFoundError:
            pd.errors.append("EF.CardSecurity not found on card")
            self.log("! EF.CardSecurity not found")
        except Exception as exc:  # noqa: BLE001
            pd.errors.append(f"EF.CardSecurity: {exc}")
            self.log(f"! EF.CardSecurity read failed: {exc}")

        # EF.CVCA (app-DF, FID 0x011C): the trust-point CAR list maintained
        # internally by the applet (ICAO Doc 9303-11 App. K). Collides with
        # MF EF.CardAccess (also 0x011C), resolved by DF context - the current
        # context is the app-DF after the CardSecurity read restored LDS1.
        try:
            cvca_raw = self.read_ef(self.CARD_ACCESS_FID)
            pd.cvca_raw = cvca_raw
            pd.cvca_info = parse_ef_cvca(cvca_raw)
            self.log(
                f"EF.CVCA: {len(cvca_raw)} bytes, CARs="
                f"{pd.cvca_info['cars_text']}"
            )
        except FileNotFoundError:
            pd.errors.append("EF.CVCA not found on card")
            self.log("! EF.CVCA not found")
        except Exception as exc:  # noqa: BLE001
            pd.errors.append(f"EF.CVCA: {exc}")
            self.log(f"! EF.CVCA read failed: {exc}")

        return pd

    def _parse(self, pd: PassportData) -> None:
        if 0x61 in pd.raw:
            try:
                pd.dg1 = parse_dg1(pd.raw[0x61])
            except Exception as exc:  # noqa: BLE001
                pd.errors.append(f"DG1 parse: {exc}")
        if 0x75 in pd.raw:
            try:
                pd.dg2 = parse_dg2(pd.raw[0x75])
            except Exception as exc:  # noqa: BLE001
                pd.errors.append(f"DG2 parse: {exc}")
        if 0x67 in pd.raw:
            try:
                pd.dg7 = parse_dg7(pd.raw[0x67])
            except Exception as exc:  # noqa: BLE001
                pd.errors.append(f"DG7 parse: {exc}")
        for tag in (0x6B, 0x6C, 0x6D, 0x68, 0x69, 0x6A):
            if tag in pd.raw:
                try:
                    pd.text_dgs[tag] = parse_text_dg(pd.raw[tag], tag)
                except Exception as exc:  # noqa: BLE001
                    pd.errors.append(f"DG {tag:02X} parse: {exc}")
