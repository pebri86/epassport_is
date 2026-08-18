#!/usr/bin/env python3
"""eMRTD Passport Reader - a JMRTD-style GUI for reading ICAO e-passports.

The application connects to a PC/SC reader, authenticates with **BAC** or
**PACE** (selectable in the toolbar), reads the Logical Data Structure
(EF.COM, EF.SOD and the data groups) over secure messaging and displays the
result in tabs, mirroring the layout of the well-known JMRTD (jmrtd) GUI:

* Passport (DG1) - the decoded machine readable zone
* Portrait (DG2) / Signature (DG7) - embedded images
* Personal / Document / Optional data (DG11-13) - field tables
* Data groups - raw EF overview + hex viewer
* Security (SOD / Passive Authentication) - integrity + signature check
* Log - the APDU / SM exchange

A **Load sample data** action lets the GUI run offline against the bundled
``test_data`` files when no card reader is available.

The interface is built with **CustomTkinter** (modern, theme-aware widgets);
``ttk.Treeview`` tables and ``tk.Text`` panes are retained where CustomTkinter
has no direct equivalent.

Run:
    .venv/bin/python epassport_gui.py

Dependencies (already in ``requirements.txt``): pyscard, pycryptodome, pillow,
customtkinter.
"""

from __future__ import annotations

import io
import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional

import customtkinter as ctk
from PIL import Image, ImageTk

from epassport_reader import EPassportReader
from epassport_reader.reader import PassportData
from epassport_reader.cvc import CardAccessInfo
from epassport_reader.pace import PARAM_ID_TO_EC, DEFAULT_EC
from epassport_reader.pa import verify_pa
from epassport_reader.samples import load_sample_data
from epassport_reader.tlvs import (
    DATA_GROUP_TAGS,
    DATA_GROUP_TAG_TO_FID,
    DATA_GROUP_TAG_TO_NUM,
)

MAX_IMAGE_W = 340
MAX_IMAGE_H = 420

FIELD_LABELS: Dict[str, str] = {
    "document_type": "Document type",
    "issuing_state": "Issuing state / org",
    "surname": "Surname (primary identifier)",
    "given_names": "Given names (secondary identifier)",
    "document_number": "Document number",
    "document_number_check": "Document number check digit",
    "nationality": "Nationality",
    "date_of_birth": "Date of birth",
    "date_of_birth_check": "Date of birth check digit",
    "sex": "Sex",
    "date_of_expiry": "Date of expiry",
    "date_of_expiry_check": "Date of expiry check digit",
    "personal_number": "Personal number",
    "composite_check": "Composite check digit",
}


class EpassportGui:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("eMRTD Passport Reader (JMRTD-style)")
        self.root.geometry("1180x760")
        self.root.minsize(980, 640)

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self._photo_refs: List[ImageTk.PhotoImage] = []
        self._last_pd: Optional[PassportData] = None
        self._reader = None  # connected EPassportReader (for CA/TA)
        self._ca_done = False  # Chip Authentication performed in session
        self._ta_done = False  # Terminal Authentication performed
        self._readers: List[str] = []
        self._recent_mrz: Optional[str] = None
        self._recent_mrz_file = Path.home() / ".epassport_is_recent_mrz"
        self._load_recent_mrz_from_disk()

        self.doc_var = tk.StringVar()
        self.dob_var = tk.StringVar()
        self.expiry_var = tk.StringVar()
        self.can_var = tk.StringVar()
        self.use_can_var = tk.BooleanVar(value=False)

        self._build_menu()
        self._build_toolbar()
        self._build_main()
        self._build_statusbar()

        self._after_id = self.root.after(120, self._poll_logs)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.refresh_readers()

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(
            label="Load sample data (offline demo)", command=self.load_sample
        )
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        mrz_menu = tk.Menu(menubar, tearoff=0)
        mrz_menu.add_command(label="Enter MRZ (two lines)...", command=self._enter_mrz)
        mrz_menu.add_command(label="Load recent MRZ", command=self._load_recent_mrz)
        menubar.add_cascade(label="MRZ", menu=mrz_menu)

        card_menu = tk.Menu(menubar, tearoff=0)
        card_menu.add_command(label="Refresh readers", command=self.refresh_readers)
        card_menu.add_command(label="Read passport", command=self.read_passport)
        card_menu.add_separator()
        card_menu.add_command(
            label="Chip Authentication (EAC)", command=self.do_chip_auth
        )
        card_menu.add_command(
            label="Terminal Authentication (EAC)", command=self.do_terminal_auth
        )
        card_menu.add_command(
            label="Active Authentication (AA)", command=self.do_active_auth
        )
        menubar.add_cascade(label="Card", menu=card_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._about)
        help_menu.add_separator()
        help_menu.add_command(
            label="Debug: Export raw SOD", command=self._debug_export_sod
        )
        help_menu.add_command(
            label="Debug: Export all raw EFs", command=self._debug_export_all_efs
        )
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

    def _build_toolbar(self) -> None:
        bar = ctk.CTkFrame(self.root, corner_radius=0)
        bar.pack(side="top", fill="x", padx=8, pady=(8, 4))

        ui_font = ctk.CTkFont(size=13)

        ctk.CTkLabel(bar, text="Reader:", font=ui_font).pack(side="left", padx=(8, 4))
        self.reader_combo = ctk.CTkComboBox(
            bar,
            width=280,
            state="readonly",
            command=lambda _v: None,
            font=ui_font,
        )
        self.reader_combo.pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            bar, text="\u21bb", width=32, command=self.refresh_readers, font=ui_font
        ).pack(side="left", padx=(0, 10))

        ctk.CTkLabel(bar, text="Protocol:", font=ui_font).pack(side="left", padx=(4, 4))
        self.protocol_combo = ctk.CTkComboBox(
            bar,
            values=["Auto-detect (ICAO)", "BAC", "PACE", "Hybrid (BAC+PACE)"],
            width=170,
            state="readonly",
            command=lambda _v: None,
            font=ui_font,
        )
        self.protocol_combo.set("Auto-detect (ICAO)")
        self.protocol_combo.pack(side="left", padx=(0, 12))

        ctk.CTkCheckBox(
            bar, text="Use CAN (PACE-CAN)", variable=self.use_can_var, font=ui_font
        ).pack(side="left", padx=(0, 12))

        ctk.CTkButton(
            bar,
            text="Load sample data",
            command=self.load_sample,
            fg_color=("gray80", "gray25"),
            text_color=("gray15", "white"),
            border_width=1,
            font=ui_font,
        ).pack(side="right", padx=(4, 0))

        self.read_btn = ctk.CTkButton(
            bar,
            text="\u25b6 Read passport",
            command=self.read_passport,
            width=130,
            font=ui_font,
        )
        self.read_btn.pack(side="right", padx=(4, 8))

        self.ca_btn = ctk.CTkButton(
            bar, text="Chip Auth (CA)", command=self.do_chip_auth, font=ui_font
        )
        self.ca_btn.pack(side="right", padx=(4, 0))
        self.ta_btn = ctk.CTkButton(
            bar, text="Terminal Auth (TA)", command=self.do_terminal_auth, font=ui_font
        )
        self.ta_btn.pack(side="right", padx=(4, 0))
        self.aa_btn = ctk.CTkButton(
            bar, text="Active Auth (AA)", command=self.do_active_auth, font=ui_font
        )
        self.aa_btn.pack(side="right", padx=(4, 0))
        self.dg3_btn = ctk.CTkButton(
            bar, text="Read DG3", command=self.do_read_dg3, font=ui_font
        )
        self.dg3_btn.pack(side="right", padx=(4, 0))

        self.ca_btn.configure(state="disabled")
        self.ta_btn.configure(state="disabled")
        self.aa_btn.configure(state="disabled")
        self.dg3_btn.configure(state="disabled")

    def _build_main(self) -> None:
        main = ctk.CTkFrame(self.root, corner_radius=0, fg_color="transparent")
        main.pack(side="top", fill="both", expand=True, padx=8, pady=4)

        # ---- left: MRZ entry panel ------------------------------------
        left = ctk.CTkFrame(main, corner_radius=8)
        left.pack(side="left", fill="y", padx=(0, 8))

        ctk.CTkLabel(
            left,
            text="Passport data (MRZ zone)",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(12, 2))
        ctk.CTkLabel(
            left,
            text=(
                "Enter the machine readable zone fields printed\n"
                "on the passport's data page. BAC and PACE-MRZ\n"
                "derive their keys from these values."
            ),
            justify="left",
            text_color=("gray40", "gray60"),
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=12, pady=(0, 8))

        form = ctk.CTkFrame(left, fg_color="transparent")
        form.pack(fill="x", padx=12)
        self._field(form, "Document number", self.doc_var, 0)
        self._field(form, "Date of birth (YYMMDD)", self.dob_var, 1)
        self._field(form, "Date of expiry (YYMMDD)", self.expiry_var, 2)
        self._field(form, "CAN (6 digits, PACE-CAN)", self.can_var, 3)

        ctk.CTkLabel(
            left,
            text=(
                "Check digits are computed automatically when\n"
                "9 / 6 / 6 character values are entered."
            ),
            justify="left",
            text_color=("gray40", "gray60"),
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=12, pady=(8, 0))

        summary = ctk.CTkFrame(left, corner_radius=8)
        summary.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(
            summary, text="Passport", font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=8, pady=(8, 2))
        self.mrz_summary = ctk.CTkLabel(
            summary,
            text="No passport read yet.",
            justify="left",
            font=ctk.CTkFont(family="Courier", size=14),
        )
        self.mrz_summary.pack(anchor="w", padx=8, pady=(0, 8))

        # ---- right: notebook with the result tabs ----------------------
        right = ctk.CTkFrame(main, corner_radius=0, fg_color="transparent")
        right.pack(side="left", fill="both", expand=True)

        self.tabview = ctk.CTkTabview(right)
        self.tabview.pack(fill="both", expand=True)
        self.tabview.configure(segmented_button_fg_color=("gray80", "gray22"))

        self.tab_mrz = self.tabview.add("Passport (DG1)")
        self.tab_photo = self.tabview.add("Portrait (DG2)")
        self.tab_sign = self.tabview.add("Signature (DG7)")
        self.tab_pers = self.tabview.add("Personal data (DG11)")
        self.tab_doc = self.tabview.add("Document data (DG12)")
        self.tab_opt = self.tabview.add("Optional data (DG13)")
        self.tab_groups = self.tabview.add("Data groups")
        self.tab_sec = self.tabview.add("Security (SOD/PA)")
        self.tab_log = self.tabview.add("Log")

        # MRZ tab
        self.mrz_lines = tk.Text(
            self.tab_mrz,
            height=4,
            font=("TkFixedFont", 14),
            background="#f8f8f8",
            relief="flat",
            padx=8,
            pady=6,
        )
        self.mrz_lines.pack(fill="x", padx=6, pady=(6, 0))
        self.mrz_lines.tag_configure("hl", background="#fff7cc")

        mrz_frame = self._make_table(self.tab_mrz, ("Field", "Value"))
        mrz_frame.pack(fill="both", expand=True, padx=6, pady=(6, 6))
        self.mrz_table = mrz_frame.table

        # image tabs
        self.photo_canvas = self._make_image_canvas(
            self.tab_photo, "No portrait (DG2) on card."
        )
        self.photo_canvas.pack(fill="both", expand=True, padx=6, pady=6)
        self.photo_meta = ctk.CTkLabel(
            self.tab_photo, text="", text_color=("gray40", "gray60")
        )
        self.photo_meta.pack(anchor="w", padx=8, pady=(0, 6))

        self.sign_canvas = self._make_image_canvas(
            self.tab_sign, "No signature (DG7) on card."
        )
        self.sign_canvas.pack(fill="both", expand=True, padx=6, pady=6)
        self.sign_meta = ctk.CTkLabel(
            self.tab_sign, text="", text_color=("gray40", "gray60")
        )
        self.sign_meta.pack(anchor="w", padx=8, pady=(0, 6))

        # text DG tables
        self.pers_table = self._make_table(
            self.tab_pers, ("Tag", "Field", "Value")
        ).table
        self.pers_table.master.pack(fill="both", expand=True, padx=6, pady=6)
        self.doc_table = self._make_table(self.tab_doc, ("Tag", "Field", "Value")).table
        self.doc_table.master.pack(fill="both", expand=True, padx=6, pady=6)
        self.opt_table = self._make_table(self.tab_opt, ("Tag", "Field", "Value")).table
        self.opt_table.master.pack(fill="both", expand=True, padx=6, pady=6)

        # data-groups tab
        self.groups_table = self._make_table(
            self.tab_groups, ("Group", "Tag", "Description", "Size")
        ).table
        self.groups_table.master.pack(fill="both", expand=False, padx=6, pady=(6, 4))
        self.groups_table.configure(height=8)

        ctk.CTkLabel(
            self.tab_groups,
            text="Raw bytes (select a group above)",
            text_color=("gray40", "gray60"),
        ).pack(anchor="w", padx=8)
        hex_frame = ctk.CTkFrame(self.tab_groups, corner_radius=6)
        hex_frame.pack(fill="both", expand=True, padx=6, pady=(4, 6))
        self.hex_text = tk.Text(hex_frame, font=("TkFixedFont", 11), wrap="none")
        sb = ttk.Scrollbar(hex_frame, orient="vertical", command=self.hex_text.yview)
        self.hex_text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.hex_text.pack(side="left", fill="both", expand=True)
        self.groups_table.bind("<<TreeviewSelect>>", self._on_group_selected)

        # security tab
        self.sec_text = tk.Text(
            self.tab_sec,
            font=("TkFixedFont", 11),
            wrap="word",
            state="disabled",
            background="#ffffff",
        )
        self.sec_text.pack(fill="both", expand=True, padx=6, pady=6)

        # log tab
        self.log_text = ctk.CTkTextbox(
            self.tab_log,
            font=ctk.CTkFont(family="Courier", size=15),
            wrap="none",
            fg_color=("#1e1e1e", "#1e1e1e"),
            text_color="#d4d4d4",
        )
        self.log_text.pack(fill="both", expand=True, padx=0, pady=0)
        self.log_text.configure(state="disabled")

    def _field(self, parent, label: str, var: tk.StringVar, row: int) -> None:
        ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(size=14)).grid(
            row=row, column=0, sticky="w", pady=3
        )
        entry = ctk.CTkEntry(
            parent, textvariable=var, width=220, font=ctk.CTkFont(size=14)
        )
        entry.grid(row=row, column=1, sticky="we", padx=(8, 0), pady=3)
        entry.bind("<Return>", lambda _e: self.read_passport())
        parent.columnconfigure(1, weight=1)

    def _make_table(self, parent, columns: tuple) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, corner_radius=6)
        table = ttk.Treeview(frame, columns=columns, show="headings", height=10)
        style = ttk.Style()
        try:
            style.configure("CTK.Treeview", font=("TkDefaultFont", 11))
            style.configure("CTK.Treeview.Heading", font=("TkDefaultFont", 11, "bold"))
            table.configure(style="CTK.Treeview")
        except tk.TclError:
            pass
        for col in columns:
            table.heading(col, text=col)
            table.column(col, width=190, anchor="w")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        table.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        frame.table = table
        return frame

    def _make_image_canvas(self, parent, placeholder: str) -> tk.Canvas:
        canvas = tk.Canvas(
            parent,
            background="#f0f0f0",
            highlightthickness=1,
            highlightbackground="#ccc",
        )
        canvas._placeholder = placeholder
        canvas._photo = None
        canvas.bind("<Configure>", lambda e: self._render_canvas(canvas))
        return canvas

    def _render_canvas(self, canvas: tk.Canvas) -> None:
        canvas.delete("all")
        photo = getattr(canvas, "_photo", None)
        w = max(canvas.winfo_width(), 10)
        h = max(canvas.winfo_height(), 10)
        if photo is not None:
            canvas.create_image(w / 2, h / 2, image=photo, anchor="center")
        else:
            canvas.create_text(
                w / 2,
                h / 2,
                text=getattr(canvas, "_placeholder", ""),
                fill="#888",
                font=("TkDefaultFont", 11),
            )

    def _build_statusbar(self) -> None:
        self.status_var = tk.StringVar(
            value="Ready. Select a reader and press Read passport."
        )
        bar = ctk.CTkLabel(
            self.root,
            textvariable=self.status_var,
            anchor="w",
            fg_color=("gray90", "gray20"),
            text_color=("gray15", "gray85"),
            corner_radius=0,
            font=ctk.CTkFont(size=13),
        )
        bar.pack(side="bottom", fill="x")

    # ------------------------------------------------------------------
    # reader management
    # ------------------------------------------------------------------

    def refresh_readers(self) -> None:
        try:
            probe = EPassportReader(protocol="BAC", log=self.log_cb)
            readers = probe.list_readers()
        except Exception as exc:  # noqa: BLE001
            readers = []
            self.log_cb(f"! reader scan failed: {exc}")
        self._readers = list(readers)
        self.reader_combo.configure(values=readers)
        if readers:
            self.reader_combo.set(readers[0])
            self.log_cb(f"Found {len(readers)} reader(s).")
            self.read_btn.configure(state="normal")
        else:
            self.log_cb(
                "No PC/SC readers found - use 'Load sample data' for an offline demo."
            )
            self.read_btn.configure(state="disabled")

    def log_cb(self, msg: str) -> None:
        self.log_queue.put(msg)

    # ------------------------------------------------------------------
    # reading
    # ------------------------------------------------------------------

    def read_passport(self) -> None:
        protocol_display = self.protocol_combo.get()
        if protocol_display == "Auto-detect (ICAO)":
            protocol = "AUTO"
        elif protocol_display == "BAC":
            protocol = "BAC"
        elif protocol_display == "PACE":
            protocol = "PACE"
        else:
            protocol = "HYBRID"

        doc = self.doc_var.get().strip()
        dob = self.dob_var.get().strip()
        expiry = self.expiry_var.get().strip()
        can = self.can_var.get().strip() if self.use_can_var.get() else None

        if not self.reader_combo.get():
            messagebox.showwarning("No reader", "Select a PC/SC reader first.")
            return

        reader_name = self.reader_combo.get()
        try:
            reader_idx = self._readers.index(reader_name)
        except ValueError:
            reader_idx = 0
        self.read_btn.configure(state="disabled")
        self._set_status(f"Reading passport ({protocol_display}) ...")
        self._log(
            f"--- Starting read: protocol={protocol_display}, reader={reader_name}"
        )

        threading.Thread(
            target=self._read_worker,
            args=(reader_idx, protocol, doc, dob, expiry, can, protocol_display),
            daemon=True,
        ).start()

    def _read_worker(
        self, reader_idx, protocol, doc, dob, expiry, can, protocol_display
    ) -> None:
        try:
            # Connect and detect protocol first (ICAO standard)
            probe = EPassportReader(
                protocol="BAC",
                doc_number=doc,
                dob=dob,
                expiry=expiry,
                can=can,
                log=self.log_cb,
            )
            probe.connect(reader_idx)

            card_access = None
            if protocol in ("AUTO", "HYBRID"):
                self.log_cb("Reading EF.CardAccess to detect supported protocols ...")
                try:
                    card_access = probe.read_card_access()
                except FileNotFoundError:
                    self.log_cb("! EF.CardAccess not found on card")
                except Exception as exc:
                    self.log_cb(f"! CardAccess read failed: {exc}")

            # Determine the final protocol
            if protocol == "AUTO":
                if card_access and card_access.pace_supported:
                    final_protocol = "PACE"
                    info = card_access.pace_info
                    self.log_cb(
                        f"Detected: {info['name']}"
                        + (f" (curve: {info['curve']})" if info.get("curve") else "")
                    )
                else:
                    final_protocol = "BAC"
                    self.log_cb(
                        "PACE not detected"
                        + (f" ({card_access.pace_info})" if card_access else "")
                        + ", falling back to BAC"
                    )
                self.root.after(
                    0,
                    lambda p=final_protocol: self._set_status(
                        f"Detected: {p}. Authenticating ..."
                    ),
                )
            else:
                final_protocol = protocol

            if final_protocol == "PACE" and not can and not (doc and dob and expiry):
                self.root.after(
                    0,
                    lambda: messagebox.showwarning(
                        "Missing credentials",
                        "PACE requires either a CAN (6 digits) or MRZ fields "
                        "(document number, date of birth, date of expiry).",
                    ),
                )
                self.root.after(
                    0, lambda: self._set_status("Failed: missing PACE credentials")
                )
                self.root.after(0, lambda: self.read_btn.configure(state="normal"))
                return

            if final_protocol == "BAC" and not (doc and dob and expiry):
                self.root.after(
                    0,
                    lambda: messagebox.showwarning(
                        "Missing MRZ data",
                        "BAC needs the document number, date of birth and "
                        "date of expiry from the passport's MRZ zone.",
                    ),
                )
                self.root.after(
                    0, lambda: self._set_status("Failed: missing MRZ fields for BAC")
                )
                self.root.after(0, lambda: self.read_btn.configure(state="normal"))
                return

            reader = EPassportReader(
                protocol=final_protocol,
                doc_number=doc,
                dob=dob,
                expiry=expiry,
                can=can,
                log=self.log_cb,
            )
            reader.card = probe.card
            reader.atr = probe.atr
            probe.card = None

            # Set the detected PACE parameters (OID + curve) whenever PACE may
            # be used (PACE protocol or HYBRID BAC+PACE).
            if card_access and card_access.pace_info:
                detected_oid = card_access.pace_info.get("oid")
                if detected_oid:
                    reader.pace_oid = detected_oid
                    self.log_cb(
                        f"PACE using detected OID: " f"{detected_oid.hex(':').upper()}"
                    )
                param_id = card_access.pace_info.get("parameter_id")
                ec = PARAM_ID_TO_EC.get(param_id, DEFAULT_EC)
                reader.pace_curve = ec
                self.log_cb(
                    f"PACE curve: {ec.name} "
                    f"(parameterId={param_id}, field={ec.field_size}B)"
                )

            if final_protocol == "HYBRID":
                reader.authenticate_hybrid()
            else:
                reader.authenticate()
            self.root.after(0, lambda r=reader: self._keep_reader(r))
            pd = reader.read_all()
            self.root.after(0, lambda: self._display(pd))
            self.root.after(
                0,
                lambda p=final_protocol: self._set_status(f"Read complete ({p})."),
            )
        except Exception as exc:
            self.log_cb(f"! ERROR: {exc}")
            self.root.after(0, lambda e=exc: self._set_status(f"Failed: {e}"))
        finally:
            self.root.after(0, lambda: self.read_btn.configure(state="normal"))

    def _keep_reader(self, reader) -> None:
        """Retain the connected+authenticated reader for the CA/TA/AA actions."""
        self._reader = reader
        self._ca_done = False
        self._ta_done = False
        self.ca_btn.configure(state="normal")
        self.ta_btn.configure(state="normal")
        self.aa_btn.configure(state="normal")
        self.dg3_btn.configure(state="disabled")

    def _set_buttons_busy(self, busy: bool) -> None:
        if busy:
            self.ca_btn.configure(state="disabled")
            self.ta_btn.configure(state="disabled")
            self.aa_btn.configure(state="disabled")
            self.dg3_btn.configure(state="disabled")
            self.read_btn.configure(state="disabled")
            return
        state = "normal" if self._reader is not None else "disabled"
        self.ca_btn.configure(state=state)
        self.ta_btn.configure(state=state)
        self.aa_btn.configure(state=state)
        self.dg3_btn.configure(
            state="normal" if self._reader is not None and self._ta_done else "disabled"
        )
        self.read_btn.configure(
            state="normal" if self.reader_combo.get() else "disabled"
        )

    # ------------------------------------------------------------------
    # EAC: Chip Authentication + Terminal Authentication
    # ------------------------------------------------------------------

    def do_chip_auth(self) -> None:
        if self._reader is None:
            messagebox.showwarning(
                "Not connected",
                "Read a passport first so the reader is connected and "
                "authenticated (BAC/PACE).",
            )
            return
        self._set_buttons_busy(True)
        self._set_status("Running Chip Authentication (EAC step 1) ...")
        self._log("--- Starting Chip Authentication (EAC CA) ---")
        threading.Thread(target=self._chip_auth_worker, daemon=True).start()

    def _chip_auth_worker(self) -> None:
        try:
            self._reader.chip_authentication()
            self._ca_done = True
            self.root.after(
                0,
                lambda: self._set_status(
                    "Chip Authentication OK - session upgraded to CA keys."
                ),
            )
            self.root.after(0, lambda: self._log("Chip Authentication OK."))
        except Exception as exc:  # noqa: BLE001
            self.log_cb(f"! Chip Authentication failed: {exc}")
            self.root.after(
                0, lambda e=exc: self._set_status(f"Chip Authentication failed: {e}")
            )
        finally:
            self.root.after(0, self._set_buttons_busy, False)

    def do_terminal_auth(self) -> None:
        if self._reader is None:
            messagebox.showwarning(
                "Not connected",
                "Read a passport first so the reader is connected and "
                "authenticated (BAC/PACE).",
            )
            return
        if not self._ca_done:
            messagebox.showwarning(
                "Chip Auth required",
                "Terminal Authentication must run after Chip Authentication. "
                "Press 'Chip Auth (CA)' first.",
            )
            return
        cvc_path = filedialog.askopenfilename(
            title="Select terminal CVC (DER)",
            filetypes=[("CVC", "*.cvc *.der *.bin"), ("All files", "*.*")],
        )
        if not cvc_path:
            return
        key_path = filedialog.askopenfilename(
            title="Select terminal EC private key (PEM/DER)",
            filetypes=[("Key", "*.pem *.der *.key"), ("All files", "*.*")],
        )
        if not key_path:
            return
        self._set_buttons_busy(True)
        self._set_status("Running Terminal Authentication (EAC step 2) ...")
        self._log("--- Starting Terminal Authentication (EAC TA) ---")
        threading.Thread(
            target=self._terminal_auth_worker,
            args=(cvc_path, key_path),
            daemon=True,
        ).start()

    def _terminal_auth_worker(self, cvc_path: str, key_path: str) -> None:
        try:
            from Crypto.PublicKey import ECC, RSA

            with open(cvc_path, "rb") as f:
                terminal_cvc = f.read()
            with open(key_path, "rb") as f:
                key_bytes = f.read()
            try:
                terminal_key = ECC.import_key(key_bytes)
            except (ValueError, TypeError):
                terminal_key = RSA.import_key(key_bytes)
            self._reader.terminal_authentication(terminal_cvc, terminal_key)
            self._ta_done = True
            self.root.after(
                0,
                lambda: self._set_status(
                    "Terminal Authentication OK - terminal authorized."
                ),
            )
            self.root.after(0, lambda: self._log("Terminal Authentication OK."))

            # EAC succeeded: re-read data groups that require EAC (DG3, DG4, ...).
            # read_all() only reads DGs listed in EF.COM's tag list, so we must
            # explicitly read DG3/DG4 here and then re-run PA.
            try:
                self.root.after(
                    0, lambda: self._log("Re-reading EAC-protected data groups ...")
                )
                pd = self._reader.read_all()
                for tag, fid in ((0x63, 0x0103), (0x76, 0x0104)):
                    try:
                        raw = self._reader.read_ef(fid)
                        pd.raw[tag] = raw
                        self.root.after(
                            0,
                            lambda t=tag, r=raw: self._log(
                                f"Read DG{t:02X} ({len(r)} bytes)"
                            ),
                        )
                    except Exception as exc:  # noqa: BLE001
                        self.root.after(
                            0,
                            lambda t=tag, e=exc: self._log(
                                f"! DG{t:02X} read failed: {e}"
                            ),
                        )
                # Re-run PA with the now-complete DG set (DG3/DG4 included).
                try:
                    dg_map = {
                        DATA_GROUP_TAG_TO_NUM.get(tag, tag): raw
                        for tag, raw in pd.raw.items()
                        if tag not in (0x60, 0x77)
                    }
                    pd.pa_result = verify_pa(
                        pd.sod_info, dg_map, eac_required_dgs=set()
                    )
                    self.root.after(
                        0,
                        lambda: self._log(
                            "Passive Authentication re-run with EAC DGs."
                        ),
                    )
                except Exception as exc:  # noqa: BLE001
                    self.root.after(
                        0, lambda e=exc: self._log(f"! PA re-run failed: {e}")
                    )
                self.root.after(0, lambda p=pd: self._display(p))
                self.root.after(
                    0,
                    lambda: self._set_status(
                        "Terminal Authentication OK - DGs read (see Data groups tab)."
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                self.log_cb(f"! Re-read after TA failed: {exc}")
        except Exception as exc:  # noqa: BLE001
            self.log_cb(f"! Terminal Authentication failed: {exc}")
            self.root.after(
                0,
                lambda e=exc: self._set_status(f"Terminal Authentication failed: {e}"),
            )
        finally:
            self.root.after(0, self._set_buttons_busy, False)

    def do_read_dg3(self) -> None:
        if self._reader is None or not self._ta_done:
            messagebox.showwarning(
                "Not authorized",
                "Run Terminal Authentication first so EAC-protected "
                "data groups can be read.",
            )
            return
        self._set_buttons_busy(True)
        self._set_status("Reading DG3 ...")
        self._log("--- Reading DG3 (fingerprints) ---")
        threading.Thread(target=self._read_dg3_worker, daemon=True).start()

    def _read_dg3_worker(self) -> None:
        try:
            raw = self._reader.read_ef(0x0103)
            pd = self._last_pd
            pd.raw[0x63] = raw
            self.root.after(0, lambda: self._log(f"DG3 read ({len(raw)} bytes)"))
            self.root.after(0, lambda p=pd: self._display(p))
            self.root.after(0, lambda: self._set_status("DG3 read."))
        except Exception as exc:  # noqa: BLE001
            self.log_cb(f"! DG3 read failed: {exc}")
            self.root.after(0, lambda e=exc: self._set_status(f"DG3 read failed: {e}"))
        finally:
            self.root.after(0, self._set_buttons_busy, False)

    def do_active_auth(self) -> None:
        if self._reader is None:
            messagebox.showwarning(
                "Not connected",
                "Read a passport first so the reader is connected and "
                "authenticated (BAC).",
            )
            return
        self._set_buttons_busy(True)
        self._set_status("Running Active Authentication ...")
        self._log("--- Starting Active Authentication (AA) ---")
        threading.Thread(target=self._active_auth_worker, daemon=True).start()

    def _active_auth_worker(self) -> None:
        try:
            result = self._reader.active_authentication()
            if result.verified:
                self.root.after(
                    0,
                    lambda: self._set_status(
                        "Active Authentication OK - chip holds the AA key."
                    ),
                )
                self.root.after(
                    0,
                    lambda: self._log(
                        "Active Authentication OK (signature verified against "
                        "EF.DG15)."
                    ),
                )
            else:
                self.root.after(
                    0,
                    lambda r=result: self._set_status(
                        f"Active Authentication FAILED: {r.reason}"
                    ),
                )
                self.root.after(
                    0,
                    lambda r=result: self._log(
                        f"! Active Authentication FAILED: {r.reason}"
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            self.log_cb(f"! Active Authentication failed: {exc}")
            self.root.after(
                0, lambda e=exc: self._set_status(f"Active Authentication failed: {e}")
            )
        finally:
            self.root.after(0, self._set_buttons_busy, False)

    # ------------------------------------------------------------------
    # MRZ helpers (load doc number / DOB / expiry from a recent MRZ)
    # ------------------------------------------------------------------

    def _mrz_to_fields(self, mrz: str) -> Optional[tuple]:
        """Extract (document_number, dob, expiry) in YYMMDD from a TD3 MRZ.

        Accepts the raw two-line MRZ (with '<' fillers) or the space-padded
        form shown in the GUI. Returns None if the string cannot be parsed.
        """
        norm = "".join(mrz.splitlines()).replace(" ", "<").upper()
        if len(norm) < 88:
            return None
        line2 = norm[44:88]
        doc = line2[0:9].replace("<", "")
        dob = line2[13:19]
        expiry = line2[21:27]
        if not doc or not dob.isdigit() or not expiry.isdigit():
            return None
        return doc, dob, expiry

    def _apply_mrz(self, mrz: str) -> bool:
        """Fill the doc/DOB/expiry fields from an MRZ and remember it as recent."""
        fields = self._mrz_to_fields(mrz)
        if not fields:
            return False
        doc, dob, expiry = fields
        self.doc_var.set(doc)
        self.dob_var.set(dob)
        self.expiry_var.set(expiry)
        self._recent_mrz = mrz
        self._save_recent_mrz_to_disk()
        self.log_cb(f"Loaded MRZ: doc={doc} dob={dob} doe={expiry}")
        return True

    def _enter_mrz(self) -> None:
        """Open a dialog to paste a two-line MRZ and load its fields."""
        win = ctk.CTkToplevel(self.root)
        win.title("Enter MRZ")
        win.geometry("560x200")
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()
        ctk.CTkLabel(
            win,
            text="Paste the two-line MRZ (TD3):",
            anchor="w",
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=12, pady=(12, 4))
        txt = ctk.CTkTextbox(
            win, height=80, font=ctk.CTkFont(family="Courier", size=14)
        )
        txt.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        if self._recent_mrz:
            txt.insert("1.0", self._recent_mrz)

        def ok() -> None:
            val = txt.get("1.0", "end").strip()
            win.destroy()
            if not self._apply_mrz(val):
                messagebox.showerror(
                    "MRZ",
                    "Could not parse the MRZ into document number / DOB / "
                    "expiry. Paste the full two-line MRZ.",
                )

        def cancel() -> None:
            win.destroy()

        bar = ctk.CTkFrame(win, fg_color="transparent")
        bar.pack(fill="x", padx=12, pady=(0, 12))
        ctk.CTkButton(bar, text="Load", width=90, command=ok).pack(
            side="right", padx=(6, 0)
        )
        ctk.CTkButton(bar, text="Cancel", width=90, command=cancel).pack(side="right")
        win.bind("<Return>", lambda _e: ok())
        win.bind("<Escape>", lambda _e: cancel())
        txt.focus_set()

    def _load_recent_mrz_from_disk(self) -> None:
        """Load the most recent MRZ from the persistence file, if any."""
        try:
            if self._recent_mrz_file.exists():
                text = self._recent_mrz_file.read_text(encoding="utf-8").strip()
                if text:
                    self._recent_mrz = text
        except OSError:
            pass

    def _save_recent_mrz_to_disk(self) -> None:
        """Persist the current recent MRZ to disk."""
        try:
            if self._recent_mrz:
                self._recent_mrz_file.parent.mkdir(parents=True, exist_ok=True)
                self._recent_mrz_file.write_text(self._recent_mrz, encoding="utf-8")
            else:
                try:
                    self._recent_mrz_file.unlink()
                except OSError:
                    pass
        except OSError:
            pass

    def _load_recent_mrz(self) -> None:
        """Reload the doc/DOB/expiry fields from the most recent MRZ."""
        if not self._recent_mrz:
            messagebox.showinfo(
                "Recent MRZ", "No MRZ entered yet. Use MRZ -> Enter MRZ first."
            )
            return
        if not self._apply_mrz(self._recent_mrz):
            messagebox.showerror("Recent MRZ", "Stored MRZ could not be parsed.")

    # ------------------------------------------------------------------
    # sample data (offline demo)
    # ------------------------------------------------------------------

    def load_sample(self) -> None:
        try:
            pd = load_sample_data()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Sample data", f"Could not load sample data: {exc}")
            return
        self._log("Loaded bundled sample data (test_data/*.bin) - offline demo.")
        self._log("Note: the sample EF.SOD is a truncated dummy, so PA is unavailable.")
        self._display(pd, sample=True)
        self._set_status("Sample data loaded (offline).")

    # ------------------------------------------------------------------
    # display
    # ------------------------------------------------------------------

    @staticmethod
    def _clear_table(table: ttk.Treeview) -> None:
        for item in table.get_children():
            table.delete(item)

    def _display(self, pd: PassportData, sample: bool = False) -> None:
        self._last_pd = pd

        # --- MRZ / DG1 ------------------------------------------------
        self._clear_table(self.mrz_table)
        self.mrz_lines.delete("1.0", tk.END)
        if pd.dg1:
            self.mrz_lines.insert(tk.END, "  " + pd.dg1["line1"] + "\n")
            self.mrz_lines.insert(tk.END, "  " + pd.dg1["line2"] + "\n", "hl")
            mrz = pd.dg1.get("line1", "").replace(" ", "<") + pd.dg1.get(
                "line2", ""
            ).replace(" ", "<")
            if mrz:
                self._recent_mrz = mrz
                self._save_recent_mrz_to_disk()
            for key, label in FIELD_LABELS.items():
                value = pd.dg1.get(key, "")
                self.mrz_table.insert("", tk.END, values=(label, value))
        else:
            self.mrz_lines.insert(tk.END, "  No DG1 (MRZ) data on card.\n")

        if pd.dg1:
            name = f"{pd.dg1['surname']} {pd.dg1['given_names']}".strip() or "(unknown)"
            self.mrz_summary.configure(
                text=(
                    f"Holder : {name}\n"
                    f"Number : {pd.dg1['document_number']}\n"
                    f"Nation : {pd.dg1['nationality']}\n"
                    f"DOB    : {pd.dg1['date_of_birth']}\n"
                    f"Expiry : {pd.dg1['date_of_expiry']}"
                )
            )
        else:
            self.mrz_summary.configure(text="No passport read yet.")

        # --- images ----------------------------------------------------
        self._show_image(
            self.photo_canvas, pd.dg2.get("image_bytes") if pd.dg2 else None
        )
        if pd.dg2 and pd.dg2.get("image_bytes"):
            meta = pd.dg2.get("metadata") or {}
            bits = ", ".join(f"{k}={v}" for k, v in meta.items())
            self.photo_meta.configure(
                text=f"DG2  {pd.dg2.get('image_format', '')}  {bits}"
            )
        else:
            self.photo_meta.configure(text="")

        self._show_image(
            self.sign_canvas, pd.dg7.get("image_bytes") if pd.dg7 else None
        )
        if pd.dg7 and pd.dg7.get("image_bytes"):
            self.sign_meta.configure(text=f"DG7  {pd.dg7.get('image_format', '')}")
        else:
            self.sign_meta.configure(text="")

        # --- text data groups ------------------------------------------
        for tag, table in (
            (0x6B, self.pers_table),
            (0x6C, self.doc_table),
            (0x6D, self.opt_table),
        ):
            self._clear_table(table)
            fields = pd.text_dgs.get(tag, [])
            for f in fields:
                table.insert("", tk.END, values=(f["tag"], f["name"], f["value"]))
            if not fields:
                table.insert(
                    "",
                    tk.END,
                    values=("--", "--", "Data group not present on this document."),
                )

        # --- data groups -----------------------------------------------
        self._clear_table(self.groups_table)
        self.hex_text.delete("1.0", tk.END)
        for tag, raw in sorted(pd.raw.items()):
            name, desc = DATA_GROUP_TAGS.get(tag, ("?", ""))
            self.groups_table.insert(
                "",
                tk.END,
                values=(name, f"{tag:02X}", desc, f"{len(raw)} bytes"),
                tags=(str(tag),),
            )

        # --- security / PA ---------------------------------------------
        self._render_security(pd)

        for err in pd.errors:
            self.log_cb(f"! {err}")

        self.tabview.set("Passport (DG1)")

    def _render_security(self, pd: PassportData) -> None:
        self.sec_text.config(state="normal")
        self.sec_text.delete("1.0", tk.END)
        self.sec_text.tag_configure("h", font=("TkDefaultFont", 11, "bold"))

        # --- EF.CardSecurity (MF): security info -------------------------
        if pd.card_security_info:
            cs = pd.card_security_info
            self.sec_text.insert(
                tk.END,
                f"EF.CardSecurity (MF) - {cs['raw_len']} bytes\n",
                "h",
            )
            infos = cs.get("infos") or []
            if infos:
                for i, si in enumerate(infos, 1):
                    protocol = si.get("protocol")
                    line = (
                        f"  SecurityInfo {i}: {protocol}"
                        if protocol
                        else f"  SecurityInfo {i}: (unparsed)"
                    )
                    self.sec_text.insert(tk.END, line + "\n")
                    if si.get("_parse_error"):
                        self.sec_text.insert(
                            tk.END, f"    parse error: {si['_parse_error']}\n"
                        )
                    if si.get("oid"):
                        self.sec_text.insert(
                            tk.END,
                            f"    OID    : {si['oid'].hex(':').upper()}\n",
                        )
                    if si.get("version") is not None:
                        self.sec_text.insert(
                            tk.END,
                            f"    version: {si['version']}\n",
                        )
                    if si.get("key_id"):
                        self.sec_text.insert(
                            tk.END,
                            f"    keyId  : {si['key_id'].hex(':').upper()}\n",
                        )
                    if si.get("public_key"):
                        pk = si["public_key"]
                        self.sec_text.insert(
                            tk.END,
                            f"    pubkey : {pk[:24].hex(' ').upper()}... "
                            f"({len(pk)} bytes)\n",
                        )
            else:
                self.sec_text.insert(tk.END, "  (no SecurityInfo parsed)\n")
        elif pd.card_security_raw:
            self.sec_text.insert(
                tk.END,
                f"EF.CardSecurity (MF) - {len(pd.card_security_raw)} bytes "
                "(unparsed)\n",
                "h",
            )

        # --- EF.SOD / Passive Authentication -----------------------------
        if not pd.sod_info:
            if not pd.card_security_info and not pd.card_security_raw:
                self.sec_text.insert(tk.END, "No security data read.\n")
            else:
                self.sec_text.insert(tk.END, "\nEF.SOD was not read.\n")
            self.sec_text.config(state="disabled")
            return

        info = pd.sod_info
        self.sec_text.insert(tk.END, "\nEF.SOD (Document Security Object)\n", "h")
        self.sec_text.insert(tk.END, f"  raw bytes    : {len(pd.raw.get(0x77, b''))}\n")
        self.sec_text.insert(
            tk.END, f"  digest alg   : {info.get('digest_algorithm')}\n"
        )
        self.sec_text.insert(
            tk.END, f"  signature    : {info.get('signature_algorithm')}\n"
        )
        self.sec_text.insert(
            tk.END,
            f"  certificate  : {info.get('certificate_subject') or 'none embedded'}\n",
        )
        if info.get("parse_error"):
            self.sec_text.insert(tk.END, f"  parse        : {info['parse_error']}\n")

        self.sec_text.insert(tk.END, "\nData-group hash verification\n", "h")
        pa = pd.pa_result or {}
        if pa.get("dg_results"):
            for dg_num, row in pa["dg_results"].items():
                status = row["status"]
                self.sec_text.insert(
                    tk.END,
                    f"  DG{dg_num:02d}  {status:8s} stored={row['stored'][:16]}... "
                    f"computed={row['computed'][:16] if row['computed'] else 'n/a'}...\n",
                )
        else:
            self.sec_text.insert(tk.END, "  (no data-group hashes available in SOD)\n")

        overall = pa.get("overall", "n/a")
        self.sec_text.insert(
            tk.END, f"\nOverall Passive Authentication : {overall}\n", "pa"
        )
        self.sec_text.insert(
            tk.END, f"Signature validation            : {pa.get('signature_valid')}\n"
        )
        for note in pa.get("notes", []):
            self.sec_text.insert(tk.END, f"  - {note}\n")

        self.sec_text.tag_configure("h", font=("TkDefaultFont", 11, "bold"))
        color = {"PASS": "#006400", "FAIL": "#8b0000"}.get(overall, "#b8860b")
        self.sec_text.tag_configure(
            "pa",
            foreground=color,
            font=("TkDefaultFont", 11, "bold"),
        )
        self.sec_text.config(state="disabled")

    def _show_image(self, canvas: tk.Canvas, image_bytes: Optional[bytes]) -> None:
        canvas._photo = None
        canvas.delete("all")
        if not image_bytes:
            self._render_canvas(canvas)
            return
        try:
            img = Image.open(io.BytesIO(image_bytes))
            img.thumbnail((MAX_IMAGE_W, MAX_IMAGE_H))
            photo = ImageTk.PhotoImage(img)
            self._photo_refs.append(photo)  # keep a reference
            self._photo_refs = self._photo_refs[-20:]
            canvas._photo = photo
            self._render_canvas(canvas)
        except Exception as exc:  # noqa: BLE001
            self.log_cb(f"! could not render image: {exc}")
            self._render_canvas(canvas)

    def _on_group_selected(self, _event=None) -> None:
        sel = self.groups_table.selection()
        if not sel or self._last_pd is None:
            return
        item = sel[0]
        try:
            tag = int(self.groups_table.item(item, "tags")[0])
        except (IndexError, ValueError):
            return
        raw = self._last_pd.raw.get(tag)
        if raw is None:
            return
        self.hex_text.delete("1.0", tk.END)
        for i in range(0, len(raw), 16):
            chunk = raw[i : i + 16]
            hexpart = " ".join(f"{b:02X}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            self.hex_text.insert(tk.END, f"{i:04X}  {hexpart:<47}  {asc}\n")

    # ------------------------------------------------------------------
    # logging / status / lifecycle
    # ------------------------------------------------------------------

    def _log(self, msg: str) -> None:
        self.log_queue.put(msg)

    def _set_status(self, msg: str) -> None:
        self.status_var.set(msg)

    def _poll_logs(self) -> None:
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_text.configure(state="normal")
                self.log_text.insert(tk.END, msg + "\n")
                self.log_text.see(tk.END)
                self.log_text.configure(state="disabled")
                if msg.startswith("!"):
                    self._set_status(msg.lstrip("! ").strip())
        except queue.Empty:
            pass
        self._after_id = self.root.after(120, self._poll_logs)

    def _about(self) -> None:
        messagebox.showinfo(
            "About",
            "eMRTD Passport Reader (JMRTD-style)\n\n"
            "A Python GUI that reads ICAO Doc 9303 e-passports via PC/SC.\n"
            "ICAO standard flow: reads EF.CardAccess first to auto-detect\n"
            "supported protocols (PACE/BAC), then authenticates accordingly.\n"
            "Manual protocol override (BAC, PACE) available in the toolbar.\n\n"
            "Offline demo: File -> Load sample data.",
        )

    def _debug_export_sod(self) -> None:
        if not self._last_pd or 0x77 not in self._last_pd.raw:
            messagebox.showinfo("Debug export", "No SOD loaded. Read a passport first.")
            return
        sod = self._last_pd.raw[0x77]
        path = filedialog.asksaveasfilename(
            title="Save raw SOD",
            defaultextension=".bin",
            filetypes=[("Binary", "*.bin"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "wb") as f:
            f.write(sod)
        self.log_cb(f"Saved SOD ({len(sod)} bytes) to {path}")

    def _debug_export_all_efs(self) -> None:
        if not self._last_pd:
            messagebox.showinfo(
                "Debug export", "No passport data loaded. Read a passport first."
            )
            return
        directory = filedialog.askdirectory(
            title="Select directory to export raw EF files"
        )
        if not directory:
            return
        from epassport_reader.tlvs import DATA_GROUP_TAGS

        tag_to_name = {tag: name for tag, (name, _desc) in DATA_GROUP_TAGS.items()}
        count = 0

        # Export DGs, EF.COM, EF.SOD from pd.raw
        for tag, raw in self._last_pd.raw.items():
            name = tag_to_name.get(tag, f"Tag_{tag:02X}")
            filename = f"EF.{name}.bin"
            path = os.path.join(directory, filename)
            with open(path, "wb") as f:
                f.write(raw)
            count += 1
            self.log_cb(f"Exported {filename} ({len(raw)} bytes)")

        # Export EF.CardSecurity (MF) if available
        if self._last_pd.card_security_raw:
            path = os.path.join(directory, "EF.CardSecurity.bin")
            with open(path, "wb") as f:
                f.write(self._last_pd.card_security_raw)
            count += 1
            self.log_cb(
                f"Exported EF.CardSecurity.bin ({len(self._last_pd.card_security_raw)} bytes)"
            )

        # Try to read and export EF.CardAccess (MF) if a reader is connected
        if self._reader is not None:
            try:
                card_access_raw = self._reader.read_card_access_raw()
                if card_access_raw:
                    path = os.path.join(directory, "EF.CardAccess.bin")
                    with open(path, "wb") as f:
                        f.write(card_access_raw)
                    count += 1
                    self.log_cb(
                        f"Exported EF.CardAccess.bin ({len(card_access_raw)} bytes)"
                    )
            except Exception as exc:  # noqa: BLE001
                self.log_cb(f"! EF.CardAccess export failed: {exc}")

        self.log_cb(f"Exported {count} EF files to {directory}")
        messagebox.showinfo(
            "Debug export", f"Exported {count} EF files to:\n{directory}"
        )

    def _on_close(self) -> None:
        if self._after_id:
            self.root.after_cancel(self._after_id)
        self.root.destroy()


def main() -> int:
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    EpassportGui(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
