"""Evidence-driven ICAO / EACv2 coverage report.

Captures a live BAC/PACE + EACv2 (Chip / Terminal / Active Authentication)
session against a card and serialises a conformance-oriented report to JSON
for an external reviewer.

The report is layered so each stage carries the *cryptographic evidence* that
was actually used (fingerprints only - never raw key material), plus access-
control and terminal-chain facts, plus functional / security / negative
coverage and an overall readiness label.

Layers
------
1. ``session``        meta + resolved parameters
2. ``result``         coverage scores + overall readiness
3. ``coverage``       functional / security / negative test matrices
4. ``evidence``       per-stage artefacts, DG access matrix, EF.CVCA, transcript
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

SCHEMA_VERSION = 2

# Ordered live stages (status: not_run / running / ok / failed / skipped).
# ``functional`` names the coverage test this stage feeds.
STAGES: List[Dict[str, str]] = [
    {"id": "connect", "label": "Card connect / applet select", "phase": "basic_access"},
    {"id": "card_access", "label": "EF.CardAccess protocol detect", "phase": "basic_access"},
    {"id": "authentication", "label": "Authentication (BAC / PACE)", "phase": "basic_access"},
    {"id": "passive_auth", "label": "Passive auth (SOD + DG hashes)", "phase": "basic_access"},
    {"id": "chip_auth", "label": "Chip Authentication (CA)", "phase": "eacv2"},
    {"id": "terminal_auth", "label": "Terminal Authentication (TA)", "phase": "eacv2"},
    {"id": "active_auth", "label": "Active Authentication (AA)", "phase": "basic_access"},
    {"id": "dg_read", "label": "Data-group read", "phase": "basic_access"},
    {"id": "eac_dg_read", "label": "EAC-protected DG read (post-TA)", "phase": "eacv2"},
]

# Functional (positive-path) coverage matrix: exercised on this live run.
FUNCTIONAL_TESTS: List[Dict[str, str]] = [
    {"id": "connect", "label": "Card connect", "stage": "connect"},
    {"id": "pace_detect", "label": "PACE detected (EF.CardAccess)", "stage": "card_access"},
    {"id": "authentication", "label": "Authentication succeeds (BAC/PACE)", "stage": "authentication"},
    {"id": "passive_auth", "label": "Passive auth verifies (SOD/hashes)", "stage": "passive_auth"},
    {"id": "chip_auth", "label": "Chip Authentication succeeds", "stage": "chip_auth"},
    {"id": "terminal_auth", "label": "Terminal Authentication succeeds", "stage": "terminal_auth"},
    {"id": "active_auth", "label": "Active Authentication succeeds", "stage": "active_auth"},
    {"id": "dg_read", "label": "Data-group read", "stage": "dg_read"},
    {"id": "eac_dg_read", "label": "DG3/DG4 readable after TA", "stage": "eac_dg_read"},
]

# Security-critical stages whose success requires cryptographic evidence.
SECURITY_STAGES = ("chip_auth", "terminal_auth", "active_auth")

# Negative (adversarial) coverage matrix: must be run by a dedicated harness;
# a negative test passes when the *rejected* outcome is observed.
NEGATIVE_TESTS: List[Dict[str, str]] = [
    {"id": "wrong_mrz", "label": "Wrong MRZ rejected"},
    {"id": "wrong_can", "label": "Wrong CAN rejected"},
    {"id": "bac_fallback", "label": "BAC fallback path"},
    {"id": "invalid_cvc", "label": "Invalid terminal CVC rejected"},
    {"id": "expired_dv", "label": "Expired DV certificate"},
    {"id": "revoked_is", "label": "Revoked IS certificate"},
    {"id": "wrong_challenge_signature", "label": "AA wrong-challenge signature"},
    {"id": "dg3_before_ta", "label": "DG3 denied before TA"},
    {"id": "link_cert_rollover", "label": "CVCA link-certificate rollover"},
]

STATUS = {"not_run", "running", "ok", "failed", "skipped"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _readiness(func: float, sec: float, neg: float) -> str:
    if func < 0.3:
        return "setup-only / not exercised"
    if func >= 0.8 and sec >= 0.8:
        if neg >= 0.8:
            return "Advanced EACv2 (positive + negative)"
        return "Advanced EACv2 (positive path)"
    return "Partial EACv2"


class SessionTrace:
    """Thread-safe accumulator for one live session (stages + evidence)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.schema_version = SCHEMA_VERSION
        self.report_name = "epassport_is evidence-driven EACv2 coverage report"
        self.started_at = _now()
        self.generated_at: Optional[str] = None
        self.meta: Dict[str, object] = {}
        self.stages: Dict[str, Dict[str, object]] = {}
        self.functional: Dict[str, Dict[str, object]] = {}
        self.negative: Dict[str, Dict[str, object]] = {}
        self.evidence: Dict[str, Dict[str, object]] = {}
        self.dg_access: Optional[List[Dict[str, object]]] = None
        self.ef_cvca: Optional[Dict[str, object]] = None
        self.events: List[Dict[str, str]] = []
        self.notes: List[str] = []
        self._event_cap = 12000

    # ------------------------------------------------------------------
    # collection
    # ------------------------------------------------------------------

    def begin_session(self, **meta: object) -> None:
        with self._lock:
            self.meta = dict(meta)
            self.stages = {}
            for st in STAGES:
                self.stages[st["id"]] = {
                    "id": st["id"],
                    "label": st["label"],
                    "phase": st["phase"],
                    "status": "not_run",
                    "detail": None,
                }
            self.functional = {}
            for ft in FUNCTIONAL_TESTS:
                self.functional[ft["id"]] = {
                    "id": ft["id"],
                    "label": ft["label"],
                    "status": "not_run",
                    "detail": None,
                }
            self.negative = {}
            for nt in NEGATIVE_TESTS:
                self.negative[nt["id"]] = {
                    "id": nt["id"],
                    "label": nt["label"],
                    "status": "not_run",
                    "detail": None,
                }
            self.evidence = {}
            self.dg_access = None
            self.ef_cvca = None

    def update_meta(self, **kw: object) -> None:
        with self._lock:
            self.meta.update(kw)

    def add_event(self, message: str, source: str = "reader") -> None:
        with self._lock:
            self.events.append({"ts": _now(), "source": source, "message": message})
            if len(self.events) > self._event_cap:
                del self.events[: len(self.events) - self._event_cap]

    def mark(
        self,
        stage: str,
        status: str,
        detail: Optional[str] = None,
        sw: Optional[int] = None,
    ) -> None:
        if stage not in self.stages or status not in STATUS:
            return
        with self._lock:
            entry = self.stages[stage]
            entry["status"] = status
            if detail is not None:
                entry["detail"] = detail
            if sw is not None:
                entry["sw"] = f"{sw:04X}"
            # keep the matching functional test in sync
            for ft in FUNCTIONAL_TESTS:
                if ft["stage"] == stage:
                    self.functional[ft["id"]]["status"] = status
                    if detail is not None:
                        self.functional[ft["id"]]["detail"] = detail
                    break

    def record_evidence(self, stage: str, evidence: Dict[str, object]) -> None:
        with self._lock:
            self.evidence[stage] = dict(evidence)

    def set_negative(self, nid: str, status: str, detail: Optional[str] = None) -> None:
        if nid not in self.negative or status not in STATUS:
            return
        with self._lock:
            self.negative[nid]["status"] = status
            if detail is not None:
                self.negative[nid]["detail"] = detail

    def set_dg_access(self, rows: List[Dict[str, object]]) -> None:
        with self._lock:
            self.dg_access = rows

    def set_ef_cvca(self, data: Dict[str, object]) -> None:
        with self._lock:
            self.ef_cvca = dict(data)

    def note(self, text: str) -> None:
        with self._lock:
            self.notes.append(text)

    # ------------------------------------------------------------------
    # scores
    # ------------------------------------------------------------------

    def _scores(self) -> Dict[str, object]:
        def frac(items: Dict[str, Dict[str, object]]) -> float:
            if not items:
                return 0.0
            ok = sum(1 for i in items.values() if i["status"] == "ok")
            return ok / len(items)

        func = frac(self.functional)
        neg = frac(self.negative)

        # Security coverage: success of security stages AND, where the stage
        # must produce crypto evidence (CA/TA), that evidence was recorded.
        sec_ok = 0
        sec_total = len(SECURITY_STAGES)
        for sid in SECURITY_STAGES:
            st = self.stages.get(sid)
            if st is None or st["status"] != "ok":
                continue
            if sid in ("chip_auth", "terminal_auth"):
                if self.evidence.get(sid):
                    sec_ok += 1
            else:
                sec_ok += 1
        sec = (sec_ok / sec_total) if sec_total else 0.0

        return {
            "functional": round(func, 3),
            "security": round(sec, 3),
            "negative": round(neg, 3),
            "overall_readiness": _readiness(func, sec, neg),
        }

    def to_dict(self) -> Dict[str, object]:
        with self._lock:
            stages = [dict(self.stages[s["id"]]) for s in STAGES]
            functional = [dict(self.functional[ft["id"]]) for ft in FUNCTIONAL_TESTS]
            negative = [dict(self.negative[nt["id"]]) for nt in NEGATIVE_TESTS]
            evidence = {k: dict(v) for k, v in self.evidence.items()}
            dg_access = [dict(r) for r in self.dg_access] if self.dg_access else None
            ef_cvca = dict(self.ef_cvca) if self.ef_cvca else None
            events = [dict(e) for e in self.events]
            meta = dict(self.meta)
            notes = list(self.notes)
        scores = self._scores()
        return {
            "report": self.report_name,
            "schema_version": self.schema_version,
            "generated_at": self.generated_at or _now(),
            "started_at": self.started_at,
            "session": meta,
            "result": scores,
            "coverage": {
                "functional": functional,
                "security_stages": list(SECURITY_STAGES),
                "negative": negative,
            },
            "evidence": {
                "stages": evidence,
                "ef_cvca": ef_cvca,
                "dg_access": dg_access,
            },
            "notes": notes,
            "transcript": events,
        }

    def finalize(self) -> None:
        with self._lock:
            self.generated_at = _now()


def write_report_json(trace: SessionTrace, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(trace.to_dict(), fh, indent=2)
        fh.write("\n")


def load_report_json(path: str) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def summarize(report: Dict[str, object]) -> str:
    r = report.get("result", {})
    meta = report.get("session", {})
    protocol = meta.get("session_protocol") or meta.get("protocol_requested") or "?"
    return (
        f"readiness={r.get('overall_readiness', '?')} "
        f"functional={r.get('functional', 0):.0%} "
        f"security={r.get('security', 0):.0%} "
        f"negative={r.get('negative', 0):.0%} "
        f"protocol={protocol}"
    )


def main(argv: Optional[List[str]] = None) -> int:
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m epassport_reader.trace <report.json>")
        return 2
    report = load_report_json(argv[0])
    print(summarize(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
