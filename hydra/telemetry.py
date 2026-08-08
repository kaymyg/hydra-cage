"""Structured, append-only event telemetry.

The event log is written by the *supervisor* (host side). Nothing inside an
execution domain can reach it. This is deliberate: an adversary that can edit
its own audit trail has already won.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

PLANE_COLORS = {
    "execution": "\033[38;5;203m",
    "containment": "\033[38;5;180m",
    "attestation": "\033[38;5;81m",
    "regeneration": "\033[38;5;120m",
    "evidence": "\033[38;5;140m",
    "policy": "\033[38;5;222m",
    "adversary": "\033[38;5;196m",
    "cage": "\033[38;5;250m",
}
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"


def _color_enabled() -> bool:
    if os.environ.get("HYDRA_NO_COLOR"):
        return False
    return sys.stdout.isatty()


@dataclass
class Event:
    ts: float
    plane: str
    kind: str
    detail: Dict[str, Any] = field(default_factory=dict)
    domain_id: Optional[str] = None
    severity: str = "info"  # info | warn | breach | blocked

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


class EventLog:
    """Thread-safe JSONL event log with a readable console mirror."""

    def __init__(self, path: Optional[str] = None, echo: bool = True):
        self.path = path
        self.echo = echo
        self._lock = threading.Lock()
        self.events: List[Event] = []
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            # truncate on boot; the forensic record lives in the evidence plane,
            # this is operational telemetry
            open(path, "w").close()

    def emit(
        self,
        plane: str,
        kind: str,
        detail: Optional[Dict[str, Any]] = None,
        domain_id: Optional[str] = None,
        severity: str = "info",
    ) -> Event:
        ev = Event(
            ts=time.time(),
            plane=plane,
            kind=kind,
            detail=detail or {},
            domain_id=domain_id,
            severity=severity,
        )
        with self._lock:
            self.events.append(ev)
            if self.path:
                with open(self.path, "a") as fh:
                    fh.write(ev.to_json() + "\n")
            if self.echo:
                sys.stdout.write(self._render(ev) + "\n")
                sys.stdout.flush()
        return ev

    def _render(self, ev: Event) -> str:
        use_color = _color_enabled()
        c = PLANE_COLORS.get(ev.plane, "") if use_color else ""
        r = RESET if use_color else ""
        d = DIM if use_color else ""
        b = BOLD if use_color else ""

        marker = {
            "info": " ",
            "warn": "!",
            "breach": "✖",
            "blocked": "⊘",
        }.get(ev.severity, " ")

        who = f" {d}[{ev.domain_id}]{r}" if ev.domain_id else ""
        bits = " ".join(f"{d}{k}={r}{v}" for k, v in ev.detail.items())
        stamp = time.strftime("%H:%M:%S", time.localtime(ev.ts))
        return f"{d}{stamp}{r} {marker} {c}{ev.plane:<12}{r} {b}{ev.kind:<26}{r}{who} {bits}"

    def filter(self, **kw) -> List[Event]:
        out = self.events
        for key, val in kw.items():
            out = [e for e in out if getattr(e, key) == val]
        return out

    def count(self, **kw) -> int:
        return len(self.filter(**kw))


NULL_LOG = EventLog(path=None, echo=False)
