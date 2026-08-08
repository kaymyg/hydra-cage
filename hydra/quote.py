"""The attestation quote.

The quote is the single most important data structure in Hydra, because it is
where the distinction between *speaking like a layer* and *being a layer* is
made mechanical.

A quote has two halves:

``observed_*``  Facts gathered by the supervisor from the isolation backend --
                the container runtime, the kernel, the host filesystem. The
                domain is not asked and cannot influence these. This is the
                origin proof.

``self_report`` Whatever the domain said about itself when challenged. Fully
                attacker-controlled. Never used to grant trust; used only to
                detect lying, by comparing it against ``observed_measurement``.

The signature covers both halves and is produced by the attestation plane's
key, which no domain can reach. A domain can therefore fabricate ``self_report``
perfectly and still fail, because the sentinel never asked it in the first
place.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

from .measurement import Measurement


@dataclass
class Challenge:
    nonce: str
    issued_at: float
    subject_domain_id: str
    ttl: float = 5.0

    def expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) - self.issued_at > self.ttl


@dataclass
class AttestationQuote:
    # --- origin proof: supervisor-sourced, unforgeable from inside ----------
    observed_domain_id: str
    observed_hw_serial: str
    observed_backend: str
    observed_measurement: Dict[str, str]
    observed_alive: bool

    # --- attacker-controlled -----------------------------------------------
    self_report: Dict[str, Any] = field(default_factory=dict)

    # --- binding ------------------------------------------------------------
    nonce: str = ""
    attester_id: str = ""
    attester_key: str = ""
    algo: str = ""
    issued_at: float = field(default_factory=time.time)
    signature: str = ""

    def canonical(self) -> bytes:
        body = {k: v for k, v in asdict(self).items() if k != "signature"}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    @property
    def measurement(self) -> Measurement:
        return Measurement(registers=dict(self.observed_measurement))

    @property
    def claimed_registers(self) -> Dict[str, str]:
        return dict(self.self_report.get("registers") or {})

    def contradictions(self) -> Dict[str, tuple]:
        """Registers where the domain's story differs from observed reality."""
        observed = self.observed_measurement
        return {
            k: (v, observed.get(k))
            for k, v in self.claimed_registers.items()
            if k in observed and v != observed[k]
        }

    def lying(self) -> bool:
        return bool(self.contradictions())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    trusted: bool
    reasons: list = field(default_factory=list)
    law_checks: list = field(default_factory=list)
    breach: bool = False
    breach_reason: str = ""

    def deny(self, reason: str, breach: bool = False) -> "Verdict":
        self.trusted = False
        self.reasons.append(reason)
        if breach:
            self.breach = True
            if not self.breach_reason:
                self.breach_reason = reason
        return self

    def note(self, reason: str) -> "Verdict":
        self.reasons.append(reason)
        return self

    def __bool__(self) -> bool:
        return self.trusted
