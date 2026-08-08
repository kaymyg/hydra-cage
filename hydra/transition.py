"""The Hydra breach transition: an eight-stage, hardware-enforced rebirth.

    1. Detect     invalid or missing attestation
    2. Freeze     suspend the affected domain
    3. Sever      cut interconnects
    4. Preserve   immutable forensic snapshot into the evidence plane
    5. Revoke     permanently invalidate the identity, zeroise keys
    6. Rebuild    fresh domain from the golden image
    7. Reattest   independently prove the new boot chain
    8. Reinsert   join the live cage as the new outermost wall

Every stage runs on the supervisor side. Nothing in this file asks the
compromised domain to cooperate with its own replacement -- that is the whole
design constraint, and it is why the sequence is safe to run against a domain
that is actively hostile.

Correctness of the trust transition outranks speed. ``prewarm`` exists to take
Stage 6 off the critical path, but a slow transition is always preferred to a
transition that skips a stage.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .laws import LawViolation, RegenerationAuthority
from .planes.attestation import AttestationPlane
from .planes.containment import ContainmentPlane, Layer
from .planes.evidence import EvidencePlane
from .planes.regeneration import RegenerationPlane
from .quote import AttestationQuote
from .telemetry import EventLog, NULL_LOG

STAGES = [
    "detect",
    "freeze",
    "sever",
    "preserve",
    "revoke",
    "rebuild",
    "reattest",
    "reinsert",
]


class TransitionAborted(Exception):
    def __init__(self, stage: str, detail: str):
        self.stage = stage
        self.detail = detail
        super().__init__(f"transition aborted at stage '{stage}': {detail}")


@dataclass
class StageRecord:
    name: str
    index: int
    started: float
    finished: float = 0.0
    ok: bool = False
    detail: Dict[str, Any] = field(default_factory=dict)

    @property
    def ms(self) -> float:
        return (self.finished - self.started) * 1000.0


@dataclass
class TransitionRecord:
    breached_domain: str
    reason: str
    started: float
    stages: List[StageRecord] = field(default_factory=list)
    replacement_domain: str = ""
    finished: float = 0.0
    completed: bool = False
    depth_before: int = 0
    depth_after: int = 0
    effective_before: int = 0
    effective_after: int = 0

    @property
    def total_ms(self) -> float:
        return (self.finished - self.started) * 1000.0

    def summary(self) -> Dict[str, Any]:
        return {
            "breached": self.breached_domain[:8],
            "replacement": self.replacement_domain[:8],
            "reason": self.reason,
            "completed": self.completed,
            "total_ms": round(self.total_ms, 1),
            "stages": {s.name: round(s.ms, 1) for s in self.stages},
            "live_depth": f"{self.depth_before}->{self.depth_after}",
            "effective_depth": f"{self.effective_before}->{self.effective_after}",
        }


class HydraBreachTransition:
    def __init__(
        self,
        containment: ContainmentPlane,
        attestation: AttestationPlane,
        regeneration: RegenerationPlane,
        evidence: EvidencePlane,
        authority: RegenerationAuthority,
        log: Optional[EventLog] = None,
        reattest_attempts: int = 3,
    ):
        self.containment = containment
        self.attestation = attestation
        self.regeneration = regeneration
        self.evidence = evidence
        self._authority = authority
        self.log = log or NULL_LOG
        self.reattest_attempts = reattest_attempts
        self.history: List[TransitionRecord] = []

    # -- driver -------------------------------------------------------------
    def run(self, layer: Layer, reason: str, last_quote: Optional[AttestationQuote] = None) -> TransitionRecord:
        rec = TransitionRecord(
            breached_domain=layer.identity.domain_id,
            reason=reason,
            started=time.time(),
            depth_before=self.containment.live_depth,
            effective_before=self.containment.effective_depth,
        )
        self.log.emit(
            "cage",
            "breach_transition_begin",
            {"reason": reason[:90], "layer": layer.label},
            domain_id=layer.identity.domain_id,
            severity="breach",
        )

        ctx: Dict[str, Any] = {"layer": layer, "reason": reason, "last_quote": last_quote}
        for i, name in enumerate(STAGES, start=1):
            sr = StageRecord(name=name, index=i, started=time.time())
            rec.stages.append(sr)
            try:
                detail = getattr(self, f"_stage_{name}")(ctx)
                sr.detail = detail or {}
                sr.ok = True
            except Exception as exc:
                sr.finished = time.time()
                sr.detail = {"error": str(exc)}
                self.log.emit(
                    "cage",
                    "stage_failed",
                    {"stage": f"{i}/{name}", "error": str(exc)[:200]},
                    domain_id=layer.identity.domain_id,
                    severity="breach",
                )
                rec.finished = time.time()
                self.history.append(rec)
                raise TransitionAborted(name, str(exc)) from exc
            sr.finished = time.time()
            self.log.emit(
                "cage",
                f"stage_{i}_{name}",
                {**{k: v for k, v in list(sr.detail.items())[:4]}, "ms": round(sr.ms, 1)},
                domain_id=layer.identity.domain_id,
            )

        rec.replacement_domain = ctx["replacement"].identity.domain_id
        rec.depth_after = self.containment.live_depth
        rec.effective_after = self.containment.effective_depth
        rec.finished = time.time()
        rec.completed = True
        self.history.append(rec)

        self.log.emit(
            "cage",
            "breach_transition_complete",
            {
                "live_depth": f"{rec.depth_before}->{rec.depth_after}",
                "effective_depth": f"{rec.effective_before}->{rec.effective_after}",
                "ms": round(rec.total_ms, 1),
            },
            domain_id=rec.replacement_domain,
        )
        return rec

    # -- stages -------------------------------------------------------------
    def _stage_detect(self, ctx) -> Dict[str, Any]:
        """1. The outer layer has an invalid or missing attestation in hand."""
        layer: Layer = ctx["layer"]
        q: Optional[AttestationQuote] = ctx.get("last_quote") or layer.last_quote
        ctx["evidence_quote"] = q.to_dict() if q else {}
        return {
            "reason": ctx["reason"][:80],
            "attester": self.attestation.identity.short,
            "subject": layer.identity.short,
        }

    def _stage_freeze(self, ctx) -> Dict[str, Any]:
        """2. Hardware containment controller suspends the domain."""
        layer: Layer = ctx["layer"]
        self.regeneration.backend.freeze(layer.handle)
        facts = self.regeneration.backend.hw_facts(layer.handle)
        ctx["frozen_facts"] = facts
        return {"paused": facts.get("paused"), "alive": facts.get("alive")}

    def _stage_sever(self, ctx) -> Dict[str, Any]:
        """3. Physical and virtual interconnects are cut."""
        layer: Layer = ctx["layer"]
        self.regeneration.backend.sever(layer.handle)
        facts = self.regeneration.backend.hw_facts(layer.handle)
        if facts.get("networks"):
            raise RuntimeError(f"domain still attached to {facts['networks']}")
        return {"networks": facts.get("networks", []), "severed": layer.handle.severed}

    def _stage_preserve(self, ctx) -> Dict[str, Any]:
        """4. Immutable forensic copy into the evidence plane. One-way."""
        layer: Layer = ctx["layer"]
        dest = self.evidence.artifact_path_for(layer.identity.domain_id)
        info = self.regeneration.backend.snapshot(layer.handle, dest)
        art = self.evidence.seal(
            domain_id=layer.identity.domain_id,
            role=layer.identity.role,
            generation=layer.identity.generation,
            hw_serial=layer.identity.hw_serial,
            reason=ctx["reason"],
            artifact_path=dest,
            measurement=layer.measurement.to_dict(),
            runtime_facts=ctx.get("frozen_facts", {}),
            last_quote=ctx.get("evidence_quote", {}),
        )
        ctx["artifact"] = art
        return {"seq": art.seq, "sha256": art.artifact_sha256[:12], "bytes": art.artifact_bytes, "kind": info["kind"]}

    def _stage_revoke(self, ctx) -> Dict[str, Any]:
        """5. Identity permanently invalidated; the enclave becomes a tombstone."""
        layer: Layer = ctx["layer"]
        entry = self.regeneration.revoke_and_destroy(
            layer.identity,
            layer.handle,
            reason=ctx["reason"],
            authority=self._authority,
            requester="breach-transition",
            destroy=True,
        )
        self.attestation.policy.retire_domain(layer.identity.domain_id)
        self.containment.entomb(layer, ctx["reason"])
        return {"ledger_seq": entry.seq, "ledger_head": entry.entry_hash[:12], "revoked_total": len(self.regeneration.ledger)}

    def _stage_rebuild(self, ctx) -> Dict[str, Any]:
        """6. A wholly new domain from a known-good, measured image."""
        layer: Layer = ctx["layer"]
        prewarmed = self.regeneration.take_prewarmed(layer.identity.role, self._authority)
        if prewarmed is not None:
            prov = prewarmed
            source = "prewarmed"
        else:
            prov = self.regeneration.provision(
                role=layer.identity.role,
                depth=0,
                authority=self._authority,
                requester="breach-transition",
                lineage=None,  # Law 3: a new lineage, not a continuation
            )
            source = "cold"
        ctx["provisioned"] = prov
        return {
            "source": source,
            "new_domain": prov.identity.short,
            "gen": prov.identity.generation,
            "mr": prov.measurement.short,
        }

    def _stage_reattest(self, ctx) -> Dict[str, Any]:
        """7. The new layer proves its whole boot chain to a separate root."""
        prov = ctx["provisioned"]
        self.attestation.policy.register_domain(prov.identity)
        last_reasons: List[str] = []
        for attempt in range(1, self.reattest_attempts + 1):
            q, verdict = self.attestation.challenge_and_verify(
                prov.handle, prov.identity, self.regeneration.policy_hash
            )
            if verdict.trusted:
                ctx["reattest_quote"] = q
                return {"attempt": attempt, "mr": q.measurement.short, "verdict": "trusted"}
            last_reasons = verdict.reasons
            time.sleep(0.1 * attempt)
        # A replacement that cannot attest is destroyed, never admitted.
        self.regeneration.revoke_and_destroy(
            prov.identity,
            prov.handle,
            reason="replacement failed reattestation",
            authority=self._authority,
            requester="breach-transition",
        )
        self.attestation.policy.retire_domain(prov.identity.domain_id)
        raise RuntimeError("replacement failed reattestation: " + "; ".join(last_reasons[:2]))

    def _stage_reinsert(self, ctx) -> Dict[str, Any]:
        """8. Only now does the new layer join the cage -- as the new outside."""
        prov = ctx["provisioned"]
        new_layer = Layer(
            handle=prov.handle,
            identity=prov.identity,
            measurement=prov.measurement,
            spec=prov.spec,
            depth=0,
            born_at=time.time(),
            last_quote=ctx.get("reattest_quote"),
        )
        self.containment.push_outer(new_layer)
        ctx["replacement"] = new_layer
        self.containment.assert_invariants(min_live_depth=1)
        return {
            "live_depth": self.containment.live_depth,
            "effective_depth": self.containment.effective_depth,
            "position": "outermost",
        }
