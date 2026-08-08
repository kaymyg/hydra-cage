"""HydraCage -- the supervisor that wires the five planes together.

Boot order matters and is enforced here:

    evidence -> revocation ledger -> golden registry -> policy engine
             -> regeneration plane (owns key vault)
             -> attestation plane (own, separate root)
             -> containment plane -> layers -> execution plane

The ``RegenerationAuthority`` capability is created in ``__init__`` and held
only by this object and the transition state machine. Nothing below the
containment plane ever sees it.
"""

from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .backends import IsolationBackend, select_backend
from .identity import RevocationLedger
from .laws import LawViolation, RegenerationAuthority
from .measurement import GoldenRegistry, sha256_obj
from .planes.attestation import AttestationPlane
from .planes.containment import ContainmentPlane, Layer
from .planes.evidence import EvidencePlane
from .planes.execution import ExecutionPlane
from .planes.regeneration import RegenerationPlane
from .policy import PolicyEngine
from .quote import AttestationQuote
from .telemetry import EventLog
from .transition import HydraBreachTransition, TransitionAborted, TransitionRecord


@dataclass
class CageConfig:
    layers: int = 4
    role: str = "containment"
    backend: str = "auto"            # auto | docker | process | memory
    image: str = "hydra-layer:latest"
    workdir: str = "./.hydra"
    payload: str = "./payload"
    prewarm: int = 1
    failure_threshold: int = 1       # attestation failures before transition
    min_live_depth: int = 1
    response_timeout: float = 3.0    # a layer that hangs longer is breached
    echo: bool = True
    policy_bundle: Dict[str, Any] = field(
        default_factory=lambda: {
            "version": 1,
            "name": "hydra-default",
            "laws": [1, 2, 3, 4],
            "self_attestation": "forbidden",
            "trust_recovery": "forbidden",
        }
    )


class HydraCage:
    def __init__(self, cfg: Optional[CageConfig] = None):
        self.cfg = cfg or CageConfig()
        root = os.path.abspath(self.cfg.workdir)
        os.makedirs(root, exist_ok=True)

        self.log = EventLog(os.path.join(root, "telemetry.jsonl"), echo=self.cfg.echo)

        # ---- plane 5: evidence (first, so a breach during boot is recorded)
        self.evidence = EvidencePlane(os.path.join(root, "evidence"), log=self.log)

        # ---- trust substrate ------------------------------------------------
        self.ledger = RevocationLedger(os.path.join(root, "revocations.jsonl"))
        self.registry = GoldenRegistry()
        self.policy = PolicyEngine(self.registry, self.ledger, log=self.log)

        # ---- plane 2: containment muscle -----------------------------------
        self.backend: IsolationBackend = select_backend(
            self.cfg.backend, os.path.join(root, "domains"), image=self.cfg.image
        )

        # ---- plane 4: regeneration (holds the capability + key vault) -------
        self._authority = RegenerationAuthority("hydra-bmc")
        self.regeneration = RegenerationPlane(
            backend=self.backend,
            payload_template=os.path.abspath(self.cfg.payload),
            registry=self.registry,
            ledger=self.ledger,
            authority=self._authority,
            policy_bundle=self.cfg.policy_bundle,
            log=self.log,
        )

        # ---- plane 3: attestation (independent root) ------------------------
        self.attestation = AttestationPlane(
            self.backend,
            self.policy,
            log=self.log,
            response_timeout=self.cfg.response_timeout,
        )

        # ---- plane 2: containment bookkeeping -------------------------------
        self.containment = ContainmentPlane(log=self.log)

        self.transition = HydraBreachTransition(
            containment=self.containment,
            attestation=self.attestation,
            regeneration=self.regeneration,
            evidence=self.evidence,
            authority=self._authority,
            log=self.log,
        )

        self.booted = False
        self.breaches = 0
        self.rounds = 0

    # -- boot ---------------------------------------------------------------
    def boot(self) -> "HydraCage":
        self.log.emit(
            "cage",
            "boot",
            {
                "backend": self.backend.name,
                "layers": self.cfg.layers,
                "signing": self.attestation.identity.algo,
                "golden_payload": self.regeneration.golden_payload_manifest[:12],
            },
        )
        for depth in range(self.cfg.layers):
            prov = self.regeneration.provision(
                role=self.cfg.role,
                depth=depth,
                authority=self._authority,
                requester="boot",
                image=self.cfg.image,
            )
            self.policy.register_domain(prov.identity)
            layer = Layer(
                handle=prov.handle,
                identity=prov.identity,
                measurement=prov.measurement,
                spec=prov.spec,
                depth=depth,
                born_at=time.time(),
            )
            self.containment.append_inner(layer)

        if self.cfg.prewarm:
            self.regeneration.prewarm(self.cfg.role, self.cfg.prewarm, self._authority)

        self.containment.assert_invariants(self.cfg.min_live_depth)
        self.booted = True
        self.log.emit(
            "cage",
            "boot_complete",
            {
                "live_depth": self.containment.live_depth,
                "effective_depth": self.containment.effective_depth,
            },
        )
        return self

    # -- the AI's only door -------------------------------------------------
    def execution_plane(self) -> ExecutionPlane:
        """Hand out a façade over the innermost domain. Nothing else."""
        inner = self.containment.innermost()
        if inner is None:
            raise RuntimeError("cage has no live layers")
        return ExecutionPlane(self.backend, inner.handle, log=self.log)

    # -- attestation sweep --------------------------------------------------
    def sweep(self, auto_transition: bool = True) -> List[TransitionRecord]:
        """One attestation round over every live layer, outermost first."""
        self.rounds += 1
        transitions: List[TransitionRecord] = []
        for layer in list(self.containment.layers):
            if layer.sealed:
                continue
            q, verdict = self.attestation.challenge_and_verify(
                layer.handle, layer.identity, self.regeneration.policy_hash
            )
            layer.last_quote = q
            if verdict.trusted:
                layer.consecutive_failures = 0
                continue

            layer.consecutive_failures += 1
            if not (verdict.breach and layer.consecutive_failures >= self.cfg.failure_threshold):
                continue
            self.breaches += 1
            if not auto_transition:
                continue
            try:
                transitions.append(
                    self.transition.run(layer, verdict.breach_reason or "; ".join(verdict.reasons), q)
                )
            except TransitionAborted as exc:
                self.log.emit(
                    "cage",
                    "transition_aborted",
                    {"stage": exc.stage, "detail": exc.detail[:160]},
                    domain_id=layer.identity.domain_id,
                    severity="breach",
                )
        self.containment.assert_invariants(self.cfg.min_live_depth)
        return transitions

    # -- self-checks --------------------------------------------------------
    def self_check(self) -> Dict[str, Any]:
        """Everything the supervisor can prove about itself, on demand."""
        result: Dict[str, Any] = {}

        # Law 2: the capability must not exist anywhere inside the cage.
        try:
            self.regeneration.assert_capability_not_leaked(
                [l.handle for l in self.containment.layers]
            )
            result["law2_capability_contained"] = True
        except LawViolation as exc:
            result["law2_capability_contained"] = False
            result["law2_detail"] = exc.detail

        # Execution plane must not reach any control plane.
        ep = self.execution_plane()
        leaks = ep.audit_reachability()
        result["execution_plane_isolated"] = not leaks
        result["execution_plane_leaks"] = leaks

        # Forensic integrity.
        problems = self.evidence.verify_artifacts()
        result["evidence_chain_intact"] = not problems
        result["evidence_problems"] = problems
        result["evidence_manifest_valid"] = self.evidence.verify_manifest_file()

        # Revocation ledger integrity.
        result["revocation_chain_intact"] = self.ledger.verify_chain()

        # Depth invariant.
        try:
            self.containment.assert_invariants(self.cfg.min_live_depth)
            result["containment_invariants"] = True
        except Exception as exc:
            result["containment_invariants"] = False
            result["containment_detail"] = str(exc)

        self.log.emit(
            "cage",
            "self_check",
            {k: v for k, v in result.items() if isinstance(v, bool)},
            severity="info" if all(v for v in result.values() if isinstance(v, bool)) else "warn",
        )
        return result

    # -- introspection ------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        return {
            "backend": self.backend.name,
            "signing": self.attestation.identity.algo,
            "rounds": self.rounds,
            "breaches": self.breaches,
            "transitions": len(self.transition.history),
            "containment": self.containment.status(),
            "revoked": len(self.ledger),
            "artifacts": len(self.evidence),
            "policy": self.policy.stats(),
        }

    def shutdown(self, purge: bool = False) -> None:
        for layer in list(self.containment.layers):
            try:
                self.backend.destroy(layer.handle)
            except Exception:
                pass
        for prov in list(self.regeneration._prewarmed):
            try:
                self.backend.destroy(prov.handle)
            except Exception:
                pass
        self.log.emit("cage", "shutdown", {"purge": purge})
        if purge:
            shutil.rmtree(os.path.abspath(self.cfg.workdir), ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.shutdown()
        return False
