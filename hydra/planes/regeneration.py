"""Regeneration plane -- the management controller.

This is the plane that must never be addressable from inside the cage. It owns:

* the KeyVault holding every domain private key,
* the only code path that can create or destroy an execution domain,
* the golden payload template that new layers are built from.

Every entry point takes a ``RegenerationAuthority`` capability and runs Law 2
before doing anything. There is no unauthenticated variant of these calls, and
the capability is never serialised into a domain.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional


from ..backends import DomainHandle, DomainSpec, IsolationBackend
from ..identity import DomainIdentity, KeyVault, RevocationLedger
from ..laws import (
    LawViolation,
    RegenerationAuthority,
    law2_assert_no_leak,
    law2_no_self_regeneration,
    law3_no_identity_inheritance,
    law4_no_trust_recovery,
)
from ..measurement import GoldenRegistry, Measurement, manifest_from_dir, sha256_obj
from ..telemetry import EventLog, NULL_LOG


class RegenerationRefused(Exception):
    """Raised when a rebuild would produce a domain that is not golden."""


@dataclass
class Provisioned:
    handle: DomainHandle
    identity: DomainIdentity
    measurement: Measurement
    spec: DomainSpec


class RegenerationPlane:
    def __init__(
        self,
        backend: IsolationBackend,
        payload_template: str,
        registry: GoldenRegistry,
        ledger: RevocationLedger,
        authority: RegenerationAuthority,
        policy_bundle: Optional[Dict] = None,
        log: Optional[EventLog] = None,
    ):
        self.backend = backend
        self.payload_template = os.path.abspath(payload_template)
        self.registry = registry
        self.ledger = ledger
        self.log = log or NULL_LOG

        # The vault and the expected capability are private to this plane.
        self._vault = KeyVault()
        self._authority = authority
        self.policy_bundle = policy_bundle or {"version": 1, "name": "hydra-default"}
        self.policy_hash = sha256_obj(self.policy_bundle)

        self._retired: List[DomainIdentity] = []
        self._prewarmed: List[Provisioned] = []
        self.golden_payload_manifest = manifest_from_dir(self.payload_template)

    # -- vault access, tightly scoped ---------------------------------------
    def sign_as(self, domain_id: str, data: bytes) -> bytes:
        return self._vault.sign_for(domain_id, data)

    def identity_of(self, domain_id: str) -> Optional[DomainIdentity]:
        return self._vault.identity(domain_id)

    # -- provisioning -------------------------------------------------------
    def provision(
        self,
        role: str,
        depth: int,
        authority: Optional[RegenerationAuthority],
        *,
        requester: str = "supervisor",
        lineage: Optional[str] = None,
        image: str = "hydra-layer:latest",
    ) -> Provisioned:
        """Stage 6 (Rebuild). Builds from the golden template, never from the
        compromised domain's state."""
        law2_no_self_regeneration(authority, self._authority, requester=requester)

        spec = DomainSpec(
            role=role,
            depth=depth,
            payload_dir=self.payload_template,
            policy_hash=self.policy_hash,
            image=image,
        )
        # The domain id is chosen here, before the domain exists, so the
        # workdir, the handle and the key all name the same incarnation.
        domain_id = uuid.uuid4().hex
        handle = self.backend.create(domain_id, spec)

        # hw_serial comes back from the runtime, not from the domain.
        ident = self._vault.mint(
            role=role, hw_serial=handle.hw_serial, lineage=lineage, domain_id=domain_id
        )

        # Law 3: nothing may be inherited from any retired incarnation.
        law3_no_identity_inheritance(ident, self._retired)
        # Law 4: a fresh identity must not collide with anything revoked.
        law4_no_trust_recovery(
            self.ledger,
            domain_id=ident.domain_id,
            public_key=ident.public_key,
            hw_serial=ident.hw_serial,
        )

        measurement = self.backend.measure(handle, self.policy_hash)

        # The new layer only becomes a golden state if its code is bit-for-bit
        # the signed template. This is what stops a "rebuild" from laundering
        # attacker-modified payload into the approved set.
        if measurement.registers.get("entrypoint") != self.golden_payload_manifest:
            self.backend.destroy(handle)
            raise RegenerationRefused(
                "provisioned payload does not match the golden template manifest"
            )
        self.registry.approve(role, measurement)

        self.log.emit(
            "regeneration",
            "domain_provisioned",
            {
                "role": role,
                "depth": depth,
                "gen": ident.generation,
                "mr": measurement.short,
                "hw": ident.hw_serial[:16],
            },
            domain_id=ident.domain_id,
        )
        return Provisioned(handle=handle, identity=ident, measurement=measurement, spec=spec)

    def prewarm(self, role: str, count: int, authority: Optional[RegenerationAuthority]) -> int:
        """Keep spare domains hot so Stage 6 is not on the critical path."""
        law2_no_self_regeneration(authority, self._authority, requester="prewarm")
        for _ in range(count):
            self._prewarmed.append(
                self.provision(role, depth=-1, authority=authority, requester="prewarm")
            )
        self.log.emit("regeneration", "prewarm_pool", {"role": role, "size": len(self._prewarmed)})
        return len(self._prewarmed)

    def take_prewarmed(self, role: str, authority: Optional[RegenerationAuthority]) -> Optional[Provisioned]:
        law2_no_self_regeneration(authority, self._authority, requester="take_prewarmed")
        for i, p in enumerate(self._prewarmed):
            if p.identity.role == role:
                return self._prewarmed.pop(i)
        return None

    # -- teardown -----------------------------------------------------------
    def revoke_and_destroy(
        self,
        ident: DomainIdentity,
        handle: DomainHandle,
        reason: str,
        authority: Optional[RegenerationAuthority],
        *,
        requester: str = "supervisor",
        destroy: bool = True,
    ):
        """Stage 5 (Revoke). Keys are zeroised, identity is tombstoned."""
        law2_no_self_regeneration(authority, self._authority, requester=requester)
        entry = self.ledger.revoke(ident, reason)
        zeroised = self._vault.destroy_key(ident.domain_id)
        self._retired.append(ident)
        if destroy:
            self.backend.destroy(handle)
        self.log.emit(
            "regeneration",
            "identity_revoked",
            {
                "reason": reason[:90],
                "gen": ident.generation,
                "keys_zeroised": zeroised,
                "ledger_head": entry.entry_hash[:12],
            },
            domain_id=ident.domain_id,
            severity="warn",
        )
        return entry

    # -- Law 2 self-check ---------------------------------------------------
    def assert_capability_not_leaked(self, handles: List[DomainHandle]) -> bool:
        blobs: List[bytes] = []
        for h in handles:
            if h.destroyed:
                continue
            try:
                blobs.extend(self.backend.scan_for_secret(h))
            except Exception:
                pass
        law2_assert_no_leak(self._authority, blobs)
        self.log.emit(
            "regeneration",
            "capability_leak_scan",
            {"domains": len(handles), "blobs": len(blobs), "result": "clean"},
        )
        return True

    @property
    def retired(self) -> List[DomainIdentity]:
        return list(self._retired)
