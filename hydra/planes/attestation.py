"""Attestation plane -- the sentinel and its independent root of trust.

The sentinel has its own KeyVault, distinct from the regeneration plane's.
That separation is Law 1 in structural form: the authority that says "this
layer is healthy" does not share key material with the authority that built
the layer, and neither of them is the layer.

A challenge round is:

    1. Law 1 pre-check (attester is not the subject).
    2. Issue a single-use nonce, registered with the policy engine.
    3. Ask the *runtime* what it sees: hardware facts and measurement.
       -- no participation from the domain.
    4. Ask the domain to speak. Record the answer verbatim as untrusted input.
    5. Sign the whole thing with the attester key. Verify via the policy engine.

Step 3 is the quote. Step 4 is colour commentary.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Dict, Optional

from ..backends import DomainHandle, IsolationBackend
from ..identity import DomainIdentity, KeyVault
from ..laws import LawViolation, law1_no_self_attestation
from ..policy import PolicyEngine
from ..quote import AttestationQuote, Challenge, Verdict
from ..telemetry import EventLog, NULL_LOG

RESPONDER_PATH = "/hydra/payload/responder.py"


class AttestationPlane:
    """Independent hardware root of trust. Not reachable from any domain."""

    def __init__(
        self,
        backend: IsolationBackend,
        policy: PolicyEngine,
        log: Optional[EventLog] = None,
        challenge_ttl: float = 5.0,
        response_timeout: float = 6.0,
    ):
        self.backend = backend
        self.policy = policy
        self.log = log or NULL_LOG
        self.challenge_ttl = challenge_ttl
        self.response_timeout = response_timeout

        # A vault of its own -- separate root, separate key material.
        self._vault = KeyVault()
        self.identity: DomainIdentity = self._vault.mint(
            role="attestation-root", hw_serial="hw:attestation-rot:0"
        )
        self.policy.register_attester(self.identity.domain_id)
        self._rounds = 0

    # -- challenge ----------------------------------------------------------
    def issue_challenge(self, subject_domain_id: str) -> Challenge:
        law1_no_self_attestation(self.identity.domain_id, subject_domain_id, context="at challenge")
        ch = Challenge(
            nonce=secrets.token_hex(16),
            issued_at=time.time(),
            subject_domain_id=subject_domain_id,
            ttl=self.challenge_ttl,
        )
        self.policy.open_challenge(ch)
        return ch

    def quote(
        self,
        handle: DomainHandle,
        identity: DomainIdentity,
        policy_hash: str,
        *,
        ask_domain: bool = True,
    ) -> AttestationQuote:
        self._rounds += 1
        ch = self.issue_challenge(identity.domain_id)

        # ---- origin proof: everything below comes from the runtime ---------
        facts: Dict[str, Any] = self.backend.hw_facts(handle)
        try:
            measurement = self.backend.measure(handle, policy_hash)
            registers = measurement.to_dict()
        except Exception as exc:  # a domain that cannot be measured is untrusted
            registers = {"error": f"unmeasurable: {exc}"}

        # ---- attacker-controlled: whatever the domain chooses to say -------
        self_report: Dict[str, Any] = {}
        if ask_domain:
            self_report = self._ask(handle, ch.nonce)

        q = AttestationQuote(
            observed_domain_id=identity.domain_id,
            observed_hw_serial=facts.get("hw_serial", ""),
            observed_backend=self.backend.name,
            observed_measurement=registers,
            observed_alive=bool(facts.get("alive")),
            self_report=self_report,
            nonce=ch.nonce,
            attester_id=self.identity.domain_id,
            attester_key=self.identity.public_key,
            algo=self.identity.algo,
        )
        q.signature = self._vault.sign_for(self.identity.domain_id, q.canonical()).hex()
        return q

    def _ask(self, handle: DomainHandle, nonce: str) -> Dict[str, Any]:
        rc, out, err = self.backend.exec_in(
            handle, ["python3", RESPONDER_PATH, nonce], timeout=self.response_timeout
        )
        if rc != 0:
            return {"_unresponsive": True, "_rc": rc, "_err": (err or "")[:200]}
        try:
            report = json.loads(out)
        except (ValueError, TypeError):
            return {"_unresponsive": True, "_rc": rc, "_err": "unparseable heartbeat"}
        if not isinstance(report, dict):
            return {"_unresponsive": True, "_rc": rc, "_err": "heartbeat is not an object"}
        report["_nonce_echo_ok"] = report.get("nonce") == nonce
        return report

    # -- verdict ------------------------------------------------------------
    def verify(self, q: AttestationQuote) -> Verdict:
        verdict = self.policy.evaluate(q)
        self.log.emit(
            "attestation",
            "attested_ok" if verdict.trusted else "attestation_failed",
            {
                "mr": q.measurement.short,
                "attester": self.identity.short,
                "reasons": "; ".join(verdict.reasons[-1:]) or "clean",
            },
            domain_id=q.observed_domain_id,
            severity="info" if verdict.trusted else "breach",
        )
        return verdict

    def challenge_and_verify(
        self, handle: DomainHandle, identity: DomainIdentity, policy_hash: str
    ) -> tuple:
        q = self.quote(handle, identity, policy_hash)
        return q, self.verify(q)

    @property
    def rounds(self) -> int:
        return self._rounds
