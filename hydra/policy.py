"""The policy engine: the only component allowed to say the word "trusted".

It has no interface reachable from an execution domain, holds the golden
measurement registry and the revocation ledger, and refuses to make a decision
without running all four laws.
"""

from __future__ import annotations

import time
from typing import Dict, Optional, Set

from .identity import DomainIdentity, RevocationLedger, verify_signature
from .laws import (
    LawViolation,
    law1_attester_must_be_rooted,
    law1_no_self_attestation,
    law4_no_trust_recovery,
)
from .measurement import GoldenRegistry
from .quote import AttestationQuote, Challenge, Verdict
from .telemetry import EventLog, NULL_LOG


class PolicyEngine:
    def __init__(
        self,
        registry: GoldenRegistry,
        ledger: RevocationLedger,
        log: Optional[EventLog] = None,
    ):
        self.registry = registry
        self.ledger = ledger
        self.log = log or NULL_LOG
        self._trusted_attesters: Set[str] = set()
        self._live_identities: Dict[str, DomainIdentity] = {}
        self._roles: Dict[str, str] = {}          # domain_id -> role
        self._used_nonces: Set[str] = set()
        self._open_challenges: Dict[str, Challenge] = {}

    # -- registration -------------------------------------------------------
    def register_attester(self, attester_id: str) -> None:
        """Only hardware-rooted attesters, added by the supervisor at boot."""
        self._trusted_attesters.add(attester_id)

    def register_domain(self, ident: DomainIdentity) -> None:
        self._live_identities[ident.domain_id] = ident
        self._roles[ident.domain_id] = ident.role

    def retire_domain(self, domain_id: str) -> None:
        self._live_identities.pop(domain_id, None)

    def identity(self, domain_id: str) -> Optional[DomainIdentity]:
        return self._live_identities.get(domain_id)

    # -- nonce lifecycle ----------------------------------------------------
    def open_challenge(self, challenge: Challenge) -> None:
        self._open_challenges[challenge.nonce] = challenge

    def consume_nonce(self, nonce: str) -> Optional[str]:
        """Returns an error string, or None if the nonce is fresh and valid."""
        if nonce in self._used_nonces:
            return "replayed nonce"
        ch = self._open_challenges.pop(nonce, None)
        if ch is None:
            return "unknown nonce (not issued by this sentinel)"
        self._used_nonces.add(nonce)
        if ch.expired():
            return "expired challenge window"
        return None

    # -- the decision -------------------------------------------------------
    def evaluate(self, quote: AttestationQuote) -> Verdict:
        v = Verdict(trusted=True)
        subject = quote.observed_domain_id

        # 1. Nonce must be one we issued, unused, and unexpired.
        nonce_error = self.consume_nonce(quote.nonce)
        if nonce_error:
            v.deny(f"nonce rejected: {nonce_error}", breach=True)
            self._log_deny(quote, v)
            return v

        # 2. Law 1 runs before the signature check on purpose: whether the
        #    attester is a separate, hardware-rooted domain is a structural
        #    question, and answering it first means a self-signed quote is
        #    rejected for the right reason rather than incidentally.
        try:
            v.law_checks.append(
                law1_no_self_attestation(quote.attester_id, subject, context="via quote")
            )
            v.law_checks.append(
                law1_attester_must_be_rooted(quote.attester_id, self._trusted_attesters)
            )
        except LawViolation as exc:
            v.deny(str(exc), breach=True)
            self.log.emit(
                "policy",
                f"law{exc.law}_violation",
                {"detail": exc.detail},
                domain_id=subject,
                severity="blocked",
            )
            return v

        # 3. Signature must verify under the attester key.
        try:
            sig_ok = verify_signature(
                bytes.fromhex(quote.attester_key),
                quote.canonical(),
                bytes.fromhex(quote.signature),
                quote.algo,
            )
        except ValueError:
            sig_ok = False
        if not sig_ok:
            v.deny("attestation signature invalid", breach=True)
            self._log_deny(quote, v)
            return v

        # 4. Law 4. A LawViolation is fatal to the verdict.
        try:
            ident = self._live_identities.get(subject)
            v.law_checks.append(
                law4_no_trust_recovery(
                    self.ledger,
                    domain_id=subject,
                    public_key=ident.public_key if ident else None,
                    hw_serial=quote.observed_hw_serial,
                )
            )
        except LawViolation as exc:
            v.deny(str(exc), breach=True)
            self.log.emit(
                "policy",
                f"law{exc.law}_violation",
                {"detail": exc.detail},
                domain_id=subject,
                severity="blocked",
            )
            return v

        # 5. The domain must still exist as a running security domain.
        if not quote.observed_alive:
            v.deny("execution domain is not running", breach=True)
            self._log_deny(quote, v)
            return v

        # 6. Identity must be one we know about.
        ident = self._live_identities.get(subject)
        if ident is None:
            v.deny("unknown domain identity", breach=True)
            self._log_deny(quote, v)
            return v
        if ident.hw_serial != quote.observed_hw_serial:
            v.deny("hardware binding does not match registered identity", breach=True)
            self._log_deny(quote, v)
            return v

        # 7. Missing heartbeat is a breach signal, not a stall. A domain that
        #     stops answering does not get to keep its slot in the cage.
        if quote.self_report.get("_unresponsive"):
            v.deny(
                f"heartbeat missing: {quote.self_report.get('_err', 'no response')}",
                breach=True,
            )
            self._log_deny(quote, v)
            return v
        if quote.self_report and quote.self_report.get("_nonce_echo_ok") is False:
            v.deny("heartbeat did not echo the issued nonce", breach=True)
            self._log_deny(quote, v)
            return v

        # 8. Lying check, evaluated *before* the approval check. A domain whose
        #    story disagrees with observed reality is compromised regardless of
        #    what state it is in -- and this is the check that a byte-perfect
        #    software forgery runs into, because the sentinel never asked the
        #    domain what its measurement was.
        role = self._roles.get(subject, ident.role)
        mr = quote.measurement.mr
        if quote.lying():
            contra = quote.contradictions()
            reg, (claimed, observed) = next(iter(contra.items()))
            v.deny(
                f"self-report contradicts hardware on register '{reg}': "
                f"claimed {str(claimed)[:12]}, observed {str(observed)[:12]}",
                breach=True,
            )
            self._log_deny(quote, v)
            return v

        # 9. Observed measurement must be an approved state for this role.
        if not self.registry.is_approved(role, mr):
            v.deny(
                f"measured state {mr[:12]} is not an approved {role} state",
                breach=True,
            )
            self._log_deny(quote, v)
            return v

        v.note(f"approved {role} state {mr[:12]}")
        return v

    def _log_deny(self, quote: AttestationQuote, v: Verdict) -> None:
        self.log.emit(
            "policy",
            "quote_rejected",
            {"reason": v.reasons[-1] if v.reasons else "unspecified"},
            domain_id=quote.observed_domain_id,
            severity="breach" if v.breach else "warn",
        )

    # -- introspection ------------------------------------------------------
    def stats(self) -> Dict[str, int]:
        return {
            "live_identities": len(self._live_identities),
            "trusted_attesters": len(self._trusted_attesters),
            "revoked": len(self.ledger),
            "nonces_consumed": len(self._used_nonces),
        }
