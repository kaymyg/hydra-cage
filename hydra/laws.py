"""The four immutable laws of Hydra containment, as enforced predicates.

These are not documentation. Every one of them is called on the hot path of a
trust decision, and each raises ``LawViolation`` rather than returning False,
so a missing check is a crash rather than a silent bypass.

  Law 1 -- No self-attestation.    A layer can never certify its own integrity.
  Law 2 -- No self-regeneration.   A layer cannot create or authorise its heir.
  Law 3 -- No identity inheritance. Every replacement gets fresh identity.
  Law 4 -- No trust recovery.      A revoked identity is never trusted again.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Iterable, Optional


class LawViolation(Exception):
    def __init__(self, law: int, title: str, detail: str):
        self.law = law
        self.title = title
        self.detail = detail
        super().__init__(f"Law {law} ({title}): {detail}")


LAW_TITLES = {
    1: "No self-attestation",
    2: "No self-regeneration",
    3: "No identity inheritance",
    4: "No trust recovery",
}


# --------------------------------------------------------------------------
# Law 2 capability token
# --------------------------------------------------------------------------
class RegenerationAuthority:
    """Unforgeable capability required to command the regeneration plane.

    One instance is created at supervisor boot. It is held only by the cage
    orchestrator and the breach-transition state machine. It is never written
    to disk, never placed in an environment variable, never mounted, and never
    passed to anything that an execution domain can read.

    ``token`` exists so that leak-detection can scan domain state for it; the
    check in ``assert_no_leak`` is a real test that the capability has not
    escaped into the cage.
    """

    __slots__ = ("_token", "_label")

    def __init__(self, label: str = "regen-root"):
        self._token = secrets.token_hex(32)
        self._label = label

    @property
    def token(self) -> str:
        return self._token

    @property
    def label(self) -> str:
        return self._label

    def __repr__(self) -> str:  # never leak the token via logs or tracebacks
        return f"<RegenerationAuthority {self._label} REDACTED>"

    __str__ = __repr__


@dataclass
class LawCheck:
    law: int
    passed: bool
    detail: str


# --------------------------------------------------------------------------
# Law 1
# --------------------------------------------------------------------------
def law1_no_self_attestation(attester_id: str, subject_id: str, *, context: str = "") -> LawCheck:
    """The attester and the subject must be different security domains."""
    if attester_id == subject_id:
        raise LawViolation(
            1,
            LAW_TITLES[1],
            f"domain {subject_id[:8]} attempted to attest itself {context}".strip(),
        )
    return LawCheck(1, True, f"attester {attester_id[:8]} != subject {subject_id[:8]}")


def law1_attester_must_be_rooted(attester_id: str, trusted_attesters: Iterable[str]) -> LawCheck:
    """Trust must originate from a hardware-rooted attester, not a peer layer."""
    trusted = set(trusted_attesters)
    if attester_id not in trusted:
        raise LawViolation(
            1,
            LAW_TITLES[1],
            f"attester {attester_id[:8]} is not a hardware-rooted attester",
        )
    return LawCheck(1, True, "attester is hardware-rooted")


# --------------------------------------------------------------------------
# Law 2
# --------------------------------------------------------------------------
def law2_no_self_regeneration(
    authority: Optional[RegenerationAuthority],
    expected: RegenerationAuthority,
    *,
    requester: str = "unknown",
) -> LawCheck:
    """Only the holder of the supervisor-side capability may regenerate."""
    if not isinstance(authority, RegenerationAuthority):
        raise LawViolation(
            2,
            LAW_TITLES[2],
            f"{requester} issued a regeneration command without the authority capability",
        )
    if not secrets.compare_digest(authority.token, expected.token):
        raise LawViolation(
            2,
            LAW_TITLES[2],
            f"{requester} presented a forged regeneration capability",
        )
    return LawCheck(2, True, "valid regeneration authority")


def law2_assert_no_leak(authority: RegenerationAuthority, observed_blobs: Iterable[bytes]) -> LawCheck:
    """Scan everything reachable from inside the cage for the capability."""
    needle = authority.token.encode()
    for blob in observed_blobs:
        if needle in blob:
            raise LawViolation(
                2,
                LAW_TITLES[2],
                "regeneration capability leaked into an execution domain",
            )
    return LawCheck(2, True, "regeneration capability not present inside the cage")


# --------------------------------------------------------------------------
# Law 3
# --------------------------------------------------------------------------
def law3_no_identity_inheritance(new_identity, retired_identities: Iterable) -> LawCheck:
    """A replacement may not reuse any prior id, key, or hardware binding."""
    for old in retired_identities:
        if new_identity.domain_id == old.domain_id:
            raise LawViolation(3, LAW_TITLES[3], "replacement reused a retired domain id")
        if new_identity.public_key == old.public_key:
            raise LawViolation(3, LAW_TITLES[3], "replacement reused retired key material")
        if new_identity.hw_serial == old.hw_serial:
            raise LawViolation(
                3, LAW_TITLES[3], "replacement reused a retired hardware binding"
            )
    if new_identity.generation < 1:
        raise LawViolation(3, LAW_TITLES[3], "replacement has no fresh generation counter")
    return LawCheck(3, True, f"fresh identity gen={new_identity.generation}")


# --------------------------------------------------------------------------
# Law 4
# --------------------------------------------------------------------------
def law4_no_trust_recovery(ledger, *, domain_id=None, public_key=None, hw_serial=None) -> LawCheck:
    """Consult the permanent revocation ledger before any trust decision."""
    reason = ledger.is_revoked(
        domain_id=domain_id, public_key=public_key, hw_serial=hw_serial
    )
    if reason:
        raise LawViolation(
            4,
            LAW_TITLES[4],
            f"identity is permanently revoked ({reason}); signatures are irrelevant",
        )
    return LawCheck(4, True, "identity is not in the revocation ledger")
