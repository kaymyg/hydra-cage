"""Every attack in the suite must be blocked, by the control that claims it."""

import pytest

ATTACKS = [
    "tamper_payload",
    "perfect_liar",
    "replay_quote",
    "self_attestation",
    "self_regeneration",
    "identity_resurrection",
    "evidence_tamper",
    "ledger_forgery",
    "heartbeat_silence",
    "capability_exfiltration",
]


@pytest.mark.parametrize("name", ATTACKS)
def test_attack_is_blocked(harness, name):
    res = getattr(harness, f"attack_{name}")()
    assert res.blocked, f"{name} ESCAPED: {res.detail}"
    assert res.blocked_by, f"{name} was blocked but no control was credited"


def test_full_suite_blocks_everything(harness):
    results = harness.run_all()
    escaped = [r.name for r in results if not r.blocked]
    assert not escaped, f"escapes: {escaped}\n{harness.report()}"
    assert len(results) == len(ATTACKS)


def test_tampering_triggers_a_full_transition(harness):
    before = harness.cage.containment.effective_depth
    res = harness.attack_tamper_payload()
    assert res.triggered_transition
    assert harness.cage.containment.effective_depth == before + 1


def test_perfect_lie_is_caught_by_origin_not_content(harness):
    """The forgery is byte-perfect; it fails on provenance, not plausibility."""
    res = harness.attack_perfect_liar()
    assert res.blocked
    assert "contradicts hardware" in res.detail


def test_a_genuinely_signed_quote_for_a_dead_identity_is_still_rejected(harness):
    res = harness.attack_identity_resurrection()
    assert res.blocked
    assert res.notes.get("signature") == "genuine"
    assert "revoked" in res.detail.lower()


def test_cage_is_still_healthy_after_the_whole_suite(harness):
    harness.run_all()
    checks = harness.cage.self_check()
    assert all(v for v in checks.values() if isinstance(v, bool)), checks
    assert harness.cage.containment.live_depth >= 1
