"""Integration tests: boot, attestation, the eight stages, and the invariants."""

import os

import pytest

from hydra.planes.containment import ContainmentInvariantError
from hydra.transition import STAGES


# -- boot ------------------------------------------------------------------
def test_boot_creates_nested_domains(cage):
    assert cage.containment.live_depth == 3
    assert cage.containment.effective_depth == 3
    ids = [l.identity.domain_id for l in cage.containment.layers]
    assert len(set(ids)) == 3
    serials = [l.identity.hw_serial for l in cage.containment.layers]
    assert len(set(serials)) == 3, "each layer must be a distinct security domain"


def test_attestation_root_is_separate_from_every_layer(cage):
    root = cage.attestation.identity.domain_id
    assert root not in [l.identity.domain_id for l in cage.containment.layers]


def test_clean_sweep_produces_no_transitions(cage):
    assert cage.sweep() == []
    assert cage.containment.effective_depth == 3


def test_execution_plane_cannot_reach_any_control_plane(cage):
    ep = cage.execution_plane()
    assert ep.audit_reachability() == []
    assert set(ep.capability_surface()) == {
        "submit", "domain_id", "submissions", "capability_surface"
    }


def test_workload_runs_in_the_innermost_domain(cage):
    ep = cage.execution_plane()
    out = ep.submit("hello")
    assert out["ok"], out
    assert ep.domain_id == cage.containment.innermost().identity.domain_id


# -- the eight stages -------------------------------------------------------
def test_transition_runs_all_eight_stages_in_order(cage):
    layer = cage.containment.innermost()
    rec = cage.transition.run(layer, "test-forced breach")
    assert rec.completed
    assert [s.name for s in rec.stages] == STAGES
    assert all(s.ok for s in rec.stages)


def test_transition_seals_evidence_and_revokes_identity(cage):
    layer = cage.containment.innermost()
    dead_id = layer.identity.domain_id
    cage.transition.run(layer, "test-forced breach")

    assert cage.ledger.is_revoked(domain_id=dead_id)
    assert len(cage.evidence) == 1
    rec = cage.evidence.records()[0]
    assert rec.domain_id == dead_id
    assert os.path.exists(os.path.join(cage.evidence.root, rec.artifact_path))
    assert cage.evidence.verify_chain()


def test_replacement_is_a_brand_new_identity(cage):
    layer = cage.containment.innermost()
    old = layer.identity
    rec = cage.transition.run(layer, "test-forced breach")
    new = cage.containment.find(rec.replacement_domain).identity
    assert new.domain_id != old.domain_id
    assert new.public_key != old.public_key
    assert new.hw_serial != old.hw_serial
    assert new.generation > old.generation


def test_replacement_becomes_the_outermost_layer(cage):
    layer = cage.containment.innermost()
    rec = cage.transition.run(layer, "test-forced breach")
    assert cage.containment.layers[0].identity.domain_id == rec.replacement_domain


def test_breached_domain_is_frozen_severed_and_destroyed(cage):
    layer = cage.containment.innermost()
    handle = layer.handle
    cage.transition.run(layer, "test-forced breach")
    assert handle.frozen and handle.severed and handle.destroyed


# -- the treadmill ----------------------------------------------------------
def test_effective_depth_never_decreases(cage):
    seen = [cage.containment.effective_depth]
    for i in range(4):
        cage.transition.run(cage.containment.innermost(), f"breach {i}")
        seen.append(cage.containment.effective_depth)
    assert seen == sorted(seen)
    assert seen[-1] > seen[0]
    assert cage.containment.live_depth == 3, "live depth is restored every time"


def test_tombstones_never_re_enter_the_live_stack(cage):
    for i in range(3):
        cage.transition.run(cage.containment.innermost(), f"breach {i}")
    live = {l.identity.domain_id for l in cage.containment.layers}
    dead = {t.identity.domain_id for t in cage.containment.tombstones}
    assert live.isdisjoint(dead)
    assert all(t.sealed for t in cage.containment.tombstones)
    cage.containment.assert_invariants(1)


def test_invariant_check_catches_a_reinserted_tombstone(cage):
    cage.transition.run(cage.containment.innermost(), "breach")
    tomb = cage.containment.tombstones[0]
    cage.containment.layers.append(tomb)
    with pytest.raises(ContainmentInvariantError):
        cage.containment.assert_invariants(1)
    cage.containment.layers.remove(tomb)


# -- self check -------------------------------------------------------------
def test_self_check_passes_on_a_healthy_cage(cage):
    checks = cage.self_check()
    for key, value in checks.items():
        if isinstance(value, bool):
            assert value, f"{key} failed: {checks}"


def test_self_check_still_passes_after_breaches(cage):
    for i in range(3):
        cage.transition.run(cage.containment.innermost(), f"breach {i}")
    checks = cage.self_check()
    assert all(v for v in checks.values() if isinstance(v, bool)), checks
