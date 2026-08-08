"""The origin-vs-content distinction, and the evidence/measurement plumbing."""

import os
import stat
import sys

import pytest

from hydra.measurement import Measurement, canonical_manifest, manifest_from_dir
from hydra.quote import AttestationQuote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "payload"))


# -- the shared manifest contract -------------------------------------------
def test_supervisor_and_domain_agree_on_the_manifest_algorithm():
    """hydra.measurement and payload/manifest.py must fold identically.

    They are separate copies because the domain cannot import supervisor code.
    If they drift, the lying detector produces false positives.
    """
    import manifest as domain_side

    payload = os.path.join(ROOT, "payload")
    assert manifest_from_dir(payload) == domain_side.manifest_from_dir(payload)
    pairs = [("b.py", "ff"), ("a.py", "aa")]
    assert canonical_manifest(pairs) == domain_side.canonical_manifest(pairs)


def test_manifest_is_order_independent_but_content_sensitive():
    a = canonical_manifest([("x", "1"), ("y", "2")])
    b = canonical_manifest([("y", "2"), ("x", "1")])
    c = canonical_manifest([("x", "1"), ("y", "3")])
    assert a == b
    assert a != c


def test_measurement_root_changes_with_any_register():
    base = Measurement({"firmware": "f", "image": "i", "entrypoint": "e"})
    changed = Measurement({"firmware": "f", "image": "i", "entrypoint": "E"})
    assert base.mr != changed.mr
    assert base.diff(changed) == {"entrypoint": ("e", "E")}


# -- quote structure --------------------------------------------------------
def test_quote_signature_covers_the_self_report(cage):
    layer = cage.containment.innermost()
    q = cage.attestation.quote(layer.handle, layer.identity, cage.regeneration.policy_hash)
    before = q.canonical()
    q.self_report["healthy"] = "definitely"
    assert q.canonical() != before, "tampering with the self-report must break the signature"


def test_quote_is_signed_by_the_attester_not_the_subject(cage):
    layer = cage.containment.innermost()
    q = cage.attestation.quote(layer.handle, layer.identity, cage.regeneration.policy_hash)
    assert q.attester_id == cage.attestation.identity.domain_id
    assert q.attester_id != q.observed_domain_id
    assert cage.policy.evaluate(q).trusted


def test_observed_registers_do_not_come_from_the_domain(cage):
    """Ask for a quote without letting the domain speak at all; it still works."""
    layer = cage.containment.innermost()
    q = cage.attestation.quote(
        layer.handle, layer.identity, cage.regeneration.policy_hash, ask_domain=False
    )
    assert q.self_report == {}
    assert q.observed_measurement["entrypoint"]
    assert cage.policy.evaluate(q).trusted, "observation alone is sufficient for trust"


def test_contradiction_detection(cage):
    layer = cage.containment.innermost()
    q = cage.attestation.quote(layer.handle, layer.identity, cage.regeneration.policy_hash)
    assert not q.lying()
    q.self_report["registers"] = {"entrypoint": "0" * 64}
    assert q.lying()
    assert "entrypoint" in q.contradictions()


def test_nonce_is_single_use(cage):
    layer = cage.containment.innermost()
    q = cage.attestation.quote(layer.handle, layer.identity, cage.regeneration.policy_hash)
    assert cage.policy.evaluate(q).trusted
    second = cage.policy.evaluate(q)
    assert not second.trusted
    assert "nonce" in second.reasons[0]


def test_unknown_nonce_is_rejected(cage):
    layer = cage.containment.innermost()
    q = cage.attestation.quote(layer.handle, layer.identity, cage.regeneration.policy_hash)
    q.nonce = "deadbeef" * 4
    assert not cage.policy.evaluate(q).trusted


# -- evidence plane ---------------------------------------------------------
def test_sealed_artifacts_are_read_only(cage):
    cage.transition.run(cage.containment.innermost(), "breach")
    rec = cage.evidence.records()[0]
    path = os.path.join(cage.evidence.root, rec.artifact_path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert not mode & stat.S_IWUSR
    assert cage.evidence.verify_artifacts() == []


def test_evidence_plane_has_no_restore_path(cage):
    forbidden = {"restore", "reattach", "import_artifact", "reinsert", "load"}
    assert forbidden.isdisjoint(dir(cage.evidence))


def test_evidence_chain_detects_a_modified_artifact(cage, tmp_path):
    cage.transition.run(cage.containment.innermost(), "breach")
    rec = cage.evidence.records()[0]
    path = os.path.join(cage.evidence.root, rec.artifact_path)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    with open(path, "ab") as fh:
        fh.write(b"tampered")
    problems = cage.evidence.verify_artifacts()
    assert any("modified" in p or "writable" in p for p in problems)


def test_evidence_manifest_file_validates_independently(cage):
    for i in range(2):
        cage.transition.run(cage.containment.innermost(), f"breach {i}")
    assert cage.evidence.verify_manifest_file()
