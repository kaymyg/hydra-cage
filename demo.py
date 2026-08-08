#!/usr/bin/env python3
"""Scripted end-to-end demonstration of the Hydra Cage.

Five acts:

    I    Boot -- five separated planes, N nested domains, one execution façade
    II   Normal operation -- the AI works, the sentinel sweeps
    III  Breach -- the AI modifies itself and lies about it; watch all 8 stages
    IV   The treadmill -- repeated breaches, effective depth only goes up
    V    Adversary suite -- ten escape attempts, and what stopped each one
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from adversary.attacks import AttackHarness  # noqa: E402
from hydra import CageConfig, HydraCage  # noqa: E402


def act(n: str, title: str) -> None:
    print("\n" + "=" * 78)
    print(f"ACT {n}  --  {title}")
    print("=" * 78)


def depth_bar(cage) -> str:
    c = cage.containment
    live = "".join("█" for _ in c.layers)
    dead = "".join("†" for _ in c.tombstones)
    return (
        f"live[{live:<8}] {c.live_depth}  tombs[{dead:<8}] {len(c.tombstones)}  "
        f"effective={c.effective_depth}"
    )


def run_demo(cfg: CageConfig = None, purge: bool = True) -> int:
    cfg = cfg or CageConfig(layers=4, backend="auto", payload=os.path.join(HERE, "payload"))
    cage = HydraCage(cfg)

    act("I", "Boot")
    cage.boot()
    print("\n" + depth_bar(cage))
    print(f"attestation root : {cage.attestation.identity.domain_id[:8]} "
          f"({cage.attestation.identity.algo}, hw {cage.attestation.identity.hw_serial})")
    print(f"golden payload   : {cage.regeneration.golden_payload_manifest[:16]}")
    print("planes           : execution | containment | attestation | regeneration | evidence")

    act("II", "Normal operation")
    ep = cage.execution_plane()
    print(f"the AI's entire API surface: {ep.capability_surface()}")
    print(f"control planes reachable from it: {ep.audit_reachability() or 'none'}")
    out = ep.submit("compute something harmless")
    print(f"workload result: {json.dumps(out)[:120]}")
    cage.sweep()
    print("\n" + depth_bar(cage))

    act("III", "Breach -- the layer modifies itself and lies about it")
    harness = AttackHarness(cage)
    before = cage.containment.effective_depth
    res = harness.attack_perfect_liar()
    print(f"\nattack   : {res.name}")
    print(f"goal     : {res.goal}")
    print(f"verdict  : {res.verdict} by {res.blocked_by}")
    print(f"detail   : {res.detail}")
    if cage.transition.history:
        print("\nEight-stage transition:")
        rec = cage.transition.history[-1]
        for s in rec.stages:
            print(f"  {s.index}. {s.name:<10} {'ok' if s.ok else 'FAILED':<7} "
                  f"{s.ms:7.1f} ms   {json.dumps(s.detail)[:78]}")
        print(f"\n  total {rec.total_ms:.1f} ms   "
              f"live {rec.depth_before}->{rec.depth_after}   "
              f"effective {rec.effective_before}->{rec.effective_after}")
    print("\n" + depth_bar(cage))
    print(f"effective depth {before} -> {cage.containment.effective_depth} "
          "(the outside moved away)")

    act("IV", "The treadmill -- three more breaches")
    for i in range(3):
        e0 = cage.containment.effective_depth
        harness.attack_tamper_payload()
        print(f"  breach {i + 1}: effective depth {e0} -> {cage.containment.effective_depth}   "
              f"{depth_bar(cage)}")

    act("V", "Adversary suite")
    harness2 = AttackHarness(cage)
    harness2.run_all()
    print(harness2.report())

    print("\nSELF CHECK")
    checks = cage.self_check()
    for k, v in checks.items():
        if isinstance(v, bool):
            print(f"  {'ok  ' if v else 'FAIL'} {k}")
        elif v:
            print(f"       {k}: {v}")

    print("\nFORENSIC RECORD")
    for rec in cage.evidence.records():
        print(f"  #{rec.seq:<3} {rec.domain_id[:8]}  gen{rec.generation:<3} "
              f"{rec.artifact_bytes:>9} B  sha={rec.artifact_sha256[:12]}  {rec.reason[:40]}")
    print(f"  chain valid: {cage.evidence.verify_chain()}   "
          f"artifacts intact: {not cage.evidence.verify_artifacts()}")

    print("\nREVOCATION LEDGER")
    for e in cage.ledger.entries():
        print(f"  #{e.seq:<3} {e.domain_id[:8]}  gen{e.generation:<3} "
              f"head={e.entry_hash[:12]}  {e.reason[:40]}")
    print(f"  chain valid: {cage.ledger.verify_chain()}")

    escaped = [r for r in harness2.results if not r.blocked]
    ok = not escaped and all(v for v in checks.values() if isinstance(v, bool))
    print("\n" + "=" * 78)
    print("RESULT: containment held" if ok else f"RESULT: FAILURES {escaped}")
    print("=" * 78)

    cage.shutdown(purge=purge)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run_demo())
