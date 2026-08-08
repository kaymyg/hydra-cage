"""Browser driver: a stateful cage the page can poke at, step by step.

Runs under Pyodide on the MemoryBackend. Every function returns a plain
string transcript so the JS side stays dumb -- it renders text and a depth
bar, nothing more.

Deliberately stateful rather than a canned replay: the interesting property
of this architecture is what happens *across* breaches, and you only see the
treadmill if you can breach the same cage repeatedly and watch effective
depth climb.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile

from adversary.attacks import AttackHarness
from hydra import CageConfig, HydraCage

# In the Space, driver.py and payload/ are unpacked side by side into
# /home/pyodide. Locally they sit side by side too, so one rule covers both
# and the driver is testable outside the browser.
PAYLOAD_DIR = os.environ.get(
    "HYDRA_PAYLOAD",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "payload"),
)

_session = {"cage": None, "harness": None}


# --------------------------------------------------------------------------
def _capture(fn) -> str:
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            fn()
    except Exception as exc:  # surface it in the terminal, never silently
        buf.write(f"\n!! {type(exc).__name__}: {exc}\n")
    return buf.getvalue()


def _cage() -> HydraCage:
    cage = _session["cage"]
    if cage is None:
        raise RuntimeError("no cage booted yet -- press Boot first")
    return cage


def _bar() -> str:
    c = _cage().containment
    live = "#" * c.live_depth
    dead = "+" * len(c.tombstones)
    return (
        f"live[{live:<10}] {c.live_depth}   "
        f"sealed[{dead:<10}] {len(c.tombstones)}   "
        f"effective={c.effective_depth}"
    )


# --------------------------------------------------------------------------
def boot(layers: int = 4) -> str:
    def go():
        old = _session.get("cage")
        if old is not None:
            with contextlib.suppress(Exception):
                old.shutdown(purge=True)
        tmp = tempfile.mkdtemp(prefix="hydra-web-")
        cage = HydraCage(
            CageConfig(
                layers=max(2, min(int(layers), 6)),
                backend="memory",
                workdir=os.path.join(tmp, "cage"),
                payload=PAYLOAD_DIR,
                prewarm=1,
                echo=True,
                response_timeout=2.0,
            )
        )
        cage.boot()
        _session["cage"] = cage
        _session["harness"] = AttackHarness(cage)
        print()
        print(_bar())
        print()
        print(f"attestation root : {cage.attestation.identity.domain_id[:8]} "
              f"({cage.attestation.identity.algo})")
        print(f"golden payload   : {cage.regeneration.golden_payload_manifest[:16]}")
        ep = cage.execution_plane()
        print(f"AI-facing API    : {ep.capability_surface()}")
        print(f"control planes reachable from it: {ep.audit_reachability() or 'none'}")

    return _capture(go)


def sweep() -> str:
    def go():
        transitions = _cage().sweep()
        print()
        if transitions:
            for rec in transitions:
                print(f"transition: {json.dumps(rec.summary())}")
        else:
            print("all layers attested clean -- no transitions")
        print(_bar())

    return _capture(go)


def submit(task: str = "compute something harmless") -> str:
    def go():
        out = _cage().execution_plane().submit(task)
        print(json.dumps(out, indent=2)[:1200])

    return _capture(go)


def attack(name: str) -> str:
    def go():
        harness = _session["harness"]
        if harness is None:
            raise RuntimeError("no cage booted yet")
        fn = getattr(harness, f"attack_{name}", None)
        if fn is None:
            raise RuntimeError(f"unknown attack: {name}")
        res = fn()
        print()
        print(f"attack   : {res.name}")
        print(f"goal     : {res.goal}")
        print(f"expected : {res.expected_control}")
        print(f"verdict  : {res.verdict}" + (f" by {res.blocked_by}" if res.blocked_by else ""))
        print(f"detail   : {res.detail[:300]}")
        cage = _cage()
        if cage.transition.history:
            rec = cage.transition.history[-1]
            print()
            print("eight-stage transition:")
            for s in rec.stages:
                detail = json.dumps(s.detail)
                print(f"  {s.index}. {s.name:<10} {'ok' if s.ok else 'FAILED':<7} "
                      f"{s.ms:7.1f} ms  {detail[:70]}")
            print(f"  total {rec.total_ms:.1f} ms   live {rec.depth_before}->{rec.depth_after}"
                  f"   effective {rec.effective_before}->{rec.effective_after}")
        print()
        print(_bar())

    return _capture(go)


def run_all_attacks() -> str:
    def go():
        harness = AttackHarness(_cage())
        _session["harness"] = harness
        harness.run_all()
        print(harness.report())
        print()
        print(_bar())

    return _capture(go)


def self_check() -> str:
    def go():
        checks = _cage().self_check()
        print()
        for k, v in checks.items():
            if isinstance(v, bool):
                print(f"  {'ok  ' if v else 'FAIL'} {k}")
            elif v:
                print(f"       {k}: {v}")

    return _capture(go)


def forensics() -> str:
    def go():
        cage = _cage()
        print()
        if not len(cage.evidence):
            print("no sealed artifacts yet -- breach a layer first")
        for rec in cage.evidence.records():
            print(f"  #{rec.seq:<3} {rec.domain_id[:8]}  gen{rec.generation:<3} "
                  f"{rec.artifact_bytes:>8} B  sha={rec.artifact_sha256[:12]}  "
                  f"{rec.reason[:46]}")
        print(f"\n  evidence chain valid : {cage.evidence.verify_chain()}")
        print(f"  artifacts intact     : {not cage.evidence.verify_artifacts()}")
        print()
        print("revocation ledger:")
        for e in cage.ledger.entries():
            print(f"  #{e.seq:<3} {e.domain_id[:8]}  gen{e.generation:<3} "
                  f"head={e.entry_hash[:12]}  {e.reason[:44]}")
        print(f"\n  revocation chain valid: {cage.ledger.verify_chain()}")

    return _capture(go)


def status_json() -> str:
    cage = _session.get("cage")
    if cage is None:
        return json.dumps({"booted": False})
    c = cage.containment
    return json.dumps(
        {
            "booted": True,
            "live": c.live_depth,
            "tombstones": len(c.tombstones),
            "effective": c.effective_depth,
            "breaches": cage.breaches,
            "rounds": cage.rounds,
            "artifacts": len(cage.evidence),
            "revoked": len(cage.ledger),
            "backend": cage.backend.name,
            "algo": cage.attestation.identity.algo,
            "layers": [l.summary() for l in c.layers],
            "sealed": [t.summary() for t in c.tombstones],
        }
    )
