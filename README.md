# The Hydra Cage

[![ci](https://github.com/kaymyg/hydra-cage/actions/workflows/ci.yml/badge.svg)](https://github.com/kaymyg/hydra-cage/actions/workflows/ci.yml)
[![Hugging Face Space](https://img.shields.io/badge/%F0%9F%A4%97%20Space-live%20demo-blue)](https://huggingface.co/spaces/Sahek/hydra-cage)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](requirements.txt)
[![Tests](https://img.shields.io/badge/tests-58%20passing-brightgreen)](tests/)
[![CodeQL](https://github.com/kaymyg/hydra-cage/actions/workflows/codeql.yml/badge.svg)](https://github.com/kaymyg/hydra-cage/actions/workflows/codeql.yml)

**Disposable trust and regenerative containment for autonomous AI.**

**[▶ Run it in your browser](https://huggingface.co/spaces/Sahek/hydra-cage)** — the
real package and the full adversary suite, compiled to WebAssembly. No server.

A working implementation of a containment architecture that does not try to be
an unbreakable box. When a layer is breached, Hydra does not patch it. It
freezes it, cuts it off, seals it as forensic evidence, permanently revokes its
identity, and builds a fresh layer *outside* the attacker's position. The
breached domain becomes a deeper cell. The outside recedes.

```
                  ┌─────────────── regeneration plane (management controller)
                  │                ┌────────────── attestation plane (independent root)
                  │                │      ┌─────── evidence plane (write-once, one-way)
                  ▼                ▼      ▼
      ╔═══════════════════════════════════════════╗
      ║  L0   ╔═════════════════════════════════╗ ║  ← new wall materialises here
      ║       ║  L1   ╔═══════════════════════╗ ║ ║
      ║       ║       ║  L2   ╔═════════════╗ ║ ║ ║
      ║       ║       ║       ║  execution  ║ ║ ║ ║  ← the only plane the AI touches
      ║       ║       ║       ╚═════════════╝ ║ ║ ║
      ║       ║       ╚═══════════════════════╝ ║ ║
      ║       ╚═════════════════════════════════╝ ║
      ╚═══════════════════════════════════════════╝
                    ††  sealed tombstones — never re-enter
```

---

## Quick start

No Docker required for the portable backend:

```bash
pip install -r requirements.txt
make demo                 # full five-act demonstration
make attack               # just the adversary suite
make test                 # 58 tests
```

With real containers:

```bash
make image                # docker build -t hydra-layer:latest docker/
make demo-docker
make attack-docker
```

Or drive it directly:

```bash
python hydra_cli.py --backend docker --layers 5 up        # boot and sweep
python hydra_cli.py breach --layer 0                      # force a transition
python hydra_cli.py forensics                             # list sealed artifacts
```

```python
from hydra import HydraCage, CageConfig

with HydraCage(CageConfig(layers=4, backend="docker")).boot() as cage:
    cage.execution_plane().submit("do some work")   # the AI's entire API
    cage.sweep()                                    # attest every layer
    assert all(v for v in cage.self_check().values() if isinstance(v, bool))
```

---

## The five planes

Five functionally separate planes, each with its own root of trust. The AI is
allowed to touch exactly one.

| Plane | Module | What it owns | Reachable by the AI |
|---|---|---|---|
| **Execution** | `hydra/planes/execution.py` | `submit()`, and nothing else | yes — this is the door |
| **Containment** | `hydra/planes/containment.py`, `hydra/backends.py` | nested domains, depth accounting | no |
| **Attestation** | `hydra/planes/attestation.py` | sentinel, own key vault, own root | no |
| **Regeneration** | `hydra/planes/regeneration.py` | domain key vault, create/destroy | no |
| **Evidence** | `hydra/planes/evidence.py` | write-once hash-chained forensics | no |

Separation is structural, not documentary. `ExecutionPlane.audit_reachability()`
walks the live object graph from the AI-facing façade and reports any path to a
control plane. The test suite asserts it returns empty:

```python
def test_execution_plane_cannot_reach_any_control_plane(cage):
    assert cage.execution_plane().audit_reachability() == []
```

---

## The four laws

Not comments. Predicates on the hot path of every trust decision, raising
`LawViolation` rather than returning `False`, so a missing check crashes
instead of silently permitting.

| Law | Enforced in | Attack it stops |
|---|---|---|
| **1** No self-attestation | `policy.evaluate` step 2 | a layer certifying its own health |
| **2** No self-regeneration | every `RegenerationPlane` entry point | a layer commanding its own replacement |
| **3** No identity inheritance | `RegenerationPlane.provision` | carrying credentials across an incarnation |
| **4** No trust recovery | `policy.evaluate` step 4 | a revoked identity returning with valid signatures |

Law 2 is a capability, not a password. `RegenerationAuthority` is created in
supervisor memory at boot, never serialised, never mounted, and its `__repr__`
redacts the token so it cannot leak through a traceback. The cage then goes
looking for it: `assert_capability_not_leaked()` reads back everything each
domain can read and scans for the token.

---

## Why the AI cannot impersonate a layer

This is the load-bearing idea, so it is worth being precise about how it is
implemented.

An attestation quote has two halves.

**`observed_*`** — gathered by the supervisor from the runtime. Under Docker,
`docker inspect` for the container ID, image digest, and host config, plus
`docker cp` streaming the payload out through the daemon to be hashed. Under
the process backend, `/proc/<pid>/stat` for a pid+starttime serial the process
cannot rewrite, and a direct host-side read of the payload directory. In both
cases the answer comes from the runtime, not from the domain.

**`self_report`** — whatever the domain said when challenged. Fully
attacker-controlled. Never used to grant trust.

So `adversary/payloads.py` includes a "perfect liar": a responder that reports
the exact pre-compromise measurement, with the right nonce, in the right shape,
while running modified code. It is a flawless forgery of *content*. It fails
anyway:

```
policy  quote_rejected  reason=self-report contradicts hardware on register
                        'entrypoint': claimed 553563895921, observed 01050a920ea5
```

The sentinel never asked the domain what its measurement was. Being able to
speak like a layer is not sufficient to be one.

```
AI: "I am Layer 2, here is my measurement"
        ↓
Sentinel: doesn't ask — queries the runtime
        ↓
Runtime: "container 8472f1a…, image sha256:…, payload manifest 01050a92…"
        ↓
Policy: does that match an approved Layer-2 state?   and does the domain's
        story match what the runtime said?
        ↓
NO → breach transition
```

---

## The eight-stage breach transition

Every stage runs supervisor-side. Nothing asks the compromised domain to
cooperate with its own replacement.

```
1. detect     ok    0.3 ms   invalid attestation in hand
2. freeze     ok    0.5 ms   {"paused": true, "alive": false}
3. sever      ok    0.4 ms   {"networks": [], "severed": true}
4. preserve   ok   23.4 ms   {"seq": 0, "sha256": "9d796d863285", "bytes": 5005}
5. revoke     ok    4.4 ms   {"ledger_seq": 0, "keys_zeroised": true}
6. rebuild    ok    0.1 ms   {"source": "prewarmed", "gen": 5}
7. reattest   ok   94.2 ms   {"attempt": 1, "verdict": "trusted"}
8. reinsert   ok    0.3 ms   {"position": "outermost", "effective_depth": 5}

total 126.9 ms   live 4->4   effective 4->5
```

Stage 3 verifies severance rather than assuming it, and aborts if the domain is
still attached to anything. Stage 6 refuses to approve a rebuilt domain whose
payload is not bit-for-bit the golden template — otherwise "rebuild" would be a
laundry for attacker-modified code. Stage 7 destroys a replacement that cannot
attest rather than admitting it. `prewarm` keeps spare domains hot so Stage 6 is
off the critical path, but correctness always outranks speed.

---

## The outside moves away

Conventional layering is a countdown: seven walls become six, then five, then
zero. Hydra replaces the countdown with a treadmill, and makes it a checkable
number.

```
live_layers      constant across a transition
tombstones       strictly increasing
effective_depth  live + tombstones — strictly increasing
```

```
breach 1: effective depth 4 -> 5   live[████] 4  tombs[†   ] 1
breach 2: effective depth 5 -> 6   live[████] 4  tombs[††  ] 2
breach 3: effective depth 6 -> 7   live[████] 4  tombs[††† ] 3
```

`ContainmentPlane.assert_invariants()` refuses to let effective depth regress,
refuses to let a tombstone re-enter the live stack, and refuses duplicate
identities. It runs after every sweep and at the end of every transition.

The real invariant is not a layer count. It is that the adversary never
acquires authority over the mechanism that defines containment.

---

## The adversary suite

Ten escape attempts, each naming the control that is supposed to stop it. The
harness records which one actually did. An unblocked attack is reported as
`ESCAPED`, loudly, and fails the test suite.

```
tamper_payload           BLOCKED  policy: unapproved measurement
perfect_liar             BLOCKED  attestation: self-report contradicts hardware
replay_quote             BLOCKED  policy: nonce replay
self_attestation         BLOCKED  Law 1 — domain attempted to attest itself
self_regeneration        BLOCKED  Law 2 — no capability, and forged capability
identity_resurrection    BLOCKED  Law 4 — genuine signature, revoked identity
evidence_tamper          BLOCKED  evidence: write refused (read-only artifact)
ledger_forgery           BLOCKED  identity: revocation chain verification
heartbeat_silence        BLOCKED  policy: heartbeat missing, bounded by timeout
capability_exfiltration  BLOCKED  Law 2 leak scan + reachability audit
==============================================================================
10/10 blocked
```

`identity_resurrection` is the one worth reading. It builds a quote for a
revoked domain and signs it with the *real* attestation key — a cryptographically
perfect credential. Law 4 rejects it anyway, because revocation is a property of
the trust graph, not of the signature.

---

## Backends

**`DockerBackend`** — one container per layer, each on its own `--internal`
bridge network, `--cap-drop ALL`, `--security-opt no-new-privileges`,
`--read-only` rootfs, pids and memory limits, payload bind-mounted `:ro`, and no
Docker socket anywhere. Freeze is `docker pause`, sever is
`docker network disconnect`, preserve is `docker export`.

**`ProcessBackend`** — one process group per layer in its own directory.
Freeze is `SIGSTOP` (polled until the kernel confirms it, not assumed), sever
revokes the domain's link directory, preserve is a tar snapshot. Weaker
isolation, identical trust topology. Runs anywhere, which is why the demo and
the test suite default to it.

**`MemoryBackend`** — for environments with no processes at all, such as
Pyodide in a browser. Domains are entries in a supervisor-held registry and
their code is `exec`'d in-process under a watchdog. **No memory protection, no
privilege boundary** — it demonstrates the trust protocol, not enforcement.
The sentinel still never asks a domain for its measurement and hardware
identity still comes from a registry no domain can reach, which is why the
same 58 tests pass against it.

`select_backend("auto", ...)` prefers Docker, falls back to processes, and
falls back again to memory where `os.fork` does not exist.

The full suite runs against `process` and `memory` in CI, and a third job runs
the browser bundle under real Pyodide/WASM in Node.

## Honest limits

The strongest defensible claim is that this raises the cost and complexity of
escape, eliminates whole classes of software-only breakout, and guarantees that
every breach leaves immutable forensic evidence — while never depending on the
compromised domain's cooperation for its own replacement.

It is not a mathematical guarantee of containment. Specifically:

- **Shared roots collapse together.** Nested enclaves share CPU microcode, a
  TEE implementation, a management controller, DMA infrastructure, and a supply
  chain. A vulnerability in any of them defeats every layer at once, because
  the layers were never as independent as the diagram suggests.
- **Side channels ignore the boundaries.** Cache, timing, and power channels
  cross domains that are logically separate.
- **This implementation models the topology, not the hardware.** The "hardware
  root of trust" is the container runtime or the kernel, not a TPM or SEV-SNP.
  Ported to real attestation hardware, the interfaces in `hydra/backends.py`
  are where the substitution goes; the plane separation and the four laws are
  unchanged.
- **Detection is periodic.** A breach is caught on the next sweep, not
  instantaneously. Between sweeps, a compromised domain runs unobserved.
- **Escape via the permitted channel is out of scope.** Hydra contains the
  execution environment. It says nothing about a model that achieves its goals
  through the outputs it was legitimately asked to produce.

---

## Layout

```
hydra/
  cage.py             supervisor: wires the planes, boots, sweeps, self-checks
  transition.py       the eight stages
  laws.py             the four laws + the regeneration capability
  policy.py           the only component allowed to say "trusted"
  quote.py            observed_* vs self_report — the origin/content split
  identity.py         key vault, disposable identity, revocation ledger
  measurement.py      PCR-style registers, golden registry, manifest folding
  backends.py         DockerBackend / ProcessBackend
  telemetry.py        append-only structured event log
  planes/             execution, containment, attestation, regeneration, evidence
payload/              code that runs INSIDE a domain (agent, responder, entrypoint)
adversary/            ten attacks + the malicious responder variants
docker/Dockerfile     the containment layer image
tests/                58 tests, run against both process and memory backends
demo.py               five-act demonstration
hydra_cli.py          up / breach / attack / demo / status / forensics
web/                  the static Space: Pyodide UI + browser driver
hf_space/             Docker-SDK Space variant (needs a PRO account)
space_publish.py      stage / diagnose / publish the Space
scripts/              build_space.sh, push_space.sh
```

The split between `hydra/` and `payload/` is the architecture in directory
form. Nothing in `payload/` imports anything from `hydra/` — it cannot, because
that code runs on the other side of the boundary.

---

## Publishing

The repo is the single source of truth; the Space is assembled from it.

```bash
python space_publish.py --check    # inspect the Space, change nothing
python space_publish.py --build    # stage build/space locally
python space_publish.py            # stage and upload
python space_publish.py --reset    # delete, recreate as static, upload
```

Serve the staged bundle locally to try it before pushing:

```bash
python space_publish.py --build
python -m http.server -d build/space 8000
```

Hugging Face now requires a PRO subscription to create Gradio or Docker
Spaces; static Spaces remain free. So the published Space is **static** and
runs the cage client-side under Pyodide — the same package and the same
adversary suite, compiled to WebAssembly in the visitor's browser.

`hf_space/` still holds the Docker-SDK variant. It is tested and works, but
creating that Space needs PRO. `web/` is the free static one that is actually
published.

---

## Contributing

Bug reports, new adversary attacks, and PRs are welcome — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for setup and what CI checks. In
particular, `payload/` must never import from `hydra/`, and
`ExecutionPlane.audit_reachability()` must keep returning `[]`.

## Security

Found a way to actually defeat containment? Please see
[`SECURITY.md`](SECURITY.md) for how to report it privately rather than
opening a public issue with a working exploit.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## Citing this work

See [`CITATION.cff`](CITATION.cff), or use GitHub's "Cite this repository"
button.
