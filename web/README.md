---
title: The Hydra Cage
emoji: 🐍
colorFrom: gray
colorTo: green
sdk: static
app_file: index.html
pinned: false
license: apache-2.0
short_description: Regenerative containment for autonomous AI, live in-browser
tags:
  - ai-safety
  - security
  - containment
  - sandboxing
  - attestation
---

# The Hydra Cage

**Disposable trust and regenerative containment for autonomous AI.**

When a containment layer is breached, Hydra does not patch it. It freezes the
domain, cuts its interconnects, seals it as immutable forensic evidence,
permanently revokes its cryptographic identity, and builds a fresh layer
*outside* the attacker's position. The breached layer becomes a deeper cell.
The outside recedes.

This Space runs the real implementation — the actual `hydra` package, the
actual ten-attack adversary suite — compiled to WebAssembly via Pyodide and
executed in your browser. No server, no backend, nothing phoning home.

## Read this before drawing conclusions

The page runs the **`MemoryBackend`**: domains are entries in a
supervisor-held registry and their code is `exec`'d inside the same Python
interpreter. There is no memory protection and no privilege boundary — a
determined payload could reach the supervisor through the interpreter itself.

What *is* faithful is the trust protocol. The sentinel still never asks a
domain what its measurement is. Hardware identity still comes from a registry
no domain has a handle to. Every law, every quote check, and all eight
transition stages behave exactly as they do on real containers — the same 58
tests pass against both backends.

**This demonstrates the topology. The Docker backend does the enforcement.**

## The architecture

**Five planes**, each with its own root of trust. The AI touches exactly one.

| Plane | Owns | Reachable by the AI |
|---|---|---|
| Execution | `submit()`, and nothing else | yes — this is the door |
| Containment | nested domains, depth accounting | no |
| Attestation | sentinel, own key vault, own root | no |
| Regeneration | domain key vault, create/destroy | no |
| Evidence | write-once hash-chained forensics | no |

**Four laws**, enforced as predicates on the hot path of every trust decision,
raising rather than returning false so a missing check crashes instead of
silently permitting: no self-attestation, no self-regeneration, no identity
inheritance, no trust recovery.

**Eight stages** on breach: detect, freeze, sever, preserve, revoke, rebuild,
reattest, reinsert. Every one runs supervisor-side. Nothing asks the
compromised domain to cooperate with its own replacement.

## The one to try first

Pick **`perfect_liar`** from the attack menu. It replaces a layer's code and
then reports the exact pre-compromise measurement — right nonce, right shape,
a byte-perfect forgery of a healthy heartbeat. It fails anyway:

```
policy  quote_rejected  self-report contradicts hardware on register
                        'entrypoint': claimed 553563895921, observed 01050a920ea5
```

The sentinel never asked it. Being able to speak like a layer is not
sufficient to be one.

Then breach the same cage three or four times and watch `effective depth`
climb. Conventional layering is a countdown — seven walls become six, then
zero. Hydra makes it a treadmill, and makes the treadmill a checkable number
that an invariant refuses to let regress.

## Honest limits

- **Shared roots collapse together.** Even on real hardware, nested enclaves
  share CPU microcode, a TEE, a management controller and a supply chain. A
  flaw in any one defeats every layer at once.
- **Side channels ignore the boundaries.** Cache, timing and power channels
  cross logically separate domains.
- **Detection is periodic.** A breach is caught on the next sweep, not
  instantly.
- **Escape via the permitted channel is out of scope.** Nothing here addresses
  a model that achieves its goals through the outputs it was legitimately
  asked to produce.

## Source

Full source, 58 tests across both backends, CI, and the Docker backend that
runs a real container per layer:
**[github.com/kaymyg/hydra-cage](https://github.com/kaymyg/hydra-cage)**

Apache-2.0.
