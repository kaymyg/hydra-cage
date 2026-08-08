---
title: The Hydra Cage
emoji: 🐍
colorFrom: gray
colorTo: green
sdk: docker
app_port: 7860
pinned: false
license: apache-2.0
short_description: Regenerative containment for autonomous AI, running live
tags:
  - ai-safety
  - security
  - containment
  - sandboxing
  - attestation
---

# The Hydra Cage

**Disposable trust and regenerative containment for autonomous AI.**

A containment architecture that does not try to be an unbreakable box. When a
layer is breached, Hydra freezes the domain, cuts its interconnects, seals it
as immutable forensic evidence, permanently revokes its cryptographic identity,
and builds a fresh layer *outside* the attacker's position. The breached layer
becomes a deeper cell. The outside recedes.

Press a button above and watch it happen.

## What you are looking at

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

## The part worth watching

Every attestation quote splits in two. `observed_*` is gathered by the
supervisor from the runtime — `docker inspect` and `docker cp` under the Docker
backend, `/proc/<pid>/stat` under the process backend. `self_report` is whatever
the domain said when challenged, and is never used to grant trust.

So the adversary suite includes a *perfect liar*: a responder that reports the
exact pre-compromise measurement, with the right nonce, in the right shape,
while running modified code. A flawless forgery of content. It fails anyway:

```
policy  quote_rejected  self-report contradicts hardware on register
                        'entrypoint': claimed 553563895921, observed 01050a920ea5
```

The sentinel never asked it. Being able to speak like a layer is not sufficient
to be one.

## The outside moves away

Conventional layering is a countdown: seven walls become six, then zero. Hydra
makes it a treadmill, and makes the treadmill a checkable number —
`effective_depth = live_layers + tombstones`, which an invariant check refuses
to let regress.

```
breach 1: effective depth 4 -> 5   live[████] 4  tombs[†   ] 1
breach 2: effective depth 5 -> 6   live[████] 4  tombs[††  ] 2
breach 3: effective depth 6 -> 7   live[████] 4  tombs[††† ] 3
```

## Honest limits

This raises the cost and complexity of escape, eliminates whole classes of
software-only breakout, and guarantees every breach leaves immutable forensic
evidence — while never depending on the compromised domain's cooperation for
its own replacement. It is not a mathematical guarantee of containment.

- **Shared roots collapse together.** Nested enclaves share CPU microcode, a TEE
  implementation, a management controller, DMA infrastructure, and a supply
  chain. A flaw in any of them defeats every layer at once.
- **Side channels ignore the boundaries.** Cache, timing, and power channels
  cross logically separate domains.
- **This models the topology, not the hardware.** The "hardware root of trust"
  here is the container runtime or the kernel, not a TPM or SEV-SNP.
- **Detection is periodic.** A breach is caught on the next sweep, not
  instantly.
- **Escape via the permitted channel is out of scope.** Nothing here addresses
  a model that achieves its goals through the outputs it was legitimately asked
  to produce.

## Source

Full source, 58 tests, CI, and the Docker backend that runs real containers:
**[github.com/kaymyg/hydra-cage](https://github.com/kaymyg/hydra-cage)**

Apache-2.0.
