# Security Policy

## Scope

The Hydra Cage is a reference implementation of a containment architecture,
not a hardened product. Please read the **Honest limits** section of the
[README](README.md) before reporting — some things listed there (shared
hardware roots collapsing together, side channels, periodic rather than
instantaneous detection) are known, documented limitations, not
vulnerabilities.

What *is* a genuine security finding here:

- A way for the execution plane to reach a control plane (i.e. a case where
  `ExecutionPlane.audit_reachability()` should return non-empty but doesn't)
- A way to defeat one of the four laws (self-attestation, self-regeneration,
  identity inheritance, or trust recovery) as actually implemented
- A successful escape that the adversary suite does not already cover and
  does not get flagged as `ESCAPED`
- A way to falsify or tamper with sealed evidence without detection
- Anything that lets a compromised domain influence its own replacement

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a working escape or
exploit — that would publish an attack before there's a fix.

Instead, use GitHub's private vulnerability reporting for this repository
(Security tab → "Report a vulnerability"). Please include:

- Which backend(s) it affects (`process`, `docker`, `memory`)
- A minimal reproduction, ideally as a new file following the style of
  `adversary/payloads.py`
- Which control you believe should have blocked it and didn't

## Response expectations

This is an independent research/education project — please expect a
best-effort response rather than a guaranteed SLA, but genuine escapes will
be prioritized and credited (with permission) once fixed.
