---
name: Escape report (non-sensitive)
about: You found a way to defeat containment and it's safe to discuss publicly
title: "[Escape] "
labels: escape
---

> If this is a genuinely working, undisclosed escape, please use private
> vulnerability reporting instead (Security tab → "Report a vulnerability")
> per [SECURITY.md](../../SECURITY.md), not this template.

Use this template for escapes that are already blocked-but-arguably-fragile,
theoretical gaps, or attacks against the "Honest limits" the README already
documents (shared roots, side channels, etc.) — cases where public
discussion doesn't hand anyone a working exploit.

**Which control should stop this, and how does it fail?**

**Backend(s) affected** (`process` / `docker` / `memory`):

**Minimal reproduction**
Ideally in the style of `adversary/payloads.py`.

**Does the adversary suite already cover this?**
If yes, why do you think it's not actually blocking it. If no, this may be a
good candidate for attack #11.
