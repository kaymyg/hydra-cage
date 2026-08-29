---
name: Bug report
about: Report unexpected behavior, a failing test, or a broken build
title: "[Bug] "
labels: bug
---

**Describe the bug**
A clear, concise description of what's wrong.

**To reproduce**
Command(s) that trigger it, e.g.:
```
python hydra_cli.py --backend process --layers 4 breach --layer 0
```

**Expected behavior**
What you expected to happen instead.

**Environment**
- OS:
- Python version:
- Backend affected (`process` / `docker` / `memory`):
- Commit/tag:

**Additional context**
Relevant output from `make test`, `make attack`, or `hydra_cli.py forensics`.
