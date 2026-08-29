# Contributing to the Hydra Cage

Thanks for considering a contribution. This project models a containment
architecture seriously, so contributions that strengthen the trust model,
the adversary suite, or the honesty of the "Honest limits" section are
especially welcome.

## Getting set up

```bash
git clone https://github.com/kaymyg/hydra-cage.git
cd hydra-cage
pip install -r requirements.txt
make test      # 58 tests
make attack     # adversary suite — must show 10/10 blocked
make demo       # full five-act demonstration, no Docker needed
```

With real containers (optional, for the `DockerBackend` path):

```bash
make image
make demo-docker
make attack-docker
```

## Before opening a PR

CI runs the test suite against **process** and **memory** backends across
Python 3.10–3.12, the adversary suite against both, a real-Pyodide/WASM
browser-bundle check, and a real-containers job on `DockerBackend`. Please
run at least the fast path locally first:

```bash
make test
make attack
```

If you touched `web/` or `space_publish.py`, also check the browser bundle
builds:

```bash
python space_publish.py --build
python -m http.server -d build/space 8000
```

## What especially matters here

- **`payload/` must never import from `hydra/`.** That boundary is the
  architecture. A PR that blurs it will be rejected regardless of what else
  it does well.
- **New attacks belong in `adversary/`,** named after what they attempt and
  what control is supposed to stop them, in the same style as the existing
  ten. If you find a real escape, please see [`SECURITY.md`](SECURITY.md)
  instead of opening a public PR with it.
- **`ExecutionPlane.audit_reachability()` must keep returning `[]`.** If your
  change adds a new reference from the execution plane to any control plane,
  even indirectly, that's a regression, not a feature.
- **Don't overstate containment guarantees.** If a change affects what the
  "Honest limits" section in the README claims, update that section in the
  same PR.

## Good places to start

- Extending `adversary/` with an eleventh attack
- A real hardware attestation backend (TPM / SEV-SNP) implementing the
  `hydra/backends.py` interface, per the "ported to real attestation
  hardware" note in the README
- Improving `ProcessBackend` isolation without changing the trust topology
- Test coverage for edge cases in the eight-stage breach transition

For anything larger, please open an issue first to discuss the approach.

## Commit style

Small, focused commits with a clear one-line summary. No strict format
enforced beyond that.

## Code of conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
