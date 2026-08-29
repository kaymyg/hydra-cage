# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-08-09

### Added
- Initial public release: five-plane containment architecture (execution,
  containment, attestation, regeneration, evidence), each with an
  independent root of trust.
- The four enforced laws (no self-attestation, no self-regeneration, no
  identity inheritance, no trust recovery) as `LawViolation`-raising
  predicates on the hot path, not comments.
- The eight-stage breach transition (detect → freeze → sever → preserve →
  revoke → rebuild → reattest → reinsert), fully supervisor-side.
- `DockerBackend`, `ProcessBackend`, and `MemoryBackend` (for Pyodide/WASM),
  all passing the same 58-test suite and the same trust protocol.
- Ten-attack adversary suite, including the "perfect liar" and
  `identity_resurrection` attacks — all 10/10 blocked.
- CLI (`hydra_cli.py`): `up`, `breach`, `attack`, `demo`, `status`,
  `forensics`.
- CI matrix across Python 3.10–3.12 and the process/memory backends, plus a
  real-Pyodide browser-bundle job and a real-containers `DockerBackend` job.
- In-browser static demo (`web/`) compiled to WebAssembly via Pyodide, and a
  Docker-SDK Space variant (`hf_space/`) for accounts with Hugging Face PRO.
- `space_publish.py` to stage/diagnose/publish the Hugging Face Space
  directly from the repo.

### Notes
- Version number matches `CITATION.cff`. This is the first tagged release;
  the two commits before this point (initial architecture + demo push) are
  included in this release rather than split out, since no prior tag existed.
