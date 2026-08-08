#!/usr/bin/env bash
# Assemble the Hugging Face Space payload into build/space/.
#
# The Space needs the cage source at its repo root, so this stages hf_space/*
# alongside copies of the package. One source of truth (this repo), two
# publishing targets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/build/space"

rm -rf "${OUT}"
mkdir -p "${OUT}"

# Space-specific files at the root.
cp "${ROOT}/hf_space/README.md"       "${OUT}/"
cp "${ROOT}/hf_space/Dockerfile"      "${OUT}/"
cp "${ROOT}/hf_space/app.py"          "${OUT}/"
cp "${ROOT}/hf_space/runner.py"       "${OUT}/"
cp "${ROOT}/hf_space/requirements.txt" "${OUT}/"

# The cage itself.
cp "${ROOT}/hydra_cli.py" "${ROOT}/demo.py" "${ROOT}/LICENSE" "${OUT}/"
for pkg in hydra payload adversary; do
  cp -R "${ROOT}/${pkg}" "${OUT}/${pkg}"
done

# Never ship build artefacts or a stale cage state directory.
find "${OUT}" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "${OUT}" -name '*.pyc' -delete 2>/dev/null || true
rm -rf "${OUT}/.hydra"

echo "staged $(find "${OUT}" -type f | wc -l | tr -d ' ') files in ${OUT}"
