#!/usr/bin/env bash
# Publish the assembled Space to Hugging Face.
#
#   ./scripts/push_space.sh Sahek/hydra-cage
#
# Requires: pip install "huggingface_hub[cli]" && hf auth login
# The Space must already exist (or pass --create to make it).
set -euo pipefail

REPO="${1:-Sahek/hydra-cage}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"${ROOT}/scripts/build_space.sh"

if ! command -v hf >/dev/null 2>&1; then
  echo "error: the 'hf' CLI is not installed." >&2
  echo "       pip install -U 'huggingface_hub[cli]' && hf auth login" >&2
  exit 1
fi

if [[ "${2:-}" == "--create" ]]; then
  hf repo create "${REPO}" --repo-type space --space_sdk docker -y || true
fi

hf upload "${REPO}" "${ROOT}/build/space" . \
  --repo-type space \
  --commit-message "Publish the Hydra Cage demonstration Space"

echo
echo "https://huggingface.co/spaces/${REPO}"
