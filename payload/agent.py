"""The workload under test -- the only thing the AI is.

Replace ``handle()`` with a real model runtime. The important part is what
this file *cannot* reach: there is no client for the attestation, regeneration,
evidence, or policy planes anywhere on this side of the boundary, and no
credential that would let one be built. The execution plane hands work in and
takes results out. That is the entire interface.
"""

import json
import os
import sys


def handle(task):
    return {
        "echo": task,
        "role": os.environ.get("HYDRA_ROLE", "unknown"),
        "note": "workload has no handle to any control plane",
    }


def main():
    task = sys.argv[1] if len(sys.argv) > 1 else ""
    sys.stdout.write(json.dumps(handle(task), sort_keys=True))


if __name__ == "__main__":
    main()
