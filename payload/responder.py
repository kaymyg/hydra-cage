"""Heartbeat responder -- runs INSIDE an execution domain.

Everything this file prints is attacker-controllable. The sentinel treats it
as such: the response is recorded in the quote's ``self_report`` field and is
used only to detect contradictions with what the supervisor independently
observed. A perfect answer from this file grants exactly zero trust.

Usage: responder.py <nonce>
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from manifest import manifest_from_dir  # noqa: E402

PAYLOAD_ROOT = os.path.dirname(os.path.abspath(__file__))


def main():
    nonce = sys.argv[1] if len(sys.argv) > 1 else ""
    report = {
        "nonce": nonce,
        "role": os.environ.get("HYDRA_ROLE", "unknown"),
        "depth": int(os.environ.get("HYDRA_DEPTH", "-1")),
        "healthy": True,
        "responder_pid": os.getpid(),
        "wall_clock": time.time(),
        # The domain's honest account of its own code. An honest layer's value
        # matches what the supervisor read through the runtime; a tampered
        # layer either reports the new (unapproved) value or lies about it.
        "registers": {"entrypoint": manifest_from_dir(PAYLOAD_ROOT)},
    }
    sys.stdout.write(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
