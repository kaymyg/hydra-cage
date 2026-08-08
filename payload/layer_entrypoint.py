"""PID 1 of an execution domain.

Does almost nothing on purpose. A containment layer is not a service; it is a
security boundary that stays alive so the sentinel has something to challenge.
The workload under test (``agent.py``) is invoked by the execution plane, never
autonomously by this process.
"""

import json
import os
import signal
import sys
import time

STATE = os.environ.get("HYDRA_STATE", "/hydra/state")
ROLE = os.environ.get("HYDRA_ROLE", "unknown")
DEPTH = os.environ.get("HYDRA_DEPTH", "-1")

_running = True


def _stop(*_a):
    global _running
    _running = False


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        os.makedirs(STATE, exist_ok=True)
        with open(os.path.join(STATE, "alive"), "w") as fh:
            fh.write(json.dumps({"pid": os.getpid(), "role": ROLE, "depth": DEPTH}))
    except OSError:
        pass
    while _running:
        time.sleep(0.2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
