import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from hydra import CageConfig, HydraCage  # noqa: E402


@pytest.fixture
def cage(tmp_path):
    # HYDRA_TEST_BACKEND=memory runs the whole suite against the in-process
    # backend the browser Space uses. Every law, quote check and transition
    # stage must behave identically on both.
    cfg = CageConfig(
        layers=3,
        backend=os.environ.get("HYDRA_TEST_BACKEND", "process"),
        workdir=str(tmp_path / "hydra"),
        payload=os.path.join(ROOT, "payload"),
        prewarm=1,
        echo=False,
        response_timeout=2.0,
    )
    c = HydraCage(cfg).boot()
    yield c
    c.shutdown(purge=False)


@pytest.fixture
def harness(cage):
    from adversary.attacks import AttackHarness

    return AttackHarness(cage)
