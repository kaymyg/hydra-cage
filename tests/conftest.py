import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from hydra import CageConfig, HydraCage  # noqa: E402


@pytest.fixture
def cage(tmp_path):
    cfg = CageConfig(
        layers=3,
        backend="process",
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
