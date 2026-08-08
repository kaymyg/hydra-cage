"""Hydra Cage -- disposable trust and regenerative containment for autonomous AI.

Five planes, four laws, one eight-stage breach transition.

    from hydra import HydraCage, CageConfig

    with HydraCage(CageConfig(layers=4, backend="docker")).boot() as cage:
        cage.execution_plane().submit("hello")
        cage.sweep()
        print(cage.self_check())
"""

from .cage import CageConfig, HydraCage
from .identity import DomainIdentity, RevocationLedger
from .laws import LAW_TITLES, LawViolation, RegenerationAuthority
from .measurement import Measurement
from .quote import AttestationQuote, Verdict
from .transition import STAGES, HydraBreachTransition, TransitionAborted

__version__ = "1.0.0"

__all__ = [
    "HydraCage",
    "CageConfig",
    "LawViolation",
    "LAW_TITLES",
    "RegenerationAuthority",
    "DomainIdentity",
    "RevocationLedger",
    "Measurement",
    "AttestationQuote",
    "Verdict",
    "HydraBreachTransition",
    "TransitionAborted",
    "STAGES",
]
