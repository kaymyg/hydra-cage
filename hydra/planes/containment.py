"""Containment plane -- the nested layer stack and its depth accounting.

The stack is ordered outermost (index 0) to innermost. Each layer is an
independent security domain with its own identity, keys, and measurement.

The interesting bookkeeping is ``effective_depth``. Conventional sandboxing
treats a breach as decrementing a counter toward zero. Hydra converts the
breached layer into a sealed tombstone and materialises a fresh layer *outside*
the attacker's position, so:

    live_layers        -- constant across a breach transition
    tombstones         -- strictly increasing
    effective_depth    -- live_layers + tombstones, strictly increasing

That last quantity is the treadmill made measurable, and ``assert_invariants``
refuses to let it go backwards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..backends import DomainHandle, DomainSpec
from ..identity import DomainIdentity
from ..measurement import Measurement
from ..quote import AttestationQuote
from ..telemetry import EventLog, NULL_LOG


class ContainmentInvariantError(Exception):
    pass


@dataclass
class Layer:
    handle: DomainHandle
    identity: DomainIdentity
    measurement: Measurement
    spec: DomainSpec
    depth: int
    born_at: float
    sealed: bool = False
    seal_reason: str = ""
    last_quote: Optional[AttestationQuote] = None
    consecutive_failures: int = 0

    @property
    def label(self) -> str:
        return f"L{self.depth}/{self.identity.role}#g{self.identity.generation}"

    def summary(self) -> Dict[str, Any]:
        return {
            "depth": self.depth,
            "role": self.identity.role,
            "generation": self.identity.generation,
            "domain": self.identity.short,
            "hw": self.identity.hw_serial[:20],
            "mr": self.measurement.short,
            "state": "sealed" if self.sealed else "live",
        }


class ContainmentPlane:
    def __init__(self, log: Optional[EventLog] = None):
        self.log = log or NULL_LOG
        self.layers: List[Layer] = []          # outermost -> innermost
        self.tombstones: List[Layer] = []
        self._max_effective_depth = 0

    # -- structure ----------------------------------------------------------
    @property
    def live_depth(self) -> int:
        return len(self.layers)

    @property
    def effective_depth(self) -> int:
        return len(self.layers) + len(self.tombstones)

    def innermost(self) -> Optional[Layer]:
        return self.layers[-1] if self.layers else None

    def outermost(self) -> Optional[Layer]:
        return self.layers[0] if self.layers else None

    def find(self, domain_id: str) -> Optional[Layer]:
        for layer in self.layers:
            if layer.identity.domain_id == domain_id:
                return layer
        return None

    def index_of(self, layer: Layer) -> int:
        return self.layers.index(layer)

    # -- mutation -----------------------------------------------------------
    def append_inner(self, layer: Layer) -> Layer:
        self.layers.append(layer)
        self._renumber()
        return layer

    def push_outer(self, layer: Layer) -> Layer:
        """Materialise a new outermost wall. The outside moves away."""
        self.layers.insert(0, layer)
        self._renumber()
        self.log.emit(
            "containment",
            "outer_wall_materialised",
            {"live_depth": self.live_depth, "effective_depth": self.effective_depth},
            domain_id=layer.identity.domain_id,
        )
        return layer

    def entomb(self, layer: Layer, reason: str) -> Layer:
        """Remove a breached layer from the live stack and seal it forever."""
        if layer in self.layers:
            self.layers.remove(layer)
        layer.sealed = True
        layer.seal_reason = reason
        self.tombstones.append(layer)
        self._renumber()
        self.log.emit(
            "containment",
            "layer_entombed",
            {"reason": reason[:90], "tombstones": len(self.tombstones)},
            domain_id=layer.identity.domain_id,
            severity="warn",
        )
        return layer

    def _renumber(self) -> None:
        for i, layer in enumerate(self.layers):
            layer.depth = i
            layer.handle.depth = i

    # -- invariants ---------------------------------------------------------
    def assert_invariants(self, min_live_depth: int) -> None:
        eff = self.effective_depth
        if eff < self._max_effective_depth:
            raise ContainmentInvariantError(
                f"effective depth regressed: {eff} < {self._max_effective_depth}"
            )
        self._max_effective_depth = max(self._max_effective_depth, eff)

        if self.live_depth < min_live_depth:
            raise ContainmentInvariantError(
                f"live depth {self.live_depth} below configured floor {min_live_depth}"
            )
        for t in self.tombstones:
            if not t.sealed:
                raise ContainmentInvariantError("tombstone is not sealed")
            if t in self.layers:
                raise ContainmentInvariantError("tombstone reinserted into live stack")
        ids = [l.identity.domain_id for l in self.layers]
        if len(set(ids)) != len(ids):
            raise ContainmentInvariantError("duplicate domain identity in live stack")

    def status(self) -> Dict[str, Any]:
        return {
            "live_depth": self.live_depth,
            "tombstones": len(self.tombstones),
            "effective_depth": self.effective_depth,
            "layers": [l.summary() for l in self.layers],
            "sealed": [t.summary() for t in self.tombstones],
        }
