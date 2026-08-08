"""Execution plane -- the only plane the AI is allowed to touch.

The whole point of this class is what it does *not* have. It holds a backend
reference and a layer, and exposes two verbs: submit work, read the result.
There is no attribute path from an ``ExecutionPlane`` instance to the
attestation, regeneration, evidence, or policy planes, and ``audit_reachability``
proves that by walking the object graph at runtime.

If you extend this class, the reachability test in the suite will fail the
moment you give it a handle to a control plane. That failure is the feature.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set

from ..backends import DomainHandle, IsolationBackend
from ..telemetry import EventLog, NULL_LOG

FORBIDDEN_TYPES = {
    "AttestationPlane",
    "RegenerationPlane",
    "EvidencePlane",
    "PolicyEngine",
    "KeyVault",
    "RevocationLedger",
    "RegenerationAuthority",
    "GoldenRegistry",
    "HydraCage",
}

AGENT_PATH = "/hydra/payload/agent.py"


class ExecutionPlane:
    """A constrained façade over one execution domain."""

    __slots__ = ("_backend", "_handle", "_log", "_submissions")

    def __init__(self, backend: IsolationBackend, handle: DomainHandle, log: Optional[EventLog] = None):
        self._backend = backend
        self._handle = handle
        self._log = log or NULL_LOG
        self._submissions = 0

    # -- the entire AI-facing API -------------------------------------------
    def submit(self, task: str, timeout: float = 10.0) -> Dict[str, Any]:
        self._submissions += 1
        rc, out, err = self._backend.exec_in(
            self._handle, ["python3", AGENT_PATH, task], timeout=timeout
        )
        self._log.emit(
            "execution",
            "task_submitted",
            {"rc": rc, "task": task[:40]},
            domain_id=self._handle.domain_id,
        )
        if rc != 0:
            return {"ok": False, "error": (err or "")[:400]}
        try:
            return {"ok": True, "result": json.loads(out)}
        except ValueError:
            return {"ok": True, "result": out[:2000]}

    @property
    def domain_id(self) -> str:
        return self._handle.domain_id

    @property
    def submissions(self) -> int:
        return self._submissions

    def capability_surface(self) -> List[str]:
        return ["submit", "domain_id", "submissions", "capability_surface"]

    # -- structural proof ---------------------------------------------------
    def audit_reachability(self, max_nodes: int = 5000) -> List[str]:
        """Walk everything reachable from this object; report control-plane leaks."""
        found: List[str] = []
        seen: Set[int] = set()
        stack: List[Any] = [getattr(self, s) for s in self.__slots__]
        nodes = 0
        while stack and nodes < max_nodes:
            obj = stack.pop()
            nodes += 1
            if id(obj) in seen:
                continue
            seen.add(id(obj))
            name = type(obj).__name__
            if name in FORBIDDEN_TYPES:
                found.append(name)
                continue
            if isinstance(obj, (str, bytes, int, float, bool, type(None))):
                continue
            if isinstance(obj, dict):
                stack.extend(list(obj.keys())[:200])
                stack.extend(list(obj.values())[:200])
                continue
            if isinstance(obj, (list, tuple, set, frozenset)):
                stack.extend(list(obj)[:200])
                continue
            slots = getattr(type(obj), "__slots__", ())
            for s in slots:
                try:
                    stack.append(getattr(obj, s))
                except AttributeError:
                    pass
            d = getattr(obj, "__dict__", None)
            if isinstance(d, dict):
                stack.extend(list(d.values())[:200])
        return sorted(set(found))
