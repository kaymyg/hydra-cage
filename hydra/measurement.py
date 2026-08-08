"""Measurement registers -- the software analogue of TPM PCRs.

A *measurement* is a set of named registers describing the boot chain and
static configuration of an execution domain. The combined root ``mr`` is what
the policy engine compares against the golden-image registry.

Critical property: every register in a trusted measurement is computed by the
supervisor from artifacts it can read *without asking the domain*. A domain's
own claim about its state is carried separately as ``self_report`` and is
always treated as untrusted input.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Dict, Optional

REGISTER_ORDER = [
    "firmware",       # backend / launcher build
    "image",          # rootfs or container image digest
    "kernel",         # kernel or runtime identity
    "entrypoint",     # hash of the code that will run
    "config",         # hash of the launch configuration
    "policy",         # hash of the policy bundle in force
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_tree(root: str, skip: Optional[set] = None) -> str:
    """Deterministic hash of a directory tree (path + content)."""
    skip = skip or set()
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for name in sorted(filenames):
            if name in skip:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            h.update(rel.encode())
            h.update(b"\0")
            try:
                h.update(sha256_file(full).encode())
            except OSError:
                h.update(b"UNREADABLE")
            h.update(b"\n")
    return h.hexdigest()


def sha256_obj(obj) -> str:
    return sha256_bytes(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode())


SKIP_NAMES = {"__pycache__", ".pyc"}


def canonical_manifest(pairs) -> str:
    """Fold ``(relpath, content_sha256)`` pairs into one digest.

    Deliberately shared between the supervisor (which reads a domain's payload
    from outside, through the container runtime) and the domain's own
    responder (which reads it from inside). Same input, same digest -- so a
    disagreement between the two is unambiguous evidence of a lie rather than
    a hashing artefact.
    """
    items = sorted((p.strip("/"), d) for p, d in pairs)
    h = hashlib.sha256()
    h.update(b"hydra-manifest-v1\n")
    for path, digest in items:
        h.update(path.encode() + b"\0" + digest.encode() + b"\n")
    return h.hexdigest()


def manifest_from_dir(root: str) -> str:
    pairs = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in filenames:
            if name.endswith(".pyc"):
                continue
            full = os.path.join(dirpath, name)
            try:
                pairs.append((os.path.relpath(full, root), sha256_file(full)))
            except OSError:
                pairs.append((os.path.relpath(full, root), "UNREADABLE"))
    return canonical_manifest(pairs)


@dataclass(frozen=True)
class Measurement:
    registers: Dict[str, str] = field(default_factory=dict)

    @property
    def mr(self) -> str:
        """Measurement root: order-independent fold of all registers."""
        parts = []
        for name in REGISTER_ORDER:
            parts.append(f"{name}={self.registers.get(name, 'UNSET')}")
        for name in sorted(k for k in self.registers if k not in REGISTER_ORDER):
            parts.append(f"{name}={self.registers[name]}")
        return sha256_bytes("|".join(parts).encode())

    @property
    def short(self) -> str:
        return self.mr[:12]

    def diff(self, other: "Measurement") -> Dict[str, tuple]:
        keys = set(self.registers) | set(other.registers)
        return {
            k: (self.registers.get(k), other.registers.get(k))
            for k in sorted(keys)
            if self.registers.get(k) != other.registers.get(k)
        }

    def to_dict(self) -> Dict[str, str]:
        return dict(self.registers)


class GoldenRegistry:
    """Approved measurement roots, keyed by layer role.

    The registry is signed material in a real deployment; here it is host-side
    memory that no execution domain has a handle to. Entries are only ever
    added by the supervisor at boot from known-good images.
    """

    def __init__(self):
        self._approved: Dict[str, set] = {}
        self._detail: Dict[str, Measurement] = {}

    def approve(self, role: str, measurement: Measurement) -> str:
        self._approved.setdefault(role, set()).add(measurement.mr)
        self._detail[measurement.mr] = measurement
        return measurement.mr

    def is_approved(self, role: str, mr: str) -> bool:
        return mr in self._approved.get(role, set())

    def known(self, mr: str) -> Optional[Measurement]:
        return self._detail.get(mr)

    def roles(self):
        return sorted(self._approved)
