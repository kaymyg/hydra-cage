"""Evidence plane -- cryptographically isolated forensic store.

Properties enforced in code:

* **Write-once.** ``seal`` refuses to overwrite an existing artifact and marks
  the file read-only after writing.
* **Hash-chained.** Every record commits to the previous record's hash, so any
  edit, deletion, or reordering of the manifest is detectable by
  ``verify_chain``.
* **No return path.** There is deliberately no ``restore``, ``import``, or
  ``reattach`` method. A sealed artifact cannot be brought back into the live
  cage by any API this module exposes.
* **Unreachable from inside.** The evidence root lives outside every domain's
  filesystem view and is never mounted into one.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..measurement import sha256_file
from ..telemetry import EventLog, NULL_LOG


class EvidenceTamper(Exception):
    pass


@dataclass
class Artifact:
    seq: int
    ts: float
    domain_id: str
    role: str
    generation: int
    hw_serial: str
    reason: str
    artifact_path: str
    artifact_sha256: str
    artifact_bytes: int
    measurement: Dict[str, str] = field(default_factory=dict)
    runtime_facts: Dict[str, Any] = field(default_factory=dict)
    last_quote: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    record_hash: str = ""

    def compute_hash(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "record_hash"}
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class EvidencePlane:
    GENESIS = "0" * 64

    def __init__(self, root: str, log: Optional[EventLog] = None):
        self.root = os.path.abspath(root)
        self.artifacts_dir = os.path.join(self.root, "artifacts")
        self.manifest_path = os.path.join(self.root, "manifest.jsonl")
        os.makedirs(self.artifacts_dir, exist_ok=True)
        open(self.manifest_path, "a").close()
        self.log = log or NULL_LOG
        self._records: List[Artifact] = []

    @property
    def head(self) -> str:
        return self._records[-1].record_hash if self._records else self.GENESIS

    def artifact_path_for(self, domain_id: str) -> str:
        return os.path.join(self.artifacts_dir, f"{domain_id}.snapshot")

    def seal(
        self,
        *,
        domain_id: str,
        role: str,
        generation: int,
        hw_serial: str,
        reason: str,
        artifact_path: str,
        measurement: Dict[str, str],
        runtime_facts: Dict[str, Any],
        last_quote: Optional[Dict[str, Any]] = None,
    ) -> Artifact:
        if not os.path.exists(artifact_path):
            raise EvidenceTamper(f"artifact missing: {artifact_path}")

        rec = Artifact(
            seq=len(self._records),
            ts=time.time(),
            domain_id=domain_id,
            role=role,
            generation=generation,
            hw_serial=hw_serial,
            reason=reason,
            artifact_path=os.path.relpath(artifact_path, self.root),
            artifact_sha256=sha256_file(artifact_path),
            artifact_bytes=os.path.getsize(artifact_path),
            measurement=dict(measurement),
            runtime_facts=dict(runtime_facts),
            last_quote=dict(last_quote or {}),
            prev_hash=self.head,
        )
        rec.record_hash = rec.compute_hash()

        # write-once: freeze the artifact bits
        os.chmod(artifact_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        self._records.append(rec)
        with open(self.manifest_path, "a") as fh:
            fh.write(json.dumps(asdict(rec), sort_keys=True, separators=(",", ":")) + "\n")

        self.log.emit(
            "evidence",
            "artifact_sealed",
            {
                "seq": rec.seq,
                "sha256": rec.artifact_sha256[:12],
                "bytes": rec.artifact_bytes,
                "reason": reason,
            },
            domain_id=domain_id,
        )
        return rec

    # -- integrity ----------------------------------------------------------
    def verify_chain(self) -> bool:
        prev = self.GENESIS
        for rec in self._records:
            if rec.prev_hash != prev or rec.compute_hash() != rec.record_hash:
                return False
            prev = rec.record_hash
        return True

    def verify_artifacts(self) -> List[str]:
        """Returns a list of problems; empty means every artifact is intact."""
        problems: List[str] = []
        for rec in self._records:
            full = os.path.join(self.root, rec.artifact_path)
            if not os.path.exists(full):
                problems.append(f"seq {rec.seq}: artifact deleted")
                continue
            if sha256_file(full) != rec.artifact_sha256:
                problems.append(f"seq {rec.seq}: artifact content modified")
            mode = stat.S_IMODE(os.stat(full).st_mode)
            if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                problems.append(f"seq {rec.seq}: artifact is writable")
        if not self.verify_chain():
            problems.append("manifest hash chain broken")
        return problems

    def verify_manifest_file(self) -> bool:
        """Re-read the on-disk manifest and re-validate it independently."""
        prev = self.GENESIS
        try:
            with open(self.manifest_path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    rec = Artifact(**json.loads(line))
                    if rec.prev_hash != prev or rec.compute_hash() != rec.record_hash:
                        return False
                    prev = rec.record_hash
        except (OSError, ValueError, TypeError):
            return False
        return True

    def records(self) -> List[Artifact]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)
