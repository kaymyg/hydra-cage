"""Isolation backends -- the containment plane's actual muscle.

Two implementations:

``DockerBackend``   Real container orchestration. Each layer is a separate
                    container on its own bridge network, with all capabilities
                    dropped, no new privileges, no docker socket, and a
                    read-only payload mount. Freeze is ``docker pause``, sever
                    is ``docker network disconnect``, preserve is
                    ``docker export``. The supervisor talks to the daemon; the
                    containers cannot.

``ProcessBackend``  Portable fallback for machines without Docker. Each layer
                    is a process group in its own directory. Freeze is
                    SIGSTOP, sever revokes the domain's socket directory,
                    preserve is a tar snapshot. Weaker isolation, identical
                    trust topology -- which is what the demo is about.

``MemoryBackend``   For environments with no processes at all, such as Pyodide
                    in a browser. Domains are registry entries and their code
                    is exec'd in-process under a watchdog. Demonstrates the
                    trust protocol; provides no enforcement. See its docstring.

The contract that matters for both: ``hw_facts()`` is answered by the
*supervisor* querying the runtime (the Docker daemon, or ``/proc``). It never
asks the domain. That is the origin proof the whole architecture rests on.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .measurement import (
    Measurement,
    canonical_manifest,
    manifest_from_dir,
    sha256_bytes,
    sha256_obj,
)


class BackendError(RuntimeError):
    pass


@dataclass
class DomainSpec:
    role: str
    depth: int
    payload_dir: str                     # host dir with the layer's code
    policy_hash: str
    image: str = "hydra-layer:latest"
    memory_mb: int = 256
    pids_limit: int = 128
    cpus: str = "0.5"
    env: Dict[str, str] = field(default_factory=dict)


@dataclass
class DomainHandle:
    domain_id: str
    hw_serial: str
    role: str
    depth: int
    backend: str
    native_id: str                       # container id / pid
    workdir: str
    network: Optional[str] = None
    severed: bool = False
    frozen: bool = False
    destroyed: bool = False
    meta: Dict[str, Any] = field(default_factory=dict)


class IsolationBackend:
    name = "abstract"

    # -- lifecycle ----------------------------------------------------------
    def create(self, domain_id: str, spec: DomainSpec) -> DomainHandle:
        raise NotImplementedError

    def destroy(self, h: DomainHandle) -> None:
        raise NotImplementedError

    # -- observation (supervisor-sourced; never asks the domain) ------------
    def hw_facts(self, h: DomainHandle) -> Dict[str, Any]:
        raise NotImplementedError

    def measure(self, h: DomainHandle, spec_policy_hash: str) -> Measurement:
        raise NotImplementedError

    def alive(self, h: DomainHandle) -> bool:
        raise NotImplementedError

    # -- containment actions ------------------------------------------------
    def freeze(self, h: DomainHandle) -> None:
        raise NotImplementedError

    def sever(self, h: DomainHandle) -> None:
        raise NotImplementedError

    def snapshot(self, h: DomainHandle, dest_path: str) -> Dict[str, Any]:
        raise NotImplementedError

    # -- interaction --------------------------------------------------------
    def exec_in(self, h: DomainHandle, argv: List[str], timeout: float = 10.0) -> Tuple[int, str, str]:
        raise NotImplementedError

    def read_file(self, h: DomainHandle, relpath: str) -> bytes:
        """Supervisor-side read of domain state, via the runtime."""
        raise NotImplementedError

    def write_file(self, h: DomainHandle, relpath: str, data: bytes) -> None:
        """Used by the adversary harness to simulate in-domain compromise."""
        raise NotImplementedError

    def delete_file(self, h: DomainHandle, relpath: str) -> None:
        raise NotImplementedError

    def scan_for_secret(self, h: DomainHandle) -> List[bytes]:
        """Everything a domain could plausibly read, for leak checks."""
        raise NotImplementedError

    def preflight(self) -> None:
        return None


# --------------------------------------------------------------------------
# Docker
# --------------------------------------------------------------------------
def _run(argv: List[str], timeout: float = 60.0, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise BackendError(f"{' '.join(argv[:3])}... failed rc={p.returncode}: {p.stderr.strip()}")
    return p


class DockerBackend(IsolationBackend):
    name = "docker"

    def __init__(self, root: str, image: str = "hydra-layer:latest", net_prefix: str = "hydra"):
        self.root = os.path.abspath(root)
        self.image = image
        self.net_prefix = net_prefix
        os.makedirs(self.root, exist_ok=True)
        self._daemon_fingerprint: Optional[str] = None

    # -- preflight ----------------------------------------------------------
    def preflight(self) -> None:
        if shutil.which("docker") is None:
            raise BackendError("docker binary not found on PATH")
        p = _run(["docker", "version", "--format", "{{json .}}"], check=False)
        if p.returncode != 0:
            raise BackendError("docker daemon is not reachable: " + p.stderr.strip())
        self._daemon_fingerprint = sha256_bytes(p.stdout.encode())
        p = _run(["docker", "image", "inspect", self.image], check=False)
        if p.returncode != 0:
            raise BackendError(
                f"image {self.image} not built. Run: make image  (or "
                f"docker build -t {self.image} docker/)"
            )

    @property
    def firmware_measure(self) -> str:
        return self._daemon_fingerprint or "unmeasured-daemon"

    # -- lifecycle ----------------------------------------------------------
    def create(self, domain_id: str, spec: DomainSpec) -> DomainHandle:
        short = domain_id[:10]
        name = f"{self.net_prefix}-{spec.role}-{short}"
        net = f"{self.net_prefix}-net-{short}"
        workdir = os.path.join(self.root, domain_id)
        os.makedirs(os.path.join(workdir, "state"), exist_ok=True)

        # per-domain payload copy: the container gets a read-only mount of it,
        # the supervisor keeps the authoritative copy outside.
        payload = os.path.join(workdir, "payload")
        shutil.copytree(spec.payload_dir, payload)

        _run(["docker", "network", "create", "--internal", net])

        argv = [
            "docker", "run", "-d",
            "--name", name,
            "--network", net,
            "--hostname", f"layer{spec.depth}",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(spec.pids_limit),
            "--memory", f"{spec.memory_mb}m",
            "--cpus", spec.cpus,
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
            "-v", f"{payload}:/hydra/payload:ro",
            "-v", f"{os.path.join(workdir, 'state')}:/hydra/state:rw",
            "-e", f"HYDRA_ROLE={spec.role}",
            "-e", f"HYDRA_DEPTH={spec.depth}",
        ]
        for k, v in spec.env.items():
            argv += ["-e", f"{k}={v}"]
        argv += [spec.image or self.image, "python3", "/hydra/payload/layer_entrypoint.py"]

        cid = _run(argv).stdout.strip()
        inspect = self._inspect(cid)

        return DomainHandle(
            domain_id=domain_id,
            hw_serial=inspect["Id"],           # daemon-assigned, unforgeable inside
            role=spec.role,
            depth=spec.depth,
            backend=self.name,
            native_id=cid,
            workdir=workdir,
            network=net,
            meta={"name": name, "image": spec.image or self.image},
        )

    def destroy(self, h: DomainHandle) -> None:
        _run(["docker", "rm", "-f", h.native_id], check=False)
        if h.network:
            _run(["docker", "network", "rm", h.network], check=False)
        h.destroyed = True

    # -- observation --------------------------------------------------------
    def _inspect(self, cid: str) -> Dict[str, Any]:
        p = _run(["docker", "inspect", cid], check=False)
        if p.returncode != 0:
            return {}
        data = json.loads(p.stdout)
        return data[0] if data else {}

    def hw_facts(self, h: DomainHandle) -> Dict[str, Any]:
        ins = self._inspect(h.native_id)
        if not ins:
            return {"alive": False, "hw_serial": h.hw_serial, "source": "docker-daemon"}
        state = ins.get("State", {})
        return {
            "source": "docker-daemon",
            "hw_serial": ins.get("Id", ""),
            "alive": bool(state.get("Running")) and not state.get("Paused"),
            "paused": bool(state.get("Paused")),
            "started_at": state.get("StartedAt"),
            "image_digest": ins.get("Image", ""),
            "networks": sorted((ins.get("NetworkSettings", {}).get("Networks") or {}).keys()),
            "pid": state.get("Pid"),
            "read_only": ins.get("HostConfig", {}).get("ReadonlyRootfs"),
            "cap_drop": ins.get("HostConfig", {}).get("CapDrop"),
            "privileged": ins.get("HostConfig", {}).get("Privileged"),
        }

    def measure(self, h: DomainHandle, spec_policy_hash: str) -> Measurement:
        ins = self._inspect(h.native_id)
        # Placement facts (depth) are excluded: where a layer sits in the stack
        # is not part of its boot chain, and moving outward must not look like
        # tampering.
        env = sorted(
            e for e in (ins.get("Config", {}).get("Env") or [])
            if not e.startswith("HYDRA_DEPTH=")
        )
        cfg = {
            "Cmd": ins.get("Config", {}).get("Cmd"),
            "Entrypoint": ins.get("Config", {}).get("Entrypoint"),
            "Env": env,
            "HostConfig": {
                k: ins.get("HostConfig", {}).get(k)
                for k in ("CapDrop", "Privileged", "ReadonlyRootfs", "PidsLimit", "Memory")
            },
        }
        # Entrypoint register is read *through the daemon* from the container
        # filesystem, not reported by the process inside it.
        payload_hash = self._hash_container_path(h, "/hydra/payload")
        return Measurement(
            registers={
                "firmware": self.firmware_measure,
                "image": ins.get("Image", "MISSING"),
                "kernel": sha256_bytes(str(ins.get("Driver", "")).encode()),
                "entrypoint": payload_hash,
                "config": sha256_obj(cfg),
                "policy": spec_policy_hash,
            }
        )

    def _hash_container_path(self, h: DomainHandle, path: str) -> str:
        """docker cp the path out and hash it. The container cannot intercept.

        This is the origin-independent read: the tar stream is produced by the
        daemon from the container's filesystem layer, so code running inside
        has no opportunity to substitute what the supervisor sees.
        """
        import io

        p = subprocess.run(
            ["docker", "cp", "-a", f"{h.native_id}:{path}", "-"],
            capture_output=True,
            timeout=60,
        )
        if p.returncode != 0:
            return "UNREADABLE"
        entries = []
        try:
            with tarfile.open(fileobj=io.BytesIO(p.stdout), mode="r|") as tf:
                for member in tf:
                    if not member.isfile():
                        continue
                    name = member.name.split("/", 1)[1] if "/" in member.name else member.name
                    if "__pycache__" in name or name.endswith(".pyc"):
                        continue
                    fh = tf.extractfile(member)
                    entries.append((name, sha256_bytes(fh.read() if fh else b"")))
        except tarfile.TarError:
            return "UNREADABLE"
        return canonical_manifest(entries)

    def alive(self, h: DomainHandle) -> bool:
        return bool(self.hw_facts(h).get("alive"))

    # -- containment --------------------------------------------------------
    def freeze(self, h: DomainHandle) -> None:
        _run(["docker", "pause", h.native_id], check=False)
        h.frozen = True

    def sever(self, h: DomainHandle) -> None:
        if h.network:
            _run(["docker", "network", "disconnect", "-f", h.network, h.native_id], check=False)
        h.severed = True

    def snapshot(self, h: DomainHandle, dest_path: str) -> Dict[str, Any]:
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, "wb") as fh:
            p = subprocess.run(["docker", "export", h.native_id], stdout=fh, stderr=subprocess.PIPE, timeout=300)
        if p.returncode != 0:
            raise BackendError("docker export failed: " + p.stderr.decode())
        return {
            "kind": "docker-export",
            "inspect": self._inspect(h.native_id),
            "bytes": os.path.getsize(dest_path),
        }

    # -- interaction --------------------------------------------------------
    def exec_in(self, h: DomainHandle, argv: List[str], timeout: float = 10.0) -> Tuple[int, str, str]:
        try:
            p = subprocess.run(
                ["docker", "exec", h.native_id] + argv,
                capture_output=True, text=True, timeout=timeout,
            )
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"

    def read_file(self, h: DomainHandle, relpath: str) -> bytes:
        rc, out, _ = self.exec_in(h, ["cat", relpath])
        return out.encode() if rc == 0 else b""

    def write_file(self, h: DomainHandle, relpath: str, data: bytes) -> None:
        """Adversary harness only: simulate in-domain compromise.

        The payload is mounted ``:ro``, so a container process genuinely
        cannot do this -- that read-only mount is a real preventive control.
        The harness writes through the host side of the bind mount instead,
        because the point of the exercise is to test *detection*, not to
        pretend prevention failed for free.
        """
        if relpath.startswith("/hydra/payload"):
            local = os.path.join(
                h.workdir, "payload", relpath[len("/hydra/payload"):].lstrip("/")
            )
            os.makedirs(os.path.dirname(local), exist_ok=True)
            with open(local, "wb") as fh:
                fh.write(data)
            return
        local = os.path.join(h.workdir, "state", os.path.basename(relpath))
        with open(local, "wb") as fh:
            fh.write(data)
        p = subprocess.run(
            ["docker", "cp", local, f"{h.native_id}:{relpath}"],
            capture_output=True, timeout=30,
        )
        if p.returncode != 0:
            raise BackendError("write into domain failed: " + p.stderr.decode())

    def delete_file(self, h: DomainHandle, relpath: str) -> None:
        if relpath.startswith("/hydra/payload"):
            local = os.path.join(
                h.workdir, "payload", relpath[len("/hydra/payload"):].lstrip("/")
            )
            if os.path.exists(local):
                os.remove(local)
            return
        self.exec_in(h, ["rm", "-f", relpath])

    def scan_for_secret(self, h: DomainHandle) -> List[bytes]:
        blobs: List[bytes] = []
        rc, out, _ = self.exec_in(h, ["/bin/sh", "-c", "env"])
        if rc == 0:
            blobs.append(out.encode())
        rc, out, _ = self.exec_in(
            h, ["/bin/sh", "-c", "find / -xdev -type f -readable 2>/dev/null | head -400 | xargs -r cat 2>/dev/null | head -c 400000"]
        )
        if rc == 0:
            blobs.append(out.encode())
        return blobs


# --------------------------------------------------------------------------
# Process (portable fallback)
# --------------------------------------------------------------------------
IDLE_LOOP = (
    "import os,sys,time,signal\n"
    "open(os.path.join(sys.argv[1],'alive'),'w').write(str(os.getpid()))\n"
    "signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))\n"
    "while True: time.sleep(0.2)\n"
)


class ProcessBackend(IsolationBackend):
    name = "process"

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self._fw = sha256_bytes(f"process-backend/{sys.version}".encode())

    def preflight(self) -> None:
        return None

    @property
    def firmware_measure(self) -> str:
        return self._fw

    def _proc_start_time(self, pid: int) -> Optional[str]:
        """Kernel-sourced. A process cannot rewrite its own /proc stat."""
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                fields = fh.read().rsplit(b")", 1)[1].split()
            return fields[19].decode()  # starttime, field 22
        except (OSError, IndexError):
            return None

    def create(self, domain_id: str, spec: DomainSpec) -> DomainHandle:
        workdir = os.path.join(self.root, domain_id)
        payload = os.path.join(workdir, "payload")
        state = os.path.join(workdir, "state")
        link = os.path.join(workdir, "uplink")
        os.makedirs(state, exist_ok=True)
        os.makedirs(link, exist_ok=True)
        shutil.copytree(spec.payload_dir, payload)

        env = dict(os.environ)
        env.update(
            {
                "HYDRA_ROLE": spec.role,
                "HYDRA_DEPTH": str(spec.depth),
                "HYDRA_STATE": state,
                **spec.env,
            }
        )
        # Deliberately minimal: no supervisor paths, no capability tokens.
        for k in list(env):
            if k.startswith("HYDRA_REGEN") or k.startswith("HYDRA_ROOT"):
                del env[k]

        proc = subprocess.Popen(
            [sys.executable, "-c", IDLE_LOOP, state],
            cwd=payload,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.05)
        start = self._proc_start_time(proc.pid) or uuid.uuid4().hex
        return DomainHandle(
            domain_id=domain_id,
            hw_serial=f"pid{proc.pid}.start{start}",
            role=spec.role,
            depth=spec.depth,
            backend=self.name,
            native_id=str(proc.pid),
            workdir=workdir,
            network=link,
            meta={"proc": proc},
        )

    def destroy(self, h: DomainHandle) -> None:
        pid = int(h.native_id)
        for sig in (signal.SIGCONT, signal.SIGKILL):
            try:
                os.killpg(os.getpgid(pid), sig)
            except (ProcessLookupError, PermissionError):
                pass
        proc = h.meta.get("proc")
        if proc is not None:
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        shutil.rmtree(h.workdir, ignore_errors=True)
        h.destroyed = True

    def hw_facts(self, h: DomainHandle) -> Dict[str, Any]:
        pid = int(h.native_id)
        start = self._proc_start_time(pid)
        serial = f"pid{pid}.start{start}" if start else None
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                state_char = fh.read().rsplit(b")", 1)[1].split()[0].decode()
        except (OSError, IndexError):
            state_char = "X"
        return {
            "source": "kernel:/proc",
            "hw_serial": serial or h.hw_serial,
            "alive": serial == h.hw_serial and state_char not in ("X", "Z", "T"),
            "paused": state_char == "T",
            "pid": pid,
            "proc_state": state_char,
            "networks": [] if h.severed else [os.path.basename(h.network or "")],
            "privileged": False,
        }

    def measure(self, h: DomainHandle, spec_policy_hash: str) -> Measurement:
        payload = os.path.join(h.workdir, "payload")
        # Placement (depth) and connectivity (severed) are excluded on purpose:
        # they change when a layer legitimately moves, and are not boot chain.
        cfg = {"role": h.role, "backend": self.name}
        return Measurement(
            registers={
                "firmware": self._fw,
                "image": sha256_bytes(b"process-rootfs-v1"),
                "kernel": sha256_bytes(platform.release().encode()),
                # supervisor reads the payload directly from the host fs
                "entrypoint": manifest_from_dir(payload),
                "config": sha256_obj(cfg),
                "policy": spec_policy_hash,
            }
        )

    def alive(self, h: DomainHandle) -> bool:
        return bool(self.hw_facts(h).get("alive"))

    def freeze(self, h: DomainHandle) -> None:
        try:
            os.killpg(os.getpgid(int(h.native_id)), signal.SIGSTOP)
        except (ProcessLookupError, PermissionError):
            h.frozen = True
            return
        # Freeze must be observed, not assumed: poll the kernel until the
        # domain is actually stopped before the transition proceeds.
        deadline = time.time() + 1.0
        while time.time() < deadline:
            if self.hw_facts(h).get("paused"):
                break
            time.sleep(0.01)
        h.frozen = True

    def sever(self, h: DomainHandle) -> None:
        if h.network and os.path.isdir(h.network):
            shutil.rmtree(h.network, ignore_errors=True)
        h.severed = True

    def snapshot(self, h: DomainHandle, dest_path: str) -> Dict[str, Any]:
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with tarfile.open(dest_path, "w:gz") as tf:
            tf.add(h.workdir, arcname=os.path.basename(h.workdir))
        return {
            "kind": "process-tar",
            "inspect": self.hw_facts(h),
            "bytes": os.path.getsize(dest_path),
        }

    def exec_in(self, h: DomainHandle, argv: List[str], timeout: float = 10.0) -> Tuple[int, str, str]:
        payload = os.path.join(h.workdir, "payload")
        if h.frozen:
            return 125, "", "domain frozen"
        # Translate container-absolute paths onto the domain's directory.
        argv = [a.replace("/hydra/payload", payload).replace("/hydra/state", os.path.join(h.workdir, "state")) for a in argv]
        try:
            p = subprocess.run(
                argv, cwd=payload, capture_output=True, text=True, timeout=timeout,
                env={**os.environ, "HYDRA_ROLE": h.role, "HYDRA_DEPTH": str(h.depth)},
            )
            return p.returncode, p.stdout, p.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            return 124, "", str(exc)

    def _local(self, h: DomainHandle, relpath: str) -> str:
        rel = relpath.replace("/hydra/payload", "payload").replace("/hydra/state", "state")
        return os.path.join(h.workdir, rel.lstrip("/"))

    def read_file(self, h: DomainHandle, relpath: str) -> bytes:
        try:
            with open(self._local(h, relpath), "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def write_file(self, h: DomainHandle, relpath: str, data: bytes) -> None:
        path = self._local(h, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)

    def delete_file(self, h: DomainHandle, relpath: str) -> None:
        path = self._local(h, relpath)
        if os.path.exists(path):
            os.remove(path)

    def scan_for_secret(self, h: DomainHandle) -> List[bytes]:
        blobs: List[bytes] = []
        for dirpath, _dirs, files in os.walk(h.workdir):
            for name in files:
                try:
                    with open(os.path.join(dirpath, name), "rb") as fh:
                        blobs.append(fh.read(200000))
                except OSError:
                    pass
        try:
            with open(f"/proc/{h.native_id}/environ", "rb") as fh:
                blobs.append(fh.read())
        except OSError:
            pass
        return blobs


# --------------------------------------------------------------------------
# Memory (in-process; runs under Pyodide in a browser)
# --------------------------------------------------------------------------
class DomainStopped(Exception):
    """Raised inside a domain when its execution budget or freeze flag hits."""


class MemoryBackend(IsolationBackend):
    """In-process domains, for environments with no processes at all.

    Pyodide gives us a real (virtual) filesystem but no ``subprocess``, no
    ``/proc``, no signals. So this backend keeps the filesystem half of
    ``ProcessBackend`` verbatim -- payload copies, ``manifest_from_dir``
    measurement, tar snapshots -- and replaces only the process half:

        process spawn   ->  a supervisor-held registry entry
        /proc stat      ->  that registry
        SIGSTOP         ->  a frozen flag the exec path honours
        subprocess.run  ->  exec() of the domain's own source, with a budget

    **Be clear about what this does and does not demonstrate.** The domain's
    code runs in the same interpreter as the supervisor. There is no memory
    protection, no privilege boundary, and a determined payload could reach
    the supervisor's objects through the interpreter itself. What survives
    intact is the *trust protocol*: the domain is still never asked what its
    measurement is, hw_serial still comes from a registry the domain has no
    handle to, and every law, quote check and transition stage behaves exactly
    as it does on real containers. This backend demonstrates the topology, not
    the enforcement. Use DockerBackend for the enforcement.
    """

    name = "memory"

    def __init__(self, root: str, exec_line_budget: int = 400_000):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.exec_line_budget = exec_line_budget
        self._fw = sha256_bytes(f"memory-backend/{sys.version}".encode())
        # The supervisor's private view. Domains get no reference to this.
        self._registry: Dict[str, Dict[str, Any]] = {}
        self._counter = 0

    def preflight(self) -> None:
        return None

    @property
    def firmware_measure(self) -> str:
        return self._fw

    # -- lifecycle ----------------------------------------------------------
    def create(self, domain_id: str, spec: DomainSpec) -> DomainHandle:
        workdir = os.path.join(self.root, domain_id)
        payload = os.path.join(workdir, "payload")
        state = os.path.join(workdir, "state")
        os.makedirs(state, exist_ok=True)
        shutil.copytree(spec.payload_dir, payload)

        self._counter += 1
        # Minted by the supervisor, stored only in the registry. Nothing the
        # domain can read, compute, or influence.
        serial = f"mem:{uuid.uuid4().hex[:12]}:{self._counter}"
        self._registry[domain_id] = {
            "hw_serial": serial,
            "alive": True,
            "frozen": False,
            "severed": False,
            "born": time.time(),
            "seq": self._counter,
        }
        return DomainHandle(
            domain_id=domain_id,
            hw_serial=serial,
            role=spec.role,
            depth=spec.depth,
            backend=self.name,
            native_id=str(self._counter),
            workdir=workdir,
            network=f"memnet-{self._counter}",
        )

    def destroy(self, h: DomainHandle) -> None:
        rec = self._registry.get(h.domain_id)
        if rec:
            rec["alive"] = False
        self._registry.pop(h.domain_id, None)
        shutil.rmtree(h.workdir, ignore_errors=True)
        h.destroyed = True

    # -- observation --------------------------------------------------------
    def hw_facts(self, h: DomainHandle) -> Dict[str, Any]:
        rec = self._registry.get(h.domain_id)
        if rec is None:
            return {
                "source": "supervisor-registry",
                "hw_serial": h.hw_serial,
                "alive": False,
                "paused": False,
                "networks": [],
                "privileged": False,
            }
        return {
            "source": "supervisor-registry",
            "hw_serial": rec["hw_serial"],
            "alive": bool(rec["alive"]) and not rec["frozen"],
            "paused": bool(rec["frozen"]),
            "seq": rec["seq"],
            "networks": [] if rec["severed"] else [h.network or ""],
            "privileged": False,
        }

    def measure(self, h: DomainHandle, spec_policy_hash: str) -> Measurement:
        payload = os.path.join(h.workdir, "payload")
        cfg = {"role": h.role, "backend": self.name}
        return Measurement(
            registers={
                "firmware": self._fw,
                "image": sha256_bytes(b"memory-rootfs-v1"),
                "kernel": sha256_bytes(b"pyodide-or-cpython"),
                # Read by the supervisor straight off the filesystem.
                "entrypoint": manifest_from_dir(payload),
                "config": sha256_obj(cfg),
                "policy": spec_policy_hash,
            }
        )

    def alive(self, h: DomainHandle) -> bool:
        return bool(self.hw_facts(h).get("alive"))

    # -- containment --------------------------------------------------------
    def freeze(self, h: DomainHandle) -> None:
        rec = self._registry.get(h.domain_id)
        if rec:
            rec["frozen"] = True
        h.frozen = True

    def sever(self, h: DomainHandle) -> None:
        rec = self._registry.get(h.domain_id)
        if rec:
            rec["severed"] = True
        h.severed = True

    def snapshot(self, h: DomainHandle, dest_path: str) -> Dict[str, Any]:
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with tarfile.open(dest_path, "w:gz") as tf:
            tf.add(h.workdir, arcname=os.path.basename(h.workdir))
        return {
            "kind": "memory-tar",
            "inspect": self.hw_facts(h),
            "bytes": os.path.getsize(dest_path),
        }

    # -- interaction --------------------------------------------------------
    def exec_in(self, h: DomainHandle, argv: List[str], timeout: float = 10.0) -> Tuple[int, str, str]:
        rec = self._registry.get(h.domain_id)
        if rec is None or not rec["alive"]:
            return 125, "", "domain not running"
        if rec["frozen"]:
            return 125, "", "domain frozen"

        script = None
        for token in argv:
            if token.endswith(".py"):
                script = token
                break
        if script is None:
            return 127, "", f"memory backend cannot run {argv!r}"

        path = self._local(h, script)
        if not os.path.exists(path):
            return 127, "", f"no such file: {script}"

        args = argv[argv.index(script):]
        try:
            source = open(path, "r", encoding="utf-8").read()
        except OSError as exc:
            return 126, "", str(exc)

        return self._exec_source(source, path, args, timeout, h)

    def _exec_source(self, source, path, args, timeout, h) -> Tuple[int, str, str]:
        """Run the domain's own code with a wall-clock and line budget.

        A compromised layer that hangs must not hang the supervisor. With no
        processes to kill, the equivalent is a trace-function watchdog plus a
        ``time.sleep`` that refuses to exceed the attestation timeout -- so the
        'go quiet' attack still reports as a missing heartbeat rather than
        freezing the page.
        """
        import io
        import types

        deadline = time.time() + timeout
        budget = {"lines": self.exec_line_budget}

        def _watchdog(frame, event, arg):
            budget["lines"] -= 1
            if budget["lines"] < 0 or time.time() > deadline:
                raise DomainStopped("execution budget exceeded")
            return _watchdog

        fake_time = types.ModuleType("time")
        for attr in dir(time):
            if not attr.startswith("_"):
                setattr(fake_time, attr, getattr(time, attr))

        def _sleep(seconds):
            if time.time() + seconds > deadline:
                raise DomainStopped(f"slept past the {timeout}s attestation window")
            time.sleep(seconds)

        fake_time.sleep = _sleep

        payload_dir = os.path.dirname(path)
        out, err = io.StringIO(), io.StringIO()
        g = {
            "__name__": "__main__",
            "__file__": path,
            "__builtins__": __builtins__,
        }

        old_argv, old_stdout, old_stderr = sys.argv, sys.stdout, sys.stderr
        old_path = list(sys.path)
        old_time = sys.modules.get("time")
        sys.argv = list(args)
        sys.stdout, sys.stderr = out, err
        sys.path.insert(0, payload_dir)
        sys.modules["time"] = fake_time
        # The domain's own modules must resolve to *its* copies, not a sibling's.
        shadowed = {
            name: sys.modules.pop(name)
            for name in ("manifest",)
            if name in sys.modules
        }
        sys.settrace(_watchdog)
        rc = 0
        try:
            exec(compile(source, path, "exec"), g)
        except DomainStopped as exc:
            rc = 124
            err.write(str(exc))
        except SystemExit as exc:
            rc = int(exc.code or 0)
        except BaseException as exc:  # a crashing layer is an unhealthy layer
            rc = 1
            err.write(f"{type(exc).__name__}: {exc}")
        finally:
            sys.settrace(None)
            sys.argv, sys.stdout, sys.stderr = old_argv, old_stdout, old_stderr
            sys.path[:] = old_path
            if old_time is not None:
                sys.modules["time"] = old_time
            for name in ("manifest",):
                sys.modules.pop(name, None)
            sys.modules.update(shadowed)
        return rc, out.getvalue(), err.getvalue()

    def _local(self, h: DomainHandle, relpath: str) -> str:
        rel = relpath.replace("/hydra/payload", "payload").replace("/hydra/state", "state")
        return os.path.join(h.workdir, rel.lstrip("/"))

    def read_file(self, h: DomainHandle, relpath: str) -> bytes:
        try:
            with open(self._local(h, relpath), "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def write_file(self, h: DomainHandle, relpath: str, data: bytes) -> None:
        path = self._local(h, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)

    def delete_file(self, h: DomainHandle, relpath: str) -> None:
        path = self._local(h, relpath)
        if os.path.exists(path):
            os.remove(path)

    def scan_for_secret(self, h: DomainHandle) -> List[bytes]:
        blobs: List[bytes] = []
        for dirpath, _dirs, files in os.walk(h.workdir):
            for name in files:
                try:
                    with open(os.path.join(dirpath, name), "rb") as fh:
                        blobs.append(fh.read(200000))
                except OSError:
                    pass
        return blobs


def select_backend(prefer: str, root: str, image: str = "hydra-layer:latest") -> IsolationBackend:
    """``docker``, ``process``, ``memory``, or ``auto``."""
    if prefer == "memory":
        return MemoryBackend(root)
    if prefer == "process":
        return ProcessBackend(root)
    if prefer in ("docker", "auto"):
        be = DockerBackend(root, image=image)
        try:
            be.preflight()
            return be
        except BackendError:
            if prefer == "docker":
                raise
    # No Docker. If there are no processes either (Pyodide), fall back further.
    if sys.platform == "emscripten" or not hasattr(os, "fork"):
        return MemoryBackend(root)
    return ProcessBackend(root)
