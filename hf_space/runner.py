"""Subprocess plumbing for the Space UI.

Kept free of any Gradio import so it can be unit-tested headlessly. Each run
gets its own temporary workdir, so concurrent visitors never share a cage.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Iterator, List

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(APP_ROOT, "hydra_cli.py")

# The Space runs unprivileged with no Docker daemon -- nested containers are
# not available on Hugging Face Spaces. The process backend has the identical
# trust topology, which is what the demo is actually about.
BACKEND = "process"

MAX_LAYERS = 6
MAX_RUNTIME_S = 240


def build_command(mode: str, layers: int, workdir: str) -> List[str]:
    layers = max(2, min(int(layers), MAX_LAYERS))
    return [
        sys.executable,
        CLI,
        "--backend", BACKEND,
        "--layers", str(layers),
        "--workdir", workdir,
        "--quiet",
        "--purge",
        mode,
    ]


def stream(mode: str, layers: int) -> Iterator[str]:
    """Yield the cumulative transcript as the run progresses."""
    workdir = tempfile.mkdtemp(prefix="hydra-space-")
    env = {
        **os.environ,
        "HYDRA_NO_COLOR": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    argv = build_command(mode, layers, os.path.join(workdir, "cage"))

    lines: List[str] = []
    started = time.time()
    proc = subprocess.Popen(
        argv,
        cwd=APP_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.append(line.rstrip("\n"))
            yield "\n".join(lines)
            if time.time() - started > MAX_RUNTIME_S:
                proc.kill()
                lines.append("")
                lines.append(f"-- run exceeded {MAX_RUNTIME_S}s and was stopped --")
                yield "\n".join(lines)
                break
        proc.wait(timeout=15)
    except Exception as exc:  # surface it rather than showing an empty box
        lines.append(f"-- runner error: {type(exc).__name__}: {exc} --")
        yield "\n".join(lines)
    finally:
        if proc.poll() is None:
            proc.kill()
        shutil.rmtree(workdir, ignore_errors=True)

    if not lines:
        yield "-- no output --"


def run(mode: str, layers: int) -> str:
    out = ""
    for out in stream(mode, layers):
        pass
    return out
