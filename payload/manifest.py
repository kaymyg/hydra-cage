"""Manifest helper -- deliberately duplicated from hydra.measurement.

This file runs *inside* an execution domain, which by construction has no
access to the supervisor's code. Both sides must fold the same
``(relpath, sha256)`` pairs the same way, so the algorithm is copied here
verbatim rather than imported. Keep the two in sync; the test suite asserts
they agree.
"""

import hashlib
import os


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_manifest(pairs):
    items = sorted((p.strip("/"), d) for p, d in pairs)
    h = hashlib.sha256()
    h.update(b"hydra-manifest-v1\n")
    for path, digest in items:
        h.update(path.encode() + b"\0" + digest.encode() + b"\n")
    return h.hexdigest()


def manifest_from_dir(root):
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
