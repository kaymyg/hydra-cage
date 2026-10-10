#!/usr/bin/env python3
"""hydra -- command line for the Hydra Cage.

    python hydra_cli.py demo                 full scripted run
    python hydra_cli.py attack               boot, run the adversary suite, report
    python hydra_cli.py up --layers 5        boot and idle, sweeping continuously
    python hydra_cli.py breach --layer 2     force a transition on a chosen layer
    python hydra_cli.py status               read a previous run's telemetry
    python hydra_cli.py forensics            list sealed artifacts, verify chain
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from adversary.attacks import AttackHarness  # noqa: E402
from hydra import CageConfig, HydraCage  # noqa: E402
from hydra.planes.evidence import EvidencePlane  # noqa: E402

BANNER = r"""
   __ __        __             ____
  / // /_ _____/ /______ _    / __/__ ____ ____
 / _  / // / _  / __/ _ `/   / /_/ _ `/ _ `/ -_)
/_//_/\_, /\_,_/_/  \_,_/    \___/\_,_/\_, /\__/
     /___/                            /___/
 disposable trust  |  regenerative containment
"""


def build_cfg(args) -> CageConfig:
    return CageConfig(
        layers=args.layers,
        backend=args.backend,
        image=args.image,
        workdir=args.workdir,
        payload=os.path.join(HERE, "payload"),
        prewarm=args.prewarm,
        echo=not args.quiet,
    )


def _print_status(cage):
    st = cage.status()
    c = st["containment"]
    print("\n" + "-" * 78)
    print(f"backend={st['backend']}  signing={st['signing']}  rounds={st['rounds']}  "
          f"breaches={st['breaches']}  transitions={st['transitions']}")
    print(f"live depth={c['live_depth']}  tombstones={c['tombstones']}  "
          f"effective depth={c['effective_depth']}")
    print("-" * 78)
    for l in c["layers"]:
        print(f"  L{l['depth']}  {l['domain']}  gen{l['generation']:<3} mr={l['mr']}  {l['state']}")
    for t in c["sealed"]:
        print(f"  ††  {t['domain']}  gen{t['generation']:<3} mr={t['mr']}  sealed")
    print("-" * 78)


# --------------------------------------------------------------------------
def cmd_up(args) -> int:
    cage = HydraCage(build_cfg(args)).boot()
    _print_status(cage)
    try:
        while True:
            time.sleep(args.interval)
            cage.sweep()
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        _print_status(cage)
        cage.shutdown(purge=args.purge)
    return 0


def cmd_breach(args) -> int:
    cage = HydraCage(build_cfg(args)).boot()
    _print_status(cage)
    idx = min(args.layer, cage.containment.live_depth - 1)
    layer = cage.containment.layers[idx]
    print(f"\n>> forcing a breach on {layer.label}\n")
    rec = cage.transition.run(layer, args.reason, layer.last_quote)
    print(json.dumps(rec.summary(), indent=2))
    _print_status(cage)
    print(json.dumps(cage.self_check(), indent=2))
    cage.shutdown(purge=args.purge)
    return 0


def cmd_attack(args) -> int:
    cage = HydraCage(build_cfg(args)).boot()
    harness = AttackHarness(cage)
    harness.run_all()
    print(harness.report())
    _print_status(cage)
    checks = cage.self_check()
    print("\nSELF CHECK")
    for k, v in checks.items():
        if isinstance(v, bool):
            print(f"  {'ok ' if v else 'FAIL'}  {k}")
        elif v:
            print(f"        {k}: {v}")
    cage.shutdown(purge=args.purge)
    return 0 if all(r.blocked for r in harness.results) else 1


def cmd_demo(args) -> int:
    from demo import run_demo

    return run_demo(build_cfg(args), purge=args.purge)


def cmd_status(args) -> int:
    path = os.path.join(os.path.abspath(args.workdir), "telemetry.jsonl")
    if not os.path.exists(path):
        print(f"no telemetry at {path}")
        return 1
    counts = {}
    with open(path) as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            counts[f"{ev['plane']}/{ev['kind']}"] = counts.get(f"{ev['plane']}/{ev['kind']}", 0) + 1
    for k in sorted(counts, key=lambda k: -counts[k]):
        print(f"  {counts[k]:>5}  {k}")
    return 0


def cmd_forensics(args) -> int:
    root = os.path.join(os.path.abspath(args.workdir), "evidence")
    if not os.path.isdir(root):
        print(f"no evidence store at {root}")
        return 1
    manifest = os.path.join(root, "manifest.jsonl")
    n = 0
    with open(manifest) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            n += 1
            print(
                f"  #{rec['seq']:<3} {rec['domain_id'][:8]}  gen{rec['generation']:<3} "
                f"{rec['artifact_bytes']:>10} B  sha={rec['artifact_sha256'][:12]}  "
                f"{rec['reason'][:44]}"
            )
    ev = EvidencePlane(root)
    print(f"\n{n} sealed artifacts")
    print(f"manifest chain valid: {ev.verify_manifest_file()}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hydra", description="Hydra Cage control")
    p.add_argument("--layers", type=int, default=4)
    p.add_argument("--backend", default="auto", choices=["auto", "docker", "process", "memory"],
                   help="isolation backend (memory = in-process, used by the browser build and CI)")
    p.add_argument("--image", default="hydra-layer:latest")
    p.add_argument("--workdir", default="./.hydra")
    p.add_argument("--prewarm", type=int, default=1)
    p.add_argument("--purge", action="store_true", help="delete the workdir on exit")
    p.add_argument("--quiet", action="store_true")

    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("up", help="boot and sweep continuously")
    s.add_argument("--interval", type=float, default=2.0)
    s.set_defaults(fn=cmd_up)

    s = sub.add_parser("breach", help="force a breach transition")
    s.add_argument("--layer", type=int, default=0)
    s.add_argument("--reason", default="operator-forced breach drill")
    s.set_defaults(fn=cmd_breach)

    s = sub.add_parser("attack", help="run the adversary suite")
    s.set_defaults(fn=cmd_attack)

    s = sub.add_parser("demo", help="full scripted demonstration")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("status", help="summarise a previous run's telemetry")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("forensics", help="list sealed artifacts")
    s.set_defaults(fn=cmd_forensics)

    args = p.parse_args(argv)
    if args.cmd in ("up", "breach", "attack", "demo"):
        print(BANNER)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
