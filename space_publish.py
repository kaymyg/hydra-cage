#!/usr/bin/env python3
"""Stage, diagnose, and publish the Hugging Face Space. One file, no bash.

    python space_publish.py --check     inspect the Space, change nothing
    python space_publish.py --build     stage locally, upload nothing
    python space_publish.py             stage and upload
    python space_publish.py --reset     delete, recreate as static, upload

This publishes a **static** Space. Hugging Face now requires a PRO
subscription to create Gradio or Docker Spaces; static Spaces remain free for
everyone. So the cage runs client-side under Pyodide instead of on a server --
same package, same adversary suite, compiled to WebAssembly in the visitor's
browser.

Requires:  pip install -U "huggingface_hub[cli]"  and  hf auth login
"""

from __future__ import annotations

import argparse
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STAGE = ROOT / "build" / "space"

REPO_ID = "Sahek/hydra-cage"

# Python that must reach the browser. driver.py sits beside them so its
# "payload next to me" lookup resolves the same way it does locally.
BUNDLED = ["hydra", "payload", "adversary"]
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".hydra", "*.egg-info")


def info(msg: str) -> None:
    print(f"  {msg}")


def section(msg: str) -> None:
    print(f"\n{msg}\n" + "-" * 60)


# --------------------------------------------------------------------------
def stage(out: Path | None = None) -> Path:
    global STAGE
    if out is not None:
        STAGE = out
    section(f"staging {STAGE}")
    if STAGE.exists():
        try:
            shutil.rmtree(STAGE)
        except OSError as exc:
            sys.exit(
                f"error: cannot clear {STAGE} ({exc}).\n"
                f"       Delete it by hand, or stage elsewhere with --out."
            )
    STAGE.mkdir(parents=True)

    for name in ("README.md", "index.html"):
        src = ROOT / "web" / name
        if not src.exists():
            sys.exit(f"error: missing {src}")
        shutil.copy2(src, STAGE / name)
    shutil.copy2(ROOT / "LICENSE", STAGE / "LICENSE")

    # Everything Python goes in one zip that Pyodide unpacks at load time.
    tmp = STAGE / "_bundle"
    tmp.mkdir()
    shutil.copy2(ROOT / "web" / "driver.py", tmp / "driver.py")
    for pkg in BUNDLED:
        shutil.copytree(ROOT / pkg, tmp / pkg, ignore=IGNORE)

    zip_path = STAGE / "hydra_web.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(tmp.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(tmp).as_posix())
    shutil.rmtree(tmp)

    kb = zip_path.stat().st_size / 1024
    with zipfile.ZipFile(zip_path) as zf:
        members = zf.namelist()
    info(f"hydra_web.zip: {len(members)} modules, {kb:.0f} KB")
    if "driver.py" not in members:
        sys.exit("error: driver.py missing from the bundle")

    head = (STAGE / "README.md").read_text(encoding="utf-8").split("---")[1]
    for line in head.strip().splitlines():
        if line.split(":")[0].strip() in ("sdk", "app_file", "title"):
            info(f"front matter: {line.strip()}")

    files = sorted(p.name for p in STAGE.iterdir())
    info(f"space root: {files}")
    return STAGE


# --------------------------------------------------------------------------
def check(api, repo_id: str) -> bool:
    section(f"inspecting {repo_id}")
    try:
        me = api.whoami()
        info(f"authenticated as: {me['name']}  (pro: {me.get('isPro', '?')})")
    except Exception as exc:
        sys.exit(f"  not logged in: {exc}\n  run: hf auth login")

    try:
        s = api.space_info(repo_id)
    except Exception as exc:
        info(f"Space does not exist or is not visible ({type(exc).__name__})")
        return False

    runtime = getattr(s, "runtime", None) or {}
    get = runtime.get if isinstance(runtime, dict) else lambda k: getattr(runtime, k, None)
    info(f"sdk      : {getattr(s, 'sdk', None)}")
    info(f"hardware : {get('hardware')}")
    info(f"stage    : {get('stage')}")
    info(f"private  : {getattr(s, 'private', None)}")

    if getattr(s, "sdk", None) != "static":
        info("")
        info("NOTE: this Space is not 'static'. Gradio and Docker Spaces now")
        info("need a PRO subscription; --reset recreates it as static, which")
        info("is free and runs the cage in the browser instead.")
    return True


def reset(api, repo_id: str) -> None:
    section("resetting the Space")
    try:
        api.delete_repo(repo_id, repo_type="space", missing_ok=True)
        info("removed any existing Space")
    except Exception as exc:
        info(f"delete skipped: {exc}")
    api.create_repo(repo_id, repo_type="space", space_sdk="static", private=False, exist_ok=True)
    info("created: sdk=static, public, free")


def upload(api, repo_id: str, folder: Path) -> None:
    section("uploading")
    api.upload_folder(
        repo_id=repo_id,
        repo_type="space",
        folder_path=str(folder),
        commit_message="Publish the Hydra Cage in-browser demonstration",
    )
    print()
    info(f"pushed -> https://huggingface.co/spaces/{repo_id}")
    info("Static Spaces deploy in seconds. First visit downloads ~10 MB of Pyodide.")


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Publish the Hydra Cage Space")
    ap.add_argument("--repo", default=REPO_ID)
    ap.add_argument("--check", action="store_true", help="diagnose only")
    ap.add_argument("--build", action="store_true", help="stage locally, no upload")
    ap.add_argument("--reset", action="store_true", help="delete and recreate first")
    ap.add_argument("--out", default=None, help="stage somewhere other than build/space")
    args = ap.parse_args()
    out = Path(args.out).resolve() if args.out else None

    print("\nHydra Cage -- Space publisher")
    print("=" * 60)

    if args.build:
        folder = stage(out)
        print()
        info(f"staged at {folder}")
        info(f'serve it locally with:  python -m http.server -d "{folder}" 8000')
        print()
        return 0

    try:
        from huggingface_hub import HfApi
    except ImportError:
        sys.exit('huggingface_hub missing.  pip install -U "huggingface_hub[cli]"')

    api = HfApi()

    if args.check:
        check(api, args.repo)
        return 0

    exists = check(api, args.repo)
    folder = stage(out)
    if args.reset or not exists:
        reset(api, args.repo)
    upload(api, args.repo, folder)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
