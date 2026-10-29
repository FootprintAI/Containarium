#!/usr/bin/env python3
"""Build the pinned host toolchain tree. Never resolve latest during a build."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
from urllib.request import urlopen
import zipfile

MOUNT = "/opt/containarium/toolchains"


def download(asset, cache):
    digest = asset["sha256"]
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("invalid checksum in toolchain lock")
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / digest
    if not target.exists():
        with urlopen(asset["url"], timeout=60) as response, target.with_suffix(".tmp").open("wb") as output:
            shutil.copyfileobj(response, output)
        target.with_suffix(".tmp").replace(target)
    # Cached bytes are checked on every invocation too.
    with target.open("rb") as data:
        actual = hashlib.file_digest(data, "sha256").hexdigest()
    if actual != digest:
        raise ValueError(f"checksum mismatch for {asset['url']}")
    return target


def unpack(source, kind, destination):
    destination.mkdir(parents=True, exist_ok=True)
    if kind == "tar":
        with tarfile.open(source) as archive:
            archive.extractall(destination, filter="data")
    elif kind == "zip":
        with zipfile.ZipFile(source) as archive:
            for entry in archive.infolist():
                if not (destination / entry.filename).resolve().is_relative_to(destination.resolve()):
                    raise ValueError("unsafe toolchain archive path")
            archive.extractall(destination)
    else:
        raise ValueError(f"unsupported archive format: {kind}")


def build(lock, arch, release, destination, cache):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", release):
        raise ValueError("invalid release id")
    destination.mkdir(parents=True)
    bin_dir = destination / "bin"
    bin_dir.mkdir()
    for tool in lock["tools"]:
        name = tool["name"]
        asset = tool["artifacts"][arch]
        source = download(asset, cache)
        if name == "buf":
            shutil.copyfile(source, bin_dir / name)
        else:
            with tempfile.TemporaryDirectory() as temp:
                extracted = Path(temp)
                unpack(source, asset["format"], extracted)
                if name in ("go", "node", "staticcheck"):
                    roots = list(extracted.iterdir())
                    if len(roots) != 1 or not roots[0].is_dir():
                        raise ValueError(f"unexpected {name} archive layout")
                    shutil.copytree(roots[0], destination / name, symlinks=True)
                elif name == "protoc":
                    shutil.copytree(extracted, destination / name, symlinks=True)
                elif name == "pnpm":
                    candidates = [p for p in extracted.rglob("pnpm") if p.is_file()]
                    if len(candidates) != 1:
                        raise ValueError("unexpected pnpm archive layout")
                    shutil.copyfile(candidates[0], bin_dir / "pnpm")
                else:
                    raise ValueError(f"unknown managed tool: {name}")
    for name, relative in {"gofmt": "../go/bin/gofmt", "node": "../node/bin/node",
                           "npm": "../node/bin/npm", "npx": "../node/bin/npx",
                           "protoc": "../protoc/bin/protoc", "staticcheck": "../staticcheck/staticcheck"}.items():
        (bin_dir / name).symlink_to(relative)
    (bin_dir / "go").write_text(f'#!/bin/sh\nGOTOOLCHAIN=local exec {MOUNT}/current/go/bin/go "$@"\n')
    for path in bin_dir.iterdir():
        path.chmod(path.stat().st_mode | 0o555)
    manifest = {"schema_version": 1, "release": release, "arch": arch,
                "tools": lock["tools"], "system_tools": lock["system_tools"]}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    shutil.copyfile(Path(__file__).with_name("install.sh"), destination / "install.sh")
    checksums = []
    for path in sorted(destination.rglob("*")):
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as data:
                digest = hashlib.file_digest(data, "sha256").hexdigest()
            checksums.append(f"{digest}  {path.relative_to(destination)}\n")
    (destination / "checksums.sha256").write_text("".join(checksums))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path("dist/toolchain-downloads"))
    parser.add_argument("--lock", type=Path, default=Path(__file__).with_name("tools.lock.json"))
    args = parser.parse_args()
    build(json.loads(args.lock.read_text()), args.arch, args.release, args.output, args.cache)
