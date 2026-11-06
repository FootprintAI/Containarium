#!/usr/bin/env python3
"""Build the pinned host toolchain tree. Never resolve latest during a build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen
import zipfile

MOUNT = "/opt/containarium/toolchains"
ARCHES = ("amd64", "arm64")
EXTRA_ENV = "CONTAINARIUM_EXTRA_TOOLS_LOCK"
EXTRA_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


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


def validate_extra_lock(extra, base, arches=ARCHES):
    """Reject a deployer lock that is unpinned, unverifiable or shadows a built-in tool."""
    if not isinstance(extra, dict) or not isinstance(extra.get("tools"), list) or not extra["tools"]:
        raise ValueError("extra lock must be an object with a non-empty tools list")
    taken = {t["name"] for t in base["tools"]} | {Path(b).name for t in base["tools"] for b in t.get("bin", [])}
    names = [t.get("name") for t in extra["tools"]]
    for name in names:
        if not isinstance(name, str) or not EXTRA_NAME.fullmatch(name):
            raise ValueError(f"invalid extra tool name: {name!r}")
    if len(set(names)) != len(names):
        raise ValueError("duplicate extra tool name in extra lock")
    for tool in extra["tools"]:
        name = tool["name"]
        if name in taken:
            raise ValueError(f"extra tool {name} collides with a built-in tool")
        version = tool.get("version")
        if not isinstance(version, str) or not version.strip() or version.strip().lower() in ("latest", "stable", "head"):
            raise ValueError(f"extra tool {name} needs a pinned version, not {version!r}")
        bins = tool.get("bin")
        if not isinstance(bins, list) or not bins:
            raise ValueError(f"extra tool {name} must list its executables in bin")
        for rel in bins:
            path = Path(rel) if isinstance(rel, str) else None
            if path is None or path.is_absolute() or ".." in path.parts or not path.name:
                raise ValueError(f"extra tool {name} has an unsafe bin path: {rel!r}")
            if path.name in taken or path.name in {Path(b).name for t in extra["tools"] if t is not tool for b in t.get("bin", [])}:
                raise ValueError(f"extra tool {name} bin {path.name} collides with another tool")
        for arch in arches:
            asset = tool.get("artifacts", {}).get(arch)
            if not isinstance(asset, dict):
                raise ValueError(f"extra tool {name} has no {arch} artifact")
            if not re.fullmatch(r"[a-f0-9]{64}", str(asset.get("sha256", ""))):
                raise ValueError(f"extra tool {name} {arch} artifact needs a 64-hex sha256")
            if not re.match(r"https://|file://", str(asset.get("url", ""))):
                raise ValueError(f"extra tool {name} {arch} url must be https")
            if asset.get("format") not in ("tar", "zip"):
                raise ValueError(f"extra tool {name} {arch} format must be tar or zip")


def install_extra(tool, arch, destination, cache):
    asset = tool["artifacts"][arch]
    target = destination / "extra" / tool["name"]
    with tempfile.TemporaryDirectory() as temp:
        extracted = Path(temp)
        unpack(download(asset, cache), asset["format"], extracted)
        roots = list(extracted.iterdir())
        root = roots[0] if len(roots) == 1 and roots[0].is_dir() else extracted
        shutil.copytree(root, target, symlinks=True)
    for rel in tool["bin"]:
        executable = target / rel
        if not executable.is_file() or not executable.resolve().is_relative_to(target.resolve()):
            raise ValueError(f"extra tool {tool['name']}: bin {rel} not found in archive")
        link = destination / "bin" / Path(rel).name
        link.symlink_to(Path("..") / "extra" / tool["name"] / rel)


def build_staticcheck(tool, lock, arch, destination, cache):
    # Rebuild the same stable source with the pinned Go security release;
    # upstream's prebuilt staticcheck may still embed an older Go stdlib.
    native = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    go = next(t for t in lock["tools"] if t["name"] == "go")
    asset = go["artifacts"][native]
    with tempfile.TemporaryDirectory() as temp:
        sdk = Path(temp)
        unpack(download(asset, cache), "tar", sdk)
        command = str(sdk / "go/bin/go")
        env = dict(os.environ, GOENV="off", GOTOOLCHAIN="local", GOSUMDB="sum.golang.org",
                   GOPROXY="https://proxy.golang.org", GOPRIVATE="", GONOSUMDB="", GONOPROXY="",
                   GOMODCACHE=str(cache / "modules"), GOCACHE=str(cache / "go-build"),
                   GOOS="linux", GOARCH=arch, CGO_ENABLED="0", GOFLAGS="-mod=readonly")
        info = json.loads(subprocess.check_output(
            [command, "mod", "download", "-json", tool["module"] + "@" + tool["module_version"]],
            env=env, timeout=180))
        if info.get("Sum") != tool["module_sum"]:
            raise ValueError("staticcheck source checksum mismatch")
        output = destination / "staticcheck/staticcheck"
        output.parent.mkdir()
        subprocess.run([command, "build", "-mod=readonly", "-trimpath", "-o", str(output), "./cmd/staticcheck"],
                       cwd=info["Dir"], env=env, check=True, timeout=600)


def build(lock, arch, release, destination, cache, extra=None, extra_digest=None):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", release):
        raise ValueError("invalid release id")
    if extra is not None:
        validate_extra_lock(extra, lock, (arch,))
    destination, cache = destination.resolve(), cache.resolve()
    destination.mkdir(parents=True)
    bin_dir = destination / "bin"
    bin_dir.mkdir()
    for tool in lock["tools"]:
        name = tool["name"]
        if name == "staticcheck" and "module" in tool:
            build_staticcheck(tool, lock, arch, destination, cache)
            continue
        asset = tool["artifacts"][arch]
        source = download(asset, cache)
        if name == "buf":
            shutil.copyfile(source, bin_dir / name)
        else:
            with tempfile.TemporaryDirectory() as temp:
                extracted = Path(temp)
                unpack(source, asset["format"], extracted)
                if name in ("go", "node", "npm", "staticcheck"):
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
    for tool in (extra or {}).get("tools", []):
        install_extra(tool, arch, destination, cache)
    npm = next(t for t in lock["tools"] if t["name"] == "npm")
    for dependency in npm.get("security_dependencies", []):
        name = dependency["name"]
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            raise ValueError("invalid npm security dependency name")
        with tempfile.TemporaryDirectory() as temp:
            extracted = Path(temp)
            artifact = dependency["artifact"]
            unpack(download(artifact, cache), artifact["format"], extracted)
            package = extracted / "package"
            metadata = json.loads((package / "package.json").read_text())
            if (metadata["name"], metadata["version"]) != (name, dependency["version"]):
                raise ValueError("npm security dependency identity mismatch")
            target = destination / "npm/node_modules" / name
            shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(package, target, symlinks=True)
    # Replace, rather than retain, Node's bundled npm and its stale dependencies.
    shutil.rmtree(destination / "node/lib/node_modules/npm", ignore_errors=True)
    for name in ("npm", "npx"):
        (destination / "node/bin" / name).unlink(missing_ok=True)
    for name, relative in {"gofmt": "../go/bin/gofmt", "node": "../node/bin/node",
                           "npm": "../npm/bin/npm-cli.js", "npx": "../npm/bin/npx-cli.js",
                           "protoc": "../protoc/bin/protoc", "staticcheck": "../staticcheck/staticcheck"}.items():
        (bin_dir / name).symlink_to(relative)
    (bin_dir / "go").write_text(f'#!/bin/sh\nGOTOOLCHAIN=local exec {MOUNT}/current/go/bin/go "$@"\n')
    for path in bin_dir.iterdir():
        path.chmod(path.stat().st_mode | 0o555)
    manifest = {"schema_version": 1, "release": release, "arch": arch,
                "tools": lock["tools"], "system_tools": lock["system_tools"],
                "system_libraries": lock.get("system_libraries", [])}
    if extra is not None:
        manifest["tools"] = lock["tools"] + [dict(t, source="extra") for t in extra["tools"]]
        manifest["extra_lock_sha256"] = extra_digest
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
    parser.add_argument("--extra-lock", type=Path, default=os.environ.get(EXTRA_ENV) or None,
                        help=f"deployer lock of additional tools (default: ${EXTRA_ENV})")
    args = parser.parse_args()
    extra_raw = args.extra_lock.read_bytes() if args.extra_lock else None
    if extra_raw is not None:  # a release serves both CPUs: fail before building either
        validate_extra_lock(json.loads(extra_raw), json.loads(args.lock.read_text()))
    build(json.loads(args.lock.read_text()), args.arch, args.release, args.output, args.cache,
          extra=json.loads(extra_raw) if extra_raw is not None else None,
          extra_digest=hashlib.sha256(extra_raw).hexdigest() if extra_raw is not None else None)
