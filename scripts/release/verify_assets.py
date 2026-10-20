#!/usr/bin/env python3
"""Verify downloaded release assets and their published Sigstore bundles (#2561)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile


def verify_assets(directory, metadata, repository, tag, *, runner=None):
    """Fail closed on incomplete inventory, invalid signatures or mismatched data."""
    directory = Path(directory)
    runner = runner or subprocess.run
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("tag must be an exact vMAJOR.MINOR.PATCH release tag")
    if metadata.get("tag_name") != tag:
        raise ValueError("downloaded release metadata does not match the requested tag")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("repository must be owner/name, preserving its exact case")
    version = tag[1:]
    chart = f"containarium-k8s-{version}.tgz"
    bundle = f"containarium-bundle-{tag}-linux-amd64.tar.gz"
    binaries = {p + "-linux-amd64" for p in ("containariumd", "containarium", "mcp-server", "agent-box")}
    sboms = {p + ".spdx.json" for p in binaries}
    required = binaries | sboms | {
        "LICENSE", "NOTICE", "SHA256SUMS.txt", "agent-runtime-bundle.tar.gz",
        "sdlc-skills.tar.gz", "sdlc-skills.tar.gz.sha256", chart, chart + ".sha256",
        bundle, bundle + ".sha256",
    }
    advertised = [a["name"] for a in metadata["assets"]]
    if len(set(advertised)) != len(advertised) or any(
        Path(name).name != name or name in (".", "..") for name in advertised
    ):
        raise ValueError("invalid release inventory names")
    local = {p.name for p in directory.iterdir()}
    if set(advertised) != local:
        raise ValueError("download inventory differs from the published release")
    missing = required - local
    if missing:
        raise ValueError(f"missing required release assets: {sorted(missing)}")
    if any(p.is_symlink() or not p.is_file() for p in directory.iterdir()):
        raise ValueError("release inventory must contain only regular files")
    payloads = {n for n in local if not n.endswith(".sigstore.json")}
    signatures = {n[:-len(".sigstore.json")] for n in local if n.endswith(".sigstore.json")}
    if payloads != signatures:
        raise ValueError("every asset must have exactly one published signature bundle")

    identity = f"https://github.com/{repository}/.github/workflows/release.yml@refs/tags/{tag}"
    for name in sorted(payloads):
        runner([
            "cosign", "verify-blob", "--bundle", str(directory / (name + ".sigstore.json")),
            "--certificate-identity", identity,
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            str(directory / name),
        ], check=True, stdout=subprocess.DEVNULL)

    for name in sorted(sboms):
        data = json.loads((directory / name).read_text())
        packages = data.get("packages")
        if (data.get("spdxVersion") not in ("SPDX-2.2", "SPDX-2.3")
                or not isinstance(packages, list) or len(packages) < 2
                or not all(isinstance(p, dict) and isinstance(p.get("name"), str) and p["name"]
                           and isinstance(p.get("SPDXID"), str) and p["SPDXID"].startswith("SPDXRef-")
                           for p in packages)):
            raise ValueError(f"empty or invalid SPDX SBOM: {name}")
    with tarfile.open(directory / chart, "r:gz") as archive:
        member = archive.getmember("containarium-k8s/Chart.yaml")
        if not member.isfile() or member.size > 65536:
            raise ValueError("invalid chart metadata")
        chart_yaml = archive.extractfile(member).read().decode("utf-8")
    # helm package emits these scalar fields at the top level, without YAML
    # aliases. Inspect the archive without extracting any paths to disk.
    def scalar(field):
        match = re.search(r"^" + field + r":[ \t]*([^\n]*)$", chart_yaml, re.MULTILINE)
        return match[1].strip().strip("\"'") if match else ""
    if scalar("appVersion") != tag:
        raise ValueError("chart appVersion does not equal the exact release tag")
    if scalar("version") != version:
        raise ValueError("chart version does not equal the release version")
    if f"Chart version `{version}`" not in metadata.get("body", ""):
        raise ValueError("release notes do not list the exact chart version")

    def check_sums(filename):
        checked = set()
        for line in (directory / filename).read_text().splitlines():
            match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
            if not match or match[2] not in payloads or match[2] in checked:
                raise ValueError(f"invalid checksum entry in {filename}: {line}")
            name = match[2]
            digest = hashlib.sha256()
            with (directory / name).open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
            if digest.hexdigest() != match[1].lower():
                raise ValueError(f"checksum mismatch: {name}")
            checked.add(name)
        return checked

    listed = check_sums("SHA256SUMS.txt")
    # Legal files are signed at repository root, outside the binary checksum
    # build. The offline bundle is covered by its dedicated sidecar instead.
    excluded = {"LICENSE", "NOTICE", "SHA256SUMS.txt", bundle}
    coverage = {n for n in payloads if not n.endswith(".sha256")} - excluded
    if coverage - listed:
        raise ValueError(f"assets missing from checksum list: {sorted(coverage - listed)}")
    for name in payloads:
        if name.endswith(".sha256") and check_sums(name) != {name[:-len(".sha256")]}:
            raise ValueError(f"checksum sidecar does not cover its own artifact: {name}")
    return {"repository": repository, "tag": tag, "identity": identity,
            "chart_version": version, "sboms": sorted(sboms), "verified_files": sorted(payloads)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--metadata", type=Path, required=True, help="GitHub release REST JSON, outside directory")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        report = verify_assets(args.directory, json.loads(args.metadata.read_text()), args.repository, args.tag)
    except (ValueError, KeyError, OSError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
