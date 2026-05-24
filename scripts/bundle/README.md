# Bundle Build Pipeline (internal)

Maintainer-facing notes on how the air-gapped install bundle is built.
For the customer-facing side, see `hacks/offline-install/README.md`.

## Scripts in this directory

| Script | Purpose |
|---|---|
| `download-deps.sh` | Pulls toolchain tarballs (Go, Node, pnpm, buf, golangci-lint, actions-runner) and `.deb` packages into `dist/bundle-cache/`. Idempotent. |
| `build-bundle.sh` | Assembles the bundle tarball from `bin/` outputs + the cache, computes SHA256 manifest, tars + gzips. |

## Local build (test the pipeline)

```bash
# 1. Build the per-platform binaries the bundle wraps
make build-release

# 2. Download toolchains + apt packages into dist/bundle-cache/
make bundle-download-deps OS=linux ARCH=amd64

# 3. Assemble the tarball
make build-bundle VERSION=v0.19.0 OS=linux ARCH=amd64

# Outputs:
#   dist/containarium-bundle-v0.19.0-linux-amd64.tar.gz
#   dist/containarium-bundle-v0.19.0-linux-amd64.tar.gz.sha256
```

## Pinned tool versions

The bundle ships exact-pinned versions for reproducibility (Tier 3
customers stay on a tested bundle for months — drift would break
their security review).

| Tool | Version | Why this version |
|---|---|---|
| Go | 1.25.10 | matches `go.mod` and the Containarium repo's CI |
| Node | 22.11.0 | LTS line; matches runner-kit's `setup_22.x` |
| pnpm | 9.12.3 | matches runner-kit's `pnpm@9` |
| buf | 1.38.0 | matches Containarium-cloud's CI pin |
| golangci-lint | 2.1.6 | latest v2; bump conservatively |
| actions-runner | 2.319.1 | matches `hacks/runner/install.sh`'s `RUNNER_VERSION` |

Override at build time:

```bash
GO_VERSION=1.26.0 make bundle-download-deps OS=linux ARCH=amd64
```

## APT package handling

`download-deps.sh` uses `apt-get download` + `apt-rdepends` to resolve
transitive deps from the same Ubuntu version the customer will install
on. **The host running the bundle build must be Ubuntu 24.04** (or
the same major version the customer targets) for the `.deb`s to be
compatible. On non-Debian hosts (e.g. a macOS dev laptop) the script
emits a warning and leaves `dist/bundle-cache/apt/` empty — drop in
pre-downloaded .debs from a separate Ubuntu host.

Bootstrap on a fresh Ubuntu builder:

```bash
sudo apt-get update
sudo apt-get install -y apt-rdepends curl
```

## Sidecar images

`build-bundle.sh` does `docker save` against locally-tagged sidecar
images. Build them first:

```bash
make sidecar-build-otel
```

If a sidecar image isn't present locally, the bundle build emits a
warning and skips that sidecar — the bundle is still functional but
the customer loses the corresponding observability feature.

## Containarium base image

The PRD calls for a `containarium-base-vX.Y.Z.tar.gz` Incus image
pre-baked with the runner-kit toolchains. **v0 does NOT include this**
— it's deferred to v0.1 because building a custom Incus image
requires an Incus host (extra build infrastructure). v0 bundles the
toolchain tarballs separately under `toolchains/` and lets the
runner kit unpack them into a vanilla Ubuntu container at first use.

To add the base image in v0.1:

```bash
# (future)
make build-base-image VERSION=v0.19.0
ls dist/bundle-cache/images/containarium-base-v0.19.0.tar.gz
```

`build-bundle.sh` already looks at `dist/bundle-cache/images/` and
copies any files it finds into the bundle's `images/` directory.

## Bundle size budget

Per PRD §"Bundle size":

| Component | Size (estimated) |
|---|---|
| 3 Containarium binaries | ~150 MB |
| Go toolchain | ~80 MB |
| Node toolchain | ~30 MB |
| pnpm + buf + golangci-lint | ~30 MB |
| actions-runner | ~150 MB |
| Incus + ZFS .debs + transitive | ~150 MB |
| OTel sidecar image | ~80 MB |
| Base Incus image (v0.1) | ~400 MB - 1 GB |
| **Total (v0, without base image)** | **~670 MB** |
| **Total (v0.1, with base image)** | **~1 GB - 1.5 GB** |

GitHub Releases caps at 2 GB/file. If the v0.1 base-image push us
over, switch to publishing bundles to an HTTPS object store and
linking from the GH release notes.

## CI

`.github/workflows/release.yml` runs `build-bundle.sh` on every `v*`
tag push, for `linux/amd64` and `linux/arm64`. The bundle uploads
alongside the per-platform binaries on the GitHub release. See the
`build-bundle` job for details.

## v0 limitations

- **No cosign signing.** v0.1 adds keyless Sigstore signing of
  `CHECKSUMS.sha256`.
- **No OCI artifact mirror.** v0.1 publishes bundles to
  `ghcr.io/footprintai/containarium-bundle:vX.Y.Z` via `oras push`.
- **No SBOM.** v0.1 ships `bundle.sbom.json` via `syft sbom`.
- **No base Incus image.** v0 ships toolchain tarballs only; v0.1
  pre-bakes them into `containarium-base-vX.Y.Z.tar.gz`.
- **No --runner-from-ghes flag** in the runner kit. v0.1 adds it for
  GHES admins who want their own runner-binary distribution.

These are all noted in the PRD §"v0.1 work".
