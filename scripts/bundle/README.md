# Bundle Build Pipeline (internal)

Maintainer-facing notes on how the air-gapped install bundle is built.
For the customer-facing side, see `hacks/offline-install/README.md`.

## Scripts in this directory

| Script | Purpose |
|---|---|
| `download-deps.sh` | Pulls toolchain tarballs (Go, Node, pnpm, buf, golangci-lint, actions-runner) and `.deb` packages into `dist/bundle-cache/`. `DEPS_ONLY=toolchains` or `DEPS_ONLY=apt` runs one half. Fails on any download or apt error. |
| `add-zabbly-repo.sh` | Configures the Zabbly Incus stable apt repo (key pinned by fingerprint) on the Ubuntu builder, for `incus`, `incus-client` and `incus-extra`. |
| `build-bundle.sh` | Assembles the bundle tarball from `bin/` outputs + the cache, computes SHA256 manifest, tars + gzips. Fails when the cache holds no `.deb`. |
| `check-bundle-content.sh` | Checks a built tarball's `tar tzf` listing: binaries, installer, toolchains, the required `.deb`s, no `images/`. The release workflow runs it before upload. |

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
| buf | See `scripts/buf-version.env` | shared with Makefile and release/proto CI; checksum-verified |
| golangci-lint | 2.1.6 | latest v2; bump conservatively |
| actions-runner | 2.319.1 | matches `hacks/runner/install.sh`'s `RUNNER_VERSION` |

Override at build time:

```bash
GO_VERSION=1.26.0 make bundle-download-deps OS=linux ARCH=amd64
```

## SDLC skills release

A coding-agent box takes its role skills from a signed skills release
(`docs/design/sdlc-skills-option-b.md`). An air-gapped box cannot fetch one,
so the bundle can carry one, pinned at bundle-build time:

```bash
SDLC_SKILLS_BASE_URL=<where skills releases are published> \
SDLC_SKILLS_VERSION=<version name> \
  scripts/bundle/download-deps.sh        # or DEPS_ONLY=skills for this step alone
```

`download-deps.sh` runs `scripts/install-sdlc-skills.sh --fetch-only`, which
verifies the release exactly as an install does (the manifest's signature
against the installer's trusted keys, then the bundle's digest against the
signed manifest) and caches it under `dist/bundle-cache/sdlc-skills/` only if
it verifies. `latest` is refused: a bundle pins the version it carries.
`build-bundle.sh` verifies the cached release again and ships it as
`sdlc-skills/` with the installer beside it. With neither variable set the
bundle carries no skills release, as before.

No signing key is built into the installer yet, so until one is, pass
`SDLC_SKILLS_TRUSTED_KEYS_FILE=<pem>` to both scripts and to the install
below.

On the air-gapped host, as the box user (no network is used; the release is
verified once more):

```bash
SDLC_SKILLS_BASE_URL=file://<bundle>/sdlc-skills SDLC_SKILLS_VERSION=<version name> \
  bash <bundle>/sdlc-skills/install-sdlc-skills.sh
```

Not wired yet: `containarium code install` and the daemon still fetch the
installer from the network, so on an air-gapped host the command above is run
by hand (or by the operator's own provisioning).

## APT package handling

`download-deps.sh` asks apt's own resolver for the install set
(`apt-get install -s --no-install-recommends` against an empty dpkg status,
so it resolves as for a host with nothing installed, providers of virtual
packages included), downloads exactly those `name=version` pairs with
`apt-get download`, and then checks the result itself: a `.deb` for every
requested package, and every `Depends`/`Pre-Depends` of every `.deb` met
inside the bundle. Any apt error fails the script. It used to filter apt's
errors away, and release bundles shipped an empty `apt/` (#3061).

**The host running the apt step must be Ubuntu 24.04** (the release the
customer installs on) for the `.deb`s to be compatible, and needs the Zabbly
repo for Incus. Bootstrap on a fresh Ubuntu builder:

```bash
scripts/bundle/add-zabbly-repo.sh          # also runs apt-get update
DEPS_ONLY=apt scripts/bundle/download-deps.sh
```

On a non-Debian host (e.g. a macOS dev laptop) the apt step fails: run
`DEPS_ONLY=toolchains` there and copy the `.deb`s from an Ubuntu builder
into `dist/bundle-cache/apt/`.

`build-bundle.sh` fails when `dist/bundle-cache/apt/` holds no `.deb`. For a
dev build that only exercises the installer's other steps, set
`BUNDLE_ALLOW_EMPTY_APT=1`; such a bundle needs `offline-install.sh
--skip-apt`. The release workflow never sets it.

The closure check is by package name; whether the `.deb`s install cleanly on
a fresh air-gapped Ubuntu 24.04 host is not something CI checks.

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
pre-baked with the runner-kit toolchains. **The bundle does not include
one**: building a custom Incus image needs an Incus host, and nothing in
this repo produces it yet. The bundle ships the toolchain tarballs under
`toolchains/` instead.

Until a producer exists the bundle has **no `images/` directory** and the
offline installer has no base-image import step (#3061); the directory used
to ship empty. `check-bundle-content.sh` fails on an `images/` entry, so
adding the producer means adding the directory, the installer step and the
content check together.

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
tag push (and on a publish-free `workflow_dispatch` rehearsal), for
`linux/amd64` on `ubuntu-24.04`, then `check-bundle-content.sh` on the
tarball before it uploads alongside the per-platform binaries. See the
`build-bundle` job for details.

`.github/workflows/offline-bundle.yml` runs on changes to these scripts:
`scripts/ci/test-offline-bundle.sh` (every gate against stubbed apt tools,
each negative a seeded failure) and the real apt step on `ubuntu-24.04`.

## v0 limitations

- **Inner `CHECKSUMS.sha256` is not signed on its own.** The release
  signs the tarball and its `.sha256` (keyless cosign; see
  `docs/security/VERIFYING-RELEASES.md`), which covers everything inside.
- **No OCI artifact mirror.** v0.1 publishes bundles to
  `ghcr.io/footprintai/containarium-bundle:vX.Y.Z` via `oras push`.
- **No SBOM.** v0.1 ships `bundle.sbom.json` via `syft sbom`.
- **No base Incus image** and no `images/` directory (see above).
- **No --runner-from-ghes flag** in the runner kit. v0.1 adds it for
  GHES admins who want their own runner-binary distribution.

These are all noted in the PRD §"v0.1 work".
