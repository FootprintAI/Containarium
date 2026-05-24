# Containarium Air-Gapped Install Bundle

This directory holds the customer-facing pieces of the **air-gapped
install bundle** specified in
`prd/cloud/air-gapped-install-bundle.md` (E3a).

## What's here

| File | Purpose |
|---|---|
| `install.sh` | The offline installer. Drop-in replacement for `hacks/install.sh`; resolves every dependency from the surrounding bundle directory tree. Ships **inside** the tarball as `./offline-install.sh`. |
| `README.md` | This file. Copied into the bundle root as the user's first read. |
| `docs/INSTALL.md` | Customer-facing install procedure (mirrored in the bundle's `docs/`). |
| `docs/VERIFY.md` | Bundle SHA256 verification walkthrough. |
| `docs/GHES.md` | GitHub Enterprise Server runner-kit setup, using the `GH_BASE_URL` env var added in this PR. |

## How customers use the bundle

```bash
# On the connected "sherpa" machine:
curl -L -o containarium-bundle-vX.Y.Z-linux-amd64.tar.gz \
  https://github.com/footprintai/containarium/releases/download/vX.Y.Z/containarium-bundle-vX.Y.Z-linux-amd64.tar.gz

# Verify outer checksum (published on the GH release page):
sha256sum -c containarium-bundle-vX.Y.Z-linux-amd64.tar.gz.sha256

# Transfer the .tar.gz to the air-gapped host (USB, file diode, etc.)

# On the air-gapped host:
tar xzf containarium-bundle-vX.Y.Z-linux-amd64.tar.gz
cd containarium-bundle-vX.Y.Z-linux-amd64/
sudo ./offline-install.sh
```

The installer's first step is to re-verify the inner
`CHECKSUMS.sha256` file, catching any in-transit corruption.

## How the bundle is built

See `scripts/bundle/README.md` for the maintainer-facing pipeline
documentation. Short version:

```bash
make build-release                # binaries
make build-bundle VERSION=v0.19.0 OS=linux ARCH=amd64
ls dist/containarium-bundle-v0.19.0-linux-amd64.tar.gz
```

CI (`.github/workflows/release.yml`) runs the same target on tag pushes
and uploads the bundle alongside the per-platform binaries.

## Bundle layout

```
containarium-bundle-vX.Y.Z-linux-amd64/
  README.md
  VERSION
  CHECKSUMS.sha256
  offline-install.sh
  bin/
    containarium
    mcp-server
    agent-box
    actions-runner-linux-x64-2.319.1.tar.gz
  sidecars/
    otel-sidecar.tar
  toolchains/
    go1.25.10.linux-amd64.tar.gz
    node-v22.x-linux-x64.tar.xz
    pnpm-9.x-linux-x64
    buf-1.38.0-linux-amd64
    golangci-lint-2.x-linux-amd64.tar.gz
  apt/
    *.deb
  images/
    containarium-base-vX.Y.Z.tar.gz   # may be absent in v0
  docs/
    INSTALL.md
    VERIFY.md
    GHES.md
```

## Reference

- PRD: `prd/cloud/air-gapped-install-bundle.md` (in the
  `Containarium-cloud` repo)
- Umbrella issue: `FootprintAI/Containarium-cloud#100` (sub-task E3b)
