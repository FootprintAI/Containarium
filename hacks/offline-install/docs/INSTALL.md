# Containarium Air-Gapped Install Procedure

This document describes the full air-gapped install flow for a Tier 3
deployment. The audience is the ops engineer responsible for the
air-gapped host; familiarity with Linux package management, systemd,
and SSH is assumed.

This guide names no release version. Set `VERSION` to the release you are
installing; `scripts/ci/check-offline-install-version.sh` fails CI if a
version is written into this file.

## Prerequisites

**Sherpa host** (has internet):
- Any Linux/macOS with `curl`, `sha256sum` (or `shasum -a 256`), and
  optionally `cosign` to check signatures.
- A way to transfer files to the air-gapped network — USB stick,
  file-transfer appliance, write-only diode, your customer's approved
  pipeline.

**Air-gapped host** (where Containarium runs):
- Ubuntu 24.04 LTS (22.04 also works; the installer warns on other
  distros but proceeds).
- Root access (`sudo`).
- No CPU, RAM or disk minimum is checked by the installer. Sizing is not
  yet measured; see the sizing section of
  [`docs/architecture/deployment-modes.md`](../../../docs/architecture/deployment-modes.md),
  which also lists the host checks `containarium doctor` runs.
- The installer itself makes no network calls; everything resolves from the
  extracted bundle directory.

## Step 1 — Fetch the bundle on the sherpa host

```bash
VERSION=<release tag>   # e.g. the tag of the latest release, vX.Y.Z
ARCH=amd64              # the release builds amd64 bundles only
BUNDLE=containarium-bundle-${VERSION}-linux-${ARCH}.tar.gz

curl -L -o "$BUNDLE" \
  https://github.com/footprintai/containarium/releases/download/${VERSION}/${BUNDLE}

curl -L -o "${BUNDLE}.sha256" \
  https://github.com/footprintai/containarium/releases/download/${VERSION}/${BUNDLE}.sha256

sha256sum -c "${BUNDLE}.sha256"
# Expected: containarium-bundle-vX.Y.Z-linux-amd64.tar.gz: OK
```

Release files are signed with keyless cosign (Sigstore): each bundle and its
`.sha256` have a `.sigstore.json` beside them. See `VERIFY.md` for the
`cosign verify-blob` command and `docs/security/VERIFYING-RELEASES.md` for
verifying with no network on the air-gapped side.

## Step 2 — Transfer to the air-gapped host

Customer's preferred secure-transfer path. The bundle is one opaque
`.tar.gz` blob; no special handling required.

## Step 3 — Extract and install

```bash
tar xzf containarium-bundle-${VERSION}-linux-amd64.tar.gz
cd containarium-bundle-${VERSION}-linux-amd64/

sudo ./offline-install.sh
```

The installer:

1. Re-verifies the inner `CHECKSUMS.sha256` (catches in-transit
   corruption). A mismatch stops the install; a missing file only warns.
2. Installs `.deb` packages from `./apt/` (Incus, ZFS, jq, etc.) using
   `apt-get install --no-download`, so it never fetches a missing package.
   A non-zero apt exit only warns; the install stops if `incus`, `zfs`,
   `jq` or `curl` is still missing. If `./apt/` holds no `.deb` the
   installer stops with an error. If those packages are already on the
   host, pass `--skip-apt` to skip this step.
3. Initializes Incus, loads ZFS + kernel modules.
4. Installs `containariumd`, `mcp-server` and `agent-box` from `./bin/`
   into `/usr/local/bin/`, and links `containarium` to `containariumd`.
5. Generates TLS certificates and a JWT secret (local CSPRNG; no
   network), unless they already exist.
6. Installs the systemd service via `containariumd service install`.
7. Opens TCP 22 and 8080 if `ufw` is installed, and 50051 only when you
   pass `--mtls`.
8. Mints an admin token at `/etc/containarium/admin.token`. It expires
   after 30 days (`--expiry 720h`).
9. Imports the sidecar images from `./sidecars/`, if present. Sidecars are
   loaded with `docker load`, so they are skipped on a host without Docker.

The bundle ships no Incus base image (there is no `./images/` directory):
bring your own image for Step 5. `--skip-base-image` is still accepted and
does nothing.

Bundles from earlier releases shipped an empty `./apt/`. The release build
now fails instead of publishing such a bundle; with an older bundle, install
Incus, ZFS, `jq` and `curl` from your own mirror and run the installer with
`--skip-apt`.

Install time has not been measured.

## Step 4 — Start the daemon

```bash
sudo systemctl start containarium
sudo systemctl status containarium

# Tail logs
sudo journalctl -u containarium -f
```

## Step 5 — Smoke test

`containarium create` defaults to a remote image (`images:ubuntu/24.04`),
which needs the network. On an air-gapped host, use an image already in the
local Incus image store. The bundle ships none, so import an image you
transferred yourself with `incus image import <file> --alias <alias>`.

```bash
sudo incus image list            # pick a local alias
sudo containarium create test-1 \
  --image <local-image-alias> \
  --ssh-key ~/.ssh/id_ed25519.pub

# Connect
ssh test-1
```

## Step 6 — Wire the platform MCP into your AI agent

Same as the connected install — see the OSS README. Make sure the
agent's host can reach the Containarium daemon on the air-gapped
network. The installed service serves REST on `:8080`. gRPC on `:50051`
is served only when the daemon runs with `--mtls`, which the installed
unit does not pass.

## Optional — Provision a self-hosted GHA runner

`hacks/runner/install.sh` is not in the bundle, and it downloads its
toolchain and the runner from the internet, so it does not work air-gapped
as written. On a box that has network access and a copy of the script:

```bash
ssh test-1 'sudo GH_REPO=org/repo GH_PAT=ghp_xxx ./install.sh'
```

For GitHub Enterprise Server, add `GH_BASE_URL=https://github.your-company.internal`
(see `GHES.md` for the full walkthrough).

## Troubleshooting

### "Required commands missing after apt step"

The `.deb` set in `./apt/` did not install on this host. The bundle build
checks that every dependency of every bundled `.deb` is in the bundle, so
the usual cause is a host that differs from the bundle's target (not
Ubuntu 24.04, or with conflicting packages already installed). Check
`/var/log/dpkg.log`, or install the missing packages on the air-gapped
host from your own mirror and re-run with `--skip-apt`.

### "Checksum mismatch"

The bundle was corrupted in transit. Re-transfer from the sherpa host.

### Incus initialization fails

The host kernel lacks ZFS support, or `/var/lib/incus` is on a
non-default filesystem the auto-init can't handle. Run
`sudo incus admin init` interactively and follow the prompts.

### Daemon won't start

```bash
sudo journalctl -u containarium -n 100
```

Most-common cause: port conflict on `:8080`. The daemon reads no config
file; change `--http-port` (or `--port`) on the `ExecStart` line of
`/etc/systemd/system/containarium.service`, then
`sudo systemctl daemon-reload`.

## Upgrading

Tier 3 customers do not auto-update. The upgrade flow is:

1. Download the next bundle on the sherpa host.
2. Transfer to the air-gapped host.
3. Extract and re-run `sudo ./offline-install.sh`. It re-installs the
   binaries and keeps the existing TLS certificates and JWT secret. It
   writes a new `admin.token`, replacing the old file.
4. `sudo systemctl restart containarium`.

The installer does not check the bundle's age. Refresh often enough to
stay inside the security-patch backport window.
