# Containarium Air-Gapped Install Procedure

This document describes the full air-gapped install flow for a Tier 3
deployment. The audience is the ops engineer responsible for the
air-gapped host; familiarity with Linux package management, systemd,
and SSH is assumed.

## Prerequisites

**Sherpa host** (has internet):
- Any Linux/macOS with `curl`, `sha256sum` (or `shasum -a 256`).
- A way to transfer files to the air-gapped network — USB stick,
  file-transfer appliance, write-only diode, your customer's approved
  pipeline.

**Air-gapped host** (where Containarium runs):
- Ubuntu 24.04 LTS (22.04 also works; the installer warns on other
  distros but proceeds).
- Root access (`sudo`).
- 2+ CPU cores, 4+ GB RAM, 50+ GB free disk.
- No internet egress required. The installer makes **zero** network
  calls; everything resolves from the extracted bundle directory.

## Step 1 — Fetch the bundle on the sherpa host

```bash
VERSION=v0.19.0
ARCH=amd64
BUNDLE=containarium-bundle-${VERSION}-linux-${ARCH}.tar.gz

curl -L -o "$BUNDLE" \
  https://github.com/footprintai/containarium/releases/download/${VERSION}/${BUNDLE}

curl -L -o "${BUNDLE}.sha256" \
  https://github.com/footprintai/containarium/releases/download/${VERSION}/${BUNDLE}.sha256

sha256sum -c "${BUNDLE}.sha256"
# Expected: containarium-bundle-vX.Y.Z-linux-amd64.tar.gz: OK
```

(See `VERIFY.md` for the optional cosign-signature verification path,
shipping in v0.1.)

## Step 2 — Transfer to the air-gapped host

Customer's preferred secure-transfer path. The bundle is one opaque
`.tar.gz` blob; no special handling required.

## Step 3 — Extract and install

```bash
tar xzf containarium-bundle-vX.Y.Z-linux-amd64.tar.gz
cd containarium-bundle-vX.Y.Z-linux-amd64/

sudo ./offline-install.sh
```

The installer:

1. Re-verifies the inner `CHECKSUMS.sha256` (catches in-transit
   corruption).
2. Installs `.deb` packages from `./apt/` (Incus, ZFS, jq, etc.) using
   `apt-get install --no-download` — fails fast if any transitive dep
   is missing instead of trying to fetch it.
3. Initializes Incus, loads ZFS + kernel modules.
4. Copies binaries from `./bin/` into `/usr/local/bin/`.
5. Generates TLS certificates and a JWT secret (local CSPRNG; no
   network).
6. Installs the systemd service via `containarium service install`.
7. Imports the bundled `containarium-base` Incus image and OTel
   sidecar image.
8. Mints an initial admin token at `/etc/containarium/admin.token`.

Total install time on a typical 4-core Ubuntu VM: **5-10 minutes**.

## Step 4 — Start the daemon

```bash
sudo systemctl start containarium
sudo systemctl status containarium

# Tail logs
sudo journalctl -u containarium -f
```

## Step 5 — Smoke test

```bash
# Use the bundled base image — no network calls
sudo containarium create test-1 \
  --image containarium-base:v0.19.0 \
  --ssh-key ~/.ssh/id_ed25519.pub

# Connect
ssh test-1
```

## Step 6 — Wire the platform MCP into your AI agent

Same as the connected install — see the OSS README. Make sure the
agent's host can reach the Containarium daemon on the air-gapped
network (the daemon listens on `:8080` for REST and `:50051` for gRPC).

## Optional — Provision a self-hosted GHA runner

For GitHub.com (the default):

```bash
ssh test-1 'sudo GH_REPO=org/repo GH_PAT=ghp_xxx ./hacks/runner/install.sh'
```

For GitHub Enterprise Server (see `GHES.md` for the full walkthrough):

```bash
ssh test-1 'sudo \
  GH_REPO=org/repo \
  GH_PAT=ghp_xxx \
  GH_BASE_URL=https://github.your-company.internal \
  ./hacks/runner/install.sh'
```

## Troubleshooting

### "Required commands missing after apt step"

The `.deb` set in `./apt/` is incomplete — most often because
`apt-rdepends` wasn't installed on the host that built the bundle and
some transitive deps got skipped. Re-build the bundle on a Debian host
with `apt-rdepends` installed, or manually install the missing packages
on the air-gapped host.

### "Checksum mismatch"

The bundle was corrupted in transit. Re-transfer from the sherpa host.

### "Incus admin init failed"

The host kernel lacks ZFS support, or `/var/lib/incus` is on a
non-default filesystem the auto-init can't handle. Run
`sudo incus admin init` interactively and follow the prompts.

### Daemon won't start

```bash
sudo journalctl -u containarium -n 100
```

Most-common cause: port conflict on `:8080` or `:50051`. Override via
`/etc/containarium/config.yaml`.

## Upgrading

Tier 3 customers do not auto-update. The upgrade flow is:

1. Download the next bundle on the sherpa host.
2. Transfer to the air-gapped host.
3. Extract and re-run `sudo ./offline-install.sh` — the installer is
   idempotent; it'll re-install binaries, leave existing config and
   tokens intact, and import the new base image.
4. `sudo systemctl restart containarium`.

The installer prints a warning if the bundle being installed is more
than 6 months old — Tier 3 customers should refresh at least that
often to stay inside the security-patch backport window.
