#!/bin/bash
# install.sh — provisions a Containarium box as an ephemeral GitHub
# Actions self-hosted runner for one GitHub repo.
#
# Run this INSIDE a Containarium box (e.g. one created via
# `containarium create runner-1`). It installs:
#
#   - actions-runner (GitHub's official binary)
#   - Common CI toolchains: git, build-essential, Go, Node 22, pnpm 9,
#     buf 1.38.0, golangci-lint
#   - A systemd unit that runs the runner in `--ephemeral` mode in a
#     respawn loop: register → run ONE job → exit → restart fresh.
#
# Required env vars (or pass on command line):
#
#   GH_REPO     org/repo for the runner (e.g. FootprintAI/Containarium-cloud)
#   GH_PAT      personal access token with `repo` scope; used to mint
#               short-lived runner-registration tokens at the start of
#               each loop iteration. Pick from
#               ${GH_BASE_URL}/settings/tokens (classic) or App
#               installation tokens.
#   GH_BASE_URL (optional) base URL of the GitHub server. Defaults to
#               https://github.com. Set this to your GHES URL for
#               GitHub Enterprise Server deployments, e.g.
#               https://github.your-company.internal. The API URL is
#               derived from this (api.github.com for github.com,
#               ${GH_BASE_URL}/api/v3 for GHES). See
#               docs/GHES.md inside the air-gapped install bundle.
#   RUNNER_NAME (optional) name for this runner; defaults to the box
#               hostname. Visible in GitHub's Actions → Runners list.
#   RUNNER_LABELS (optional) comma-separated runner labels; defaults
#               to "containarium,ephemeral". Workflows target with
#               `runs-on: [self-hosted, containarium, ephemeral]`.
#   RUNNER_DNS  (optional) space-separated DNS server(s) to pin the box's
#               resolver to, e.g. "8.8.8.8 8.8.4.4". Use when the box is
#               handed a split-horizon / internal record for a host it
#               must reach over public egress (e.g. a tenant box whose
#               bridge DNS resolves the control plane to a stale internal
#               IP). Unset (default) leaves the box's DNS untouched — the
#               correct default for GHES / air-gapped runners that rely on
#               their own internal resolver.
#
# Usage from outside the box:
#
#   containarium create runner-1
#   ssh runner-1 'curl -fsSL https://raw.githubusercontent.com/footprintai/containarium/main/hacks/runner/install.sh \
#     | sudo GH_REPO=FootprintAI/Containarium-cloud GH_PAT=ghp_xxx bash'
#
# Against GitHub Enterprise Server:
#
#   ssh runner-1 'sudo \
#     GH_REPO=org/repo \
#     GH_PAT=ghp_xxx \
#     GH_BASE_URL=https://github.your-company.internal \
#     ./hacks/runner/install.sh'
#
# After this runs, the runner registers itself within ~30s and starts
# accepting jobs. Verify at
# https://github.com/<owner>/<repo>/settings/actions/runners.

set -euo pipefail

# ---- input validation ----
: "${GH_REPO:?GH_REPO is required (org/repo)}"
: "${GH_PAT:?GH_PAT is required (PAT with repo scope)}"

# GH_BASE_URL — the GitHub server URL. Defaults to github.com; set to
# your GHES URL for on-prem deployments (e.g.
# https://github.your-company.internal). Added per
# prd/cloud/air-gapped-install-bundle.md (E3a §"GHES support").
GH_BASE_URL="${GH_BASE_URL:-https://github.com}"

# Strip any trailing slash so downstream concatenation is consistent
# regardless of whether the operator typed it with or without.
GH_BASE_URL="${GH_BASE_URL%/}"

# Derive the API base URL. github.com hosts the API at the separate
# api.github.com hostname; GHES collapses both under one host at /api/v3.
if [ "$GH_BASE_URL" = "https://github.com" ]; then
  GH_API_BASE="https://api.github.com"
else
  GH_API_BASE="${GH_BASE_URL}/api/v3"
fi

RUNNER_NAME="${RUNNER_NAME:-$(hostname -s)}"
RUNNER_LABELS="${RUNNER_LABELS:-containarium,ephemeral}"
RUNNER_VERSION="${RUNNER_VERSION:-2.319.1}"
RUNNER_USER="${RUNNER_USER:-ghrunner}"
RUNNER_HOME="${RUNNER_HOME:-/opt/actions-runner}"

RUNNER_DNS="${RUNNER_DNS:-}"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) RUNNER_ARCH=x64 ;;
  aarch64|arm64) RUNNER_ARCH=arm64 ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# ---- optional: pin the box resolver (RUNNER_DNS) ----
# Some environments hand the box a split-horizon / internal DNS record for a
# host it actually has to reach over public egress — e.g. a Containarium
# tenant box whose bridge resolver maps cloud.containarium.dev to a private
# control-plane IP that goes stale after a control-plane redeploy, so
# `containarium create` fails with curl exit 7 ("couldn't connect"). Pinning
# a public resolver makes the box resolve such hosts to their public address
# and reach them over its normal egress. Done before anything network-heavy
# so the whole install uses the intended resolver. No-op when RUNNER_DNS is
# unset (the right default for GHES / air-gapped runners).
if [ -n "$RUNNER_DNS" ]; then
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    mkdir -p /etc/systemd/resolved.conf.d
    # Domains=~. routes ALL lookups to these servers, overriding the
    # per-link DNS that DHCP set from the bridge.
    cat > /etc/systemd/resolved.conf.d/zz-containarium-runner-dns.conf <<EOF
[Resolve]
DNS=${RUNNER_DNS}
Domains=~.
EOF
    systemctl restart systemd-resolved
  else
    # No systemd-resolved (stub at 127.0.0.53) — write resolv.conf directly,
    # replacing any managed symlink so our entries actually take effect.
    rm -f /etc/resolv.conf
    : > /etc/resolv.conf
    for ns in $RUNNER_DNS; do echo "nameserver ${ns}" >> /etc/resolv.conf; done
  fi
  echo "Pinned box resolver to: ${RUNNER_DNS}"
fi

# ---- system deps ----
# `sudo` is required so the runner user can be granted passwordless sudo
# (below): both FootprintAI/containarium-run (its `install-cli.sh | sudo
# bash` step) and a workflow's own dependency-install steps shell out to
# sudo, and a bare ubuntu/24.04 box may not ship it. We deliberately do NOT
# pre-install repo-specific job tools (rsync, yq, ...) here — once the runner
# user has sudo, the *workflow* installs whatever it needs, keeping the
# runner image generic and repo-agnostic. jq stays because the respawn loop
# itself needs it (to parse the registration-token response) before any job.
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl jq git build-essential libicu-dev sudo

# ---- toolchains ----
# Go (matches Containarium repo's go.mod pinning convention; bumps are
# a one-line edit here).
GO_VERSION="${GO_VERSION:-1.25.10}"
if ! command -v go >/dev/null 2>&1 || [ "$(go version | awk '{print $3}')" != "go${GO_VERSION}" ]; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi

# Node 22 + pnpm 9 (for repos with frontend builds)
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
  npm install -g pnpm@9
fi

# buf (proto toolchain — pin matches Containarium-cloud's CI)
BUF_VERSION="${BUF_VERSION:-1.38.0}"
if ! command -v buf >/dev/null 2>&1; then
  GOBIN=/usr/local/bin /usr/local/go/bin/go install \
    "github.com/bufbuild/buf/cmd/buf@v${BUF_VERSION}"
fi

# golangci-lint v2 — install via `go install` from the module proxy, NOT the
# upstream curl|sh install.sh. That script's tarball download intermittently
# fails its OWN sha256 verify ("hash_sha256_verify … did not verify"), which
# under `set -e` aborts the entire runner install before the actions-runner
# is even set up. `go install` has no tarball/checksum step. Pin for
# reproducibility; mirrors the buf install above.
GOLANGCI_VERSION="${GOLANGCI_VERSION:-2.12.2}"
if ! command -v golangci-lint >/dev/null 2>&1; then
  GOBIN=/usr/local/bin /usr/local/go/bin/go install \
    "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v${GOLANGCI_VERSION}"
fi

# ---- runner user + binary ----
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd -m -d "$RUNNER_HOME" -s /bin/bash "$RUNNER_USER"
fi

# Passwordless sudo for the runner user. The actions-runner agent runs as
# $RUNNER_USER (systemd User= below), and CI job steps frequently shell out
# to `sudo` (the dogfood workflow's prerequisite step is the canonical
# example). Without this they fail with "sudo: a password is required"
# because an Actions step has no controlling TTY. Validate with `visudo -c`
# so a malformed drop-in can never lock sudo out entirely.
cat > "/etc/sudoers.d/90-${RUNNER_USER}" <<EOF
${RUNNER_USER} ALL=(ALL) NOPASSWD:ALL
EOF
chmod 0440 "/etc/sudoers.d/90-${RUNNER_USER}"
visudo -cf "/etc/sudoers.d/90-${RUNNER_USER}"

if [ ! -x "$RUNNER_HOME/run.sh" ]; then
  mkdir -p "$RUNNER_HOME"
  cd "$RUNNER_HOME"
  TARBALL="actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz"
  curl -fsSL -o "$TARBALL" \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${TARBALL}"
  tar xzf "$TARBALL"
  rm "$TARBALL"
  chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_HOME"
fi

# ---- env file (PAT lives here; chmod 600) ----
cat > /etc/containarium-runner.env <<EOF
GH_REPO=${GH_REPO}
GH_PAT=${GH_PAT}
GH_BASE_URL=${GH_BASE_URL}
GH_API_BASE=${GH_API_BASE}
RUNNER_NAME=${RUNNER_NAME}
RUNNER_LABELS=${RUNNER_LABELS}
RUNNER_HOME=${RUNNER_HOME}
EOF
chmod 600 /etc/containarium-runner.env
# The respawn loop runs as $RUNNER_USER (systemd `User=` below) and `source`s
# this file, so it must be readable by that user — not just root. Owning it by
# $RUNNER_USER with mode 600 keeps the PAT unreadable to everyone else while
# letting the loop read it. Without this the service crash-loops on
# "source /etc/containarium-runner.env: Permission denied".
chown "$RUNNER_USER:$RUNNER_USER" /etc/containarium-runner.env

# ---- run-loop script ----
install -m 0755 /dev/stdin /usr/local/bin/containarium-runner-loop <<'EOF'
#!/bin/bash
# Ephemeral-runner respawn loop. One iteration = one job.
set -euo pipefail
source /etc/containarium-runner.env

cd "$RUNNER_HOME"

# GH_API_BASE and GH_BASE_URL come from /etc/containarium-runner.env;
# they default to github.com / api.github.com when not set (back-compat
# for old env files written before GHES support landed).
GH_API_BASE="${GH_API_BASE:-https://api.github.com}"
GH_BASE_URL="${GH_BASE_URL:-https://github.com}"

# Mint a short-lived runner-registration token (valid ~1h).
REG_TOKEN=$(curl -sX POST \
  -H "Authorization: token $GH_PAT" \
  -H "Accept: application/vnd.github+json" \
  "${GH_API_BASE}/repos/${GH_REPO}/actions/runners/registration-token" \
  | jq -r '.token')

if [ -z "$REG_TOKEN" ] || [ "$REG_TOKEN" = "null" ]; then
  echo "Failed to mint registration token — check GH_PAT scope (needs 'repo')" >&2
  echo "GH_API_BASE in use: ${GH_API_BASE}" >&2
  exit 1
fi

# Clear any stale local registration left by a previous ephemeral job whose
# run.sh exited UNcleanly (box restart, OOM-kill, SIGKILL): config.sh aborts
# with "Cannot configure ... already configured" whenever .runner exists, and
# --replace does NOT bypass that local guard — it only resolves a server-side
# name collision. Without this cleanup the service crash-loops forever on
# "already configured" and never reaches run.sh, so the runner silently drops
# offline and CI jobs queue indefinitely. Removing these is safe: --replace
# below re-claims the name on GitHub's side.
rm -f .runner .credentials .credentials_rsaparams

# Register, run ONE job, exit. --replace overwrites any stale
# registration with the same name. --ephemeral makes run.sh exit
# after the first job completes (success or failure).
./config.sh \
  --url "${GH_BASE_URL}/${GH_REPO}" \
  --token "$REG_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "$RUNNER_LABELS" \
  --ephemeral --replace --unattended

./run.sh
EOF

# ---- systemd unit ----
cat > /etc/systemd/system/containarium-runner.service <<EOF
[Unit]
Description=Containarium ephemeral GitHub Actions runner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUNNER_USER}
WorkingDirectory=${RUNNER_HOME}
ExecStart=/usr/local/bin/containarium-runner-loop
# Respawn on exit — each iteration is one job. RestartSec=2 buffers a
# tiny gap so we don't hot-loop if GitHub is rejecting registrations.
Restart=always
RestartSec=2
# Capture stdout/stderr in the journal for easy debugging.
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# ---- enable + start ----
systemctl daemon-reload
systemctl enable --now containarium-runner.service

echo
echo "================================================================"
echo "  Runner '${RUNNER_NAME}' is registering with ${GH_REPO}."
echo "  GitHub server: ${GH_BASE_URL}"
echo "  Verify at: ${GH_BASE_URL}/${GH_REPO}/settings/actions/runners"
echo
echo "  Service: containarium-runner.service"
echo "  Logs:    journalctl -u containarium-runner -f"
echo "================================================================"
