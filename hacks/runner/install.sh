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
#               https://github.com/settings/tokens (classic) or App
#               installation tokens.
#   RUNNER_NAME (optional) name for this runner; defaults to the box
#               hostname. Visible in GitHub's Actions → Runners list.
#   RUNNER_LABELS (optional) comma-separated runner labels; defaults
#               to "containarium,ephemeral". Workflows target with
#               `runs-on: [self-hosted, containarium, ephemeral]`.
#
# Usage from outside the box:
#
#   containarium create runner-1
#   ssh runner-1 'curl -fsSL https://raw.githubusercontent.com/footprintai/containarium/main/hacks/runner/install.sh \
#     | sudo GH_REPO=FootprintAI/Containarium-cloud GH_PAT=ghp_xxx bash'
#
# After this runs, the runner registers itself within ~30s and starts
# accepting jobs. Verify at
# https://github.com/<owner>/<repo>/settings/actions/runners.

set -euo pipefail

# ---- input validation ----
: "${GH_REPO:?GH_REPO is required (org/repo)}"
: "${GH_PAT:?GH_PAT is required (PAT with repo scope)}"

RUNNER_NAME="${RUNNER_NAME:-$(hostname -s)}"
RUNNER_LABELS="${RUNNER_LABELS:-containarium,ephemeral}"
RUNNER_VERSION="${RUNNER_VERSION:-2.319.1}"
RUNNER_USER="${RUNNER_USER:-ghrunner}"
RUNNER_HOME="${RUNNER_HOME:-/opt/actions-runner}"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) RUNNER_ARCH=x64 ;;
  aarch64|arm64) RUNNER_ARCH=arm64 ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# ---- system deps ----
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl jq git build-essential libicu-dev

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

# golangci-lint v2 (latest minor; pin if reproducibility matters)
if ! command -v golangci-lint >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b /usr/local/bin
fi

# ---- runner user + binary ----
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd -m -d "$RUNNER_HOME" -s /bin/bash "$RUNNER_USER"
fi

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
RUNNER_NAME=${RUNNER_NAME}
RUNNER_LABELS=${RUNNER_LABELS}
RUNNER_HOME=${RUNNER_HOME}
EOF
chmod 600 /etc/containarium-runner.env

# ---- run-loop script ----
install -m 0755 /dev/stdin /usr/local/bin/containarium-runner-loop <<'EOF'
#!/bin/bash
# Ephemeral-runner respawn loop. One iteration = one job.
set -euo pipefail
source /etc/containarium-runner.env

cd "$RUNNER_HOME"

# Mint a short-lived runner-registration token (valid ~1h).
REG_TOKEN=$(curl -sX POST \
  -H "Authorization: token $GH_PAT" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${GH_REPO}/actions/runners/registration-token" \
  | jq -r '.token')

if [ -z "$REG_TOKEN" ] || [ "$REG_TOKEN" = "null" ]; then
  echo "Failed to mint registration token — check GH_PAT scope (needs 'repo')" >&2
  exit 1
fi

# Register, run ONE job, exit. --replace overwrites any stale
# registration with the same name. --ephemeral makes run.sh exit
# after the first job completes (success or failure).
./config.sh \
  --url "https://github.com/${GH_REPO}" \
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
echo "  Verify at: https://github.com/${GH_REPO}/settings/actions/runners"
echo
echo "  Service: containarium-runner.service"
echo "  Logs:    journalctl -u containarium-runner -f"
echo "================================================================"
