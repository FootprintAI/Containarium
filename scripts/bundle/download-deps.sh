#!/bin/bash
# download-deps.sh — pulls toolchain tarballs + .deb packages into the
# bundle staging directory, for the air-gapped install bundle.
#
# Per prd/cloud/air-gapped-install-bundle.md (E3a), the bundle ships:
#
#   - Go toolchain (runner kit uses it for buf install + Go CI jobs)
#   - Node + pnpm (runner kit uses it for frontend builds)
#   - buf (proto codegen)
#   - golangci-lint (Go linting)
#   - actions-runner (GitHub Actions self-hosted runner binary)
#   - Incus debs + ZFS utils + base apt deps (no internet during install)
#
# Required env (or default):
#
#   STAGING_DIR    where to write tarballs (default: dist/bundle-cache)
#   OS             linux (only OS supported today)
#   ARCH           amd64 | arm64
#   GO_VERSION     pinned in the script (override if bumping)
#   NODE_VERSION
#   PNPM_VERSION
#   BUF_VERSION     pinned in scripts/buf-version.env (not overridden)
#   GOLANGCI_LINT_VERSION
#   RUNNER_VERSION
#   DEPS_ONLY      all (default) | toolchains | apt — run only one half,
#                  e.g. toolchains on a non-Debian laptop, apt on an Ubuntu
#                  builder
#   APT_PACKAGES   space-separated packages to bundle with their dependency
#                  closure (default: the list below)
#   APT_BATCH_SIZE packages per `apt-get download` call (default 25); each
#                  batch is logged, so a stall shows which batch it is in
#   GITHUB_STEP_SUMMARY  when set (GitHub Actions), the step's result,
#                  duration and package count are appended to it
#
# Outputs (under $STAGING_DIR):
#
#   toolchains/go${GO_VERSION}.${OS}-${ARCH}.tar.gz
#   toolchains/node-v${NODE_VERSION}-${OS}-${node_arch}.tar.xz
#   toolchains/pnpm-${PNPM_VERSION}-${OS}-${node_arch}
#   toolchains/buf-${OS}-${buf_arch}
#   toolchains/golangci-lint-${GOLANGCI_LINT_VERSION}-${OS}-${ARCH}.tar.gz
#   bin/actions-runner-${OS}-${runner_arch}-${RUNNER_VERSION}.tar.gz
#   apt/*.deb
#
# Idempotent — re-runs skip already-downloaded files (checks file
# existence; does NOT re-validate checksums beyond what curl returns).
#
# NOTE on apt downloads: requires `apt-get` and `dpkg-deb` on an Ubuntu host
# of the target release (after `apt-get update`), and
# the Zabbly repo for incus (scripts/bundle/add-zabbly-repo.sh). Any apt error,
# a missing tool, or a dependency the bundle cannot satisfy fails the script
# (#3061). See scripts/bundle/README.md.

set -euo pipefail

# ---- defaults ----
STAGING_DIR="${STAGING_DIR:-dist/bundle-cache}"
OS="${OS:-linux}"
ARCH="${ARCH:-amd64}"

# Toolchain versions — pin precisely per PRD reproducibility requirement.
GO_VERSION="${GO_VERSION:-1.25.10}"
NODE_VERSION="${NODE_VERSION:-22.11.0}"
PNPM_VERSION="${PNPM_VERSION:-9.12.3}"
source "$(dirname "$0")/../buf-version.env"
GOLANGCI_LINT_VERSION="${GOLANGCI_LINT_VERSION:-2.1.6}"
RUNNER_VERSION="${RUNNER_VERSION:-2.319.1}"

DEPS_ONLY="${DEPS_ONLY:-all}"
case "$DEPS_ONLY" in
  all|toolchains|apt) ;;
  *) echo "DEPS_ONLY must be all, toolchains or apt (got: $DEPS_ONLY)" >&2; exit 1 ;;
esac

APT_BATCH_SIZE="${APT_BATCH_SIZE:-25}"
if ! [[ "$APT_BATCH_SIZE" =~ ^[1-9][0-9]*$ ]]; then
  echo "APT_BATCH_SIZE must be a positive integer (got: $APT_BATCH_SIZE)" >&2
  exit 1
fi

# What install.sh would apt-get install on a connected host: runner-kit deps,
# ZFS, and incus/incus-client/incus-extra from the Zabbly stable repo.
APT_PACKAGES="${APT_PACKAGES:-curl wget gnupg ca-certificates software-properties-common jq zfsutils-linux build-essential libicu-dev git incus incus-client incus-extra}"

# Network bounds for every apt call (#3118). Without them one stalled HTTPS
# connection held `apt-get download` silent for 46 minutes. A connection idle
# for 30s now fails and is retried 3 times; apt's error then names the URL.
APT_NET_OPTS=(-o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=3)
APT_PKG_COUNT=""   # resolved package count, for the job summary

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[deps]${NC} $1"; }
log_success() { echo -e "${GREEN}[deps]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[deps]${NC} $1"; }
log_error()   { echo -e "${RED}[deps]${NC} $1" >&2; }

# Map ARCH → vendor-specific naming conventions.
# Go uses linux-amd64 / linux-arm64.
# Node uses linux-x64 / linux-arm64.
# buf uses Linux-x86_64 / Linux-aarch64.
# golangci-lint uses linux-amd64 / linux-arm64.
# actions-runner uses linux-x64 / linux-arm64.
case "$ARCH" in
  amd64)
    NODE_ARCH="x64"
    BUF_ARCH="x86_64"
    RUNNER_ARCH="x64"
    ;;
  arm64)
    NODE_ARCH="arm64"
    BUF_ARCH="aarch64"
    RUNNER_ARCH="arm64"
    ;;
  *)
    log_error "Unsupported ARCH: $ARCH (expected amd64 or arm64)"
    exit 1
    ;;
esac

# Capitalised OS for buf (Linux vs linux).
case "$OS" in
  linux)
    BUF_OS="Linux"
    ;;
  *)
    log_error "Unsupported OS: $OS (expected linux)"
    exit 1
    ;;
esac

mkdir -p "$STAGING_DIR/toolchains" "$STAGING_DIR/bin" "$STAGING_DIR/apt"

# fetch <url> <output-path>
# Skip if the output already exists and is non-empty (idempotent re-runs).
fetch() {
  local url="$1" out="$2"
  if [ -s "$out" ]; then
    log_info "skip (cached): $(basename "$out")"
    return 0
  fi
  log_info "fetch: $url"
  # -L follow redirects; -f fail on HTTP error; --retry 3 buffers flaky
  # network without masking persistent failure.
  if ! curl -fL --retry 3 --retry-delay 2 -o "$out.partial" "$url"; then
    log_error "fetch failed: $url"
    rm -f "$out.partial"
    return 1
  fi
  mv "$out.partial" "$out"
  log_success "fetched: $(basename "$out")"
}

# ---- Go ----
download_go() {
  local file="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
  fetch "https://go.dev/dl/${file}" "$STAGING_DIR/toolchains/${file}"
}

# ---- Node ----
download_node() {
  # Node tarballs for linux use .tar.xz; for darwin .tar.gz. We only
  # ship linux today so xz is fine.
  local file="node-v${NODE_VERSION}-${OS}-${NODE_ARCH}.tar.xz"
  fetch "https://nodejs.org/dist/v${NODE_VERSION}/${file}" \
        "$STAGING_DIR/toolchains/${file}"
}

# ---- pnpm ----
download_pnpm() {
  # pnpm publishes raw binaries (no tarball wrapper) named like
  # pnpm-linux-x64 / pnpm-linux-arm64 via GitHub releases.
  local file="pnpm-${OS}-${NODE_ARCH}"
  fetch "https://github.com/pnpm/pnpm/releases/download/v${PNPM_VERSION}/${file}" \
        "$STAGING_DIR/toolchains/pnpm-${PNPM_VERSION}-${OS}-${NODE_ARCH}"
}

# ---- buf ----
download_buf() {
  # Share CI's pin and checksum validation, including on cached-file reruns.
  "$(dirname "$0")/../install-buf.sh" \
    "$STAGING_DIR/toolchains/buf-${BUF_VERSION}-${OS}-${ARCH}" "$BUF_OS" "$BUF_ARCH"
}

# ---- golangci-lint ----
download_golangci_lint() {
  local file="golangci-lint-${GOLANGCI_LINT_VERSION}-${OS}-${ARCH}.tar.gz"
  fetch "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}/${file}" \
        "$STAGING_DIR/toolchains/${file}"
}

# ---- actions-runner ----
download_actions_runner() {
  local file="actions-runner-${OS}-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz"
  fetch "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${file}" \
        "$STAGING_DIR/bin/${file}"
}

# ---- apt packages ----
# Downloads the .debs install.sh would pull on a connected host, plus their
# whole Depends/Pre-Depends closure, into $STAGING_DIR/apt/.
#
# Fails loudly (#3061). It used to filter apt's `E:` lines and discard the
# exit status, so a release bundle shipped an empty apt/ from a green step.
# The causes are handled on purpose here:
#
#   - The closure came from `apt-rdepends`, which lists virtual names
#     (debconf-2.0, logind, default-dbus-system-bus, ...) and removed
#     alternatives (mime-support) but never follows a virtual name to the
#     package that provides it. One such name made the single
#     `apt-get download` call fail and fetch nothing, and skipping them would
#     still have left out dbus, libpam-systemd and friends. apt's own
#     resolver now picks the set: `apt-get install -s` against an empty dpkg
#     status lists every package a fresh host would need, providers of
#     virtual names included, and exactly those name=version pairs are
#     downloaded. Recommends are not followed (--no-install-recommends).
#   - incus, incus-client and incus-extra come from the Zabbly stable repo,
#     as on a connected install (hacks/install.sh); Ubuntu has no
#     incus-extra. Add the repo first with scripts/bundle/add-zabbly-repo.sh.
#     A requested package apt cannot locate fails the resolver step.
#   - check_apt_closure then proves the result independently of apt: a .deb
#     for every requested package, and every Depends/Pre-Depends group of
#     every downloaded .deb met inside the bundle.
#
# Run it on the Ubuntu release the bundle targets (24.04), after
# `apt-get update`: the .debs are only valid for that release.
download_apt_packages() {
  local tool missing_tool=0
  for tool in apt-get dpkg-deb; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      log_error "$tool not found; the apt step needs it"
      missing_tool=1
    fi
  done
  if [ "$missing_tool" = 1 ]; then
    log_error "Run the apt step on an Ubuntu builder of the target release, or run"
    log_error "with DEPS_ONLY=toolchains and put the .debs into $STAGING_DIR/apt/ yourself."
    return 1
  fi

  local apt_dir="$STAGING_DIR/apt" work sim
  local pkgs=() fetch=()
  read -r -a pkgs <<<"$APT_PACKAGES"
  if [ "${#pkgs[@]}" -eq 0 ]; then
    log_error "APT_PACKAGES is empty"
    return 1
  fi

  work="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand now: $work is local
  trap "rm -rf '$work'; trap - RETURN" RETURN
  : >"$work/status"   # empty dpkg status: resolve as for a host with nothing installed

  log_info "Resolving the install set of: ${pkgs[*]}"
  if ! sim="$(apt-get install -s --no-install-recommends "${APT_NET_OPTS[@]}" \
                -o Dir::State::status="$work/status" -o Debug::NoLocking=1 \
                "${pkgs[@]}")"; then
    log_error "apt could not resolve the package set (see the apt error above)."
    log_error "Is every repo configured? incus* need scripts/bundle/add-zabbly-repo.sh."
    return 1
  fi
  # `Inst <name> (<version> <origin> [<arch>])`
  mapfile -t fetch < <(awk '$1 == "Inst" { v = $3; sub(/^\(/, "", v); print $2 "=" v }' <<<"$sim")
  if [ "${#fetch[@]}" -eq 0 ]; then
    log_error "apt resolved an empty install set"
    return 1
  fi

  # Batched (#3118): the log shows which batch is in flight, so a stall is
  # placed to a few packages instead of the whole set.
  APT_PKG_COUNT="${#fetch[@]}"
  local batches=$(( (${#fetch[@]} + APT_BATCH_SIZE - 1) / APT_BATCH_SIZE ))
  local b i batch=()
  log_info "Resolved ${#fetch[@]} packages; downloading into $apt_dir/ in $batches batch(es) of up to $APT_BATCH_SIZE"
  for (( b = 1, i = 0; i < ${#fetch[@]}; b++, i += APT_BATCH_SIZE )); do
    batch=("${fetch[@]:i:APT_BATCH_SIZE}")
    log_info "batch $b/$batches: ${#batch[@]} packages (${batch[0]%%=*} .. ${batch[-1]%%=*})"
    if ! (cd "$apt_dir" && apt-get download "${APT_NET_OPTS[@]}" "${batch[@]}"); then
      log_error "apt-get download failed in batch $b/$batches (apt's error above names the host)"
      return 1
    fi
  done

  check_apt_closure "$apt_dir" "${pkgs[@]}"
  log_success "apt packages downloaded: $(find "$apt_dir" -maxdepth 1 -name '*.deb' | wc -l) .deb files"
}

# check_apt_closure DIR REQUIRED...
# Fails unless DIR holds a .deb for every REQUIRED package and every
# Depends/Pre-Depends group of every .deb in DIR is met by a package in DIR
# or one of its Provides. Matching is by name: the versions are whatever apt
# resolved from one archive snapshot, and dpkg checks them at install time.
check_apt_closure() {
  local dir="$1"; shift
  local -A have=() pkgname=()
  local debs=() deb p field value group alt ok n
  local groups=() alts=() unmet=() absent=()
  shopt -s nullglob
  debs=("$dir"/*.deb)
  shopt -u nullglob
  if [ "${#debs[@]}" -eq 0 ]; then
    log_error "No .deb files in $dir"
    return 1
  fi

  for deb in "${debs[@]}"; do
    p="$(dpkg-deb -f "$deb" Package)"
    pkgname[$deb]="$p"
    have[$p]=1
    value="$(dpkg-deb -f "$deb" Provides | tr '\n' ' ')"
    IFS=',' read -r -a groups <<<"$value"
    for alt in "${groups[@]}"; do
      alt="$(dep_name "$alt")"
      [ -n "$alt" ] && have[$alt]=1
    done
  done

  for n in "$@"; do
    if ! printf '%s\n' "${pkgname[@]}" | grep -qxF -- "$n"; then
      absent+=("$n")
    fi
  done

  for deb in "${debs[@]}"; do
    for field in Pre-Depends Depends; do
      value="$(dpkg-deb -f "$deb" "$field" | tr '\n' ' ')"
      [ -z "${value// /}" ] && continue
      IFS=',' read -r -a groups <<<"$value"
      for group in "${groups[@]}"; do
        ok=0
        IFS='|' read -r -a alts <<<"$group"
        for alt in "${alts[@]}"; do
          alt="$(dep_name "$alt")"
          if [ -n "$alt" ] && [ -n "${have[$alt]:-}" ]; then ok=1; break; fi
        done
        if [ "$ok" = 0 ]; then
          unmet+=("${pkgname[$deb]} $field:${group}")
        fi
      done
    done
  done

  if [ "${#absent[@]}" -gt 0 ]; then
    log_error "No .deb downloaded for requested package(s): ${absent[*]}"
  fi
  if [ "${#unmet[@]}" -gt 0 ]; then
    log_error "${#unmet[@]} dependency group(s) not met inside the bundle:"
    for n in "${unmet[@]}"; do log_error "  $n"; done
  fi
  if [ "${#absent[@]}" -gt 0 ] || [ "${#unmet[@]}" -gt 0 ]; then
    return 1
  fi
  log_success "Dependency closure OK: ${#debs[@]} .deb files, every Depends/Pre-Depends met"
}

# dep_name " libfoo:any (>= 1.2) " -> libfoo
dep_name() {
  local a="$1"
  a="${a%%(*}"; a="${a%%\[*}"; a="${a%%<*}"
  a="${a//[[:space:]]/}"
  echo "${a%%:*}"
}

# write_summary EXIT_STATUS: one line in the GitHub job summary, so a slow or
# failed step is visible without opening the log (#3118).
write_summary() {
  local rc="$1" result pkgs=""
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  if [ "$rc" -eq 0 ]; then result="ok in ${SECONDS}s"; else result="failed after ${SECONDS}s (exit $rc)"; fi
  [ -n "$APT_PKG_COUNT" ] && pkgs=", $APT_PKG_COUNT apt packages in batches of $APT_BATCH_SIZE"
  echo "**Download bundle dependencies** ($DEPS_ONLY): $result$pkgs." \
       "Expected: a few minutes on a healthy run; build-bundle times out at 30 minutes." \
       >>"$GITHUB_STEP_SUMMARY" || true
}

main() {
  SECONDS=0
  trap 'write_summary $?' EXIT
  log_info "Staging dir: $STAGING_DIR"
  log_info "Target:      $OS/$ARCH"
  log_info "Steps:       $DEPS_ONLY"
  log_info "Versions:    Go $GO_VERSION  Node $NODE_VERSION  pnpm $PNPM_VERSION"
  log_info "             buf $BUF_VERSION  golangci-lint $GOLANGCI_LINT_VERSION"
  log_info "             actions-runner $RUNNER_VERSION"
  echo

  case "$DEPS_ONLY" in
    all|toolchains)
      download_go
      download_node
      download_pnpm
      download_buf
      download_golangci_lint
      download_actions_runner
      ;;
  esac
  case "$DEPS_ONLY" in
    all|apt) download_apt_packages ;;
  esac

  echo
  log_success "All downloads complete. Staging tree:"
  if command -v find >/dev/null 2>&1; then
    find "$STAGING_DIR" -maxdepth 3 -type f | sort
  fi
}

main "$@"
