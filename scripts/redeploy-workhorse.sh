#!/usr/bin/env bash
# redeploy-workhorse.sh — safe, reversible upgrades for the Containarium
# workhorse OSS daemon (the cloud-tenants pool host).
#
# WHY THIS EXISTS
# ---------------
# The workhorse daemon historically ran as a *bare, hand-launched* process
# (`containarium daemon … &`, parented to init, no auto-restart, env only in
# that process). Upgrading meant: back up the binary, swap it, kill the
# process, and relaunch it by hand with the exact flags AND environment. A
# single wrong flag / missing KMS env / a failed eBPF attach takes the host
# that runs EVERY tenant box offline, with nothing to auto-restart it.
#
# This script turns that into a systemd-managed, health-gated, auto-rolling
# operation. Run order on a host the first time:
#
#   sudo ./redeploy-workhorse.sh capture     # adopt the live invocation+env → unit (no disruption)
#   sudo ./redeploy-workhorse.sh diff        # review the generated unit + env keys
#   sudo ./redeploy-workhorse.sh cutover      # ONE restart: bare process → systemd (auto-rollback)
#
# Thereafter, an upgrade is just:
#
#   sudo ./redeploy-workhorse.sh deploy v0.26.3   # download, verify, swap, restart, health-gate, auto-rollback
#   sudo ./redeploy-workhorse.sh rollback         # undo to the previous binary
#   sudo ./redeploy-workhorse.sh status           # version + unit + eBPF + listener
#
# It is deliberately conservative: every state-changing step has a health gate
# and restores the prior binary (and, on cutover failure, the prior bare
# process) if the daemon doesn't come back healthy.
#
# CONCURRENCY (cloud postmortem, 2026-09-22): a local shell timeout killed an
# operator's `deploy` invocation, but the REMOTE process kept running
# unattended (SSH without a pty does not guarantee a remote command dies with
# the local client). A second `deploy` was then launched, racing the still-live
# first one on the same binary + unit: a torn write, a failed `exec`, and a
# ~16 minute outage. This script now refuses a second concurrent invocation
# outright (see acquire_lock) instead of racing.
set -euo pipefail

# ---- config (override via env) ---------------------------------------------
# Resolve through any symlink so every downstream decision (process-name
# detection, the release asset to download, what gets backed up/installed)
# is based on the binary that is ACTUALLY invoked, not a hardcoded guess.
# `install` (containarium.service's ExecStart, the Makefile's `make install`)
# lays down both the CLI-named compat symlink and containariumd as
# byte-identical/linked files (#1782), and per the containarium ->
# containariumd rename (#1781) the real install target is ALWAYS
# containariumd — the shorter name is legitimate only as that compat
# symlink. BIN_RAW is what got configured/exec'd (before resolving); BIN is
# the real file, resolved through any symlink, and is what every FILE
# operation (backup, install, current_version) acts on — content is shared
# either way, so operating on the real file is always correct there.
#
# PROCESS matching is a different story: Linux's `comm` (and argv[0] as
# read from /proc/<pid>/cmdline) reflects the LITERAL path a process was
# exec'd with, not its resolved realpath. A unit whose ExecStart names the
# compat symlink shows up in `ps` as "containarium" even though it's byte-
# identical to containariumd — readlink-ing BIN before matching processes
# fixes hosts that exec containariumd directly (2026-09-22's asia outage)
# but silently BREAKS hosts that exec the symlink instead, which is exactly
# as broken as the single hardcoded default this replaced. daemon_pid()
# therefore matches EITHER name rather than picking one.
BIN_RAW="${CTN_BIN:-/usr/local/bin/containariumd}"
BIN="$(readlink -f "$BIN_RAW" 2>/dev/null || echo "$BIN_RAW")"
# Was the unit pinned by the operator? Recorded BEFORE defaulting, because an
# explicit CTN_UNIT is a deliberate assertion we must not silently override —
# whereas the default is only a guess, and a wrong guess is what made this
# script capable of a false-success deploy (#1352).
CTN_UNIT_EXPLICIT=0
[ -n "${CTN_UNIT:-}" ] && CTN_UNIT_EXPLICIT=1
# Default to the unit the fleet ACTUALLY runs. Every workhorse (asia-east1 and
# us-west1, verified 2026-08-27) serves from containarium.service, installed by
# the host startup-script; containarium-daemon.service was this script's own
# invention and is inactive/disabled everywhere. Defaulting to the latter meant
# a deploy swapped the shared binary and then restarted a dead unit -- and, on
# a host where that unit file exists, could start a SECOND daemon fighting the
# live one for the HTTP/gRPC ports (#1352).
#
# deploy/redeploy-host.sh already forced CTN_UNIT=containarium.service to work
# around this; that override is now the default here, so the wrapper and the
# script agree instead of one compensating for the other.
UNIT_NAME="${CTN_UNIT:-containarium.service}"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
ENV_FILE="${CTN_ENV_FILE:-/etc/containarium/daemon.env}"
# The subcommand this host's daemon runs — how health detection recognises the
# process. Workhorses run `containarium daemon` (default); a sentinel runs
# `containarium sentinel`. Set CTN_SUBCMD=sentinel to roll a sentinel, or its
# health gate never finds the process and every deploy false-fails + rolls back.
SUBCMD="${CTN_SUBCMD:-daemon}"
HTTP_PORT="${CTN_HTTP_PORT:-8080}"
GH_REPO="${CTN_GH_REPO:-FootprintAI/Containarium}"
# Derived from BIN's (resolved) basename, so a host that execs containariumd
# downloads containariumd-linux-amd64 by default, matching the fleet's
# self-update convention (#1779) without needing a manual override. The two
# assets are byte-identical (#1782) so this is purely naming consistency, not
# a functional requirement.
RELEASE_ASSET="${CTN_ASSET:-$(basename "$BIN")-linux-amd64}"
HEALTH_TIMEOUT="${CTN_HEALTH_TIMEOUT:-60}"   # seconds to wait for a healthy daemon
LOCK_FILE="${CTN_LOCK_FILE:-/run/lock/containarium-redeploy-workhorse.lock}"

log() { printf '== %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "run as root (sudo)"; }

# Refuse a second concurrent invocation instead of racing it. Holds an flock
# on LOCK_FILE for the lifetime of this process (fd 9 closes, and the lock
# releases, on any exit — normal or `die`). Non-blocking: a second operator
# (or an orphaned first attempt that outlived its own caller) gets a clear
# refusal immediately, not a hang.
acquire_lock() {
  exec 9>"$LOCK_FILE" || die "cannot open lock file ${LOCK_FILE}"
  if ! flock -n 9; then
    die "another redeploy-workhorse.sh is already running against this host
  (lock: ${LOCK_FILE}). Refusing to run concurrently — this exact race (an
  orphaned first attempt + a second one racing it) caused a ~16 minute
  production outage on 2026-09-22. If you are certain no other invocation is
  actually running (e.g. the lock file is stale from a killed process), check
  \`fuser ${LOCK_FILE}\` before removing it by hand."
  fi
}

# Find the running daemon PID whether it's the bare process or systemd-managed.
# Anchor the match to the START of the cmdline ("<bin> daemon …") so it only
# ever matches the real daemon — NOT a bash wrapper, the containarium-runner-
# loop, this script, or the ssh session that's running it (all of which start
# with /bin/bash, not the binary path).
#
# Matches EITHER "containarium" or "containariumd" as the process name (see
# the BIN/BIN_RAW comment above for why): `pgrep -x` treats its argument as
# an extended regex requiring a full-string match, so 'containariumd?'
# matches exactly those two names and nothing else (never e.g.
# containarium-shell or containarium-runner-loop).
daemon_pid() {
  local p argv1
  for p in $(pgrep -x 'containariumd?' 2>/dev/null); do
    argv1="$(tr '\0' '\n' < "/proc/$p/cmdline" 2>/dev/null | sed -n '2p')"
    if [ "$argv1" = "$SUBCMD" ]; then echo "$p"; return 0; fi
  done
  # Fallback: anchored full-cmdline match against either the resolved real
  # path or the as-configured (possibly-symlink) path — whichever one this
  # host's unit actually execs.
  pgrep -f "^(${BIN}|${BIN_RAW}) ${SUBCMD}( |\$)" 2>/dev/null | head -1 || true
}

current_version() {
  "$BIN" version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown"
}

# Which systemd unit actually owns a PID? Read from its cgroup, which is the
# only authority — a unit NAME proves nothing about what is running.
#
# cgroup v2 gives a single line "0::/system.slice/containarium.service"; v1
# gives several, of which the systemd hierarchy is the one we want. Returns
# empty for a bare (non-systemd) process, which is a legitimate state here:
# `capture`/`cutover` exist precisely to adopt one.
unit_of_pid() {
  local pid="${1:-}" cg
  [ -n "$pid" ] || return 1
  cg="$(awk -F: '$2=="" || $2=="name=systemd" {print $3}' "/proc/$pid/cgroup" 2>/dev/null | head -1)"
  [ -n "$cg" ] || return 1
  # A non-service cgroup (a .scope, user.slice, a bare process) yields no
  # match. Return non-zero rather than an empty string with exit 0, so callers
  # can branch on either.
  local u
  u="$(printf '%s\n' "$cg" | grep -oE '[^/]+\.service' | tail -1)"
  [ -n "$u" ] || return 1
  printf '%s\n' "$u"
}

# Point UNIT_NAME at the unit that actually owns the live daemon.
#
# WHY (#1352): BIN is shared across units, so a deploy swaps the binary the
# LIVE daemon runs from, then restarts whatever UNIT_NAME happens to name. If
# that is not the owning unit, the live daemon is never restarted (and a
# disabled-but-present unit may even start a SECOND daemon that collides on
# the HTTP port). health_gate then matches the live process by cmdline shape
# and passes — so the script reports "deploy OK" having upgraded nothing.
# Observed on the asia-east1 primary: default containarium-daemon.service was
# inactive while containarium.service was serving.
resolve_unit() {
  local pid owner
  pid="$(daemon_pid)"
  if [ -z "$pid" ]; then
    log "no live '${SUBCMD}' process — proceeding with unit ${UNIT_NAME}"
    return 0
  fi
  owner="$(unit_of_pid "$pid" || true)"
  if [ -z "$owner" ]; then
    log "live daemon pid=${pid} is a bare process (no systemd unit) — proceeding with ${UNIT_NAME}"
    return 0
  fi
  if [ "$owner" = "$UNIT_NAME" ]; then
    return 0
  fi
  if [ "$CTN_UNIT_EXPLICIT" = 1 ]; then
    die "CTN_UNIT=${UNIT_NAME} but the live daemon (pid=${pid}) is owned by ${owner}.
  Refusing: acting on ${UNIT_NAME} would swap ${BIN} under ${owner} without restarting it.
  Re-run with CTN_UNIT=${owner}, or stop ${owner} first if you really mean ${UNIT_NAME}."
  fi
  log "NOTE: live daemon pid=${pid} is owned by ${owner}, not the default ${UNIT_NAME}"
  log "      retargeting this run at ${owner} (pass CTN_UNIT to pin it explicitly)"
  UNIT_NAME="$owner"
  UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
}

# --- health gate: the single source of "is the daemon OK after a change?" ---
# Hard gate (rollback if any fail):
#   1. process for ${BIN} daemon is alive
#   2. it's LISTENING on ${HTTP_PORT}
#   3. no panic / fatal in the unit's recent journal
# Soft check (warn only): the per-veth eBPF program is attached.
health_gate() {
  local deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  local ok_proc=0 ok_port=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ -n "$(daemon_pid)" ]; then ok_proc=1; else ok_proc=0; fi
    if ss -ltn 2>/dev/null | grep -q ":${HTTP_PORT} "; then ok_port=1; else ok_port=0; fi
    [ "$ok_proc" = 1 ] && [ "$ok_port" = 1 ] && break
    sleep 2
  done
  [ "$ok_proc" = 1 ] || { log "health: daemon process not running"; return 1; }
  [ "$ok_port" = 1 ] || { log "health: not listening on :${HTTP_PORT}"; return 1; }

  # The process AND the port can both belong to a daemon this run never
  # touched — that is exactly how a wrong-unit deploy used to report success
  # (#1352). Tie the evidence to the unit we acted on.
  local hp howner
  hp="$(daemon_pid)"
  howner="$(unit_of_pid "$hp" || true)"
  if [ -n "$howner" ] && [ "$howner" != "$UNIT_NAME" ]; then
    log "health: pid=${hp} is owned by ${howner}, not ${UNIT_NAME}"
    log "health: refusing to report success on another unit's process"
    return 1
  fi

  # Recent journal must not show a panic / fatal (only when systemd-managed).
  if systemctl list-unit-files "$UNIT_NAME" >/dev/null 2>&1; then
    if journalctl -u "$UNIT_NAME" --since "-${HEALTH_TIMEOUT}s" --no-pager 2>/dev/null \
        | grep -iqE 'panic:|fatal|level=error.*(start|listen|bpf|ebpf).*fail'; then
      log "health: panic/fatal in recent journal — see: journalctl -u ${UNIT_NAME} -n 80"
      return 1
    fi
  fi

  # Soft: confirm the eBPF traffic program attached (v0.26.3+). Don't fail the
  # gate on it (daemon can run degraded), but make it loud.
  if command -v bpftool >/dev/null 2>&1; then
    if bpftool prog show 2>/dev/null | grep -iqE 'sched_cls|sched_act|tc|cgroup_skb'; then
      log "health: eBPF program(s) attached (traffic collector OK)"
    else
      log "health: WARNING — no eBPF traffic program found; per-container network stats may be off"
    fi
  fi
  log "health: OK (version=$(current_version))"
  return 0
}

# ---- capture: adopt the live bare process into a systemd unit ---------------
cmd_capture() {
  need_root
  acquire_lock
  local pid; pid="$(daemon_pid)"
  [ -n "$pid" ] || die "no running '${BIN} daemon' process to capture"
  log "capturing live daemon pid=$pid (version=$(current_version))"

  # ExecStart from /proc/<pid>/cmdline (argv joined on NUL).
  local exec_start
  exec_start="$(tr '\0' ' ' < "/proc/$pid/cmdline" | sed 's/ *$//')"
  [ -n "$exec_start" ] || die "could not read /proc/$pid/cmdline"

  # Secret env from /proc/<pid>/environ. Keep only the daemon-relevant vars so
  # we don't copy the whole login environment. NEVER echo values.
  install -d -m 0750 "$(dirname "$ENV_FILE")"
  : > "$ENV_FILE"; chmod 0600 "$ENV_FILE"
  tr '\0' '\n' < "/proc/$pid/environ" \
    | grep -E '^(CONTAINARIUM_|GOOGLE_|GCLOUD_|OTEL_|CTN_|AWS_|KMS_)' \
    >> "$ENV_FILE" || true
  log "wrote env vars -> ${ENV_FILE}: $(grep -cE '=' "$ENV_FILE" 2>/dev/null || echo 0) keys (values not shown)"

  # Render the unit from the template, substituting the live ExecStart.
  local tmpl; tmpl="$(dirname "$0")/containarium.service"
  [ -f "$tmpl" ] || die "template not found: $tmpl"
  awk -v es="ExecStart=${exec_start}" '
    /^ExecStart=/ { print es; skip=1; next }
    skip && /^[^[:space:]]/ && !/^ExecStart=/ { skip=0 }
    skip { next }
    { print }
  ' "$tmpl" > "$UNIT_PATH"
  systemctl daemon-reload
  log "wrote ${UNIT_PATH} (NOT started). Review with: ./redeploy-workhorse.sh diff"
  log "ExecStart adopted: ${exec_start}"
}

cmd_diff() {
  echo "---- ${UNIT_PATH} ----"; sed -n '1,200p' "$UNIT_PATH" 2>/dev/null || echo "(no unit yet — run capture)"
  echo "---- ${ENV_FILE} (keys only) ----"
  [ -f "$ENV_FILE" ] && sed -E 's/=.*/=<redacted>/' "$ENV_FILE" || echo "(no env file)"
}

# ---- cutover: bare process -> systemd, exactly once -------------------------
cmd_cutover() {
  need_root
  acquire_lock
  [ -f "$UNIT_PATH" ] || die "no unit at ${UNIT_PATH} — run capture first"
  local pid; pid="$(daemon_pid)"
  # cutover means bare process -> systemd. If the daemon is ALREADY owned by a
  # unit, this host is past that step and cutover would fight it (#1352).
  local coowner; coowner="$(unit_of_pid "$pid" || true)"
  if [ -n "$coowner" ]; then
    die "daemon pid=${pid} is already systemd-managed by ${coowner} — cutover is not needed.
  To upgrade it:  CTN_UNIT=${coowner} $0 deploy <version>"
  fi
  local bare_cmd=""
  [ -n "$pid" ] && bare_cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | sed 's/ *$//')"

  log "stopping bare daemon (pid=${pid:-none}) and starting via systemd…"
  systemctl enable "$UNIT_NAME" >/dev/null 2>&1 || true
  # Stop the bare process (systemd start would otherwise hit the busy port).
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 15); do [ -z "$(daemon_pid)" ] && break; sleep 1; done

  if systemctl start "$UNIT_NAME" && health_gate; then
    log "cutover OK — daemon is now systemd-managed (${UNIT_NAME})"
    return 0
  fi

  log "CUTOVER FAILED — rolling back to the bare process"
  systemctl stop "$UNIT_NAME" 2>/dev/null || true
  systemctl disable "$UNIT_NAME" 2>/dev/null || true
  if [ -n "$bare_cmd" ]; then
    # Relaunch the original bare invocation so the host is not left down.
    # (Env: the bare process had it; a fresh relaunch here inherits the
    # operator's shell env — prefer running cutover from the same env, or
    # source ${ENV_FILE} first.)
    setsid bash -c "set -a; [ -f '${ENV_FILE}' ] && . '${ENV_FILE}'; exec ${bare_cmd}" \
      >/var/log/containarium-daemon.bare.log 2>&1 < /dev/null &
    sleep 3
    health_gate && log "rolled back to bare process" || die "ROLLBACK ALSO UNHEALTHY — manual intervention needed"
  else
    die "no prior bare command captured — manual intervention needed"
  fi
  return 1
}

# ---- deploy: upgrade the binary under systemd, with auto-rollback -----------
cmd_deploy() {
  need_root
  acquire_lock
  local ref="${1:?usage: deploy <version|path-to-binary>}"
  resolve_unit
  systemctl list-unit-files "$UNIT_NAME" >/dev/null 2>&1 \
    || die "daemon is not systemd-managed yet — run capture + cutover first"

  local src
  if [ -f "$ref" ]; then
    src="$ref"
  else
    local ver="${ref#v}"; local url="https://github.com/${GH_REPO}/releases/download/v${ver}/${RELEASE_ASSET}"
    local sums="https://github.com/${GH_REPO}/releases/download/v${ver}/SHA256SUMS.txt"
    src="$(mktemp)"
    log "downloading ${url}"
    curl -fsSL "$url" -o "$src" || die "download failed"
    # Best-effort checksum verify against the release SHA256SUMS.
    if curl -fsSL "$sums" -o "${src}.sums" 2>/dev/null; then
      local want; want="$(grep -E " ${RELEASE_ASSET}\$" "${src}.sums" | awk '{print $1}' | head -1)"
      local got; got="$(sha256sum "$src" | awk '{print $1}')"
      [ -n "$want" ] && [ "$want" != "$got" ] && die "checksum mismatch: want=$want got=$got"
      [ -n "$want" ] && log "checksum verified"
    fi
  fi
  chmod +x "$src"
  "$src" version >/dev/null 2>&1 || die "downloaded binary is not runnable"

  local oldver; oldver="$(current_version)"
  local bak="${BIN}.bak-${oldver}"
  log "backing up ${BIN} (${oldver}) -> ${bak}"
  cp -a "$BIN" "$bak"
  install -m 0755 "$src" "$BIN"

  log "restarting ${UNIT_NAME} onto $("$BIN" version 2>/dev/null | head -1)…"
  systemctl restart "$UNIT_NAME"
  if health_gate; then
    log "deploy OK — now on $(current_version)"
    return 0
  fi

  log "DEPLOY UNHEALTHY — rolling back to ${oldver}"
  install -m 0755 "$bak" "$BIN"
  systemctl restart "$UNIT_NAME"
  health_gate && log "rolled back to ${oldver}" || die "ROLLBACK UNHEALTHY — manual intervention needed"
  return 1
}

cmd_rollback() {
  need_root
  acquire_lock
  resolve_unit
  local bak; bak="$(ls -t "${BIN}".bak-* 2>/dev/null | head -1)"
  [ -n "$bak" ] || die "no ${BIN}.bak-* to roll back to"
  log "restoring ${bak} -> ${BIN}"
  install -m 0755 "$bak" "$BIN"
  systemctl restart "$UNIT_NAME" 2>/dev/null || true
  health_gate
}

cmd_status() {
  local spid sowner
  spid="$(daemon_pid)"
  sowner="$(unit_of_pid "$spid" || true)"
  echo "binary:  ${BIN} ($(current_version))   [file on disk, NOT necessarily what the live process is running]"
  echo "process: pid=${spid} listening :${HTTP_PORT}=$(ss -ltn 2>/dev/null | grep -q ":${HTTP_PORT} " && echo yes || echo NO)"
  echo "owned by: ${sowner:-<bare process / none>}"
  echo "expected: ${UNIT_NAME}"
  if [ -n "$sowner" ] && [ "$sowner" != "$UNIT_NAME" ]; then
    echo "WARNING: the live daemon is owned by ${sowner}, not ${UNIT_NAME}."
    echo "         deploy/rollback will retarget ${sowner} automatically."
    echo "         Do NOT run capture/cutover here — this host is already systemd-managed."
  fi
  if [ -z "$spid" ]; then
    echo "WARNING: no matching 'containarium(d)? ${SUBCMD}' process found — either the daemon is"
    echo "         genuinely down, or detection is wrong for this host (check CTN_BIN/CTN_SUBCMD)."
    echo "         Do not assume 'no output' means 'all clear' — investigate before deploying."
  fi
  systemctl status "${sowner:-$UNIT_NAME}" --no-pager -l 2>/dev/null | head -6 || echo "unit: not installed"
  command -v bpftool >/dev/null 2>&1 && echo "ebpf progs: $(bpftool prog show 2>/dev/null | grep -icE 'sched_cls|sched_act|tc|cgroup_skb')"
  echo "backups: $(ls -1 "${BIN}".bak-* 2>/dev/null | wc -l | tr -d ' ')"
}

case "${1:-}" in
  capture)  cmd_capture ;;
  diff)     cmd_diff ;;
  cutover)  cmd_cutover ;;
  deploy)   shift; cmd_deploy "${1:-}" ;;
  rollback) cmd_rollback ;;
  status)   cmd_status ;;
  *) cat >&2 <<USAGE
usage: $0 <command>
  capture          adopt the live bare daemon into ${UNIT_PATH} (+ ${ENV_FILE}); no restart
  diff             show the generated unit + env keys (review before cutover)
  cutover          switch the running daemon from bare process to systemd (one restart; auto-rollback)
  deploy <ver|bin> upgrade the binary + systemctl restart, health-gated, auto-rollback on failure
  rollback         restore the most recent ${BIN}.bak-* and restart
  status           current version, unit state, listener, eBPF prog count, backups
USAGE
     exit 2 ;;
esac
