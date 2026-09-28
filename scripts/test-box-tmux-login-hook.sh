#!/usr/bin/env bash
# Table test for the box login hook (#2121):
# pkg/core/container/tmux_login_hook.sh, installed as
# /etc/profile.d/containarium-tmux.sh in every box.
#
# Runs the REAL hook under a real shell on a real pty (python3's pty module),
# with a fake `tmux` on PATH that records its argv. Each row is one login
# shape; the assertion is whether the stub was asked for `new -A -s main`,
# and whether the shell fell through to a normal prompt afterwards.
#
# No image build and no sshd: the "ssh shapes" are reproduced by the three
# things sshd actually varies (login argv0 "-bash" or not, pty or not,
# SSH_TTY set or not). What this cannot prove is that a given sshd / IDE /
# mosh really produces those shapes; see the PR for that list.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK="$ROOT/pkg/core/container/tmux_login_hook.sh"
BASH_BIN="$(command -v bash)"
PY_BIN="$(command -v python3)"

for dep in python3 bash; do
  command -v "$dep" >/dev/null 2>&1 || { echo "SKIP: $dep not available"; exit 0; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- fake tmux ------------------------------------------------------------
# Records argv (one invocation per line) to $TMUX_STUB_LOG. `-V` succeeds
# unless TMUX_STUB_V_RC says otherwise; `new ...` exits TMUX_STUB_NEW_RC.
stub="$tmp/stubbin"
mkdir -p "$stub"
cat > "$stub/tmux" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> "$TMUX_STUB_LOG"
case "$1" in
  -V) echo "tmux 3.4-stub"; exit "${TMUX_STUB_V_RC:-0}" ;;
esac
exit "${TMUX_STUB_NEW_RC:-0}"
STUB
chmod +x "$stub/tmux"

# A PATH with the stub but WITHOUT any real tmux, and one with no tmux at all.
nobin="$tmp/nobin"
mkdir -p "$nobin"
for b in cat sh bash dash env mkdir; do
  p="$(command -v "$b" 2>/dev/null)" && ln -s "$p" "$nobin/$b"
done
PATH_STUB="$stub:$nobin"
PATH_NOTMUX="$nobin"

# mosh-server stand-in: a script NAMED mosh-server (so /proc/<pid>/comm of
# the parent reads "mosh-server", as for the real daemon) that starts the
# login shell as a CHILD, the way mosh-server does.
# The shebang must name bash directly: via /usr/bin/env the comm would be
# re-set to "bash" by env's own exec.
# shellcheck disable=SC2016 # expanded by the stub at run time, not here
{ echo "#!$BASH_BIN"; echo '( exec -a -bash "$REAL_BASH" --noprofile --norc -i )'; } > "$stub/mosh-server"
chmod +x "$stub/mosh-server"

# --- pty driver -----------------------------------------------------------
# run.py MODE ARGV0 PROG [ARGS...]
#   MODE=pty    child gets a fresh pty as stdin/stdout/stderr; we type the
#               probe line into it, as a user at a prompt would.
#   MODE=nopty  child's stdin is a pipe carrying the probe line (no tty),
#               like `ssh host <cmd>` without -t.
# Prints the child's output; exits with the child's exit status.
cat > "$tmp/run.py" <<'PY'
import os, pty, select, subprocess, sys, time
mode, argv0, prog, args = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
probe = os.environ["PROBE"].encode() + b"\n"
if mode == "nopty":
    p = subprocess.Popen([argv0] + args, executable=prog, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = p.communicate(probe, timeout=20)
    sys.stdout.write(out.decode(errors="replace"))
    sys.exit(p.returncode)
pid, fd = pty.fork()
if pid == 0:
    os.execv(prog, [argv0] + args)
os.write(fd, probe)
out = b""
deadline = time.time() + 20
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 0.5)
    if fd in r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
_, status = os.waitpid(pid, 0)
sys.stdout.write(out.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(status))
PY

# The probe the "user" types: source the hook the way /etc/profile does,
# then prove the shell is still alive. The marker is split in the source so
# the tty's echo of the typed line can never match it.
PROBE=". '$HOOK'; echo SHELL'-'CONTINUED; exit 7"

pass=0; fail=0
# row NAME EXPECT(fire|silent|fire-fallthrough) MODE ARGV0 PROG ARGS... -- ENV...
row() {
  local name="$1" expect="$2" mode="$3" argv0="$4" prog="$5"; shift 5
  local args=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do args+=("$1"); shift; done
  [ "${1:-}" = "--" ] && shift
  local home="$tmp/home-$pass-$fail"
  mkdir -p "$home"
  local log="$tmp/tmux-argv-$pass-$fail.log"
  : > "$log"
  local out rc
  out="$(env -i HOME="$home" TERM=xterm PATH="$PATH_STUB" TMUX_STUB_LOG="$log" \
           REAL_BASH="$BASH_BIN" PROBE="$PROBE" "$@" \
           "$PY_BIN" "$tmp/run.py" "$mode" "$argv0" "$prog" "${args[@]}" 2>&1)"
  rc=$?
  local invoked=no continued=no
  grep -qx 'new -A -s main' "$log" && invoked=yes
  printf '%s' "$out" | grep -q 'SHELL-CONTINUED' && continued=yes

  local ok=no
  case "$expect" in
    fire)             [ "$invoked" = yes ] && [ "$continued" = no ] && [ "$rc" -eq 0 ] && ok=yes ;;
    silent)           [ "$invoked" = no ] && [ "$continued" = yes ] && [ "$rc" -eq 7 ] && ok=yes ;;
    fire-fallthrough) [ "$invoked" = yes ] && [ "$continued" = yes ] && [ "$rc" -eq 7 ] && ok=yes ;;
  esac
  if [ "$ok" = yes ]; then
    echo "  PASS  $name (tmux new invoked: $invoked, shell continued: $continued, rc=$rc)"
    pass=$((pass+1))
  else
    echo "  FAIL  $name: expected $expect; tmux new invoked: $invoked, shell continued: $continued, rc=$rc"
    echo "        tmux argv log: $(tr '\n' '|' < "$log")"
    echo "        output: $(printf '%s' "$out" | tr -d '\r' | tail -5 | tr '\n' '|')"
    fail=$((fail+1))
  fi
}

LOGIN=(pty -bash "$BASH_BIN" --noprofile --norc -i)
TTY=SSH_TTY=/dev/pts/9

echo "box tmux login hook (#2121)"
row "interactive ssh login on a pty"                fire    "${LOGIN[@]}" -- "$TTY"
row "no SSH_TTY (IDE remote terminal)"              silent  "${LOGIN[@]}" -- SSH_CONNECTION="10.0.0.1 1 10.0.0.2 22"
row "TERM_PROGRAM=vscode"                           silent  "${LOGIN[@]}" -- "$TTY" TERM_PROGRAM=vscode
row "TERMINAL_EMULATOR=JetBrains-JediTerm"          silent  "${LOGIN[@]}" -- "$TTY" TERMINAL_EMULATOR=JetBrains-JediTerm
row "already inside tmux (TMUX set)"                silent  "${LOGIN[@]}" -- "$TTY" TMUX=/tmp/tmux-1000/default,1,0
row "inside screen (STY set)"                       silent  "${LOGIN[@]}" -- "$TTY" STY=1234.pts-0.box
row "opt-out: CONTAINARIUM_NO_TMUX=1"               silent  "${LOGIN[@]}" -- "$TTY" CONTAINARIUM_NO_TMUX=1
row "tmux missing from PATH (shell continues)"      silent  "${LOGIN[@]}" -- "$TTY" PATH="$PATH_NOTMUX"
row "tmux -V fails (shell continues)"               silent  "${LOGIN[@]}" -- "$TTY" TMUX_STUB_V_RC=1
row "tmux new fails (falls through to shell)"       fire-fallthrough "${LOGIN[@]}" -- "$TTY" TMUX_STUB_NEW_RC=1
row "ssh host <cmd>: no pty, non-interactive"       silent  nopty bash "$BASH_BIN" --noprofile --norc -s
row "ssh -t host <cmd>: pty, non-interactive"       silent  pty bash "$BASH_BIN" --noprofile --norc -c "eval \"\$PROBE\"" -- "$TTY"
row "login shell running a command (su - u -c), pty" silent  pty -bash "$BASH_BIN" --noprofile --norc -c "eval \"\$PROBE\"" -- "$TTY"
row "ssh -t host bash: pty, interactive, not login" silent  pty bash "$BASH_BIN" --noprofile --norc -i -- "$TTY"
row "interactive login but stdin is not a tty"      silent  nopty -bash "$BASH_BIN" --noprofile --norc -i -- "$TTY"
row "mosh: login shell whose parent is mosh-server" fire    pty mosh-server "$stub/mosh-server"

# Opt-out file: needs the file in the row's HOME before the shell starts.
optout_home="$tmp/home-optout"
mkdir -p "$optout_home/.containarium" && touch "$optout_home/.containarium/no-tmux"
row "opt-out: ~/.containarium/no-tmux"              silent  "${LOGIN[@]}" -- "$TTY" HOME="$optout_home"

# POSIX: the same hook under dash as a login shell, when dash is present.
if DASH_BIN="$(command -v dash 2>/dev/null)"; then
  row "dash login shell on a pty"                   fire    pty -sh "$DASH_BIN" -i -- "$TTY"
  row "dash login shell, opt-out env"               silent  pty -sh "$DASH_BIN" -i -- "$TTY" CONTAINARIUM_NO_TMUX=1
else
  echo "  SKIP  dash rows: dash not installed"
fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
