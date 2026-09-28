#!/usr/bin/env bash
# shellcheck disable=SC2016 # remote commands: $VARS expand on the box, not here
# Image smoke + e2e for #2121 (mosh-server + tmux-on-login in the box).
#
# Builds an Ubuntu 24.04 image with the packages the daemon adds to every
# Debian-family box (tmux, mosh; see pkg/core/ospkg/debian.go) and the login
# hook it writes (pkg/core/container/tmux_login_hook.sh ->
# /etc/profile.d/containarium-tmux.sh), with a normal adduser'd user and a
# stock OpenSSH sshd. Then, over REAL ssh:
#   - mosh-server --version and tmux -V run for the box user;
#   - two interactive logins land in ONE tmux session "main" (2 clients);
#   - ssh host <cmd>, ssh -t host <cmd> and sftp are left alone;
#   - the ~/.containarium/no-tmux opt-out gives a plain shell.
#
# This is not the Incus provisioning path itself (that needs an Incus host;
# the incus-create lane covers creates); it proves the packages and the hook
# behave under a real sshd. Needs podman or docker; skips cleanly otherwise.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK="$ROOT/pkg/core/container/tmux_login_hook.sh"

ENGINE=""
for e in podman docker; do
  if command -v "$e" >/dev/null 2>&1 && "$e" info >/dev/null 2>&1; then ENGINE="$e"; break; fi
done
if [ -z "$ENGINE" ]; then
  echo "SKIP: neither podman nor docker is usable here; the image smoke test needs one"
  exit 0
fi
for dep in ssh ssh-keygen sftp; do
  command -v "$dep" >/dev/null 2>&1 || { echo "SKIP: $dep not available"; exit 0; }
done

tmp="$(mktemp -d)"
name="containarium-box-login-$$"
img="localhost/containarium-box-login-test:$$"
bgpids=()
cleanup() {
  for p in "${bgpids[@]}"; do kill "$p" 2>/dev/null; done
  "$ENGINE" rm -f "$name" >/dev/null 2>&1
  "$ENGINE" rmi -f "$img" >/dev/null 2>&1
  rm -rf "$tmp"
}
trap cleanup EXIT

pass=0; fail=0
check() { # name, then a command whose success is the assertion
  local n="$1"; shift
  if "$@"; then echo "  PASS  $n"; pass=$((pass+1)); else echo "  FAIL  $n"; fail=$((fail+1)); fi
}

cp "$HOOK" "$tmp/containarium-tmux.sh"
ssh-keygen -q -t ed25519 -N "" -f "$tmp/id" >/dev/null
cp "$tmp/id.pub" "$tmp/authorized_keys"
cat > "$tmp/Containerfile" <<'CF'
FROM docker.io/library/ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server tmux mosh \
 && rm -rf /var/lib/apt/lists/* \
 && adduser --disabled-password --gecos "" boxuser \
 && mkdir -p /run/sshd /home/boxuser/.ssh
COPY containarium-tmux.sh /etc/profile.d/containarium-tmux.sh
COPY authorized_keys /home/boxuser/.ssh/authorized_keys
RUN chmod 0644 /etc/profile.d/containarium-tmux.sh \
 && chown -R boxuser:boxuser /home/boxuser/.ssh && chmod 700 /home/boxuser/.ssh \
 && chmod 600 /home/boxuser/.ssh/authorized_keys \
 && ssh-keygen -A
CMD ["/usr/sbin/sshd", "-D", "-e", "-p", "2222"]
CF

echo "box login extras image (#2121) via $ENGINE"
if ! "$ENGINE" build -q -t "$img" "$tmp" >"$tmp/build.log" 2>&1; then
  echo "  FAIL  image build"; tail -20 "$tmp/build.log"; exit 1
fi

check "mosh-server --version runs for the box user" \
  "$ENGINE" run --rm --user boxuser "$img" sh -c 'mosh-server --version >/dev/null 2>&1'
check "tmux -V runs for the box user" \
  "$ENGINE" run --rm --user boxuser "$img" sh -c 'tmux -V >/dev/null' 

port=$((20000 + RANDOM % 20000))
"$ENGINE" run -d --name "$name" -p "127.0.0.1:$port:2222" "$img" >/dev/null || { echo "  FAIL  start sshd"; exit 1; }
SSH=(ssh -F /dev/null -i "$tmp/id" -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o LogLevel=ERROR -o ConnectTimeout=5 boxuser@127.0.0.1)
for _ in $(seq 1 30); do "${SSH[@]}" true 2>/dev/null && break; sleep 1; done

# Holds an interactive login open: stdin is a fifo nobody writes to, so the
# remote tmux client stays attached until we kill the ssh.
login_bg() {
  local fifo="$tmp/fifo-$1"; mkfifo "$fifo"
  sleep 600 > "$fifo" & bgpids+=("$!")
  TERM=xterm "${SSH[@]}" -tt < "$fifo" > "$tmp/login-$1.out" 2>&1 & bgpids+=("$!")
}
count_clients() { "${SSH[@]}" 'tmux list-clients -t main 2>/dev/null | wc -l' 2>/dev/null | tr -d '[:space:]'; }
wait_clients() { # want
  for _ in $(seq 1 20); do [ "$(count_clients)" = "$1" ] && return 0; sleep 0.5; done; return 1
}

login_bg 1
check "first interactive login starts tmux session main" wait_clients 1
login_bg 2
check "second interactive login attaches to the same session (2 clients)" wait_clients 2
check "exactly one tmux session exists" \
  test "$("${SSH[@]}" 'tmux ls -F "#{session_name}"')" = "main"

out="$("${SSH[@]}" 'echo "tmux=[${TMUX:-}]"; tty' 2>&1)"
check "ssh host <cmd>: no tmux, no pty, output intact" \
  test "$out" = "$(printf 'tmux=[]\nnot a tty')"
out="$(TERM=xterm "${SSH[@]}" -tt 'echo "tmux=[${TMUX:-}]"' 2>&1 < /dev/null | tr -d '\r')"
check "ssh -t host <cmd>: runs the command, not tmux" test "$out" = "tmux=[]"
check "ssh -t host <cmd>: no extra tmux client appeared" wait_clients 2
check "sftp works (hook is silent for the subsystem)" \
  sh -c "echo pwd | sftp -F /dev/null -i '$tmp/id' -P '$port' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -b - boxuser@127.0.0.1 >/dev/null 2>&1"

"${SSH[@]}" 'mkdir -p ~/.containarium && touch ~/.containarium/no-tmux'
out="$(printf 'echo "optout""-tmux=[${TMUX:-}]"\nexit\n' | TERM=xterm "${SSH[@]}" -tt 2>&1 | tr -d '\r')"
check "opt-out file: interactive login gets a plain shell" \
  sh -c 'printf "%s" "$1" | grep -q "optout-tmux=\[\]"' _ "$out"
check "opt-out file: no new tmux client" wait_clients 2

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
