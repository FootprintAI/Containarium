#!/usr/bin/env bash
#
# code-run-fake-agent-e2e.sh — plumbing e2e for `containarium code
# run/status/attach/stop` using a FAKE agent, so it needs no model, no
# Anthropic credits and no `claude setup-token`.
#
# `code run` executes `~/.local/bin/claude -p '<prompt>' [--output-format
# stream-json]` on the box (internal/coderun/ops.go). This script swaps that
# path for a stub whose behaviour is chosen by the prompt, then proves the
# transport around the agent: launch, streaming, quoting, framed capture,
# detach/reattach, stop, and same-box concurrency. It says NOTHING about
# whether a real agent does good work — that is the (blocked) real-agent lane.
#
# Requirements:
#   - a built CLI (default ./bin/containarium; override with CONTAINARIUM_BIN)
#   - a logged-in CLI / CONTAINARIUM_SERVER + token for the target daemon
#   - an EXISTING box you may scribble on: E2E_BOX=<box>
#     (the script backs up and restores any real ~/.local/bin/claude)
#
# Usage:
#   E2E_BOX=<box> bash scripts/code-run-fake-agent-e2e.sh
#
# Prove-it-can-fail: E2E_SABOTAGE=silent-agent makes the stub print nothing,
# so the streaming assertions MUST go red:
#   E2E_SABOTAGE=silent-agent E2E_BOX=<box> bash scripts/code-run-fake-agent-e2e.sh; echo $?  # non-zero
#
# KNOWN GAP surfaced while writing this: `code status` prints only the
# "<icon> <name> (pid N, exited)" header line, not the exit code, even though
# its --help promises one. So a failing agent is indistinguishable from a
# passing one via `code status`; assertion 5 pins today's behaviour and says so.

set -uo pipefail

BIN="${CONTAINARIUM_BIN:-./bin/containarium}"
BOX="${E2E_BOX:?set E2E_BOX=<an existing box to run the fake agent on>}"
SABOTAGE="${E2E_SABOTAGE:-}"
RUN="e2e-$$"                       # unique run-name prefix; never collides with "code"
WORK="$(mktemp -d)"
REMOTE_CLAUDE='$HOME/.local/bin/claude'
FAILS=0
PIDS=()

ok()   { echo "OK   $*"; }
fail() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }
box_exec() { "$BIN" connect "$BOX" --exec "$1"; }
code() { "$BIN" code "$1" "$BOX" "${@:2}"; }

assert_contains() { # <desc> <haystack> <needle>
  if grep -qF -- "$3" <<<"$2"; then ok "$1"; else fail "$1 — missing '$3' in: $(head -c 300 <<<"$2")"; fi
}
assert_not_contains() {
  if grep -qF -- "$3" <<<"$2"; then fail "$1 — unexpected '$3'"; else ok "$1"; fi
}
wait_status() { # <name> <regex> <secs>
  local end=$((SECONDS + $3)) out
  while [ $SECONDS -lt $end ]; do
    out="$(code status --name "$1" 2>&1)"
    grep -qE "$2" <<<"$out" && { echo "$out"; return 0; }
    sleep 1
  done
  echo "$out"; return 1
}

cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  for n in "$RUN-long" "$RUN-a" "$RUN-b"; do code stop --name "$n" --force >/dev/null 2>&1; done
  box_exec 'rm -f /tmp/e2e-pwned-*; if [ -f $HOME/.local/bin/claude.e2e-orig ]; then mv -f $HOME/.local/bin/claude.e2e-orig $HOME/.local/bin/claude; else rm -f $HOME/.local/bin/claude; fi' >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- the fake agent -------------------------------------------------------
# Behaviour by prompt content (argv: -p <prompt> [--output-format stream-json]):
#   contains FAIL   -> exits 1
#   contains SLEEP  -> heartbeat every second for 120 s
#   otherwise       -> echoes the prompt and a marker, exits 0
cat >"$WORK/claude" <<'STUB'
#!/bin/sh
prompt="$2"; fmt="$4"
if [ "$fmt" = stream-json ]; then
  printf '{"type":"system","subtype":"init"}\n'
  echo 'e2e-stderr-diagnostic' >&2
  printf '{"type":"result","subtype":"success"}\n'
else
  printf 'FAKE-AGENT-PROMPT<<%s>>\n' "$prompt"
  echo FAKE-AGENT-DONE
fi
case "$prompt" in
  *FAIL*)  exit 1 ;;
  *SLEEP*) i=0; while [ $i -lt 120 ]; do echo "heartbeat-$i"; i=$((i+1)); sleep 1; done ;;
esac
exit 0
STUB
if [ "$SABOTAGE" = silent-agent ]; then sed -i.bak '1a\
exit 0' "$WORK/claude"; fi

# `connect` authorizes the key via the API, but the sentinel only learns of it
# at its next keysync (~2 min cadence). On a fresh box the first connects fail
# with "Permission denied (publickey)" until then, so wait instead of failing.
echo "== wait for SSH to $BOX (up to ${E2E_SSH_WAIT:-300}s)"
t0=$SECONDS
until "$BIN" connect "$BOX" --exec true >/dev/null 2>&1; do
  [ $((SECONDS - t0)) -ge "${E2E_SSH_WAIT:-300}" ] && { echo "SSH to $BOX not ready after $((SECONDS - t0))s"; exit 2; }
  sleep 10
done
echo "SSH ready after $((SECONDS - t0))s"

# `code run` speaks MCP to `ssh <box> -- agent-box`, so the box needs agent-box
# on PATH (/usr/local/bin). Boxes provisioned for coding agents have it; a plain
# fresh box does not, and every `code` command then dies with "initialize MCP
# session: transport closed". Build it with `make build-agent-box-linux`.
AGENT_BOX_BIN="${E2E_AGENT_BOX_BIN:-./bin/agent-box-linux-amd64}"
if [ -n "${E2E_FORCE_AGENT_BOX_INSTALL:-}" ] || ! box_exec 'command -v agent-box' >/dev/null 2>&1; then
  echo "== install agent-box on $BOX from $AGENT_BOX_BIN"
  [ -f "$AGENT_BOX_BIN" ] || { echo "missing $AGENT_BOX_BIN (make build-agent-box-linux)"; exit 2; }
  SSH_CMD="$("$BIN" connect "$BOX" --print | tail -1)"
  # shellcheck disable=SC2086  # SSH_CMD is a command line, split on purpose
  $SSH_CMD 'sudo tee /usr/local/bin/agent-box >/dev/null && sudo chmod 755 /usr/local/bin/agent-box' <"$AGENT_BOX_BIN" \
    || { echo "cannot install agent-box on $BOX"; exit 2; }
fi

echo "== install fake agent on $BOX"
B64="$(base64 <"$WORK/claude" | tr -d '\n')"
box_exec "mkdir -p \$HOME/.local/bin; [ -f $REMOTE_CLAUDE ] && [ ! -f $REMOTE_CLAUDE.e2e-orig ] && cp $REMOTE_CLAUDE $REMOTE_CLAUDE.e2e-orig; echo $B64 | base64 -d > $REMOTE_CLAUDE && chmod +x $REMOTE_CLAUDE" >/dev/null \
  || { echo "cannot install fake agent on $BOX"; exit 2; }

# ---- 1. happy path: output streams back, run ends exited ------------------
echo "== 1. happy path"
out="$(code run --name "$RUN-a" --prompt 'hello world' 2>"$WORK/err")"
assert_contains "1a agent output streamed to local stdout" "$out" 'FAKE-AGENT-PROMPT<<hello world>>'
assert_contains "1b agent ran to completion"               "$out" 'FAKE-AGENT-DONE'
assert_contains "1c 'started' diagnostic on stderr"        "$(cat "$WORK/err")" 'started'
st="$(code status --name "$RUN-a" 2>&1)"
assert_contains "1d status reports exited"                 "$st" 'exited'

# ---- 2. quoting: prompt is data, never shell ------------------------------
echo "== 2. quoting / injection"
nasty="it's \$(touch /tmp/e2e-pwned-1) \`touch /tmp/e2e-pwned-2\` ; touch /tmp/e2e-pwned-3"
out="$(code run --name "$RUN-b" --prompt "$nasty" 2>/dev/null)"
assert_contains "2a prompt arrives byte-exact" "$out" "FAKE-AGENT-PROMPT<<$nasty>>"
leaked="$(box_exec 'ls /tmp/e2e-pwned-* 2>/dev/null')"
[ -z "$leaked" ] && ok "2b no command was executed from the prompt" || fail "2b prompt was shell-interpreted: $leaked"

# ---- 3. framed capture: JSON on stdout, diagnostics on stderr -------------
echo "== 3. --output-format-stream-json"
out="$(code run --name "$RUN-a" --prompt 'json please' --output-format-stream-json 2>"$WORK/err")"
assert_contains     "3a stdout carries the JSON stream"     "$out" '"subtype":"success"'
assert_not_contains "3b stderr text is not mixed into stdout" "$out" 'e2e-stderr-diagnostic'
assert_contains     "3c stderr text arrives on stderr"       "$(cat "$WORK/err")" 'e2e-stderr-diagnostic'
n_bad="$(grep -vc '^{.*}$' <<<"$out")"
[ "$n_bad" = 0 ] && ok "3d every stdout line is valid-looking JSON" || fail "3d $n_bad non-JSON stdout lines"

# ---- 4. detach survives client death; attach replays; stop ---------------
echo "== 4. detach / attach / stop"
code run --name "$RUN-long" --prompt SLEEP >"$WORK/long.out" 2>&1 & LOCAL=$!; PIDS+=("$LOCAL")
wait_status "$RUN-long" ', running\)' 30 >/dev/null && ok "4a run is running" || fail "4a run never reached running"
sleep 4
kill "$LOCAL" 2>/dev/null; wait "$LOCAL" 2>/dev/null
sleep 2
st="$(code status --name "$RUN-long" 2>&1)"
assert_contains "4b killing the local client did NOT kill the run" "$st" 'running'
attach_for() { # <secs> — attach, then drop the client after <secs>
  code attach --name "$RUN-long" 2>&1 & local p=$!; sleep "$1"; kill "$p" 2>/dev/null; wait "$p" 2>/dev/null
}
out="$(attach_for 8)"
assert_contains "4c attach replays output from the start" "$out" 'heartbeat-0'
code stop --name "$RUN-long" >"$WORK/stop.out" 2>&1
assert_contains "4d stop reports the run" "$(cat "$WORK/stop.out")" "name: $RUN-long"
if wait_status "$RUN-long" ', running\)' 3 >/dev/null; then fail "4e run still running after stop"; else ok "4e run is no longer running after stop"; fi
out="$(attach_for 6)"
assert_contains "4f log stays readable after stop" "$out" 'heartbeat-0'

# ---- 5. failing agent (pins current behaviour, see KNOWN GAP) -------------
echo "== 5. failing agent"
out="$(code run --name "$RUN-b" --prompt 'please FAIL' 2>&1)"
assert_contains "5a failing agent's output still streams" "$out" 'FAKE-AGENT-DONE'
st="$(code status --name "$RUN-b" 2>&1)"
assert_contains "5b status shows exited" "$st" 'exited'
if grep -qiE 'exit(ed)? *(code)?[ :=]*1' <<<"$st"; then ok "5c status surfaces exit code 1"; else echo "NOTE 5c status does not surface the exit code (known gap) — flip this to a hard assertion once fixed"; fi

# ---- 6. same-box concurrency ----------------------------------------------
echo "== 6. concurrent names"
code run --name "$RUN-a" --prompt SLEEP >/dev/null 2>&1 & PIDS+=("$!")
code run --name "$RUN-b" --prompt SLEEP >/dev/null 2>&1 & PIDS+=("$!")
wait_status "$RUN-a" ', running\)' 30 >/dev/null && wait_status "$RUN-b" ', running\)' 30 >/dev/null \
  && ok "6a two named runs run concurrently" || fail "6a concurrent runs did not both reach running"
code stop --name "$RUN-a" --force >/dev/null 2>&1; code stop --name "$RUN-b" --force >/dev/null 2>&1

# ---- 7. unknown run -------------------------------------------------------
echo "== 7. unknown run"
if code status --name "$RUN-does-not-exist" >/dev/null 2>&1; then fail "7a status of an unknown run exited 0"; else ok "7a status of an unknown run fails"; fi

echo
if [ "$FAILS" -eq 0 ]; then echo "PASS: all assertions held"; else echo "FAILED: $FAILS assertion(s)"; exit 1; fi
