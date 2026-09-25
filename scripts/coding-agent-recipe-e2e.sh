#!/usr/bin/env bash
#
# coding-agent-recipe-e2e.sh — proof that the `coding-agent` recipe yields a box
# with the toolchain and NO credential (#2031). UNVERIFIED in CI: it needs a
# running daemon with Incus and egress to GitHub and claude.ai, so it is not yet
# wired into a workflow. Run it by hand against a scratch daemon.
#
# Usage: RELEASE=v0.89.0 bash scripts/coding-agent-recipe-e2e.sh
# Env:   RELEASE (required, v-prefixed), BOX (default coding-agent-e2e),
#        BOX_USER (default ubuntu), CONTAINARIUM (CLI, default containarium)
#        ANTHROPIC_TEST_KEY (optional) — if set, the tester's own key is placed
#        in the box user's ~/.claude/settings.json and `code run` is exercised.
set -euo pipefail

RELEASE="${RELEASE:?set RELEASE to a v-prefixed release tag}"
BOX="${BOX:-coding-agent-e2e}"
BOX_USER="${BOX_USER:-ubuntu}"
CLI="${CONTAINARIUM:-containarium}"

boxsh() { "$CLI" connect "$BOX" --user root --exec "bash -c $(printf %q "$1")"; }
ok() { echo "OK  $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }

"$CLI" recipe deploy coding-agent "$BOX" --param "release=$RELEASE" --param "box_user=$BOX_USER"

boxsh 'test -x /usr/local/bin/agent-box && test -x /usr/local/bin/mcp-server' || fail "agent-box/mcp-server missing"
ok "agent-box and mcp-server installed"

boxsh "runuser -u $BOX_USER -- env HOME=/home/$BOX_USER /home/$BOX_USER/.local/bin/claude --version" || fail "claude --version"
ok "claude runs as $BOX_USER"

boxsh "test ! -e /home/$BOX_USER/.claude/.credentials.json" || fail "credentials file present"
ok "no ~/.claude/.credentials.json"

boxsh 'test ! -e /etc/claude-code && ! find / -xdev -name managed-settings.json 2>/dev/null | grep -q .' || fail "managed settings present"
ok "no /etc/claude-code, no managed-settings.json"

if [ -n "${ANTHROPIC_TEST_KEY:-}" ]; then
  # The tester's own key, placed by the tester, not the recipe.
  boxsh "install -d -o $BOX_USER /home/$BOX_USER/.claude && printf '{\"env\":{\"ANTHROPIC_API_KEY\":\"%s\"}}' '$ANTHROPIC_TEST_KEY' > /home/$BOX_USER/.claude/settings.json && chown $BOX_USER /home/$BOX_USER/.claude/settings.json"
  "$CLI" code run "$BOX" --prompt "say hi" || fail "code run"
  ok "code run completed with the tester's own key"
fi
echo "coding-agent recipe e2e: all assertions passed"
