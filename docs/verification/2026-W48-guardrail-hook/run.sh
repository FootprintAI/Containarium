#!/bin/bash
# Runs inside a throwaway node:22-bookworm container. Synthetic values only.
set -u
npm install -g --silent @anthropic-ai/claude-code@2.1.332 >/out/npm.log 2>&1 || { echo "npm install failed"; exit 1; }
# The v0.141.3 client release asset, at the path the daemon pins the hook
# binary to inside a box (docs/architecture/guardrail.md, managed drop-in).
install -D -m 0755 /in/containarium /usr/local/lib/containarium-guardrail/containarium
mkdir -p /work /home/node/.claude && chown -R node:node /work /home/node/.claude
printf 'AWS=AKIAIOSFODNN7EXAMPLE\nowner ann@example.com\n' > /work/.env
cp /in/settings.json /home/node/.claude/settings.json
chown -R node:node /work /home/node/.claude
su node -s /bin/bash -c 'python3 /in/stub.py 8765 >/out/stub.log 2>&1 &'
sleep 1
cd /work
su node -s /bin/bash -c 'cd /work && env ANTHROPIC_BASE_URL=http://127.0.0.1:8765 ANTHROPIC_API_KEY=sk-ant-stub-not-a-real-key \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_AUTOUPDATER=1 \
  timeout 300 claude -p "Follow the plan." --permission-mode acceptEdits --allowedTools "Read,Write,Bash" \
  --output-format stream-json --verbose' > /out/claude.jsonl 2> /out/claude.err
echo "claude exit=$?" > /out/claude.exit
claude --version > /out/claude.version 2>&1
cp /work/out.txt /out/out.txt 2>/dev/null || echo "(no out.txt)" > /out/out.txt
cp /home/node/.local/state/containarium-guardrail/findings.jsonl /out/findings.jsonl 2>/dev/null || echo "" > /out/findings.jsonl
ls -la /home/node/.local/state/containarium-guardrail/ > /out/state.ls 2>&1
chmod -R a+r /out
