#!/usr/bin/env bash
# Prove scripts/lib/wait-daemon-ready.sh waits through the daemon's early-bind
# 503s, and that the old `curl -s -o /dev/null` probe would not (#3143 follow-up).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT/scripts/lib/wait-daemon-ready.sh"

TMP="$(mktemp -d)"; trap 'kill "$SRV" 2>/dev/null; rm -rf "$TMP"' EXIT
PORT=$((20000 + RANDOM % 20000))
# Stub daemon: 503 for the first N requests to /v1/x, then 200.
cat > "$TMP/stub.py" <<'PY'
import sys, http.server
port, n = int(sys.argv[1]), int(sys.argv[2])
seen = [0]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        seen[0] += 1
        code = 503 if seen[0] <= n else 200
        self.send_response(code); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
python3 "$TMP/stub.py" "$PORT" 3 & SRV=$!
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break; sleep 0.1; done
URL="http://127.0.0.1:$PORT/v1/x"
fails=0
check() { if [ "$2" = ok ]; then echo "ok   - $1"; else echo "FAIL - $1"; fails=$((fails+1)); fi; }

# Old pattern: breaks on the very first (503) response.
tries_old=0
for i in 1 2 3 4 5 6; do tries_old=$i; curl -s -o /dev/null "$URL" && break; done
# Stub counter already advanced by 1; the old loop must have stopped at try 1.
[ "$tries_old" = 1 ] && check "old pattern accepts a 503 on try 1 (the bug)" ok || check "old pattern accepts a 503 on try 1 (the bug)" no

# New helper against a fresh stub (3 x 503, then 200).
kill "$SRV"; wait "$SRV" 2>/dev/null
python3 "$TMP/stub.py" "$PORT" 3 & SRV=$!
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break; sleep 0.1; done
tries=0
for i in $(seq 1 10); do tries=$i; daemon_is_ready "$URL" && break; sleep 0.1; done
[ "$tries" = 4 ] && check "helper waits through 503s and stops on the 4th try" ok || check "helper waits through 503s (stopped at try $tries, want 4)" no

# Connection refused (000) is not ready.
kill "$SRV"; wait "$SRV" 2>/dev/null
daemon_is_ready "$URL" && check "helper treats 000 as not ready" no || check "helper treats 000 as not ready" ok

# A non-503 error (401 from an auth-gated route) counts as ready.
cat > "$TMP/s401.py" <<'PY'
import sys, http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(401); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$TMP/s401.py" "$PORT" & SRV=$!
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break; sleep 0.1; done
daemon_is_ready "$URL" && check "helper treats 401 as ready" ok || check "helper treats 401 as ready" no

[ "$fails" = 0 ] || { echo "$fails check(s) failed" >&2; exit 1; }
echo "all checks passed"
