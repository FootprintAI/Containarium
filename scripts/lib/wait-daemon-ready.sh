#!/usr/bin/env bash
# wait-daemon-ready.sh — shared readiness probe for the e2e lanes that start a
# real daemon (#3143 follow-up).
#
# Since the daemon binds its HTTP port early, a daemon that is still waiting for
# core containers answers EVERY path except /health with
# `503 daemon is starting: ...`. A bare `curl -s -o /dev/null URL` succeeds on
# any response, so it proves only that the port is bound, not that the daemon
# is ready. A ready daemon answers the probe paths with anything except 503
# (200, or 401/403 for an unauthenticated probe); 000 means no connection.
#
# Source this file; it defines functions only.

# daemon_ready_status PORT PATH — probe 127.0.0.1:PORT/PATH and print the HTTP status curl saw (000 on no answer).
daemon_ready_status() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$1$2" 2>/dev/null || true
}

# daemon_is_ready PORT PATH — succeed only for a status that is neither 503 nor 000.
daemon_is_ready() {
  local code
  code="$(daemon_ready_status "$1" "$2")"
  case "$code" in
    503|000|"") return 1 ;;
    *) return 0 ;;
  esac
}
