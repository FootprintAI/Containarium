#!/usr/bin/env bash
# Fail when published docs name a specific deployment (CLAUDE.md, "No instance /
# endpoint / tenant names in OSS-visible files").
#
# Usage:
#   scripts/ci/check-doc-names.sh [file-or-dir ...]   # default: docs README.md CHANGELOG.md
#   scripts/ci/check-doc-names.sh --self-test
#
# Rules (every *.md under the given paths):
#   public-ip   an IPv4 address outside private, loopback, link-local, multicast,
#               0.0.0.0/8 and the RFC 5737 documentation ranges, unless listed
#               as `ip` in doc-names.allow. Applies inside code fences too.
#   tailscale   an address in 100.64.0.0/10, or any hostname under .ts.net.
#   private-ip  a private IPv4 *host* address in running prose, outside a fenced
#               block. Not flagged: a CIDR (followed by /N), 10.0.3.x (the
#               Incus default bridge) and CHANGELOG.md (historical default subnets). Write <private-ip> instead.
#   tenant-name a `<word>-container` token (a single word before -container)
#               whose word is not a generic example in doc-names.allow. Tokens
#               with placeholders (<tenant>-container, ${user}-container) and
#               hyphenated words (per-container) never match.
# There is deliberately no list of real names: the rules are structural, and an
# entry in doc-names.allow needs a reason.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ALLOW=${DOC_NAMES_ALLOW:-$HERE/doc-names.allow}

scan() {
  local f
  while IFS= read -r -d '' f; do
    awk -v allow="$ALLOW" -v file="$f" '
      BEGIN {
        while ((getline l < allow) > 0) {
          sub(/[ \t]+#.*$/, "", l)
          n = split(l, p, /[ \t]+/)
          if (p[1] == "ip") okip[p[2]] = 1
          else if (p[1] == "name") okname[p[2]] = 1
          else if (p[1] == "pending") pend[p[2] SUBSEP p[3]] = 1
        }
        rel = file; sub(/^\.\//, "", rel)
      }
      /^[ \t]*(```|~~~)/ { fence = !fence; next }
      {
        line = $0; rest = line
        while (match(rest, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
          s = RSTART; len = RLENGTH; ip = substr(rest, s, len)
          pre = (s > 1) ? substr(rest, s - 1, 1) : ""
          post = substr(rest, s + len, 1)
          after = substr(rest, s + len)
          rest = substr(rest, s + len)
          if (pre ~ /[0-9.]/ || post ~ /[0-9]/) continue
          split(ip, o, ".")
          if (o[1] > 255 || o[2] > 255 || o[3] > 255 || o[4] > 255) continue
          a = o[1] + 0; b = o[2] + 0; c = o[3] + 0
          cidr = (post == "/")
          if (a == 100 && b >= 64 && b <= 127) { print "tailscale " rel ":" FNR ": " ip; continue }
          priv = (a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168))
          if (priv) {
            if (!fence && !cidr && rel != "CHANGELOG.md" && !(a == 10 && b == 0 && c == 3)) print "private-ip " rel ":" FNR ": " ip
            continue
          }
          if (a == 0 || a == 127 || a >= 224 || (a == 169 && b == 254)) continue
          if ((a == 192 && b == 0 && c == 2) || (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113)) continue
          if (ip in okip) continue
          print "public-ip " rel ":" FNR ": " ip
        }
        if (line ~ /\.ts\.net([^a-z0-9-]|$)/) print "tailscale " rel ":" FNR ": .ts.net hostname"
        rest = line
        while (match(rest, /[A-Za-z0-9<>${}_-]+-container/)) {
          tok = substr(rest, RSTART, RLENGTH)
          pre = (RSTART > 1) ? substr(rest, RSTART - 1, 1) : ""
          rest = substr(rest, RSTART + RLENGTH)
          if (tok ~ /[<>${}]/ || tok ~ /^-/) continue
          w = tok; sub(/-container$/, "", w)
          if (w ~ /-/ || pre ~ /[-A-Za-z0-9_]/) continue
          if (w !~ /^[a-z][a-z0-9]*$/) continue
          if ((w in okname) || ((rel SUBSEP w) in pend)) continue
          print "tenant-name " rel ":" FNR ": " tok
        }
      }' "$f"
  done < <(find "$@" -type f -name '*.md' -print0 | sort -z)
}

check() {
  local out
  out=$(scan "$@")
  if [[ -n "$out" ]]; then printf '%s\n' "$out"; return 1; fi
}

self_test() {
  local d rc=0
  d=$(mktemp -d); trap 'rm -rf "$d"' RETURN
  seed() { # name content rule
    mkdir -p "$d/$1"; printf '%s\n' "$2" >"$d/$1/x.md"
    local out; out=$(check "$d/$1" 2>&1) && { echo "self-test FAIL: '$2' was accepted"; rc=1; return; }
    grep -q "^$3 " <<<"$out" || { echo "self-test FAIL: '$2' flagged but not as $3: $out"; rc=1; }
  }
  seed ip   'ssh admin@34.120.7.9' public-ip
  seed ipf  $'```\nHostName 52.14.9.200\n```' public-ip
  seed ts   'reach it at box.tail1234.ts.net' tailscale
  seed ts2  'peer 100.101.102.103' tailscale
  seed pip  'the backend listens on 10.7.7.7 today' private-ip
  seed ten  'incus exec zed-container -- sh' tenant-name
  mkdir -p "$d/ok"
  cat >"$d/ok/x.md" <<'Y'
Example `203.0.113.7`, resolver 8.8.8.8, bridge 10.0.3.5, range 10.0.0.0/8.
```
ip addr add 10.7.7.7/24 dev eth0
ping 10.7.7.7
```
Use <tenant>-container, ${user}-container, per-container and alice-container.
Y
  check "$d/ok" >/dev/null || { echo "self-test FAIL: clean fixture rejected"; check "$d/ok"; rc=1; }
  [[ $rc -eq 0 ]] && echo "self-test ok: public IP, Tailscale, private host IP and tenant-name seeds rejected; placeholders accepted"
  return $rc
}

if [[ "${1:-}" == "--self-test" ]]; then self_test; exit; fi
[[ $# -gt 0 ]] || set -- docs README.md CHANGELOG.md
if check "$@"; then echo "no deployment names found in docs"; else
  echo "Anonymise per CLAUDE.md: <private-ip>, a documentation address (RFC 5737), <tenant>-container. Documented exceptions go in scripts/ci/doc-names.allow with a reason." >&2
  exit 1
fi
