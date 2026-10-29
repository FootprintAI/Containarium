#!/usr/bin/env bash
# Tests for the air-gapped bundle gates (#3061), against stubbed apt tools:
#   - download-deps.sh downloads exactly the name=version set apt's resolver
#     picks (providers of virtual names included; virtual names themselves
#     used to abort the whole batch), and fails on a resolver error, an
#     apt-get download error, an empty download, and a dependency the bundle
#     cannot satisfy;
#   - build-bundle.sh fails when the cache holds no .deb (opt-out:
#     BUNDLE_ALLOW_EMPTY_APT=1) and ships no images/ directory;
#   - check-bundle-content.sh rejects a tarball without debs or with images/;
#   - the offline installer errors on an empty apt/ unless --skip-apt, and
#     has no base-image import step;
#   - add-zabbly-repo.sh refuses a key with the wrong fingerprint.
# Needs bash, coreutils, tar, gzip, dpkg-deb and gpg (all on ubuntu runners).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
deps=$repo/scripts/bundle/download-deps.sh
build=$repo/scripts/bundle/build-bundle.sh
content=$repo/scripts/bundle/check-bundle-content.sh
zabbly=$repo/scripts/bundle/add-zabbly-repo.sh
installer=$repo/hacks/offline-install/install.sh
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
t() { echo "FAIL: $*"; fail=1; }
pass() { echo "ok:   $*"; }

# ---------------------------------------------------------------- fixtures
# mkdeb NAME [DEPENDS] [PROVIDES] -> $tmp/debs/NAME.deb
mkdir -p "$tmp/debs"
mkdeb() {
  local d=$tmp/debsrc/$1
  mkdir -p "$d/DEBIAN"
  {
    printf 'Package: %s\nVersion: 1.0\nArchitecture: all\n' "$1"
    printf 'Maintainer: test <test@example.com>\nDescription: fixture\n'
    [ -n "${2:-}" ] && printf 'Depends: %s\n' "$2"
    [ -n "${3:-}" ] && printf 'Provides: %s\n' "$3"
  } >"$d/DEBIAN/control"
  dpkg-deb --root-owner-group -Zgzip --build "$d" "$tmp/debs/$1.deb" >/dev/null
}
mkdeb alpha 'libx, virt-thing | libx'
mkdeb beta 'libx (>= 1.0), python3:any'
mkdeb libx '' 'virt-thing, python3'
mkdeb broken 'libmissing (>= 2)'

# Restricted PATH: the stubs plus only the system tools the scripts need, so
# a host apt-get never leaks into a test.
farm=$tmp/farm; mkdir -p "$farm"
for c in bash sh env sort uniq grep awk sed cat mkdir mktemp ls find dirname basename \
         cp mv rm touch tr wc head tail cut dpkg-deb tar gzip printf date; do
  p=$(command -v "$c" || true)
  [ -n "$p" ] && ln -sf "$p" "$farm/$c"
done

stubs=$tmp/stubs; mkdir -p "$stubs"
# apt-get install -s PKGS: what apt's resolver would install on an empty
# system: the union of FAKE/resolve/PKG, as `Inst` lines; an unknown PKG
# fails like apt does. FAKE_RESOLVE_RC makes it exit non-zero AFTER printing
# the Inst lines, so only the exit status shows the failure.
# Every call appends "<mode> <-o values>" to $FAKE/apt-get.opts.
# apt-get download NAME=VER...: records the args; FAKE_APT_RC makes it exit
# non-zero AFTER writing every .deb (a partial-failure shape only the exit
# status reveals); FAKE_NO_WRITE pretends success without writing anything.
cat >"$stubs/apt-get" <<'EOF'
#!/bin/bash
mode=; pkgs=(); opts=()
while [ $# -gt 0 ]; do
  case "$1" in
    -o) shift; opts+=("$1") ;;
    -*) ;;
    install|download) mode=$1 ;;
    *) pkgs+=("$1") ;;
  esac
  shift
done
echo "$mode ${opts[*]}" >>"$FAKE/apt-get.opts"
case "$mode" in
  install)
    echo "install ${pkgs[*]}" >>"$FAKE/apt-get.log"
    for n in "${pkgs[@]}"; do
      [ -f "$FAKE/resolve/$n" ] || { echo "E: Unable to locate package $n" >&2; exit 100; }
    done
    for n in "${pkgs[@]}"; do cat "$FAKE/resolve/$n"; done | sort -u | while read -r p; do
      echo "Inst $p (1.0 Fake:1/stable [all])"
    done
    if [ "${FAKE_RESOLVE_RC:-0}" != 0 ]; then echo "E: Unable to correct problems" >&2; exit "$FAKE_RESOLVE_RC"; fi ;;
  download)
    echo "download ${pkgs[*]}" >>"$FAKE/apt-get.log"
    [ -n "${FAKE_NO_WRITE:-}" ] && exit 0
    for nv in "${pkgs[@]}"; do
      n=${nv%%=*}
      [ -f "$FAKE/debs/$n.deb" ] || { echo "E: Can't find package $n" >&2; exit 100; }
      cp "$FAKE/debs/$n.deb" "./${n}_1.0_all.deb"
    done
    if [ "${FAKE_APT_RC:-0}" != 0 ]; then echo "E: Failed to fetch" >&2; exit "$FAKE_APT_RC"; fi ;;
  *) echo "stub apt-get: unsupported mode" >&2; exit 2 ;;
esac
EOF
chmod +x "$stubs"/*

# newfake DIR: alpha's closure is alpha + libx (libx provides the virtual
# virt-thing and python3 that alpha and beta depend on); broken depends on a
# package its resolved set lacks.
newfake() {
  local f=$1; mkdir -p "$f/resolve" "$f/debs"
  cp "$tmp/debs/"*.deb "$f/debs/"
  printf 'alpha\nlibx\n' >"$f/resolve/alpha"
  printf 'beta\nlibx\n' >"$f/resolve/beta"
  printf 'broken\n' >"$f/resolve/broken"
  : >"$f/apt-get.log"
}

# deps NAME [ENV=VAL...] -> runs download-deps.sh (apt step only) under the
# stubs; output in $tmp/NAME.out, staging in $tmp/NAME.stage.
deps() {
  local name=$1; shift
  newfake "$tmp/$name.fake"
  env -i HOME="$tmp" PATH="$stubs:$farm" FAKE="$tmp/$name.fake" \
    STAGING_DIR="$tmp/$name.stage" DEPS_ONLY=apt APT_PACKAGES="alpha beta" \
    "$@" bash "$deps" >"$tmp/$name.out" 2>&1
}

# ------------------------------------------------- download-deps.sh tests
if deps ok; then
  n=$(find "$tmp/ok.stage/apt" -name '*.deb' | wc -l)
  [ "$n" -eq 3 ] && pass "download-deps: resolved closure downloaded (3 debs)" || t "download-deps: want 3 debs, got $n"
  grep -qx 'download alpha=1.0 beta=1.0 libx=1.0' "$tmp/ok.fake/apt-get.log" \
    && pass "download-deps: downloads exactly the resolver's name=version set" \
    || { t "download-deps: download args differ from the resolved set"; cat "$tmp/ok.fake/apt-get.log"; }
  grep -q 'closure OK' "$tmp/ok.out" && pass "download-deps: virtual deps met through Provides" || t "download-deps: closure check did not run"
else t "download-deps: good closure failed"; cat "$tmp/ok.out"; fi

if deps resolvefail FAKE_RESOLVE_RC=100; then t "download-deps: resolver failure exited 0"
else
  grep -q 'apt could not resolve' "$tmp/resolvefail.out" && pass "download-deps: resolver exit status checked" \
    || t "download-deps: resolver failure not reported as such"; fi

if deps aptfail FAKE_APT_RC=100; then t "download-deps: failing apt-get download exited 0"
else
  grep -q 'apt-get download failed' "$tmp/aptfail.out" && pass "download-deps: apt-get download exit status checked" \
    || t "download-deps: apt-get download failure not reported as such"; fi

if deps nowrite FAKE_NO_WRITE=1; then t "download-deps: empty download exited 0"
else pass "download-deps: empty download exits non-zero"; fi

if deps missing APT_PACKAGES="alpha gamma"; then t "download-deps: unknown requested package accepted"
else
  grep -q gamma "$tmp/missing.out" && pass "download-deps: unknown requested package fails, named" \
    || t "download-deps: unknown requested package not named"; fi

if deps closure APT_PACKAGES="alpha broken"; then t "download-deps: unsatisfied dependency accepted"
else
  grep -q libmissing "$tmp/closure.out" && pass "download-deps: unsatisfied dependency fails, named" \
    || t "download-deps: unsatisfied dependency not named"; fi

# #3118: a stalled mirror must fail fast, and the log must show progress.
for mode in install download; do
  for o in Acquire::http::Timeout=30 Acquire::https::Timeout=30 Acquire::Retries=3; do
    if grep -E "^$mode " "$tmp/ok.fake/apt-get.opts" | grep -qwF -- "$o"; then :
    else t "download-deps: apt-get $mode runs without -o $o"; fi
  done
done
pass "download-deps: resolver and download carry the apt network bounds"
grep -q 'Resolved 3 packages' "$tmp/ok.out" && pass "download-deps: logs the resolved package count" \
  || t "download-deps: resolved package count not logged"
grep -q 'batch 1/1' "$tmp/ok.out" && pass "download-deps: default batch size fits 3 packages in one batch" \
  || t "download-deps: default batch progress not logged"

if deps batched APT_BATCH_SIZE=2; then
  if [ "$(grep -c '^download ' "$tmp/batched.fake/apt-get.log")" -eq 2 ] \
     && grep -qx 'download alpha=1.0 beta=1.0' "$tmp/batched.fake/apt-get.log" \
     && grep -qx 'download libx=1.0' "$tmp/batched.fake/apt-get.log"; then
    pass "download-deps: APT_BATCH_SIZE=2 downloads 3 packages in 2 batches"
  else t "download-deps: batches differ from APT_BATCH_SIZE=2"; cat "$tmp/batched.fake/apt-get.log"; fi
  grep -q 'batch 1/2' "$tmp/batched.out" && grep -q 'batch 2/2' "$tmp/batched.out" \
    && pass "download-deps: per-batch progress logged" || { t "download-deps: per-batch progress missing"; cat "$tmp/batched.out"; }
  n=$(find "$tmp/batched.stage/apt" -name '*.deb' | wc -l)
  [ "$n" -eq 3 ] && pass "download-deps: batched run downloads the whole closure" || t "download-deps: batched run got $n debs"
else t "download-deps: batched run failed"; cat "$tmp/batched.out"; fi

if deps batchfail APT_BATCH_SIZE=2 FAKE_APT_RC=100; then t "download-deps: failing batch exited 0"
else
  grep -q 'apt-get download failed in batch 1/2' "$tmp/batchfail.out" \
    && pass "download-deps: failing batch named" || { t "download-deps: failing batch not named"; cat "$tmp/batchfail.out"; }
  [ "$(grep -c '^download ' "$tmp/batchfail.fake/apt-get.log")" -eq 1 ] \
    && pass "download-deps: stops at the first failing batch" || t "download-deps: kept downloading after a failed batch"
fi

for bad in 0 -1 abc 08 1e3 " 5" 501 1000 18446744073709551616 9223372036854775807; do
  if deps badbatch APT_BATCH_SIZE="$bad"; then t "download-deps: APT_BATCH_SIZE=$bad accepted"
  else grep -q 'APT_BATCH_SIZE' "$tmp/badbatch.out" && pass "download-deps: APT_BATCH_SIZE=$bad rejected" \
    || t "download-deps: APT_BATCH_SIZE=$bad failed without naming it"; fi
done

for ok in 500 1; do
  if deps okbatch APT_BATCH_SIZE="$ok"; then pass "download-deps: APT_BATCH_SIZE=$ok accepted"
  else t "download-deps: APT_BATCH_SIZE=$ok rejected"; cat "$tmp/okbatch.out"; fi
done
if deps emptybatch APT_BATCH_SIZE=; then
  grep -q 'batch 1/1' "$tmp/emptybatch.out" && pass "download-deps: empty APT_BATCH_SIZE keeps the default" \
    || t "download-deps: empty APT_BATCH_SIZE did not use the default"
else t "download-deps: empty APT_BATCH_SIZE rejected"; cat "$tmp/emptybatch.out"; fi

# The job summary records how long the step took, on success and failure.
if deps summary GITHUB_STEP_SUMMARY="$tmp/summary.md"; then
  grep -qE 'Download bundle dependencies.*[0-9]+s' "$tmp/summary.md" 2>/dev/null \
    && grep -q '3 apt packages' "$tmp/summary.md" \
    && pass "download-deps: duration and package count in the job summary" \
    || { t "download-deps: job summary lacks duration or package count"; cat "$tmp/summary.md" 2>/dev/null || true; }
else t "download-deps: summary run failed"; cat "$tmp/summary.out"; fi
if deps summaryfail GITHUB_STEP_SUMMARY="$tmp/summaryfail.md" FAKE_APT_RC=100; then t "download-deps: failing summary run exited 0"
else grep -qiE 'failed after [0-9]+s' "$tmp/summaryfail.md" 2>/dev/null \
  && pass "download-deps: a failed step's duration is in the job summary" \
  || { t "download-deps: failed step left no duration in the job summary"; cat "$tmp/summaryfail.md" 2>/dev/null || true; }
fi

mv "$stubs/apt-get" "$stubs/apt-get.off"
if deps noaptget; then t "download-deps: ran without apt-get"
else pass "download-deps: missing apt-get exits non-zero"; fi
mv "$stubs/apt-get.off" "$stubs/apt-get"

# --------------------------------------------------- build-bundle.sh tests
fake_repo=$tmp/repo
mkdir -p "$fake_repo/bin" "$fake_repo/hacks/offline-install/docs"
for b in containariumd mcp-server agent-box; do printf '#!/bin/sh\n' >"$fake_repo/bin/$b-linux-amd64"; done
cp "$installer" "$fake_repo/hacks/offline-install/install.sh"
echo readme >"$fake_repo/hacks/offline-install/README.md"
for d in INSTALL.md VERIFY.md GHES.md; do echo doc >"$fake_repo/hacks/offline-install/docs/$d"; done

# bundle NAME CACHE [ENV=VAL...] -> runs build-bundle.sh; tarball path in $tmp/NAME.tgz
bundle() {
  local name=$1 cache=$2; shift 2
  rm -rf "$fake_repo/dist"
  env REPO_ROOT="$fake_repo" CACHE_DIR="$cache" VERSION=v0.0.0-test OS=linux ARCH=amd64 \
    "$@" bash "$build" >"$tmp/$name.out" 2>&1 || return 1
  cp "$fake_repo/dist/containarium-bundle-v0.0.0-test-linux-amd64.tar.gz" "$tmp/$name.tgz"
}
mkcache() { # mkcache DIR [deb...]
  local c=$1; shift
  mkdir -p "$c/toolchains" "$c/bin" "$c/apt"
  echo go >"$c/toolchains/go1.0.linux-amd64.tar.gz"
  for d in "$@"; do cp "$tmp/debs/$d.deb" "$c/apt/${d}_1.0_all.deb"; done
}
mkcache "$tmp/cache-empty"
mkcache "$tmp/cache-sentinel"; touch "$tmp/cache-sentinel/apt/.MANUAL_APT_DOWNLOAD_REQUIRED"
mkcache "$tmp/cache-good" alpha libx

if bundle empty "$tmp/cache-empty"; then t "build-bundle: apt/ with no .deb exited 0"
elif grep -qF "no .deb files in $tmp/cache-empty/apt" "$tmp/empty.out"; then
  pass "build-bundle: apt/ with no .deb exits non-zero, names the empty directory"
else t "build-bundle: apt/ with no .deb failed without naming the directory"; cat "$tmp/empty.out"; fi
if bundle sentinel "$tmp/cache-sentinel"; then t "build-bundle: sentinel-only apt/ exited 0"
else pass "build-bundle: sentinel-only apt/ exits non-zero"; fi
if bundle optout "$tmp/cache-empty" BUNDLE_ALLOW_EMPTY_APT=1; then pass "build-bundle: BUNDLE_ALLOW_EMPTY_APT=1 opts out"
else t "build-bundle: opt-out did not build"; cat "$tmp/optout.out"; fi
if bundle good "$tmp/cache-good"; then
  pass "build-bundle: populated cache builds"
  tar tzf "$tmp/good.tgz" >"$tmp/good.list"
  grep -qE '/apt/alpha_1\.0_all\.deb$' "$tmp/good.list" && pass "build-bundle: debs in tarball" || t "build-bundle: debs missing from tarball"
  if grep -q '/images/' "$tmp/good.list"; then t "build-bundle: tarball still ships images/"
  else pass "build-bundle: no images/ directory"; fi
else t "build-bundle: populated cache failed"; cat "$tmp/good.out"; fi

# ------------------------------------------- check-bundle-content.sh tests
if [ -f "$tmp/good.tgz" ] && REQUIRED_DEBS="alpha libx" bash "$content" "$tmp/good.tgz" >"$tmp/content-good.out" 2>&1; then
  pass "check-bundle-content: complete bundle accepted"
else t "check-bundle-content: complete bundle rejected"; cat "$tmp/content-good.out" 2>/dev/null || true; fi
if [ -f "$tmp/good.tgz" ] && ! REQUIRED_DEBS="alpha incus" bash "$content" "$tmp/good.tgz" >"$tmp/content-req.out" 2>&1 \
   && grep -q 'missing apt/incus_' "$tmp/content-req.out"; then
  pass "check-bundle-content: missing required package rejected, named"
else t "check-bundle-content: missing required package accepted"; fi
if [ -f "$tmp/optout.tgz" ] && ! REQUIRED_DEBS= bash "$content" "$tmp/optout.tgz" >/dev/null 2>&1; then
  pass "check-bundle-content: bundle without debs rejected"
else t "check-bundle-content: bundle without debs accepted"; fi
mkt() { # mkt NAME: tarball from $tmp/NAME.tree/<top>
  tar -C "$tmp/$1.tree" -czf "$tmp/$1.tgz" containarium-bundle-v0-linux-amd64
}
top=containarium-bundle-v0-linux-amd64
for v in fine img nobin; do
  r=$tmp/$v.tree/$top
  mkdir -p "$r/bin" "$r/apt" "$r/toolchains"
  for b in containariumd mcp-server agent-box; do echo x >"$r/bin/$b"; done
  echo x >"$r/offline-install.sh"; echo x >"$r/VERSION"; echo x >"$r/CHECKSUMS.sha256"
  echo x >"$r/toolchains/go1.0.linux-amd64.tar.gz"; cp "$tmp/debs/libx.deb" "$r/apt/libx_1.0_all.deb"
done
mkdir -p "$tmp/img.tree/$top/images"; mkt img
rm "$tmp/nobin.tree/$top/bin/containariumd"; mkt nobin; mkt fine
if REQUIRED_DEBS=libx bash "$content" "$tmp/fine.tgz" >/dev/null 2>&1; then pass "check-bundle-content: control tarball accepted"
else t "check-bundle-content: control tarball rejected"; fi
# A ref with a slash (a branch rehearsal) nests the bundle directory one
# level down; that is still one bundle. Two side-by-side roots are not.
mkdir -p "$tmp/nested.tree/outer"; cp -r "$tmp/fine.tree/$top" "$tmp/nested.tree/outer/"
tar -C "$tmp/nested.tree" -czf "$tmp/nested.tgz" "outer/$top"
if REQUIRED_DEBS=libx bash "$content" "$tmp/nested.tgz" >"$tmp/nested.out" 2>&1; then pass "check-bundle-content: nested bundle directory accepted"
else t "check-bundle-content: nested bundle directory rejected"; cat "$tmp/nested.out"; fi
mkdir -p "$tmp/two.tree"; cp -r "$tmp/fine.tree/$top" "$tmp/two.tree/"; cp -r "$tmp/fine.tree/$top" "$tmp/two.tree/other"
tar -C "$tmp/two.tree" -czf "$tmp/two.tgz" "$top" other
if REQUIRED_DEBS=libx bash "$content" "$tmp/two.tgz" >/dev/null 2>&1; then t "check-bundle-content: two top-level directories accepted"
else pass "check-bundle-content: two top-level directories rejected"; fi
# A tarball whose apt/ exists but holds no .deb: rejected for that problem only.
mkdir -p "$tmp/noapt.tree"; cp -r "$tmp/fine.tree/$top" "$tmp/noapt.tree/"
rm "$tmp/noapt.tree/$top/apt/"*.deb; mkt noapt
if REQUIRED_DEBS= bash "$content" "$tmp/noapt.tgz" >"$tmp/noapt.out" 2>&1; then t "check-bundle-content: apt/ without a .deb accepted"
elif grep -q 'apt/ holds no .deb' "$tmp/noapt.out" && grep -q '(1 problem(s))' "$tmp/noapt.out"; then
  pass "check-bundle-content: apt/ without a .deb rejected, that problem only"
else t "check-bundle-content: apt/ without a .deb rejected for the wrong reason"; cat "$tmp/noapt.out"; fi
if REQUIRED_DEBS=libx bash "$content" "$tmp/img.tgz" >/dev/null 2>&1; then t "check-bundle-content: images/ accepted"
else pass "check-bundle-content: images/ rejected"; fi
if REQUIRED_DEBS=libx bash "$content" "$tmp/nobin.tgz" >/dev/null 2>&1; then t "check-bundle-content: missing containariumd accepted"
else pass "check-bundle-content: missing containariumd rejected"; fi
# A real bundle lists hundreds of debs. With a listing larger than a pipe
# buffer, a check that stops reading at its first match (grep -q) must not be
# read as "missing" or "absent" under pipefail. The entries the checks look
# for come first, so every match happens long before the listing ends.
# mkbig NAME [FIRST...]: FIRST entries, then the control set, then 3000 debs.
mkbig() {
  local name=$1; shift
  local r=$tmp/$name.tree/$top f i
  mkdir -p "$tmp/$name.tree"; cp -r "$tmp/fine.tree/$top" "$tmp/$name.tree/"
  for i in $(seq 1 3000); do : >"$r/apt/pkg$i-with-a-long-name_1.0.0-0ubuntu0.24.04.1_amd64.deb"; done
  { for f in "$@"; do echo "$top/$f"; done
    for f in bin/containariumd bin/mcp-server bin/agent-box VERSION CHECKSUMS.sha256 \
             offline-install.sh toolchains/go1.0.linux-amd64.tar.gz apt/libx_1.0_all.deb; do echo "$top/$f"; done
    for i in $(seq 1 3000); do echo "$top/apt/pkg$i-with-a-long-name_1.0.0-0ubuntu0.24.04.1_amd64.deb"; done
  } >"$tmp/$name.order"
  tar -C "$tmp/$name.tree" --no-recursion -czf "$tmp/$name.tgz" -T "$tmp/$name.order"
}
mkbig big
if REQUIRED_DEBS=libx bash "$content" "$tmp/big.tgz" >"$tmp/big.out" 2>&1; then pass "check-bundle-content: large bundle accepted"
else t "check-bundle-content: large bundle rejected"; cat "$tmp/big.out"; fi
mkdir -p "$tmp/bigimg.tree/$top/images"; mkbig bigimg images
if REQUIRED_DEBS=libx bash "$content" "$tmp/bigimg.tgz" >"$tmp/bigimg.out" 2>&1; then t "check-bundle-content: large bundle with images/ accepted"
elif [ "$(grep -c 'check-bundle-content: ' "$tmp/bigimg.out")" = 2 ] && grep -q 'ships images/' "$tmp/bigimg.out"; then
  pass "check-bundle-content: large bundle with images/ rejected for images/ only"
else t "check-bundle-content: large bundle with images/ rejected for the wrong reason"; cat "$tmp/bigimg.out"; fi

# -------------------------------------------- offline install.sh tests
# Source the installer (its main runs only when executed) and call the apt
# step against a given apt/ directory.
apt_step() { # apt_step APTDIR [installer flags...]
  local dir=$1; shift
  APT_TEST_DIR=$dir bash -c 'f=$1; shift; source "$f" "$@" && APT_DIR="$APT_TEST_DIR" && install_apt_dependencies' \
    test-harness "$installer" "$@" >"$tmp/apt-step.out" 2>&1 </dev/null
}
mkdir -p "$tmp/apt-empty"; touch "$tmp/apt-empty/.MANUAL_APT_DOWNLOAD_REQUIRED"
if apt_step "$tmp/apt-empty"; then t "install.sh: empty apt/ did not error"
else
  grep -q -- 'ERROR.*--skip-apt' "$tmp/apt-step.out" && pass "install.sh: empty apt/ errors, names --skip-apt" \
    || t "install.sh: empty apt/ failed without the --skip-apt error"; fi
if apt_step "$tmp/apt-empty" --skip-apt; then pass "install.sh: --skip-apt skips the empty apt/ step"
else t "install.sh: --skip-apt still failed"; cat "$tmp/apt-step.out"; fi
if bash -c 'f=$1; shift; source "$f" && declare -F install_apt_dependencies >/dev/null && ! declare -F import_base_image >/dev/null' \
     test-harness "$installer" </dev/null >/dev/null 2>&1; then
  pass "install.sh: no base-image import step"
else t "install.sh: base-image import step still present (or script not sourceable)"; fi
if bash -c 'f=$1; shift; source "$f" "$@" && declare -F main >/dev/null' test-harness "$installer" --skip-base-image </dev/null >/dev/null 2>&1; then
  pass "install.sh: --skip-base-image still accepted (no-op)"
else t "install.sh: --skip-base-image now rejected"; fi

# ---------------------------------------------- add-zabbly-repo.sh test
# A key whose fingerprint is not the pinned one must be refused before
# anything is written. The fake curl serves a freshly generated key.
zk=$tmp/zk; mkdir -p "$zk/gnupg" "$zk/bin"; chmod 700 "$zk/gnupg"
GNUPGHOME=$zk/gnupg gpg --batch --quiet --passphrase '' --quick-gen-key 'not zabbly <x@example.com>' default default never 2>/dev/null
GNUPGHOME=$zk/gnupg gpg --batch --armor --export >"$zk/wrong.asc"
cat >"$zk/bin/curl" <<EOF
#!/bin/bash
out=; while [ \$# -gt 0 ]; do [ "\$1" = -o ] && out=\$2; shift; done
cp "$zk/wrong.asc" "\$out"
EOF
printf '#!/bin/bash\necho "sudo must not run: $*" >>%q/sudo.log\n' "$zk" >"$zk/bin/sudo"
chmod +x "$zk/bin/curl" "$zk/bin/sudo"
if PATH="$zk/bin:$PATH" bash "$zabbly" >"$tmp/zabbly.out" 2>&1; then t "add-zabbly-repo: wrong key fingerprint accepted"
else
  if [ -s "$zk/sudo.log" ]; then t "add-zabbly-repo: wrote before checking the fingerprint"
  else pass "add-zabbly-repo: wrong key fingerprint refused before any write"; fi
fi

[ "$fail" -eq 0 ] && echo "all offline-bundle tests passed"
exit "$fail"
