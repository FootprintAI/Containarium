#!/usr/bin/env bash
# #3258: real apt, synthetic debs and an empty dpkg state/cache. Only dpkg
# is replaced: the test must exercise apt's archive acquisition without
# installing anything on the host. APT_CONFIG disables host hooks/sources.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
installer=$here/../../hacks/offline-install/install.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/state/lists/partial" "$tmp/cache/archives/partial" "$tmp/bundle apt" \
  "$tmp/etc/apt.conf.d" "$tmp/etc/sources.list.d" "$tmp/log"
: >"$tmp/state/status"
: >"$tmp/etc/apt.conf"
: >"$tmp/etc/sources.list"
for cmd in incus zfs jq curl; do ln -s /bin/true "$tmp/bin/$cmd"; done
cat >"$tmp/bin/dpkg" <<'EOF'
#!/bin/bash
for arg; do
  case "$arg" in
    --print-architecture) echo amd64 ;;
    *.deb)
      [[ "$arg" = /* ]] && [ -f "$arg" ] || exit 42
      printf '%s\n' "${arg##*/}" >>"$TEST_UNPACKED"
      ;;
  esac
done
exit 0
EOF
chmod +x "$tmp/bin/dpkg"
cat >"$tmp/apt.conf" <<EOF
Dir::Etc "$tmp/etc";
Dir::State "$tmp/state";
Dir::State::status "$tmp/state/status";
Dir::State::lists "$tmp/state/lists";
Dir::Cache "$tmp/cache";
Dir::Cache::archives "$tmp/cache/archives";
Dir::Log "$tmp/log";
Dir::Bin::dpkg "$tmp/bin/dpkg";
APT::Architecture "amd64";
APT::Sandbox::User "";
Debug::NoLocking "true";
EOF
export APT_CONFIG="$tmp/apt.conf" TEST_UNPACKED="$tmp/unpacked"
for pkg in offline-test-base offline-test-app; do
  mkdir -p "$tmp/$pkg/DEBIAN"
  {
    printf 'Package: %s\nVersion: 1\nArchitecture: all\n' "$pkg"
    printf 'Maintainer: test <test@example.invalid>\nDescription: offline fixture\n'
    if [ "$pkg" = offline-test-app ]; then echo 'Depends: offline-test-base (= 1)'; fi
  } >"$tmp/$pkg/DEBIAN/control"
  dpkg-deb --root-owner-group -Zgzip --build "$tmp/$pkg" "$tmp/bundle apt/${pkg}_1_all.deb" >/dev/null
done

run_install() {
  PATH="$tmp/bin:$PATH" TEST_APT_DIR="$tmp/bundle apt" bash -c '
    f=$1; shift; source "$f"
    APT_DIR="$TEST_APT_DIR"
    install_apt_dependencies
  ' test "$installer"
}
if ! run_install >"$tmp/install.log" 2>&1; then
  cat "$tmp/install.log"; echo 'FAIL: local package installation failed'; exit 1
fi
if [ ! -f "$TEST_UNPACKED" ] || \
   ! grep -Fx 'offline-test-base_1_all.deb' "$TEST_UNPACKED" >/dev/null || \
   ! grep -Fx 'offline-test-app_1_all.deb' "$TEST_UNPACKED" >/dev/null; then
  cat "$tmp/install.log"; echo 'FAIL: apt never handed both local archives to dpkg'; exit 1
fi
echo 'ok: real apt hands the local dependency closure to dpkg with an empty host cache'

# Even if critical commands already exist, an apt error must stop installation.
cat >"$tmp/bin/apt-get" <<'EOF'
#!/bin/bash
echo 'E: seeded apt failure' >&2
exit 100
EOF
chmod +x "$tmp/bin/apt-get"
if run_install >"$tmp/error.log" 2>&1; then
  cat "$tmp/error.log"; echo 'FAIL: apt failure was hidden by existing commands'; exit 1
fi
echo 'ok: apt failure is fatal even when required executables are present'
