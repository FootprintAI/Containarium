#!/usr/bin/env bash
# Prove the installer's binary-source policy (#3681): a binary is installed only
# from a regular file owned by root or by the invoking operator. A file owned by
# anyone else, or a symlink, is refused with an error naming the path and the
# owner found. Needs no root: "another user" is any uid that is neither the
# file's owner nor 0.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/binary-source-policy.sh
. "$here/lib/binary-source-policy.sh"
# shellcheck source=lib/deploy-install.sh
. "$here/lib/deploy-install.sh"

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
pass=0; fail=0
ok() { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }

me="$(id -u)"; other=$((me + 4242))
printf x > "$work/mine"

# Owned by the invoking operator: accepted.
binary_src_check "$work/mine" "$me" >/dev/null 2>&1 && ok "operator-owned file accepted" || bad "operator-owned file accepted"

# Owned by a user who is not the operator (and not root): refused, path and owner named.
out="$(binary_src_check "$work/mine" "$other" 2>&1)"; rc=$?
[ $rc != 0 ] && ok "file owned by another user refused" || bad "file owned by another user refused"
case "$out" in *"$work/mine"*"uid $me"*) ok "refusal names the path and the owner";; *) bad "refusal names the path and the owner: $out";; esac

# Owned by root: accepted, whoever the operator is. Needs a root-owned regular file.
rootfile="$(readlink -f /bin/sh)"
if [ "$(stat -c %u "$rootfile")" = 0 ]; then
  binary_src_check "$rootfile" "$other" >/dev/null 2>&1 && ok "root-owned file accepted" || bad "root-owned file accepted"
else bad "no root-owned file to test with"; fi

# A symlink is refused even when its target is acceptable.
ln -s "$rootfile" "$work/link"
out="$(binary_src_check "$work/link" "$me" 2>&1)"; rc=$?
[ $rc != 0 ] && ok "symlink refused" || bad "symlink refused"
case "$out" in *"$work/link"*) ok "symlink refusal names the path";; *) bad "symlink refusal names the path: $out";; esac

# Missing path: refused.
binary_src_check "$work/none" "$me" >/dev/null 2>&1 && bad "missing path refused" || ok "missing path refused"

# The remote install command applies the same policy before it touches the unit.
mkdir -p "$work/fakebin" "$work/bin"
printf '#!/usr/bin/env bash\nexec "$@"\n' > "$work/fakebin/sudo"
printf '#!/usr/bin/env bash\necho "systemctl $*" >> "$FAKE_LOG"\n' > "$work/fakebin/systemctl"
printf '#!/usr/bin/env bash\nif [ "$1" = -u ]; then echo %s; else /usr/bin/id "$@"; fi\n' "$other" > "$work/fakebin/id"
chmod +x "$work/fakebin/"*
cmd="$(BIN_DIR="$work/bin" SRC="$work/mine" HEALTH_TRIES=1 HEALTH_INTERVAL=0 deploy_install_cmd containarium http://x)"
: > "$work/log"
PATH="$work/fakebin:$PATH" FAKE_LOG="$work/log" bash -c "$cmd" >"$work/out" 2>&1; rc=$?
[ $rc != 0 ] && ok "deploy install: foreign-owned source fails" || bad "deploy install: foreign-owned source fails"
grep -q "$work/mine" "$work/out" && ok "deploy install: error names the path" || bad "deploy install: error names the path"
[ ! -s "$work/log" ] && [ ! -e "$work/bin/containariumd" ] && ok "deploy install: unit and binary untouched" || bad "deploy install: unit and binary untouched"

# install-lab-tunnel.sh uses the same check, with the sudo-invoking operator.
grep -q 'binary_src_check "\$BINARY_SRC"' "$here/install-lab-tunnel.sh" && ok "install-lab-tunnel.sh applies the policy" || bad "install-lab-tunnel.sh applies the policy"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
