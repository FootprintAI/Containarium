#!/usr/bin/env bash
# A successful installer exit must not conceal apt/dpkg failure (#3061).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
for cmd in incus zfs jq curl; do
  printf '#!/bin/sh\nexit 0\n' >"$tmp/bin/$cmd"
done
cat >"$tmp/bin/dpkg" <<'EOF'
#!/bin/sh
printf '%s' "${AUDIT:-}"
EOF
chmod +x "$tmp/bin/"*
for cmd in bash grep; do ln -s "$(command -v "$cmd")" "$tmp/bin/$cmd"; done
check() {
  PATH="$tmp/bin" bash "$here/offline-install-guest.sh" --check-install "$tmp/install.log"
}
echo 'Containarium Air-Gapped Installation Complete' >"$tmp/install.log"
check
echo 'ok: clean installation accepted'
for error in 'E: Unmet dependencies' 'apt-get install exited non-zero; checking critical commands below' \
             'dpkg: error processing package incus' 'Errors were encountered while processing:'; do
  printf 'Containarium Air-Gapped Installation Complete\n%s\n' "$error" >"$tmp/install.log"
  if check; then echo "FAIL: concealed package error accepted: $error"; exit 1; fi
done
echo 'ok: concealed apt/dpkg failures rejected even when the installer exited zero'
echo 'Containarium Air-Gapped Installation Complete' >"$tmp/install.log"
if AUDIT='incus is only half configured' check; then
  echo 'FAIL: incomplete dpkg configuration accepted'; exit 1
fi
echo 'ok: incomplete dpkg configuration rejected'
mv "$tmp/bin/incus" "$tmp/incus.saved"
if check; then echo 'FAIL: missing Incus executable accepted'; exit 1; fi
echo 'ok: missing required executable rejected'
mv "$tmp/incus.saved" "$tmp/bin/incus"
echo 'partial installation output' >"$tmp/install.log"
if check; then echo 'FAIL: missing completion message accepted'; exit 1; fi
echo 'ok: missing completion message rejected'
