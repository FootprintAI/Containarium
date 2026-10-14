#!/usr/bin/env bash
# Exercise the same Makefile gates CI uses, including their failure paths.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

make -C "$repo" proto-lint
echo 'PASS: repository protos pass lint'

# A mismatched tool that would otherwise accept every command must be refused.
source "$repo/scripts/buf-version.env"
cat > "$scratch/old-buf" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == --version ]]; then echo 1.38.0; fi
exit 0
EOF
chmod +x "$scratch/old-buf"
if BUF="$scratch/old-buf" make -C "$repo" proto-lint > "$scratch/version.log" 2>&1; then
  echo 'FAIL: accepted the wrong buf version' >&2
  exit 1
fi
grep -q "requires buf $BUF_VERSION" "$scratch/version.log"
echo 'PASS: wrong buf version is rejected before lint'

# Isolate mutations from the checkout and run its actual Makefile recipe.
cp -R "$repo/proto" "$scratch/proto"
cp "$repo/buf.yaml" "$repo/buf.lock" "$repo/Makefile" "$scratch/"
mkdir -p "$scratch/pkg/version"
cp "$repo/pkg/version/version.go" "$scratch/pkg/version/"
mkdir "$scratch/scripts"
cp "$repo/scripts/buf-command.sh" "$repo/scripts/buf-version.env" "$scratch/scripts/"
probe="$scratch/proto/containarium/v1/proto_gate_probe.proto"
cat > "$probe" <<'EOF'
syntax = "proto3";
package containarium.v1;
option go_package = "github.com/footprintai/containarium/pkg/pb/containarium/v1;containariumv1";
message invalid_message_name {
  string value = 1;
}
EOF
if make -C "$scratch" proto-lint > "$scratch/lint.log" 2>&1; then
  echo 'FAIL: lint accepted a non-PascalCase message' >&2
  exit 1
fi
grep -q 'should be PascalCase' "$scratch/lint.log"
echo 'PASS: invalid message name makes the lint gate fail'

sed 's/invalid_message_name/ProtoGateProbe/' "$probe" > "$probe.tmp"
mv "$probe.tmp" "$probe"
make -C "$scratch" proto-lint
(cd "$scratch" && ./scripts/buf-command.sh build --output "$scratch/baseline.binpb")
PROTO_AGAINST="$scratch/baseline.binpb" make -C "$scratch" proto-breaking
echo 'PASS: unchanged schema passes breaking check'

sed '/string value = 1;/d' "$probe" > "$probe.tmp"
mv "$probe.tmp" "$probe"
if PROTO_AGAINST="$scratch/baseline.binpb" make -C "$scratch" proto-breaking > "$scratch/breaking.log" 2>&1; then
  echo 'FAIL: breaking gate accepted a deleted field' >&2
  exit 1
fi
grep -q 'Previously present field' "$scratch/breaking.log"
echo 'PASS: deleted field makes the breaking gate fail'
