#!/usr/bin/env bash
# Shared by release.yml and the PR lane: build, inventory and package the same bytes.
set -euo pipefail
release=${1:?release id}
arch=${2:?amd64 or arm64}
tree="dist/toolchains-$arch"
mkdir -p bin
python3 scripts/toolchains/build.py --arch "$arch" --release "$release" --output "$tree"
"${SYFT:-syft}" scan "dir:$tree" -o "spdx-json=bin/toolchains-linux-$arch.spdx.json" -q
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert len(d["packages"]) > 1' "bin/toolchains-linux-$arch.spdx.json"
cp "$tree/manifest.json" "bin/toolchains-linux-$arch.manifest.json"
tar -czf "bin/toolchains-linux-$arch.tar.gz" -C "$tree" .
(cd bin && sha256sum "toolchains-linux-$arch.tar.gz" "toolchains-linux-$arch.manifest.json" "toolchains-linux-$arch.spdx.json" >> SHA256SUMS.txt)
