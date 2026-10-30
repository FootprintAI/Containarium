# Managed build tools

Each Incus host installs one toolchain release under
`/opt/containarium/toolchains`. Boxes bind-mount that **parent directory**
read-only at the same path. `/usr/local/bin` links resolve through
`current/bin`; changing the host's `current` link updates existing boxes.
Toolchains consume host storage once, rather than each box's root filesystem.

The release includes Go (with gofmt), Node, npm (with npx), pnpm, buf,
protoc (with its standard includes), and staticcheck. Exact versions, source
URLs, archive SHA-256 digests and Go module checksums for Linux amd64/arm64 live in
[`tools.lock.json`](../scripts/toolchains/tools.lock.json). Bump that lock
deliberately from the vendors' stable releases; builds never resolve
`latest`. The managed `go` launcher sets `GOTOOLCHAIN=local`, including when
called from a bare non-interactive shell. npm is pinned independently and
replaces Node's bundled copy so its dependencies can be patched promptly.
The lock also inventories security updates to npm's bundled dependencies
(currently undici 6.29.1). These use verified registry archives and preserve
the dependency's compatible major version; the final installed tree is scanned.
staticcheck is rebuilt from its checksum-verified stable source using the
pinned Go security release, rather than retaining an older embedded stdlib
from an upstream prebuilt binary. Module downloads use the Go checksum
database and an explicit module checksum; no tool is built from `latest`.

`manifest.json` inventories the managed versions and lists python3, make,
git and gcc as **system tools supplied by the box image**. Their measured
versions come from the run wrapper's tool report. The release does not copy
those OS tools into the shared volume. npm has its own inventory entry.
Each architecture's tree is catalogued into an SPDX SBOM and scanned by
Trivy during both PR checks and the host release build. The scan uses
`rootfs`, which checks deployed binaries and installed npm packages. Trivy's
`fs` mode scans SDK source manifests instead of Go binaries; those
manifests also describe code generators and do not reflect security fixes
backported into a released Go toolchain. A coverage check requires the
actual Go, buf and staticcheck binaries in every report. High/Critical
findings with fixes block publication; scan reports are signed release assets.

## Install on each host

Install the tools alongside the matching daemon release. A binary-only
upgrade does not download or activate a toolchain automatically. Choose
`amd64` or `arm64` for the host CPU and an exact published release tag:

```bash
tag=vX.Y.Z
arch=amd64
mkdir -p toolchain-release
cd toolchain-release
gh release download "$tag" --repo FootprintAI/Containarium \
  --pattern "toolchains-linux-$arch.tar.gz" \
  --pattern "toolchains-linux-$arch.tar.gz.sigstore.json"
cosign verify-blob --bundle "toolchains-linux-$arch.tar.gz.sigstore.json" \
  --certificate-identity "https://github.com/FootprintAI/Containarium/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "toolchains-linux-$arch.tar.gz"
mkdir extracted
tar -xzf "toolchains-linux-$arch.tar.gz" -C extracted
sudo bash extracted/install.sh
```

The installer requires Bash, Python 3, coreutils and tar. It verifies the
archive's internal file checksums and CPU architecture, stages a root-owned,
world-readable release in `releases/<tag>`, then atomically switches
`current`. Existing releases are retained. Reinstalling the same version
verifies the existing copy before activation. A damaged installation or
download fails without switching `current`.

New Linux containers receive the mount at creation. Old boxes receive it
lazily when an unattended run starts. The daemon checks the kernel's mount
table for a read-only mount and checks every tool before exposing the links.
An existing executable in `/usr/local/bin` that conflicts with a managed
link is preserved; creation logs the conflict and keeps the box usable at
NONE/FULL_SUDO. A BUILD_TOOLS run refuses the conflict until the operator
reconciles it. This includes pnpm installed by the nodejs stack.

A `BUILD_TOOLS` run without a working mount is refused with
`FailedPrecondition` naming `/opt/containarium/toolchains`. `NONE` and
`FULL_SUDO` still work without a toolchain installation. npm/pnpm caches and
project outputs belong in the run user's writable home/workspace, outside
the shared volume. Registries remain reachable; this is not an install or
network restriction.

Node also needs the OS runtime libraries `libatomic.so.1` and
`libstdc++.so.6`, listed in the manifest. At create/lazy setup, the platform
probes Node and installs the small distro library packages only if Node
cannot start (`libatomic1`/`libstdc++6` on Debian, `libatomic`/`libstdc++` on
RHEL). Provisioned boxes skip this step. The agent remains unprivileged;
the toolchains themselves remain exclusively on the shared read-only mount.

## Update and rollback

Install the next release using the same steps. To roll back, rerun the
previous verified release's `install.sh`. Both operations switch only the
host's `current` link. Keep previous directories while processes may still
be using them. Coordinate activation with running builds: processes already
started can retain old executables while subsequent invocations see the
new release.

## Verification

The `Managed toolchains` PR checks build both real architectures, scan them,
and execute the native tools as an unprivileged user. The `Incus create path`
lane runs `TestIntegrationIncus_ManagedToolchainVolume`: create-time mount,
lazy hotplug, all tools visible through a bare `sh -c` as `ctn-run`, a kernel
read-only write rejection even as root, host-side version switch and
rollback on the same box without remount, and the actual run wrapper's
`PRESENT_AT_START` / `SYSTEM` report. The fixture executables isolate mount
semantics from tool download availability; the packaging lane checks the
real vendor binaries.

After a host rollout, an operator can confirm the actual released tools:

```bash
incus exec <box> -- su -s /bin/sh ctn-run -c \
  'env -i PATH=/usr/local/bin:/usr/bin:/bin sh -c "go version; node --version; npm --version; pnpm --version; buf --version; protoc --version; staticcheck -version; go env GOTOOLCHAIN"'
```

Expect the manifest's managed versions and `local` for `GOTOOLCHAIN`.
The wrapper report measures availability, not whether the agent used a tool.
