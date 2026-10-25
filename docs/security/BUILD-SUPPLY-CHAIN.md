# Build supply chain: lockfiles, pinned downloads, fetch inventory

Story 5 of the supply-chain umbrella (#2649, issue #2795). Every network fetch
a Containarium build, test lane or release makes is listed here with how it is
pinned. `scripts/ci/check-build-fetches.sh` (run by the `workflow-lint` lane,
with a seeded self-test) fails when a fetch exists that is not in
`scripts/ci/build-fetches.allow`, when an entry is stale, or when a listed file
is missing from this page. It also rejects, with no allow-list escape:

- any `@latest` tool install in workflows, composite actions, shell scripts,
  Makefiles and Dockerfiles;
- a project-level `npm install` (use `npm ci`; a pinned `npm install -g
  <pkg>@<version>` is an ordinary listed fetch).

Each fetch is one line in the allow-list, keyed by file, tool and a
fingerprint (a hash of the whitespace-normalised command), never by line
number. Moving or re-indenting a fetch needs no edit. Adding a fetch, changing
a URL, version or checksum, appending `| sh` to a listed command, or
duplicating a line fails the check until the allow-list is updated on purpose
(`scripts/ci/check-build-fetches.sh --list` prints the lines). The scanner
reads workflow and action YAML under `.github/`, `*.sh`, `*.bash`, `*.mk`,
Makefiles and Dockerfiles, joins backslash-continued lines, and recognises
`curl`, `wget`, `go install|get`, `npm|pnpm|yarn install|ci|add`, `npx`,
`pip`, `pipx`, `uv`, `cargo install`, `gem install`, `git clone`,
`docker pull`, `xcaddy build` and Dockerfile `ADD <url>`. A line that only
talks to `localhost`, `127.0.0.1` or `[::1]` is exempt; anything with another
host on the line is not.

## Pin levels

| Level | Meaning |
| --- | --- |
| lockfile | Resolved by `npm ci` against a committed `package-lock.json` (integrity hashes). |
| version + sha256 | Fixed version and a checksum verified before use. Checksums were computed from the downloaded upstream asset and cross-checked against the upstream checksum file or release digest. |
| module version | `go install <module>@vX.Y.Z`; the Go checksum database and module proxy verify the content. |
| version only | Fixed version, no checksum. A known gap, tracked below. |
| not a build fetch | Talks to a local or test-target service, or is text in an echo/notes. Listed because it matches the scanner. |

## Lockfiles

| Tree | Lockfile | Installed with |
| --- | --- | --- |
| `web-ui/` | `web-ui/package-lock.json` | `npm ci` (`web-ui/Dockerfile`, `scripts/build-webui.sh`, `proxyproto-e2e.yml`) |
| `agent-runtime/` | `agent-runtime/package-lock.json` | `npm ci` (`Makefile`, `agent-runtime.yml`, `scripts/install-agent-runtime.sh`) |
| `mcp-registry-submission/` | none | Not installed by any build or lane; its `package.json` declares no dependencies, so a lockfile would pin nothing. Add one with the first dependency. |
| `distros/py` | none | `pip`; see the pip rows below. Hash-locked requirements need a resolver we do not run today; tracked as a follow-up. |

The issue text says `webui/`; the directory is `web-ui/`.

## apt / package-manager installs (one category)

`apt-get install` in Dockerfiles, CI jobs and host setup scripts is not tracked
per file. It resolves against the distribution archive signed by the distro
keyring, with no per-package version pin. Third-party apt repositories add a
signing key fetch (rows below for `tenant-guard-e2e.yml`,
`scripts/install-lab-phase-b.sh`, `scripts/setup-gpu-host.sh`).

## Install-time and non-product trees (not scanned)

These fetch things when an operator installs or provisions, or are not part of
building the product. They are outside the check on purpose, not safe by
omission; several are the larger supply-chain risk and are tracked as
follow-ups.

| Tree | What it fetches | Pinned how |
| --- | --- | --- |
| `hacks/install.sh`, `hacks/install-cli.sh`, `hacks/runner/` | The operator install path: daemon and CLI binaries from a release (or the newest one by default), a package-repository signing key, the actions runner | Release tag when one is passed; no checksum; unpinned signing key |
| `terraform/` startup scripts | Daemon binary, sshpiper, and a Google ops-agent installer script on first boot | Version only |
| `pkg/core/stacks/stacks.yaml`, `pkg/core/recipes/recipes.yaml` (YAML outside `.github/`) | Tenant dev-stack and recipe installs, including `@latest` Go tools and a NodeSource `curl \| bash`, run inside a tenant container at the tenant's request | Unpinned |
| `benchmark/`, `examples/`, `experimental/` | Lab and demo scripts | Unpinned |

Follow-up: bring `hacks/install.sh` and the terraform startup scripts under the
check with a checksum for each download.

## Inventory

### Pinned with a checksum

| File | Tool | What | Pinned how |
| --- | --- | --- | --- |
| `scripts/install-xcaddy.sh` | curl | xcaddy release tarball for `make build-caddy`, `scripts/setup-caddy.sh`, `proxyproto-e2e.yml` | version + sha256 per platform in `scripts/xcaddy-version.env` (replaces `go install ...@latest`) |
| `scripts/install-buf.sh` | curl | buf release binary | version + sha256 per platform in `scripts/buf-version.env` |
| `.github/workflows/ebpf-load.yml` | curl | bpftool release tarball | version + sha256 (`BPFTOOL_VERSION`, `BPFTOOL_SHA256`) |
| `.github/workflows/fence-probe-e2e.yml` | curl | bpftool release tarball (twice: the observation-only job and the split-egress job each fetch it) | version + sha256 |
| `.github/workflows/release.yml` | curl | bpftool release tarball | version + sha256. The `curl` commands inside the release-notes heredoc are text shown to users, not fetches the build runs |
| `.github/workflows/k8s-e2e.yml` | curl | kind v0.24.0 binary | version + sha256 (`KIND_SHA256`, from the published `kind-linux-amd64.sha256sum`) |
| `.github/workflows/helm-install-upgrade.yml` | curl | kind v0.24.0 binary | version + sha256 |
| `.github/workflows/workflow-lint.yml` | curl | actionlint and zizmor release tarballs | version + sha256 |
| `scripts/install-sdlc-skills.sh` | curl | skills tarball and its `.sha256` from the same release | sha256 verified against the release sidecar file (integrity, not independent authenticity) |
| `scripts/redeploy-workhorse.sh` | curl | release binary and `SHA256SUMS.txt` | sha256 verified against the release's sums file when it is published |

### Pinned by lockfile or module version

| File | Tool | What | Pinned how |
| --- | --- | --- | --- |
| `web-ui/Dockerfile` | npm ci | web UI dependencies | lockfile |
| `scripts/build-webui.sh` | npm ci | web UI dependencies | lockfile (was `npm install`) |
| `Makefile` | npm ci | agent-runtime dependencies | lockfile |
| `.github/workflows/agent-runtime.yml` | npm ci | agent-runtime dependencies | lockfile |
| `.github/workflows/proxyproto-e2e.yml` | npm ci | web UI dependencies | lockfile |
| `scripts/install-agent-runtime.sh` | npm ci | agent-runtime production dependencies in a box | lockfile shipped in the bundle |
| `scripts/verify-agent-runtime-bundle.sh` | npm ci | bundle dependency check | lockfile shipped in the bundle |
| `scripts/ci/npm-licenses.sh` | npm ci | license scan of both lockfiles | lockfile |
| `.github/workflows/security.yml` | go install | govulncheck | module version `v1.9.0` (was `@latest`) |
| `.github/workflows/golangci-lint.yml` | go install | golangci-lint | module version |
| `.github/workflows/licenses.yml` | go install | go-licenses | module version `v1.6.0` |
| `scripts/ci/check-licenses.sh` | go install | go-licenses | hint text in an error message; module version `v1.6.0` |
| `sidecars/otel-sidecar/Dockerfile` | go install | OpenTelemetry collector builder | module version (`OTELCOL_VERSION`) |
| `sidecars/otel-sidecar/Dockerfile` | wget | `wget` is an apt package installed for the health check; no download | not a build fetch |
| `scripts/build-macos11.sh` | go install | rebuilds the patched Go linker from the local toolchain tree | not a network fetch |

### Version only or floating (known gaps, follow-up)

| File | Tool | What | Pinned how |
| --- | --- | --- | --- |
| `scripts/bundle/download-deps.sh` | curl | Go, Node, pnpm, golangci-lint, runner tarballs for the offline bundle (buf excepted, it is checksum-pinned above) | version only |
| `scripts/bundle/download-deps.sh` | wget | `wget` is listed as an apt package to bundle | not a build fetch |
| `scripts/download-swagger-ui.sh` | curl | swagger-ui source tarball | version only (`SWAGGER_VERSION`) |
| `scripts/install-agent-runtime.sh` | curl | agent-box, mcp-server and runtime bundle from a release tag | release tag; no checksum verification |
| `internal/runner/install_script_payload.sh` | curl | runner installer payload: Go tarball, NodeSource setup script piped to bash, actions runner tarball | version only; the NodeSource script is unpinned |
| `internal/runner/install_script_payload.sh` | npm install | `npm install -g pnpm@9` | major version range only |
| `.github/workflows/distros-py-ci.yml` | pip install | `pip install --upgrade pip`, `pip install -e ".[dev]"` | unpinned |
| `.github/workflows/distros-py-release.yml` | pip install | `pip install --upgrade pip`, `pip install build` | unpinned |
| `.github/workflows/tenant-guard-e2e.yml` | curl | Incus apt repository signing key | unpinned key fetch |
| `scripts/install-lab-phase-b.sh` | curl | Incus apt repository signing key | unpinned key fetch |
| `scripts/setup-gpu-host.sh` | curl | NVIDIA and Incus apt signing keys and source list | unpinned |
| `scripts/setup-gpu-host.sh` | wget | `wget` in an apt package list | not a build fetch |
| `scripts/setup-caddy.sh` | curl | `curl https://test.$DOMAIN` in a usage hint printed to the operator | not a build fetch |
| `Makefile` | xcaddy build | `make build-caddy` builds Caddy `$(CADDY_VERSION)` with `--with` plugin modules (caddy-l4 and the DNS providers) | Caddy core version pinned; plugin modules float to the newest version the Go module proxy serves (the Go checksum database still verifies each download). Pinning each module would also change the list `TestCaddyModulesInSyncWithMakefile` reads, so it is a follow-up |
| `scripts/setup-caddy.sh` | xcaddy build | Builds Caddy with one DNS plugin on a host | Caddy core and plugin float |
| `.github/workflows/proxyproto-e2e.yml` | xcaddy build | Builds Caddy for the real-Caddy e2e | Caddy core and plugins float |
| `scripts/k8s-sentinel-e2e.sh` | docker pull | The agent-box image, default tag `latest-stable` | Floating tag, no digest |
| `images/sshpiper/Dockerfile` | git clone | sshpiper source at `SSHPIPER_VERSION` | Release tag, no commit hash |
| `.github/workflows/ssh-approval-spike.yml` | git clone | sshpiper source at a release tag | Release tag, no commit hash |
| `.github/workflows/containarium-daemon.yml`, `.github/workflows/release.yml`, `.github/workflows/sidecars.yml` | docker pull | Pulls the image this workflow just published, by tag, so Trivy scans the registry copy | Tag produced by the same run; not an external dependency |
| `scripts/ci/npm-licenses.sh` | npx | `license-checker-rseidelsohn@5.0.1` | Exact version, npm registry integrity only, no lockfile |

### Probes of local or test-target services (not build fetches)

| File | Tool | What |
| --- | --- | --- |
| `.github/workflows/gitlab-e2e.yml` | curl | readiness and API probes of the GitLab service under test |
| `scripts/agent-skill-lease-e2e.sh` | curl | calls to the local gateway under test |
| `scripts/engineer-crew-e2e.sh` | curl | calls to the local gateway; HEAD request for the release bundle |
| `scripts/two-engine-crew-e2e.sh` | curl | calls to the local gateway; HEAD request for the release bundle |
| `scripts/ci/tunnel-smoke.sh` | curl | probe of a loopback test backend |
| `scripts/backup-scoped-token-e2e.sh` | curl | calls to the daemon under test through `$server`. It defaults to `http://localhost:8080` but can be overridden by `CONTAINARIUM_BACKUP_E2E_SERVER`, so the checker cannot prove it is loopback and its calls (through one wrapper) are listed rather than exempted |

## Adding a fetch

1. Pin it: a lockfile, a module version, or a version plus a checksum taken
   from the upstream asset (verify the hash yourself; do not copy it from a
   blog post). Model new checksum pins on `.github/workflows/workflow-lint.yml`
   or `scripts/install-xcaddy.sh`.
2. Add its line to `scripts/ci/build-fetches.allow` (`scripts/ci/check-build-fetches.sh --list`
   prints it; the snippet column is for reviewers and is not compared).
3. Add a row above naming the file, the tool and how it is pinned.

## Follow-ups (out of scope for #2795)

- Pin Dockerfile base images by digest (P1).
- Add checksums for the version-only rows above, and hash-locked pip
  requirements for `distros/py`.
