# Release Process

How to cut a new Containarium (OSS) release: which files change, how the
release pipeline is triggered, and how to confirm it actually shipped.

This covers the **containarium** repo only. `containarium-cloud` is a
separate, closed-source repo with its own (stricter) release gate — not
covered here.

## Versioning

Containarium follows [Semantic Versioning](https://semver.org/) —
`vMAJOR.MINOR.PATCH`, e.g. `v0.48.2`. Tags are the source of truth for
what a released binary reports as its version; see [How release builds
get their version](#how-release-builds-get-their-version) below for why
that matters.

## Files to change when cutting a release

1. **`CHANGELOG.md`** — move the `## [Unreleased]` section's contents (or
   add new entries) under a new `## [X.Y.Z] - YYYY-MM-DD` heading, above
   the previous release. Keep an empty `## [Unreleased]` heading at the
   top for the next round of changes. Follow [Keep a
   Changelog](https://keepachangelog.com/en/1.0.0/) categories (`Added`,
   `Fixed`, `Changed`, etc.).
2. **`pkg/version/version.go`** — bump the `Version` constant to match
   the tag (no `v` prefix, e.g. `"0.48.2"`).
3. **Only if the skills should move: `pkg/core/sdlcskills/sdlc-skills.lock`** —
   the SDLC role skills shipped in coding-agent boxes are pinned to a
   commit of
   [open-sdlc-skills](https://github.com/FootprintAI/open-sdlc-skills)
   (it has no tags). Ask "bump the skills pin?" at every cut: if the
   answer is yes, set `ref` to the new full commit SHA and run
   `scripts/build-sdlc-skills-bundle.sh --update-lock bin/` to refresh the
   `sha256`. The release build and the `sdlc-skills-lock` check both
   rebuild the tarball from the pin and fail on a digest mismatch, so
   forgetting the digest cannot ship.

That's it — two files (three when the skills pin moves), one commit, conventionally messaged
`chore(release): cut vX.Y.Z — <one-line summary>` (see recent history on
`main` for the pattern). PR it, get CI green, merge like any other
change.

**Not required:** `web-ui/package.json`'s `version` field is versioned
independently of the daemon and does not need to track the release tag.

## How release builds get their version

`pkg/version/version.go`'s `Version` constant is only the **fallback**
used by a plain `go build` / `make build`. A real release build
overrides it via `ldflags`:

```
make build-release VERSION="${GITHUB_REF_NAME#v}"
```

`.github/workflows/release.yml` triggers on any pushed tag matching
`v*` and runs exactly this. **There is currently no CI gate that checks
`pkg/version/version.go` matches the tag** — a forgotten bump won't fail
the release build, it just means anyone building from source with plain
`go build` between releases sees a stale fallback version. Bump it
anyway; it's the only thing a non-release build has to go on.

## Cutting a release, step by step

1. Confirm everything you want in the release is merged to `main`.
2. Branch off `main`, make the two file changes above, commit, PR,
   merge (see [Files to change](#files-to-change-when-cutting-a-release)).
3. Tag the merged commit on `main` and push the tag:
   ```bash
   git checkout main && git pull
   git tag v0.48.2
   git push origin v0.48.2
   ```
4. This triggers **four** workflows, not one — see [What a tag
   push actually publishes](#what-a-tag-push-actually-publishes) below.
   Pushing the tag is the point of no return for all of them.
5. **Verify every one of them actually built and published** — don't
   treat a pushed tag as done. Check the Release page has all expected
   artifacts and `SHA256SUMS.txt`, that `SHA256SUMS.txt` lists every
   asset except the `.sha256` sidecars, itself, the `.sigstore.json`
   signatures and the air-gapped `containarium-bundle-*` tarball (that
   one is covered by its sidecar only), that `containarium version` on a
   freshly downloaded binary reports the new tag, and that the image
   and PyPI publishes succeeded. For the Helm chart, check that
   `containarium-k8s-<version>.tgz` and its `.sha256` are on the Release
   page (`sha256sum -c` passes), that the sums verify the downloads:
   `gh release download <tag> --pattern SHA256SUMS.txt --pattern
   'containarium-k8s-*.tgz' --pattern agent-runtime-bundle.tar.gz &&
   sha256sum -c --ignore-missing SHA256SUMS.txt`, that
   `helm pull oci://ghcr.io/<org>/charts/containarium-k8s --version <version>`
   succeeds, and that the pulled chart is stamped `version: <version>` and
   `appVersion: v<version>`. Check that the `sign-release` job ran and
   that every file on the Release has a `<file>.sigstore.json`
   (`docs/security/VERIFYING-RELEASES.md`); verify one binary with the
   documented `cosign verify-blob` command. This job and the SBOM
   attachment run only on a real tag, so the first release after they
   landed is their first run: expect to look.
   Also require the `helm-install-upgrade` job to pass: it downloads the
   published OCI chart, installs baseline `0.108.0`, upgrades to this tag,
   then clean-installs this tag in kind (Kubernetes 1.31.0), checking the
   running daemon's exact image and readiness. The chart is already published
   when this check runs; a failed job means the release needs attention,
   even if its files are downloadable. See `docs/EKS-GKE-DEPLOY.md` for the
   compatibility baseline and local command.
6. **Wait for the managed-clusters KVM e2e lane to go green on the
   tag** (`.github/workflows/cluster-e2e.yml`, also runs nightly). It
   is release-blocking (#1418): a red or missing run means the release
   is not announced or deployed anywhere until the lane passes on that
   tag — the publish workflows above don't wait for it, so this gate
   is yours to enforce.

   That workflow carries two other release-blocking jobs. `agent-skill-lease`
   needs nothing from you. `engineer-crew-live` runs a real model against a
   pinned public fixture and therefore only does anything when a provider-key
   Actions secret (`ANTHROPIC_API_KEY` or `GEMINI_API_KEY`) exists on the
   repository; with no secret it emits a `::notice::` and is green without
   having measured anything, which is expected and not a gate you need to
   chase. It also waits for `release.yml` to publish the tag's
   `agent-runtime-bundle.tar.gz` before it can run — so if that publish fails,
   expect this job to go red for that reason and fix the publish, not the lane.

### Release checks that run for you

`release.yml` runs these in the build job, before the GitHub Release is created,
so a failure stops the publish:

- **Tunnel interop smoke test** (`scripts/ci/tunnel-smoke.sh`, #2469). The built
  `containariumd` runs as the sentinel and as the tunnel client: the pin is read
  with `sentinel tunnel-identity`, the client must register over TLS, and a
  request must round-trip through the tunnel. A second step repeats it with the
  *previous release's* `containariumd` as the client, the combination a staged
  rollout actually runs. You can run it by hand against any build:
  `scripts/ci/tunnel-smoke.sh ./containariumd [./older-containariumd]` (needs
  passwordless sudo; the sentinel adds a loopback alias).

### Release PR checklist

Before merging the release PR, check each:

- **Upgrade notes.** Any change in this release that makes a client flag or
  environment variable mandatory, or removes a fallback, has an explicit
  "Upgrading" heading in the changelog that names the flag and what an operator
  must do first. v0.101.0 and v0.101.1 made `--sentinel-pin` mandatory on tunnel
  clients without saying so, and a tunnel host upgraded on release day could not
  reconnect.
- **Paired changes.** If a change to a client needs a counterpart on the server
  (or the reverse), both halves are in this release. If the second half is not
  merged yet, the first half does not ship: revert it from the release branch or
  hold the release.

## What a tag push actually publishes

A `v*` tag fires **four** workflows in parallel. Three of them publish
to places you cannot un-publish from, so read this before pushing a tag
rather than after.

| Workflow | What it publishes | Where | Reversible? |
| --- | --- | --- | --- |
| `release.yml` | 28 assets: the CLI for linux/darwin-amd64/darwin-arm64/windows (plus best-effort `-macos11` darwin builds from `scripts/build-macos11.sh`), MCP server and agent-box binaries for linux/darwin-amd64/darwin-arm64, the agent-runtime bundle (listed in `SHA256SUMS.txt`), the SDLC skills bundle + its `.sha256` (#2065), the air-gapped install bundle + its `.sha256`, the Helm chart `containarium-k8s-<version>.tgz` + its `.sha256`, four SPDX SBOMs (`containariumd`, `containarium`, `mcp-server`, `agent-box`, linux/amd64; #2561), and a generated `SHA256SUMS.txt` that lists the binaries, the SBOMs, the agent-runtime bundle, the SDLC skills bundle and (appended by the `helm-chart` job, which downloads, appends and re-uploads the file before signing; #2702) the chart `.tgz`, and a keyless cosign `<file>.sigstore.json` for each of those files (the `sign-release` job, #2561). The `helm-chart` job also pushes the chart to GHCR as an OCI artifact (`oci://ghcr.io/<org>/charts/containarium-k8s`) | GitHub Release on the tag, and GHCR | Release assets are deletable, but anyone who already pulled has them; treat a published OCI chart version as permanent |
| `containarium-daemon.yml` | Daemon container image | `ghcr.io/footprintai/containarium` | Tag is mutable in principle; treat as published |
| `sidecars.yml` | `containarium-otel-sidecar`, `containarium-sshpiper`, `containarium-agent-box` images | `ghcr.io` | Same |
| `distros-py-release.yml` | `containarium-telemetry` Python package | **PyPI** | **No.** PyPI does not allow re-uploading a version, even after deletion |

The PyPI one deserves particular care: per `TELEMETRY-DISTRO-DESIGN.md`
decision D5 the distro version tracks the project version, so **every**
`v*.*.*` tag publishes a matching `containarium-telemetry` release. A
version number, once used on PyPI, is burned — you cannot re-upload it
after deleting it. A botched tag therefore costs a version number
permanently on PyPI, whereas on GitHub it only costs a dead tag (as with
v0.48.0 below).

That asymmetry is the reason not to push a tag "to see if the build
works" — and the reason you don't have to.

### Cross-platform build checks

The released `containarium` client targets Linux/amd64, macOS/amd64,
macOS/arm64, and Windows/amd64. Build the client with
`-tags containarium_client`.

The released `agent-box` targets Linux/amd64, macOS/amd64, and macOS/arm64.
`internal/agentbox` and `cmd/agent-box` use Unix process and file-locking
APIs and are excluded from Windows builds. Windows clients reach
`agent-box` on a Linux box over SSH.

Windows validation covers the client, rather than `go build ./...`:

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
  -tags containarium_client -o /dev/null ./cmd/containarium/
```

The `cli-split-gates.yml` workflow cross-compiles the Windows client and
the macOS client and `agent-box` for both amd64 and arm64. It also runs
the hostcheck, agentbox, and sandbox/dialer tests on Linux and rejects
agent-box source files enabled for Windows. Cross-compilation checks
build compatibility; it does not run the binaries on Windows or macOS.

### Rehearsing a release build without publishing

`release.yml`, `containarium-daemon.yml` and `sidecars.yml` each accept
a `workflow_dispatch` trigger that runs the **identical** build against
any ref and publishes nothing: no Release, no artifact upload, no image
push, no chart push. For `release.yml` this includes the Helm chart: the
rehearsal packages it and renders it to check the pinned daemon image, and
skips the GHCR login, OCI push and Release upload. Use it before tagging, especially when the diff touches the build
itself (new `cmd/` files, web-ui changes, Dockerfiles, `Makefile`).

```bash
gh workflow run release.yml --ref main -f version=0.61.0-rc
gh workflow run containarium-daemon.yml --ref main -f version=0.61.0-rc
gh workflow run sidecars.yml --ref main -f version=0.61.0-rc
```

`version` is optional (defaults to `0.0.0-dryrun`) and only labels the
build — nothing is published under it. Publishing is gated on the ref
being a tag, so a rehearsal cannot become an accidental release.

This directly covers the two incidents below: both were build failures
invisible until a real tag had already been pushed, costing a burned
tag. A rehearsal on the merge commit would have caught either one.

**`distros-py-release.yml` is the exception** — its `workflow_dispatch`
exists for recovering from a PyPI infra blip and it **does** publish. Do
not use it as a rehearsal.

## Why step 5 matters: two real incidents

Both caught *after* a tag was pushed, because nothing exercised the
real release build at PR time:

- **v0.47.0**: the release build's Windows CLI binary
  (`GOOS=windows go build ./cmd/containarium/`) broke because a new file
  under `cmd/` transitively imported the Linux-only eBPF loader
  (`internal/netbpf`) without a `//go:build !windows` guard. Regular PR
  CI never cross-compiled for Windows, so this was invisible until the
  release build itself failed.
- **v0.48.0**: `make build-release`'s full `next build` (with real
  TypeScript type-checking) failed on two genuine web-ui compile errors.
  Neither was caught at PR time — no CI job ran a full production
  web-ui build; `next dev` and lint both stayed green. **No artifacts
  were ever published from the v0.48.0 tag** — it's a dead tag,
  superseded by v0.48.1.

Both classes of gap are now covered by PR-time CI (see the "Windows
build guard" and "Web UI build guard" steps in
`.github/workflows/proxyproto-e2e.yml`) — but treat that as defense in
depth, not a reason to skip verifying a specific release's artifacts
before pointing anything at it.

## Deploying a release to a host you operate

Cutting a release and deploying it to a specific host are two different
actions — don't conflate them. Once a tag's artifacts are verified
published:

- `scripts/deploy-binary.sh` is the operator-side tool for rolling a
  release binary onto a primary + sentinel pair. See its own `--help`
  and the script's inline comments for current flags and known gotchas
  (host daemon service unit naming has drifted between hosts before;
  verify the live unit before scripting a restart).
- Never scp an ad hoc binary built from an untagged commit onto a host
  that serves real traffic. If a fix needs to reach production, cut a
  release for it first — that's the whole point of this document.
