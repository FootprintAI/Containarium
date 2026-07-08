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

That's it — two files, one commit, conventionally messaged
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
4. This triggers `release.yml`, which runs `make build-release` (10
   artifacts: the CLI for linux/darwin-amd64/darwin-arm64/windows, the
   MCP server and agent-box binaries for linux/darwin-amd64/darwin-arm64,
   plus a generated `SHA256SUMS.txt`) and publishes them as a GitHub
   Release attached to the tag.
5. **Verify the release actually built and published** — don't treat a
   pushed tag as done. Check the Release page has all expected
   artifacts and `SHA256SUMS.txt`, and that `containarium version` on a
   freshly downloaded binary reports the new tag.

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
