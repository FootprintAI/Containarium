<!-- Link the issue this PR addresses. Use "Closes #N" only when every
     "Done when" item in the issue is met. -->
Closes #

## What and why

<!-- 2-4 bullets. -->

## Checklist

- [ ] Tied to one issue; the PR is small and in scope.
- [ ] Tests added or updated, and they pass locally for the packages I changed.
- [ ] API change: defined in `proto/containarium/v1/*.proto` first, regenerated with `make proto` (no hand-edited generated code), typed enums instead of strings.
- [ ] New platform action: a `containarium <verb>` CLI subcommand first; any MCP tool is a thin wrapper over the same function.
- [ ] `CHANGELOG.md` entry added under `## [Unreleased]`.
- [ ] No instance, host, IP or tenant names in docs, comments, the PR description or commit messages (I grepped the diff).

### Dependencies, build and CI

Skip this block if the PR touches none of: `go.mod`, `go.sum`, `package*.json`, `.github/**`, `Makefile`, `scripts/**`, `install.sh`, Dockerfiles, `proto/**`, `deploy/**`, `terraform/**`.

- [ ] This change is in its own PR, not mixed with feature work.
- [ ] New or upgraded dependency: why it is needed and why the standard library or an existing module is not enough is explained above.
- [ ] Its licence is on the allow-list (`scripts/ci/check-licenses.sh` / `scripts/ci/npm-licenses.sh check` pass) and `NOTICE` is regenerated if needed.
- [ ] New or changed GitHub Action, base image or tool download: exact version and source are named above.
- [ ] No new `replace` directive and no new `@latest` tool install.

See [CONTRIBUTING.md](../CONTRIBUTING.md#dependencies-build-and-ci-changes).
