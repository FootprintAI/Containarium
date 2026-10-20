# Contributing to Containarium

Thanks for contributing. This file covers one thing that comes up often:
what happens when more than one pull request addresses the same issue.

## Claim the issue first

Comment on the issue before you start (for example "starting on this").
The earliest claim is the tiebreaker between otherwise comparable PRs.
If an issue is already claimed, ask in the thread before opening a PR.

## When several PRs address the same issue

Maintainers pick **one** PR to merge and close the others as duplicates.
We do not merge a blend of overlapping PRs. The decision uses this order:

1. **Gates (must pass, otherwise the PR is not a candidate).**
   - It builds, `go vet` is clean, tests pass, and CI is green
     (including `golangci-lint` and `gosec`).
   - It is not in conflict with `main`.
   - It follows the repo conventions in `CLAUDE.md`: proto-first API,
     generated code from `make proto`, typed enums instead of strings,
     CLI-first, no instance, host, or tenant names in files that ship.
   - Its scope matches the issue. No unrelated files, no regenerated code
     outside the change, no work that belongs to a different issue.
   - It does not close the issue early (`Fixes #N` only when every
     "Done when" item is met).
2. **Quality score** among the PRs that pass the gates, out of 100:
   works (30), fits the repo rules and the issue's recorded decisions (20),
   security and robustness (20), tests (15), scope and mergeability (15).
3. **Tiebreak** when scores are within a few points: earliest claim on the
   issue, then earliest opened PR.

Dependency order matters. A contract (proto) PR merges before PRs that build
on it. Dependent PRs rebase onto the winner rather than carrying their own
copy of the contract.

## What happens to the PRs that do not win

- We close them with a comment that names the winning PR and the reason.
- Anything strictly better in a closed PR is welcome as a follow-up PR or a
  review comment on the winner. Credit is kept in the commit message.
- A PR that is a good idea but premature (blocked on another issue) is
  put on hold, not closed.

## Dependencies, build and CI changes

The daemon runs as root on operators' hosts, so a change that alters what
gets built, downloaded or run in CI deserves more scrutiny than its line
count suggests. These paths are the ones we read most closely:

- `go.mod`, `go.sum`, `web-ui/package*.json`, `agent-runtime/package*.json`
- `.github/**` (workflows, Dependabot config)
- `Makefile`, `scripts/**`, `install.sh`, Dockerfiles
- `proto/**`, `deploy/**`, `terraform/**`

Keep such a change in its own PR, separate from feature work, and say in
the description what it changes and why. A maintainer reviews these paths
before merging. A required code-owner approval for them (a `CODEOWNERS`
file plus branch protection) is planned and not in place yet; it is
tracked in [#2792](https://github.com/FootprintAI/Containarium/issues/2792).

### Proposing a new dependency

Prefer the standard library and the modules already in `go.mod`. If you
still need a new one, open an issue (or explain it in the PR) before the
code lands, covering:

- what it is used for and why the standard library or an existing module
  does not do it;
- its licence. CI fails a Go module or npm package whose licence is not on
  the allow-list; the policy and the recorded exceptions are in
  [`docs/security/DEPENDENCY-LICENSES.md`](docs/security/DEPENDENCY-LICENSES.md);
- who maintains it and how active it is, and how many transitive modules it
  brings.

If the new module ships its own `NOTICE` text, regenerate `NOTICE` with
`scripts/ci/notice.sh generate > NOTICE` (the `licenses` workflow fails when it is
out of date). For a new or changed GitHub Action, `docker` base image or
tool download, name the exact version and where it comes from.

### What CI checks today

| Check | Workflow | Covers |
| --- | --- | --- |
| Dependency licences | `licenses.yml` | Go modules linked into shipped programs, web UI and `agent-runtime` npm packages, and that `NOTICE` is complete. Runs when `go.mod`, `go.sum`, a `package*.json` or the licence scripts change. |
| Static analysis, known vulnerabilities, dependency scan | `security.yml` | `gosec`, `govulncheck`, `Trivy`. See [`SECURITY.md`](SECURITY.md#automated-scanning). |
| Lint | `golangci-lint.yml` | `golangci-lint` on Go code. |
| Proto lint and compatibility | `proto.yml` | `buf` lint and breaking-change checks. |
| Dependency updates | `.github/dependabot.yml` | Weekly Go module and GitHub Actions update PRs. They are reviewed like any other PR. |

Run `scripts/ci/check-licenses.sh` (needs `go-licenses` v1.6.0) or
`scripts/ci/npm-licenses.sh check` locally to see a licence failure before
you push.

### Planned, not enforced yet

These are open stories of the
[contributor supply-chain gates](https://github.com/FootprintAI/Containarium/issues/2649)
epic. Until each ships, do not assume the check exists:

- OpenSSF Scorecard lane:
  [#2791](https://github.com/FootprintAI/Containarium/issues/2791)
- Code owners and required review on the paths above:
  [#2792](https://github.com/FootprintAI/Containarium/issues/2792)
- GitHub Actions pinned by commit SHA, and a workflow-lint lane:
  [#2793](https://github.com/FootprintAI/Containarium/issues/2793)
- Dependency-change gate (dependency review, new or changed `replace`
  directives, modules missing from the Go checksum database):
  [#2794](https://github.com/FootprintAI/Containarium/issues/2794)
- Lockfiles everywhere, pinned downloads and an inventory of build-time
  fetches:
  [#2795](https://github.com/FootprintAI/Containarium/issues/2795)

## Before you push

- Run `make proto` if you touched `.proto` files and commit the output.
- Run the tests for the packages you changed and `golangci-lint`.
- Grep your diff, PR description, and commit messages for concrete host,
  tenant, or IP names and anonymize them.
- Keep the PR small and tied to one issue.
- Add a `CHANGELOG.md` entry under `## [Unreleased]` (never inside a
  released section).
- Fill in the pull request template checklist.
