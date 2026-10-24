# Dependency-change gate

Story 3 of #2649 (#2794). Two workflows check every pull request that
changes dependencies. Neither has a `paths:` filter, so every check reports on
every PR.

| Check | Workflow | Runs on | Fails on |
| --- | --- | --- | --- |
| `dependency review` | `dependency-review.yml` | PRs | A new dependency, in any ecosystem the GitHub dependency graph reads, with a known vulnerability of severity high or critical. The licence summary is informational; the licence policy is `licenses.yml` ([DEPENDENCY-LICENSES.md](DEPENDENCY-LICENSES.md)). |
| `go mod verify (readonly, sum.golang.org)` | `deps-guard.yml` | PRs and `main` | The deps-guard unit tests or self-test; a Go environment without `-mod=readonly` and `GOSUMDB=sum.golang.org`, or with `GONOSUMDB`, `GOPRIVATE`, `GONOPROXY` or `GOINSECURE` set; `go mod verify`. |
| `deps-guard (replace + checksum database)` | `deps-guard.yml` | PRs | Compared with the PR base: a new or changed `replace`; a new or re-versioned module that sum.golang.org has no record of, or whose `go.sum` hash differs from it; a `go.sum` listing one module version twice with different hashes; a second `go.mod`, a `go.work` or a `vendor/` directory. |
| `deps-guard PR comment` | `deps-guard.yml` | Same-repo PRs | Never (reporting only). |

The comment lists each new or re-versioned module with its age (the module
proxy's publication time) and source (its recorded VCS origin). Modules
published less than 14 days ago, or of unknown age, are in bold. Fork PRs get
the same report in the job summary, because their token cannot comment.

## Overrides

A `deps-guard` failure is a hard fail with no label. The only override is a
code-owner approval of the PR (#2649, decision 4). It takes effect only once
the CODEOWNERS file and branch protection from #2792 are applied, and only if
`deps-guard (replace + checksum database)` is **not** a required check: a
required check that is red blocks the merge whatever the approval. The
environment rule and `go mod verify` are in their own check so they can be
required without blocking that override.

`deps-guard` does not run on pushes to `main`. A `replace` approved by a code
owner merges as intended; re-checking it against the previous commit would
only turn `main` red for a reviewed decision.

## What the gate trusts

- **The PR's own copy of the gate.** CI runs `scripts/ci/deps-guard.sh` and
  `cmd/deps-guard` as they are in the PR, so a PR that edits them can make the
  gate pass and make its report say anything. The gate cannot protect
  itself; code-owner review of `.github/**` and `scripts/**` (#2792) does.
  The sticky comment is advisory text from PR-controlled code. It is posted
  with every PR- or network-supplied string in a code span and every control
  character escaped, so it cannot carry links, mentions, HTML or workflow
  commands, but it is not a check to require.
- **TLS to sum.golang.org.** The checksum-database lookup trusts TLS to
  sum.golang.org and does not verify the signed tree note; the go command
  verifies the tree itself on every module download.

## Not checked

- `exclude`, `retract` and `toolchain` directives are not diffed. An
  `exclude` cannot add code, `retract` only affects consumers of this module,
  and the go command verifies a toolchain download against sum.golang.org.
- Only the root `go.mod` and `go.sum` are read. A second module, a workspace
  or a vendor directory fails the `layout` rule until the gate is extended to
  cover it.
- The `-replace` flags that image builds under `images/` pass to
  `go mod edit` are outside this gate; they are part of the build-time fetch
  inventory (#2795).
