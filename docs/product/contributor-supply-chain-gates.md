# PRD: Contributor supply-chain gates — merge public contributions without merging an attack

**Date:** 2026-10-18
**Status:** reviewed — open questions decided 2026-10-19 on #2649; tracked there
**Owner:** @hsinatfootprintai

## Problem

The repository is public and already takes pull requests from people
outside the organisation: of the last 200 merged PRs, 18 came from six
external accounts, 12 from Dependabot, and the rest from the two
maintainers (both repo admins; there are no other collaborators).
Opening up further means more PRs from people nobody has met, more
agent-authored PRs, and the same two reviewers.

The question the maintainers cannot answer today with evidence is: *when
I merge this PR, how do I know it did not add a dependency, a build step,
or a CI change that lets someone else's code run in our users' daemons or
in our pipeline?* Dependency and build-pipeline attacks are the dominant
open-source attack class of the last three years (a backdoor shipped
through a maintainer-trusted compression library; a widely used GitHub
Action retagged to exfiltrate CI secrets; typosquatted and hijacked
packages in every registry). The daemon this repository ships runs as
root on customers' hosts and is served to their workhorses by the
sentinel, so one bad merge is a fleet-wide problem, not a repo problem.

What exists today (verified on `main`, 2026-10-18):

| Control | State |
|---|---|
| Branch protection on `main` | 7 required status checks, strict, admins enforced |
| Required approving reviews | **none** — a PR with green checks can be merged with zero reviews |
| `CODEOWNERS` | **absent** — no path requires a specific reviewer |
| GitHub Actions pinning | **0 of 17** distinct actions pinned by commit SHA; one pinned to a mutable branch (`trivy-action@master`) |
| Default `GITHUB_TOKEN` | **write**; the token may approve pull requests; allowed actions: **all** |
| Secret scanning / push protection / Dependabot security updates | **all disabled** (Dependabot *version* updates are on, weekly, Go + Actions) |
| Dependency review on PRs | **none** — a PR that adds a module or a `replace` directive gets no automated comment or block |
| Go module integrity in CI | `go mod tidy` no-op check only; no `go mod verify`, no `-mod=readonly`, no explicit `GOSUMDB` policy |
| Lockfiles | Go: `go.sum` ✓; `agent-runtime`: `npm ci` ✓; **`webui`: no lockfile, `scripts/build-webui.sh` runs `npm install`** (floating versions resolved at build time) |
| Floating tool installs | `go install .../xcaddy@latest` in `Makefile:320` and `scripts/setup-caddy.sh:103` |
| Security lanes | gosec, govulncheck, Trivy, two repo-specific injection gates (#1732, #1596), `go mod tidy` drift |
| Fork PR workflows | `first_time_contributors` approval; no `pull_request_target`; self-hosted runners never run on `pull_request`; PR workflows reference no secrets a fork could reach |
| Release artefacts | container images carry provenance + SBOM; binaries are checksummed only (signing is #2561) |
| Contributor policy | `CONTRIBUTING.md` covers claiming and duplicate PRs; says nothing about dependency or CI changes; no PR template |

Evidence that the gap is real, not theoretical:

- #1732 (closed): a Make-level variable override was a second injection
  layer under a shell-quoting fix. The class of "build system is an
  attack surface" has already bitten this repo once.
- 2026-10-18: PR #2644 was merged by a maintainer within minutes of
  opening, before the review's should-fix items landed (they followed as
  #2647). Nothing was wrong with that PR; it shows that with no required
  review the only gate is the merger's attention on a busy day.
- The most dangerous changes are the smallest to read: one line in
  `go.mod`, one `replace` to a fork, one `uses:` retag, one `npm install`
  of a new package. Diff review does not scale to them without tooling.

**Why now.** Opening to public contributors is the stated plan; agent-
authored PRs multiply PR volume without multiplying reviewers; the
reseller-readiness review (#2561) is already asking for supply-chain
evidence on the release side. The merge side has to be at least as
defensible as the release side.

## Target user

The **repository maintainer** who reviews and merges. Job-to-be-done:
*merge a PR from someone I do not know, in a few minutes, with the
machine having already told me what it changed in dependencies, build and
CI, and with the repository refusing to let me (or a stolen token) skip
that look.* The external contributor is the second user: they must be
able to see the rules before they push and get a clear, fast "why was my
PR blocked".

## Success metrics

| Metric | Baseline | Target |
|--------|----------|--------|
| OpenSSF Scorecard score (the industry's standard measure of exactly these controls) | unknown — instrument first (story 1) | ≥ 7.0 within 30 days of the gates landing; no check scoring 0 among Branch-Protection, Pinned-Dependencies, Token-Permissions, Dangerous-Workflow, Dependency-Update-Tool |
| PRs that change dependency, build or CI paths merged without a code-owner approval | not measurable (no code owners, no required review) | 0, enforced by branch protection, measured monthly from the audit log |
| Actions pinned by full commit SHA | 0 / 17 | 17 / 17, and a lane that fails on any unpinned `uses:` |
| Median time from PR open to first automated supply-chain verdict (dependency diff + lanes) | n/a | < 10 minutes, so the gate costs contributors no waiting |

## MVP scope: the core journey

> An external contributor opens a PR that, among other things, adds a Go
> module and bumps a GitHub Action. Within ten minutes CI has posted a
> dependency report on the PR: the new module, its version, source,
> age, licence, whether it or its version is known-vulnerable, and that a
> `replace` directive was introduced. The pinning lane fails because the
> Action is referenced by tag. Branch protection shows the PR needs an
> approval from a code owner because it touched `go.mod` and
> `.github/workflows/`. The contributor reads `CONTRIBUTING.md`, pins the
> Action by SHA, explains the new module in the PR template's dependency
> section, and pushes. A maintainer reads the report, approves as code
> owner, and merges. Nothing in this journey needed the maintainer to
> diff `go.sum` by eye.

### P0 stories

**Story 1: Measure first — OpenSSF Scorecard lane and badge.**
As a maintainer, I want the repository's supply-chain posture scored by
the standard tool on every push to `main` and weekly, so that the rest of
this PRD has a baseline and a regression alarm.
**Acceptance criteria:**
- [ ] `ossf/scorecard-action` runs on push to `main` and weekly, with
      results published to the repository's code-scanning view and the
      badge in `README.md`.
- [ ] The first run's per-check scores are recorded on the tracking
      issue as the baseline.
- [ ] The workflow itself is SHA-pinned and has read-only token
      permissions except the `security-events: write` it needs.
**Priority:** P0 · **Size:** S

**Story 2: Code owners and required review for the paths that matter.**
As a maintainer, I want any PR that touches dependency, build, CI,
install, or contract files to require an approving review from a code
owner, with stale approvals dismissed on new pushes, so that no such
change can land on a green checkmark alone.
**Acceptance criteria:**
- [ ] `.github/CODEOWNERS` names the maintainers for: `go.mod`, `go.sum`,
      `.github/**`, `Makefile`, `scripts/**`, `install.sh`,
      `**/Dockerfile*`, `**/package.json`, `**/package-lock.json`,
      `proto/**`, `deploy/**`, `terraform/**`, `webui/package*.json`.
- [ ] Branch protection on `main`: 1 required approving review, code-owner
      review required, stale reviews dismissed on push, conversation
      resolution required; existing required checks and admin enforcement
      kept.
- [ ] Repository Actions settings: default `GITHUB_TOKEN` permissions
      **read**; "allow GitHub Actions to approve pull requests" **off**;
      allowed actions restricted to GitHub-owned, verified creators, and
      an explicit allow-list of the third-party actions the workflows use.
- [ ] Secret scanning, push protection, and Dependabot security updates
      **on**.
- [ ] A PR from a non-owner that edits only `go.mod` shows "review
      required from code owners" and cannot be merged until a listed
      owner approves (verified with a throwaway PR).
**Priority:** P0 · **Size:** S (settings) · **needs-verification** (repo
settings are not CI-provable; verify on the live repository)

**Story 3: Dependency-change gate on every PR.**
As a maintainer, I want every PR that changes dependencies to get an
automated report and to fail when the change is known-bad, so that the
review of a one-line `go.mod` change starts from facts.
**Acceptance criteria:**
- [ ] `actions/dependency-review-action` runs on `pull_request`, fails
      on any added dependency with a known vulnerability of severity
      ≥ high, and comments a summary (added/removed/changed, licences)
      on the PR.
- [ ] A `deps-guard` job fails when a PR introduces or changes a
      `replace` directive in `go.mod`, or adds a module whose path is not
      on the `sum.golang.org` checksum database; the failure message says
      exactly which line and why. There is no label override: the only
      way past is a code-owner approval of the PR (decided 2026-10-19).
- [ ] Go module integrity in CI: `go mod verify` passes, builds run with
      `GOFLAGS=-mod=readonly`, and `GOSUMDB=sum.golang.org` is set
      explicitly (no `GONOSUMDB`/`GONOSUMCHECK`); the existing
      `go mod tidy` drift check stays.
- [ ] The job comments the **age** (first-publish date) and **source
      repository** of every newly added module; a module younger than 14
      days is called out in bold. (Age is the cheapest typosquat and
      hijack signal.)
- [ ] Tests: a fixture PR adding a `replace` fails; one adding a known-
      vulnerable version fails; one bumping an existing module within
      the same major passes with a comment.
**Priority:** P0 · **Size:** M

**Story 4: Pin every Action by SHA and lint the workflows.**
As a maintainer, I want all `uses:` references pinned to full commit
SHAs with a version comment, and a lane that fails on any unpinned or
dangerous workflow pattern, so that a retagged upstream Action cannot
run in our CI.
**Acceptance criteria:**
- [ ] All 17 distinct actions across the 29 workflows are pinned to a
      40-character SHA with a `# vX.Y.Z` comment; `trivy-action@master`
      is replaced by a released, pinned version.
- [ ] A `workflow-lint` lane runs `zizmor` (or `actionlint` plus a pin
      check) on `pull_request` and fails on: unpinned `uses:`, any
      `pull_request_target` with a checkout of the PR head, template
      injection of `${{ github.event.* }}` into `run:` steps, and
      `permissions` missing or broader than `contents: read` without a
      job-level justification comment.
- [ ] Dependabot's existing `github-actions` schedule keeps the SHAs
      current (it updates SHA pins with version comments).
- [ ] Every workflow declares top-level `permissions: contents: read`
      and elevates only per job (today all 29 declare permissions;
      confirm none is broader than it needs).
**Priority:** P0 · **Size:** M

**Story 5: Lockfiles and pinned tool downloads everywhere code is built.**
As a maintainer, I want every build step to resolve exactly the versions
committed in the repository, so that a release built tomorrow contains
the same third-party code as the one tested today.
**Acceptance criteria:**
- [ ] `webui/package-lock.json` committed; `scripts/build-webui.sh` and
      every workflow use `npm ci`, never `npm install`; a lane fails if
      `package.json` changes without the lockfile.
- [ ] No `@latest` or unpinned `go install` in `Makefile`, `scripts/**`,
      or workflows; `xcaddy` is pinned to a version and its checksum is
      verified where the script downloads a binary.
- [ ] A `build-fetch-inventory` doc (`docs/security/BUILD-SUPPLY-CHAIN.md`)
      lists every network fetch a build or install script performs
      (module proxy, npm, apt, GitHub releases, container base images)
      and how each is pinned; the list is checked by a test that greps
      for `curl|wget|go install|npm install|pip install` outside the
      allow-listed lines.
**Priority:** P0 · **Size:** M

**Story 6: Tell contributors the rules before they push.**
As an external contributor, I want to know which changes need a
maintainer's explicit sign-off and what the automated gates will check,
so that my PR is not a surprise to either side.
**Acceptance criteria:**
- [ ] `CONTRIBUTING.md` gains a "Dependencies, build and CI changes"
      section: what paths are code-owned, that new modules need a reason
      in the PR, that Actions must be SHA-pinned, that `replace`
      directives are refused by default, and the expected turnaround.
- [ ] `.github/PULL_REQUEST_TEMPLATE.md` with a short checklist including
      "Dependencies added/changed? List each with why and link to its
      source" and "Workflow/build changes? Explain".
- [ ] `SECURITY.md` "Automated scanning" section updated to list the new
      lanes and the Scorecard badge, so the policy describes what runs.
**Priority:** P0 · **Size:** S

Six P0 stories, all small or medium. Stories 2 and 4 remove the two
largest exposures (zero required review; mutable Action references);
story 3 is what makes the review of a dependency change a minute's work
instead of an act of faith.

## Later phases

- **P1 — DCO sign-off (`Signed-off-by`) enforced by a lane.** Provenance
  of authorship for external contributions; cheap, but it adds friction
  to every PR and is not a security control against malicious code.
- **P1 — CodeQL for Go and TypeScript** alongside gosec; broader taint
  analysis on the paths external PRs touch. Needs a tuning pass to be
  more signal than noise.
- **P1 — Sign release binaries and the offline bundle** (#2561; cosign +
  SBOM). The release side of the same story; already filed.
- **P1 — Semgrep rules for this repository's own injection classes**
  (#1732 Make override, #1596 host-key persistence) so the gates that
  exist as one-off shell checks become reviewable rules.
- **P1 — Agent-authored PR policy.** A PR whose author is the
  maintainer's own account but produced by an agent gets a second
  human's approval or a cooling-off period before merge; today the
  same account authors, reviews and merges.
- **P2 — Reproducible builds.** Two independent builds of a tag produce
  byte-identical binaries; the strongest answer to "what is in this
  release", and the most work.
- **P2 — SLSA level 3 provenance for binaries** (images already carry
  buildx provenance).

## Out of scope

- **A CLA.** Legal provenance, not security; DCO (P1) covers the
  authorship question with less friction.
- **Commit signature requirement (GPG/SSH) for contributors.** High
  friction for first-time contributors; branch protection and code-owner
  review on sensitive paths give the control this PRD needs.
- **Running fork PRs on self-hosted runners in a sandbox.** They do not
  run there today (verified: the self-hosted job is gated to push,
  schedule and dispatch); keep it that way rather than build a sandbox.
- **A full licence-compliance programme.** #2561's allow-list scan
  covers release artefacts; this PRD only surfaces licences in the PR
  report.
- **Replacing Dependabot with Renovate.** Dependabot already covers Go
  and Actions weekly; switching tools is not a security gain.

## Open questions & assumptions

All five were decided on 2026-10-19 (#2649): 1 both admins over the full
path list; 2 Dependabot under the same review; 3 the allow-list is the
current inventory; 4 hard fail with a code-owner PR approval as the only
override (no `deps-approved` label); 5 Scorecard target 7.0. The original
questions are kept below for the record.

1. **Who are the code owners?** Assumption: the two current admins, with
   a team added when a third maintainer exists. With two owners and one
   of them authoring most PRs, every code-owned change by one owner
   needs the other's approval. Validate that the pace is acceptable; if
   not, the fallback is code-owner review on `go.mod`, `go.sum` and
   `.github/**` only.
2. **Dependabot PRs and the required review.** Assumption: Dependabot
   PRs go through the same code-owner review (they change `go.mod`).
   Auto-merge for patch bumps that pass all lanes is a P1 decision, not
   a default.
3. **Third-party action allow-list.** Assumption: `aquasecurity/trivy-
   action`, `docker/*`, `azure/setup-helm`, `golangci/golangci-lint-
   action`, `ossf/scorecard-action` and `actions/dependency-review-
   action` are the full set; story 4 confirms by inventory.
4. **`deps-approved` label semantics.** Assumption: only code owners
   can apply it (GitHub cannot restrict label application per label; the
   lane checks the label's last applier via the API). Validate that this
   is enforceable; otherwise the `replace`-directive guard is a hard
   fail with the override being a code-owner approval of the PR.
5. **Scorecard target.** 7.0 is chosen as the common "good" threshold;
   the first run sets the real baseline and may move the target.
