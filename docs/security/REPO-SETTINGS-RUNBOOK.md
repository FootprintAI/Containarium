# Repository settings runbook (supply chain story 2)

Decided on #2649, tracked in #2792. This applies the repository settings that
make a code-owner review mandatory for the build-and-dependency paths and
tightens the Actions defaults. **A repository admin runs it.** The script is
reviewed in a PR like any code; applying it is a separate, human action. No
agent changes live settings.

## What is applied

| Area | Setting | Target |
| --- | --- | --- |
| Branch protection (`main`) | Pull request reviews | 1 approval, **code-owner review required**, **dismiss stale approvals** |
| | Conversation resolution | required |
| | Required status-check contexts, `strict`, enforce admins | **left exactly as they are** |
| Actions | Default `GITHUB_TOKEN` | read-only |
| | Actions may approve PRs | no |
| | Allowed actions | selected: GitHub-owned plus the list in [ACTION-ALLOW-LIST.md](ACTION-ALLOW-LIST.md); the dependency-review action (#2794) is GitHub-owned so it is already covered |
| | Require full-length commit SHAs | yes |
| Security | Secret scanning, push protection | enabled |
| | Dependabot alerts and security updates | enabled |

Code owners are in [`.github/CODEOWNERS`](../../.github/CODEOWNERS): the two
current admins on the 11 paths decided on #2649 (`go.mod`, `go.sum`,
`.github/**`, `Makefile`, `scripts/**`, `install.sh`, `**/Dockerfile*`,
`**/package*.json`, `proto/**`, `deploy/**`, `terraform/**`). A team replaces
the two logins when a third maintainer exists. A CI test
(`scripts/ci/check-codeowners.sh`) fails if a decided path or owner is missing.

## How the script behaves

`scripts/admin/apply-repo-settings.sh`

- **Default is a dry run**: it reads the live settings, prints the before
  state and a diff to the target, and writes nothing.
- **`--apply` writes**, then reads everything back and compares it with the
  target. It exits non-zero on any mismatch, and also if the required
  status-check contexts, `strict` or enforce-admins differ from before.
- **Read-modify-write on branch protection**: the live protection is read and
  sent back with only the review and conversation fields changed, so the
  contexts and their app ids survive. If the live protection has push
  restrictions or review dismissal/bypass lists, it stops instead of guessing.
- `--check-allow-list` (offline, run in CI) fails if a third-party `uses:` in
  `.github/` is not covered by the allow-list, so turning the list on cannot
  lock CI out.

Requires `gh` authenticated as a repository admin, and `jq`.

## Procedure (admin)

1. Merge the PR that adds the script and CODEOWNERS (the CODEOWNERS file must
   be on `main` before the review rule can bite).
2. Dry run and read it:

   ```sh
   scripts/admin/apply-repo-settings.sh
   ```

   Check the planned diff: only the fields in the table above change.
3. Register the new required checks (next section) **before or right after**
   step 4, once their workflows have run on `main` at least once, so the check
   names are selectable.
4. Apply:

   ```sh
   scripts/admin/apply-repo-settings.sh --apply
   ```

   Expect `OK: every setting reads back as desired`. Paste the **After**
   block (it contains no secrets) as a comment on #2792.
5. Run the verification below.

Roll back a single setting from the repository settings page or with the same
`gh api` call and the old value from the dry-run **Before** block; the
required-check list is untouched by the script, so there is nothing to
restore there.

## Verify on the live repo

1. Run the dry run again: it must print `(none: already compliant)`. Record the
   output on #2792 as the read-back of each setting.
2. As an admin, create a throwaway branch and PR that changes `go.mod`
   (for example, a comment-only edit). Only an admin should create and later
   delete this PR and its branch.
3. Expect: the PR shows "Review required" from a code owner and the merge
   button is blocked, even with all checks green. Approve it as the **other**
   code owner (the author cannot approve their own PR); the block lifts.
   Push another commit and confirm the approval is dismissed.
4. Close the PR without merging and delete the branch.
5. Record the result on #2792, then the verification pass can mark it verified.

## Required checks to register (from #2794)

Story 3 (#2794) adds the dependency-change gate. After its workflows have run
on `main`, add their job names as required status checks (Settings, Branches,
`main`, "Require status checks"). The authoritative names are the `name:` of
each job in the merged #2794 workflows; list them with:

```sh
gh api repos/<owner>/<repo>/commits/main/check-runs --jq '.check_runs[].name' | sort -u
```

Expected, by purpose (confirm the exact spelling against the command above):

| Purpose | Check |
| --- | --- |
| `actions/dependency-review-action` (fail on high, licence summary) | the dependency-review job |
| `deps-guard` (new/changed `replace`, module absent from the checksum database) | the deps-guard job and its fixture self-test |
| `go mod verify` with `-mod=readonly` and an explicit `GOSUMDB` | the go-mod-verify step's job |

The `replace` / off-sumdb override is a code-owner approval of the PR, which
the rule above already requires; there is no label.

## Note for agent-authored PRs

Once code-owner review is enforced, an agent account cannot approve its own
PR, and cannot approve one on these paths either unless it is a listed owner.
A later PR touching these paths needs a human code owner to approve it.
