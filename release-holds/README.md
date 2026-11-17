# Release holds

A file here, `<issue>.md`, blocks cutting a release until it is deleted.
`scripts/ci/check-release-holds.sh` fails the release while any hold is open.

Use a hold when a change is safe to merge but unsafe to ship until an operator
has checked live state on the machines that will run the release, for example a
change that refuses a credential format older clusters still present. A change
that merely needs an "Upgrading" note does not need a hold; see
`docs/RELEASE-PROCESS.md`.

Add the hold in the same PR as the change, or before it, so there is no window
in which the change is on `main` and a release can be cut.

## Hold file format

```markdown
# <one line: what must be true before this ships>

Issue: #<number>
Change: #<PR number>

## Gate
<the exact command or query, and the result that clears it, run on every daemon>

## Evidence to record when clearing
<what the clearing PR's description must contain; counts only, no host,
cluster or tenant names>
```

## Clearing a hold

Open a PR that deletes the file. Its description records the gate result for
every daemon that will run the release, and the person who ran it. Reviewers
check the evidence is there; the release check then passes.

Do not delete a hold to get a release through. If the gate cannot be run, the
release waits.
