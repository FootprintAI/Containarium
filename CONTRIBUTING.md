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

## Before you push

- Run `make proto` if you touched `.proto` files and commit the output.
- Run the tests for the packages you changed and `golangci-lint`.
- Grep your diff, PR description, and commit messages for concrete host,
  tenant, or IP names and anonymize them.
- Keep the PR small and tied to one issue.
