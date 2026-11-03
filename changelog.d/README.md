# Changelog fragments

A PR with a user-visible change adds **one new file** here instead of
editing `CHANGELOG.md`. Two PRs never touch the same file, so they never
conflict on the changelog.

```
changelog.d/<pr-or-issue-number>.<category>.md
```

`<category>` is one of `added`, `changed`, `deprecated`, `removed`,
`fixed`, `security`, `upgrading`, `documentation`. The file body is the
entry exactly as it should appear in the changelog (a `- ` bullet,
continuation lines indented two spaces), written for a user of the
product. Example, `changelog.d/3460.changed.md`:

```markdown
- **CI shares one Go module cache across jobs** (#3460). ...
```

A PR with no user-visible change adds no fragment and says so in its
description.

Do **not** put a release heading or a `### Category` heading in a
fragment, and do not mention concrete deployment, host or tenant names
(see `CLAUDE.md`).

## At release

`scripts/changelog-assemble.sh X.Y.Z` moves everything under
`## [Unreleased]` plus all fragments into a new `## [X.Y.Z] - <date>`
section, leaves an empty `## [Unreleased]`, and deletes the fragments, all
in the working tree. That is the release PR's `CHANGELOG.md` change
(`docs/RELEASE-PROCESS.md`). The tag build fails if fragments are still
present, so they cannot be forgotten.

`scripts/changelog-assemble.sh --check` validates fragment names and
bodies; CI runs it on every PR.
