# Recipe: `coding-agent`

A box with the coding-agent toolchain preinstalled and **no credential of any
kind** baked in. It sits beside the [`agent-runtime`](../AGENT-SKILLS-QUICKSTART.md)
recipe: `agent-runtime` runs a headless one-shot skill loop; `coding-agent` is
for a person (or `containarium code`) running Claude Code against a repo.

## What you get

- `agent-box` and `mcp-server` at the requested Containarium release, in
  `/usr/local/bin` (installed with
  `scripts/install-agent-runtime.sh --no-agent-runtime`; no Node bundle).
- Claude Code, installed by Anthropic's own installer, unmodified, as the
  unprivileged box user (`~/.local/bin/claude`). Never root.
- Optionally, a bootstrap bundle applied once as the box user.

- The pinned **SDLC role skills** from
  [open-sdlc-skills](https://github.com/FootprintAI/open-sdlc-skills)
  (product, architect, project manager, scrum master, engineer, QA, reviewer,
  DevOps, release, coordinator), installed into the box user's
  `~/.claude/skills/<namespace>-<name>/SKILL.md` so `claude` can run
  `/engineer-implement`, `/qa-sprint-verify`, ... on first boot. They come from
  a release asset checked against a sha256, at the commit pinned in
  `pkg/core/sdlcskills/sdlc-skills.lock`; nothing is copied into this repo.

The recipe writes no Claude credential, environment variable, or settings key
and creates nothing under `/etc` for Claude Code. Each user signs in to Claude
Code themselves. A lint test (`TestCodingAgentRecipe`) fails if the recipe text
ever mentions an auth-method setting or a managed-settings path.

## Deploy

```bash
containarium recipe deploy coding-agent my-box --param release=v0.89.0
```

| Parameter | Meaning |
|---|---|
| `release` | Required. Containarium release tag (v-prefixed) for `agent-box` + `mcp-server`. |
| `claude_code_version` | Passed to the Claude Code installer. Empty = latest. |
| `bootstrap_url` | Optional URL of a `tar.gz` bundle. Extracted under the box user's home; its `apply.sh` is run as that user. A failed download fails the deploy. Empty skips. |
| `box_user` | Unprivileged user to install for. Default `ubuntu`; must exist in the image. |
| `sdlc_skills` | Install the pinned SDLC role skills into the box user's `~/.claude/skills`. Default `true`; `false` skips. A `release` cut before the skills asset existed is skipped with a message. |

For an existing box, use `containarium code install` instead (it installs the
same skills for the Claude engine; pass `--no-sdlc-skills` to skip them).
A team's own skill overrides layer on top: set `SDLC_SKILLS_OVERLAY_DIR` for
`scripts/install-sdlc-skills.sh` and its directories win over the public set.
Skills the installer wrote are listed in `~/.claude/skills/.sdlc-skills-manifest`,
and `.sdlc-skills-version` records the release and digest; an update removes only
what the previous install owned. Anything else in `~/.claude/skills` is untouched. End-to-end check:
`scripts/coding-agent-recipe-e2e.sh`.
