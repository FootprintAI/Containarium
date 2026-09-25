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

For an existing box, use `containarium code install` instead. End-to-end check:
`scripts/coding-agent-recipe-e2e.sh`.
