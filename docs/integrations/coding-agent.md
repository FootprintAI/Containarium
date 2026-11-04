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
| `skill_sets` | Which pinned skill sets to install into the box user's `~/.claude/skills`: a comma-separated list of set ids (`sdlc`, `qa`, `security`; `security` is opt-in and not sent by the control plane), `all`, or the literal `none`. Empty means unset: it falls back to `sdlc_skills`, whose default installs everything. An unknown id fails the deploy and names the known ids. Narrowing the list on a redeploy removes the dropped sets; an unchanged list leaves the tree identical. `_shared/` is installed whenever at least one set is. A `release` cut before skill sets existed fails the deploy for a list of set ids, rather than installing everything; `all` and `none` still work against it (`none` is skipped). |
| `sdlc_skills` | Deprecated alias, removed after one release: `true` is `skill_sets=all`, `false` is `skill_sets=none`. `skill_sets` wins when both are set. A `release` cut before the skills asset existed is skipped with a message. |

For an existing box, use `containarium code install` instead (it installs the
same skills for the Claude engine; `--skill-sets qa` or `--skill-sets sdlc,qa`
selects sets, `--skill-sets none` installs none and removes what the installer
owned, and `--no-sdlc-skills` is a deprecated alias for `--skill-sets none`).

To change a box's sets **after** that, without re-creating the box or
re-installing the engine, use `containarium code skill-sets <box>
--skill-sets <ids>` (#3374): it is the thin CLI over the daemon's
`ApplyBoxSkillSets` RPC (`POST /v1/containers/{username}/skill-sets:apply`,
the same call a control plane makes when a tenant's skill sets change). The
two paths are two halves of one mechanism: `code install --skill-sets` sets
the selection once, over SSH, when the agent first lands on the box;
`code skill-sets` re-applies the same installer at a release (default: the
daemon's own) through the daemon, as the box's own user, with no SSH client.
`--skill-sets` is the complete target list: newly listed sets are installed,
sets the box's manifest records and the list omits are removed (only the skill
directories that set installed), the files of sets kept are refreshed to the
release's pin, and anything you installed by hand under `~/.claude/skills` is
never touched. Repeating the call reports `unchanged`. The daemon keeps a
per-box manifest beside the skills, `~/.claude/skills/.sdlc-skill-sets.json`,
recording which skill directories each set installed; a set installed by
`code install` or the recipe before that manifest existed can be adopted by
keeping it in the list, and is refused (`SET_PREDATES_MANIFEST`) if omitted
before it has been adopted once. A box with a run in progress — a running
`code run`, or a skill run executing in it — is refused (`RUN_IN_PROGRESS`)
and nothing is changed; an unknown set id is refused (`UNKNOWN_SKILL_SET`)
naming the known ones. Each refusal carries that reason as a typed detail of
the error (a `google.rpc.PreconditionFailure` violation type, or the
`google.rpc.BadRequest` field-violation reason for an unknown id), so a caller
never matches on message text. The daemon advertises the call as
`box_skill_sets` in `SystemInfo.capabilities`.

The refusal runs the other way too: a run start (`StartBoxRun`) that arrives
while an apply is installing on the box is refused at once with
`FAILED_PRECONDITION` and the typed reason `APPLY_IN_PROGRESS` (a
`google.rpc.PreconditionFailure` violation whose `type` is
`BOX_SKILL_SETS_REFUSAL_APPLY_IN_PROGRESS` and whose `subject` is the box).
The start does not queue or wait; retry it once the apply has returned.

An apply that arrives while the box's gate is busy waits for it, at most 30
seconds, and gives up at once if its caller cancels. On the cap it changes
nothing and is refused with `FAILED_PRECONDITION`: `APPLY_IN_PROGRESS` when
another apply on the box is still installing, `RUN_IN_PROGRESS` when run starts
kept the gate busy (the message names the starts still in flight at that moment;
a steady stream of overlapping starts can starve an apply for the whole cap).
Retry either one shortly. Note that `RUN_IN_PROGRESS` on this path can mean a
run start, not only a live run. See [BOX-RUN-API.md](../BOX-RUN-API.md).

A run started over SSH never reaches the daemon, so it is kept out another
way (#3529). A run started with `containarium code run` (agent or
`--command`) or the MCP `code_run` tool is refused before it launches, with
`skill sets are being applied on this box (ApplyBoxSkillSets started <n> ago,
...)`. For this the apply holds a marker beside the skills,
`~/.claude/skills/.sdlc-skill-sets.applying`, written as the box user, which
the SSH path reads with no call to the daemon. The apply takes the marker
before it checks for runs in progress, and removes it when it returns, also
when it fails. Retry the run once the apply has returned.

A run can pass that check in the instant before an apply takes the marker,
too early for the apply's own check to see the run. So the SSH path checks
the marker again right after the run starts. The helper on the box records
the run before the start returns, so either the apply sees the run and
refuses, or this second check sees the marker. In the second case the run
is stopped at once with SIGKILL (its log is kept, as for any stopped run)
and refused with the same message, ending `... the run "<name>" had just
started and was stopped`. If it cannot be stopped, the message ends `... could
not be stopped: ...` instead; stop it with `containarium code stop`. If the
second check cannot run, the run continues and the start prints `warning:
could not re-check for a skill-set apply after the start ...`.

The marker is a lease. The apply writes an expiry 10 minutes ahead (box
clock) and renews it every 200 seconds while it runs. If the daemon dies
mid-apply, the marker therefore stops refusing runs within 10 minutes: the
next run removes the stale marker, starts, and prints `warning: cleared a
stale skill-set apply marker ...`. Anything else at that path is cleared the
same way: a file that cannot be read, is larger than 4 KiB, is not the
marker's JSON, or has an expiry implausibly far ahead, and also a directory
or a symlink (the symlink itself is removed; what it points to is not
touched). The apply's own write likewise replaces whatever is at that path.
The clear removes the path only if it is still the one the check read (same
inode, change time and size), and re-checks when it is not, so a marker a new
apply wrote in between is kept and refuses the run. The comparison and the
removal are separate steps on the box, so this narrows the race rather than
closing it: the clear first renames the path aside and puts it back when it
is not the file checked, so a new apply's marker caught in that instant is
restored rather than deleted. If the box user cannot remove the stale marker
(for example a read-only `~/.claude/skills`), the run is refused with `a
stale skill-set apply marker could not be removed ... remove it by hand`;
retrying does not help until it is removed. One limit: if the box clock steps back
by more than about a minute during a live apply, its marker reads as stale
until the next renewal (at most 200 seconds), and a run started then is not
refused.

An agent re-applies a box's sets with the platform MCP tool
`apply_box_skill_sets` (#3511), a thin wrapper over the same client function
as `code skill-sets` and the same REST path. Its arguments are `box`,
`skill_sets` (the complete target list of set ids; an empty array removes
every set, and there is no `all` literal) and an optional `release`. It reports
what was installed, removed or left unchanged, and a refusal comes back as
`refused (RUN_IN_PROGRESS)`, `refused (SET_PREDATES_MANIFEST)` or
`refused (UNKNOWN_SKILL_SET)` followed by the daemon's message. A bad box name,
a bad release tag, or a set id that is not `[a-z0-9-]+` is rejected before any
request is made. It needs the `containers:write` scope.

To re-apply the **bootstrap bundle** on a box that already has its agent
(a new skill set, a rotated credential, a changed MCP config), use
`containarium code bootstrap <box> --url <url>` or `--url-cmd '<command>'`
(#3512). It runs the bundle step of `code install --bootstrap-url` and nothing
else: no engine, agent-box or skills reinstall, and `~/.containarium/code.json`
is left alone. `--url-cmd` runs through your `$SHELL` (`/bin/sh` when `$SHELL`
is unset) with `CONTAINARIUM_BOX=<box>` set and its first stdout line is the
URL, so a control plane that hands out one-shot bundle URLs can document one
command for every box. A hook still running after 30 seconds is killed and
nothing is applied. The URL is requested only after one silent SSH round trip has confirmed
the box is reachable, accepts your key, and has a writable home, `curl` and
`tar`; a failure there means nothing was requested or applied. If the download
never reached the server (host not resolved, connection refused), the URL was
not consumed and a retry is safe. If it reached the server and then failed (an
HTTP error such as 404 or 410, or a broken transfer), the URL may already be
consumed: if a retry fails, request a new URL. If the bundle was fetched
but is unreadable or its `apply.sh` fails, the one-shot URL is spent (and a
control plane may have rotated the box's credential on fetch): request a new
URL and re-run. `code install --bootstrap-url` runs the same check before its
first script and reports bundle failures the same way. The URL is never
printed.

Which namespaces a set covers is defined next to the pin, in the `set.<id>=`
lines of `pkg/core/sdlcskills/sdlc-skills.lock`, so a caller sends set ids and
never has to track upstream namespaces. That lock has one `[source]` section
per pinned repository (`repo`, full commit `ref`, and deterministic bundle
`sha256`). `scripts/build-sdlc-skills-bundle.sh [source] <out-dir>` writes
`<source>-skills.tar.gz`; omitting `source` keeps the existing `sdlc` default.
The builder inspects every source on each run and refuses duplicate namespaces,
so installing two source bundles can never make the last copy silently win.
A team's own skill overrides layer on top: set `SDLC_SKILLS_OVERLAY_DIR` for
`scripts/install-sdlc-skills.sh` and its directories win over the public set.
Skills the installer wrote are listed in `~/.claude/skills/.sdlc-skills-manifest`,
and `.sdlc-skills-version` records the release and digest; an update removes only
what the previous install owned. Anything else in `~/.claude/skills` is untouched. End-to-end check:
`scripts/coding-agent-recipe-e2e.sh`.
