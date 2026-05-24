# `hacks/runner/` — Containarium as a GitHub Actions runner pool

Set up **ephemeral GitHub Actions self-hosted runners** that live inside
Containarium boxes. Eliminates GitHub-hosted-runner minutes for your CI,
and crucially avoids the classic self-hosted-runner failure mode
(one long-lived runner host, stuck processes, queue stalls forever)
by making every job run on a runner that's never run anything before.

This is what [Containarium](https://containarium.dev) uses for its own
CI — read [the design notes](#design-notes) for the why.

## What you get

- One `containarium-runner.service` per box, registered to one GitHub
  repo, labeled `[self-hosted, containarium, ephemeral]`.
- Each iteration: mint a registration token via GitHub API → register
  the runner in `--ephemeral` mode → run **one** job → deregister →
  systemd respawns the loop with a fresh registration.
- Spin N boxes for N concurrent jobs. Scale by `containarium create`
  + re-running this install script.
- Toolchains baked in by `install.sh`: Go 1.25, Node 22 + pnpm 9,
  buf 1.38.0, golangci-lint v2. Edit the script's version vars for
  other pinnings.

## Prerequisites

- A Containarium daemon you can `containarium create` against (OSS or
  the Cloud product, doesn't matter).
- A GitHub repo you control + a Personal Access Token with `repo`
  scope (classic PAT) for that repo. See
  [GitHub's docs](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/adding-self-hosted-runners#using-the-rest-api)
  for what scopes the registration-token endpoint needs.
- One Containarium box per concurrent CI job you want to run. Start
  with 3 if you have no idea; bump as needed.

## Setup (one-time per box)

```bash
# 1. Create the box (from your laptop, talking to a Containarium daemon).
containarium create runner-1

# 2. Wait for SSH, then install the runner inside it. Replace the
#    env vars with your repo + PAT.
ssh runner-1 'curl -fsSL \
  https://raw.githubusercontent.com/footprintai/containarium/main/hacks/runner/install.sh \
  | sudo GH_REPO=<owner>/<repo> GH_PAT=ghp_xxxxxxxxxxxx bash'

# 3. (Optional) Repeat for runner-2, runner-3 for parallelism.
for i in 2 3; do
  containarium create runner-$i
  ssh runner-$i 'curl -fsSL .../install.sh | sudo GH_REPO=... GH_PAT=... bash'
done
```

After step 2 finishes, verify the runner appears at
`https://github.com/<owner>/<repo>/settings/actions/runners` within
~30 seconds. It'll show idle, with labels `containarium, ephemeral`,
ready to pick up jobs.

## Targeting the runners from a workflow

In your repo's `.github/workflows/*.yml`:

```yaml
jobs:
  test:
    runs-on: [self-hosted, containarium, ephemeral]
    steps:
      - uses: actions/checkout@v4
      - run: go test ./...   # runs natively in the Containarium box
```

No need for the [`containarium-run`](https://github.com/FootprintAI/containarium-run)
Action — the runner IS already on Containarium. The Action is for
the *other* model (thin-shim on GHA-hosted runners that spawn boxes
on demand).

## Operations

**Tail one runner's logs:**
```bash
ssh runner-1 'journalctl -u containarium-runner -f'
```

**Restart a runner:**
```bash
ssh runner-1 'sudo systemctl restart containarium-runner'
```

**Replace the PAT (rotation):**
```bash
ssh runner-1 'sudo sed -i "s/^GH_PAT=.*/GH_PAT=ghp_newvalue/" /etc/containarium-runner.env'
ssh runner-1 'sudo systemctl restart containarium-runner'
```

**Drain + tear down a runner box:**
```bash
ssh runner-1 'sudo systemctl stop containarium-runner'   # waits for current job
containarium delete runner-1 --yes
```

**Add capacity:**
```bash
containarium create runner-4
ssh runner-4 'curl -fsSL .../install.sh | sudo GH_REPO=... GH_PAT=... bash'
```

That's it. There's no central controller — each box is independent.
If one box hangs (network drop, kernel panic), only that one runner
slot is lost; the others keep picking up jobs.

## Design notes

### Why `--ephemeral`?

Long-lived self-hosted runners are the classic CI hell. A bad job
leaks processes, fills `/tmp`, corrupts a global state — and every
subsequent job inherits the mess. Eventually the runner hangs and the
queue stalls.

`--ephemeral` flips that: the runner config and process exist for
exactly one job, then exit. systemd respawns the loop with a fresh
registration. Each job's container state is provably clean.

### Why a long-lived box for each runner slot?

Could each *job* spawn its own box (controller-managed, ARC-style)?
Yes, and that's the right answer at scale — but it requires a real
controller (watch the GitHub webhook, allocate a box, register, drain,
delete). For most teams, **N long-lived boxes running ephemeral
runners** gives 90% of the benefit with 10% of the engineering.

If/when you outgrow this — e.g., you want sub-second runner availability
or per-job resource sizing — graduate to a controller. Until then,
this is fine.

### Why does the install script have toolchains baked in?

Per-job apt installs are the dominant CI cost when nothing is cached.
Baking Go + Node + buf + golangci-lint into the box at provision time
means `go test` starts in <1s after the runner picks up a job, not
after a 60s apt cycle. Adjust the toolchain list in `install.sh` for
your project's stack.

### What about secrets and isolation?

This setup gives every job in your repo access to whatever's in the
runner box (the PAT in `/etc/containarium-runner.env`, anything else
you've installed). That's the standard self-hosted-runner tradeoff.
**Do not** use these runners for jobs from forks of public repos —
GitHub's
[security guidance](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security)
covers this. For public OSS where untrusted contributors can open PRs,
stick to GitHub-hosted runners (or use the `containarium-run` Action's
thin-shim model where each job is in a fresh Containarium box created
on-demand and torn down).

## Troubleshooting

### Runner doesn't appear in GitHub's UI

Check the logs: `ssh runner-1 'journalctl -u containarium-runner -n 100'`.
Most common: PAT lacks `repo` scope, or the repo path in `GH_REPO`
is wrong (must be `owner/repo` not a URL).

### Runner appears but immediately deregisters

`--ephemeral` means it deregisters after one job. If you're not seeing
it stay around between jobs, that's normal — the loop spawns a new
registration each iteration.

### Jobs queue but no runner picks them up

- Confirm the workflow's `runs-on:` matches the labels on your runners
  (`[self-hosted, containarium, ephemeral]` by default).
- Confirm the runner box has network access to `github.com`.
- Check `journalctl -u containarium-runner -f` while pushing a commit
  to trigger CI — you should see the registration succeed and the
  runner pick up the job.

### Toolchain version drift

Edit `install.sh`'s `GO_VERSION`, `BUF_VERSION`, etc., then re-run on
each box:
```bash
ssh runner-1 'curl -fsSL .../install.sh | sudo GH_REPO=... GH_PAT=... bash'
```
The script is idempotent — it only reinstalls toolchains whose
version changed.

## Cost comparison (rough)

For a repo doing ~100 PRs/month, each triggering ~5 min of CI:

| | GHA-hosted (default) | containarium-run Action (thin-shim) | This (ephemeral on Containarium) |
|---|---|---|---|
| GHA-hosted minutes/month | ~500 min | ~50 min | 0 min |
| Containarium box-hours/month | 0 | ~8 hr | ~8 hr (across 3 idle-most-of-the-time runner boxes) |
| Setup complexity | None | Add Action + 2 secrets | This README (~30 min one-time) |
| Best for | Hobby / open-source contributions | Want failure-debug UX, don't want to manage runners | Want zero GHA minutes; have a Containarium fleet |
