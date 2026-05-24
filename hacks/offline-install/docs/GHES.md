# GitHub Enterprise Server (GHES) Runner Kit Setup

The Containarium runner kit (`hacks/runner/install.sh`) provisions a
self-hosted GitHub Actions runner inside a Containarium box. By default
it targets `github.com`; for GitHub Enterprise Server, set one extra
env var.

## TL;DR

```bash
ssh runner-1 'sudo \
  GH_REPO=org/repo \
  GH_PAT=ghp_xxx \
  GH_BASE_URL=https://github.your-company.internal \
  ./hacks/runner/install.sh'
```

The `GH_BASE_URL` variable was added in v0.19.0 per the air-gapped
install bundle PRD (E3a §"GHES support"). It defaults to
`https://github.com`, so the variable is **purely additive** — every
existing invocation against github.com keeps working without change.

## URL derivation

Internally, the runner kit derives both the API URL and the runner
config URL from `GH_BASE_URL`:

```
GH_BASE_URL=https://github.com                       (default)
  → GH_API_BASE    = https://api.github.com          (github.com special case)
  → RUNNER_CONFIG  = https://github.com/${GH_REPO}

GH_BASE_URL=https://github.your-company.internal     (GHES)
  → GH_API_BASE    = https://github.your-company.internal/api/v3
  → RUNNER_CONFIG  = https://github.your-company.internal/${GH_REPO}
```

Why the asymmetry: github.com uses a separate `api.github.com` host;
GHES collapses both into the same hostname under `/api/v3`. This is the
documented GHES convention.

## Firewall allowlist

The Containarium runner box only needs to reach `${GH_BASE_URL}` (and
nothing else):

| Source | Destination | Why |
|---|---|---|
| Containarium box | `${GH_BASE_URL}` (port 443) | runner registration + job polling |

No outbound to `github.com`, `api.github.com`, or
`pkg.actions.githubusercontent.com` is required — GHES proxies
everything internally.

## Runner binary

GHES ships its own copy of the actions-runner, versioned with the GHES
release. Two options:

1. **(Default)** Use the runner binary bundled in the air-gapped
   tarball at `./bin/actions-runner-*.tar.gz`. Version-pinned to what
   we tested with; survives even if GHES is at a different patch
   level.
2. **(v0.1+)** Pull from GHES at `${GH_BASE_URL}/_status/actions-runners`
   via `--runner-from-ghes` — matches the GHES admin's preferred
   update flow.

v0 uses option 1.

## Personal Access Token scopes

On GHES, the PAT needs `repo` scope (same as github.com). Some GHES
instances disable PAT-classic and require fine-grained tokens; in that
case use a fine-grained PAT scoped to the target repo with **Actions:
Read & write** and **Administration: Read & write** permissions.

Generate at: `${GH_BASE_URL}/settings/tokens` (classic) or
`${GH_BASE_URL}/settings/personal-access-tokens` (fine-grained).

## Minimum supported GHES version

The runner-registration endpoint
(`POST /api/v3/repos/.../actions/runners/registration-token`) has been
stable since GHES 3.0. We test against **GHES 3.10 LTS** and above; older
versions may work but are not in our test matrix.

## Verifying it worked

After `install.sh` completes:

```bash
# On the runner box:
sudo systemctl status containarium-runner.service
sudo journalctl -u containarium-runner -f
```

On GHES:

```
${GH_BASE_URL}/<owner>/<repo>/settings/actions/runners
```

The new runner should appear within ~30s, in **Idle** state, labelled
`self-hosted,containarium,ephemeral` (or whatever you set
`RUNNER_LABELS` to).

## Targeting in workflows

```yaml
# .github/workflows/ci.yml on your GHES repo
jobs:
  build:
    runs-on: [self-hosted, containarium, ephemeral]
    steps:
      - uses: actions/checkout@v6
      - run: make build
```

The runner picks up the job, runs it once (ephemeral mode), exits, and
the systemd unit respawns a fresh registration for the next job.
