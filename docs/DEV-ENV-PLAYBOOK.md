# Dev environment playbook: ship a release to a Containarium Cloud box

> Operator playbook for standing up a **dev box** on a Containarium Cloud
> control plane, shipping one committed version to it, proving the deploy
> is healthy, and handing the box to the post-release verification pass.
> It is the written form of the `/devops-deploy` → `/release-verify` →
> `/qa-sprint-verify` chain. Every command here is the `containarium` CLI;
> the MCP tool that does the same job is named beside it. Concrete cluster
> and host names belong in a private operator runbook, never in this file:
> placeholders below are `<cluster>.example.com`, `<sentinel-host>`,
> `<box>`.

## When to use it

- A release was tagged and the dev environment must run **that exact
  commit** before verification starts (`/release-verify released --tag
  vX.Y.Z --env dev`).
- A batched verification pass needs a box that runs one known commit.
- You are not shipping to prod. Prod is a separate, human-confirmed
  deploy of an already-verified tag; nothing in this playbook creates or
  deletes anything on a prod backend.

## Principles

1. **A commit is the unit of deployment.** `git rev-list -n1 vX.Y.Z`
   names it. A dirty or unpushed tree does not ship.
2. **Remote mirrors local exactly.** After the push, the box's checked-out
   commit must equal the local one. A mismatch is a failed deploy:
   diagnose it, never hand-edit the box.
3. **One version per environment per pass.** Never redeploy while a
   verification pass is running, and never push a single branch to a
   shared box so someone can look at it.
4. **Credentials never pass through the agent.** A human logs in and
   rotates tokens; the agent only references where a token lives.
5. **One box per pass, named for what it is.** `verify-<ref>-<short-sha>`,
   so a listing never shows an anonymous box nobody dares delete.

## 0. Readiness: prove the runtime can do the job

Run all of these before creating anything. A check passes only when the
command succeeded in this session.

| Capability | Check | CLI / MCP |
|------------|-------|-----------|
| Tracker access | `gh auth status` | `gh` |
| Control plane answers | list backends: at least one healthy | `containarium backends` / `list_backends` |
| Containers listable | list boxes | `containarium list` / `list_containers` |
| CLI matches the server | `containarium version --check` | n/a |
| SSH config | `containarium ssh-config sync`, then `grep -c '^Host ' ~/.containarium/ssh_config` | `sync_ssh_config` |
| Key directory | `~/.containarium/keys` exists with mode `0700` | n/a |
| Sentinel reachable | `nc -z -w 5 <sentinel-host> 22` | n/a |

Every `ssh` or `scp` in this playbook carries `-o IdentitiesOnly=yes`.
Without it ssh offers every key in `~/.ssh/`, and each rejected key counts
toward the sentinel's failed-login ban for your IP.

### If the control plane answers `401 invalid or expired token`

The session token is stale. This is a human step; do not paste a token
into a chat, a config file or a remote shell.

```bash
containarium login --server https://<cluster>.example.com      # browser device flow
# no browser on this machine:
containarium login --server https://<cluster>.example.com --no-browser
```

For the MCP server, point it at a token **file** (re-read on every
request, so rotation is a file move, not a restart):

```json
"containarium": {
  "type": "stdio",
  "command": "<path>/mcp-server",
  "env": {
    "CONTAINARIUM_SERVER_URL": "https://<cluster>.example.com",
    "CONTAINARIUM_JWT_TOKEN_FILE": "~/.containarium/mcp.key",
    "CONTAINARIUM_KEYS_DIR": "~/.containarium/keys"
  }
}
```

Re-run the readiness table. A `404` from an update-check call is not an
auth failure; a `401` on any list call is.

## 1. Pick the commit

```bash
git fetch --tags origin
COMMIT=$(git rev-list -n1 vX.Y.Z)        # the tag's commit, not a branch tip
git status --porcelain                   # must print nothing
git branch -r --contains "$COMMIT"       # must include origin/main
```

CI on that commit must be green. A commit that never passed CI does not
get a dev box.

## 2. Create the box

```bash
containarium create verify-vX.Y.Z-${COMMIT:0:7} \
  --ssh-key ~/.ssh/<key>.pub \
  --pool dev \
  --cpu 4 --memory 8GB --disk 50GB \
  --podman \
  --labels purpose=verify --labels release=vX.Y.Z
```

`dev` is a placeholder: use whatever pool your cluster tags for dev boxes. MCP: `create_container` (omit `ssh_keys` and an ephemeral keypair is
written to `~/.containarium/keys/<name>`, mode `0600`). Placement: `--pool`
for "any healthy backend in the pool", `--backend-id` for a specific one
(`containarium backends` lists IDs). Use `--isolation vm` only when the
workload needs its own kernel and the backend has KVM.

Confirm it is running and note its address:

```bash
containarium get verify-vX.Y.Z-${COMMIT:0:7}
containarium ssh-config sync
```

If ssh or the box misbehaves, run `containarium debug <name>` (MCP
`debug_container`) before reporting a failure: it surfaces host-side
state the agent cannot see and returns ordered next actions.

## 3. Apply the per-pass box defaults

A box that dies when the ssh session closes is not a deploy target. On a
fresh box, once:

```bash
ssh -o IdentitiesOnly=yes -i ~/.containarium/keys/<box> <box>@<sentinel-host> '
  set -e
  sudo loginctl enable-linger "$USER"          # user services outlive the ssh session
  sudo apt-get install -y --no-install-recommends tmux
  # rootless podman must resolve unqualified image names against docker.io
  grep -rq docker.io /etc/containers/registries.conf* /etc/containers/registries.conf.d 2>/dev/null \
    || echo "unqualified-search-registries = [\"docker.io\"]" | sudo tee /etc/containers/registries.conf.d/10-docker.conf
'
# prove it
ssh -o IdentitiesOnly=yes -i ~/.containarium/keys/<box> <box>@<sentinel-host> \
  'loginctl show-user "$USER" -p Linger; podman info >/dev/null && echo podman-ok; tmux -V'
```

Expected: `Linger=yes`, `podman-ok`, a tmux version.

## 4. Ship the committed state

```bash
containarium push <box> .        # ships committed history; delta on later pushes
```

MCP: `push`. `push` refuses a dirty tree unless `--include-wip` is set; do
not set it for a deploy. `containarium sync <box>` mirrors the working
directory including uncommitted files, so it is for iteration, never for a
version that gets recorded.

Prove parity: the box's checkout must equal the commit.

```bash
ssh -o IdentitiesOnly=yes -i ~/.containarium/keys/<box> <box>@<sentinel-host> \
  'git -C ~/work rev-parse HEAD'      # must equal $COMMIT
```

A mismatch is a failed deploy. Diagnose with `debug`; never patch the box.

## 5. Run it

Run the service the way it runs everywhere else: the project's own compose
file.

```bash
containarium compose discover <box>
containarium compose enable <box> --dir <compose-dir>
containarium compose status <box> --dir <compose-dir>
```

Secrets enter through the platform's secret store (MCP `set_secret` /
`refresh_secrets`), never a committed file or a shell history. A
dev-only daemon flag belongs in a committed, reviewed dev override in the
repo, not authored on the box at deploy time; if one is missing, file an
issue on the repo.

## 6. Expose and verify: the deploy is the health check passing

```bash
containarium expose-port <box> --container-port <port> --domain <box>.<cluster>.example.com
curl -fsS -m 10 https://<box>.<cluster>.example.com/<health-path>
```

MCP: `expose_port`, `list_routes`. The deploy is done only when
`compose status` shows the service up **and** the real route answers
correctly. A synced box with a dead process is an outage with extra steps.
If the check fails, the deploy FAILED: report it red, fix forward in git
or redeploy the previous good commit.

## 7. Record the deploy

Post this on **every** queue home and the open release issue (the release
issue is a ledger; the others are where rows flip ⏳ → 🔍):

```markdown
## Dev deploy: `<short-sha>` (vX.Y.Z = `<full-sha>`) @ https://<box>.<cluster>.example.com: <date>

Parity verified (box HEAD == tag commit). Service up, health check passing <time>.
Environment: box `verify-vX.Y.Z-<short-sha>` on the dev pool, created for this pass;
deleted after results post. Rollback point: `<previous-good-commit>`.
```

A record whose commit equals the tag's commit is exactly what
`/release-verify released` reads, whether or not anything was redeployed
to produce it. If the environment already runs that commit, post the
record and stop; do not redeploy.

## 8. Hand off

```text
/release-verify released --tag vX.Y.Z --env dev
```

That triggers the one batched `/qa-sprint-verify --env dev --commit <sha>`
pass. Do not verify rows yourself and do not redeploy while it runs.

## 9. Tear down (only after the results are posted)

Delete the box only when all of these hold:

- the newest `/qa-sprint-verify` results comment names this commit on
  every queue home, and every ❌ row carries a defect number;
- no pass is in flight;
- every evidence link points somewhere that outlives the box (a committed
  report, attachments on the issues), never at the box's route;
- the target is a `verify-*` box on a **dev** backend, confirmed with
  `containarium get <name>`.

```bash
containarium list                       # find routes that point at the box
# remove each route to the box first (MCP: list_routes, delete_route)
containarium compose disable <box> --dir <compose-dir>
containarium delete <box>
containarium list                       # confirm it is gone and standing boxes are untouched
```

Never delete a standing environment or anything on a prod backend with
this procedure; on those, "release" means deploy the next version.

## Failure modes

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `401 invalid or expired token` | stale session | `containarium login` (human), rotate the MCP token file |
| ssh refused after several tries | key spray hit the sentinel ban | add `-o IdentitiesOnly=yes`; wait out the ban |
| `push` refuses | dirty tree | commit or stash; do not use `--include-wip` for a deploy |
| box HEAD != tag commit | push failed or wrong ref | `debug`; redeploy; never hand-patch |
| `compose status` shows the service down | dev-only flag or secret missing | fix in git or the secret store, redeploy |
| `create` fails on `--isolation vm` | backend has no KVM | pick a KVM-capable backend or use a container box |
| box disappears when the ssh session ends | linger not enabled | step 3 |

## Rollback

Deploy the previous known-good commit through the same steps (push,
run, verify). If data changed shape between commits, restore the
pre-deploy backup (`containarium backup` / MCP `restore_backup`) and say
so in the record: a data rollback is never silent.
