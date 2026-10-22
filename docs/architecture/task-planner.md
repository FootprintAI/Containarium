# Task planner

`containarium crew plan` runs the built-in `task-planner` skill in a box.
The skill reads the fetched repository's layout, manifests, architecture
documentation and entry points, and proposes a TaskGraph. The daemon parses
that output with protojson (unknown fields are rejected), checks the goal,
and calls the same `taskgraph.Validate` used by `crew plan validate`.
Planning never executes the graph's nodes. Direct assignments to the planner,
and assignments to crews containing it, are rejected after generic graph
validation. Both are also excluded from the model's candidate lists.

The planner manifest leaves engine and model unspecified, so it follows the
daemon's primary provider through the existing skill provisioning path.
Its task input contains the daemon's current skill/crew ids and descriptions,
plus the platform node/depth caps. The planner itself is excluded from the
skill candidates. Repository references use the existing git-source fetch
mechanism; local paths on the CLI machine are not uploaded.

## Usage

The daemon must have a working agent runtime and provider configuration.
The request requires `crews:read`, `agents:run`, and `containers:write`;
the usual skill provisioning authorization checks also apply.

```bash
containarium crew plan \
  --goal 'Review the API and its test coverage' \
  --repo https://example.com/org/repo.git \
  --git-ref '<commit-sha>' \
  --server '<host>' > plan.json

containarium crew plan validate plan.json --server '<host>'
```

For a private repository, add `--git-credential-file <token-file>`.
The successful planner run id is printed on stderr; stdout contains only the
graph, so redirecting it to a file remains safe.
The credential is used for the fetch and is not included in the saved plan
input or output. `--backend` and `--pool` select planner placement.

## Failures and verification

Runtime errors and invalid planner output fail the RPC. The error includes
the planner run id; `containarium crew status <run-id> --server <host>`
returns its saved failure reason. A successful run stores the graph as its
artifact. The runtime's existing run journal and lease cleanup are reused.
RPC cancellation does not interrupt the existing in-box exec mechanism;
cleanup runs when that exec returns.

## Verify on dev

Deploy the PR commit to a dedicated dev daemon with the matching CLI,
the updated skill catalog, a working agent-runtime recipe and a configured
primary provider. Use an authenticated operator with the scopes above.
The following checks are instructions for deployment verification, not a
record that they have been performed.

### Real repository and model

Replace the server URL, small fixture repository and full commit SHA:

```bash
export CONTAINARIUM_SERVER='http://<dev-host>:8080'
export CONTAINARIUM_HTTP=true
export PLANNER_VERIFY_REPO='https://example.com/org/small-fixture.git'
export PLANNER_VERIFY_REF='<full-commit-sha>'

containarium crew plan \
  --goal 'Review the API entry points and their tests' \
  --repo "$PLANNER_VERIFY_REPO" --git-ref "$PLANNER_VERIFY_REF" \
  > plan.json 2> planner.log
cat planner.log
containarium crew plan validate plan.json
```

Expected: exit status zero, a valid graph with the requested goal, and
`Planner run: <run-id>` on stderr. Extract that id to inspect the daemon:

```bash
PLANNER_VERIFY_RUN_ID=$(sed -n 's/^Planner run: //p' planner.log)
test -n "$PLANNER_VERIFY_RUN_ID"
containarium crew status "$PLANNER_VERIFY_RUN_ID"
containarium crew logs "$PLANNER_VERIFY_RUN_ID"
```

Expected: `CREW_RUN_STATE_COMPLETED`, the requested git commit and a graph
artifact. The journal must show reads of repository layout/manifests and
relevant entry points. Its graph should describe work informed by those
paths. No graph assignee tasks should have been launched. Retain the deployed
commit, planner run id, graph, status and journal as verification evidence.

### Controlled invalid planner output

On the dedicated Incus dev host, after the successful check above, substitute
the planner runtime temporarily. This fixture emits a structurally valid
graph assigning work to the planner itself; it does not call a model.
Use only this dedicated fixture box, with no concurrent planner runs.

```bash
incus exec agent-task-planner-container -- bash -lse <<'BOX'
set -euo pipefail
planner_runtime=$(command -v agent-runtime)
test ! -e /tmp/planner-verify-runtime.backup
cp -p "$planner_runtime" /tmp/planner-verify-runtime.backup
printf '%s' "$planner_runtime" > /tmp/planner-verify-runtime.path
cat > "$planner_runtime" <<'STUB'
#!/bin/sh
set -eu
printf '%s\n' '{"outputJson":"{\"goal\":\"planner-verification-invalid\",\"nodes\":[{\"id\":\"self\",\"goal\":\"implement\",\"skill_id\":\"task-planner\"}]}","error":""}' > "$AGENT_SEED_DIR/artifact.json"
STUB
chmod +x "$planner_runtime"
BOX

containarium crew plan --goal planner-verification-invalid \
  --repo "$PLANNER_VERIFY_REPO" --git-ref "$PLANNER_VERIFY_REF" \
  > invalid-plan.json 2> invalid-plan.log
cat invalid-plan.log
```

Expected: the plan command fails, stdout contains no graph, and stderr
identifies the planner run and the rejected `self` node. Inspect it with:

```bash
test ! -s invalid-plan.json
PLANNER_VERIFY_FAILED_RUN_ID=$(sed -nE 's/.*planner run ([A-Za-z0-9._-]+):.*/\1/p' invalid-plan.log)
test -n "$PLANNER_VERIFY_FAILED_RUN_ID"
containarium crew status "$PLANNER_VERIFY_FAILED_RUN_ID"
```

Expect `CREW_RUN_STATE_FAILED`, the self-assignment reason, and no successful graph
artifact. Do not substitute `crew plan validate` for this check: file
validation does not create a planner run or record planner failure.

Restore the runtime after this check, including if the assertions fail:

```bash
incus exec agent-task-planner-container -- bash -se <<'BOX'
set -euo pipefail
planner_runtime=$(cat /tmp/planner-verify-runtime.path)
cp -p /tmp/planner-verify-runtime.backup "$planner_runtime"
rm /tmp/planner-verify-runtime.backup /tmp/planner-verify-runtime.path
BOX
```
