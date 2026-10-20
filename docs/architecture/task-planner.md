# Task planner

`containarium crew plan` runs the built-in `task-planner` skill in a box.
The skill reads the fetched repository's layout, manifests, architecture
documentation and entry points, and proposes a TaskGraph. The daemon parses
that output with protojson (unknown fields are rejected), checks the goal,
and calls the same `taskgraph.Validate` used by `crew plan validate`.
Planning never executes the graph's nodes.

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
  --git-ref <commit-sha> \
  --server <host> > plan.json

containarium crew plan validate plan.json --server <host>
```

For a private repository, add `--git-credential-file <token-file>`.
The credential is used for the fetch and is not included in the saved plan
input or output. `--backend` and `--pool` select planner placement.

## Failures and verification

Runtime errors and invalid planner output fail the RPC. The error includes
the planner run id; `containarium crew status <run-id> --server <host>`
returns its saved failure reason. A successful run stores the graph as its
artifact. The runtime's existing run journal and lease cleanup are reused.
RPC cancellation does not interrupt the existing in-box exec mechanism;
cleanup runs when that exec returns.

To verify with a real deployment, plan against a pinned repository commit,
validate the printed graph against the same daemon, and inspect the planner
journal to confirm it read the repository structure and entry points. Confirm
that no assignee nodes were launched. Unit tests use a fake planner runner
and do not establish that a deployed model read the repository successfully.
