# Task graph execution

> Status: **Implemented** (`pkg/core/taskgraph`, `internal/server/crew_graph_test.go`, `containarium crew run --plan`).

ORCHESTRATOR and FREEFORM crews accept an explicit TaskGraph. The daemon
validates the whole graph before starting any node. PIPELINE rejects a graph;
all existing runs without a graph retain their existing behavior.

```bash
containarium crew plan --goal 'Inspect the API and tests' \
  --repo https://example.com/org/repo.git --git-ref <commit-sha> \
  --server <host> > plan.json

containarium crew run freeform-crew --plan plan.json --concurrency 5 \
  --git-source https://example.com/org/repo.git --git-ref <commit-sha> \
  --server <host>
```

Use the same pinned SHA for planning and execution; the graph does not embed
repository credentials or select a new checkout automatically. Zero concurrency
uses the default of five nodes; the upper bound is the platform node cap.

The scheduler starts a node only when all its dependencies succeeded. A
failed node blocks its downstream dependents while independent branches finish.
Every result includes a child run id, typed state, output/error, and start/end
timestamps. The final crew status retains every node's result, even on failure.
Cancellation stops new dispatch; existing in-box exec operations are not
interruptible and are drained before cleanup completes.

Each assignee receives JSON with `goal`, the node's `input_json` string, and
`dependencies` (entries with `node_id` and `output_json`). Dependency edges
schedule work; they do not grant peer permissions.

Every graph node gets a fresh child run id and physical boxes derived from
that id. Two nodes assigned to the same skill or crew do not share a box,
seed directory, workspace, runtime process, or credential. The internal `tg-`
skill-identity prefix is reserved for these boxes. Catalog ids remain the
logical identities in run journals and A2A requests. A2A routing within a
child run checks the original manifest's allowed peers and refuses other
crews' boxes. Leases end and temporary boxes are deleted after each node.

The execution policy also rejects direct assignments to `task-planner` and
crews containing that skill. The planner endpoint applies the same policy,
so excluding the planner from a prompt's candidates is not the only check.

## Dev verification

On one deployed commit, plan a goal that yields three independent nodes and
execute that plan. Record the parent and child run ids, compare the node
timestamps to prove all three intervals overlap, inspect the journals, and
retain the final report listing each node's result. Local fake-runner tests
exercise scheduling and failure behavior; they do not replace this deployment
check.
