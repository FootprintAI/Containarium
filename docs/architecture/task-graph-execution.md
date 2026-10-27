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

## Local host resource requirements

Manually authored graph nodes may declare minimum measured host capabilities:

```yaml
goal: inspect a repository
nodes:
  - id: inspect
    goal: inspect entry points
    skill_id: code-review
    resources:
      min_cpu_cores: 4
      min_memory_bytes: 8589934592
      requires_gpu: false
```

Run this plan with the existing `crew run <crew-id> --plan <file>` command
over either gRPC or HTTP. Use a daemon that supports `TaskNode.resources`;
older daemons may ignore new protobuf fields and cannot enforce these
requirements. No backend capability inventory is supplied to the planner;
author these requirements manually.

The shared graph validator rejects negative CPU or memory minima. Structural
validation (`crew plan validate`) does not probe host capabilities. Execution
checks every constrained node against the daemon's last recorded capability
profile before recording a graph run or provisioning any boxes. A missing
profile, unhealthy local backend, insufficient CPU/RAM, or an unvalidated
required GPU returns
`FailedPrecondition` with the node id and reason. An operator can profile the backend with
`containarium backends profile --format json --server <daemon-http-url>`;
CPU-only hosts may add `--skip-gpu`.

This version validates only the local host. An explicit backend must name this
daemon, and a requested pool must contain it. Constrained nodes are pinned to
the local backend, with pool fallback disabled. Their profile is checked again
when dependencies finish, immediately before dispatch. If that check fails,
the node fails with the reason recorded, its dependents are blocked, and
independent branches can finish. Unconstrained nodes in the same graph retain
their original placement settings. Absent or all-zero `resources` preserve
legacy behavior and require no profile.

These are host eligibility checks against measured CPU cores, total RAM and
GPU passthrough availability; they do not use the self-reported hardware
class. The last recorded profile is a snapshot, not a fresh measurement or a
reservation. Refresh it after hardware changes. Requirements do not change
per-box CPU/RAM limits, configure GPU passthrough in a recipe, or reserve a
GPU. For a crew node they apply to the host of the whole crew. Existing
recipe configuration and provisioning/admission checks still apply.

## Dev verification

On one deployed commit, plan a goal that yields three independent nodes and
execute that plan. Record the parent and child run ids, compare the node
timestamps to prove all three intervals overlap, inspect the journals, and
retain the final report listing each node's result. Local fake-runner tests
exercise scheduling and failure behavior; they do not replace this deployment
check.
