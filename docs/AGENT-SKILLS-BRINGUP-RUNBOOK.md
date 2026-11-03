# Agent Skills — Live Bring-Up Runbook

Bring the agent-skills mechanism live on a backend: from a released daemon to a
real `agent run` artifact, an A2A `crew run` that reaches `COMPLETED`, and
(optionally) armed in-kernel egress enforcement.

Everything in Phases 0–4 is built; this is the **ops** sequence that needs a
real box (a Linux backend) + a model-provider API key. Replace `<host>` with
your daemon's address and `<TAG>` with the release tag throughout.

## Prerequisites

- A **Linux backend** running the Containarium daemon.
- A **model-provider API key**: Anthropic (`ANTHROPIC_API_KEY`) for the default
  `claude` engine, or OpenAI (`OPENAI_API_KEY`) for the `codex` engine.
- CLI auth to the daemon (`--server <host>` + your token / mTLS certs).

## Step 1 — Cut a release (so the box artifacts exist)

The `agent-runtime` box pulls `agent-box-linux-amd64` + `agent-runtime-bundle.tar.gz`
from a GitHub release. Tag to trigger the Release workflow:

```bash
git tag <TAG>            # e.g. v0.28.0
git push origin <TAG>
```

Verify the release has **both** assets (the workflow runs `make bundle-agent-runtime`):

```bash
gh release view <TAG> --json assets --jq '.assets[].name' | grep -E 'agent-box-linux-amd64|agent-runtime-bundle'
```

## Step 2 — Run the daemon on that release

The daemon passes **its own version** as the box's `release` param, so the box
pulls artifacts matching the daemon. Deploy `<TAG>` to the backend (e.g. via
`scripts/deploy-binary.sh`), then confirm:

```bash
containarium version --server <host>     # must report <TAG>
containarium agent list                  # offline catalog: hello-agent, relay-agent
```

## Step 3 — Seed the provider key on the agent box

Secrets are stamped onto the box env (`environment.<NAME>`), and the daemon's
agent-runtime exec is a *new* exec, so it sees them. The agent box's tenant is
`agent-<skill-id>`.

The box is created on first run, so the simplest order is **run once (creates
the box) → set the key → run again**:

```bash
# 1. First run provisions the box (empty artifact — no key yet, best-effort).
containarium agent run hello-agent --input '{"q":"ping"}' --server <host>

# 2. Seed the key on that box's tenant.
containarium secrets set agent-hello-agent ANTHROPIC_API_KEY "sk-ant-..." --server <host>
```

> To use the **codex** engine instead, also set `CONTAINARIUM_AGENT_ENGINE=codex`
> and `OPENAI_API_KEY` as secrets on the box, e.g.
> `containarium secrets set agent-hello-agent CONTAINARIUM_AGENT_ENGINE codex`.

## Step 4 — Run a skill (expect a real artifact)

```bash
containarium agent run hello-agent --input '{"q":"say hi as JSON"}' --server <host>
```

The daemon provisions/reuses the box, seeds the task, execs `agent-runtime`
(which drives the Claude Agent SDK over the in-box `agent-box` MCP), and reads
`artifact.json` back. **Expect a non-empty artifact** (not the empty-artifact
fallback).

## Step 5 — Run a crew (A2A end-to-end → COMPLETED)

A crew is the simplest way to exercise A2A: `RunCrew` provisions each member,
starts it in **serve mode** (the `:8674` A2A server), and drives the hops.

```bash
# Seed the key on each member box (relay-agent + hello-agent) the same way as
# Step 3, then:
containarium crew run hello-crew --input '{"q":"relay then echo"}' --server <host>
containarium crew status <run-id> --server <host>   # expect COMPLETED + artifact
```

`hello-crew` is the pipeline `relay-agent → hello-agent` (relay's `allowed_peers`
includes hello, so the hop is permitted).

## Step 6 (optional) — Arm in-kernel enforcement

To validate the trust fabric (the eBPF egress drop), arm **both** the
daemon-wide enforcer and the agent opt-in on the Linux backend, and give the
agent box its platform egress so it isn't stranded:

```bash
# daemon env (eBPF Phase A enforcer)
CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=/path/to/netpolicy.bpf.o
CONTAINARIUM_NETWORK_POLICY_ENFORCE=1
# agent-skill policies in ENFORCE
CONTAINARIUM_AGENT_NETWORK_POLICY_ENFORCE=1
# platform egress the loop needs (daemon API + DNS resolver); the model
# providers (api.anthropic.com/api.openai.com) are allowed by default.
CONTAINARIUM_AGENT_EGRESS_CIDRS=<daemon-ip>/32,<dns-resolver-ip>/32
```

Then confirm a disallowed hop is dropped and audited:

```bash
# A skill calling a peer NOT in its allowed_peers is denied (API boundary) and,
# under ENFORCE, dropped in-kernel + logged:
containarium audit logs --action agent.a2a_call --server <host>
containarium audit logs --action network_policy.deny_dropped --server <host>
```

## Verification & troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `agent run` returns an empty artifact | Box image lacks the loop — check the release has the artifacts (Step 1) and the daemon is on `<TAG>` (Step 2); inspect `/etc/containarium/agent/artifact.json` and the recipe `post_start` log in the box. |
| Artifact `error: ...unauthorized` / provider auth | Key not stamped — re-check `secrets set` for the box tenant (Step 3) and that a fresh `agent run` (new exec) picked it up. |
| Artifact `error: ...api.anthropic.com ...` (unreachable) under ENFORCE | Model egress blocked — ensure `CONTAINARIUM_AGENT_EGRESS_DOMAINS` defaults are in effect and the DNS resolver CIDR is in `CONTAINARIUM_AGENT_EGRESS_CIDRS` (Step 6); the daemon logs a WARNING if armed with no model egress. |
| `agent-python: error: package index unreachable: ...` in a skill's shell output | The box's egress does not reach the Python package index. Under ENFORCE add `pypi.org,files.pythonhosted.org` to `CONTAINARIUM_AGENT_EGRESS_DOMAINS` (it replaces the provider defaults, so keep those listed), or point `PIP_INDEX_URL` at a reachable mirror. See the Python toolchain section of `agent-runtime/README.md`. |
| `crew run` lands `FAILED`, hop "no listener" | A member's serve-mode A2A server isn't up — check the member box ran `CONTAINARIUM_AGENT_MODE=serve agent-runtime` (RunCrew starts it; see the box's `/var/log/agent-runtime.log`). |
| `PermissionDenied: skill ... not permitted to call peer` | Working as intended — the target isn't in the caller's `allowed_peers`. |

## See also

- `docs/AGENT-SKILLS-QUICKSTART.md` — the CLI/MCP surface + trust fabric
- `docs/AGENT-RUNTIME-INBOX-LOOP-DESIGN.md` — the in-box loop design
- `agent-runtime/README.md` — engines, modes, build
