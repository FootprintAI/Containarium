# PoC — Containarium input/output gate as an AgentCore Gateway interceptor

Proof-of-concept for the interposition path described in
[`docs/AGENTCORE-GATEWAY-INTERCEPTOR-SPIKE.md`](../../docs/AGENTCORE-GATEWAY-INTERCEPTOR-SPIKE.md).

A single Lambda serves as both the REQUEST and RESPONSE interceptor on an
AgentCore Gateway:

| Direction | What it does | Gate |
| --- | --- | --- |
| REQUEST | Reads `params.arguments` of a `tools/call`; short-circuits with a JSON-RPC error when the arguments carry a credential or a long blob in a URL query | Output gate — action interception |
| RESPONSE | Scans the tool result for injection markers and redacts them before the data re-enters the agent's context | Input gate |
| Both | Emits an audit event toward the Containarium hash chain | Evidence |

The detection logic is deliberately shallow — the point is to prove the
*mechanism* carries a verdict, not to ship a DLP engine. Production should
compile the Go inspection engine to a Lambda, or make this a thin proxy to it.

## Run the tests locally (no AWS account)

```bash
cd examples/agentcore-interceptor
python3 -m unittest discover -v
```

12 tests cover both documented payload shapes (`mcp` with parsed JSON bodies,
`http` with base64 bodies), the block path, the redaction path, and the
excluded-body case.

## Deploy against a real gateway

```bash
zip -j interceptor.zip handler.py

aws lambda create-function \
  --function-name containarium-gate \
  --runtime python3.12 \
  --handler handler.lambda_handler \
  --role arn:aws:iam::<account>:role/<lambda-exec-role> \
  --zip-file fileb://interceptor.zip

# The gateway service role must be allowed to invoke it — scope to this one
# function, never a wildcard.
aws lambda add-permission \
  --function-name containarium-gate \
  --statement-id agentcore-gateway \
  --action lambda:InvokeFunction \
  --principal bedrock-agentcore.amazonaws.com \
  --source-arn arn:aws:bedrock-agentcore:<region>:<account>:gateway/<gateway-id>
```

Then attach it as both the REQUEST and RESPONSE interceptor on the gateway. A
gateway accepts **at most one of each**; if the customer already runs an
interceptor (AWS recommends one for private IdP auth), ours has to absorb that
logic rather than sit beside it.

Leave `passRequestHeaders` **off** unless something genuinely needs it — headers
carry bearer tokens, and an interceptor that logs them has turned a security
control into a credential leak.

## The experiment that actually matters

**Does the gateway fail open or fail closed when the interceptor dies?**

The AWS docs do not say. Everything else here is worthless if the answer is
"fails open" — an attacker who can time out the Lambda would simply walk past
the gate.

```bash
# 1. Baseline: confirm a blocked call is actually blocked.
#    Expect the JSON-RPC error, and no invocation on the target.

# 2. Crash the interceptor and repeat the same call.
aws lambda update-function-configuration \
  --function-name containarium-gate \
  --environment 'Variables={CONTAINARIUM_INTERCEPTOR_FAILMODE=crash}'

#    Did the tool call go through anyway?  -> FAILS OPEN. The control is
#    advisory only; say so on every slide, and keep the eBPF/VPC backstop as
#    the enforcing layer.
#    Was it refused?                       -> FAILS CLOSED. Then measure the
#    availability cost: every interceptor error is now a failed agent action.

# 3. Repeat with FAILMODE=timeout — a hang and a crash are not always handled
#    the same way, and a slow interceptor is the more realistic attack.

# 4. Reset.
aws lambda update-function-configuration \
  --function-name containarium-gate --environment 'Variables={}'
```

Record the result in the spike doc before any of this reaches a customer.

## Also measure

- **Added latency** per tool call and per inference call — this sits on the hot
  path of every agent action.
- **The 6 MB ceiling.** Lambda's synchronous payload limit covers request and
  response *combined*, and AWS notes large bodies are "common with inference
  models". The workaround — a payload filter excluding `RESPONSE_BODY` — means
  the body is `null` and DLP on it is impossible. The handler reports that case
  as `input_gate.skipped` rather than claiming a clean scan; find out how often
  it fires in practice.
- **Streaming.** MCP streaming invokes the RESPONSE interceptor once per event.
  HTTP-target interceptors are buffered-only, so inference streaming is not yet
  covered at all.

## Environment

| Variable | Purpose |
| --- | --- |
| `CONTAINARIUM_AUDIT_URL` | Where audit events are POSTed. Unset = log only. |
| `CONTAINARIUM_AUDIT_TOKEN` | Bearer token for the above. |
| `CONTAINARIUM_INTERCEPTOR_FAILMODE` | `crash` / `timeout`. Test-only — never set in production. |

Audit emission is fail-soft: a dropped audit event leaves a gap in evidence, a
dropped tool call is an outage. Both are bad; they are not equally bad.
