# openhands-runtime-shim (proof of concept)

A PoC implementation of the [OpenHands](https://github.com/OpenHands/OpenHands)
**runtime API** contract on top of Containarium, making Containarium boxes
usable as OpenHands agent sandboxes.

Both OpenHands clients provision sandboxes through this one contract:

- the SDK's `APIRemoteWorkspace`
  (`software-agent-sdk/openhands-workspace/.../remote_api/workspace.py`)
- the self-hosted app's `RemoteSandboxService`
  (`OpenHands/openhands/app_server/sandbox/remote_sandbox_service.py`)

so a single provider implementation serves both. There is no published spec;
the contract here was derived from those two (MIT-licensed) clients.

## What it maps

| OpenHands concept | Containarium implementation |
| --- | --- |
| runtime session (`session_id`) | one persistent box per session (`oh-<hash>`) |
| agent-server pod | podman container in the box (root podman, `--restart=always`) |
| ingress `url` | the box's managed-TLS public subdomain → `:60000` |
| `session_api_key` | minted by the shim, injected as `OH_SESSION_API_KEYS_0` env |
| `pause` / `resume` | box `sleep` / `wake` (+ new session key on resume, per contract) |
| `runtime_class` (sysbox/gvisor) | ignored — the system container is the isolation boundary |

Because the box persists across sessions, the same `session_id` re-attaches to
its sandbox with all state intact — unlike ephemeral-first hosted runtimes.

## Validation status

The **full contract is validated end-to-end** against a live Containarium
cloud control plane, driving the shim with OpenHands' **unmodified** SDK
(v1.32.0) and raw HTTP for the lifecycle verbs:

- **Cold provision** (`/start` → box create → image pull → agent-server →
  route → healthy): ~2 min to `ready`, inside the SDK's default 300 s window.
- **Attach + exec**: `execute_command` round-trips inside the agent-server
  container; readiness/health/WebSocket URL shapes all consumed by the SDK
  as-is.
- **Persistence**: two SDK runs with the same `session_id` land in the same
  sandbox with prior state intact.
- **`/pause` / `/resume`**: box sleeps and wakes; resume mints a **new**
  `session_api_key` (the old one is invalidated, per the upstream security
  invariant), re-runs the agent-server with the new key, recreates the route
  for the box's new IP, and the session returns to `running`/`ready`.
  Requires a control plane whose OSS-compat shim serves the container
  stop/start sub-path verbs (Containarium-cloud #785).
- **`/stop`**: box and route are actually destroyed.
- **Failure semantics**: a failed provision surfaces as `pod_status: failed`
  + `pod_logs`, which the SDK raises verbatim.
- **Recovery**: re-`/start` of a failed session adopts the existing box and
  finishes provisioning.

One environmental requirement surfaced by validation: the runtime hostname
family must be **DNS-only (not proxied through a CDN/WAF)**. The SDK's health
check uses raw `urllib` (bot protection 403s it on User-Agent), and proxy
request-duration caps would sever long agent operations. Direct-to-ingress
with the managed wildcard TLS cert works as-is.

## Run

```sh
go build -o oh-shim .
OH_SHIM_API_KEY=<key clients send as X-API-Key> \
OH_SHIM_URL_SUFFIX="-<org>.<zone>" \
OH_SHIM_CLI=/path/to/containarium \
./oh-shim
```

The shim uses the `containarium` CLI (logged-in via `containarium login`) for
box lifecycle, and the REST API for route management. Point an OpenHands
client at it:

```python
from openhands.workspace import APIRemoteWorkspace

workspace = APIRemoteWorkspace(
    runtime_api_url="http://127.0.0.1:8700",
    runtime_api_key="<OH_SHIM_API_KEY>",
    server_image="ghcr.io/openhands/agent-server:latest-python",
)
with workspace:
    print(workspace.execute_command("echo hello").stdout)
```

## PoC limitations (productization gaps)

- **Warm images**: first start on a cold box pulls a ~4 GB agent-server image.
  A real provider must pre-pull/cache the image host-side (the SDK's default
  readiness timeout is 300 s).
- Single shim API key ↔ single Containarium account; no multi-tenant key
  issuance/metering.
- State is a local JSON file; no reconciliation with actual box state.
- Only the agent-server port (60000) is routed; the app's extra services
  (VS Code :60001, worker previews :12000/:12001) expect
  `{service}-{host}` subdomains that are not yet claimed.
- No webhook egress validation (`RUNTIME` → app-server callbacks).
- The CLI `expose-port` verb is gRPC-only today, so routes go through REST
  directly — a CLI-first gap to fix upstream.
- `pause`/`resume` need a control plane whose OSS-compat shim serves the
  container stop/start sub-path verbs (Containarium-cloud #785; against a
  plain OSS daemon the endpoints already exist).
- Fresh boxes have two transient windows the shim retries through: sentinel
  SSH-key propagation (~2 min) and in-box tenant-user creation (SSH auth can
  succeed before the user is fully written — surfaces as an su "user does not
  exist / required fields" error). Long steps (the image pull) run detached
  in-box with short polling execs, because a single exec spanning minutes can
  be reset mid-flight on a proxied SSH path.
