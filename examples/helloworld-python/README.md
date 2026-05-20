# Demo: Python hello-world via the agent-native flow

A tiny Python `http.server` that displays the visitor's IP, the deployed commit ID, and the current server time. It exists primarily to exercise — and demonstrate — the four-step deploy flow you'd use with any other app:

1. **Create** a container
2. **Push** code into it (git over SSH)
3. **Expose** a port on a public hostname
4. (no step 4 — Caddy ACMEs a cert on the first request)

The deployment is live at **https://helloworld.demo.containarium.dev/**. Open it in a browser; refresh to see the time change.

## What's in this folder

| File | Role |
|---|---|
| `app.py` | The Python server. Uses stdlib `BaseHTTPServer` — no deps. Reads commit SHA from `commit.txt`, real client IP from the `X-Forwarded-For` header that Caddy populates from PROXY-v2. |
| `deploy.sh` | Runs inside the container as a post-receive deploy hook. Writes `commit.txt`, installs the systemd unit, restarts the service. |
| `helloworld.service` | systemd unit that runs `app.py` as the `helloworld` user, restarting on failure. |

## Reproducing it

Pre-requisites: a Containarium cluster you can talk to, the MCP server wired to it (or the `containarium` CLI configured with `--server`), and an admin JWT.

### Via MCP (agent-native path)

```text
mcp__<your-cluster>__create_container(username="helloworld", cpu="1", memory="512MB", disk="10GB")

mcp__<your-cluster>__push(
  username="helloworld",
  local_path="examples/helloworld-python",
  deploy_cmd="bash deploy.sh",
)

mcp__<your-cluster>__expose_port(
  username="helloworld",
  container_port=8080,
  domain="helloworld.demo.containarium.dev",
)
```

That's it. The first request to `https://helloworld.demo.containarium.dev/` will trigger Caddy's ACME-on-demand to mint the cert, then proxy through to the Python server.

### Via CLI

```sh
containarium create helloworld --ssh-key ~/.ssh/id_ed25519.pub
# (push step needs the MCP push tool today; bare git-push works too if you set up the bare repo manually)
containarium expose-port helloworld --container-port 8080 --hostname helloworld.demo.containarium.dev
```

## Notes

- **Why systemd, not nohup?** The post-receive deploy hook needs to fully detach from the SSH session. systemd does this naturally and gives us free restart-on-failure + log capture in `journalctl`. The alternative (`nohup ... &`) leaves edge cases around tty hangups.
- **Why does the `Your IP` field show your real IP?** The cluster's sentinel emits a PROXY-v2 header on the forwarded TCP stream; the destination Caddy is configured with `--proxy-protocol-trusted` covering the bridge subnet and decodes it, then sets `X-Forwarded-For`. Without that trust config, you'd see the LXC bridge gateway (`10.x.x.1`) instead. See [PROXY-PROTOCOL.md](../docs/PROXY-PROTOCOL.md).
- **Auto-sleep?** This container is opted into auto-sleep (`user.containarium.auto_sleep_enabled=true`, 15-minute threshold). If nobody's hit the URL in 15 minutes, the autosleep ticker stops the container; the next request wakes it (~2s on this image). You can verify by curling, waiting 20 minutes, then timing another curl.

## Verified against

Containarium **v0.17.0** (May 2026). API/MCP surface may drift in later releases; check `docs/MCP-INTEGRATION.md` for the current tool schema if `push` or `expose_port` parameters look different.
