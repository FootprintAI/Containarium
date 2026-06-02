# Multi-Pool Architecture

Multi-pool lets a single sentinel front several independent Containarium clusters. Each cluster ("pool") has its own primary VM, its own peers, its own postgres/Grafana/Caddy core stack, and its own subdomain. The sentinel routes inbound HTTPS by SNI to the right pool, transparently.

This is layered on top of the existing single-pool architecture in [MULTI-BACKEND-PEERS.md](MULTI-BACKEND-PEERS.md). It does not replace it: a sentinel with no registered primaries behaves exactly as before.

## When to use multi-pool

- Two teams want hard isolation (separate users, separate dashboards, separate audit logs) but want to share GLB / DNS / sentinel infrastructure.
- Workloads with different blast-radius (production vs lab/dev) shouldn't share a postgres/Grafana.
- You're splitting a single big VM into multiple smaller ones for cost, and want each piece to be a self-contained tenant rather than a shared cluster.

If a single team needs visibility across all containers, **don't use multi-pool** — keep one pool with multiple peers, which is the existing single-pool model.

## High-level architecture

```
                       <prod-pool>.example.com  <lab-pool>.example.com
                                       │                       │
                                       └──────────┬────────────┘
                                                  │ HTTPS
                                                  ▼
                                  ┌────────────────────────────────┐
                                  │          GLB → Sentinel          │
                                  │                                  │
                                  │  port 443 dispatcher:            │
                                  │   1. peek TLS ClientHello SNI    │
                                  │   2. m.primaries.LookupByHostname│
                                  │   3. forward TCP (passthrough)   │
                                  │      to that primary's IP:port   │
                                  │                                  │
                                  │  /sentinel/peers      (peers)    │
                                  │  /sentinel/primaries  (primaries)│
                                  │  yamux tunnels (peers)           │
                                  └──────────┬───────────────────────┘
                                             │
                            ┌────────────────┼────────────────┐
                            │ TCP passthrough │                │
                            ▼                 ▼                ▼
                   ┌─────────────────┐  ┌─────────────────┐
                   │ Primary (prod)  │  │ Primary (lab)   │
                   │ pool=prod       │  │ pool=lab        │
                   │ daemon + Caddy  │  │ daemon + Caddy  │
                   │ + postgres      │  │ + postgres      │
                   │ + Grafana       │  │ + Grafana       │
                   └────────┬────────┘  └────────┬────────┘
                            │                    │
              ┌─────────────┼──────┐    ┌────────┼───────┐
              ▼             ▼      ▼    ▼        ▼       ▼
          peer-prod-1  peer-prod-2 ...  peer-lab-1  peer-lab-2
          pool=prod    pool=prod        pool=lab    pool=lab
```

## Component responsibilities

| Component | Role | Pool-aware? |
|---|---|---|
| **Sentinel** | TCP/SNI routing, tunnel termination, peer/primary registry | Yes — but stateless about pool semantics; just routes by tag |
| **Primary daemon** (per pool) | Owns a pool's local containers, aggregates pool peers, serves WebUI/API for the pool | Yes — `--pool` flag scopes peer discovery |
| **Peer daemon** (per host) | Hosts containers under one pool, exposes API via reverse tunnel | Yes — `--pool` flag picks pool at registration |
| **GLB** | TLS-passthrough load balancer in front of sentinel | No — same single-host config as before |
| **DNS** | Subdomain per pool, all CNAME'd to the GLB | Operator-managed |

## The four pieces of plumbing

| Slice | What it added | Code |
|---|---|---|
| 1 | Pool tag on tunnel handshake → `TunnelSpot` → `Backend`; `/sentinel/peers?pool=X` filter; `--pool` on `containarium tunnel` and `setup-peer.sh` | `internal/sentinel/tunnel_*.go`, `cmd/tunnel.go`, `scripts/setup-peer.sh` |
| 2 | `--pool` flag on the daemon; `PeerPool` appends `?pool=` to discovery so primaries see only their own peers | `internal/cmd/daemon.go`, `internal/server/peer.go` |
| 3 | Primary self-registration with sentinel: `POST /sentinel/primaries`, heartbeat, deregister; `--public-hostname` / `--public-port` flags | `internal/sentinel/primary_registry.go`, `internal/server/primary_register.go` |
| 4 | SNI peeking + routing in the sentinel HTTPS dispatcher; falls back to the legacy single-backend behavior on miss | `internal/sentinel/sni.go`, `internal/sentinel/manager.go` |
| 5 | Hostname aliases on `Primary` so app domains (e.g. `api.example.com`) route to the right pool's primary; `--public-aliases` flag | `internal/sentinel/primary_registry.go`, `internal/server/primary_register.go` |
| 6 | Primary registration via tunnel handshake — a primary behind NAT/Tailscale tunnels into the sentinel and gets auto-promoted into the primary registry pointing at its loopback alias | `internal/sentinel/tunnel_auth.go`, `tunnel_registry.go`, `manager.go`, `internal/cmd/tunnel.go`, `scripts/setup-peer.sh` |
| 7 | Token-bound pool authorization — `--tunnel-token-policy token=pool1,pool2` per-pool tokens; sentinel rejects handshakes whose `pool` field isn't in the token's allow-list. Adds `type Pool string` so pool routing uses a distinct type instead of bare strings. | `internal/sentinel/pool.go`, `tunnel_auth.go`, `internal/cmd/sentinel.go` |
| 8 | SNI router uses yamux for tunneled primaries — `TunnelRegistry.DialTunnel()` opens a yamux stream directly to the primary's local port, avoiding the loopback-listener-on-:443 conflict with the sentinel's own ConnMux. | `internal/sentinel/tunnel_registry.go`, `manager.go`, `tunnel_server.go` |

## Flows

### Peer registration

```
peer host                    sentinel
  │                              │
  │  containarium tunnel \       │
  │    --pool prod \             │
  │    --spot-id host-a \        │
  │    --token …                 │
  │                              │
  │  ───── handshake ─────────▶  │  TunnelHandshake{spot_id, pool=prod, …}
  │                              │  → TunnelRegistry.Register(…, pool="prod")
  │                              │  → BackendPool.Add(Backend{Pool: "prod"})
  │  ◀──── handshake ok ──────   │
  │                              │
  │  ═══════ yamux session ═══   │
```

### Primary discovery

```
primary daemon (pool=prod)         sentinel
       │                              │
       │  GET /sentinel/peers?pool=prod
       │  ─────────────────────────▶  │
       │                              │  PeersHandler:
       │                              │    filter b.Pool == "prod"
       │  ◀──── { peers: […prod] }    │
       │                              │
       │  store in PeerPool, fan out  │
       │  /v1/containers, etc.        │
```

### Primary registration + heartbeat

```
primary daemon                        sentinel
       │                                 │
       │  POST /sentinel/primaries       │
       │  { pool: "prod",                │
       │    hostname: "containarium-     │
       │      <prod-pool>.example.com",         │
       │    port: 443 }                  │
       │  ────────────────────────────▶  │  PrimaryRegistry.Register
       │                                 │  IP filled from RemoteAddr
       │  ◀── 201 Created                │
       │                                 │
       │  every 30s:                     │
       │  PUT /sentinel/primaries/prod   │
       │  ────────────────────────────▶  │  Heartbeat refreshes LastHeartbeat
       │                                 │  (entries older than 90s are evicted)
       │                                 │
       │  on shutdown:                   │
       │  DELETE /sentinel/primaries/prod│
       │  ────────────────────────────▶  │
```

### Inbound HTTPS routing (SNI)

```
client (browser)                sentinel                          primary (prod)
    │                              │                                   │
    │  TCP connect :443            │                                   │
    │  ─────────────────────────▶  │                                   │
    │                              │  startHTTPSProxy handler:         │
    │  TLS ClientHello             │   1. bufio.Peek the record        │
    │   SNI=containarium-          │   2. extractSNI(buf) → "…-prod…"  │
    │   <prod-pool>.example.com           │   3. primaries.LookupByHostname() │
    │  ─────────────────────────▶  │   4. dial primary.IP:primary.Port │
    │                              │   5. replay peeked bytes,         │
    │                              │      then io.Copy both directions │
    │                              │  ─────────────────────────────▶   │
    │                              │                                   │  Caddy terminates TLS,
    │                              │                                   │  routes by Host to /webui or
    │  ◀════════════════════════════════════════════════════════════   │  /v1/* on the daemon
```

If SNI is missing, malformed, or doesn't match any registered primary, the dispatcher falls back to the existing single-backend forwarding — **fully back-compat for unpooled deployments.**

### App domain routing via aliases

A primary registers its main hostname plus any *additional* hostnames its Caddy serves (`api.example.com`, `voice.example.com`, etc.). The SNI lookup matches against both, so app-domain traffic lands on the same primary that owns the pool's apps:

```
client (browser)                sentinel                          primary (prod)
    │                              │                                   │
    │  TLS ClientHello              │                                   │
    │   SNI=api.example.com         │                                   │
    │  ─────────────────────────▶   │                                   │
    │                              │  primaries.LookupByHostname        │
    │                              │   matches Aliases of pool=prod     │
    │                              │   → forward to prod primary:443    │
    │                              │  ─────────────────────────────▶    │
    │                              │                                   │  Caddy:
    │                              │                                   │   Host=api.example.com
    │                              │                                   │   → api-container:8080
    │  ◀════════════════════════════════════════════════════════════    │
```

Without aliases, app-domain SNI would miss the registry and fall through to the legacy single-backend forwarder — losing pool isolation. **In a multi-pool deployment, every app hostname served by a pool's Caddy must appear in that primary's `--public-aliases`.**

### Primary behind NAT/Tailscale (slice 6)

A primary doesn't need to be in the same network as the sentinel. If it can only reach the sentinel via the existing yamux tunnel (Tailscale, behind NAT, etc.), the *tunnel handshake itself* carries the primary registration:

```
peer/primary host                           sentinel
       │                                       │
       │  containarium tunnel \                │
       │    --pool lab \                       │
       │    --spot-id lab-primary-1 \          │
       │    --ports 22,8080,443 \              │
       │    --public-hostname containarium-    │
       │      lab.example.com \                │
       │    --public-aliases lab-api.kafeido.  │
       │      app \                            │
       │    --public-port 443                  │
       │                                       │
       │  ─── handshake (JSON) ─────────────▶  │  TunnelRegistry.Register
       │                                       │  → assigns 127.0.0.X loopback
       │                                       │  → OnTunnelConnect:
       │                                       │     primaries.Register(
       │                                       │       Pool=lab,
       │                                       │       Hostname=containarium-lab…,
       │                                       │       IP=127.0.0.X, Port=443,
       │                                       │       BackendID=tunnel-lab-primary-1)
       │  ◀── handshake_ok                     │
       │                                       │
       │  ═══════ yamux session ═════════════  │
       │   sentinel binds 127.0.0.X:443        │
       │   (loopback proxy → yamux)            │
```

When inbound TLS arrives with `SNI=<lab-pool>.example.com`, the SNI router's `LookupByHostname` returns the tunnel-promoted entry. Sentinel dials `127.0.0.X:443` (its own loopback alias), bytes stream through yamux back to the primary's local `:443` (where Caddy terminates TLS).

On tunnel disconnect, the primary entry is removed automatically (`UnregisterByBackendID`).

**Limitation**: a tunneled primary's daemon can't reach `/sentinel/peers` for peer discovery (the binary server isn't publicly exposed). Acceptable for a single-node lab pool; future work if you want peers under a tunneled primary.

## Operator workflow: adding a new pool

1. **Pick a name and subdomain.** E.g. `pool=lab`, hostname `<lab-pool>.example.com`.
2. **Provision a primary VM.** Same Terraform module as your existing primary (`terraform/modules/containarium/`). The new VM runs its own postgres/Grafana/Caddy core stack.
3. **Configure the primary daemon** with the registration flags:
   ```
   containarium daemon \
     --sentinel-url http://<sentinel-internal-ip>:8888 \
     --pool lab \
     --public-hostname <lab-pool>.example.com \
     --public-aliases lab-api.example.com,lab-grafana.example.com \
     --public-port 443 \
     --proxy-protocol --proxy-protocol-trusted=127.0.0.0/8 \
     ...other flags...
   ```
   `--public-aliases` lists every hostname the primary's Caddy serves *besides* the primary's own subdomain (app domains, custom hostnames). The sentinel routes any of these to this primary by SNI.

   `--proxy-protocol --proxy-protocol-trusted=127.0.0.0/8` is required when the sentinel itself runs with `--proxy-protocol` (the prod sentinel does). The sentinel's SNI router writes a PROXY v2 frame before the TLS bytes; without the matching flag on the primary, the primary's Caddy mis-parses the frame and the first TLS handshake fails silently with no log on either end. See [`PROXY-PROTOCOL.md` → Troubleshooting](PROXY-PROTOCOL.md#tls-handshake-fails-silently-for-a-tunnel-promoted-pool-primary). Trusted is `127.0.0.0/8` because the tunnel client forwards bytes from local loopback.
4. **Register peers** with the matching pool tag:
   ```
   sudo bash setup-peer.sh --spot-id host-a --pool lab ...
   ```
5. **Add DNS:** `<lab-pool>.example.com` CNAME → the GLB.
6. **TLS:** wildcard cert on the GLB (`*.example.com`) already covers it. If using per-subdomain certs, add a managed cert.
7. **Verify:**
   ```
   curl -s https://<cluster>.example.com/sentinel/primaries | jq
   # → confirms lab primary is registered
   curl -s https://<cluster>.example.com/sentinel/peers?pool=lab | jq
   # → confirms peers are tagged correctly
   curl -sI https://<lab-pool>.example.com/      # → 200 from lab primary
   ```

No sentinel config edits, no Caddy admin API edits, no daemon restart on the existing pool.

## Trade-offs

- **One sentinel = single point of failure for both pools.** A sentinel outage takes both pools' inbound traffic down. We accept this for simplicity; if SLA matters, run a regional GLB with multiple sentinels.
- **Each pool runs its own postgres/Grafana/Caddy.** That's ~4–6 GB extra RAM per pool. The trade-off is clean isolation: a postgres outage in one pool can't take down the other.
- **Pool tag is set-once per peer.** Moving a peer between pools requires re-running `setup-peer.sh --pool=...` and a tunnel restart.
- **`/sentinel/primaries` is currently unauthenticated.** Acceptable for VPC-internal traffic. Add auth (shared secret like the tunnel token, or signed registrations) before exposing publicly.
- **Pools are tags, not first-class entities.** A pool exists the moment a peer or primary registers with the name. There is no "create pool" command — by design.

## What's still ahead

- Auth on `/sentinel/primaries` (low risk in VPC, real before public exposure).
- Cross-pool aggregator UI (out of scope today; would be a separate service that queries each primary's `/v1/backends`).
- Heartbeat-based primary failover (today: sentinel falls back to legacy single-backend on SNI miss; not yet a "primary failed → use a hot spare" path).
- **Pool-namespaced SSH usernames (correctness — high priority).** Today the sentinel's keysync iterates every backend's `/authorized-keys` and writes one global sshpiper YAML mapping. If two pools both expose a user named `test01`, last-write-wins silently routes `ssh test01` to whichever backend got iterated last. Fix: keysync should emit `<user>-<pool>` (e.g. `test01-lab`, `test01-node-a`) and sshpiper YAML maps that namespaced form to the correct upstream. Requires changes to the sshpiper YAML generator on the sentinel and a one-time SSH config migration on operator side.
- **sshpiper routing updates no longer go through a restart (#301, resolved).** keysync used to `systemctl restart sshpiper` after every YAML change, which dropped all live SSH sessions and — observed during multi-pool bring-up — didn't even reliably refresh the routing table (only `systemctl kill` + `start` did). Root cause: the `sshpiperd` `yaml` plugin re-reads `config.yaml` from disk on **every** incoming connection (`listPipe` → `loadConfig`), so a restart was never the mechanism for picking up new routes — writing the file is enough, and new connections see new routes immediately while in-flight sessions stay live. keysync now just rewrites the file; no restart. If a stale-routing symptom ever recurs it's a config-write/flush bug, not a restart-timing one.
- **Daemon `/authorized-keys` should skip nologin host users when the wrapper isn't installed.** Defensive: if `/usr/local/bin/containarium-shell` doesn't exist on a peer, the daemon still advertises every "Containarium user - *" host account, but those accounts have a nologin shell and just confuse keysync + give "account not available" when SSH'd. Filter: if `getUserShell()` would return nologin, omit the user from `/authorized-keys`.
