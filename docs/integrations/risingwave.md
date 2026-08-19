# RisingWave on Containarium

Run [RisingWave](https://risingwave.com) — a streaming database that speaks the
Postgres wire protocol — as a dedicated, always-on box. The `risingwave` recipe
provisions an Ubuntu LXC, starts RisingWave in single-node mode inside it, puts
the dashboard and the webhook ingestion endpoint on public hostnames, and keeps
all state on a persistent volume.

```bash
containarium recipe deploy risingwave rw1 --server <host>
```

No GPU, no parameters, no sidecars required.

## How it works

Like every recipe, this does not run the upstream image *as* the container —
Containarium boxes are LXC system containers. It provisions an Ubuntu LXC and
runs the image inside it via Podman:

```
Incus LXC container
  └── Podman
      └── risingwavelabs/risingwave  single_node
          ├── :4566  Postgres wire protocol (SQL)
          ├── :5691  dashboard (HTTP)
          └── :4560  webhook source (HTTP)
```

`single_node` collapses meta, compute, frontend, and compactor into one process
backed by an **embedded SQLite meta store** and a **local-filesystem object
store**, both under `--store-directory`. That is what makes RisingWave a
one-box recipe rather than a compose stack: the batteries-included topology
RisingWave ships in its own `docker-compose.yml` needs MinIO, a Postgres meta
store, Prometheus, and Grafana alongside it.

State lives on the named Podman volume `risingwave-data`, mounted at
`/var/lib/risingwave`, so it survives container and box restarts.

## Reaching SQL: SSH local-forward, not a public hostname

Recipe ports become Caddy **HTTP reverse-proxy** routes. RisingWave's SQL port
speaks the Postgres wire protocol, which is not HTTP and cannot traverse that
proxy — so `:4566` is deliberately not in the recipe's port list. It is
published on the box, and you reach it the same way as any other non-HTTP
service (cf. [Android/VNC](../ANDROID-DEV-SETUP.md)):

```bash
ssh -L 4566:localhost:4566 rw1@<host>
# in another shell
psql -h localhost -p 4566 -d dev -U root
```

This is a property of the platform, not of RisingWave: until Containarium grows
an L4/TCP ingress, every Postgres/Redis/Kafka-shaped workload reaches its wire
protocol over SSH.

## Prerequisites

- **A host with the SIMD extensions RisingWave requires** — AVX2 on x86_64,
  NEON on ARM64. Check before deploying:

  ```bash
  ssh <host> 'grep -qm1 avx2 /proc/cpuinfo && echo ok || echo "no AVX2"'
  ```

  Nested virtualization that masks AVX2 from the guest is the usual cause of a
  box that deploys cleanly and then fails to boot RisingWave. The recipe's
  readiness gate catches this at deploy time rather than on your first `psql`.
- Enough headroom for the box's `cpu=8 memory=16GB disk=100GB` request.
- App hosting / routing enabled on the daemon if you want the dashboard and
  webhook endpoint on public hostnames. Without it the workload still runs and
  is reachable on the LAN; the deploy returns a warning instead of a URL.

## Discover the recipe

```bash
containarium recipe list
containarium recipe get risingwave
```

```
ID:          risingwave
Name:        RisingWave
Image:       images:ubuntu/24.04
Requires GPU: false
Resources:   cpu=8 memory=16GB disk=100GB
Port:        5691 -> dashboard
Port:        4560 -> webhook
Volume:      risingwave-data at /var/lib/risingwave
Param:       version [string] default="v3.0.0" — Image tag of risingwavelabs/risingwave to run.
Param:       total_memory_bytes [string] — Memory RisingWave divides between frontend, compute, and compactor.
Param:       parallelism [string] — Streaming/batch parallelism for the compute node.
```

## Deploy

```bash
containarium recipe deploy risingwave rw1 \
    --param total_memory_bytes=12884901888 \
    --server <host>
```

| Argument | Meaning |
|---|---|
| `risingwave` | recipe ID |
| `rw1` | deployment name → container `rw1-container` |
| `--param version=<tag>` | image tag to run (default `v3.0.0`) |
| `--param total_memory_bytes=<n>` | memory budget; see the note below |
| `--param parallelism=<n>` | compute parallelism (default: auto from CPU count) |

On success the deploy prints the first public URL, e.g.
`https://rw1-dashboard.<base-domain>`; the webhook endpoint is
`https://rw1-webhook.<base-domain>`.

### Set `total_memory_bytes` for anything long-lived

Left empty, RisingWave auto-detects its memory budget by reading *available
system memory* — which, from inside an LXC, reports the **host's** memory, not
the box's limit. On a large host that makes RisingWave size its caches for
memory the box will never be allowed to use, and the box gets OOM-killed under
load. Set it to roughly 80% of the box's memory limit:

```bash
# 16GB box -> ~12.8GB
--param total_memory_bytes=12884901888
```

## Verify

```bash
# dashboard
curl -sf https://rw1-dashboard.<base-domain>/ >/dev/null && echo ok

# SQL, over the tunnel
ssh -fN -L 4566:localhost:4566 rw1@<host>
psql -h localhost -p 4566 -d dev -U root -c 'SELECT version();'
```

A minimal end-to-end check — a materialized view that maintains itself:

```sql
CREATE TABLE events (user_id INT, amount INT);
CREATE MATERIALIZED VIEW totals AS
    SELECT user_id, SUM(amount) AS total FROM events GROUP BY user_id;

INSERT INTO events VALUES (1, 10), (1, 5), (2, 7);
FLUSH;
SELECT * FROM totals ORDER BY user_id;
```

### Webhook ingestion

`:4560` is RisingWave's webhook source — it is HTTP, so unlike SQL it *is*
routable. That makes an agent box able to push events into a table over plain
HTTPS with no Postgres driver and no tunnel:

```sql
CREATE TABLE wh_events (data JSONB)
WITH (
    connector = 'webhook'
) VALIDATE AS secure_compare(headers->>'x-signature', 'your-secret');
```

```bash
curl -X POST https://rw1-webhook.<base-domain>/webhook/dev/public/wh_events \
    -H 'x-signature: your-secret' \
    -H 'Content-Type: application/json' \
    -d '{"hello":"world"}'
```

## Via MCP

```jsonc
// discover
{ "tool": "list_recipes" }

// deploy
{ "tool": "deploy_recipe",
  "arguments": { "recipe_id": "risingwave", "name": "rw1",
                 "parameters": { "total_memory_bytes": "12884901888" } } }
```

`deploy_recipe` requires the `containers:write` scope; `list_recipes` requires
`containers:read`.

## Limitations

- **Single node only.** This recipe is one process on one box with a local-FS
  state store and an embedded SQLite meta store. It does not scale out, and the
  state store is only as durable as the box's disk. For an S3/MinIO state store
  and an external meta store, run RisingWave's own `docker-compose.yml` in a
  box created with the `docker` stack, and use `compose_enable` so the stack
  survives a host reboot.
- **SQL is not publicly routable.** See above — SSH local-forward until the
  platform has an L4/TCP ingress.
- **Local backend only (v1).** A recipe deploys on the backend its `--server`
  daemon manages; `--backend-id`/`--pool` returns `Unimplemented`.
- The recipe does not take a backup. `containarium backup create <name>` covers the
  box; a logical dump is `pg_dump` over the tunnel.

## Cleanup

```bash
containarium delete rw1 --server <host>
```

The `risingwave-data` volume lives inside the box, so deleting the box deletes
the state with it.
