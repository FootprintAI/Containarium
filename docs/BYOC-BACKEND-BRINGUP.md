# Bringing up a BYOC backend

How to deploy a Containarium daemon on a **BYOC backend** — a host that joins a
control plane (CP) over an outbound tunnel — without it claiming names that
belong to the CP. Read this before the first `containarium daemon` start on such
a host: some of its settings persist and are easy to get wrong silently.

Related: [BYOC-PUBLIC-INGRESS-DESIGN.md](BYOC-PUBLIC-INGRESS-DESIGN.md) (data
path), [PER-POOL-BASE-DOMAIN.md](PER-POOL-BASE-DOMAIN.md) (pool domains),
[TLS-PROVISIONING.md](TLS-PROVISIONING.md) (certificates).

## What runs on a BYOC backend

A BYOC backend runs its **own** daemon and, with `--app-hosting`, its own set of
`containarium-core-*` containers (Postgres, Caddy, and optionally the security,
OTel and VictoriaMetrics containers). These are local services for that host.
They are **not** the control plane's services, which run elsewhere.

| Local container | Role | Needed on a BYOC backend? |
| --- | --- | --- |
| `containarium-core-postgres` | The daemon's own state (`daemon_config`, routes) | Yes, when `--app-hosting` is on |
| `containarium-core-caddy` | Local ingress for apps exposed on this host | Yes, when this host serves apps |
| `containarium-core-security`, `-otelcollector`, `-victoriametrics` | Scanning and local metrics | Optional |

## The invariants

A correctly brought-up BYOC backend has all of these:

1. **It does not use the CP's domain as its base domain.** The CP's base domain
   is the CP's. Leave `base_domain` empty unless this host serves a pool domain
   *it* owns.
2. **No bridge DNS wildcard for a domain it does not own.** With a base domain
   set, the daemon makes every box on the bridge resolve `*.<base-domain>` to the
   local Caddy (`raw.dnsmasq` on the bridge). That silently hides the real
   public records for that whole domain from every box.
3. **No management apex route or certificate order for a domain it does not
   own.** The daemon serves its management API on the apex of each base domain
   and asks for a certificate for it. If the name is not served by this host,
   the order fails forever (see [Symptoms](#symptoms)).
4. **Public HTTPS is terminated at the edge, not on the backend.** The primary
   model in the ingress design (#733; the design doc is still marked draft) is
   for the sentinel to terminate TLS with the wildcard it already holds and
   forward plaintext over the tunnel to a loopback listener on the backend.
   Enable it with `CONTAINARIUM_BYOC_INGRESS_ADDR=127.0.0.1:<port>`. The
   backend then has no reason to hold a DNS-provider token or to obtain public
   certificates itself. See
   [BYOC-PUBLIC-INGRESS-DESIGN.md](BYOC-PUBLIC-INGRESS-DESIGN.md), which also
   covers the alternative where the backend's Caddy terminates TLS (that one
   does need a certificate on the backend).
5. **Bring-your-own domains are per-hostname bindings, not base domains.** A
   customer domain is bound in the cloud (hostname to container and port),
   verified by a DNS TXT ownership check, and only then pushed to the backend
   as a single route. It needs no wildcard on any backend.

## The persistence trap: `base_domain` outlives the flag

The daemon stores its effective configuration in the `daemon_config` table of
its local Postgres. On every start, **if `--base-domain` is not passed, the
stored value is used** and logged:

```
base-domain = <value> (from DB)
```

So a one-time `--base-domain` — a copy-pasted example, a test run, an earlier
install — sticks. Removing the flag from the systemd unit does **not** clear it,
and re-running `containarium pool join` without `--base-domain` strips the flag
from the unit but leaves the stored value in place.

Check what a host actually uses:

```bash
sudo journalctl -u containarium -b --no-pager -o cat -g 'base-domain'
```

## Bring-up

1. Join the pool. `--base-domain` is optional; omit it on a BYOC backend.
   ```bash
   sudo containarium pool join --pool <pool> ...
   ```
2. Start the daemon with app hosting. Do not pass `--base-domain` unless the
   host owns that domain.
   ```bash
   containarium daemon --app-hosting --rest --jwt-secret-file /etc/containarium/jwt.secret ...
   ```
3. Set the edge ingress for the sentinel-terminated path in the daemon's
   environment: `CONTAINARIUM_BYOC_INGRESS_ADDR=127.0.0.1:<port>`.
4. Set `CONTAINARIUM_POSTGRES_PASSWORD` or `CONTAINARIUM_POSTGRES_PASSWORD_FILE`.
   Without it the daemon logs a warning and uses the compiled-in development
   password for the core Postgres.
5. Run the checks below.

## Verify

Run these on the backend after bring-up and after every upgrade. Replace
`<core-caddy>` with the core Caddy container name and `<box>` with any running
box.

```bash
# 1. Which base domain is the daemon using, and where did it come from?
sudo journalctl -u containarium -b --no-pager -o cat -g 'base-domain'

# 2. Is a wildcard DNS record installed on the bridge? (Expect empty unless
#    this host owns a pool domain.)
sudo incus network get incusbr0 raw.dnsmasq

# 3. Does Caddy hold a route or certificate subject you did not expect?
sudo incus exec <core-caddy> -- curl -s localhost:2019/config/apps/http/servers/srv0/routes
sudo incus exec <core-caddy> -- curl -s localhost:2019/config/apps/tls/automation/policies

# 4. Are certificate orders failing? (Expect no output.)
sudo incus exec <core-caddy> -- journalctl -u caddy --since -10min --no-pager -o cat \
  | grep -v admin.api | grep -E 'challenge failed|will retry'

# 5. What does a box see for the CP's names? It should be the real public
#    address, not the local Caddy's private address.
sudo incus exec <box> -- getent ahostsv4 <cp-hostname>
```

## Symptoms

| What you see | Likely cause |
| --- | --- |
| TLS handshake fails (`internal error`) for every name, including the wrong SNI and no SNI | The local Caddy holds no certificate for any name; boxes are being sent to it by a bridge wildcard |
| A name that should reach the public site or the CP resolves to a private address inside boxes | A bridge wildcard for a domain this host does not own (`raw.dnsmasq`) |
| Caddy logs `challenge failed` and `will retry` for the base-domain apex | The name is not served by this host (proxied or pointed elsewhere), so HTTP-01 and TLS-ALPN-01 can never succeed |
| A removed apex route reappears within seconds | The daemon's route sync re-adds it from its own store; delete it with `containarium route delete`, not through Caddy's admin API |
| A bridge record you deleted returns | `--bridge-dns-reconcile` restores drift on a bridge that has a record; see below |

## Recovering a host that claimed the wrong domain

Do these in order. Each step is reversible: keep the old values.

1. **Clear the stored base domain.** In the host's core Postgres, update the
   `base_domain` row of `daemon_config` to an empty string (or the correct pool
   domain), then restart the daemon. Confirm the startup log shows the new
   value.
2. **Remove the bridge record.**
   ```bash
   sudo incus network unset incusbr0 raw.dnsmasq
   ```
   With the reconciler on, a bridge that has *no* record is left alone (it only
   restores drift on an existing record), so the removal holds. If you need the
   record to stay exactly as it is, start the daemon with
   `--bridge-dns-reconcile=false`.
3. **Delete the leftover apex route at its source,** then confirm it stays gone
   for a few minutes. This needs an admin token (`containarium token generate`
   with a short `--expiry`, passed via `CONTAINARIUM_TOKEN` so it never lands in
   shell history or logs):
   ```bash
   containarium route delete <old-base-domain> --http --server http://localhost:8080
   ```
4. **Re-run the checks above,** including the box-side DNS probe.

Never fix the apex route or the bridge record by editing Caddy or the bridge
by hand while the daemon still holds the old base domain: both are rewritten.
