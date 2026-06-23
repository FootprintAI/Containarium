# Sentinel ↔ daemon HMAC secret (`CONTAINARIUM_SENTINEL_AUTH_SECRET`)

> **As of v0.45.0 there is a stronger, asymmetric successor.** The shared HMAC
> secret below is symmetric — every daemon that can verify the sentinel can also
> forge a request, which is a cross-tenant escalation on multi-tenant / BYOC
> deployments. To migrate to per-direction ed25519 keys (sentinel signs, daemons
> verify with a public key they cannot forge with), follow
> [SENTINEL-ED25519-MIGRATION-RUNBOOK.md](./SENTINEL-ED25519-MIGRATION-RUNBOOK.md).
> This document remains the reference for the legacy scheme and the shared
> `env.secrets` plumbing both schemes use.

Since **v0.19.0** the sentinel-facing daemon endpoints are gated behind an
HMAC signature keyed on a shared secret:

| Endpoint | Used by |
| --- | --- |
| `/authorized-keys` | sentinel keysync — builds the sshpiper upstream map |
| `/authorized-keys/sentinel` | sentinel pushes its own upstream key to the daemon |
| `/certs` | sentinel certsync — pulls Caddy-managed TLS certs |

Both ends read the secret from the environment variable
`CONTAINARIUM_SENTINEL_AUTH_SECRET`, which must be **at least 32 bytes** and
**identical on the sentinel and every daemon it talks to** (one secret per
cluster, not per host).

The endpoints **fail closed**: if the secret is missing or too short on either
end, the daemon answers every request with
`{"error":"sentinel auth not configured","code":401}`.

## Why this matters — the silent-lockout failure mode

A binary upgrade from a pre-HMAC version that leaves the secret unset does not
fail at startup; it fails per request, hours later:

1. Sentinel keysync hits the daemon's `/authorized-keys` → 401 every cycle.
2. The sshpiper upstream map stops being refreshed — frozen at last-known-good.
3. As backend addresses rotate (tunnel reconnects, loopback-alias races), the
   frozen map develops stale upstream pointers.
4. Tenants start getting `Permission denied (publickey)` / `Connection closed`
   — symptoms that look like per-user SSH problems but are a sentinel-wide
   outage.
5. Both daemons still report `active` in `systemctl status`, so the cause is
   several layers down (sshpiper pipe → backend listener → daemon endpoint 401).

This is tracked in **issue #341** (a real incident locked tenants out for
hours after a routine upgrade). The daemon and sentinel now log a rate-limited
`WARNING` when the secret is missing (see [Verifying](#verifying) below), and
`scripts/deploy-binary.sh` refuses to swap a binary onto a host whose secret
isn't provisioned.

## Generate the secret (once per cluster)

```bash
# 64 hex chars = 64 bytes, comfortably over the 32-byte minimum.
openssl rand -hex 32
```

Keep this value somewhere durable and off-host (a secrets manager / password
vault). It is **not** stored in Terraform state when written by the startup
scripts, and losing it means regenerating + redistributing to the whole
cluster.

## Distribute to the sentinel and every daemon

On **each** host — the sentinel, the primary daemon, and every peer daemon —
install the *same* value:

```bash
# As root on the host. Mode 0600 so the secret never shows up in `ps`,
# `systemctl cat`, or `systemctl show -p Environment`.
sudo install -d -m 0700 /etc/containarium
umask 077
sudo tee /etc/containarium/env.secrets >/dev/null <<EOF
CONTAINARIUM_SENTINEL_AUTH_SECRET=<the-secret-from-above>
EOF
sudo chmod 0600 /etc/containarium/env.secrets
```

Wire it into the systemd unit via a drop-in (the leading `-` on
`EnvironmentFile=-` tells systemd to tolerate the file being absent, which keeps
a not-yet-provisioned host bootable):

```bash
# Daemon hosts (primary + peers): unit name `containarium`.
# Sentinel host: unit name `containarium-sentinel`.
UNIT=containarium   # or containarium-sentinel on the sentinel
sudo mkdir -p "/etc/systemd/system/${UNIT}.service.d"
sudo tee "/etc/systemd/system/${UNIT}.service.d/secrets.conf" >/dev/null <<'EOF'
[Service]
EnvironmentFile=-/etc/containarium/env.secrets
EOF
sudo chmod 0644 "/etc/systemd/system/${UNIT}.service.d/secrets.conf"
sudo systemctl daemon-reload
```

> On a Terraform-provisioned cluster the startup scripts already write
> `/etc/containarium/env.secrets` and this drop-in from the `sentinel_auth_secret`
> module variable — see `terraform/modules/containarium/scripts/startup*.sh`.
> Set that variable to the cluster secret and you get the same result on boot.

## Restart order

Restart **daemons first, then the sentinel**, so that by the time the sentinel
resumes keysync/certsync the daemons are already accepting signed requests:

```bash
# 1. Each daemon host (primary + peers)
sudo systemctl restart containarium

# 2. Sentinel host, last
sudo systemctl restart containarium-sentinel
```

## Upgrading from < v0.19.0

1. Generate the cluster secret (above) if you don't already have one.
2. Distribute it to the sentinel and every daemon, install the drop-in,
   `daemon-reload`.
3. Deploy the new binary. `scripts/deploy-binary.sh` runs a preflight that
   **aborts** if the secret is missing on the sentinel or primary, pointing
   back here. Provision first, then re-run.
4. Restart daemons, then the sentinel.
5. Verify (below).

## Verifying

**Sentinel** exposes the state on its status endpoint — alert on
`sentinel_auth_misconfigured` being `true`:

```bash
curl -s http://<sentinel-host>:<health-port>/status | jq '.sentinel_auth_misconfigured, .sentinel_auth_detail'
# want: false / null
```

**Daemon** logs a rate-limited (once / 60s) line while the secret is missing
and a sentinel request arrives:

```bash
journalctl -u containarium --since '-5min' | grep -i 'sentinel-hmac'
# a healthy daemon logs nothing here
```

Once both are quiet and `/status` reports `false`, keysync/certsync is
authenticating and the sshpiper map is refreshing again.

## Rotating the secret

Rotation is the same distribute-then-restart dance with a fresh
`openssl rand -hex 32`. Push the new value to **every** host before restarting
anything; during the window where hosts disagree, requests 401. Restart
daemons first, then the sentinel, to minimize that window.
