# Sentinel → daemon ed25519 auth — migration runbook (#688)

Migrates the sentinel→daemon authentication from the deployment-wide
**symmetric HMAC secret** (`CONTAINARIUM_SENTINEL_AUTH_SECRET`, see
[SENTINEL-AUTH-SECRET.md](./SENTINEL-AUTH-SECRET.md)) to an **asymmetric ed25519**
scheme. Available since **v0.45.0**.

## Why

The HMAC secret is symmetric and shared by the whole cluster: every daemon that
must *verify* a sentinel request also holds the key to *forge* one. On a
multi-tenant deployment that is a **cross-tenant escalation** — a BYO-compute
(BYOC) host only needs to *accept* the sentinel's keysync/certsync, but holding
the shared secret lets it forge a request the shared host accepts and push
attacker-controlled SSH keys into other tenants' boxes via
`/authorized-keys/sentinel`.

With ed25519 the sentinel→daemon direction becomes "sentinel signs, daemon
verifies":

| Key | Lives on | Env var | Sensitivity |
| --- | --- | --- | --- |
| ed25519 **private** | the sentinel only | `CONTAINARIUM_SENTINEL_SIGNING_KEY` | **secret** |
| ed25519 **public** | every daemon | `CONTAINARIUM_SENTINEL_PUBLIC_KEY` | safe to distribute (incl. BYOC) |

A daemon holding only the public key can verify the sentinel but **cannot
forge** a request. The endpoints covered are the same three the HMAC scheme
gated (`/authorized-keys`, `/authorized-keys/sentinel`, `/certs`) plus the
`/sentinel/peers` discovery response.

> The daemon→sentinel PKI bootstrap (`/sentinel/ca`, `/sentinel/peer-cert`) is a
> **different trust direction** with its own threat model and is **not** changed
> by this migration — it stays on the shared secret.

## Safe-by-default + dual-accept

The verifier is **dual-accept**: it accepts ed25519 (when a public key is
configured) and/or the legacy HMAC (when the secret is configured). With **no
ed25519 env set, behavior is identical to the HMAC scheme** — so v0.45.0 can be
deployed everywhere before any key is introduced. The migration only takes
effect as you set the env vars in the order below.

> **Env is read once at process start.** The daemon and sentinel cache these
> values on first use, so **every env change requires a process restart** to
> take effect. There is no hot reload.

## Prerequisite

**v0.45.0+ on the sentinel and every daemon** (including BYOC hosts). Verify:

```bash
containarium version    # daemon hosts
# sentinel host:
containarium-sentinel --version 2>/dev/null || containarium version
```

A daemon still on an older binary does not understand
`CONTAINARIUM_SENTINEL_PUBLIC_KEY` and will reject ed25519 signatures — which is
exactly why the signing key goes on the sentinel **last** (see ordering).

---

## Step 0 — generate the keypair (once per cluster)

On any host with the v0.45.0 binary:

```bash
containarium sentinel keygen
```

Output (two env lines):

```
CONTAINARIUM_SENTINEL_SIGNING_KEY=<base64 ed25519 private key>   # sentinel only — keep secret
CONTAINARIUM_SENTINEL_PUBLIC_KEY=<base64 ed25519 public key>     # every daemon — safe to distribute
```

Store the **signing key** somewhere durable and off-host (secrets manager /
vault), the same way you handle `CONTAINARIUM_SENTINEL_AUTH_SECRET`. Losing it
means regenerating + redistributing the public key to the whole fleet.

---

## Step 1 — public key to **every** daemon (first)

On **each** daemon host — primary, every peer, and **every BYOC host** — append
the public key to the existing secrets file and restart so it is picked up.
This is additive: the daemon stays dual-accept (HMAC still works), it just
*also* becomes able to verify ed25519.

```bash
# As root on each daemon host.
umask 077
echo 'CONTAINARIUM_SENTINEL_PUBLIC_KEY=<public key from Step 0>' \
  | sudo tee -a /etc/containarium/env.secrets >/dev/null
sudo chmod 0600 /etc/containarium/env.secrets
sudo systemctl restart containarium
```

> Uses the same `/etc/containarium/env.secrets` + `EnvironmentFile=-` drop-in as
> [SENTINEL-AUTH-SECRET.md](./SENTINEL-AUTH-SECRET.md#distribute-to-the-sentinel-and-every-daemon).
> If that drop-in isn't installed yet, install it first.

Confirm each daemon logged that the public key was accepted:

```bash
journalctl -u containarium --since '-2min' | grep -i 'ed25519 public key configured'
# want: "Sentinel ed25519 public key configured — ... accept ed25519-signed requests"
```

**Do not proceed to Step 2 until every daemon — including BYOC — shows this.**
A daemon that hasn't received the public key will reject the sentinel's ed25519
signatures in Step 2 and its keysync/certsync will start 401-ing (the #341
silent-lockout failure mode).

---

## Step 2 — signing key on the sentinel

Now the sentinel can start signing ed25519; every daemon already verifies it,
and HMAC is still accepted on both ends, so there is no window where a daemon
can't authenticate the sentinel.

```bash
# As root on the SENTINEL host.
umask 077
echo 'CONTAINARIUM_SENTINEL_SIGNING_KEY=<signing key from Step 0>' \
  | sudo tee -a /etc/containarium/env.secrets >/dev/null
sudo chmod 0600 /etc/containarium/env.secrets
sudo systemctl restart containarium-sentinel
```

Confirm the sentinel switched to ed25519 signing:

```bash
journalctl -u containarium-sentinel --since '-2min' | grep -i 'ed25519 signing key configured'
# want: "ed25519 signing key configured — outbound sentinel→daemon requests/responses are ed25519-signed"
```

---

## Step 3 — verify ed25519 is in use end-to-end

Keysync/certsync and peer discovery should be flowing with no auth errors:

```bash
# On a daemon host — no sentinel-auth failures in the last few minutes:
journalctl -u containarium --since '-5min' | grep -iE 'sentinel auth failed|sentinel-hmac|signature verify failed'
# want: nothing

# A fresh box's SSH proves the full sshpiper upstream path (keysync working):
ssh <tenant>@<sentinel-apex> -i ~/.containarium/keys/<tenant> hostname
```

At this point both schemes are accepted; ed25519 is what's actually being used.

---

## Step 4 — drop the shared secret from daemons (ed25519-only)

This is the step that **closes the escalation**: once a daemon no longer holds
`CONTAINARIUM_SENTINEL_AUTH_SECRET`, it has nothing that can forge a sentinel
request — it can only verify with the public key.

On **each** daemon host (BYOC hosts especially — that's the whole point):

```bash
# As root on each daemon host: remove the HMAC line, keep the public key.
sudo sed -i '/^CONTAINARIUM_SENTINEL_AUTH_SECRET=/d' /etc/containarium/env.secrets
sudo systemctl restart containarium
```

Verify the daemon is now ed25519-only and still authenticating:

```bash
journalctl -u containarium --since '-3min' | grep -iE 'sentinel auth failed|signature verify failed'
# want: nothing — ed25519 requests from the sentinel still verify
```

---

## Step 5 — (optional) drop the shared secret from the sentinel

Once every daemon is ed25519-only, the sentinel no longer needs the HMAC secret
to talk to them. Remove it for cleanliness (keep it only if some other
daemon-→sentinel path still relies on it — the PKI bootstrap does **not** use
this variable):

```bash
# As root on the SENTINEL host.
sudo sed -i '/^CONTAINARIUM_SENTINEL_AUTH_SECRET=/d' /etc/containarium/env.secrets
sudo systemctl restart containarium-sentinel
```

---

## Rollback

Because the daemons stayed dual-accept through Steps 1–3, rollback before Step 4
is trivial — the HMAC path was never removed:

- **Before Step 4:** unset `CONTAINARIUM_SENTINEL_SIGNING_KEY` on the sentinel
  and restart it. It reverts to HMAC signing; daemons still accept HMAC. (You
  can leave the public key on the daemons; it's inert without a signing
  sentinel.)
- **After Step 4 (daemons are ed25519-only):** to roll back you must re-add
  `CONTAINARIUM_SENTINEL_AUTH_SECRET` to the daemons **before** unsetting the
  sentinel's signing key — otherwise a daemon would accept neither scheme and
  keysync 401s. Re-add secret to daemons → restart daemons → unset signing key
  on sentinel → restart sentinel.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Daemon logs `sentinel auth failed` / keysync 401 right after Step 2 | A daemon didn't get the public key in Step 1 (skipped host, or not restarted). Re-do Step 1 on it. |
| `CONTAINARIUM_SENTINEL_PUBLIC_KEY is set but invalid` | The value is truncated or not the base64 from `keygen`. Re-copy the whole line. |
| Peer discovery `signature verify failed` | Sentinel signing key and daemon public key are from different `keygen` runs. Regenerate once and redistribute. |
| Tenant SSH `Permission denied` after migration | The frozen-sshpiper-map failure mode (#341) — a daemon's keysync is 401-ing. Check the daemon's journal for `sentinel auth failed`. |

Env changes never take effect without a **restart** — re-check that first.

## Relationship to the HMAC doc

[SENTINEL-AUTH-SECRET.md](./SENTINEL-AUTH-SECRET.md) remains the reference for the
legacy scheme and the `env.secrets` / drop-in plumbing. This runbook layers the
ed25519 keys on top of that same mechanism and then removes the shared secret.
