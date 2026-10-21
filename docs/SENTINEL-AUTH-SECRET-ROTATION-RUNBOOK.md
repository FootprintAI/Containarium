# Sentinel secrets — rotation and convergence runbook (#1365)

How to **rotate** or **converge** the two sentinel secret domains without
tenant-visible impact. This is the operator procedure; the background
(what the secrets are, how they are provisioned) is in
[SENTINEL-AUTH-SECRET.md](./SENTINEL-AUTH-SECRET.md), and the asymmetric
successor is in [SENTINEL-ED25519-MIGRATION-RUNBOOK.md](./SENTINEL-ED25519-MIGRATION-RUNBOOK.md).

All hosts, IPs and secret values below are placeholders. Never paste a real
secret into a ticket, chat, or shell history you do not control.

## Scope and vocabulary

| Term | Meaning |
| --- | --- |
| **AUTH secret** | `CONTAINARIUM_SENTINEL_AUTH_SECRET`. Shared by one sentinel and every daemon in its **domain** |
| **ADMIN secret** | `CONTAINARIUM_SENTINEL_ADMIN_SECRET`. Held by the sentinel and by whoever issues join tokens / drives `/peer/`; deliberately **not** on every daemon |
| **Domain** | One sentinel plus every daemon (primary, peers, BYOC) that talks to it. A fleet can end up with more than one domain, each with its own pair of secrets ("drift") |
| **Source domain / target domain** | When converging, the domain whose value you keep / the one you re-key onto it |

Both secrets must be at least 32 bytes (`auth.SentinelMinSecretLen`). Any
encoding is accepted by the code; the documented form is `openssl rand -hex 32`
(64 hex chars). Two domains with different lengths are simply two different
generations, not a re-encoding of the same value.

**Which domain to converge onto which** is a judgement the code cannot make for
you. Rule of thumb: re-key the domain with **fewer hosts and no customer-operated
hosts** onto the other, so no credential change has to be coordinated with people
outside your team. Count the hosts in each domain first (Step 0).

## What the code does today (read this before choosing a procedure)

Everything below was read from the tree, not assumed:

1. **Secrets are read once, at process start.** The sentinel reads both in
   `NewManager`; the sentinel signing path caches the AUTH secret on first use
   (`sync.Once`); the daemon caches it at startup and on first use in peer
   discovery. **Every change needs a restart. There is no hot reload.**
2. **Only one value of each secret is accepted at a time.**
   `auth.SentinelHMACMiddleware(secret, next)` and `VerifySentinelRequest`
   take a single secret; there is no "previous secret" setting. So a plain
   rotation always has a mismatch window between the two restarts.
3. **The AUTH secret gates more than keysync/certsync.**

   | Direction | Endpoints | Failure while secrets differ |
   | --- | --- | --- |
   | sentinel to daemon | `/authorized-keys`, `/authorized-keys/sentinel`, `/certs` (keysync every 2m, certsync every 6h) | 401; sshpiper config stops being refreshed |
   | sentinel to daemon | signed `/sentinel/peers` response | daemon logs `signature verify failed; refusing to update peer map`; keeps its existing map |
   | daemon to sentinel | `/sentinel/primaries` (register + heartbeat), `/sentinel/keys/resync`, `/sentinel/ca`, `/sentinel/peer-cert`, `/sentinel/fetch-release` | 401; the primary registration TTL is 90s with a 30s heartbeat, so a window longer than about 90s lets the registration lapse until the next successful heartbeat |

4. **Established tenant SSH keeps working during a window.** sshpiper serves
   from the config already on disk. What degrades is *new* state: a box created
   in the window gets no SSH pipe until the next successful keysync, and a key
   change is not propagated. The damage in the #341 incident came from a window
   that lasted hours and went unnoticed, not from the cutover. Keep the window
   under one keysync interval (2m) and watch for it to close.
5. **The daemon verifier is dual-accept for ed25519 and HMAC**
   (`auth.NewSentinelVerifier`). A sentinel that signs with ed25519 is accepted
   by a daemon that holds the matching public key **regardless of which HMAC
   secret the daemon holds**. This is what makes Procedure A possible. It does
   **not** cover the daemon-to-sentinel direction in row 3, which is HMAC-only
   on the sentinel side.
6. **The ADMIN secret is on-demand only.** Nothing polls it. It gates
   `/sentinel/tunnel-tokens`, `/sentinel/audit-ingest-tokens`,
   `/sentinel/byoc-routes`, `/sentinel/fail2ban/*`, `/sentinel/ssh-bans/`,
   `/peer/` (control path to tunnel-joined backends) and the pprof endpoints.
   Daemons do not hold it, so rotating it never touches a daemon.
7. **Where the value lives.**
   - Terraform-provisioned hosts: `/etc/containarium/env.secrets`, loaded by an
     `EnvironmentFile=-/etc/containarium/env.secrets` drop-in on the
     `containarium` (daemon) and `containarium-sentinel` units.
   - Hosts joined with `containarium pool join --sentinel-auth-secret ...`:
     `/etc/containarium/sentinel-auth.env`, referenced from the pool drop-in.
     `pool join` keeps an existing file and does not rewrite it on a re-join
     unless you pass the flag again, so **rotation on a joined host is an edit
     of that file, not a re-run of `pool join`**.
   - A host can have both files, and with several `EnvironmentFile=` lines the
     **later one wins**. This is how a stale value can stay live while the file
     you edited looks right (#1364). Always confirm the effective value
     (Step 0), never infer it from one file.
8. **Terraform rewrites `env.secrets` at boot.**
   `startup-sentinel.sh` truncates and rewrites it from the
   `sentinel_auth_secret` / `sentinel_admin_secret` module variables
   (`startup.sh` and `startup-spot.sh` do the same on daemon hosts). A rotation
   done only on the host is **silently reverted by the next reboot or VM
   re-creation**. Update the Terraform variables in the same change. The same
   rewrite also drops any `CONTAINARIUM_SENTINEL_SIGNING_KEY` /
   `CONTAINARIUM_SENTINEL_PUBLIC_KEY` lines that were appended by hand per the
   ed25519 runbook, so those need to be carried by whatever feeds the host's
   secrets file too (see "Gaps found").

## Choosing a procedure

| Situation | Use |
| --- | --- |
| Rotate or converge **ADMIN** | Procedure 1 (no daemon involved) |
| Rotate or converge **AUTH**, all daemons on v0.45.0+ and ed25519 acceptable | Procedure A: bridge with ed25519, no sentinel-to-daemon window |
| Rotate or converge **AUTH**, otherwise | Procedure B: direct, short window, both ends in one sitting |
| Any host in the domain is customer-operated | The customer must perform the daemon-side steps in their own maintenance window. Plan the whole rotation around that, or leave that domain alone until Procedure A is in place |

Do **ADMIN first, AUTH second**: ADMIN has no window, so it is the cheap
rehearsal of the file and restart mechanics.

## Step 0 — inventory and safety net (both procedures)

Do this on the sentinel and **every** daemon in the target domain.

1. **List the domain.** The sentinel's journal names every backend it syncs:

   ```bash
   journalctl -u containarium-sentinel --since '-10min' | grep -E 'keysync\] sync (OK|failed) for'
   ```

   Write down each `<host>` and whether you operate it.

2. **Find which files the unit actually loads, and the effective value.**

   ```bash
   # Which EnvironmentFile= entries (later wins)
   systemctl show -p EnvironmentFiles containarium-sentinel   # or: containarium
   sudo grep -l 'CONTAINARIUM_SENTINEL_' /etc/containarium/*.env /etc/containarium/env.secrets 2>/dev/null

   # Effective value, as a short fingerprint only (never print the secret)
   pid=$(systemctl show -p MainPID --value containarium-sentinel)   # or: containarium
   sudo tr '\0' '\n' < /proc/$pid/environ \
     | sed -n 's/^CONTAINARIUM_SENTINEL_AUTH_SECRET=//p' \
     | tr -d '\n' | sha256sum | cut -c1-8
   ```

   Run the fingerprint on every host. Hosts in one domain must print the same
   value. Record fingerprints and lengths, not values.

3. **Snapshot the current pair** on every host, dated, root-only, before
   changing anything. This is your rollback source.

   ```bash
   sudo install -d -m 0700 /root/sentinel-secret-backup
   for f in /etc/containarium/env.secrets /etc/containarium/sentinel-auth.env; do
     [ -f "$f" ] && sudo cp -p "$f" "/root/sentinel-secret-backup/$(basename "$f").$(date +%Y%m%d%H%M)"
   done
   ```

   Do not rely on a pre-existing `*.bak` in `/etc/containarium/`: such a file
   may hold the *target* value, not the current one.

4. **Baseline health** (must be clean before you start):

   ```bash
   curl -s http://<sentinel-host>:8888/status | grep -o '"sentinel_auth_misconfigured":[a-z]*'   # want false
   journalctl -u containarium-sentinel --since '-6min' | grep -c 'keysync\] sync OK'               # at least one per backend
   ```

   Note the user count in the latest `sync OK for <backend>: N users` line to
   compare against afterwards. (Port 8888 is the sentinel binary port,
   `--binary-port`.)

5. **Generate the new value once**, on a trusted workstation, and keep it in your
   secrets manager (`openssl rand -hex 32`). When converging, the "new value" is
   the source domain's existing value, which you read from its host file; do not
   mint a new one.

## Procedure 1 — ADMIN secret (no mismatch window on the platform)

1. Identify every holder of the ADMIN secret **besides the sentinel**: the join
   token issuer or cloud control plane, any operator workstation that runs
   `containarium sentinel register-token`, `deregister-token`, `pprof`, and
   anything that drives `/peer/<backend>/...` through the sentinel. These are
   the only things that can break.
2. On the sentinel, set the new `CONTAINARIUM_SENTINEL_ADMIN_SECRET` in the file
   that Step 0.2 showed is effective (mirror it into the other file if both
   exist, so they cannot disagree).
3. Restart: `sudo systemctl restart containarium-sentinel`. The sentinel unit is
   `Restart=always` and comes straight back (the time to settle was not measured
   by the author). BYOC tunnels reconnect on their own, and runtime-registered tunnel tokens and
   BYOC route bindings are persisted and survive the restart.
4. Update every holder from step 1 to the new value. Until each is updated, its
   calls get 401; nothing else is affected.
5. Verify with a read-only call using the new secret:

   ```bash
   CONTAINARIUM_SENTINEL_ADMIN_SECRET=<new> \
     containarium sentinel pprof --url http://<sentinel-host>:8888 --list
   ```

   and confirm the old value is now refused (same command with the old secret
   returns 401).
6. Update `sentinel_admin_secret` in Terraform (fact 8).

Rollback: restore the Step 0.3 snapshot on the sentinel and restart it; revert
the holders.

## Procedure A — AUTH secret via the ed25519 bridge (no sentinel-to-daemon window)

Use when every daemon in the domain can run v0.45.0 or later. The idea: while
the sentinel signs with ed25519 and every daemon holds the public key, the HMAC
secret is not used on the sentinel-to-daemon path, so it can be changed on each
side independently in any order.

Prerequisite: complete steps 0 to 3 of the ed25519 runbook **and leave the
daemons dual-accept** (do **not** run its step 4). That means: public key on
every daemon and restarted, signing key on the sentinel and restarted, and the
`ed25519 signing key configured` / `ed25519 public key configured` log lines
seen on each. Customer-operated daemons need the public key too; it is safe to
send (it cannot forge).

1. Confirm the bridge is live: keysync is succeeding and the sentinel logged
   `ed25519 signing key configured`.
2. On each daemon, set the new AUTH secret in the effective file (Step 0.2) and
   `sudo systemctl restart containarium`. Sentinel-to-daemon keysync/certsync/peers
   keep verifying through ed25519, so no 401s there.
3. On the sentinel, set the same value and `sudo systemctl restart containarium-sentinel`.
4. The **daemon-to-sentinel** HMAC calls (table row 3) still mismatch between
   step 2 and step 3 for each daemon. They retry on their own heartbeat/resync
   cadence. Keep the gap between a daemon restart and the sentinel restart
   under 90 seconds so primary registrations do not lapse, or accept a brief
   lapse that heals at the next heartbeat.
5. Verify (below).

Caveats from the code:

- Do **not** apply the ed25519 runbook's step 5 ("drop the shared secret from
  the sentinel") while any daemon-to-sentinel path in table row 3 is in use:
  those endpoints are still gated by the HMAC secret on the sentinel. See
  "Gaps found".
- The anonymous-box door plugin on the sentinel signs through the same
  `SignRequest` path and reads the same environment, so it follows the sentinel
  restart with no extra step.

## Procedure B — AUTH secret, direct (short window)

Everything is prepared first; the mismatch lasts from the first restart to the
last, so do all hosts of the domain **in one sitting** with the commands ready.

1. Complete Step 0 on every host. Have the new value in a file or secrets
   manager entry on the workstation you will paste from.
2. **Stage, do not restart.** On every daemon and the sentinel, write the new
   value into the effective file, in a way that is easy to review before the
   restart (no restart yet, so nothing changes):

   ```bash
   # As root. Replace the line in place; keep mode 0600.
   sudo sed -i 's|^CONTAINARIUM_SENTINEL_AUTH_SECRET=.*|CONTAINARIUM_SENTINEL_AUTH_SECRET=<new-secret>|' /etc/containarium/env.secrets
   sudo chmod 0600 /etc/containarium/env.secrets
   # If the host also has /etc/containarium/sentinel-auth.env, apply the same edit there.
   ```

   Re-run the Step 0.2 file listing to confirm only the files you meant to
   change contain the new value and nothing later in the `EnvironmentFile=` order
   overrides it.
3. **Restart daemons, then the sentinel**, back to back (the order from
   [SENTINEL-AUTH-SECRET.md](./SENTINEL-AUTH-SECRET.md#restart-order)):

   ```bash
   sudo systemctl restart containarium            # each daemon host: primary, peers, BYOC
   sudo systemctl restart containarium-sentinel   # sentinel, last
   ```

   The window is the time between the first daemon restart and the sentinel
   restart. With several daemons, start the sentinel restart as soon as the
   last daemon is back, not after a verification pause.
4. Verify (below) immediately.

If a customer-operated host cannot restart in the same sitting, it will 401
until it does. That is the reason to prefer Procedure A for any domain that
contains such a host.

## Verify (after A or B)

- Sentinel status: `curl -s http://<sentinel-host>:8888/status | grep -o '"sentinel_auth_misconfigured":[a-z]*'` is `false`. This only proves the sentinel *has* a usable secret, not that it matches the daemons, so also check the next items.
- Window closed: within one keysync interval (2m) the sentinel logs, for every backend:

  ```bash
  journalctl -u containarium-sentinel -f | grep 'keysync\] sync OK for'
  ```

  with the same user count as the baseline. A `rejected the signed /authorized-keys request with 401` line (the keysync message that names the secret mismatch) means that backend still disagrees.
- Daemons quiet: `journalctl -u containarium --since '-5min' | grep -iE 'sentinel-hmac|sentinel auth failed|signature verify failed'` prints nothing.
- Fingerprints (Step 0.2) are now identical on the sentinel and every daemon of the domain, and equal to the intended value.
- An existing tenant can still SSH in, and a freshly created box gets a pipe on the next sync.
- Update the Terraform variables (`sentinel_auth_secret`, and `sentinel_admin_secret` if you rotated it) so a reboot does not revert the host (fact 8).

## Rollback

Restore the Step 0.3 snapshot on **every** host of the domain and restart in the
same order as the forward procedure (daemons, then sentinel; or per Procedure A).
The mismatch window rules are identical in reverse, so the rollback needs the same
"all hosts in one sitting" discipline. Roll back ADMIN independently of AUTH.

## Converging two domains (summary)

Converging is rotation where the "new value" is the source domain's existing
value. For the target domain's hosts only: Step 0, then Procedure 1 for ADMIN,
then Procedure A or B for AUTH, using the source domain's secrets as the new
values. Run Step 0.2 fingerprints across **both** domains at the end and expect
one fingerprint per secret. The source domain is not touched.

Note that a converged fleet shares one blast radius: every daemon in it can
forge for every other (the reason the ed25519 scheme exists). Prefer finishing
the ed25519 migration over spending effort to widen a shared symmetric secret.

## Gaps found while writing this runbook

None of these block the procedures above. They are for follow-up issues, not
fixed here.

1. **No previous-secret acceptance.** A true zero-downtime HMAC rotation would
   need `SentinelHMACMiddleware` to accept an optional previous secret. Procedure
   A reaches the same result for the sentinel-to-daemon direction using what
   already ships, but not for the daemon-to-sentinel direction.
2. **ed25519 runbook says the PKI bootstrap does not use the AUTH secret.** The
   code disagrees: `/sentinel/ca` and `/sentinel/peer-cert` are registered behind
   `SentinelHMACMiddleware(manager.hmacSecret, ...)` and `FetchPeerPKI` requires
   the secret. Its Step 5 should be read with that in mind.
3. **Terraform startup scripts overwrite `env.secrets`** (fact 8), including hand-appended
   ed25519 key lines.
4. **The sentinel's `/status` flag reports only "secret present and long enough"**,
   not "matches the daemons"; mismatch is visible only in keysync logs.
5. **Commands not run by the author.** This runbook was written from the code;
   it was not executed against a live fleet. Execution on live and
   customer-operated hosts is an operator task.
