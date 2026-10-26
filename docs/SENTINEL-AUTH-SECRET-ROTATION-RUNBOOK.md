# Sentinel secrets — rotation and convergence runbook (#1365)

How to **rotate** or **converge** the two sentinel secret domains with the
least impact on tenants. It is not impact-free: a sentinel restart drops BYOC
tunnels and the sessions carried over them, and restarting the anonymous-box
door drops its sessions. This is the operator procedure; the background
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
   | daemon to sentinel | `/sentinel/primaries` (register + heartbeat), `/sentinel/keys/resync`, `/sentinel/ca`, `/sentinel/peer-cert`, `/sentinel/fetch-release` | 401; the primary registration TTL is 90s with a 30s heartbeat. A daemon deregisters on SIGTERM and its re-register is refused (401) until the first heartbeat that authenticates after the sentinel has the matching secret, so the registration is gone from the daemon stop until up to 30s after that, whatever the TTL |

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
   # (the glob must expand as root: /etc/containarium can be 0700)
   sudo sh -c "grep -l 'CONTAINARIUM_SENTINEL_' /etc/containarium/*.env /etc/containarium/env.secrets 2>/dev/null"

   # Effective value, as a short fingerprint only (never print the secret).
   # `sudo cat` reads as root; a `< /proc/$pid/environ` redirect would run as you.
   pid=$(systemctl show -p MainPID --value containarium-sentinel)   # or: containarium
   fp=$(sudo cat "/proc/$pid/environ" | tr '\0' '\n' \
     | sed -n 's/^CONTAINARIUM_SENTINEL_AUTH_SECRET=//p' \
     | tr -d '\n' | sha256sum | cut -c1-8)
   case "$fp" in
     e3b0c442) echo "FAIL: no process (MainPID=$pid) or no secret in its environment" ;;
     *) echo "$fp" ;;
   esac
   ```

   `e3b0c442` is the SHA-256 of the empty string: it means the read failed or
   the variable is not set, not that the hosts match. Run the fingerprint on
   every host. Hosts in one domain must print the same value, and none may print
   `FAIL`. Record fingerprints and lengths, not values.

3. **Snapshot the current pair** on every host, dated, root-only, before
   changing anything. This is your rollback source.

   ```bash
   # Run as root throughout: /etc/containarium can be 0700 (the documented
   # manual setup, and `pool join`), so an unprivileged glob or `[ -f ]` sees nothing.
   sudo sh -c '
     set -e
     install -d -m 0700 /root/sentinel-secret-backup
     n=0
     for f in /etc/containarium/env.secrets /etc/containarium/sentinel-auth.env; do
       if [ -f "$f" ]; then
         cp -p "$f" "/root/sentinel-secret-backup/$(basename "$f").$(date +%Y%m%d%H%M)"
         n=$((n + 1))
       fi
     done
     [ "$n" -gt 0 ] || { echo "FAIL: no secret file found to snapshot; stop here" >&2; exit 1; }
     ls -l /root/sentinel-secret-backup
   '
   ```

   Do not continue on a host where this prints `FAIL`: there is no rollback
   source. If Step 0.2 showed the value comes from a file not listed here,
   add it to the loop. The snapshot holds secrets: delete the directory once
   the rotation is verified and the rollback window has closed (see Rollback).

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

## Setting a secret without putting it on a command line

Never put a secret in `sed -i 's|...=<secret>|...'`, `VAR=<secret> command`, or
any other argument or inline assignment: it lands in `ps`, shell history and
sudo's `COMMAND=` syslog line. Use this flow instead. The value goes in through
the terminal or a pipe, and the script below contains only a variable *name*.
The value must be hex or base64 (`openssl rand -hex 32`): systemd's
`EnvironmentFile` parsing mangles quotes, backslashes and trailing spaces, so
anything else would not be read back as written.

Save this as `set-secret.sh` on each host (it holds no secret) and run it as
root:

```sh
set -e
VAR=CONTAINARIUM_SENTINEL_AUTH_SECRET          # or CONTAINARIUM_SENTINEL_ADMIN_SECRET
f=/etc/containarium/env.secrets                # the file Step 0.2 showed is effective
IFS= read -r v                                 # the value arrives on stdin
tmp=$(mktemp -p /etc/containarium)
chown --reference="$f" "$tmp"; chmod --reference="$f" "$tmp"
{ grep -v "^$VAR=" "$f" || true; printf '%s=%s\n' "$VAR" "$v"; } > "$tmp"
mv "$tmp" "$f"
```

Run it with the value on stdin:

```bash
read -rs -p 'new secret: ' NEW_SECRET; echo      # `read` is a shell builtin: not in ps or history
printf '%s\n' "$NEW_SECRET" | sudo sh set-secret.sh   # `printf` is a builtin too
unset NEW_SECRET
```

If the host also loads `/etc/containarium/sentinel-auth.env` (Step 0.2), run it
again with `f=` set to that file.

**Converging.** The value to carry is the source domain's, and it exists only in
a file on a source host. Pipe it host to host rather than copying it through a
terminal or a file on your workstation:

```bash
ssh <source-host> "sudo sed -n 's/^CONTAINARIUM_SENTINEL_AUTH_SECRET=//p' /etc/containarium/env.secrets" \
  | ssh <target-host> "sudo sh /path/to/set-secret.sh"
```

The secret travels on stdin, never in an argument. Because stdin carries it,
sudo cannot prompt for a password on either host (the prompt would read the
secret): both need passwordless sudo, which Step 0 of the provisioning docs
already requires for these hosts.

## Procedure 1 — ADMIN secret (no mismatch window on the platform)

1. Identify every holder of the ADMIN secret **besides the sentinel**: the join
   token issuer or cloud control plane, any operator workstation that runs
   `containarium sentinel register-token`, `deregister-token`, `pprof`, and
   anything that drives `/peer/<backend>/...` through the sentinel. These are
   the only things that can break.
2. On the sentinel, set the new `CONTAINARIUM_SENTINEL_ADMIN_SECRET` in the file
   that Step 0.2 showed is effective, using the flow in "Setting a secret
   without putting it on a command line". If the sentinel also loads a second
   file that sets it, set that too, so they cannot disagree.
3. Restart: `sudo systemctl restart containarium-sentinel`. The sentinel unit is
   `Restart=always` and comes straight back (the time to settle was not measured
   by the author). BYOC tunnels reconnect on their own, and runtime-registered tunnel tokens and
   BYOC route bindings are persisted and survive the restart.
4. Update every holder from step 1 to the new value. Until each is updated, its
   calls get 401; nothing else is affected.
5. Verify with a read-only call using the new secret:

   ```bash
   read -rs -p 'ADMIN secret to test: ' CONTAINARIUM_SENTINEL_ADMIN_SECRET; echo
   export CONTAINARIUM_SENTINEL_ADMIN_SECRET
   containarium sentinel pprof --url http://<sentinel-host>:8888 --list
   unset CONTAINARIUM_SENTINEL_ADMIN_SECRET
   ```

   and confirm the old value is now refused (repeat with the old secret: 401).
   The `read` keeps the value out of shell history.
6. Update `sentinel_admin_secret` in Terraform (fact 8).

Rollback: restore the Step 0.3 snapshot on the sentinel and restart it; revert
the holders.

## Procedure A — AUTH secret via the ed25519 bridge (no sentinel-to-daemon window)

Use when every daemon in the domain can run v0.45.0 or later. While the
sentinel signs with ed25519 and every daemon holds the public key, changing the
AUTH secret does not interrupt sentinel→daemon requests. Daemon→sentinel
requests still use HMAC, however, so the secret must match again before a
daemon starts and performs primary registration or peer PKI bootstrap.

Prerequisite: complete steps 0 to 3 of the ed25519 runbook and keep the shared
AUTH secret on both the sentinel and every daemon (as its steps 4 and 5 now
require). That means: public key on every daemon and restarted, signing key on
the sentinel and restarted, and the `ed25519 signing key configured` /
`ed25519 public key configured` log lines seen on each. Customer-operated
daemons need the public key too; it is safe to send (it cannot forge).

1. Confirm the bridge is live **in the running processes**, not in a log line
   from an earlier boot: a Terraform-driven reboot rewrites `env.secrets` and
   drops hand-appended ed25519 lines (fact 8), after which step 2 would quietly
   be Procedure B. On the sentinel and on every daemon check the effective
   environment:

   ```bash
   pid=$(systemctl show -p MainPID --value containarium-sentinel)   # or: containarium
   sudo cat "/proc/$pid/environ" | tr '\0' '\n' \
     | grep -c -E '^CONTAINARIUM_SENTINEL_(SIGNING|PUBLIC)_KEY='    # sentinel: SIGNING; daemon: PUBLIC; want 1
   ```

   and confirm the log line (`ed25519 signing key configured` on the sentinel,
   `Sentinel ed25519 public key configured` on a daemon) is newer than the
   process start (`systemctl show -p ActiveEnterTimestamp <unit>`). Any host
   that fails this is not on the bridge: use Procedure B for it.
2. Stage the new AUTH secret in the effective secret file (Step 0.2) on the
   sentinel and every daemon, using "Setting a secret without putting it on a
   command line" (it leaves the ed25519 key lines in place). Do not restart any
   host until all files are staged.
3. Restart the sentinel first:

   ```bash
   sudo systemctl restart containarium-sentinel
   ```

   Sentinel→daemon requests continue over ed25519. Until each daemon restarts,
   its daemon→sentinel HMAC requests use the old value and are rejected. The
   sentinel's primary registry is in memory and starts empty after its restart;
   each daemon repopulates it when its startup registration succeeds.
4. Restart each daemon after the sentinel is back:

   ```bash
   sudo systemctl restart containarium
   ```

   On startup, the daemon performs primary registration before calling
   `PeerPool.BootstrapPKI` (`internal/server/dual_server.go`). With the new
   secret already active on the sentinel, registration and the HMAC-signed
   `POST /sentinel/peer-cert` succeed. Keep the rollout in one maintenance
   window and verify both registration and `[peer-pki] bootstrap complete` on
   every daemon.
5. Verify (below).

Caveats from the code:

- Do **not** remove the shared AUTH secret from either side by following the
  ed25519 runbook's steps 4 or 5. This migration changes only
  sentinel→daemon authentication; daemon registration and peer PKI bootstrap
  still require the matching HMAC secret on both sides.
- The anonymous-box door (`sshpiper-anon.service`, installed only when the
  sentinel has an `anon_door_addr`; check with `systemctl cat sshpiper-anon`)
  is `PartOf=` and `BindsTo=` the sentinel unit
  (`terraform/modules/containarium/scripts/sshpiper-anon.service.tmpl`), so the
  sentinel restart in step 3 restarts it too and it re-reads
  `/etc/containarium/env.secrets`. Nothing extra to run, but the restart drops
  established door sessions, so keep it inside the maintenance window. Under
  this procedure the door keeps working throughout, because it signs with the
  same ed25519 key as the sentinel.

## Procedure B — AUTH secret, direct (short window)

Everything is prepared first; the mismatch lasts from the first restart to the
last, so do all hosts of the domain **in one sitting** with the commands ready.

1. Complete Step 0 on every host. Have the new value in a file or secrets
   manager entry on the workstation you will paste from.
2. **Stage, do not restart.** On every daemon and the sentinel, write the new
   value into the effective file with "Setting a secret without putting it on a
   command line" (no restart yet, so nothing changes; if the host also loads
   `/etc/containarium/sentinel-auth.env`, apply it there too).

   Re-run the Step 0.2 file listing to confirm only the files you meant to
   change contain the new value and nothing later in the `EnvironmentFile=` order
   overrides it.
3. **Restart the sentinel first, then the daemons**, back to back. This is the
   opposite of the ordinary restart order in
   [SENTINEL-AUTH-SECRET.md](./SENTINEL-AUTH-SECRET.md#restart-order), on purpose
   for a *secret change*: at startup each daemon posts to `/sentinel/peer-cert`
   with its secret once (`PeerPool.BootstrapPKI`,
   `internal/server/dual_server.go`, `internal/server/peer.go`). A daemon that
   starts with the new secret while the sentinel still has the old one gets 401,
   logs `[peer-pki] bootstrap failed`, is never retried, and stays on plain-HTTP
   peer-to-peer until its next restart.

   ```bash
   sudo systemctl restart containarium-sentinel   # sentinel, first (also restarts sshpiper-anon, if installed)
   sudo systemctl restart containarium            # then each daemon host: primary, peers, BYOC
   ```

   The anonymous-box door follows the sentinel restart on its own (it is
   `PartOf=` the sentinel unit) and drops its established sessions when it does.

   The window is the time between the sentinel restart and the last daemon
   restart. Start the daemon restarts as soon as the sentinel is back, not after
   a verification pause. If a daemon was restarted before the sentinel by
   mistake, restart that daemon again once the sentinel has the new secret.
4. Verify (below) immediately, including `[peer-pki] bootstrap complete` on every
   daemon.

If a customer-operated host cannot restart in the same sitting, it will 401
until it does. That is the reason to prefer Procedure A for any domain that
contains such a host.

## Verify (after A or B)

- Sentinel status: `curl -s http://<sentinel-host>:8888/status | grep -o '"sentinel_auth_misconfigured":[a-z]*'` is `false`. This only proves the sentinel *has* a usable secret, not that it matches the daemons, so also check the next items.
- Primary auth health: `curl -s http://<sentinel-host>:8888/status | jq '.primary_auth_counts, .unattributed_auth_failures'` gives a count of primaries per state (`ok`, `failing_401`, `unknown`) and never a pool name, because `/status` is unauthenticated. Which primary is failing is on `GET /sentinel/primary-auth-health`, which needs a request signed with the sentinel **ADMIN secret** (`CONTAINARIUM_SENTINEL_ADMIN_SECRET`, the sentinel's `adminSecret`), **not** the daemon AUTH secret; an unsigned, wrongly signed (the AUTH secret included) or stale (more than 5 minutes off) request gets 401, and only GET is served. Daemons do not hold the ADMIN secret, so a compromised daemon cannot read the pool inventory. No containarium command signs requests, so sign by hand with `openssl`, using the same scheme as `auth.SignSentinelRequest`: the signature is the hex HMAC-SHA256 of `METHOD\nPATH\nTIMESTAMP` under the secret, sent in `X-Containarium-Sentinel-Ts` and `X-Containarium-Sentinel-Sig`. Read the ADMIN secret as in the rotation steps above (without echoing it) into `ADMIN_SECRET`, then: `ts=$(date +%s); sig=$(printf 'GET\n/sentinel/primary-auth-health\n%s' "$ts" | openssl dgst -sha256 -hmac "$ADMIN_SECRET" -r | cut -d' ' -f1); curl -s -H "X-Containarium-Sentinel-Ts: $ts" -H "X-Containarium-Sentinel-Sig: $sig" http://<sentinel-host>:8888/sentinel/primary-auth-health | jq .`. A refused read of this route is not counted as any primary's 401. `failing_401` means a request from that primary's address (registration, heartbeat, peer-cert, key resync) failed the signature check since its last authenticated registration or heartbeat. **That can be a false alarm.** The sentinel attributes a 401 by source address alone, and a bad-signature request needs no secret: a scanner, or any other client on the same host or NAT as the primary, sends one. One such request per 30 s heartbeat keeps `failing_401` set. So `failing_401` is a prompt to look, not proof of a wrong secret: **confirm in the sentinel logs that the 401s are the primary's own heartbeats or registrations before you rotate or change a secret.** `unknown` is a live registered primary the sentinel has no auth record for (for example after a sentinel restart, until its next authenticated request); it is not a failure. Only primaries that register over HTTP (`/sentinel/primaries`) are counted; a primary promoted by a tunnel handshake never is, even with the right secret, so check those by their logs. The record is in memory, so after a sentinel restart a primary counts as `ok` only once its registration or heartbeat has authenticated again. A pool that deregistered keeps its record, so it stays in the counts (as `ok`, or `failing_401` if it 401ed since) until 24 hours after it was last heard from. A rising `unattributed_auth_failures` means 401s that could not be tied to one primary. These fields carry no secret-derived data (#2892, #3004).
- Window closed: within one keysync interval (2m) the sentinel logs, for every backend:

  ```bash
  journalctl -u containarium-sentinel -f | grep 'keysync\] sync OK for'
  ```

  with the same user count as the baseline. A `rejected the signed /authorized-keys request with 401` line (the keysync message that names the secret mismatch) means that backend still disagrees.
- Daemons quiet: `journalctl -u containarium --since '-5min' | grep -iE 'sentinel-hmac|sentinel auth failed|signature verify failed|\[primary-register\].*failed|\[peer-pki\] bootstrap failed'` prints nothing. The last two cover the daemon-to-sentinel direction.
- Peer PKI came up on every daemon: `journalctl -u containarium -b | grep '\[peer-pki\] bootstrap complete'` prints a line newer than the daemon's restart. A daemon without it is on plain-HTTP peer calls until restarted again.
- Only if the sentinel has an anonymous-box door (`systemctl cat sshpiper-anon`
  succeeds): it restarted with the sentinel
  (`systemctl show -p ActiveEnterTimestamp sshpiper-anon` is newer than the
  secret change) and `ssh new.<domain>` logs in.
- Fingerprints (Step 0.2) are now identical on the sentinel and every daemon of the domain, and equal to the intended value.
- An existing tenant can still SSH in, and a freshly created box gets a pipe on the next sync.
- Update the Terraform variables (`sentinel_auth_secret`, and `sentinel_admin_secret` if you rotated it) so a reboot does not revert the host (fact 8).

## Rollback

1. **Restore the Terraform source value first.** Set the deployment's
   `sentinel_auth_secret` input back to the Step 0.3 value on every Terraform-
   managed part of the domain, then run `terraform apply` so the instance
   metadata and rendered startup scripts carry the rollback value. In this
   repo, the module variable is declared in
   `terraform/modules/containarium/variables.tf` and passed into the daemon and
   sentinel startup scripts; the `terraform/gce-demo` consumer declares and
   forwards its input through `variables.tf` and `main.tf`. Update the
   deployment's actual Terraform input source (for example, its tfvars or
   automation variable), not the variable declaration. If ADMIN is also being
   rolled back, restore its `sentinel_admin_secret` input separately.
2. **Restore the effective host files.** Restore the Step 0.3 snapshot on every
   host of the domain, then restart in the same order as the forward procedure
   (sentinel, then daemons, for either procedure; the door follows the sentinel).
   Restore as root, picking the snapshot stamp you took in Step 0.3:

   ```bash
   sudo sh -c '
     set -e
     stamp=<YYYYMMDDHHMM>
     n=0
     for f in env.secrets sentinel-auth.env; do
       b="/root/sentinel-secret-backup/$f.$stamp"
       if [ -f "$b" ]; then cp -p "$b" "/etc/containarium/$f"; n=$((n + 1)); fi
     done
     [ "$n" -gt 0 ] || { echo "FAIL: no snapshot with stamp $stamp; nothing restored" >&2; exit 1; }
     ls -l /etc/containarium/env.secrets /etc/containarium/sentinel-auth.env 2>/dev/null || true
   '
   ```

   Confirm the Step 0.2 fingerprint on the restored host matches the value you
   recorded before the rotation.

   The Terraform startup scripts write `sentinel_auth_secret` into
   `/etc/containarium/env.secrets` when they run. A Terraform apply updates the
   instance metadata/startup-script input, but the repo has no live reconcile
   for this secret; a host-only rollback can therefore be overwritten the next
   time that host's startup script runs. The spot startup script runs on every
   boot; the sentinel and regular-instance scripts also write the templated
   value when executed.

The mismatch window rules are identical in reverse, so complete the rollback
in one maintenance window. Roll back ADMIN independently of AUTH.

**Clean up.** Once the rotation (or rollback) is verified and you will not need
the old value again, delete the snapshots on every host:
`sudo rm -rf /root/sentinel-secret-backup`. They hold the previous secret.

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
2. **The ed25519 migration does not retire the AUTH secret.** Its Step 4
   ("keep the shared secret on every daemon") exists for this reason, and
   following the runbook without it breaks registration and PKI on daemons
   (`internal/server/primary_register.go`, `internal/server/peer.go`). Its public-key
   verification covers sentinel→daemon requests only. Daemon→sentinel primary
   registration remains HMAC-signed (`internal/server/primary_register.go`),
   and peer PKI bootstrap requires the secret and signs
   `POST /sentinel/peer-cert` (`internal/server/peer_pki.go`); the sentinel
   gates that route with the same secret (`internal/sentinel/binaryserver.go`).
   Keep the secret configured on both sides until daemon→sentinel
   authentication has a separate replacement.
3. **Terraform startup scripts overwrite `env.secrets`** (fact 8), including hand-appended
   ed25519 key lines.
4. **The sentinel's `/status` flag reports only "secret present and long enough"**,
   not "matches the daemons". For the daemon-to-sentinel direction, `/status`
   also counts primaries per auth state, and the per-pool detail is on an
   ADMIN-secret-gated route (#2892, #3004; see Verify). The sentinel-to-daemon
   direction is still visible only in keysync logs.
5. **Commands not run by the author.** This runbook was written from the code;
   it was not executed against a live fleet. Execution on live and
   customer-operated hosts is an operator task.
