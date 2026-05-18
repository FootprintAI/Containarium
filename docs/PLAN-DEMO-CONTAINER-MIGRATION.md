# Plan: demo container migration (Phase 4)

**Status**: Draft plan, not yet executed.
**Depends on**: [CUTOVER-DEMO-INTO-PROD-SENTINEL.md](CUTOVER-DEMO-INTO-PROD-SENTINEL.md) completed (demo VM joined prod sentinel as `pool=demo`). The recommended path (B2) additionally needs [#207](https://github.com/FootprintAI/Containarium/pull/207) merged for multi-base-domain primary registration.
**Mechanism**: existing `MoveContainer` RPC + [`move_container` MCP tool](../internal/mcp/tools.go) — see `internal/server/move_container.go` for the three-phase orchestration. This plan is about *when* to use it, *what it doesn't cover*, and *how to fill those gaps*.

---

## Pick a path first

The recommendation order is **B2 → A → B1**. Read the option you pick; the others are stubs.

| Path | What you do | New VM needed? | When it's right |
|---|---|---|---|
| **A — Keep demo VM, share sentinel** | No container migration. Demo VM stays in `footprintai-dev` as the `pool=demo` backend; only the routing layer (Phase 2 cutover) is shared. Phase 4 collapses to a 4-command smoke test. | No | The ~$30/mo demo VM cost isn't bothering you, or you want the demo cluster to stay physically isolated from anything in `footprintai-prod`. |
| **B1 — New GCP VM in `footprintai-prod`** | Provision a new spot VM via `terraform/modules/containarium/`, tag it `pool=demo --public-base-domain=demo.containarium.dev`, migrate every demo container onto it, destroy the demo VM. | Yes — new Terraform | You want a clean GCP-resident answer (same VPC, easy `incus remote add` over the internal network) and have budget for one more VM. Goes against the earlier "don't touch Terraform" preference. |
| **B2 — Host demo on the lab backend (Recommended)** | The lab backend re-registers with `--public-base-domain=lab.kafeido.app --public-base-domain=demo.containarium.dev`. Demo containers migrate onto the lab hardware. No new VM, no new Terraform. Lab and demo share blast radius — accept that or pick B1. | No (uses existing lab hardware) | You want to retire the demo VM without provisioning anything. The lab box has spare capacity. The demo workloads aren't so production-critical that they need physical isolation from lab. |

The rest of this doc is structured around **Path B2**. Path A is the short "verify-only" section at the bottom. Path B1 substitutes the lab backend for "the new GCP VM" but is otherwise identical to B2 — read B2, mentally swap the target.

---

## What `MoveContainer` does for you

From [`internal/server/move_container.go`](../internal/server/move_container.go) (the source of truth):

- **Pre-copy snapshot + delta refresh.** Initial full copy of the LXC's ZFS snapshot to the target, then iterative refreshes while the source keeps running. Cutover only stops the source for the final delta. Sub-second downtime on ZFS, tens of seconds on dir-pool.
- **Host user provisioning on target.** Adopt-on-target registers the Linux user that owns the container so SSH keeps working post-move.
- **Caddy route swap.** Route store's `target_ip` is updated; new traffic lands on the target backend within ~5 seconds.
- **Cascade cleanup on source.** Old LXC + host user + sync snapshots are removed.
- **Failure safety.** Any failure *before* the route swap leaves the source untouched and running.

## What `MoveContainer` does NOT do (the gaps you fill)

| Gap | Why | What to do |
|---|---|---|
| **Tenant secrets** | Each backend has its own AES-GCM master key (`/etc/containarium/secrets.key`) and its own postgres-backed store. Migrating the container body doesn't carry secrets across the trust boundary. | Re-`put` every secret on the target *before* the route swap. The container's next Start (post-move) re-stamps them as env vars. See "Secrets handoff" below. |
| **`incus remote add`** | The orchestrator assumes the source's incusd already knows the target as a named remote (convention: remote name == target backend ID). No auto-bootstrap. | Operator step on the source VM before the first move. See pre-flight step 4. |
| **Process state (memory, open sockets)** | `stateful=true` requires CRIU on both ends, which we don't deploy. | Treat every move as a restart from the container's perspective. App must tolerate it. |
| **External integrations keyed to backend ID** | Anything that tags by `backend_id` (Grafana dashboards filtering on a label, an alert that says "OOM on tunnel-lab-1") will silently drift. | Audit dashboards/alerts referencing the source backend ID; relabel using `pool=demo` or container labels instead. |
| **Per-container base-domain naming** | The route-builder in `internal/app/proxy.go` already handles "FQDN that doesn't match the daemon's `--base-domain` → use as-is." So a demo container exposed at `blog.demo.containarium.dev` continues to be served correctly by the lab backend even though the lab daemon's `--base-domain=lab.kafeido.app`. | Re-verify each exposed route after the move; if any were created with the shorthand `expose_port blog` (which appended the source daemon's base domain), they'll need re-exposing with the FQDN form on the target. |

---

## Pre-flight (Path B2)

1. **Confirm Phase 2 cutover is healthy.** `*.demo.containarium.dev` already terminates on the prod sentinel; demo VM is registered as `pool=demo` peer. (No point migrating off if the routing layer isn't stable.)

2. **Confirm Phase 3b (#207) is merged and lab backend is running it.** `containarium version` on the lab backend should print a release that includes #207. Without it, the lab can only advertise ONE base domain and the lab-hosts-demo pattern doesn't work.

3. **Inventory.** Snapshot what you're about to move:
   ```sh
   containarium list --pool=demo -o yaml > demo-inventory-$(date +%Y%m%d).yaml
   ```
   For each container, record: username, image, resource limits, GPU passthrough (if any), exposed ports + hostnames, secrets list (`containarium secrets list <username>`), labels.

4. **Re-register the lab backend with the second base domain.** On the lab backend's host:
   ```sh
   # Edit /etc/systemd/system/containarium-tunnel.service to add a second
   # --public-base-domain flag (repeatable per Phase 3b):
   #   --public-base-domain lab.kafeido.app \
   #   --public-base-domain demo.containarium.dev \
   sudo systemctl daemon-reload
   sudo systemctl restart containarium-tunnel.service
   ```
   Verify the prod sentinel picked it up:
   ```sh
   curl -s https://containarium.kafeido.app/sentinel/primaries \
     | jq '.primaries[] | select(.pool=="lab") | .base_domains'
   # Should show: ["lab.kafeido.app", "demo.containarium.dev"]
   ```
   Once the lab advertises `demo.containarium.dev` AND the demo VM still advertises it, you have an ambiguous-base-domain misconfig — `LookupByBaseDomainSuffix` will fail closed and demo SNI will start falling through to the legacy fallback. **Don't dwell here**: immediately disable the demo backend's `--public-base-domain` (set it empty in the demo daemon's service file and restart) so only the lab claims the suffix. From this moment on, new demo SNI lands on the lab — but the *containers* still live on the demo VM. The orchestration runs through the lab's tunnel back to the demo VM's Caddy via the sentinel? **No** — once the lab claims the suffix, demo SNI goes directly to the lab. So we need step 5 done FIRST or the brief ambiguity will black-hole demo traffic.

   **Better ordering**: do step 5 (`incus remote add`) and step 6 (secrets pre-stage) BEFORE this step 4. Then schedule step 4 as the cutover moment that coincides with the first batch of container moves.

5. **`incus remote add` on the source.** Source = demo VM's incusd. Target = the lab backend. On the source:
   ```sh
   ssh demo.containarium.dev sudo incus remote add tunnel-lab https://<lab-internal-ip>:8443 \
     --accept-certificate --token <provisioning-token>
   ```
   The remote name must match the lab's backend ID (`tunnel-<spot-id>`). Validate: `sudo incus remote list` shows the new entry. The lab's IP needs to be reachable from the demo VM — which it isn't directly (lab is on the home LAN, demo is on GCE). Options: a Tailscale mesh (the same one the lab uses to reach the sentinel), or temporarily exposing the lab daemon's incusd on a routable address. Pick whichever is operationally lighter for your setup.

6. **Pre-stage all tenant secrets onto the lab.** See "Secrets handoff" below — do this BEFORE step 4 so the cutover moment is short.

## Secrets handoff

Each backend's master key never leaves the host, so encrypted blobs can't be shipped source→target. Operator-mediated re-put is the only option:

```sh
SOURCE=demo.containarium.dev
TARGET=lab.kafeido.app             # or wherever the lab backend's API is reachable
USERNAME=blog

# Enumerate secret names on source
secret_names=$(containarium --server https://${SOURCE} secrets list ${USERNAME} -o json | jq -r '.[].name')

for name in $secret_names; do
  # Read plaintext from source (admin token required; CLI doesn't log values)
  value=$(containarium --server https://${SOURCE} secrets get ${USERNAME} ${name})

  # Write to target — same plaintext, target master key encrypts differently
  printf '%s' "${value}" | containarium --server https://${TARGET} secrets put ${USERNAME} ${name} --stdin
done
```

Guardrails:

- **Don't echo a secret value in a shell where history persists.** The example pipes via variable expansion for clarity; for the real run use `read -s` or `--from-file` with a tmpfs path you `shred` after.
- **Pre-stage every container's secrets before flipping the routing in step 4.** The container's next Start on the target stamps env vars from the target's store. If secrets aren't there yet, the first start runs without them.
- **Re-running `secrets put` is idempotent.** Safe to script and re-run mid-migration if you add a new secret on the source.

## Move sequence (per container)

After pre-flight and secrets pre-stage:

```sh
# 1) Final secret sync (cheap idempotent re-put)
./migrate-secrets.sh ${USERNAME}

# 2) Issue the move (sync: completes when migration finishes)
containarium --server https://${SOURCE} move ${USERNAME} --target tunnel-lab

# 3) Verify
containarium --server https://${TARGET} get ${USERNAME}            # state should be Running on target
curl -v https://${USERNAME}.demo.containarium.dev/                 # exposed hostname still resolves + serves
ssh ${USERNAME}@demo.containarium.dev                              # SSH alias still works (sshpiper routes by host_user via sentinel)
```

Move in **batches of 3–5**, not all at once. ZFS send/receive is bandwidth-hungry; saturating the demo VM's egress while users are hitting it = sad users. Pause if you see any error in the source's `journalctl -u containarium`.

## Post-move per container

- **Confirm route store points at the target's IP.** Should be automatic via `MoveContainer`'s route swap; spot-check by hitting the URL twice and watching the lab backend's Caddy log.
- **Smoke-test the application, not just HTTP 200.** App-level health (DB connection, cron jobs firing, OTel emissions) tells you secrets stamped correctly.
- **Re-attach Grafana dashboards** pinned to the old `backend_id` label — they will need relabeling to `pool=demo` or to the lab's backend ID. The OTel `service.instance.id` carries the backend ID, so any long-range query will have a series-break at the cutover moment.

## Final decommission (when all containers are moved)

```sh
# 1) Stop the tunnel on the demo VM (sentinel marks the peer offline)
ssh demo.containarium.dev sudo systemctl stop containarium-tunnel.service
ssh demo.containarium.dev sudo systemctl disable containarium-tunnel.service

# 2) Wait 5 minutes. Confirm /sentinel/peers no longer shows the demo VM.

# 3) Destroy the footprintai-dev project's Containarium resources
cd terraform/gce-demo
terraform destroy
```

DNS for `*.demo.containarium.dev` was already pointing at the prod sentinel from Phase 2 — no DNS change needed for this phase. The lab backend now owns the suffix via its second `--public-base-domain`.

---

## Rollback

### Per-container (within the move)

`MoveContainer` is one-way once the route swap is complete. The source's LXC has been cascade-deleted. To roll back a single container:

```sh
# Move it BACK — same mechanism, source and target swapped.
containarium --server https://${TARGET} move ${USERNAME} --target tunnel-<demo-spot-id>
```

Rollback is a *forward* reverse-move, not an undo. Plan time/bandwidth accordingly.

If the move itself fails mid-flight, the orchestrator restarts the source ([`move_container.go`](../internal/server/move_container.go) failure handling section). No manual rollback needed.

### Whole-path rollback (if Phase 4 itself is going badly)

If after several containers something doesn't look right and you want to stop migrating:

1. Don't run any more `move` commands.
2. The containers already migrated stay on the lab; the rest stay on the demo VM.
3. The lab's `--public-base-domain=demo.containarium.dev` is still claimed. That's fine — SNI for migrated names lands on lab, SNI for unmigrated names also lands on lab… and then 404s because those containers aren't there. Fix: temporarily remove the lab's `--public-base-domain=demo.containarium.dev`, restore the demo backend's, restart both tunnels.

If you need the demo VM to fully own `*.demo.containarium.dev` again, just reverse step 4 of the pre-flight (drop the flag on lab, add it back on demo) and `systemctl restart containarium-tunnel.service` on both.

---

## Path A: verify-only

If you're keeping the demo VM and just want to confirm Phase 2 cutover didn't break anything:

```sh
# 1) Inventory
containarium list --pool=demo

# 2) For each container, smoke-test its public hostname
for host in blog.demo.containarium.dev wiki.demo.containarium.dev ... ; do
  echo "=== ${host} ==="
  curl -sI https://${host}/ | head -5
done

# 3) SSH still works (sshpiper through prod sentinel)
ssh blog@demo.containarium.dev whoami    # should print "blog"

# 4) Container metrics still flowing
curl -s "https://grafana.kafeido.app/api/.../query?query=container_cpu_usage_seconds_total{pool=\"demo\"}" \
  | jq '.data.result | length'           # should be > 0
```

If all four pass, you're done. The demo VM continues operating exactly as before; only the sentinel-side routing has changed.

---

## Known unknowns

- **Cross-pool moves (folding demo into prod).** This plan keeps containers in `pool=demo` even when they live on the lab hardware. If you wanted them to become `pool=prod` instead, that's a different operation with different RBAC and operator-group implications. Out of scope here.
- **OTel `service.instance.id` continuity.** Each container's OTel emissions are tagged with the `backend_id` they run on. A move changes that tag, breaking long-range queries across the cutover. Design dashboards against `pool` (stable) rather than `backend_id` (ephemeral).
- **Storage-class differences.** Demo VM uses ZFS on a persistent disk; lab uses whatever was set up in `scripts/setup-gpu-host.sh` (also ZFS in practice). If they differ, the migration works but performance characteristics change. Worth noting in any post-migration capacity planning.
- **`secrets get` exposing plaintext to operator shell.** The handoff protocol above puts secrets through a shell variable. A future improvement: a `containarium secrets migrate <username> --to <backend-id>` command that uses a one-time encrypted channel between the two daemons. Worth doing if Phase 4 will be repeated for other migrations; not blocking for a one-shot demo retirement.
- **`incus remote add` reachability.** The lab is on the home LAN behind NAT; the demo VM is on GCE. The `incus copy` step needs them to talk directly. Tailscale mesh works; what we don't have today is an automated bootstrap for that mesh. Operator step.
