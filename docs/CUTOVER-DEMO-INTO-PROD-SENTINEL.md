# Cutover: demo cluster → prod sentinel as `pool=demo`

**Goal**: retire the standalone demo cluster's sentinel + DNS by re-pointing its base domain at the prod sentinel. The demo VM keeps running as a `pool=demo` peer of the prod sentinel. Demo containers stay in place — no migration of container state in this step (that's Phase 4).

**Depends on**: a containarium release containing both #204 (pool selector) AND #205 (per-pool base-domain suffix routing) on every binary involved. Replace `vX.Y.Z` below with that release tag.

**Background reads**: [MULTI-POOL.md](MULTI-POOL.md) (operator workflow for adding a pool), [PER-POOL-BASE-DOMAIN.md](PER-POOL-BASE-DOMAIN.md) (what `--public-base-domain` does and why), [PROXY-PROTOCOL.md](PROXY-PROTOCOL.md) (the silent-fail mode if you forget the trusted-CIDR flag).

---

## What's true today

| | Demo (footprintai-dev / us-central1-a) | Prod (footprintai-prod / us-west1-a) |
|---|---|---|
| Sentinel | `containarium-demo-sentinel` (e2-micro) | `containarium-jump-usw1-sentinel` (e2-micro) |
| Backend | `containarium-demo` (e2-standard-2 spot) | `containarium-jump-usw1` (c3d-highmem-8) |
| Base domain | `demo.containarium.dev` | `kafeido.app` |
| DNS wildcard | `*.demo.containarium.dev` → demo sentinel IP | `*.kafeido.app` → prod sentinel IP |
| Daemon binary | v0.16.7 (per terraform/gce-demo/variables.tf default) | v0.15.0 last observed 2026-05-03 — **verify before starting** |

The demo backend's own Caddy ACMEs `*.demo.containarium.dev` certs and terminates TLS. The prod sentinel is TCP/SNI passthrough — it never sees the TLS bytes — so post-cutover the demo backend keeps doing its own cert lifecycle exactly as today.

## What changes after cutover

- The demo backend's daemon stops registering itself as a sentinel primary and instead opens a yamux tunnel into the prod sentinel, declaring `--pool=demo --public-base-domain=demo.containarium.dev`.
- The prod sentinel's SNI router suffix-matches any inbound `*.demo.containarium.dev` to that tunnel and forwards bytes through it.
- `*.demo.containarium.dev` DNS re-points from demo sentinel IP → prod sentinel IP.
- The demo sentinel + its public IP can be destroyed (decommission step, last).

---

## Pre-flight checklist

Run from your laptop. Each step is verifiable independently.

1. **Confirm both binaries support the new flags.**
   ```sh
   # On the prod sentinel host
   ssh footprintai-prod-sentinel sudo /usr/local/bin/containarium version
   # On the prod daemon host
   ssh -p 2222 footprintai-prod-sentinel "ssh containarium-jump-usw1 sudo /usr/local/bin/containarium version"
   # On the demo daemon host
   ssh demo.containarium.dev sudo /usr/local/bin/containarium version
   ```
   All three must print `vX.Y.Z` or later (a release that includes #204 + #205). If any is older, **upgrade it first** — the cutover assumes the prod sentinel knows about `base_domain` and the daemons know about `--public-base-domain`.

2. **Confirm the prod backend is already pool-tagged.** Per [memory](../README.md), the prod backend may have been brought up before the pool concept landed.
   ```sh
   curl -s https://containarium.kafeido.app/sentinel/peers | jq '.peers[] | {id, pool, healthy}'
   ```
   If `containarium-jump-usw1` shows `pool: ""`, restart its daemon with `--pool=prod --public-base-domain=kafeido.app` *before* introducing the demo pool — otherwise demo and prod would both be "untagged" and the routing decision would be ambiguous.

3. **Confirm a tunnel token exists for the demo pool.** The sentinel's `--tunnel-token-policy` controls which tokens can register which pools. Either:
   ```sh
   ssh footprintai-prod-sentinel "systemctl cat containarium-sentinel" | grep tunnel-token
   ```
   should already include a `token=demo` entry, OR you need to add one and reload the sentinel. Generate a fresh token and store it in GCP Secret Manager:
   ```sh
   openssl rand -hex 32 | gcloud secrets create containarium-demo-tunnel-token --data-file=- --project=footprintai-prod
   ```
   Then update the sentinel systemd unit's `--tunnel-token-policy` to include `<that-hex>=demo`, `systemctl daemon-reload`, and restart the sentinel.

4. **Confirm Caddy on the demo backend can keep ACME-ing post-cutover.** It already does HTTP-01 by default. HTTP-01 traverses the sentinel transparently (port 80 passthrough is identical to port 443). No code change.
   ```sh
   ssh demo.containarium.dev sudo journalctl -u caddy --since '1 day ago' | grep -E 'obtain|renew' | tail -5
   ```
   If you see recent successful renews, you're good.

5. **Note the current DNS TTL** so you know how long the cutover takes to propagate.
   ```sh
   dig +short TTL=ANSWER A blog.demo.containarium.dev   # whatever subdomain is in use
   ```
   Cloudflare default is 300s; cutover-then-rollback window matches that.

---

## Cutover steps

### Step 1 — register demo backend as a peer of prod sentinel

On the demo backend (`containarium-demo` spot VM):

```sh
ssh demo.containarium.dev

# Stop the local standalone roles (sentinel registration + own sentinel)
sudo systemctl stop containarium-sentinel.service     # if present locally
sudo systemctl disable containarium-sentinel.service  # so it doesn't come back on reboot

# Pull the demo pool's tunnel token (set in pre-flight step 3)
TUNNEL_TOKEN=$(gcloud secrets versions access latest --secret=containarium-demo-tunnel-token --project=footprintai-prod)

# Find prod sentinel's external IP (or use the public hostname)
PROD_SENTINEL=containarium.kafeido.app:9443

# Install / update the tunnel client unit
sudo tee /etc/systemd/system/containarium-tunnel.service > /dev/null <<EOF
[Unit]
Description=Containarium reverse tunnel to prod sentinel (pool=demo)
After=network-online.target
Wants=network-online.target

[Service]
Environment=CONTAINARIUM_TUNNEL_TOKEN=${TUNNEL_TOKEN}
ExecStart=/usr/local/bin/containarium tunnel \\
  --sentinel-addr ${PROD_SENTINEL} \\
  --spot-id containarium-demo-spot \\
  --pool demo \\
  --ports 22,80,443 \\
  --public-hostname demo.containarium.dev \\
  --public-base-domain demo.containarium.dev \\
  --public-port 443
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now containarium-tunnel.service
sudo journalctl -u containarium-tunnel -f
```

The journal should show `connected to sentinel`, `registered as "containarium-demo-spot"`, and an assigned `127.0.0.X` loopback IP within ~5 seconds.

### Step 2 — verify the prod sentinel learned about us

From your laptop (or any host that can reach `containarium.kafeido.app`):

```sh
# Peer registry — demo backend should appear with pool=demo
curl -s https://containarium.kafeido.app/sentinel/peers \
  | jq '.peers[] | select(.id == "tunnel-containarium-demo-spot")'

# Primary registry — should show the demo primary with base_domain set
curl -s https://containarium.kafeido.app/sentinel/primaries \
  | jq '.primaries[] | select(.pool == "demo")'
```

Look for `pool: "demo"`, `base_domain: "demo.containarium.dev"`, `backend_id: "tunnel-containarium-demo-spot"`. If `base_domain` is empty, the daemon binary is too old (back to pre-flight step 1).

### Step 3 — prove SNI routing works BEFORE touching DNS

This is the cutover's keystone: confirm the prod sentinel forwards `*.demo.containarium.dev` to the demo backend, without trusting DNS yet.

```sh
# Pick any existing demo container hostname (e.g. blog, agent01, …)
EXISTING_HOST=blog.demo.containarium.dev
PROD_SENTINEL_IP=$(dig +short A containarium.kafeido.app | head -1)

# --resolve forces curl to dial the prod sentinel, but the TLS SNI
# and Host header still say the demo hostname. If the suffix route
# is working, the byte path is: curl → prod sentinel → SNI peek →
# LookupByBaseDomainSuffix → yamux to demo backend → demo Caddy.
curl -vk --resolve "${EXISTING_HOST}:443:${PROD_SENTINEL_IP}" \
  "https://${EXISTING_HOST}/"
```

Expected: an HTTP response from the demo backend (or its app). The demo backend's Caddy log should show the request. The prod sentinel log should show `forwarding SNI=${EXISTING_HOST} to tunnel-containarium-demo-spot`.

**If this fails, STOP and read the daemon + sentinel logs.** Do not change DNS until this works. Most likely cause: pre-flight step 1 (binary too old) was skipped.

### Step 4 — DNS cutover

Once step 3 is green:

```sh
# In Cloudflare, update both records:
#   *.demo.containarium.dev   A   <prod_sentinel_ip>   (was demo_sentinel_ip)
#   demo.containarium.dev     A   <prod_sentinel_ip>   (was demo_sentinel_ip)
# TTL 300 (same as today) so rollback is fast.
```

Verify propagation from a few resolvers:

```sh
for resolver in 1.1.1.1 8.8.8.8 9.9.9.9; do
  echo "=== ${resolver} ==="
  dig @${resolver} +short A blog.demo.containarium.dev
done
```

All three should return the prod sentinel IP within a few minutes.

### Step 5 — verify end-to-end via real DNS

```sh
curl -v https://blog.demo.containarium.dev/
```

Should hit the demo backend exactly as before, but the TCP connection terminates on the prod sentinel.

---

## Decommission (after 24h of clean prod-sentinel-routed traffic)

```sh
# Remove the demo sentinel VM
cd terraform/gce-demo
terraform destroy -target=module.containarium.google_compute_instance.sentinel  # exact resource name per module

# Release its static IP if it had one
gcloud compute addresses delete containarium-demo-sentinel-ip --region=us-central1 --project=footprintai-dev
```

The demo backend keeps running. Its only changed responsibility is "talk to prod sentinel via yamux instead of being its own primary."

---

## Rollback

If anything in step 3 or after misbehaves and you need to revert within the DNS TTL window:

```sh
# 1) Stop the tunnel on the demo backend
ssh demo.containarium.dev sudo systemctl stop containarium-tunnel.service

# 2) Re-enable the local sentinel
ssh demo.containarium.dev sudo systemctl enable --now containarium-sentinel.service

# 3) Revert DNS records in Cloudflare to the demo sentinel IP

# 4) Verify
curl -v https://blog.demo.containarium.dev/   # should hit demo backend via demo sentinel again
```

Rollback is non-destructive on the prod side — the prod sentinel just stops getting `*.demo.containarium.dev` traffic; no config change needed there.

---

## What is NOT covered here

- **Container migration.** All demo containers stay on the demo backend during this step. Phase 4 will document moving them onto prod-pool backends (and the secrets-store cross-cluster gotcha that involves).
- **Tenant secrets.** The demo backend's secrets master key (`/etc/containarium/secrets.key`) stays put — it's per-host. Containers using the tenant secrets API continue to read from the same store.
- **OTel relay.** The demo backend's `--otel-collector-endpoint` is unchanged. If you want demo metrics in the prod VictoriaMetrics, that's a separate flag flip on the demo daemon (out of scope here).
- **Cross-pool RBAC / quota.** No daemon-side enforcement — pool is currently a placement tag, not an access boundary.

---

## One-pager (for the runbook drawer)

1. Confirm all three binaries are >= vX.Y.Z (#204 + #205).
2. Pool-tag prod backend (`--pool=prod --public-base-domain=kafeido.app`) if not already.
3. Mint a demo-pool tunnel token, add to sentinel's `--tunnel-token-policy`.
4. Stop the demo sentinel role; install `containarium-tunnel.service` with `--pool=demo --public-base-domain=demo.containarium.dev`.
5. Verify `/sentinel/peers` and `/sentinel/primaries` on prod.
6. `curl --resolve` an existing demo hostname against prod sentinel IP — must succeed before DNS change.
7. Cut DNS `*.demo.containarium.dev` to prod sentinel IP.
8. After 24h: destroy demo sentinel + its static IP.
