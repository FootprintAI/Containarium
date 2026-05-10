# Demo Deployment

This directory provisions the smallest realistic Containarium cluster
that supports the agent-native demo flow: an agent driving an MCP
client (Claude Code, Cursor) creates a sandbox, installs an app,
exposes it on a public hostname, and the URL works.

If you watched the demo video and thought "I want to try that" — you're
in the right place. Run `terraform apply` here and you'll have a
working cluster in ~15 minutes. Cost is ~$30/month while running;
`terraform destroy` tears it all down when you're done.

## Architecture

```
Your laptop (Claude Code)
      |
      | MCP over stdio → SSH
      v
Sentinel VM (e2-micro, free tier)
  ├── sshpiper :22       (routes SSH by username)
  └── Caddy :443         (routes HTTPS by hostname → backend)
      |
      v
Backend VM (e2-medium, spot)
  ├── containarium daemon
  ├── Incus (LXC)
  └── containers ← agent operates here via agent-box MCP
```

Wildcard DNS (`*.demo.<your-zone>`) points at the sentinel. Apps the
agent deploys (e.g. `blog.demo.<your-zone>`) reach the right container
via Caddy's hostname routing.

## Prerequisites

- GCP project with billing enabled
- `gcloud` CLI authenticated (`gcloud auth application-default login`)
- An SSH key pair (one public key goes in tfvars; the private key
  stays on your laptop for sentinel access)
- **A domain you control with DNS records you can edit.** Cloud DNS is
  the integrated path (Terraform creates records for you); see
  ["Without Cloud DNS"](#without-cloud-dns-godaddy-cloudflare-route-53-etc)
  below if your domain lives on GoDaddy / Cloudflare / Route 53 / etc.

## Step-by-step

### 1. Configure

```bash
cd terraform/gce-demo
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars
```

Required fields: `project_id`, `admin_ssh_keys`, `jwt_secret` (generate
with `openssl rand -hex 32`).

If you have a Cloud DNS zone for the domain you're demoing on, also
fill in `dns_managed_zone_name`, `dns_zone_domain`, and optionally
`demo_subdomain`. With these set, Terraform creates a wildcard A-record
pointing at the sentinel — no manual DNS work.

### 2. Apply

```bash
terraform init
terraform apply
```

Provisions ~10 GCP resources; takes 5–10 minutes. The output prints
a `next_steps` block with copy-paste commands for the next stage —
read it.

### 2a. Smoke-test (recommended)

Before committing to the demo recording, verify the cluster actually
works:

```bash
./scripts/smoke-test.sh
```

Four checks: SSH to sentinel, daemon running on backend, JWT issuance,
authenticated API call. Run after every `terraform apply`. Pass
`--expected-version=0.16.4` to fail if the daemon is on a different
version than you expected.

### 3. Issue a demo JWT

```bash
SENTINEL=$(terraform output -raw sentinel_vm_name)
ZONE=$(terraform output -json | jq -r '.[].value' | grep -E "^[a-z0-9-]+-[a-z0-9]$" | head -1)
gcloud compute ssh "$SENTINEL" --zone "$ZONE" \
  --command='sudo /usr/local/bin/containarium token generate \
              --username demo --roles admin --expiry 24h \
              --secret-file /etc/containarium/jwt.secret 2>/dev/null \
              | grep "^eyJ"' \
  > ~/.containarium-demo-token.txt && chmod 600 ~/.containarium-demo-token.txt
```

`~/.containarium-demo-token.txt` now holds a 24-hour admin JWT. Anyone
who reads the file can do anything to your demo cluster — keep it on
disk only.

### 4. Build and register the platform MCP

```bash
# From the repo root:
make build-mcp

# Wire it into Claude Code (or your MCP client of choice):
SENTINEL_IP=$(terraform -chdir=terraform/gce-demo output -raw sentinel_ip)
claude mcp add containarium-demo --scope user \
  --env CONTAINARIUM_SERVER_URL=http://$SENTINEL_IP:8080 \
  --env CONTAINARIUM_JWT_TOKEN="$(cat ~/.containarium-demo-token.txt)" \
  -- $(pwd)/bin/mcp-server
```

Restart Claude Code so it loads the new server.

### 5. Drive the demo

In Claude Code, paste this prompt (substitute your domain):

> Spin up a sandbox called `demo-blog`, install nginx, serve a hello-world page, and expose it at `demo-blog.demo.<your-zone>`.

The agent should:

1. Call `create_container demo-blog` (platform MCP)
2. Configure SSH (you may need to run `containarium ssh-config sync`
   between this step and the next so the in-the-box MCP wiring works)
3. Call `shell_exec apt install nginx` (agent-box MCP)
4. Call `write_file /var/www/html/index.html` with the hello page
5. Call `process_start nginx` to run it in the background
6. Call `tail_log` on the access log to confirm it's serving
7. Call `expose_port demo-blog --container-port 80 --domain demo-blog.demo.<your-zone>`

Then `curl https://demo-blog.demo.<your-zone>/` returns the hello page.

### 6. Tear down

```bash
terraform destroy
```

Everything (VMs, disk, DNS records) goes away. The `~/.containarium-demo-token.txt`
on your laptop is now invalid; delete it.

## Cost

| Resource | Cost / month |
|---|---|
| Sentinel VM (e2-micro) | $0 (free tier) |
| Backend VM (e2-medium spot) | ~$10 |
| 100 GB persistent disk (pd-balanced) | ~$10 |
| Cloud NAT | ~$1 |
| DNS records | ~$0.50 |
| **Total** | **~$25–35** |

Spot preemption can interrupt the backend; the persistent disk
preserves containers across restarts. For a recording session, run
`terraform apply` an hour beforehand so the cluster has time to
stabilize.

## Customization

Most knobs are in `variables.tf`. Common changes:

- **Bigger backend** for heavier workloads: set `machine_type =
  "n2-standard-4"`. Cost roughly doubles.
- **Different region**: set `region` and `zone` to anywhere with
  Cloud DNS + spot VMs available.
- **Specific containarium version**: set `containarium_version =
  "0.16.5"` (or whatever's current).

The Containarium module itself lives at `../modules/containarium/` —
that's the actual implementation. This directory is a thin "consumer"
on top of it tailored for the demo experience.

## Without Cloud DNS (GoDaddy, Cloudflare, Route 53, etc.)

If your domain isn't managed by Google Cloud DNS, leave
`dns_managed_zone_name` and `dns_zone_domain` blank in tfvars. Run
`terraform apply` as usual — it'll skip the DNS-record resources and
emit `(set DNS manually)` for the `demo_base_domain` output.

You then create two A records by hand on whichever provider hosts
your domain:

```
terraform output -raw sentinel_ip
# e.g. 34.123.45.67
```

| Type | Name (host) | Value | TTL |
|---|---|---|---|
| A | `*.demo` | sentinel IP | 600 |
| A | `demo` | sentinel IP | 600 |

The `*.demo` wildcard makes `anything.demo.<your-domain>` resolve to
the sentinel — that's what makes `expose_port` work for arbitrary
hostnames the agent picks. The plain `demo` record covers
`demo.<your-domain>` directly so you can hit the platform API or web
UI in a browser.

### GoDaddy

1. Sign in → **My Products** → your domain → **DNS** (or
   `dcc.godaddy.com/manage/<your-domain>/dns`).
2. **Add Record** → type `A`, name `*.demo`, value the sentinel IP,
   TTL 600 seconds. Save.
3. **Add Record** again → type `A`, name `demo`, same value, TTL 600.
4. GoDaddy's UI calls out wildcard support directly (`Use * for
   wildcards`); if it rejects `*.demo` for any reason, fall back to
   creating one A record per app you'll demo (e.g., `blog.demo`,
   `app.demo`) with the same IP.
5. Note: **DNS records**, not **Forwarding** — those are different
   tabs and "Forwarding" won't do what we need.

### Cloudflare

1. Sign in → your domain → **DNS** → **Records**.
2. **Add record** → type `A`, name `*.demo`, IPv4 sentinel IP,
   proxy status **DNS only** (the orange cloud OFF — Cloudflare's
   proxy doesn't pass HTTP-routed domains through PROXY-protocol
   correctly to our sentinel). TTL 5 min.
3. Repeat for `demo` (same IP, DNS-only).

### Route 53

1. Open the hosted zone for your domain.
2. **Create record** → record name `*.demo`, record type `A`, value
   the sentinel IP, TTL 600.
3. Repeat for `demo`.

### Verify (any provider)

```bash
dig +short blog.demo.<your-domain>
dig +short demo.<your-domain>
# Both should return the sentinel IP.
```

Propagation: 5–60 minutes typically. If `dig` returns nothing, wait
and retry; don't move on to the demo recording until both names
resolve.

### Tear-down

After `terraform destroy`, the sentinel IP is released. Delete the
two A records on your provider (otherwise they'll point at someone
else's GCP IP next time someone gets that ephemeral IP).

## Troubleshooting

**`terraform apply` fails with "Error 403: APIs not enabled"** — enable
Compute Engine, Cloud DNS, and IAM APIs in your project.

**Wildcard DNS doesn't resolve** — Cloud DNS has 5-minute TTLs;
propagation isn't instant. `dig +short *.demo.<your-zone>` should
eventually return the sentinel IP.

**Agent's `expose_port` call fails with auth error** — your JWT may
have expired (24h default). Re-issue per step 3.

**`curl https://...` returns 502** — the sentinel hits the backend's
Caddy via PROXY protocol. If the backend's Caddy isn't running yet
(daemon still starting), retries within 30s usually clear it.
