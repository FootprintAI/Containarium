# SSH Jump Server Setup Guide

This guide explains how to configure SSH access to Containarium containers through the jump server (bastion host).

## Architecture Overview

### With Sentinel HA (Production)

When using the sentinel + spot VM architecture, SSH traffic flows through sshpiper on the sentinel:

```
┌─────────────┐      ┌────────────────────┐      ┌──────────────┐      ┌─────────────────┐
│ User Laptop │─────▶│  Sentinel (e2-micro)│─────▶│  Spot VM     │─────▶│ LXC Containers  │
│             │ SSH  │  sshpiper on :22   │ SSH  │  (Jump Host) │ SSH  │ (10.x.x.x)      │
└─────────────┘      └────────────────────┘      └──────────────┘      └─────────────────┘
                      Static IP                   Internal IP           Private IPs
                      35.x.x.x                    10.130.0.x            10.0.3.100
                                                                        10.0.3.101
```

- **sshpiper** (port 22) acts as an SSH reverse proxy on the sentinel. It sees real client IPs and bans brute-force attackers via the `failtoban` plugin (3 failures = 1h ban).
- **sshd** on the sentinel listens on port 2222 for management/IAP access only.
- Authorized keys are synced from the spot VM every 2 minutes. sshpiper routes each user to the spot VM automatically.
- Client SSH config is unchanged — users connect to the sentinel's static IP on port 22 as before.

### Single VM (Development)

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────────┐
│ User Laptop │─────▶│  GCE VM (Jump)   │─────▶│ LXC Containers  │
│             │ SSH  │  (Bastion Host)  │ SSH  │ (10.x.x.x)      │
└─────────────┘      └──────────────────┘      └─────────────────┘
                      Public IP                  Private IPs
                      35.x.x.x                  10.0.3.100
                                                10.0.3.101
                                                10.0.3.102
```

## Two Approaches

### Approach 1: SSH ProxyJump (Recommended) ⭐

**Advantages**:
- Native SSH feature (OpenSSH 7.3+)
- Seamless experience (feels like direct SSH)
- Secure (keys never leave your machine)
- Works with SCP, rsync, VS Code Remote

**How it works**: SSH connects to jump server, then automatically jumps to target container in one command.

### Approach 2: Port Forwarding (Alternative)

**Advantages**:
- Simple setup
- Each container gets a unique port on jump server
- Compatible with older SSH clients

**How it works**: GCE VM port 2201 → Container 1, port 2202 → Container 2, etc.

---

## Method 1: SSH ProxyJump Setup (Recommended)

### Step 1: Configure GCE VM (Jump Server)

The Terraform configuration automatically sets this up, but here's what happens:

```bash
# On GCE VM - Incus networking creates a bridge
incus network list
# NAME      TYPE      MANAGED  IPV4            IPV6  DESCRIPTION
# incusbr0  bridge    YES      10.0.3.1/24     -     Container network

# Containers get IPs from this subnet
# alice-container: 10.0.3.100
# bob-container:   10.0.3.101
```

### Step 2: User SSH Config

Users configure their `~/.ssh/config`:

```ssh-config
# Jump server (bastion host)
Host containarium-jump
    HostName 35.x.x.x          # Your GCE VM public IP
    User admin                  # Admin user on jump server
    IdentityFile ~/.ssh/id_rsa

# Alice's container
Host alice-dev
    HostName 10.0.3.100         # Container's private IP
    User alice
    ProxyJump containarium-jump
    IdentityFile ~/.ssh/alice_key

# Bob's container
Host bob-dev
    HostName 10.0.3.101
    User bob
    ProxyJump containarium-jump
    IdentityFile ~/.ssh/bob_key

# Or use wildcard pattern for all containers
Host *.containarium
    ProxyJump containarium-jump
    User %r
```

### Step 3: Connect to Containers

```bash
# Direct connection (SSH automatically jumps through bastion)
ssh alice-dev

# Or with username@host
ssh alice@alice-dev

# SCP files
scp myfile.txt alice-dev:/home/alice/

# Rsync
rsync -av ./project/ alice-dev:/home/alice/project/

# VS Code Remote SSH
# Just select "alice-dev" from SSH targets
code --remote ssh-remote+alice-dev /home/alice/project
```

### Step 4: One-Line ProxyJump (Without Config)

```bash
# Direct command without ~/.ssh/config
ssh -J admin@35.x.x.x alice@10.0.3.100

# Or multiple jumps (if needed)
ssh -J jump1,jump2 alice@10.0.3.100
```

---

## Method 2: Port Forwarding Setup

### Step 1: Configure Port Forwarding on GCE VM

When creating containers, assign unique ports:

```bash
# Alice's container → port 2201
incus config device add alice-container ssh-proxy proxy \
    listen=tcp:0.0.0.0:2201 \
    connect=tcp:127.0.0.1:22

# Bob's container → port 2202
incus config device add bob-container ssh-proxy proxy \
    listen=tcp:0.0.0.0:2202 \
    connect=tcp:127.0.0.1:22
```

### Step 2: GCE Firewall Rules

Open ports in GCE firewall:

```bash
# In Terraform (see terraform/gce/main.tf)
# Allow ports 2200-2299 for container SSH access
```

### Step 3: User SSH Config

```ssh-config
Host alice-dev
    HostName 35.x.x.x           # GCE VM public IP
    Port 2201                    # Alice's assigned port
    User alice
    IdentityFile ~/.ssh/alice_key

Host bob-dev
    HostName 35.x.x.x
    Port 2202                    # Bob's assigned port
    User bob
    IdentityFile ~/.ssh/bob_key
```

### Step 4: Connect to Containers

```bash
# Connect to alice's container
ssh alice-dev

# Or direct
ssh -p 2201 alice@35.x.x.x
```

---

## Security Considerations

### 1. SSH Brute-Force Protection (Sentinel Architecture)

When using the sentinel HA architecture, SSH brute-force protection is handled by **sshpiper** with its built-in `failtoban` plugin:

- sshpiper sits on the sentinel's port 22 and sees real client IPs
- After 3 failed auth attempts, the client IP is banned for 1 hour
- This replaces the previous iptables DNAT approach, which masked real client IPs and caused fail2ban on the spot VM to ban the sentinel itself (blocking all users)

**Verify sshpiper is running:**
```bash
# SSH to sentinel via IAP (port 2222)
gcloud compute ssh <sentinel-vm> --tunnel-through-iap --ssh-flag="-p 2222"

# Check sshpiper status
systemctl status sshpiper

# Check which IPs are banned
journalctl -u sshpiper | grep "banned"

# Check sshpiper config (auto-generated from key sync)
cat /etc/sshpiper/config.yaml
```

### 2. Jump Server Hardening

```bash
# On GCE VM - Edit /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers admin alice bob

# Restart SSH
systemctl restart sshd
```

### 3. SSH Key Management

```bash
# Generate separate keys for jump server and containers
ssh-keygen -t ed25519 -f ~/.ssh/containarium_jump -C "jump-server"
ssh-keygen -t ed25519 -f ~/.ssh/alice_container -C "alice-container"

# Use SSH agent to avoid typing passphrases
eval $(ssh-agent)
ssh-add ~/.ssh/containarium_jump
ssh-add ~/.ssh/alice_container
```

### 4. Firewall Rules

**With sentinel architecture**:
- Port 22 on sentinel: sshpiper (SSH reverse proxy with failtoban)
- Port 2222 on sentinel: sshd (management/IAP access)
- Port 80/443/8080: DNAT'd to spot VM
- Spot VM has no external IP (internal VPC only)

**Without sentinel (single VM)**:
- Only port 22 open on GCE VM (jump server)
- Containers only accessible via jump server

### 5. Audit Logging

```bash
# On jump server - Log all SSH sessions
# /etc/ssh/sshd_config
LogLevel VERBOSE

# View SSH logs
journalctl -u ssh -f

# View sshpiper logs (sentinel only)
journalctl -u sshpiper -f
```

---

## Automated Setup with Containarium CLI

The `containarium` CLI will automate this:

```bash
# Create container and show SSH config
containarium create alice --ssh-key ~/.ssh/alice.pub

# Output:
# ✓ Container created: alice-container
# IP: 10.0.3.100
#
# Add to ~/.ssh/config:
# Host alice-dev
#     HostName 10.0.3.100
#     User alice
#     ProxyJump admin@35.x.x.x
```

Or generate entire SSH config:

```bash
# Generate SSH config for all containers
containarium ssh-config

# Output:
# Host containarium-jump
#     HostName 35.x.x.x
#     User admin
#
# Host alice-dev
#     HostName 10.0.3.100
#     User alice
#     ProxyJump containarium-jump
#
# Host bob-dev
#     HostName 10.0.3.101
#     User bob
#     ProxyJump containarium-jump
```

Copy to your SSH config:

```bash
containarium ssh-config >> ~/.ssh/config
```

---

## Common Scenarios

### Scenario 1: Developer Wants to Use VS Code

```bash
# Install "Remote - SSH" extension in VS Code
# Add to ~/.ssh/config (ProxyJump method)
Host alice-dev
    HostName 10.0.3.100
    User alice
    ProxyJump admin@35.x.x.x

# In VS Code: Command Palette → Remote-SSH: Connect to Host → alice-dev
```

### Scenario 2: CI/CD Pipeline Needs Access

```bash
# Use SSH key-based auth (no ProxyJump needed if on same network)
# Or use ProxyJump with service account keys

# GitHub Actions example
- name: Deploy to container
  run: |
    ssh -J admin@35.x.x.x alice@10.0.3.100 'cd /app && git pull'
```

### Scenario 3: Multiple Team Members

```bash
# Each person gets their own container
containarium create alice --ssh-key ~/.ssh/alice.pub
containarium create bob --ssh-key ~/.ssh/bob.pub
containarium create charlie --ssh-key ~/.ssh/charlie.pub

# Each person configures their own SSH config
# All use the same jump server
```

### Scenario 4: Copy Files Between Containers

```bash
# From alice's container to bob's container
# On alice's container:
scp myfile.txt bob@bob-container:/tmp/

# Or from your laptop using ProxyJump
scp -o ProxyJump=admin@35.x.x.x \
    alice@10.0.3.100:/app/build.tar.gz \
    bob@10.0.3.101:/tmp/
```

---

## Troubleshooting

### Can't Connect to Jump Server

```bash
# Check if jump server is accessible
ping 35.x.x.x

# Test SSH connection
ssh -v admin@35.x.x.x

# Check GCE firewall rules
gcloud compute firewall-rules list
```

### Can't Connect to Container via ProxyJump

```bash
# Test jump server first
ssh admin@35.x.x.x

# From jump server, test container
ssh alice@10.0.3.100

# Check container is running
incus list

# Check container SSH service
incus exec alice-container -- systemctl status ssh
```

### ProxyJump Command Not Found

```bash
# Update SSH (need OpenSSH 7.3+)
ssh -V

# For older SSH, use ProxyCommand instead
Host alice-dev
    HostName 10.0.3.100
    User alice
    ProxyCommand ssh admin@35.x.x.x -W %h:%p
```

### DNS Not Resolving Container Hostnames

```bash
# Use IP addresses instead of hostnames
# Or set up /etc/hosts on jump server
sudo tee -a /etc/hosts <<EOF
10.0.3.100  alice-container
10.0.3.101  bob-container
10.0.3.102  charlie-container
EOF
```

---

## Known Limitations

### SSH `-R`/`-L` port-forwards bind in the host network namespace, not the box

When you open a port-forward against a box (`ssh -R`/`-L`), the tunnel endpoint lives in the **host** network namespace on the jump server — not inside the box. This is a direct consequence of how sshpiper works: the SSH transport terminates on the host sshd, which then executes `containarium-shell` to proxy commands into the box via `incus exec`. The forwarded socket is opened before the `incus exec` hand-off, so it never enters the box's network namespace.

**What this means in practice:**

- `ssh -R 1080 user@host` creates a listener at `host:127.0.0.1:1080`. A process **inside the box** cannot reach that listener because the box's `127.0.0.1` is a separate network namespace.
- `ssh -L 8080:localhost:80 user@host` similarly binds on your **local** machine, but the tunnel's upstream (`localhost:80`) is resolved in the host netns, not the box's.

**Recommended workaround — initiate the tunnel from inside the box:**

Instead of forwarding a port *to* the box, run the SSH client *from* inside the box so the listener is created in the right network namespace:

```bash
# 1. SSH into the box normally
ssh <username>@<sentinel-host>

# 2. From inside the box, establish a SOCKS or local-forward tunnel
#    outbound to your workstation (which runs a SOCKS server or target port):
ssh -fN -L 1080:127.0.0.1:1080 <you>@<your-workstation>

# 3. Any process inside the box can now use socks5://127.0.0.1:1080
```

This is safe for multi-tenant deployments: the listener binds inside the box's netns and is not reachable by other tenants.

> **Note:** There is no single-command solution today for "create an in-box listener reachable inside the box from an outside SSH session" — this requires a design change to run an sshd inside each box. See [issue #808](https://github.com/FootprintAI/Containarium/issues/808) for discussion.

### Per-source-IP rate limit on the sentinel (bursty SSH automation)

The public SSH gateway (SSHPiper "sentinel") enforces a **per-source-IP
connection limit**. A burst of short-lived SSH connections from one IP — a CI
deploy loop, say — can trip it: the first several succeed, then subsequent ones
are dropped mid-handshake with a bare `Connection closed by <sentinel> port 22`
(the TCP + SSH KEX complete, then the sentinel closes the stream), and it
recovers after a short cooldown. There is no protocol-level way for SSHPiper to
tell the client "you were rate-limited," so the drop looks like a generic
connection failure (issue #933).

**Where the limit lives.** It's SSHPiper's built-in "failtoban" limiter, set on
the `sshpiperd` command line in
`terraform/modules/containarium/scripts/sshpiper.service.tmpl`:

```
--max-failures 100      # ban a source IP after this many failed handshakes …
--ban-duration 5m       # … for this long
```

Rapid short-lived connections that don't complete a full session can register
as failures and accumulate toward `--max-failures`, so high-churn automation
trips it far sooner than a human would.

**The shared-NAT trap.** CI runners commonly egress through a small pool of
public IPs, so *many independent clients present as one source IP* and share a
single IP's budget — one saturating client makes every other client on the same
egress IP fail. Confirm your automation's egress IPs before assuming the limit
is "too low."

**Diagnose it.** From the backend, `containarium debug_container <user>` reports
whether the host-side path is healthy and (when a sentinel fronts the backend)
points at the sentinel's ban table. A drop that only happens under load, only
from a high-volume source IP, and clears within seconds is this limiter — not
the container's own `sshd` (whose `MaxStartups` is generous and idle under
normal load).

**Mitigations.**

- **Raise the limit** for a fleet with heavy SSH automation: increase
  `--max-failures` (and/or `--ban-duration`) in the sshpiperd unit above and
  restart `containarium-sentinel`. These are currently baked into the service
  template; making them tunable module variables is a small follow-up.
- **Spread egress** across more source IPs so no single IP saturates the budget.
- **Reuse connections** instead of opening a new SSH per command — SSH
  `ControlMaster`/`ControlPersist` multiplexes many sessions over one
  connection, which avoids the burst entirely:

  ```
  # ~/.ssh/config
  Host <sentinel-host>
    ControlMaster auto
    ControlPath ~/.ssh/cm-%r@%h:%p
    ControlPersist 60s
  ```

- **Back off + retry** transient `Connection closed` drops in automation (a
  single attempt after a brief pause succeeds once the cooldown clears).

---

## Best Practices

1. **Use SSH ProxyJump** instead of port forwarding for better security
2. **Use SSH keys** everywhere (no passwords)
3. **Use SSH agent** to avoid typing passphrases repeatedly
4. **Use separate keys** for jump server vs containers
5. **Enable SSH multiplexing** for faster connections:

```ssh-config
Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
```

6. **Keep ~/.ssh/config organized** with comments:

```ssh-config
# Containarium Jump Server
Host containarium-jump
    HostName 35.x.x.x
    User admin

# Development Team Containers
Host alice-dev bob-dev charlie-dev
    ProxyJump containarium-jump

Host alice-dev
    HostName 10.0.3.100
    User alice
```

---

## Next Steps

1. ✅ Deploy GCE VM with Terraform
2. ✅ Configure Incus networking
3. ✅ Create containers with `containarium create`
4. ✅ Configure users' `~/.ssh/config`
5. ✅ Test SSH access
6. ✅ Distribute SSH config snippets to team

The Terraform configuration (coming next) will automate most of this setup!
