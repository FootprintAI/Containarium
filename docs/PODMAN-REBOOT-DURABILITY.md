# Podman reboot/preemption durability for `--podman` tenants

Long-lived services in a `containarium create --podman` tenant (e.g. a
podman-compose app stack) must come back automatically after the **host**
reboots — which on a spot / sentinel-HA deployment happens routinely
(preemption → sentinel recovers the workhorse from the persistent ZFS disk →
reboot). This note describes what the platform provisions for you and the one
thing you still have to do: **give your workloads a restart policy.**

## The recovery chain

```
host boot
  → Incus starts the tenant LXC          (boot.autostart=true, set at create)
    → tenant systemd starts               (PID 1 in the LXC)
      → podman-restart.service            (system + per-user, enabled at create)
        → restarts podman containers that carry a restart policy
```

Every link except the last is automatic. The last link only fires for
containers created with a **restart policy** — that part is yours to set.

## What `--podman` provisions for you

At create time the daemon wires up both podman runtimes (see issue #387):

- **LXC autostart** — `boot.autostart=true` on the tenant container, so it
  comes back on host boot.
- **Rootful** — the **system** `podman-restart.service` is enabled. On boot it
  restarts every root-owned container created with
  `--restart=always|unless-stopped`.
- **Rootless** — `loginctl enable-linger <tenant-user>` is set so the tenant's
  `systemd --user` manager starts at boot even with no SSH session, and the
  **user** `podman-restart.service` is enabled for them (so their rootless
  containers with a restart policy come back too).

All of this is best-effort and idempotent; it does **not** invent a restart
policy for your containers.

## What you must do: set a restart policy

`podman-restart.service` only restarts containers that already carry
`--restart=always` (or `unless-stopped`). Without it, a `podman run` /
`podman-compose up` leaves containers **stopped** after a reboot and your
service silently does not come back.

**`podman run`:**

```bash
podman run -d --restart=always --name myservice myimage:tag
```

**`podman-compose` / compose file** — set `restart: always` on every service:

```yaml
services:
  api:
    image: myimage:tag
    restart: always   # <-- required for reboot durability
  db:
    image: postgres:16
    restart: always
```

> **Caveat:** `podman-compose up -d` has historically been inconsistent about
> stamping the compose `restart:` value onto the created containers. After
> `up -d`, verify the policy actually landed:
>
> ```bash
> podman inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' $(podman ps -q)
> # each should print `always`, not `no`/empty
> ```
>
> If it didn't stick, the most robust path is to generate systemd units and let
> systemd own lifecycle (below).

## Rootful vs rootless — which podman are you using?

- **Rootful** (running podman as `root` / via `sudo`): the system
  `podman-restart.service` handles you. Nothing extra needed beyond the restart
  policy.
- **Rootless** (running podman as the tenant user, the default for a
  non-privileged service): you rely on the **user** `podman-restart.service` +
  linger, both provisioned above. If you created the tenant before this was
  provisioned, enable them yourself once:

  ```bash
  # as root on the host / in the LXC:
  loginctl enable-linger <tenant-user>
  # as the tenant user:
  systemctl --user enable podman-restart.service
  ```

## Most robust: systemd-owned units

For a service you really don't want to lose, let systemd own it rather than
relying on `podman-restart.service` + a correctly-stamped policy:

- **Quadlet** (`.container` / `.kvm` files under
  `~/.config/containers/systemd/`) — the modern, declarative path.
- **`podman generate systemd`** — generate a unit from a running container.
- **Containarium compose autostart** — the in-box agent tooling can emit a
  `systemd --user` unit for a compose stack and enable linger for you; see
  [COMPOSE-AUTOSTART-DESIGN.md](COMPOSE-AUTOSTART-DESIGN.md).

Each of these is enabled with `systemctl --user enable --now <unit>` and, with
linger on, starts at host boot independently of `podman-restart.service`.

## Verifying durability

After bringing a workload up:

```bash
# 1. policy is stamped
podman inspect -f '{{.HostConfig.RestartPolicy.Name}}' <container>   # -> always

# 2. the restart units are enabled
systemctl is-enabled podman-restart.service            # system (rootful)
systemctl --user is-enabled podman-restart.service     # user   (rootless)
loginctl show-user <tenant-user> -p Linger             # -> Linger=yes
```

A real end-to-end check reboots the host (or simulates a spot preemption +
sentinel recovery) and asserts the workload is `RUNNING` again with no manual
intervention — see the reboot-survival case in the acceptance suite.
