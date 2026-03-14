# OCI Runtime Cgroup Injection

Containarium injects LXC cgroup resource limits into nested Docker/Podman containers so they see correct memory and CPU constraints instead of the physical host's resources.

## Problem

LXC containers have cgroup limits (e.g., 30GB memory), but nested Docker containers see the **host's** physical resources (e.g., 62GB). This causes:

- `free` / `top` report wrong memory totals
- Applications auto-tuning to host resources (JVM heap, Node.js memory, database buffers) allocate too much and get OOM-killed
- Docker Compose v2 bypasses CLI wrappers entirely (it uses the Docker Engine API, not the `docker` CLI binary)

## Solution: Two-Layer Approach

### Layer 1: CLI Wrapper (Podman + Docker)

A wrapper script at `/usr/local/bin/docker` (or `/usr/local/bin/podman`) intercepts `run` and `create` commands, reads LXC cgroup limits, and injects `--memory` / `--cpus` flags.

**Limitation:** Only catches direct CLI usage. Docker Compose v2 and Docker API calls bypass it.

### Layer 2: OCI Runtime Wrapper (Docker only)

A custom OCI runtime at `/usr/local/bin/containarium-runtime` wraps the real `/usr/bin/runc`. Registered as Docker's default runtime via `daemon.json`, it intercepts **every** container creation regardless of how it was triggered.

On `runc create`, the wrapper:

1. Finds `--bundle` in the runc args (which come after global options like `--root`, `--log`)
2. Reads `config.json` from the bundle directory
3. Injects LXC memory/CPU limits into the OCI spec if not already set
4. Bind-mounts LXCFS-backed `/proc` files so `free`, `top`, etc. report correct values
5. Delegates to the real runc

## How It Works

### Cgroup Limit Injection

The runtime reads limits from the LXC container's cgroup v2 interface:

| Source | OCI Spec Field | Effect |
|--------|---------------|--------|
| `/sys/fs/cgroup/memory.max` | `linux.resources.memory.limit` | Container memory limit |
| `/sys/fs/cgroup/cpu.max` (quota period) | `linux.resources.cpu.quota` + `cpu.period` | CPU time allocation |

Limits are only injected if the OCI spec has no existing limit (0, null, or absent). User-specified limits (e.g., `--memory=1g` or compose `mem_limit`) take precedence.

### LXCFS Bind Mounts

LXC uses [LXCFS](https://linuxcontainers.org/lxcfs/) to virtualize `/proc/meminfo`, `/proc/cpuinfo`, etc. so they reflect cgroup limits. Without pass-through, Docker containers see raw host values via procfs.

The runtime appends bind mounts to the OCI spec:

```
/proc/meminfo   (makes free/top show correct memory)
/proc/cpuinfo   (shows correct CPU count)
/proc/stat      (CPU statistics)
/proc/uptime    (container uptime)
/proc/loadavg   (load average)
/proc/diskstats (disk I/O stats)
/proc/swaps     (swap info)
```

These are only injected when LXCFS is detected (`mount | grep 'lxcfs on /proc/meminfo'`).

### daemon.json

The runtime is registered as Docker's default:

```json
{
  "default-runtime": "containarium",
  "runtimes": {
    "containarium": {
      "path": "/usr/local/bin/containarium-runtime"
    }
  }
}
```

Existing `daemon.json` settings are preserved via `jq` deep merge.

## Runc Argument Parsing

Docker/containerd invokes runc with global options before the subcommand:

```
runc --root /var/run/docker/runtime-runc/moby \
     --log /run/containerd/.../log.json \
     --log-format json \
     create --bundle /path/to/bundle <container-id>
```

The wrapper scans all arguments for `create` (not just `$1`) and separately extracts `--bundle`.

## Installation

The OCI runtime is automatically installed:

- **New containers:** During `installPackages()` when `stackID == "docker"`
- **Existing containers:** On daemon startup via `UpgradeCgroupWrappers()`
- **Stack install:** When running `InstallStack("docker")`

Installation steps (inside the LXC container):
1. `apt-get install -y jq`
2. Write runtime script to `/usr/local/bin/containarium-runtime`
3. Merge runtime config into `/etc/docker/daemon.json`
4. `systemctl restart docker` (compose services with `restart: always` auto-recover)

## Verification

```bash
# Inside an LXC container with Docker:

# 1. Runtime is default
docker info | grep "Default Runtime"
# → containarium

# 2. Cgroup limits enforced
docker run --rm ubuntu cat /sys/fs/cgroup/memory.max
# → 32000000000 (LXC limit, not "max")

# 3. free reports correct memory
docker run --rm ubuntu free -h
# → Mem: 29Gi (not 62Gi)

# 4. User limits take precedence
docker run --rm --memory=1g ubuntu cat /sys/fs/cgroup/memory.max
# → 1073741824

# 5. Docker Compose containers also see limits
docker compose up -d
docker exec <service> free -h
# → Shows LXC limit, not host memory
```

## Files

| File | Purpose |
|------|---------|
| `internal/container/cgroup_wrapper.go` | `ociRuntimeScript()` and `installDockerOCIRuntime()` |
| `internal/container/cgroup_wrapper_test.go` | Script content validation tests |
| `internal/container/manager.go` | Hooks in `installPackages()` and `InstallStack()` |

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| User sets `--memory` in docker run | OCI spec has non-zero limit, runtime skips |
| User sets `mem_limit` in compose | Same — runtime skips |
| CLI wrapper already injected limits | OCI spec has non-zero limit, runtime skips |
| `memory.max = "max"` (unlimited LXC) | Runtime skips memory injection |
| `cpu.max = "max 100000"` (unlimited CPU) | Runtime skips CPU injection |
| No LXCFS | LXCFS bind mounts skipped, cgroup limits still injected |
| No `jq` installed | Installed automatically during setup |
| Existing `daemon.json` | Deep-merged, existing settings preserved |
| Docker not installed (Podman only) | OCI runtime skipped entirely |
| Daemon restart during upgrade | Docker restarted; `restart: always` services auto-recover |
