package container

import (
	"fmt"
	"log"
)

// cgroupWrapperScript returns a bash wrapper script that intercepts run/create
// subcommands and injects --memory/--cpus flags from the LXC container's live
// cgroup v2 limits. This ensures nested Docker/Podman containers see the
// correct resource limits instead of the physical host's resources.
//
// For Docker, the OCI runtime wrapper (see ociRuntimeScript) catches all
// container creation including Docker Compose v2. The CLI wrapper is kept as
// a compatible belt-and-suspenders layer.
func cgroupWrapperScript(realBinary string) string {
	return fmt.Sprintf(`#!/bin/bash
# Containarium: cgroup-limit-aware wrapper for nested containers.
# Injects --memory and --cpus from LXC cgroup v2 limits so that
# nested containers see the correct resource constraints.
# NOTE: Docker Compose v2 uses the Docker API directly and bypasses this wrapper.
REAL=%s

case "${1:-}" in
  run|create)
    # Skip injection if user already set the flag
    for a in "$@"; do
      case "$a" in --memory=*|--memory|-m=*|-m) HAS_MEM=1;; esac
      case "$a" in --cpus=*|--cpus) HAS_CPU=1;; esac
    done

    INJECT=""

    # Memory: read /sys/fs/cgroup/memory.max (bytes, or "max")
    if [ -z "${HAS_MEM:-}" ] && [ -r /sys/fs/cgroup/memory.max ]; then
      MEM=$(cat /sys/fs/cgroup/memory.max)
      [ "$MEM" != "max" ] && [ "$MEM" -gt 0 ] 2>/dev/null && INJECT="--memory=$MEM"
    fi

    # CPU: read /sys/fs/cgroup/cpu.max ("$QUOTA $PERIOD" or "max $PERIOD")
    if [ -z "${HAS_CPU:-}" ] && [ -r /sys/fs/cgroup/cpu.max ]; then
      read -r QUOTA PERIOD < /sys/fs/cgroup/cpu.max
      if [ "$QUOTA" != "max" ] && [ "$PERIOD" -gt 0 ] 2>/dev/null; then
        CPUS=$(awk "BEGIN {printf \"%%.2f\", $QUOTA/$PERIOD}")
        INJECT="$INJECT --cpus=$CPUS"
      fi
    fi

    if [ -n "$INJECT" ]; then
      SUB="$1"; shift
      exec $REAL "$SUB" $INJECT "$@"
    fi
    ;;
esac
exec $REAL "$@"
`, realBinary)
}

// ociRuntimeScript returns a bash script that acts as a custom OCI runtime.
// It wraps the real runc binary and injects cgroup resource limits from the
// LXC container's cgroup v2 into the OCI spec's config.json on "create".
// This catches ALL container creation paths including Docker Compose v2,
// which bypasses the CLI wrapper by using the Docker Engine API directly.
//
// The script is installed at /usr/local/bin/containarium-runtime and registered
// as Docker's default runtime via daemon.json.
func ociRuntimeScript() string {
	return `#!/bin/bash
# Containarium OCI runtime wrapper.
# Intercepts "runc create" to inject cgroup limits from LXC into OCI config.json
# and bind-mount LXCFS-backed /proc files so tools like "free" see correct values.
# This catches all container creation paths including Docker Compose v2.
REAL_RUNC=/usr/bin/runc

# Docker/containerd invokes runc with global options before the subcommand:
#   runc --root ... --log ... create --bundle /path ...
# Scan all args to find the "create" subcommand.
IS_CREATE=false
BUNDLE=""
ARGS=("$@")
for ((i=0; i<${#ARGS[@]}; i++)); do
  if [ "${ARGS[$i]}" = "create" ]; then
    IS_CREATE=true
  fi
  if [ "${ARGS[$i]}" = "--bundle" ] && [ $((i+1)) -lt ${#ARGS[@]} ]; then
    BUNDLE="${ARGS[$((i+1))]}"
  fi
done

if $IS_CREATE; then
  CONFIG="${BUNDLE:-.}/config.json"

  if [ -f "$CONFIG" ] && command -v jq >/dev/null 2>&1; then
    MODIFIED=false

    # Read LXC memory limit
    if [ -r /sys/fs/cgroup/memory.max ]; then
      LXC_MEM=$(cat /sys/fs/cgroup/memory.max)
      if [ "$LXC_MEM" != "max" ] && [ "$LXC_MEM" -gt 0 ] 2>/dev/null; then
        # Check if OCI spec has no memory limit (0, null, or absent)
        OCI_MEM=$(jq -r '.linux.resources.memory.limit // 0' "$CONFIG" 2>/dev/null)
        if [ "$OCI_MEM" = "0" ] || [ "$OCI_MEM" = "null" ] || [ -z "$OCI_MEM" ]; then
          jq --argjson limit "$LXC_MEM" \
            '.linux.resources.memory.limit = $limit' "$CONFIG" > "${CONFIG}.tmp" \
            && mv "${CONFIG}.tmp" "$CONFIG"
          MODIFIED=true
        fi
      fi
    fi

    # Read LXC CPU limit
    if [ -r /sys/fs/cgroup/cpu.max ]; then
      read -r QUOTA PERIOD < /sys/fs/cgroup/cpu.max
      if [ "$QUOTA" != "max" ] && [ "$PERIOD" -gt 0 ] 2>/dev/null; then
        # Check if OCI spec has no CPU quota (0, null, or absent)
        OCI_QUOTA=$(jq -r '.linux.resources.cpu.quota // 0' "$CONFIG" 2>/dev/null)
        if [ "$OCI_QUOTA" = "0" ] || [ "$OCI_QUOTA" = "null" ] || [ -z "$OCI_QUOTA" ]; then
          jq --argjson quota "$QUOTA" --argjson period "$PERIOD" \
            '.linux.resources.cpu.quota = $quota | .linux.resources.cpu.period = $period' \
            "$CONFIG" > "${CONFIG}.tmp" \
            && mv "${CONFIG}.tmp" "$CONFIG"
          MODIFIED=true
        fi
      fi
    fi

    # Inject LXCFS bind mounts so /proc/meminfo, /proc/cpuinfo, etc. inside
    # Docker containers reflect the LXC cgroup limits (makes "free" correct).
    # Only inject if LXCFS is mounted (detected via /proc/meminfo mount type).
    if mount | grep -q 'lxcfs on /proc/meminfo'; then
      LXCFS_MOUNTS='[
        {"destination":"/proc/meminfo","type":"bind","source":"/proc/meminfo","options":["bind","ro"]},
        {"destination":"/proc/cpuinfo","type":"bind","source":"/proc/cpuinfo","options":["bind","ro"]},
        {"destination":"/proc/stat","type":"bind","source":"/proc/stat","options":["bind","ro"]},
        {"destination":"/proc/uptime","type":"bind","source":"/proc/uptime","options":["bind","ro"]},
        {"destination":"/proc/loadavg","type":"bind","source":"/proc/loadavg","options":["bind","ro"]},
        {"destination":"/proc/diskstats","type":"bind","source":"/proc/diskstats","options":["bind","ro"]},
        {"destination":"/proc/swaps","type":"bind","source":"/proc/swaps","options":["bind","ro"]}
      ]'
      jq --argjson lxcfs "$LXCFS_MOUNTS" '.mounts += $lxcfs' "$CONFIG" > "${CONFIG}.tmp" \
        && mv "${CONFIG}.tmp" "$CONFIG"
      MODIFIED=true
    fi
  fi
fi

exec $REAL_RUNC "$@"
`
}

// installDockerOCIRuntime installs the containarium OCI runtime wrapper and
// registers it as Docker's default runtime via daemon.json. This ensures all
// Docker container creation paths (CLI, Compose v2, API) have cgroup limits
// injected from the LXC container.
func (m *Manager) installDockerOCIRuntime(containerName string) error {
	// Step 1: Ensure jq is installed (needed by the runtime script)
	if err := m.incus.Exec(containerName, []string{"apt-get", "install", "-y", "jq"}); err != nil {
		return fmt.Errorf("failed to install jq: %w", err)
	}

	// Step 2: Write the OCI runtime script
	runtimePath := "/usr/local/bin/containarium-runtime"
	script := ociRuntimeScript()
	if err := m.incus.WriteFile(containerName, runtimePath, []byte(script), "0755"); err != nil {
		return fmt.Errorf("failed to write OCI runtime script: %w", err)
	}

	// Step 3: Merge our runtime config into daemon.json using jq
	// This preserves any existing daemon.json settings (log drivers, registries, etc.)
	mergeScript := `
if [ -f /etc/docker/daemon.json ]; then
  jq -s '.[0] * .[1]' /etc/docker/daemon.json /dev/stdin <<'JSONEOF' > /etc/docker/daemon.json.tmp && mv /etc/docker/daemon.json.tmp /etc/docker/daemon.json
{"default-runtime":"containarium","runtimes":{"containarium":{"path":"/usr/local/bin/containarium-runtime"}}}
JSONEOF
else
  mkdir -p /etc/docker
  cat > /etc/docker/daemon.json <<'JSONEOF'
{"default-runtime":"containarium","runtimes":{"containarium":{"path":"/usr/local/bin/containarium-runtime"}}}
JSONEOF
fi
`
	if err := m.incus.Exec(containerName, []string{"bash", "-c", mergeScript}); err != nil {
		return fmt.Errorf("failed to configure daemon.json: %w", err)
	}

	// Step 4: Restart Docker to pick up the new default runtime
	if err := m.incus.Exec(containerName, []string{"systemctl", "restart", "docker"}); err != nil {
		return fmt.Errorf("failed to restart docker: %w", err)
	}

	return nil
}

// installCgroupWrappers installs wrapper scripts at /usr/local/bin/ that
// intercept podman/docker CLI calls and inject cgroup resource limits.
func (m *Manager) installCgroupWrappers(containerName string, podman bool, docker bool) error {
	type wrapper struct {
		realBinary  string
		wrapperPath string
	}

	var wrappers []wrapper
	if podman {
		wrappers = append(wrappers, wrapper{"/usr/bin/podman", "/usr/local/bin/podman"})
	}
	if docker {
		wrappers = append(wrappers, wrapper{"/usr/bin/docker", "/usr/local/bin/docker"})
	}

	for _, w := range wrappers {
		// Only install if the real binary exists
		if err := m.incus.Exec(containerName, []string{"test", "-x", w.realBinary}); err != nil {
			continue // binary not installed, skip
		}

		script := cgroupWrapperScript(w.realBinary)
		if err := m.incus.WriteFile(containerName, w.wrapperPath, []byte(script), "0755"); err != nil {
			return fmt.Errorf("failed to write cgroup wrapper %s: %w", w.wrapperPath, err)
		}
	}

	return nil
}

// UpgradeCgroupWrappers installs cgroup wrapper scripts on all running user
// containers. This is intended to be called on daemon startup to retrofit
// existing containers that were created before the wrapper feature existed.
// It is idempotent — WriteFile with overwrite mode replaces existing wrappers.
func (m *Manager) UpgradeCgroupWrappers() (int, error) {
	containers, err := m.incus.ListContainers()
	if err != nil {
		return 0, fmt.Errorf("failed to list containers: %w", err)
	}

	count := 0
	for _, c := range containers {
		if c.Role.IsCoreRole() {
			continue
		}
		if c.State != "Running" {
			continue
		}

		// Try both podman and docker; installCgroupWrappers checks test -x internally
		if err := m.installCgroupWrappers(c.Name, true, true); err != nil {
			log.Printf("Warning: failed to install cgroup wrappers on %s: %v", c.Name, err)
			continue
		}

		// Install OCI runtime for containers with Docker (catches Compose v2)
		if err := m.incus.Exec(c.Name, []string{"test", "-x", "/usr/bin/docker"}); err == nil {
			if err := m.installDockerOCIRuntime(c.Name); err != nil {
				log.Printf("Warning: failed to install OCI runtime on %s: %v", c.Name, err)
			}
		}

		count++
	}

	return count, nil
}
