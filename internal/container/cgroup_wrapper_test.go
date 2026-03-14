package container

import (
	"strings"
	"testing"
)

func TestCgroupWrapperScript_Podman(t *testing.T) {
	script := cgroupWrapperScript("/usr/bin/podman")

	// Shebang
	if !strings.HasPrefix(script, "#!/bin/bash\n") {
		t.Error("wrapper script must start with #!/bin/bash shebang")
	}

	// Real binary path
	if !strings.Contains(script, "REAL=/usr/bin/podman") {
		t.Error("wrapper script must set REAL to the real binary path")
	}

	// Memory cgroup read
	if !strings.Contains(script, "/sys/fs/cgroup/memory.max") {
		t.Error("wrapper script must read memory.max from cgroup v2")
	}

	// CPU cgroup read
	if !strings.Contains(script, "/sys/fs/cgroup/cpu.max") {
		t.Error("wrapper script must read cpu.max from cgroup v2")
	}

	// Flag detection for --memory
	if !strings.Contains(script, "--memory=*|--memory|-m=*|-m") {
		t.Error("wrapper script must detect existing --memory / -m flags")
	}

	// Flag detection for --cpus
	if !strings.Contains(script, "--cpus=*|--cpus") {
		t.Error("wrapper script must detect existing --cpus flag")
	}

	// exec passthrough
	if !strings.Contains(script, "exec $REAL") {
		t.Error("wrapper script must exec the real binary")
	}

	// Docker Compose v2 limitation comment
	if !strings.Contains(script, "Docker Compose v2") {
		t.Error("wrapper script must document Docker Compose v2 limitation")
	}
}

func TestCgroupWrapperScript_Docker(t *testing.T) {
	script := cgroupWrapperScript("/usr/bin/docker")

	if !strings.Contains(script, "REAL=/usr/bin/docker") {
		t.Error("wrapper script must set REAL to /usr/bin/docker")
	}
}

func TestCgroupWrapperScript_AwkFormat(t *testing.T) {
	script := cgroupWrapperScript("/usr/bin/podman")

	// The awk printf format should be %.2f (after Go fmt.Sprintf processing)
	// In the shell script, it appears as printf \"%.2f\" inside double-quoted awk
	if !strings.Contains(script, `printf \"%.2f\"`) {
		t.Errorf("wrapper script should contain awk printf with %%.2f format, got:\n%s",
			extractLine(script, "printf"))
	}
}

func TestCgroupWrapperScript_RunCreateInterception(t *testing.T) {
	script := cgroupWrapperScript("/usr/bin/podman")

	if !strings.Contains(script, "run|create)") {
		t.Error("wrapper script must intercept run and create subcommands")
	}
}

func TestCgroupWrapperScript_MemoryMaxHandling(t *testing.T) {
	script := cgroupWrapperScript("/usr/bin/podman")

	// Must skip "max" value (unlimited)
	if !strings.Contains(script, `"$MEM" != "max"`) {
		t.Error("wrapper script must skip memory injection when value is 'max'")
	}
}

func TestCgroupWrapperScript_CpuMaxHandling(t *testing.T) {
	script := cgroupWrapperScript("/usr/bin/podman")

	// Must skip "max" quota (unlimited)
	if !strings.Contains(script, `"$QUOTA" != "max"`) {
		t.Error("wrapper script must skip CPU injection when quota is 'max'")
	}
}

// --- OCI Runtime Script Tests ---

func TestOCIRuntimeScript_Shebang(t *testing.T) {
	script := ociRuntimeScript()
	if !strings.HasPrefix(script, "#!/bin/bash\n") {
		t.Error("OCI runtime script must start with #!/bin/bash shebang")
	}
}

func TestOCIRuntimeScript_RealRuncPath(t *testing.T) {
	script := ociRuntimeScript()
	if !strings.Contains(script, "REAL_RUNC=/usr/bin/runc") {
		t.Error("OCI runtime script must set REAL_RUNC to /usr/bin/runc")
	}
}

func TestOCIRuntimeScript_CreateInterception(t *testing.T) {
	script := ociRuntimeScript()
	// Must scan all args for "create" (not just $1) because Docker/containerd
	// passes global options (--root, --log, etc.) before the subcommand
	if !strings.Contains(script, `"create"`) {
		t.Error("OCI runtime script must detect the 'create' subcommand")
	}
	if !strings.Contains(script, "IS_CREATE") {
		t.Error("OCI runtime script must use IS_CREATE flag to handle global options before subcommand")
	}
}

func TestOCIRuntimeScript_BundleParsing(t *testing.T) {
	script := ociRuntimeScript()
	if !strings.Contains(script, "--bundle") {
		t.Error("OCI runtime script must parse --bundle argument")
	}
	if !strings.Contains(script, "config.json") {
		t.Error("OCI runtime script must reference config.json")
	}
}

func TestOCIRuntimeScript_MemoryInjection(t *testing.T) {
	script := ociRuntimeScript()

	// Must read LXC memory limit
	if !strings.Contains(script, "/sys/fs/cgroup/memory.max") {
		t.Error("OCI runtime script must read memory.max from cgroup v2")
	}

	// Must skip if memory is "max" (unlimited)
	if !strings.Contains(script, `"$LXC_MEM" != "max"`) {
		t.Error("OCI runtime script must skip memory injection when value is 'max'")
	}

	// Must use jq to set memory limit in config.json
	if !strings.Contains(script, "memory.limit") {
		t.Error("OCI runtime script must inject memory.limit into OCI spec")
	}
}

func TestOCIRuntimeScript_CPUInjection(t *testing.T) {
	script := ociRuntimeScript()

	// Must read LXC CPU limit
	if !strings.Contains(script, "/sys/fs/cgroup/cpu.max") {
		t.Error("OCI runtime script must read cpu.max from cgroup v2")
	}

	// Must skip if quota is "max" (unlimited)
	if !strings.Contains(script, `"$QUOTA" != "max"`) {
		t.Error("OCI runtime script must skip CPU injection when quota is 'max'")
	}

	// Must use jq to set cpu quota and period
	if !strings.Contains(script, "cpu.quota") {
		t.Error("OCI runtime script must inject cpu.quota into OCI spec")
	}
	if !strings.Contains(script, "cpu.period") {
		t.Error("OCI runtime script must inject cpu.period into OCI spec")
	}
}

func TestOCIRuntimeScript_JqUsage(t *testing.T) {
	script := ociRuntimeScript()
	if !strings.Contains(script, "jq") {
		t.Error("OCI runtime script must use jq for JSON manipulation")
	}
}

func TestOCIRuntimeScript_Passthrough(t *testing.T) {
	script := ociRuntimeScript()
	// Non-create commands should pass through to real runc
	if !strings.Contains(script, "exec $REAL_RUNC") {
		t.Error("OCI runtime script must exec the real runc binary")
	}
}

func TestOCIRuntimeScript_SkipsIfLimitsSet(t *testing.T) {
	script := ociRuntimeScript()

	// Must check existing OCI memory limit before injecting
	if !strings.Contains(script, "OCI_MEM") {
		t.Error("OCI runtime script must check existing memory limit in OCI spec")
	}

	// Must check existing OCI CPU quota before injecting
	if !strings.Contains(script, "OCI_QUOTA") {
		t.Error("OCI runtime script must check existing CPU quota in OCI spec")
	}
}

func TestOCIRuntimeScript_LXCFSBindMounts(t *testing.T) {
	script := ociRuntimeScript()

	// Must detect LXCFS
	if !strings.Contains(script, "lxcfs on /proc/meminfo") {
		t.Error("OCI runtime script must detect LXCFS via mount check")
	}

	// Must bind-mount key /proc files for correct free/top output
	for _, procFile := range []string{"/proc/meminfo", "/proc/cpuinfo", "/proc/stat", "/proc/uptime", "/proc/loadavg", "/proc/diskstats", "/proc/swaps"} {
		if !strings.Contains(script, `"destination":"`+procFile+`"`) {
			t.Errorf("OCI runtime script must bind-mount %s from LXCFS", procFile)
		}
	}

	// Must append to mounts array
	if !strings.Contains(script, ".mounts += $lxcfs") {
		t.Error("OCI runtime script must append LXCFS mounts to OCI spec mounts array")
	}
}

// extractLine returns the first line from s that contains substr, for error messages.
func extractLine(s, substr string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, substr) {
			return strings.TrimSpace(line)
		}
	}
	return "<not found>"
}
