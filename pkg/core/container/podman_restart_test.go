package container

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// captureExec returns a Manager whose backend records every Exec command.
func captureExec() (*Manager, *[][]string) {
	var calls [][]string
	mock := &incustest.MockBackend{
		ExecFunc: func(_ string, command []string) error {
			calls = append(calls, command)
			return nil
		},
	}
	return NewWithBackend(mock), &calls
}

func hasCall(calls [][]string, match func([]string) bool) bool {
	for _, c := range calls {
		if match(c) {
			return true
		}
	}
	return false
}

func TestEnablePodmanRestartDurability_RootfulAndRootless(t *testing.T) {
	m, calls := captureExec()
	m.enablePodmanRestartDurability("cld-test", "alice")

	// Rootful: system podman-restart.service enabled.
	if !hasCall(*calls, func(c []string) bool {
		return len(c) >= 3 && c[0] == "systemctl" && c[1] == "enable" && c[2] == "podman-restart.service"
	}) {
		t.Error("expected `systemctl enable podman-restart.service`")
	}

	// Rootless: linger enabled for the tenant user.
	if !hasCall(*calls, func(c []string) bool {
		return len(c) >= 3 && c[0] == "loginctl" && c[1] == "enable-linger" && c[2] == "alice"
	}) {
		t.Error("expected `loginctl enable-linger alice`")
	}

	// Rootless: user podman-restart unit enabled via a bash script that takes
	// the username as its positional arg and symlinks the user unit.
	if !hasCall(*calls, func(c []string) bool {
		return len(c) >= 5 && c[0] == "bash" && c[1] == "-c" &&
			strings.Contains(c[2], "default.target.wants/podman-restart.service") &&
			c[len(c)-1] == "alice"
	}) {
		t.Error("expected the user podman-restart.service enable script with username arg")
	}
}

func TestEnablePodmanRestartDurability_NoUserSkipsRootless(t *testing.T) {
	m, calls := captureExec()
	m.enablePodmanRestartDurability("cld-test", "")

	// System unit still enabled.
	if !hasCall(*calls, func(c []string) bool {
		return len(c) >= 3 && c[0] == "systemctl" && c[2] == "podman-restart.service"
	}) {
		t.Error("expected system podman-restart.service enable even with no username")
	}
	// No rootless steps without a username.
	if hasCall(*calls, func(c []string) bool { return len(c) > 0 && c[0] == "loginctl" }) {
		t.Error("did not expect loginctl enable-linger with empty username")
	}
}
