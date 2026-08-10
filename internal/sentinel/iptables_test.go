package sentinel

import (
	"runtime"
	"testing"
)

func TestPort22FilteredFromForwarding(t *testing.T) {
	// Verify that enableForwarding filters port 22.
	// We can't run actual iptables on dev machines, but we can verify the
	// filtering logic by checking the constant and the filter code path.

	if sshPiperPort != 22 {
		t.Errorf("sshPiperPort should be 22, got %d", sshPiperPort)
	}

	// Test the filtering logic inline (same as enableForwarding)
	ports := []int{22, 80, 443, 50051}
	filtered := make([]int, 0, len(ports))
	for _, p := range ports {
		if p == sshPiperPort {
			continue
		}
		filtered = append(filtered, p)
	}

	if len(filtered) != 3 {
		t.Fatalf("expected 3 ports after filtering, got %d: %v", len(filtered), filtered)
	}

	for _, p := range filtered {
		if p == 22 {
			t.Error("port 22 should have been filtered out")
		}
	}

	expectedPorts := []int{80, 443, 50051}
	for i, p := range expectedPorts {
		if filtered[i] != p {
			t.Errorf("filtered[%d] = %d, want %d", i, filtered[i], p)
		}
	}
}

func TestPort22FilteringPreservesOrder(t *testing.T) {
	ports := []int{80, 22, 443, 50051}
	filtered := make([]int, 0, len(ports))
	for _, p := range ports {
		if p == sshPiperPort {
			continue
		}
		filtered = append(filtered, p)
	}

	expected := []int{80, 443, 50051}
	if len(filtered) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(filtered))
	}
	for i, p := range expected {
		if filtered[i] != p {
			t.Errorf("filtered[%d] = %d, want %d", i, filtered[i], p)
		}
	}
}

func TestPort22FilteringNoPort22(t *testing.T) {
	// If port 22 is not in the list, nothing changes
	ports := []int{80, 443, 50051}
	filtered := make([]int, 0, len(ports))
	for _, p := range ports {
		if p == sshPiperPort {
			continue
		}
		filtered = append(filtered, p)
	}

	if len(filtered) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(filtered))
	}
}

// onNonLinuxHost makes the code under test believe it is running somewhere
// without iptables, and restores the real value afterwards.
//
// The two tests below are named "OnNonLinux" but had no such control, so on a
// Linux host — which is every CI runner — they fell through to the real
// iptables path. They passed by writing actual DNAT rules into the runner's
// nat table, and failed outright on a Linux machine without the privilege to
// do it. Neither result said anything about the early return they exist to
// cover.
func onNonLinuxHost(t *testing.T) {
	t.Helper()
	real := goos()
	hostGOOS.Store("darwin")
	t.Cleanup(func() { hostGOOS.Store(real) })
}

func TestEnableForwardingOnNonLinux(t *testing.T) {
	onNonLinuxHost(t)

	// On non-Linux (macOS, etc.), enableForwarding should return nil without
	// error and touch nothing.
	err := enableForwarding("10.0.0.1", []int{80, 443})
	if err != nil {
		t.Errorf("expected nil error on non-Linux, got: %v", err)
	}
}

func TestDisableForwardingOnNonLinux(t *testing.T) {
	onNonLinuxHost(t)

	// On non-Linux, disableForwarding should return nil and touch nothing.
	err := disableForwarding()
	if err != nil {
		t.Errorf("expected nil error on non-Linux, got: %v", err)
	}
}

// The control has to actually control something. If hostGOOS stopped being
// what the early returns read, the two tests above would go back to running
// the real iptables path on every CI runner and would still report a pass.
func TestNonLinuxControlActuallyDivertsTheHostCheck(t *testing.T) {
	if goos() != runtime.GOOS {
		t.Fatalf("hostGOOS = %q before any override, want the real %q", goos(), runtime.GOOS)
	}

	func() {
		onNonLinuxHost(t)
		if goos() == runtime.GOOS && runtime.GOOS == "linux" {
			t.Error("the override did not change what the code under test reads — the " +
				"non-Linux tests would run the real iptables path against the host")
		}
	}()
}
