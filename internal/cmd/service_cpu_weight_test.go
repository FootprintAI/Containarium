//go:build !windows && !containarium_client

package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/hostcheck"
)

// unitDirective returns the value of the LAST non-comment `key=` line in a
// unit's text ("" if absent) — systemd's last-wins semantics.
func unitDirective(unit, key string) string {
	val := ""
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, key+"=") {
			val = strings.TrimPrefix(line, key+"=")
		}
	}
	return val
}

// TestSystemdServiceCPUWeight: the generated daemon unit carries the
// platform CPU weight the doctor checks for (#2284), so `service install`
// alone protects the daemon — no separate drop-in to forget.
func TestSystemdServiceCPUWeight(t *testing.T) {
	want := strconv.Itoa(hostcheck.PlatformCPUWeight)
	if got := unitDirective(systemdServiceTemplate, "CPUWeight"); got != want {
		t.Errorf("systemdServiceTemplate CPUWeight=%q, want %q (hostcheck.PlatformCPUWeight)", got, want)
	}
	if got := unitDirective(systemdServiceTemplate, "CPUAccounting"); got != "yes" {
		t.Errorf("systemdServiceTemplate CPUAccounting=%q, want yes", got)
	}
}

// The shipped copy (scripts/containarium.service) is not generated from the
// template, so pin it to the same weight or the two drift apart silently.
func TestShippedUnitCPUWeightMatchesTemplate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "containarium.service"))
	if err != nil {
		t.Fatalf("read shipped unit: %v", err)
	}
	if got, want := unitDirective(string(raw), "CPUWeight"), unitDirective(systemdServiceTemplate, "CPUWeight"); got != want {
		t.Errorf("scripts/containarium.service CPUWeight=%q, template has %q", got, want)
	}
}

// TestEnsureIncusCPUWeightDropIn: `incusd` is installed from the distro /
// Zabbly package, so its unit is not ours to edit — the weight lands as a
// drop-in under incus.service.d, written by the same install step that
// writes the daemon unit, and idempotent like it.
func TestEnsureIncusCPUWeightDropIn(t *testing.T) {
	root := t.TempDir()
	if err := ensureIncusCPUWeightDropIn(root); err != nil {
		t.Fatalf("first write: %v", err)
	}
	path := filepath.Join(root, incusCPUWeightDropInPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("drop-in not written at %s: %v", path, err)
	}
	unit := string(raw)
	if !strings.HasPrefix(strings.TrimSpace(stripComments(unit)), "[Service]") {
		t.Errorf("drop-in must start with [Service]:\n%s", unit)
	}
	if got, want := unitDirective(unit, "CPUWeight"), strconv.Itoa(hostcheck.PlatformCPUWeight); got != want {
		t.Errorf("drop-in CPUWeight=%q, want %q", got, want)
	}
	if got := unitDirective(unit, "CPUAccounting"); got != "yes" {
		t.Errorf("drop-in CPUAccounting=%q, want yes", got)
	}
	if unitDirective(unit, "ExecStart") != "" || unitDirective(unit, "CPUQuota") != "" {
		t.Errorf("drop-in must only set weight — never ExecStart or a quota on incusd:\n%s", unit)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("drop-in mode = %o, want 0644 (no secrets, world-readable by convention)", info.Mode().Perm())
	}
	// Idempotent: a second run rewrites the same content without error.
	if err := ensureIncusCPUWeightDropIn(root); err != nil {
		t.Fatalf("second write: %v", err)
	}
	again, _ := os.ReadFile(path)
	if string(again) != unit {
		t.Error("second write changed the drop-in content")
	}
}

// The drop-in path must be the one systemd actually reads for the Zabbly /
// distro incus unit — incus.service, not a snap unit name.
func TestIncusCPUWeightDropInPath(t *testing.T) {
	if !strings.HasPrefix(incusCPUWeightDropInPath, "/etc/systemd/system/incus.service.d/") || !strings.HasSuffix(incusCPUWeightDropInPath, ".conf") {
		t.Errorf("incusCPUWeightDropInPath = %q", incusCPUWeightDropInPath)
	}
}

func stripComments(unit string) string {
	var out []string
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
