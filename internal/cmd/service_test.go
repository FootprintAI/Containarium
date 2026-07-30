//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/hostcheck"
)

// TestBackupUnitStateDirectory covers the sibling unit shipped as a plain file
// (scripts/containarium-backup.service) rather than generated from a Go
// template, so nothing else in the build would notice it regressing.
//
// That unit runs ProtectSystem=strict and needs /var/lib/containarium writable
// for the backup JSON index. Nothing on the host creates that directory --
// hacks/install.sh declares DATA_DIR=/var/lib/containarium but never creates it,
// and the one `mkdir -p /var/lib/containarium` in the tree runs inside a
// container via incus exec. StateDirectory= is what makes systemd create it and
// grant write access; an ignore-if-absent ReadWritePaths entry alone would let
// the unit start with the path read-only, so the index could not be written.
func TestBackupUnitStateDirectory(t *testing.T) {
	// Relative to this package dir; the unit ships in the repo, not embedded.
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "containarium-backup.service"))
	if err != nil {
		t.Fatalf("read backup unit: %v", err)
	}
	var stateDir string
	var rwFields []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "StateDirectory="):
			stateDir = strings.TrimPrefix(line, "StateDirectory=")
		case strings.HasPrefix(line, "ReadWritePaths="):
			rwFields = strings.Fields(strings.TrimPrefix(line, "ReadWritePaths="))
		}
	}
	if stateDir != "containarium" {
		t.Errorf("expected StateDirectory=containarium (creates + grants /var/lib/containarium), got %q", stateDir)
	}
	// If the path is also listed explicitly, it must be ignore-if-absent so the
	// entry itself can never fail namespace setup.
	if slices.Contains(rwFields, "/var/lib/containarium") {
		t.Errorf("ReadWritePaths lists /var/lib/containarium without the \"-\" ignore-if-absent prefix: %v", rwFields)
	}
}

// TestOptContainariumIsIgnoreIfAbsent pins the "-" prefix on the one
// ReadWritePaths entry Containarium owns rather than inherits.
//
// ProtectSystem=strict makes systemd build the unit's mount namespace before
// the daemon executes, and a listed path that does not exist fails that setup
// with status=226/NAMESPACE -- an opaque crashloop naming neither the path nor
// the setting. Every other entry is a standard system directory that already
// exists; /opt/containarium is ours and may not. `service install` / `pool
// join` create it, but a hand-installed unit (scripts/containarium.service,
// the Terraform startup scripts) has no such guarantee, so the prefix is what
// degrades that case into a legible `containarium doctor` finding.
func TestOptContainariumIsIgnoreIfAbsent(t *testing.T) {
	var fields []string
	for _, line := range strings.Split(systemdServiceTemplate, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ReadWritePaths=") {
			fields = strings.Fields(strings.TrimPrefix(line, "ReadWritePaths="))
			break
		}
	}
	if len(fields) == 0 {
		t.Fatal("systemdServiceTemplate has no ReadWritePaths= line")
	}
	if !slices.Contains(fields, "-/opt/containarium") {
		t.Errorf("expected -/opt/containarium (ignore-if-absent) in ReadWritePaths, got %v", fields)
	}
}

// TestSystemdServiceDoesNotHardRequireIncus guards the boot-resilience contract.
//
// With Requires=incus.service, a transient incus failure at boot fails
// containarium.service's *start job*. Restart=on-failure does not retry job
// failures, so the daemon stays dead even after incus recovers seconds later --
// observed on a pool member, where it means silently dropping out of the pool
// until a human notices. After= alone gives the ordering; Wants= keeps a bad
// incus start from being terminal, and Restart=on-failure handles "not ready yet".
func TestSystemdServiceDoesNotHardRequireIncus(t *testing.T) {
	var after, requires, wants []string
	for _, line := range strings.Split(systemdServiceTemplate, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "After="):
			after = strings.Fields(strings.TrimPrefix(line, "After="))
		case strings.HasPrefix(line, "Requires="):
			requires = strings.Fields(strings.TrimPrefix(line, "Requires="))
		case strings.HasPrefix(line, "Wants="):
			wants = strings.Fields(strings.TrimPrefix(line, "Wants="))
		}
	}
	if slices.Contains(requires, "incus.service") {
		t.Error("systemdServiceTemplate has Requires=incus.service; use Wants= so a " +
			"transient incus failure does not permanently kill the daemon's start job")
	}
	if !slices.Contains(wants, "incus.service") {
		t.Errorf("systemdServiceTemplate should declare Wants=incus.service, got Wants=%v", wants)
	}
	if !slices.Contains(after, "incus.service") {
		t.Errorf("systemdServiceTemplate must keep After=incus.service for ordering, got After=%v", after)
	}
}

// TestSystemdServiceReadWritePathsCoverDoctorContract guards against the unit's
// ProtectSystem=strict sandbox drifting away from the paths the daemon's own
// doctor self-check requires writable. A path the doctor requires but the unit
// denies makes a freshly-installed host boot DEGRADED (this is exactly what
// happened when /var/log — which useradd touches via /var/log/lastlog — was
// missing from ReadWritePaths). The generated unit's ReadWritePaths must be a
// superset of hostcheck.DaemonWritablePaths.
func TestSystemdServiceReadWritePathsCoverDoctorContract(t *testing.T) {
	var rwLine string
	for _, line := range strings.Split(systemdServiceTemplate, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ReadWritePaths=") {
			rwLine = strings.TrimSpace(line)
			break
		}
	}
	if rwLine == "" {
		t.Fatal("systemdServiceTemplate has no ReadWritePaths= line")
	}
	granted := make(map[string]bool)
	for _, p := range strings.Fields(strings.TrimPrefix(rwLine, "ReadWritePaths=")) {
		// A leading "-" means "ignore if absent" (systemd.exec(5)); it is a
		// modifier, not part of the path, and the doctor contract is about
		// the path itself.
		granted[strings.TrimPrefix(p, "-")] = true
	}
	for _, required := range hostcheck.DaemonWritablePaths {
		if !granted[required] {
			t.Errorf("ReadWritePaths is missing %q (required by hostcheck.DaemonWritablePaths); "+
				"the host would boot DEGRADED. ReadWritePaths=%v", required, rwLine)
		}
	}
}
