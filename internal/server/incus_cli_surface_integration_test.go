//go:build incus

package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Which `incus` CLI commands the migration runner uses actually exist.
//
// Found the hard way: #1390's test called `incus snapshot <c> <name>` — copied
// from pkg/core/incus/migration.go, which is the PRODUCTION migration runner —
// and Incus 6.0.0 answered:
//
//	Error: unknown command "reg19801-container" for "incus snapshot"
//
// `incus snapshot` is a command GROUP in Incus 6.x, not a verb. Every
// MoveContainer test substitutes a fake MigrationRunner, and dual_server.go
// wires the real ExecRunner only in production — so these six shell-outs have
// never run against a real Incus in CI, and at least one of them cannot work.
//
// This file probes each command against a real Incus and records the answer,
// so the fix is designed against demonstrated behaviour rather than against a
// plausible reading of the CLI docs. Same ordering that turned #1160c's
// premise from plausible into disproved (#1384) — applied here to a defect in
// shipped code rather than to a design.
//
// It asserts nothing about which syntax SHOULD win. It asserts that for each
// operation, at least one candidate works, and it logs which — because the
// point is to learn the answer, and a probe that presumes it is not a probe.

// incusRun runs the incus CLI and returns combined output plus whether it
// succeeded, without failing the test — a non-zero exit is data here.
func incusRun(args ...string) (string, bool) {
	out, err := exec.Command("incus", args...).CombinedOutput() // #nosec G204 -- literal args below
	return strings.TrimSpace(string(out)), err == nil
}

// probeCandidates tries each candidate argv for one operation and returns the
// first that worked, or "" if none did.
func probeCandidates(t *testing.T, op string, candidates [][]string) []string {
	t.Helper()
	for _, argv := range candidates {
		out, ok := incusRun(argv...)
		if ok {
			t.Logf("FACT [%s]: `incus %s` works", op, strings.Join(argv, " "))
			return argv
		}
		t.Logf("  [%s] `incus %s` failed: %s", op, strings.Join(argv, " "), firstLine(out))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// TestIntegrationIncus_MigrationRunnerCLISurface establishes the syntax for
// every command pkg/core/incus/migration.go shells out to.
//
// Deliberately NOT a fix: this PR establishes facts. The fix to ExecRunner is
// its own change, designed against what this records.
func TestIntegrationIncus_MigrationRunnerCLISurface(t *testing.T) {
	s, _, _ := encTestEnv(t)

	if v, ok := incusRun("version"); ok {
		t.Logf("incus version:\n%s", v)
	}

	tenant := fmt.Sprintf("cli%d", os.Getpid())
	instance := tenant + "-container"
	t.Cleanup(func() { incusenv.DeleteInstance(t, instance) })

	ctx, cancel := context.WithTimeout(
		tenantWithScopes(tenant, auth.ScopeContainersWrite), 25*time.Minute)
	defer cancel()
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Username:  tenant,
		Image:     incusenv.BoxImage(),
		OsType:    pb.OSType_OS_TYPE_UBUNTU_2404,
		Resources: &pb.ResourceLimits{Disk: "5GB"},
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}

	const snap = "probe-snap"

	// 1. Snapshot — the one already known to be wrong.
	snapArgv := probeCandidates(t, "snapshot", [][]string{
		{"snapshot", instance, snap},           // what ExecRunner.Snapshot does today
		{"snapshot", "create", instance, snap}, // Incus 6.x command group
	})
	if snapArgv == nil {
		t.Fatal("no candidate creates a snapshot — the migration runner cannot work at all, and " +
			"the fix needs a syntax this test does not know about")
	}
	if snapArgv[0] == "snapshot" && len(snapArgv) == 3 {
		t.Log("ExecRunner.Snapshot's current syntax works on this Incus; the failure seen in " +
			"#1390's test came from somewhere else and needs re-examining")
	} else {
		t.Errorf("DEFECT: ExecRunner.Snapshot shells out to `incus snapshot <c> <n>`, which this "+
			"Incus rejects. The working form is `incus %s`. MoveContainer fails at phase 1 on "+
			"this version, and no test caught it because every move test uses a fake runner",
			strings.Join(snapArgv, " "))
	}

	// 2. DeleteSnapshot — `incus delete <c>/<snap>`.
	delArgv := probeCandidates(t, "delete-snapshot", [][]string{
		{"delete", instance + "/" + snap},      // what ExecRunner.DeleteSnapshot does today
		{"snapshot", "delete", instance, snap}, // the command-group form
	})
	if delArgv == nil {
		t.Error("DEFECT: no candidate deletes a snapshot — a migration would leave its sync " +
			"snapshots behind on every run")
	}

	// 3/4. Stop and Start, used either side of the cutover.
	if argv := probeCandidates(t, "stop", [][]string{{"stop", instance}}); argv == nil {
		t.Error("DEFECT: `incus stop` failed — the migration cutover cannot stop the source")
	}
	if argv := probeCandidates(t, "start", [][]string{{"start", instance}}); argv == nil {
		t.Error("DEFECT: `incus start` failed — a rolled-back migration cannot restart the source")
	}

	// 5/6. Copy. Not run for real (it needs a second daemon), so only the
	// argument shape is checked — `--help` proves the flags parse, which is
	// what the runner gets wrong when a CLI changes under it.
	if out, ok := incusRun("copy", "--help"); !ok {
		t.Errorf("DEFECT: `incus copy --help` failed: %s", firstLine(out))
	} else {
		for _, flag := range []string{"--instance-only", "--refresh", "--storage"} {
			if !strings.Contains(out, flag) {
				t.Errorf("DEFECT: `incus copy` does not advertise %s, which CopyInitial/CopyRefresh "+
					"pass — the migration would fail on an unknown flag", flag)
			}
		}
	}
}
