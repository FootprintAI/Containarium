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
	"github.com/footprintai/containarium/pkg/core/incus"
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
// It calls the PRODUCTION ExecRunner methods rather than probing raw argv.
// Probing argv would only prove that some syntax works, while leaving
// ExecRunner free to use a different one — which is precisely the gap that let
// #1392 ship. What needs testing is the function the daemon actually calls.
//
// probeCandidates below survives for the one case that still needs it: #1390's
// test has to produce an Incus-level snapshot across Incus versions without
// depending on the runner it is investigating.

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

// TestIntegrationIncus_MigrationRunnerCLISurface exercises every command
// pkg/core/incus/migration.go shells out to, against a real Incus.
//
// This is the test #1392 needed and did not have. It fails if a future Incus
// changes any of these commands under the runner, instead of that surfacing as
// a migration failing in production.
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
	runner := &incus.ExecRunner{}

	// The production methods, called directly. Probing raw argv would prove
	// that SOME syntax works while leaving ExecRunner free to use another —
	// which is exactly the gap that let #1392 ship. What needs testing is the
	// function the daemon actually calls.
	if err := runner.Snapshot(instance, snap); err != nil {
		t.Fatalf("ExecRunner.Snapshot against a real Incus: %v\n\n"+
			"This is MoveContainer's FIRST call, so migration is broken end to end on this "+
			"version. Re-run the raw-syntax probe below to find the form this Incus accepts.", err)
	}
	t.Log("FACT: ExecRunner.Snapshot works against this Incus")

	// Idempotency is matched on the CLI's message text, so it breaks silently
	// whenever the CLI is corrected under it — as it just was. A retry after a
	// partial failure re-snapshots the same name and must not error.
	if err := runner.Snapshot(instance, snap); err != nil {
		t.Errorf("re-snapshotting an existing name failed: %v — MoveContainer retries after a "+
			"partial failure, and this is the swallow that makes that safe", err)
	}

	if err := runner.DeleteSnapshot(instance, snap); err != nil {
		t.Errorf("ExecRunner.DeleteSnapshot against a real Incus: %v — every migration would "+
			"leave its sync snapshots behind, pinning disk on both hosts", err)
	}
	// And deleting one that is already gone must stay a no-op, same reasoning.
	if err := runner.DeleteSnapshot(instance, snap); err != nil {
		t.Errorf("deleting an absent snapshot returned %v, want nil — a cleanup that already "+
			"ran must not fail the migration", err)
	}

	if err := runner.Stop(instance); err != nil {
		t.Errorf("ExecRunner.Stop: %v — the migration cutover cannot stop the source", err)
	}
	if err := runner.Start(instance); err != nil {
		t.Errorf("ExecRunner.Start: %v — a rolled-back migration cannot restart the source", err)
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
