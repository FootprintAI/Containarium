package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
)

// The gate's staging scope is the AUTHENTICATED SUBJECT, not the deploy
// name (#2414). An admin may deploy a box under any name, so a name-derived
// scope would let an admin-token proxy that forwards a user-chosen name read
// any tenant's staged dataset. These tests pin the rule.

// moveStaged moves the fixture's staged dataset (staged under alice) to the
// same ref under owner, so only owner's staging directory holds it.
func moveStaged(t *testing.T, f *gateFixture, owner string) {
	t.Helper()
	dst := filepath.Join(f.srv.guardrailStagingRoot, owner, "ds1")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.staged, dst); err != nil {
		t.Fatal(err)
	}
	f.staged = dst
}

// TestDeployGate_AdminCannotReadAnotherTenantsStagingByName is #2414
// acceptance criterion 1: an admin caller naming tenant alice does not get
// alice's staged dataset, even with a valid attestation for it. The deploy
// is refused and no box is created.
func TestDeployGate_AdminCannotReadAnotherTenantsStagingByName(t *testing.T) {
	f := newGateFixture(t) // valid attestation over <root>/alice/ds1
	f.caller = adminWithScopes(auth.ScopeContainersWrite)
	f.req.Name = "alice"
	_, err := f.deploy(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "staging_ref") {
		t.Fatalf("admin deploy naming alice = %v, want FailedPrecondition on staging_ref (alice's staged data is not the admin's)", err)
	}
	if len(f.boxes.created) != 0 || len(f.boxes.events) != 0 {
		t.Fatalf("refused deploy touched the backend: created %v, events %v", f.boxes.created, f.boxes.events)
	}
	f.assertNoSnapshotLeft(t)
}

// TestDeployGate_AdminReadsItsOwnStagingWhateverTheName: the admin's ref
// resolves under the admin's own subject, whatever name the box gets.
func TestDeployGate_AdminReadsItsOwnStagingWhateverTheName(t *testing.T) {
	f := newGateFixture(t)
	moveStaged(t, f, "ops") // adminWithScopes authenticates as "ops"
	f.caller = adminWithScopes(auth.ScopeContainersWrite)
	f.req.Name = "alice"
	if _, err := f.deploy(t); err != nil {
		t.Fatalf("admin deploy of its own staged dataset: %v", err)
	}
	if len(f.boxes.created) != 1 || f.boxes.created[0] != "alice" {
		t.Fatalf("created %v, want one box for alice", f.boxes.created)
	}
	assertDelivered(t, f.boxes, f.files)
	f.assertNoSnapshotLeft(t)
}

// TestDeployGate_TenantNamingAnotherTenantIsDenied is #2414 acceptance
// criterion 2: non-admin behaviour is unchanged. Tenant alice naming bob is
// PERMISSION_DENIED before the gate runs, even with bob's dataset staged and
// validly attested.
func TestDeployGate_TenantNamingAnotherTenantIsDenied(t *testing.T) {
	f := newGateFixture(t)
	moveStaged(t, f, "bob")
	f.req.Name = "bob" // caller stays tenant alice
	_, err := f.deploy(t)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("alice deploying as bob = %v, want PermissionDenied", err)
	}
	if len(f.boxes.created) != 0 || len(f.boxes.events) != 0 {
		t.Fatalf("denied deploy touched the backend: created %v, events %v", f.boxes.created, f.boxes.events)
	}
	f.assertNoSnapshotLeft(t)
}
