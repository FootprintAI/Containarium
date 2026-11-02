package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"filippo.io/age"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- #3357: RestoreBoxBackup at the server boundary ---

// boxRestoreFixture is a daemon with a whole-box backup of alice's box, the
// Incus mock behind a real container manager, and the identity that opens
// the backup. bob's database backup and box exist too.
type boxRestoreFixture struct {
	s        *BackupServer
	backend  *incustest.MockBackend
	id       string // the BOX record
	identity string
}

func newBoxRestoreFixture(t *testing.T) *boxRestoreFixture {
	t.Helper()
	dir := t.TempDir()
	seedBackupRecord(t, dir, "alice-app-20261003T010000Z", "alice")
	seedBackupRecord(t, dir, bobBackupID, "bob")
	backend := incustest.NewMockBackend()
	for _, n := range []string{"alice-container", "bob-container"} {
		if err := backend.CreateContainer(incus.ContainerConfig{Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	backend.Archives = map[string][]byte{"alice-container": minimalBoxArchive(t)}
	backend.GetContainerMetricsFunc = func(name string) (*incus.ContainerMetrics, error) {
		return &incus.ContainerMetrics{Name: name, DiskUsageBytes: 1 << 20}, nil
	}
	cs := &ContainerServer{manager: container.NewWithBackend(backend)}
	mgr := backup.NewManager(&restoreTargetOps{touched: map[string]int{}}, nil, dir, backup.WithBoxOps(cs.manager))
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := mgr.CreateBox(backup.BoxCreateOptions{
		Username: "alice", ContainerName: "alice-container", Destination: backup.DestLocal,
		AgeRecipient: key.Recipient().String(), KeyMode: backup.KeyModeAgeRecipient,
	})
	if err != nil {
		t.Fatalf("CreateBox: %v", err)
	}
	return &boxRestoreFixture{
		s:        &BackupServer{containers: cs, mgr: mgr},
		backend:  backend,
		id:       rec.ID,
		identity: key.String(),
	}
}

// boxes lists the instances the mock holds, other than the two tenant
// boxes it starts with.
func (f *boxRestoreFixture) newBoxes() []string {
	var out []string
	for n := range f.backend.Containers {
		if n != "alice-container" && n != "bob-container" {
			out = append(out, n)
		}
	}
	return out
}

func boxRestoreCtx(user string, admin bool) context.Context {
	roles := []string{"user"}
	if admin {
		roles = []string{auth.RoleAdmin}
	}
	return auth.ContextWithTestSubjectScopes(context.Background(), user, roles, []string{auth.ScopeBackupsWrite})
}

// An admin restoring with no target gets "<source box>-restored", stopped,
// through the container manager and the Incus mock.
func TestRestoreBoxBackup_AdminDefaultTarget(t *testing.T) {
	f := newBoxRestoreFixture(t)
	resp, err := f.s.RestoreBoxBackup(boxRestoreCtx("ops", true), &pb.RestoreBoxBackupRequest{Id: f.id, AgeIdentity: f.identity})
	if err != nil {
		t.Fatalf("RestoreBoxBackup: %v", err)
	}
	if resp.Box != "alice-restored" || !strings.Contains(resp.Message, f.id) {
		t.Errorf("response = %+v, want box alice-restored and a message naming the backup", resp)
	}
	got := f.backend.Containers["alice-restored-container"]
	if got == nil || got.State != "Stopped" {
		t.Fatalf("restored box = %+v, want alice-restored-container, stopped", got)
	}
	if n := f.newBoxes(); len(n) != 1 {
		t.Errorf("new instances %v, want only the restored box", n)
	}
	if len(f.backend.Archives["alice-restored-container"]) == 0 {
		t.Error("the restored box was imported from nothing")
	}
}

// Q4 (decided 2026-11-01, fail closed): the caller must be authorized for
// the source backup's tenant AND the target box. A non-admin may restore
// only into a name inside its own tenant, so the default name works for
// admins only.
func TestRestoreBoxBackup_TargetAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  string
		force   bool
		stopped bool // stop alice-container first
		want    codes.Code
		wantBox string
	}{
		{name: "default name is another tenant: refused", want: codes.PermissionDenied},
		{name: "another tenant's box: refused", target: "bob", want: codes.PermissionDenied},
		{name: "own tenant, stopped, force: allowed", target: "alice", force: true, stopped: true, want: codes.OK, wantBox: "alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBoxRestoreFixture(t)
			if tc.stopped {
				f.backend.Containers["alice-container"].State = "Stopped"
			} else {
				f.backend.Containers["alice-container"].State = "Running"
			}
			resp, err := f.s.RestoreBoxBackup(boxRestoreCtx("alice", false), &pb.RestoreBoxBackupRequest{
				Id: f.id, TargetBox: tc.target, Force: tc.force, AgeIdentity: f.identity,
			})
			if status.Code(err) != tc.want {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want != codes.OK {
				if n := f.newBoxes(); len(n) != 0 {
					t.Errorf("a refused restore created %v", n)
				}
				return
			}
			if resp.Box != tc.wantBox {
				t.Errorf("box = %q, want %q", resp.Box, tc.wantBox)
			}
			if n := f.newBoxes(); len(n) != 0 {
				t.Errorf("staging instance left behind: %v", n)
			}
		})
	}
}

// The target and record rules surface as gRPC codes, and the identity
// never appears in an error.
func TestRestoreBoxBackup_Refusals(t *testing.T) {
	other, _ := age.GenerateX25519Identity()
	for _, tc := range []struct {
		name   string
		req    func(f *boxRestoreFixture) *pb.RestoreBoxBackupRequest
		setup  func(f *boxRestoreFixture)
		want   codes.Code
		forbid string
	}{
		{
			name: "missing id",
			req:  func(*boxRestoreFixture) *pb.RestoreBoxBackupRequest { return &pb.RestoreBoxBackupRequest{} },
			want: codes.InvalidArgument,
		},
		{
			name: "unknown backup",
			req: func(*boxRestoreFixture) *pb.RestoreBoxBackupRequest {
				return &pb.RestoreBoxBackupRequest{Id: "alice-box-20991231T000000Z"}
			},
			want: codes.NotFound,
		},
		{
			name: "a database backup",
			req: func(f *boxRestoreFixture) *pb.RestoreBoxBackupRequest {
				return &pb.RestoreBoxBackupRequest{Id: "alice-app-20261003T010000Z", TargetBox: "copy", AgeIdentity: f.identity}
			},
			want: codes.InvalidArgument,
		},
		{
			name: "a target name that is not a box name",
			req: func(f *boxRestoreFixture) *pb.RestoreBoxBackupRequest {
				return &pb.RestoreBoxBackupRequest{Id: f.id, TargetBox: "../etc", AgeIdentity: f.identity}
			},
			want: codes.InvalidArgument,
		},
		{
			name: "an existing target without force",
			req: func(f *boxRestoreFixture) *pb.RestoreBoxBackupRequest {
				return &pb.RestoreBoxBackupRequest{Id: f.id, TargetBox: "bob", AgeIdentity: f.identity}
			},
			want: codes.AlreadyExists,
		},
		{
			name:  "a running target with force",
			setup: func(f *boxRestoreFixture) { f.backend.Containers["bob-container"].State = "Running" },
			req: func(f *boxRestoreFixture) *pb.RestoreBoxBackupRequest {
				return &pb.RestoreBoxBackupRequest{Id: f.id, TargetBox: "bob", Force: true, AgeIdentity: f.identity}
			},
			want: codes.FailedPrecondition,
		},
		{
			name: "the wrong identity",
			req: func(f *boxRestoreFixture) *pb.RestoreBoxBackupRequest {
				return &pb.RestoreBoxBackupRequest{Id: f.id, AgeIdentity: other.String()}
			},
			want:   codes.InvalidArgument,
			forbid: other.String(),
		},
		{
			name: "no identity",
			req: func(f *boxRestoreFixture) *pb.RestoreBoxBackupRequest {
				return &pb.RestoreBoxBackupRequest{Id: f.id}
			},
			want: codes.InvalidArgument,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBoxRestoreFixture(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			_, err := f.s.RestoreBoxBackup(boxRestoreCtx("ops", true), tc.req(f))
			if status.Code(err) != tc.want {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.forbid != "" && strings.Contains(err.Error(), tc.forbid) {
				t.Error("the error carries the age identity")
			}
			if strings.Contains(err.Error(), "AGE-SECRET-KEY") {
				t.Errorf("the error carries key material: %v", err)
			}
			if n := f.newBoxes(); len(n) != 0 {
				t.Errorf("a refused restore created %v", n)
			}
		})
	}
}

// A non-admin cannot restore another tenant's backup at all, whatever the
// target (the source check precedes the target check).
func TestRestoreBoxBackup_SourceTenantRefused(t *testing.T) {
	f := newBoxRestoreFixture(t)
	_, err := f.s.RestoreBoxBackup(boxRestoreCtx("bob", false), &pb.RestoreBoxBackupRequest{Id: f.id, TargetBox: "bob", Force: true, AgeIdentity: f.identity})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}

func TestBoxRestoreStatus(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want codes.Code
	}{
		{fmt.Errorf("w: %w", backup.ErrNotBoxBackup), codes.InvalidArgument},
		{fmt.Errorf("w: %w", backup.ErrBoxBackupKey), codes.InvalidArgument},
		{fmt.Errorf("w: %w", backup.ErrBoxRestoreTargetExists), codes.AlreadyExists},
		{fmt.Errorf("w: %w", backup.ErrBoxRestoreTargetRunning), codes.FailedPrecondition},
		{fmt.Errorf("w: %w", backup.ErrBoxRestoreUnavailable), codes.FailedPrecondition},
		{fmt.Errorf("w: %w", backup.ErrBoxRestoreInProgress), codes.Aborted},
		{fmt.Errorf("w: %w", backup.ErrBoxBackupCorrupt), codes.DataLoss},
		{fmt.Errorf("w: %w", backup.ErrDumpTooLarge), codes.ResourceExhausted},
		{errors.New("incus said no"), codes.Internal},
	} {
		if got := status.Code(boxRestoreStatus(tc.err)); got != tc.want {
			t.Errorf("boxRestoreStatus(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
