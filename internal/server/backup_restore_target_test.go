package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// restoreTargetOps records which containers a restore touches.
type restoreTargetOps struct{ touched map[string]int }

func (o *restoreTargetOps) Exec(c string, _ []string) error { o.touched[c]++; return nil }
func (o *restoreTargetOps) ExecWithOutput(c string, _ []string) (string, string, error) {
	o.touched[c]++
	return "", "", nil
}
func (o *restoreTargetOps) ReadFile(string, string) ([]byte, error) { return nil, os.ErrNotExist }
func (o *restoreTargetOps) WriteFile(c, _ string, _ []byte, _ string) error {
	o.touched[c]++
	return nil
}

// newRestoreTargetServer seeds one plaintext pg_dump record for alice and
// tenant containers for alice and scratch.
func newRestoreTargetServer(t *testing.T) (*BackupServer, *restoreTargetOps, string) {
	t.Helper()
	dir := t.TempDir()
	const id = "alice-app-20261003T010000Z"
	dump := []byte("PGDMP-test-archive")
	sum := sha256.Sum256(dump)
	loc := filepath.Join(dir, id+".dump")
	if err := os.WriteFile(loc, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(&backup.Record{
		ID: id, Username: "alice", Database: "app", CreatedAt: time.Now().UTC(),
		SizeBytes: int64(len(dump)), SHA256: hex.EncodeToString(sum[:]),
		Destination: backup.DestLocal, Location: loc, Engine: backup.EnginePostgres,
	})
	if err := os.WriteFile(filepath.Join(dir, id+".meta.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	backend := newFakeSandboxBackend()
	for _, n := range []string{"alice-container", "scratch-container"} {
		if err := backend.CreateContainer(incus.ContainerConfig{Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	ops := &restoreTargetOps{touched: map[string]int{}}
	return &BackupServer{
		containers: &ContainerServer{manager: container.NewWithBackend(backend)},
		mgr:        backup.NewManager(ops, nil, dir),
	}, ops, id
}

func restoreCtx(user string, admin bool) context.Context {
	roles := []string{"user"}
	if admin {
		roles = []string{auth.RoleAdmin}
	}
	return auth.ContextWithTestSubjectScopes(context.Background(), user, roles, []string{auth.ScopeBackupsWrite})
}

// #2403: RestoreBackupRequest.target_container is honoured, and empty
// still means the backup's own source container.
func TestRestoreBackup_TargetContainer(t *testing.T) {
	for _, tc := range []struct {
		name, target, want, untouched string
	}{
		{"empty target restores in place", "", "alice-container", "scratch-container"},
		{"named target is restored into, source untouched", "scratch-container", "scratch-container", "alice-container"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ops, id := newRestoreTargetServer(t)
			if _, err := s.RestoreBackup(restoreCtx("ops", true), &pb.RestoreBackupRequest{Id: id, TargetContainer: tc.target}); err != nil {
				t.Fatalf("RestoreBackup: %v", err)
			}
			if ops.touched[tc.want] == 0 {
				t.Errorf("restore never reached %s: %v", tc.want, ops.touched)
			}
			if ops.touched[tc.untouched] != 0 {
				t.Errorf("%s was touched: %v", tc.untouched, ops.touched)
			}
		})
	}
}

// A target is written to, so the caller must be authorized for the
// target's tenant too, and it must resolve to a tenant container that
// exists; every refusal precedes any container command.
func TestRestoreBackup_TargetContainerRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		target string
		code   codes.Code
	}{
		{"tenant may not restore into another tenant's container", restoreCtx("alice", false), "scratch-container", codes.PermissionDenied},
		{"target that is not a tenant container", restoreCtx("ops", true), "scratch", codes.InvalidArgument},
		{"target that does not exist", restoreCtx("ops", true), "ghost-container", codes.NotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ops, id := newRestoreTargetServer(t)
			_, err := s.RestoreBackup(tc.ctx, &pb.RestoreBackupRequest{Id: id, TargetContainer: tc.target})
			if status.Code(err) != tc.code {
				t.Fatalf("err = %v, want code %v", err, tc.code)
			}
			if len(ops.touched) != 0 {
				t.Errorf("containers touched before the refusal: %v", ops.touched)
			}
		})
	}
}
