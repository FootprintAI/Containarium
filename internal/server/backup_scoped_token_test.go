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

// seedBackupRecord writes one plaintext local backup record for user.
func seedBackupRecord(t *testing.T, dir, id, user string) {
	t.Helper()
	dump := []byte("PGDMP-" + id)
	sum := sha256.Sum256(dump)
	loc := filepath.Join(dir, id+".dump")
	if err := os.WriteFile(loc, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(&backup.Record{
		ID: id, Username: user, Database: "app", CreatedAt: time.Now().UTC(),
		SizeBytes: int64(len(dump)), SHA256: hex.EncodeToString(sum[:]),
		Destination: backup.DestLocal, Location: loc, Engine: backup.EnginePostgres,
	})
	if err := os.WriteFile(filepath.Join(dir, id+".meta.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// verifierServer holds backups for two tenants and a tenant container each.
func verifierServer(t *testing.T) (*ContainerServer, *BackupServer) {
	t.Helper()
	dir := t.TempDir()
	seedBackupRecord(t, dir, "alice-app-20261003T010000Z", "alice")
	seedBackupRecord(t, dir, "bob-app-20261003T010000Z", "bob")
	backend := newFakeSandboxBackend()
	for _, n := range []string{"alice-container", "bob-container"} {
		if err := backend.CreateContainer(incus.ContainerConfig{Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	cs := &ContainerServer{manager: container.NewWithBackend(backend)}
	return cs, &BackupServer{
		containers: cs,
		mgr:        backup.NewManager(&restoreTargetOps{touched: map[string]int{}}, nil, dir),
	}
}

// verifierCtx is the documented per-set verifier token (#2401): a non-admin
// token bound to ONE tenant, scopes exactly backups:read + backups:write.
func verifierCtx(tenant string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), tenant, []string{"user"},
		[]string{auth.ScopeBackupsRead, auth.ScopeBackupsWrite})
}

// TestBackupScopedToken_AllowsOwnBackupsOnly is the scope contract for the
// nightly backup verifier's token (#2401): it can list and verify its own
// tenant's backups, and nothing else — not another tenant's backups, not
// containers, not secrets.
func TestBackupScopedToken_AllowsOwnBackupsOnly(t *testing.T) {
	cs, bs := verifierServer(t)
	ctx := verifierCtx("alice")

	t.Run("ListBackups for the bound tenant succeeds and returns only its records", func(t *testing.T) {
		for _, username := range []string{"", "alice"} {
			resp, err := bs.ListBackups(ctx, &pb.ListBackupsRequest{Username: username})
			if err != nil {
				t.Fatalf("ListBackups(%q): %v", username, err)
			}
			if len(resp.Records) != 1 || resp.Records[0].Username != "alice" {
				t.Fatalf("ListBackups(%q) = %+v, want exactly alice's record", username, resp.Records)
			}
		}
	})

	t.Run("ListBackups naming another tenant never returns that tenant's records", func(t *testing.T) {
		resp, err := bs.ListBackups(ctx, &pb.ListBackupsRequest{Username: "bob"})
		if err != nil {
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("err = %v, want nil or PermissionDenied", err)
			}
			return
		}
		for _, r := range resp.Records {
			if r.Username != "alice" {
				t.Fatalf("leaked %s's record %s to alice's token", r.Username, r.Id)
			}
		}
	})

	t.Run("VerifyBackup for the bound tenant passes authorization", func(t *testing.T) {
		_, err := bs.VerifyBackup(ctx, &pb.VerifyBackupRequest{Id: "alice-app-20261003T010000Z", TargetUsername: "alice"})
		// The fake container ops cannot run a real restore, so the outcome
		// past authorization is not the point: it must not be an authz denial.
		if c := status.Code(err); c == codes.PermissionDenied || c == codes.Unauthenticated {
			t.Fatalf("VerifyBackup on own backup was refused by authz: %v", err)
		}
	})

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"VerifyBackup of another tenant's backup", func() error {
			_, err := bs.VerifyBackup(ctx, &pb.VerifyBackupRequest{Id: "bob-app-20261003T010000Z", TargetUsername: "alice"})
			return err
		}},
		{"VerifyBackup into another tenant's container", func() error {
			_, err := bs.VerifyBackup(ctx, &pb.VerifyBackupRequest{Id: "alice-app-20261003T010000Z", TargetUsername: "bob"})
			return err
		}},
		{"ListContainers (containers:read not granted)", func() error {
			_, err := cs.ListContainers(ctx, &pb.ListContainersRequest{})
			return err
		}},
		{"GetSecret (secrets:read not granted)", func() error {
			_, err := cs.GetSecret(ctx, &pb.GetSecretRequest{Username: "alice", Name: "db"})
			return err
		}},
	} {
		t.Run(tc.name+" is denied", func(t *testing.T) {
			if c := status.Code(tc.call()); c != codes.PermissionDenied {
				t.Fatalf("code = %v, want PermissionDenied", c)
			}
		})
	}
}
