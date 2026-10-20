package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
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
	backend := incustest.NewMockBackend()
	for _, n := range []string{"alice-container", "bob-container"} {
		if err := backend.CreateContainer(incus.ContainerConfig{Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	cs := &ContainerServer{manager: container.NewWithBackend(backend)}
	return cs, &BackupServer{
		containers: cs,
		mgr:        backup.NewManager(&scopedVerifierOps{t: t}, nil, dir),
	}
}

type scopedVerifierOps struct{ t *testing.T }

func (o *scopedVerifierOps) checkTarget(name string) {
	o.t.Helper()
	if !strings.HasPrefix(name, "backup-verify-") {
		o.t.Fatalf("verification touched tenant container %s", name)
	}
}
func (o *scopedVerifierOps) Exec(name string, _ []string) error {
	o.checkTarget(name)
	return nil
}
func (o *scopedVerifierOps) ExecWithOutput(name string, _ []string) (string, string, error) {
	o.checkTarget(name)
	return "0", "", nil
}
func (o *scopedVerifierOps) WriteFile(name, _ string, _ []byte, _ string) error {
	o.checkTarget(name)
	return nil
}
func (o *scopedVerifierOps) ReadFile(string, string) ([]byte, error) { return nil, os.ErrNotExist }

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

	for _, tc := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"ListBackups for the bound tenant succeeds and returns only its records", func(t *testing.T) {
			for _, username := range []string{"", "alice"} {
				resp, err := bs.ListBackups(ctx, &pb.ListBackupsRequest{Username: username})
				if err != nil {
					t.Fatalf("ListBackups(%q): %v", username, err)
				}
				if len(resp.Records) != 1 || resp.Records[0].Username != "alice" {
					t.Fatalf("ListBackups(%q) = %+v, want exactly alice's record", username, resp.Records)
				}
			}
		}},

		{"VerifyBackup for the bound tenant succeeds in an isolated container", func(t *testing.T) {
			resp, err := bs.VerifyBackup(ctx, &pb.VerifyBackupRequest{Id: "alice-app-20261003T010000Z", TargetUsername: "alice"})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Verification.GetResult() != pb.VerificationResult_VERIFICATION_RESULT_PASSED {
				t.Fatalf("verification failed: %+v", resp.Verification)
			}
			if resp.Record.GetLastVerification().GetVerifiedBy() != "alice" {
				t.Fatalf("missing persisted caller evidence: %+v", resp.Record)
			}
			instances, err := cs.manager.List()
			if err != nil {
				t.Fatal(err)
			}
			for _, instance := range instances {
				if strings.HasPrefix(instance.Name, "backup-verify-") {
					t.Fatalf("verifier was not cleaned up: %s", instance.Name)
				}
			}
		}},
	} {
		t.Run(tc.name, tc.run)
	}

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"ListBackups naming another tenant", func() error {
			_, err := bs.ListBackups(ctx, &pb.ListBackupsRequest{Username: "bob"})
			return err
		}},
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

func TestBackupScopedToken_FailedVerificationCleansTarget(t *testing.T) {
	cs, bs := verifierServer(t)
	const id = "alice-app-20261003T010000Z"
	record, err := bs.mgr.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	// A checksum mismatch must still produce durable failed evidence and
	// delete the managed verifier, without touching either tenant container.
	if err := os.WriteFile(record.Location, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := bs.VerifyBackup(verifierCtx("alice"), &pb.VerifyBackupRequest{Id: id, TargetUsername: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verification.GetResult() != pb.VerificationResult_VERIFICATION_RESULT_FAILED {
		t.Fatalf("want failed verification, got %+v", resp.Verification)
	}
	instances, err := cs.manager.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 2 {
		t.Fatalf("expected only the two original tenant containers, got %+v", instances)
	}
}
