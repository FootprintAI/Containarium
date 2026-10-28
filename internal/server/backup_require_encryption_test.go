package server

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/backup"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3169: require_encryption refuses only the case that would be stored with
// no key at all. Every other combination, and every request without the
// flag, behaves exactly as before.
func TestRefusePlaintext(t *testing.T) {
	for _, tc := range []struct {
		name       string
		require    bool
		mode       backup.KeyMode
		recipient  string
		hasWrapper bool
		wantRefuse bool
	}{
		{"required, nothing to encrypt to: refused", true, "", "", false, true},
		{"required, registered or given recipient", true, "", "age1x", false, false},
		{"required, daemon has a managed key", true, "", "", true, false},
		{"required, explicit managed mode", true, backup.KeyModeManaged, "", true, false},
		{"not required, nothing to encrypt to: plaintext as today", false, "", "", false, false},
		{"not required, recipient: unchanged", false, "", "age1x", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := refusePlaintext(tc.require, "alice", tc.mode, tc.recipient, tc.hasWrapper)
			if (err != nil) != tc.wantRefuse {
				t.Fatalf("refusePlaintext = %v, want refuse=%v", err, tc.wantRefuse)
			}
			if err == nil {
				return
			}
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("code = %v, want FailedPrecondition", status.Code(err))
			}
			for _, want := range []string{"alice", "CONTAINARIUM_BACKUP_AGE_RECIPIENT", "require_encryption"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("message %q does not mention %q", err.Error(), want)
				}
			}
		})
	}
}

// The refusal happens before any container is looked up: s.containers has
// no manager here, so a request that got past it would panic, not fail —
// and nothing can have been dumped or stored.
func TestCreateBackup_RequireEncryptionRefusedBeforeAnyWork(t *testing.T) {
	s := &BackupServer{containers: &ContainerServer{}, mgr: backup.NewManager(nil, nil, t.TempDir())}
	_, err := s.CreateBackup(backupTestCtx("alice"), &pb.CreateBackupRequest{
		Username:          "alice",
		Destination:       pb.BackupDestination_BACKUP_DESTINATION_LOCAL,
		RequireEncryption: true,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("CreateBackup = %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "alice") {
		t.Errorf("error does not name the tenant: %v", err)
	}
}
