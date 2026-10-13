package server

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- #2402: managed key mode at the server boundary ---

const testBackupKMSKey = "projects/test-proj/locations/us-west1/keyRings/r/cryptoKeys/backups"

// clearBackupKMSEnv unsets every variable NewBackupServer's wrapper
// loading reads, so a developer's shell cannot leak into the table.
func clearBackupKMSEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CONTAINARIUM_BACKUP_KMS_KEY_NAME", "CONTAINARIUM_KMS_BACKEND",
		"CONTAINARIUM_GCP_KMS_KEY_NAME", "CONTAINARIUM_GCP_KMS_TOKEN",
		"CONTAINARIUM_GCP_KMS_TOKEN_FILE", "CONTAINARIUM_GCP_KMS_ENDPOINT",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("CONTAINARIUM_BACKUP_DIR", t.TempDir())
}

// The wrapper is built from CONTAINARIUM_BACKUP_KMS_KEY_NAME via the same
// resource-name keyed factory the secrets store uses for per-tenant KEKs.
// Empty means no wrapper (today's behaviour). Set but unloadable — the
// KMS backend is not gcp, or the name is not a CryptoKey — is a startup
// error: an operator who configured managed backups must never get
// silent legacy backups instead.
func TestNewBackupServer_WrapperFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name        string
		env         map[string]string
		wantWrapper bool
		wantErr     string
	}{
		{
			name: "unset: no wrapper, legacy behaviour",
		},
		{
			name: "set with a gcp backend: wrapper built",
			env: map[string]string{
				"CONTAINARIUM_BACKUP_KMS_KEY_NAME": testBackupKMSKey,
				"CONTAINARIUM_KMS_BACKEND":         "gcp",
				"CONTAINARIUM_GCP_KMS_KEY_NAME":    "projects/test-proj/locations/us-west1/keyRings/r/cryptoKeys/secrets",
				"CONTAINARIUM_GCP_KMS_TOKEN":       "tok",
			},
			wantWrapper: true,
		},
		{
			name: "set but no KMS backend configured",
			env: map[string]string{
				"CONTAINARIUM_BACKUP_KMS_KEY_NAME": testBackupKMSKey,
			},
			wantErr: "CONTAINARIUM_BACKUP_KMS_KEY_NAME",
		},
		{
			name: "set but the KMS backend is not gcp",
			env: map[string]string{
				"CONTAINARIUM_BACKUP_KMS_KEY_NAME": testBackupKMSKey,
				"CONTAINARIUM_KMS_BACKEND":         "inproc",
			},
			wantErr: "CONTAINARIUM_BACKUP_KMS_KEY_NAME",
		},
		{
			name: "malformed key name",
			env: map[string]string{
				"CONTAINARIUM_BACKUP_KMS_KEY_NAME": "not/a/crypto/key",
				"CONTAINARIUM_KMS_BACKEND":         "gcp",
				"CONTAINARIUM_GCP_KMS_KEY_NAME":    "projects/test-proj/locations/us-west1/keyRings/r/cryptoKeys/secrets",
				"CONTAINARIUM_GCP_KMS_TOKEN":       "tok",
			},
			wantErr: "CryptoKey",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearBackupKMSEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			s, err := NewBackupServer(&ContainerServer{})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("NewBackupServer err = %v, want one mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewBackupServer: %v", err)
			}
			if got := s.Manager().HasWrapper(); got != tc.wantWrapper {
				t.Errorf("HasWrapper = %v, want %v", got, tc.wantWrapper)
			}
		})
	}
}

func TestKeyModeFromProto(t *testing.T) {
	for _, tc := range []struct {
		name         string
		requested    pb.BackupKeyMode
		hasWrapper   bool
		hasRecipient bool
		want         backup.KeyMode
		wantCode     codes.Code
	}{
		{"unspecified is the daemon default", pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED, false, false, "", codes.OK},
		{"unspecified with a wrapper is still the daemon default", pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED, true, true, "", codes.OK},
		{"age_recipient with a recipient", pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT, false, true, backup.KeyModeAgeRecipient, codes.OK},
		{"age_recipient without a recipient", pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT, true, false, "", codes.InvalidArgument},
		{"managed with a wrapper", pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED, true, false, backup.KeyModeManaged, codes.OK},
		{"managed without a wrapper", pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED, false, true, "", codes.FailedPrecondition},
		{"both with both", pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH, true, true, backup.KeyModeBoth, codes.OK},
		{"both without a wrapper", pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH, false, true, "", codes.FailedPrecondition},
		{"both without a recipient", pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH, true, false, "", codes.InvalidArgument},
		{"a value this build does not know", pb.BackupKeyMode(99), true, true, "", codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := keyModeFromProto(tc.requested, tc.hasWrapper, tc.hasRecipient)
			if code := status.Code(err); code != tc.wantCode {
				t.Fatalf("code = %v (err %v), want %v", code, err, tc.wantCode)
			}
			if got != tc.want {
				t.Errorf("mode = %q, want %q", got, tc.want)
			}
		})
	}
}

// The record's wire key_mode is derived in one place: the recorded mode
// for managed records, AGE_RECIPIENT for any other encrypted record
// (every record written before the field existed), UNSPECIFIED for
// plaintext. wrapped_key and kek_id ride along untouched.
func TestRecordToProto_CarriesKeyFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  backup.Record
		want pb.BackupKeyMode
	}{
		{"plaintext", backup.Record{ID: "x"}, pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED},
		{"legacy encrypted, no key_mode in sidecar", backup.Record{ID: "x", Encrypted: true, AgeRecipient: "age1legacy"}, pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT},
		{"managed", backup.Record{ID: "x", Encrypted: true, AgeRecipient: "age1ephemeral", KeyMode: backup.KeyModeManaged, WrappedKey: []byte("w"), KEKID: "gcp:k/cryptoKeyVersions/1"}, pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED},
		{"both", backup.Record{ID: "x", Encrypted: true, AgeRecipient: "age1legacy", KeyMode: backup.KeyModeBoth, WrappedKey: []byte("w"), KEKID: "gcp:k/cryptoKeyVersions/1"}, pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH},
		{"a mode this build does not know", backup.Record{ID: "x", Encrypted: true, KeyMode: backup.KeyMode("rot13")}, pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recordToProto(&tc.rec)
			if got.KeyMode != tc.want {
				t.Errorf("key_mode = %v, want %v", got.KeyMode, tc.want)
			}
			if !bytes.Equal(got.WrappedKey, tc.rec.WrappedKey) || got.KekId != tc.rec.KEKID {
				t.Errorf("wrapped_key/kek_id = %q/%q, want %q/%q", got.WrappedKey, got.KekId, tc.rec.WrappedKey, tc.rec.KEKID)
			}
		})
	}
}

func backupTestCtx(username string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), username, []string{"user"}, []string{auth.ScopeBackupsWrite})
}

// A request the daemon cannot satisfy is refused with a gRPC code before
// any container is looked up: s.containers has no manager here, so a
// request that got past the key-mode check would panic, not fail.
func TestCreateBackup_KeyModeRefusedBeforeContainerLookup(t *testing.T) {
	inproc, err := secrets.NewInProcKMS(bytes.Repeat([]byte{1}, secrets.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	noWrapper := &BackupServer{containers: &ContainerServer{}, mgr: backup.NewManager(nil, nil, t.TempDir())}
	withWrapper := &BackupServer{containers: &ContainerServer{}, mgr: backup.NewManager(nil, nil, t.TempDir(), backup.WithWrapper(inproc))}

	for _, tc := range []struct {
		name string
		s    *BackupServer
		req  *pb.CreateBackupRequest
		want codes.Code
	}{
		{"managed on a daemon with no wrapper", noWrapper, &pb.CreateBackupRequest{
			Username: "alice", Destination: pb.BackupDestination_BACKUP_DESTINATION_LOCAL,
			KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED,
		}, codes.FailedPrecondition},
		{"both on a daemon with no wrapper", noWrapper, &pb.CreateBackupRequest{
			Username: "alice", Destination: pb.BackupDestination_BACKUP_DESTINATION_LOCAL,
			KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH, AgeRecipient: "age1x",
		}, codes.FailedPrecondition},
		{"both without a recipient", withWrapper, &pb.CreateBackupRequest{
			Username: "alice", Destination: pb.BackupDestination_BACKUP_DESTINATION_LOCAL,
			KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH,
		}, codes.InvalidArgument},
		{"age_recipient without a recipient", withWrapper, &pb.CreateBackupRequest{
			Username: "alice", Destination: pb.BackupDestination_BACKUP_DESTINATION_LOCAL,
			KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT,
		}, codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.s.CreateBackup(backupTestCtx("alice"), tc.req)
			if code := status.Code(err); code != tc.want {
				t.Fatalf("CreateBackup = %v (code %v), want code %v", err, code, tc.want)
			}
		})
	}
}
