package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/footprintai/containarium/pkg/core/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const managedTestKEKID = "gcp:projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/1"

// managedFakeKMS stands in for the operator's own KMS client (#2403).
type managedFakeKMS struct {
	plaintext  []byte
	err        error
	unwraps    int
	gotWrapped []byte
	gotKEKID   string
}

func (f *managedFakeKMS) Wrap(context.Context, []byte) ([]byte, string, error) {
	return nil, "", errors.New("the operator side never wraps")
}

func (f *managedFakeKMS) Unwrap(_ context.Context, wrapped []byte, kekID string) ([]byte, error) {
	f.unwraps++
	f.gotWrapped, f.gotKEKID = wrapped, kekID
	if f.err != nil {
		return nil, f.err
	}
	return f.plaintext, nil
}

// managedHostAPI is the fake host: it serves records and counts every
// mutating RPC, so a test can prove nothing reached the host.
type managedHostAPI struct {
	recordingBackupAPI
	records    []*pb.BackupRecord
	gets       int
	lists      int
	restores   int
	verifies   int
	gotVerify  *pb.VerifyBackupRequest
	verifyResp *pb.VerifyBackupResponse
}

func (f *managedHostAPI) GetBackup(id string) (*pb.BackupRecord, error) {
	f.gets++
	for _, r := range f.records {
		if r.Id == id {
			return r, nil
		}
	}
	return nil, errors.New("not found")
}

func (f *managedHostAPI) ListBackups(username string) ([]*pb.BackupRecord, error) {
	f.lists++
	var out []*pb.BackupRecord
	for _, r := range f.records {
		if username == "" || r.Username == username {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *managedHostAPI) RestoreBackup(req *pb.RestoreBackupRequest) (*pb.RestoreBackupResponse, error) {
	f.restores++
	return f.recordingBackupAPI.RestoreBackup(req)
}

func (f *managedHostAPI) VerifyBackup(req *pb.VerifyBackupRequest) (*pb.VerifyBackupResponse, error) {
	f.verifies++
	f.gotVerify = req
	return f.verifyResp, nil
}

type managedHarness struct {
	host  *managedHostAPI
	kms   *managedFakeKMS
	dials int
	// identity is a freshly generated throwaway age identity; never real.
	identity string
}

func newManagedHarness(t *testing.T) *managedHarness {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	h := &managedHarness{identity: id.String()}
	h.kms = &managedFakeKMS{plaintext: []byte(h.identity)}
	h.host = &managedHostAPI{
		records: []*pb.BackupRecord{
			{Id: "alice-app-20261001T010000Z", Username: "alice", Database: "app", CreatedAt: "2026-10-01T01:00:00Z",
				Encrypted: true, WrappedKey: []byte("wrapped-old"), KekId: managedTestKEKID, KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED},
			{Id: "alice-app-20261003T010000Z", Username: "alice", Database: "app", CreatedAt: "2026-10-03T01:00:00Z",
				Encrypted: true, WrappedKey: []byte("wrapped-new"), KekId: managedTestKEKID, KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED},
			{Id: "alice-other-20261009T010000Z", Username: "alice", Database: "other", CreatedAt: "2026-10-09T01:00:00Z"},
			{Id: "bob-app-20261009T010000Z", Username: "bob", Database: "app", CreatedAt: "2026-10-09T01:00:00Z"},
		},
		verifyResp: &pb.VerifyBackupResponse{
			Message:      "ok",
			Verification: &pb.BackupVerification{Result: pb.VerificationResult_VERIFICATION_RESULT_PASSED},
		},
	}
	origDial, origKMS := newBackupClientFn, managedKMSLoader
	newBackupClientFn = func() (backupAPI, error) { h.dials++; return h.host, nil }
	managedKMSLoader = func(string) (secrets.KMSClient, error) { return h.kms, nil }
	t.Cleanup(func() { newBackupClientFn, managedKMSLoader = origDial, origKMS })
	resetBackupRestoreFlags(t)
	resetBackupVerifyFlags(t)
	return h
}

func resetBackupRestoreFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		backupRestoreClean, backupRestoreDatabase, backupRestoreAgeIdentityFile = false, "", ""
		backupRestoreManaged, backupRestoreLatest, backupRestoreUser, backupRestoreTarget = false, false, "", ""
	}
	reset()
	t.Cleanup(reset)
}

func resetBackupVerifyFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		backupVerifyTarget, backupVerifyAgeIdentityFile = "", ""
		backupVerifyManaged, backupVerifyLatest, backupVerifyUser, backupVerifyDatabase = false, false, "", ""
	}
	reset()
	t.Cleanup(reset)
}

func TestRestoreManaged_UnwrapsThenSendsIdentityOverTLSOnly(t *testing.T) {
	t.Run("mTLS gRPC: identity unwrapped from the record and sent only in the RPC", func(t *testing.T) {
		h := newManagedHarness(t)
		setTransportGlobals(t, "host.example.com:50051", false, false)
		backupRestoreManaged = true

		if err := runBackupRestore(backupRestoreCmd, []string{"alice-app-20261001T010000Z"}); err != nil {
			t.Fatalf("runBackupRestore: %v", err)
		}
		if h.kms.unwraps != 1 || string(h.kms.gotWrapped) != "wrapped-old" || h.kms.gotKEKID != managedTestKEKID {
			t.Errorf("unwrap calls=%d wrapped=%q kek=%q, want the record's wrapped_key under its kek_id",
				h.kms.unwraps, h.kms.gotWrapped, h.kms.gotKEKID)
		}
		if h.host.restores != 1 || h.host.gotRestore.AgeIdentity != h.identity {
			t.Fatal("the unwrapped identity must be the restore request's age_identity")
		}
		if h.host.gotRestore.Id != "alice-app-20261001T010000Z" {
			t.Errorf("restored %q", h.host.gotRestore.Id)
		}
		for _, b := range h.kms.plaintext {
			if b != 0 {
				t.Fatal("the unwrapped identity buffer was not zeroed after the call")
			}
		}
	})

	for _, tc := range []struct {
		name     string
		server   string
		http     bool
		insecure bool
	}{
		{"cleartext http endpoint", "http://host.example.com", true, false},
		{"scheme-less http endpoint", "host.example.com:8080", true, false},
		{"gRPC --insecure", "host.example.com:50051", false, true},
	} {
		t.Run(tc.name+" is refused before the unwrap and before dialing", func(t *testing.T) {
			h := newManagedHarness(t)
			setTransportGlobals(t, tc.server, tc.http, tc.insecure)
			backupRestoreManaged = true

			err := runBackupRestore(backupRestoreCmd, []string{"alice-app-20261001T010000Z"})
			if err == nil || !strings.Contains(err.Error(), "age identity") {
				t.Fatalf("err = %v, want the cleartext refusal", err)
			}
			if h.kms.unwraps != 0 || h.dials != 0 {
				t.Errorf("unwraps=%d dials=%d, want zero of both", h.kms.unwraps, h.dials)
			}
		})
	}
}

func TestRestoreManaged_PermissionDeniedBeforeAnyHostCall(t *testing.T) {
	h := newManagedHarness(t)
	setTransportGlobals(t, "host.example.com:50051", false, false)
	h.kms.err = errors.New("gcp kms decrypt: 403 PERMISSION_DENIED: Permission 'cloudkms.cryptoKeyVersions.useToDecrypt' denied")
	backupRestoreManaged = true

	err := runBackupRestore(backupRestoreCmd, []string{"alice-app-20261001T010000Z"})
	if err == nil || !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Fatalf("err = %v, want the KMS permission error surfaced", err)
	}
	// The only call the host sees is the read that fetched the wrapped
	// key; no restore (or anything else that acts) reaches it.
	if h.host.restores != 0 || h.host.verifies != 0 || h.host.gotCreate != nil || h.host.gotPrune != nil {
		t.Errorf("restores=%d verifies=%d after a denied unwrap, want zero", h.host.restores, h.host.verifies)
	}
}

func TestVerifyManaged_UnwrapsThenSendsIdentity(t *testing.T) {
	h := newManagedHarness(t)
	setTransportGlobals(t, "host.example.com:50051", false, false)
	backupVerifyManaged, backupVerifyTarget = true, "scratch"

	if err := runBackupVerify(backupVerifyCmd, []string{"alice-app-20261001T010000Z"}); err != nil {
		t.Fatalf("runBackupVerify: %v", err)
	}
	if h.host.verifies != 1 || h.host.gotVerify.AgeIdentity != h.identity || h.host.gotVerify.TargetUsername != "scratch" {
		t.Fatal("verify must carry the unwrapped identity and the target")
	}

	t.Run("denied unwrap sends no verify", func(t *testing.T) {
		h := newManagedHarness(t)
		setTransportGlobals(t, "host.example.com:50051", false, false)
		h.kms.err = errors.New("PERMISSION_DENIED")
		backupVerifyManaged, backupVerifyTarget = true, "scratch"
		if err := runBackupVerify(backupVerifyCmd, []string{"alice-app-20261001T010000Z"}); err == nil {
			t.Fatal("want an error")
		}
		if h.host.verifies != 0 {
			t.Error("a verify reached the host after a denied unwrap")
		}
	})
}

func TestRestoreLatest_SelectsNewestForUserAndDatabase(t *testing.T) {
	h := newManagedHarness(t)
	setTransportGlobals(t, "host.example.com:50051", false, false)
	backupRestoreLatest, backupRestoreUser, backupRestoreDatabase = true, "alice", "app"

	if err := runBackupRestore(backupRestoreCmd, nil); err != nil {
		t.Fatalf("runBackupRestore --latest: %v", err)
	}
	if h.host.gotRestore == nil || h.host.gotRestore.Id != "alice-app-20261003T010000Z" {
		t.Fatalf("restored %v, want the newest alice/app record", h.host.gotRestore)
	}
	if h.host.gotRestore.AgeIdentity != "" {
		t.Error("no identity may be sent without --managed or --age-identity-file")
	}

	t.Run("with --managed unwraps the newest record's key", func(t *testing.T) {
		h := newManagedHarness(t)
		setTransportGlobals(t, "host.example.com:50051", false, false)
		backupRestoreLatest, backupRestoreUser, backupRestoreDatabase, backupRestoreManaged = true, "alice", "app", true
		if err := runBackupRestore(backupRestoreCmd, nil); err != nil {
			t.Fatalf("runBackupRestore: %v", err)
		}
		if string(h.kms.gotWrapped) != "wrapped-new" || h.host.gotRestore.Id != "alice-app-20261003T010000Z" {
			t.Errorf("unwrapped %q for %q, want the newest record's key", h.kms.gotWrapped, h.host.gotRestore.Id)
		}
	})

	t.Run("verify --latest", func(t *testing.T) {
		h := newManagedHarness(t)
		backupVerifyLatest, backupVerifyUser, backupVerifyDatabase, backupVerifyTarget = true, "alice", "app", "scratch"
		if err := runBackupVerify(backupVerifyCmd, nil); err != nil {
			t.Fatalf("runBackupVerify --latest: %v", err)
		}
		if h.host.gotVerify.Id != "alice-app-20261003T010000Z" {
			t.Errorf("verified %q, want the newest alice/app record", h.host.gotVerify.Id)
		}
	})
}

// Flag combinations that would make the command guess are refused before
// anything is dialed or unwrapped.
func TestBackupRestore_SelectionAndKeyFlagValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		set     func()
		wantErr string
	}{
		{"neither id nor --latest", nil, func() {}, "backup id"},
		{"id and --latest", []string{"alice-app-x"}, func() { backupRestoreLatest, backupRestoreUser, backupRestoreDatabase = true, "alice", "app" }, "--latest"},
		{"--latest without --user", nil, func() { backupRestoreLatest, backupRestoreDatabase = true, "app" }, "--user"},
		{"--latest without --database", nil, func() { backupRestoreLatest, backupRestoreUser = true, "alice" }, "--database"},
		{"--managed with --age-identity-file", []string{"alice-app-x"}, func() { backupRestoreManaged, backupRestoreAgeIdentityFile = true, "backup.key" }, "--managed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newManagedHarness(t)
			setTransportGlobals(t, "host.example.com:50051", false, false)
			tc.set()
			err := runBackupRestore(backupRestoreCmd, tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one naming %s", err, tc.wantErr)
			}
			if h.dials != 0 || h.kms.unwraps != 0 {
				t.Errorf("dials=%d unwraps=%d, want zero", h.dials, h.kms.unwraps)
			}
		})
	}
}

func TestBackupRestore_TargetFlagReachesRequest(t *testing.T) {
	for _, target := range []string{"", "scratch-container"} {
		t.Run("target="+target, func(t *testing.T) {
			h := newManagedHarness(t)
			backupRestoreTarget = target
			if err := runBackupRestore(backupRestoreCmd, []string{"alice-app-20261001T010000Z"}); err != nil {
				t.Fatalf("runBackupRestore: %v", err)
			}
			if h.host.gotRestore.TargetContainer != target {
				t.Errorf("target_container = %q, want %q", h.host.gotRestore.TargetContainer, target)
			}
		})
	}
}

// The operator must be told whose credentials the unwrap runs under and
// that it is audited, plus the one-liner that makes it work (#2403).
func TestBackupRestoreVerifyHelp_ManagedCredentialsAndAudit(t *testing.T) {
	for _, c := range []struct {
		name string
		long string
	}{{"restore", backupRestoreCmd.Long}, {"verify", backupVerifyCmd.Long}} {
		for _, want := range []string{
			"your own cloud credentials",
			"audited by the KMS",
			"CONTAINARIUM_KMS_BACKEND=gcp",
			"CONTAINARIUM_GCP_KMS_TOKEN=$(gcloud auth print-access-token)",
		} {
			if !strings.Contains(c.long, want) {
				t.Errorf("backup %s help is missing %q", c.name, want)
			}
		}
	}
	if strings.Contains(backupRestoreCmd.Long, "cannot be restored\nby the platform") {
		t.Error("restore help still says a hook backup can never be restored")
	}
}
