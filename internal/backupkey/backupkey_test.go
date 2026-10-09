package backupkey

import (
	"context"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/footprintai/containarium/pkg/core/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const testKEKID = "gcp:projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/1"

func TestUnwrapIdentity(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	managed := &pb.BackupRecord{Id: "alice-app-x", WrappedKey: []byte("wrapped"), KekId: testKEKID}

	t.Run("unwraps the record's key under the loaded client", func(t *testing.T) {
		kms := &fakeKMS{Plaintext: []byte(id.String())}
		var loadedFor string
		got, err := UnwrapIdentity(context.Background(), func(kekID string) (secrets.KMSClient, error) {
			loadedFor = kekID
			return kms, nil
		}, managed)
		if err != nil {
			t.Fatalf("UnwrapIdentity: %v", err)
		}
		if string(got) != id.String() {
			t.Error("returned identity differs from the KMS plaintext")
		}
		if loadedFor != testKEKID || kms.GotKEKID != testKEKID || string(kms.GotWrapped) != "wrapped" {
			t.Errorf("unwrap used kek %q / loader %q / wrapped %q", kms.GotKEKID, loadedFor, kms.GotWrapped)
		}
	})

	t.Run("a record without a managed key is refused before any KMS call", func(t *testing.T) {
		called := false
		_, err := UnwrapIdentity(context.Background(), func(string) (secrets.KMSClient, error) {
			called = true
			return &fakeKMS{}, nil
		}, &pb.BackupRecord{Id: "alice-app-x", Encrypted: true, AgeRecipient: "age1example"})
		if err == nil || !strings.Contains(err.Error(), "no managed key") {
			t.Fatalf("err = %v, want a 'no managed key' refusal", err)
		}
		if called {
			t.Error("KMS loaded for a record that has nothing to unwrap")
		}
	})

	t.Run("an unwrap error is returned with its cause", func(t *testing.T) {
		denied := errors.New("PermissionDenied: caller lacks cloudkms.cryptoKeyVersions.useToDecrypt")
		_, err := UnwrapIdentity(context.Background(), func(string) (secrets.KMSClient, error) {
			return &fakeKMS{Err: denied}, nil
		}, managed)
		if !errors.Is(err, denied) {
			t.Fatalf("err = %v, want it to wrap the KMS error", err)
		}
	})

	t.Run("plaintext that is not an age identity is zeroed and refused", func(t *testing.T) {
		kms := &fakeKMS{Plaintext: []byte("not-an-identity")}
		_, err := UnwrapIdentity(context.Background(), func(string) (secrets.KMSClient, error) { return kms, nil }, managed)
		if err == nil || !strings.Contains(err.Error(), "age identity") {
			t.Fatalf("err = %v, want a refusal naming the age identity", err)
		}
		for _, b := range kms.Plaintext {
			if b != 0 {
				t.Fatal("rejected plaintext was not zeroed")
			}
		}
	})
}

func TestNewest(t *testing.T) {
	recs := []*pb.BackupRecord{
		{Id: "alice-app-1", Username: "alice", Database: "app", CreatedAt: "2026-10-01T01:00:00Z"},
		{Id: "alice-app-3", Username: "alice", Database: "app", CreatedAt: "2026-10-03T01:00:00Z"},
		{Id: "alice-app-2", Username: "alice", Database: "app", CreatedAt: "2026-10-02T01:00:00Z"},
		{Id: "alice-other-9", Username: "alice", Database: "other", CreatedAt: "2026-10-09T01:00:00Z"},
		{Id: "bob-app-9", Username: "bob", Database: "app", CreatedAt: "2026-10-09T01:00:00Z"},
	}
	for _, tc := range []struct {
		name, user, db string
		recs           []*pb.BackupRecord
		want, wantErr  string
	}{
		{name: "newest for user and database", user: "alice", db: "app", recs: recs, want: "alice-app-3"},
		{name: "other database", user: "alice", db: "other", recs: recs, want: "alice-other-9"},
		{name: "no match", user: "alice", db: "missing", recs: recs, wantErr: "no backup"},
		{name: "user required", db: "app", recs: recs, wantErr: "user"},
		{name: "database required", user: "alice", recs: recs, wantErr: "database"},
		{name: "unparseable timestamp is an error, not a guess", user: "alice", db: "app",
			recs: []*pb.BackupRecord{{Id: "a", Username: "alice", Database: "app", CreatedAt: "yesterday"}}, wantErr: "created_at"},
		{name: "a tie at the newest timestamp is ambiguous", user: "alice", db: "app",
			recs: []*pb.BackupRecord{
				{Id: "a", Username: "alice", Database: "app", CreatedAt: "2026-10-03T01:00:00Z"},
				{Id: "b", Username: "alice", Database: "app", CreatedAt: "2026-10-03T01:00:00Z"},
			}, wantErr: "same newest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Newest(tc.recs, tc.user, tc.db)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Newest: %v", err)
			}
			if got.Id != tc.want {
				t.Errorf("Newest = %s, want %s", got.Id, tc.want)
			}
		})
	}
}

func TestLoadOperatorKMS_RefusesWithoutGCPBackend(t *testing.T) {
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "")
	_, err := LoadOperatorKMS(testKEKID)
	if err == nil || !strings.Contains(err.Error(), "CONTAINARIUM_KMS_BACKEND=gcp") ||
		!strings.Contains(err.Error(), "gcloud auth print-access-token") {
		t.Fatalf("err = %v, want guidance naming the backend and the token step", err)
	}
}

func TestLoadOperatorKMS_RefusesNonGCPKEKID(t *testing.T) {
	_, err := LoadOperatorKMS("inproc:v1")
	if err == nil || !strings.Contains(err.Error(), "kek_id") {
		t.Fatalf("err = %v, want a kek_id refusal", err)
	}
}

// fakeKMS records what it was asked to unwrap and hands back a canned
// plaintext (or error). Wrap is unused: the operator side never wraps.
type fakeKMS struct {
	Plaintext  []byte
	Err        error
	GotWrapped []byte
	GotKEKID   string
}

func (f *fakeKMS) Wrap(context.Context, []byte) ([]byte, string, error) {
	return nil, "", errors.New("not used")
}

func (f *fakeKMS) Unwrap(_ context.Context, wrapped []byte, kekID string) ([]byte, error) {
	f.GotWrapped, f.GotKEKID = wrapped, kekID
	return f.Plaintext, f.Err
}
