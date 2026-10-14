package sshauthz

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// memKeys is an in-memory registry for the unit run of the decider table.
// The registration semantics themselves are tested against Postgres.
type memKeys struct {
	rows map[string]KeyRecord
	err  error
}

func newMemKeys(*testing.T) keySeeder { return &memKeys{rows: map[string]KeyRecord{}} }

func (m *memKeys) Lookup(_ context.Context, fingerprint string) (KeyRecord, error) {
	if m.err != nil {
		return KeyRecord{}, m.err
	}
	rec, ok := m.rows[fingerprint]
	if !ok {
		return KeyRecord{}, ErrKeyNotFound
	}
	return rec, nil
}

func (m *memKeys) InsertIfAbsent(_ context.Context, rec KeyRecord) (bool, error) {
	if _, ok := m.rows[rec.Fingerprint]; ok {
		return false, nil
	}
	m.rows[rec.Fingerprint] = rec
	return true, nil
}

func TestSelfHostDecider_Table(t *testing.T) {
	runDeciderCases(t, newMemKeys)
}

// A registry read failure is not a decision: it is returned as
// Unavailable so the caller's outage handling applies, never ALLOW.
func TestSelfHostDecider_RegistryErrorIsUnavailable(t *testing.T) {
	home := t.TempDir()
	writeHome(t, home, "alice", testKey(t))
	d := &SelfHostDecider{
		HomeRoot: home,
		Boxes:    fakeBoxes{names: aliceBox},
		Keys:     &memKeys{err: errors.New("connection refused")},
	}
	resp, err := d.Decide(context.Background(), &pb.AuthorizeSSHRequest{
		Login: "alice",
		Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{
			FingerprintSha256: "SHA256:abc",
		}}},
	})
	if status.Code(err) != codes.Unavailable || resp != nil {
		t.Fatalf("got (%v, %v), want Unavailable error and no response", resp, err)
	}
}

// A collaborator login on a daemon without a collaborator store cannot be
// checked, so it is refused.
func TestSelfHostDecider_CollaboratorWithoutStore(t *testing.T) {
	home := t.TempDir()
	writeHome(t, home, "alice-container-bob", testKey(t))
	d := &SelfHostDecider{HomeRoot: home, Boxes: fakeBoxes{names: aliceBox}, Keys: &memKeys{rows: map[string]KeyRecord{}}}
	resp, err := d.Decide(context.Background(), &pb.AuthorizeSSHRequest{Login: "alice-container-bob"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetDenyReason() != pb.SSHDenyReason_SSH_DENY_REASON_NO_ACCESS {
		t.Fatalf("got %v, want NO_ACCESS", resp.GetDenyReason())
	}
}

func TestUserIDForLogin(t *testing.T) {
	for login, want := range map[string]string{
		"alice":               "alice",
		"alice-container-bob": "bob",
		"":                    "",
	} {
		if got := UserIDForLogin(login); got != want {
			t.Errorf("UserIDForLogin(%q) = %q, want %q", login, got, want)
		}
	}
}

func TestNewKeyRecord(t *testing.T) {
	pub := testKey(t)
	rec, err := NewKeyRecord(pub, "alice-container-bob", SourceCollaborator, caseNow)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Username != "alice-container-bob" || rec.UserID != "bob" || rec.Source != SourceCollaborator ||
		rec.KeyType != pb.SSHKeyType_SSH_KEY_TYPE_ED25519 || !rec.CreatedAt.Equal(caseNow) || !rec.RevokedAt.IsZero() {
		t.Fatalf("unexpected record %+v", rec)
	}
	if len(rec.Fingerprint) < len("SHA256:") || rec.Fingerprint[:7] != "SHA256:" {
		t.Fatalf("fingerprint %q is not in ssh-keygen SHA256 form", rec.Fingerprint)
	}
	if _, err := NewKeyRecord("garbage", "alice", SourceAPI, caseNow); err == nil {
		t.Fatal("garbage key must not produce a record")
	}
}
