package sshauthz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/prototext"

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

// A registry that cannot be read (or is not configured) fails closed:
// DENY with UPSTREAM_UNAVAILABLE (decided on #2517, #2550), never ALLOW
// and never a transport error. Nothing from the underlying failure
// (paths, DSNs, credentials) may reach the response.
func TestSelfHostDecider_UnreadableRegistryDenies(t *testing.T) {
	const leak = "/var/lib/secret/registry.db postgres://u:hunter2@db"
	for _, tc := range []struct {
		name string
		keys KeyLookup
	}{
		{"read error", &memKeys{err: errors.New("connection refused: " + leak)}},
		{"not configured", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeHome(t, home, "alice", testKey(t))
			d := &SelfHostDecider{HomeRoot: home, Boxes: fakeBoxes{names: aliceBox}, Keys: tc.keys}
			resp, err := d.Decide(context.Background(), &pb.AuthorizeSSHRequest{
				Login: "alice",
				Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{
					FingerprintSha256: "SHA256:abc",
				}}},
			})
			if err != nil {
				t.Fatalf("got error %v, want a DENY decision", err)
			}
			if resp.GetDecision() != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY ||
				resp.GetDenyReason() != pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE {
				t.Fatalf("got %v/%v, want DENY/UPSTREAM_UNAVAILABLE", resp.GetDecision(), resp.GetDenyReason())
			}
			if resp.GetCacheTtl() != nil {
				t.Fatalf("a deny must carry no cache ttl, got %v", resp.GetCacheTtl())
			}
			text := prototext.Format(resp)
			for _, s := range []string{"/var/lib", "registry.db", "postgres://", "hunter2", "connection refused"} {
				if strings.Contains(text, s) {
					t.Fatalf("response leaks %q: %s", s, text)
				}
			}
		})
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
