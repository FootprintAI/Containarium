package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sshauthz"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Done-when 4 of #2517: every key write path records the key in the
// ssh_keys registry, and RemoveSSHKey revokes it. The registry's own
// semantics (first registration wins, revoke for every account) are tested
// against Postgres in internal/sshauthz; here a recording fake proves each
// path hands it the right row.

type revocation struct {
	rec sshauthz.KeyRecord
	at  time.Time
}

type recordingRegistry struct {
	registered []sshauthz.KeyRecord
	revoked    []revocation
	err        error
}

func (r *recordingRegistry) Register(_ context.Context, rec sshauthz.KeyRecord) error {
	if r.err != nil {
		return r.err
	}
	r.registered = append(r.registered, rec)
	return nil
}

func (r *recordingRegistry) Revoke(_ context.Context, rec sshauthz.KeyRecord, at time.Time) error {
	if r.err != nil {
		return r.err
	}
	r.revoked = append(r.revoked, revocation{rec, at})
	return nil
}

func newTestPubKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

// fakeAuthorizedKeys replaces the host-side authorized_keys file operations.
type fakeAuthorizedKeys struct {
	files  map[string][]string
	addErr map[string]error // by key
}

func newFakeAuthorizedKeys() *fakeAuthorizedKeys {
	return &fakeAuthorizedKeys{files: map[string][]string{}, addErr: map[string]error{}}
}

func (f *fakeAuthorizedKeys) ops() authorizedKeysOps {
	return authorizedKeysOps{
		add: func(u, k string) error {
			if err := f.addErr[k]; err != nil {
				return err
			}
			f.files[u] = append(f.files[u], k)
			return nil
		},
		remove: func(u, k string) error {
			var kept []string
			for _, l := range f.files[u] {
				if l != k {
					kept = append(kept, l)
				}
			}
			f.files[u] = kept
			return nil
		},
		count: func(u string) (int32, error) { return int32(len(f.files[u])), nil },
	}
}

func testServerWithRegistry(reg *recordingRegistry, fs *fakeAuthorizedKeys) *ContainerServer {
	s := &ContainerServer{authorizedKeys: fs.ops(), sshKeyNow: func() time.Time { return caseClock }}
	s.SetSSHKeyRegistry(reg)
	return s
}

var caseClock = time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)

func TestAddSSHKey_RegistersKey(t *testing.T) {
	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	pub := newTestPubKey(t)

	_, err := s.AddSSHKey(tenantWithScopes("alice", auth.ScopeSSHWrite), &pb.AddSSHKeyRequest{Username: "alice", SshPublicKey: pub})
	if err != nil {
		t.Fatalf("AddSSHKey: %v", err)
	}
	if len(reg.registered) != 1 {
		t.Fatalf("registered %d rows, want 1", len(reg.registered))
	}
	got := reg.registered[0]
	want, _ := sshauthz.NewKeyRecord(pub, "alice", sshauthz.SourceAPI, caseClock)
	if got != want {
		t.Fatalf("row = %+v, want %+v", got, want)
	}
}

// A registry write failure is reported: the key is on disk, but with the
// authorization plugin enforcing it would be refused as UNKNOWN_KEY, so the
// caller must retry (AddSSHKey is idempotent).
func TestAddSSHKey_RegistryFailureIsAnError(t *testing.T) {
	reg, fs := &recordingRegistry{err: errors.New("db down")}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	_, err := s.AddSSHKey(tenantWithScopes("alice", auth.ScopeSSHWrite), &pb.AddSSHKeyRequest{Username: "alice", SshPublicKey: newTestPubKey(t)})
	if err == nil {
		t.Fatal("AddSSHKey must fail when the key cannot be registered")
	}
}

func TestAddSSHKey_NoRegistryConfigured(t *testing.T) {
	fs := newFakeAuthorizedKeys()
	s := &ContainerServer{authorizedKeys: fs.ops()}
	if _, err := s.AddSSHKey(tenantWithScopes("alice", auth.ScopeSSHWrite), &pb.AddSSHKeyRequest{Username: "alice", SshPublicKey: newTestPubKey(t)}); err != nil {
		t.Fatalf("a daemon without a registry (no Postgres) must keep working: %v", err)
	}
}

func TestRemoveSSHKey_RevokesKey(t *testing.T) {
	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	pub := newTestPubKey(t)
	fs.files["alice"] = []string{pub}

	_, err := s.RemoveSSHKey(tenantWithScopes("alice", auth.ScopeSSHWrite), &pb.RemoveSSHKeyRequest{Username: "alice", SshPublicKey: pub})
	if err != nil {
		t.Fatalf("RemoveSSHKey: %v", err)
	}
	if len(reg.revoked) != 1 {
		t.Fatalf("revoked %d rows, want 1", len(reg.revoked))
	}
	want, _ := sshauthz.NewKeyRecord(pub, "alice", sshauthz.SourceAPI, caseClock)
	if reg.revoked[0].rec.Fingerprint != want.Fingerprint || !reg.revoked[0].at.Equal(caseClock) {
		t.Fatalf("revocation = %+v, want fingerprint %s at %v", reg.revoked[0], want.Fingerprint, caseClock)
	}
}

func TestRemoveSSHKey_RegistryFailureIsAnError(t *testing.T) {
	reg, fs := &recordingRegistry{err: errors.New("db down")}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	_, err := s.RemoveSSHKey(tenantWithScopes("alice", auth.ScopeSSHWrite), &pb.RemoveSSHKeyRequest{Username: "alice", SshPublicKey: newTestPubKey(t)})
	if err == nil {
		t.Fatal("RemoveSSHKey must fail when the revocation cannot be recorded")
	}
}

// Box creation: the create-request keys mirrored into the jump account are
// registered with source box_create; a key that could not be written is not.
func TestSyncCreateRequestKeys_RegistersBoxKeys(t *testing.T) {
	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	good, bad := newTestPubKey(t), newTestPubKey(t)
	fs.addErr[bad] = errors.New("disk full")

	s.syncCreateRequestKeys(context.Background(), "alice", []string{good, bad})

	if len(reg.registered) != 1 {
		t.Fatalf("registered %d rows, want 1: %+v", len(reg.registered), reg.registered)
	}
	want, _ := sshauthz.NewKeyRecord(good, "alice", sshauthz.SourceBoxCreate, caseClock)
	if reg.registered[0] != want {
		t.Fatalf("row = %+v, want %+v", reg.registered[0], want)
	}
}

// AddCollaborator: each collaborator key is registered to the collaborator
// jump account, which resolves to the collaborator's user id.
func TestRegisterCollaboratorKeys(t *testing.T) {
	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	k1, k2 := newTestPubKey(t), newTestPubKey(t)

	s.registerCollaboratorKeys(context.Background(), "alice-container-bob", []string{k1, k2})

	if len(reg.registered) != 2 {
		t.Fatalf("registered %d rows, want 2", len(reg.registered))
	}
	for i, k := range []string{k1, k2} {
		want, _ := sshauthz.NewKeyRecord(k, "alice-container-bob", sshauthz.SourceCollaborator, caseClock)
		if reg.registered[i] != want || reg.registered[i].UserID != "bob" {
			t.Fatalf("row %d = %+v, want %+v", i, reg.registered[i], want)
		}
	}
}
