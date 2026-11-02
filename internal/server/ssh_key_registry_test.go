package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/internal/sshauthz"
	"github.com/footprintai/containarium/pkg/core/container"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Done-when 4 of #2517: every key write path records the key in the
// ssh_keys registry, and RemoveSSHKey revokes it. The registry's own
// semantics (first registration wins, revoke only the owner's row) are tested
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
	return newTestPubKeyFrom(t, func() ed25519.PublicKey {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub
	})
}

// newTestPubKeyFrom draws public keys from next until one passes the
// production validator. A random base64 body can contain a placeholder marker
// (e.g. "todo") and be rejected by SetSSHKeys, so such draws are discarded.
// It asks the validator rather than keeping its own marker list.
func newTestPubKeyFrom(t *testing.T, next func() ed25519.PublicKey) string {
	t.Helper()
	for i := 0; i < 1000; i++ {
		line := testPubKeyLine(t, next())
		if container.ValidateSSHPublicKey(line) == nil {
			return line
		}
	}
	t.Fatal("newTestPubKeyFrom: no validator-clean key after 1000 draws")
	return ""
}

func testPubKeyLine(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

// A draw whose encoding contains a placeholder marker must be regenerated.
func TestNewTestPubKey_RegeneratesPlaceholderMarkerDraw(t *testing.T) {
	// The wire blob has a 19-byte header (len+"ssh-ed25519"+len), so key
	// byte 2 starts a base64 group (offset 21 = 7*3). Put the 3 bytes that
	// encode "todo" there.
	marker, err := base64.StdEncoding.DecodeString("todo")
	if err != nil {
		t.Fatal(err)
	}
	bad := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(bad[2:], marker)
	if container.ValidateSSHPublicKey(testPubKeyLine(t, bad)) == nil {
		t.Fatal("precondition: forced key should be rejected by the validator")
	}
	good, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	draws := 0
	got := newTestPubKeyFrom(t, func() ed25519.PublicKey {
		draws++
		if draws == 1 {
			return bad
		}
		return good
	})
	if draws < 2 {
		t.Fatalf("placeholder-marker draw was returned without regeneration (draws=%d)", draws)
	}
	if err := container.ValidateSSHPublicKey(got); err != nil {
		t.Fatalf("newTestPubKeyFrom returned a key the validator rejects: %v", err)
	}
}

// fakeAuthorizedKeys replaces the host-side authorized_keys file operations.
type fakeAuthorizedKeys struct {
	files  map[string][]string
	addErr map[string]error // by key

	platform     string // platform-managed line the fake replace preserves
	inReplace    bool   // true while the fake replace's critical section is open
	replaceCalls int
}

func newFakeAuthorizedKeys() *fakeAuthorizedKeys {
	return &fakeAuthorizedKeys{files: map[string][]string{}, addErr: map[string]error{}}
}

// OtherAccountHolds is the fake's sshauthz.HolderLookup: any account other
// than excludeUsername whose fake file holds the fingerprint.
func (f *fakeAuthorizedKeys) OtherAccountHolds(_ context.Context, fingerprint, excludeUsername string) (bool, error) {
	for user, lines := range f.files {
		if user == excludeUsername {
			continue
		}
		for _, l := range lines {
			if rec, err := sshauthz.NewKeyRecord(l, user, sshauthz.SourceAPI, caseClock); err == nil && rec.Fingerprint == fingerprint {
				return true, nil
			}
		}
	}
	return false, nil
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
		count: func(u string) (int32, error) { return safecast.I32(len(f.files[u])), nil },
		replace: func(u string, keys []string, hooks container.ReplaceHooks) ([]string, error) {
			f.replaceCalls++
			var removed []string
			for _, l := range f.files[u] {
				keep := false
				for _, k := range keys {
					if k == l {
						keep = true
					}
				}
				if !keep && l != f.platform {
					removed = append(removed, l)
				}
			}
			f.inReplace = true
			defer func() { f.inReplace = false }()
			if hooks.BeforeWrite != nil {
				if err := hooks.BeforeWrite(removed); err != nil {
					return nil, err
				}
			}
			f.files[u] = append(append([]string{}, keys...), f.platform)
			if hooks.AfterWrite != nil {
				if err := hooks.AfterWrite(); err != nil {
					return nil, err
				}
			}
			return removed, nil
		},
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

// Revoke before the file changes (#3187, as SetSSHKeys does): a registry
// failure leaves the key in authorized_keys, so the caller's retry sees it
// and repeats the revocation. Removing first would drop the key from the file
// with its registry entry still active.
func TestRemoveSSHKey_RegistryFailureLeavesFileAndRetryRevokes(t *testing.T) {
	reg, fs := &recordingRegistry{err: errors.New("db down")}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	pub := newTestPubKey(t)
	fs.files["alice"] = []string{pub}
	ctx := tenantWithScopes("alice", auth.ScopeSSHWrite)
	req := &pb.RemoveSSHKeyRequest{Username: "alice", SshPublicKey: pub}

	if _, err := s.RemoveSSHKey(ctx, req); err == nil {
		t.Fatal("RemoveSSHKey must fail when the revocation cannot be recorded")
	}
	if len(fs.files["alice"]) != 1 || fs.files["alice"][0] != pub {
		t.Fatalf("file changed although the revocation failed: %q", fs.files["alice"])
	}

	reg.err = nil
	if _, err := s.RemoveSSHKey(ctx, req); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if len(fs.files["alice"]) != 0 || len(reg.revoked) != 1 || reg.revoked[0].rec.PublicKey != pub {
		t.Fatalf("retry: file=%q revoked=%+v, want key gone and revoked once", fs.files["alice"], reg.revoked)
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
