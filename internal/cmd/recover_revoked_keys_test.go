//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/footprintai/containarium/internal/sshauthz"
)

// fakeKeyLookup is an in-memory registry: fingerprint -> row. A missing
// fingerprint answers ErrKeyNotFound like the real store; err forces a failure.
type fakeKeyLookup struct {
	rows map[string]sshauthz.KeyRecord
	err  error
}

func (f fakeKeyLookup) Lookup(_ context.Context, fp string) (sshauthz.KeyRecord, error) {
	if f.err != nil {
		return sshauthz.KeyRecord{}, f.err
	}
	r, ok := f.rows[fp]
	if !ok {
		return sshauthz.KeyRecord{}, sshauthz.ErrKeyNotFound
	}
	return r, nil
}

func testAuthorizedKey(t *testing.T) (line, fingerprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(sp)), ssh.FingerprintSHA256(sp)
}

func TestDropRevokedKeys(t *testing.T) {
	active, activeFP := testAuthorizedKey(t)
	revoked, revokedFP := testAuthorizedKey(t)
	unregistered, _ := testAuthorizedKey(t)
	now := time.Now()

	lookup := fakeKeyLookup{rows: map[string]sshauthz.KeyRecord{
		activeFP:  {Fingerprint: activeFP},
		revokedFP: {Fingerprint: revokedFP, RevokedAt: now},
	}}

	// Revoked key first: the seed key must not be the revoked one.
	kept, dropped, err := dropRevokedKeys(context.Background(), lookup, []string{revoked, active, unregistered})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1", dropped)
	}
	if len(kept) != 2 || kept[0] != active || kept[1] != unregistered {
		t.Errorf("kept = %q, want [active, unregistered] in order", kept)
	}
}

func TestDropRevokedKeys_AllRevoked(t *testing.T) {
	revoked, fp := testAuthorizedKey(t)
	lookup := fakeKeyLookup{rows: map[string]sshauthz.KeyRecord{fp: {Fingerprint: fp, RevokedAt: time.Now()}}}
	kept, dropped, err := dropRevokedKeys(context.Background(), lookup, []string{revoked})
	if err != nil || len(kept) != 0 || dropped != 1 {
		t.Fatalf("kept=%q dropped=%d err=%v, want none kept, 1 dropped", kept, dropped, err)
	}
}

// A registry that cannot answer must fail closed: returning the keys
// unfiltered would bring a revoked key back.
func TestDropRevokedKeys_RegistryErrorFailsClosed(t *testing.T) {
	k, _ := testAuthorizedKey(t)
	boom := errors.New("registry down")
	kept, _, err := dropRevokedKeys(context.Background(), fakeKeyLookup{err: boom}, []string{k})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped %v", err, boom)
	}
	if len(kept) != 0 {
		t.Errorf("kept = %q on error, want none", kept)
	}
}

func TestDropRevokedKeys_UnparseableKeyIsDropped(t *testing.T) {
	kept, dropped, err := dropRevokedKeys(context.Background(), fakeKeyLookup{}, []string{"not a key"})
	if err != nil || len(kept) != 0 || dropped != 1 {
		t.Fatalf("kept=%q dropped=%d err=%v", kept, dropped, err)
	}
}
