//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/footprintai/containarium/internal/sshauthz"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
)

type ownerSyncBackend struct {
	incus.Backend
	file string
}

func (b *ownerSyncBackend) ListContainers() ([]incus.ContainerInfo, error) {
	return []incus.ContainerInfo{{Name: "zzownersync-container"}}, nil
}
func (b *ownerSyncBackend) GetContainer(string) (*incus.ContainerInfo, error) {
	return &incus.ContainerInfo{Name: "zzownersync-container", State: "Running"}, nil
}
func (b *ownerSyncBackend) ReadFile(string, string) ([]byte, error) { return []byte(b.file), nil }

func stubRegistry(t *testing.T, reg sshauthz.KeyLookup, err error) {
	t.Helper()
	prev := openKeyRegistry
	openKeyRegistry = func(context.Context, string) (sshauthz.KeyLookup, func(), error) { return reg, nil, err }
	t.Cleanup(func() { openKeyRegistry = prev })
}

// DryRun keeps the test off the host: the wiring is what is under test, and
// KeysRestored shows which keys survived the registry filter.
func TestSyncOwnerAccountsFiltered_RegistryWiring(t *testing.T) {
	revoked, revokedFP := testAuthorizedKey(t)
	unregistered, _ := testAuthorizedKey(t)
	mgr := container.NewWithBackend(&ownerSyncBackend{file: revoked + unregistered})

	t.Run("revoked key dropped, unregistered kept", func(t *testing.T) {
		stubRegistry(t, fakeKeyLookup{rows: map[string]sshauthz.KeyRecord{
			revokedFP: {Fingerprint: revokedFP, RevokedAt: time.Now()},
		}}, nil)
		res, err := syncOwnerAccountsFiltered(mgr, "dsn", container.OwnerSyncOptions{DryRun: true})
		if err != nil {
			t.Fatal(err)
		}
		if res.KeysRestored["zzownersync"] != 1 || res.RevokedDropped["zzownersync"] != 1 {
			t.Fatalf("res = %+v, want 1 key kept and 1 dropped", res)
		}
	})

	t.Run("registry unreachable fails closed", func(t *testing.T) {
		boom := errors.New("db down")
		stubRegistry(t, nil, boom)
		res, err := syncOwnerAccountsFiltered(mgr, "dsn", container.OwnerSyncOptions{DryRun: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Restored) != 0 || len(res.Failed) != 1 || !errors.Is(res.FilterErr, boom) {
			t.Fatalf("res = %+v, want nothing restored and the registry error surfaced", res)
		}
	})

	t.Run("registry lookup error fails closed", func(t *testing.T) {
		boom := errors.New("lookup failed")
		stubRegistry(t, fakeKeyLookup{err: boom}, nil)
		res, _ := syncOwnerAccountsFiltered(mgr, "dsn", container.OwnerSyncOptions{DryRun: true})
		if len(res.Restored) != 0 || !errors.Is(res.FilterErr, boom) {
			t.Fatalf("res = %+v", res)
		}
	})
}

// fakeKeyLookup is an in-memory registry; a missing fingerprint answers
// ErrKeyNotFound like the real store, err forces a failure.
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

// Both entry points (sync-accounts, daemon startup) must go through
// syncOwnerAccountsFiltered. A direct SyncOwnerAccounts call elsewhere in this
// package could pass a permissive KeyFilter and bring revoked keys back (#3395).
func TestOwnerSyncOnlyThroughFilteredHelper(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "owner_sync_registry.go" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), ".SyncOwnerAccounts(") {
			t.Errorf("%s calls SyncOwnerAccounts directly; use syncOwnerAccountsFiltered", f)
		}
	}
	for _, f := range []string{"sync_accounts.go", "daemon.go"} {
		b, _ := os.ReadFile(f)
		if !strings.Contains(string(b), "syncOwnerAccountsFiltered(") {
			t.Errorf("%s does not use syncOwnerAccountsFiltered", f)
		}
	}
}
