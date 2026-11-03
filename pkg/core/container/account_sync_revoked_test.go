//go:build !windows

package container

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

const (
	syncRevokedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMw0GUYQZVPWxSAC4T8RdKFGqzb8jxbFFM/SB6ILi1Ji revoked@host"
	syncActiveKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyOtherKeyOtherKeyOtherKeyOtherKeyOtherKe active@host"
	syncUnregKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIThirdKeyThirdKeyThirdKeyThirdKeyThirdKeyThirdKe unregistered@host"
)

// syncBackend is a single running box whose authorized_keys holds the given file.
type syncBackend struct {
	incus.Backend
	name string
	file string
}

func (b *syncBackend) ListContainers() ([]incus.ContainerInfo, error) {
	return []incus.ContainerInfo{{Name: b.name}}, nil
}
func (b *syncBackend) GetContainer(string) (*incus.ContainerInfo, error) {
	return &incus.ContainerInfo{Name: b.name, State: "Running"}, nil
}
func (b *syncBackend) ReadFile(string, string) ([]byte, error) { return []byte(b.file), nil }

// recordAccounts stubs the host-side account functions and records what they
// were asked to install.
func recordAccounts(t *testing.T) *[]string {
	t.Helper()
	var installed []string
	prevC, prevA := createJumpServerAccountFn, addAuthorizedKeyFn
	createJumpServerAccountFn = func(_, key string, _ bool) error { installed = append(installed, key); return nil }
	addAuthorizedKeyFn = func(_, key string) error { installed = append(installed, key); return nil }
	t.Cleanup(func() { createJumpServerAccountFn, addAuthorizedKeyFn = prevC, prevA })
	return &installed
}

func dropOne(revoked string) KeyFilter {
	return func(_ context.Context, keys []string) ([]string, int, error) {
		var kept []string
		dropped := 0
		for _, k := range keys {
			if k == revoked {
				dropped++
				continue
			}
			kept = append(kept, k)
		}
		return kept, dropped, nil
	}
}

func syncManager() *Manager {
	return NewWithBackend(&syncBackend{
		name: "zzsyncrevoked-container",
		file: strings.Join([]string{syncRevokedKey, syncActiveKey, syncUnregKey}, "\n") + "\n",
	})
}

// #3395: a key revoked in the registry but still in the box's authorized_keys
// must not seed (or be added to) the restored host account; keys the registry
// does not know are still seeded.
func TestSyncOwnerAccounts_DropsRevokedKeys(t *testing.T) {
	installed := recordAccounts(t)
	res, err := syncManager().SyncOwnerAccounts(OwnerSyncOptions{KeyFilter: dropOne(syncRevokedKey)})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range *installed {
		if k == syncRevokedKey {
			t.Fatalf("revoked key was installed: %q", *installed)
		}
	}
	if len(*installed) != 2 || (*installed)[0] != syncActiveKey || (*installed)[1] != syncUnregKey {
		t.Fatalf("installed = %q, want [active, unregistered]", *installed)
	}
	if len(res.Restored) != 1 || res.KeysRestored["zzsyncrevoked"] != 2 || res.RevokedDropped["zzsyncrevoked"] != 1 {
		t.Fatalf("res = %+v", res)
	}
}

func TestSyncOwnerAccounts_DryRunCountsOnlyUnrevokedKeys(t *testing.T) {
	installed := recordAccounts(t)
	res, err := syncManager().SyncOwnerAccounts(OwnerSyncOptions{DryRun: true, KeyFilter: dropOne(syncRevokedKey)})
	if err != nil {
		t.Fatal(err)
	}
	if len(*installed) != 0 || res.KeysRestored["zzsyncrevoked"] != 2 {
		t.Fatalf("installed=%q res=%+v", *installed, res)
	}
}

func TestSyncOwnerAccounts_AllKeysRevokedRestoresNothing(t *testing.T) {
	installed := recordAccounts(t)
	m := NewWithBackend(&syncBackend{name: "zzsyncrevoked-container", file: syncRevokedKey + "\n"})
	res, err := m.SyncOwnerAccounts(OwnerSyncOptions{KeyFilter: dropOne(syncRevokedKey)})
	if err != nil {
		t.Fatal(err)
	}
	if len(*installed) != 0 || len(res.Restored) != 0 || len(res.AllRevoked) != 1 {
		t.Fatalf("installed=%q res=%+v", *installed, res)
	}
}

// Fail closed: a registry that cannot answer restores no account.
func TestSyncOwnerAccounts_FilterErrorFailsClosed(t *testing.T) {
	installed := recordAccounts(t)
	boom := errors.New("registry down")
	res, err := syncManager().SyncOwnerAccounts(OwnerSyncOptions{
		KeyFilter: func(context.Context, []string) ([]string, int, error) { return nil, 0, boom },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(*installed) != 0 || len(res.Restored) != 0 || len(res.Failed) != 1 || !errors.Is(res.FilterErr, boom) {
		t.Fatalf("installed=%q res=%+v", *installed, res)
	}
}

// No filter at all is also fail-closed, so a new caller cannot silently skip it.
func TestSyncOwnerAccounts_NilFilterFailsClosed(t *testing.T) {
	installed := recordAccounts(t)
	if _, err := syncManager().SyncOwnerAccounts(OwnerSyncOptions{}); err == nil {
		t.Fatal("expected an error without a KeyFilter")
	}
	if len(*installed) != 0 {
		t.Fatalf("installed = %q", *installed)
	}
}
