package server

import (
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/pkg/core/zfskey"
)

// Key custody wiring (#1342) — the switch that makes --encrypted reachable.
//
// This is the last piece of #1199 and the one that changes what an operator
// can do, so the tests here are about the switch being off by default and
// about it not depending on the order two startup calls happen to run in.

// An unset --zfs-keys-dir must leave custody unconfigured, which is what
// keeps validateEncryption refusing every encrypted create. Returning an
// error instead would stop the daemon from starting; returning a provider
// would silently turn the feature on for every existing deployment.
func TestKeyProviderFromDir_UnsetIsNotAnError(t *testing.T) {
	p, err := keyProviderFromDir("")
	if err != nil {
		t.Fatalf("an unset keys dir failed the daemon: %v", err)
	}
	if p != nil {
		t.Error("an unset keys dir produced a KeyProvider — encrypted creates would start " +
			"succeeding on every daemon that never asked for encryption")
	}
}

func TestKeyProviderFromDir_ConfiguredDirYieldsAProvider(t *testing.T) {
	p, err := keyProviderFromDir(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatalf("keyProviderFromDir: %v", err)
	}
	if p == nil {
		t.Fatal("a configured keys dir produced no provider")
	}
}

// The ordering trap.
//
// SetEncryptionStorage builds the hooks holding whatever provider the server
// has at that moment. If custody is configured afterwards, hooks built
// earlier would keep a nil provider, stay inert, and every encrypted create
// would fail with "resolved no storage pool" — on a daemon the operator had
// correctly configured. Either order has to work.
func TestSetKeyProvider_WorksInEitherOrder(t *testing.T) {
	provider, err := zfskey.NewFileKeyProvider(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}

	t.Run("custody configured before the storage wiring", func(t *testing.T) {
		s := &ContainerServer{}
		s.SetKeyProvider(provider)
		s.setEncryptionHooks("tank/tenants", &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, newFakePools())

		if !s.encryption.enabled() {
			t.Fatal("hooks are inert although key custody is configured")
		}
	})

	t.Run("custody configured after the storage wiring", func(t *testing.T) {
		s := &ContainerServer{}
		s.setEncryptionHooks("tank/tenants", &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, newFakePools())
		s.SetKeyProvider(provider)

		if !s.encryption.enabled() {
			t.Fatal("hooks built before SetKeyProvider kept a nil provider, so encryption stays " +
				"off on a daemon that configured it — the failure would look like a bug in the " +
				"create path rather than in startup ordering")
		}
	})
}

// With no custody the hooks stay inert, which is what makes the refusal in
// validateEncryption the only thing an OSS operator sees.
func TestSetEncryptionStorage_StaysInertWithoutCustody(t *testing.T) {
	s := &ContainerServer{}
	s.setEncryptionHooks("tank/tenants", &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, newFakePools())

	if s.encryption.enabled() {
		t.Error("the encryption hooks are live on a daemon with no KeyProvider — an encrypted " +
			"create would proceed with no key custody configured")
	}
}
