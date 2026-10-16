//go:build !windows

package sentinel

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/gateway"
	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
)

func TestSSHAuthzBridgeUsesKeyStoreAndPrivateSocket(t *testing.T) {
	ks := NewKeyStore()
	ks.backends["z"] = &backendKeys{backendID: "z", users: []gateway.UserKeys{{Username: "alice"}}}
	ks.backends["a"] = &backendKeys{backendID: "a", users: []gateway.UserKeys{{Username: "alice"}}}
	manager := &Manager{keyStore: ks}
	path := filepath.Join(t.TempDir(), "authz.sock")
	stop, err := manager.startSSHAuthzBridge(path)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("socket mode: %v %v", st, err)
	}
	client := sshauthz.NewBridgeClient(path)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, known, err := client.ResolveBackend(ctx, "alice")
	if err != nil || !known || b != "a" {
		t.Fatalf("keystore winner: %s %v %v", b, known, err)
	}
	ks.RemoveBackend("a")
	b, known, err = client.ResolveBackend(ctx, "alice")
	if err != nil || !known || b != "z" {
		t.Fatalf("keystore update: %s %v %v", b, known, err)
	}
	if _, err := manager.startSSHAuthzBridge(path); err == nil {
		t.Fatal("replaced a live socket")
	}
	if _, _, err := client.ResolveBackend(ctx, "alice"); err != nil {
		t.Fatal("live socket disturbed")
	}
}

func TestSSHAuthzBridgeRefusesRegularFileAndRecoversStaleSocket(t *testing.T) {
	manager := &Manager{keyStore: NewKeyStore()}
	path := filepath.Join(t.TempDir(), "socket")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.startSSHAuthzBridge(path); err == nil {
		t.Fatal("replaced a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "keep" {
		t.Fatal("regular file modified")
	}
	stale := filepath.Join(t.TempDir(), "stale.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	_ = ln.Close()
	stop, err := manager.startSSHAuthzBridge(stale)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("socket not removed on shutdown: %v", err)
	}
}
