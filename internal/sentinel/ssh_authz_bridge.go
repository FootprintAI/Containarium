package sentinel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
)

type authzKeyStoreResolver struct{ ks *KeyStore }

func (r authzKeyStoreResolver) ResolveBackend(_ context.Context, login string) (string, bool, error) {
	id, ok := r.ks.BackendForLogin(login)
	return id, ok, nil
}

// startSSHAuthzBridge exposes the live keystore only through a private Unix
// socket. sshpiperd runs the authz plugin in another process, without the
// manager's memory or signing environment. The manager signs the daemon call.
func (m *Manager) startSSHAuthzBridge(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("ssh authz bridge: %s is not a socket", path)
		}
		// Never unlink a socket owned by a running manager.
		c, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("ssh authz bridge: %s already listening", path)
		}
		if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	authorizer := &sshauthz.HTTPAuthorizer{BackendURL: m.ShipperBackendURL, Sign: SignRequest}
	srv := &http.Server{Handler: sshauthz.BridgeHandler(authzKeyStoreResolver{m.keyStore}, authorizer), ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return func() { _ = srv.Close(); _ = ln.Close() }, nil
}
