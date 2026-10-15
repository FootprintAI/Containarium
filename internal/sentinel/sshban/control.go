package sshban

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
)

// DefaultSocket isolates control endpoints for the two independently enforcing
// processes. No remote request can choose a filesystem path.
func DefaultSocket(listener pb.SSHBanListener) string {
	switch listener {
	case pb.SSHBanListener_SSH_BAN_LISTENER_MAIN:
		return "/run/containarium/ssh-ban/main.sock"
	case pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS:
		return "/run/containarium/ssh-ban/anonymous.sock"
	default:
		return ""
	}
}

// ListenControl exposes the enforcing Guard over a private Unix socket. Only
// stale sockets in a private directory may be removed; live servers and regular
// files are preserved. The returned stop function is idempotent.
func ListenControl(path string, g *Guard) (func(), error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("control socket requires a private directory: %s", dir)
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace a non-socket: %s", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("control socket already in use: %s", path)
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot establish stale socket: %w", dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = l.Close()
		return nil, err
	}
	server := grpc.NewServer()
	pb.RegisterSentinelSSHBanServiceServer(server, g)
	go func() { _ = server.Serve(l) }()
	var once sync.Once
	return func() { once.Do(func() { server.Stop(); _ = l.Close() }) }, nil
}
