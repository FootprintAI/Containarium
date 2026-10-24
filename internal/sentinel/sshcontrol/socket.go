package sshcontrol

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

// ListenControl exposes the generated service on an operator-private socket only.
func ListenControl(path string, c *Controller) (func(), error) {
	if err := privateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket: %s", path)
		}
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil, errors.New("upstream control socket already in use")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
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
	s := grpc.NewServer()
	pb.RegisterSentinelSSHUpstreamServiceServer(s, c)
	go func() { _ = s.Serve(l) }()
	var once sync.Once
	return func() { once.Do(func() { s.Stop(); _ = l.Close() }) }, nil
}
