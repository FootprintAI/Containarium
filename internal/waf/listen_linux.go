//go:build linux

package waf

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// NewTransparentListener binds a TCP listener with IP_TRANSPARENT so the kernel
// delivers TPROXY-steered connections with their ORIGINAL destination as the
// accepted socket's local address (recovered by TransparentProxy.OrigDst).
// Requires CAP_NET_ADMIN. Linux-only — the stub build returns an error
// elsewhere, mirroring the netbpf loader (compiles everywhere, runs on Linux).
func NewTransparentListener(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					sockErr = fmt.Errorf("set IP_TRANSPARENT (need CAP_NET_ADMIN): %w", err)
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					sockErr = fmt.Errorf("set SO_REUSEADDR: %w", err)
				}
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}
