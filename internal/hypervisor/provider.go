// Package hypervisor implements the host-side half of console access to a
// BYOC VM host that is itself unreachable — see
// docs/architecture/byoc-vm-console-access.md. It runs on the physical
// machine hosting the VM (VirtualBox, today), not inside any guest, since a
// guest hung at BIOS POST has nothing running that could serve its own
// console.
package hypervisor

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
)

// ConsoleProvider returns a raw byte stream to a target's serial console.
// No PTY negotiation, no shell — a serial console is a dumb byte pipe.
type ConsoleProvider interface {
	OpenConsole(ctx context.Context, target string) (io.ReadWriteCloser, error)
}

// VirtualBoxProvider is a ConsoleProvider backed by VirtualBox's
// serial-port-to-UNIX-socket redirect
// (`VBoxManage modifyvm <vm> --uart1 0x3F8 4 --uartmode1 server <path>`),
// configured once per guest while it is powered off — VirtualBox does not
// accept UART changes on a running VM. OpenConsole itself is a plain
// `net.Dial("unix", ...)`; no VBoxManage subprocess at attach time.
type VirtualBoxProvider struct {
	// SocketPath resolves a guest name to the UNIX socket path its serial
	// port was configured to serve on. Required.
	SocketPath func(target string) (string, error)
}

// NewVirtualBoxProvider returns a VirtualBoxProvider using the convention
// "<baseDir>/<target>.sock" — the path this package's own provisioning
// helper (see docs/architecture/byoc-vm-console-access.md) uses when it
// sets up a guest's serial redirect. A deployment that names its sockets
// differently can build a VirtualBoxProvider directly with a custom
// SocketPath instead.
func NewVirtualBoxProvider(baseDir string) *VirtualBoxProvider {
	return &VirtualBoxProvider{
		SocketPath: func(target string) (string, error) {
			if target == "" {
				return "", fmt.Errorf("hypervisor: target is required")
			}
			return filepath.Join(baseDir, target+".sock"), nil
		},
	}
}

// OpenConsole implements ConsoleProvider.
func (p *VirtualBoxProvider) OpenConsole(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	if p.SocketPath == nil {
		return nil, fmt.Errorf("hypervisor: VirtualBoxProvider has no SocketPath resolver configured")
	}
	path, err := p.SocketPath(target)
	if err != nil {
		return nil, fmt.Errorf("hypervisor: resolve console socket for %q: %w", target, err)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("hypervisor: dial console socket %q for %q: %w", path, target, err)
	}
	return conn, nil
}
