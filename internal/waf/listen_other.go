//go:build !linux

package waf

import (
	"fmt"
	"net"
)

// NewTransparentListener is Linux-only: IP_TRANSPARENT / TPROXY don't exist
// elsewhere. The package still compiles on the dev mac (so the proxy logic is
// unit-testable), but binding a real transparent listener errors off-Linux.
func NewTransparentListener(addr string) (net.Listener, error) {
	return nil, fmt.Errorf("waf: transparent proxy requires Linux (IP_TRANSPARENT); addr=%s", addr)
}
