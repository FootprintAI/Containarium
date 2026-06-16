//go:build !k8s

package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// TestNewBoxBackend_SelectsLXC — the default build selects the LXC backend.
// The k8s build variant's selection is exercised by the k8s package's own
// skeleton test (go test -tags k8s ./pkg/core/box/k8s/).
func TestNewBoxBackend_SelectsLXC(t *testing.T) {
	mgr := container.NewWithBackend(incustest.NewMockBackend())
	bb, err := newBoxBackend(mgr)
	if err != nil {
		t.Fatalf("newBoxBackend: %v", err)
	}
	if bb == nil {
		t.Fatal("newBoxBackend returned nil backend")
	}
	if bb.Kind() != box.KindLXC {
		t.Errorf("Kind() = %q, want %q", bb.Kind(), box.KindLXC)
	}
}
