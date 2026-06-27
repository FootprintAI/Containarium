//go:build !windows

package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// TestNewBoxBackend_SelectsLXC verifies that "lxc" (the default) selects the
// LXC backend.
func TestNewBoxBackend_SelectsLXC(t *testing.T) {
	mgr := container.NewWithBackend(incustest.NewMockBackend())
	bb, err := newBoxBackend(RuntimeLXC, mgr)
	if err != nil {
		t.Fatalf("newBoxBackend(lxc): %v", err)
	}
	if bb.Kind() != box.KindLXC {
		t.Errorf("Kind() = %q, want %q", bb.Kind(), box.KindLXC)
	}
}

// TestNewBoxBackend_UnknownRuntimeErrors verifies that an unrecognized runtime
// returns a clear error rather than silently falling through.
func TestNewBoxBackend_UnknownRuntimeErrors(t *testing.T) {
	mgr := container.NewWithBackend(incustest.NewMockBackend())
	_, err := newBoxBackend("qemu", mgr)
	if err == nil {
		t.Fatal("expected error for unknown runtime, got nil")
	}
}
