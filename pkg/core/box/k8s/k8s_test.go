//go:build k8s

package k8s

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/pkg/core/box"
)

// TestSkeletonShape locks the build-tag seam: the K8s backend constructs,
// reports its kind, and every lifecycle method returns ErrNotImplemented until
// the real reconciliation lands. Run with: go test -tags k8s ./pkg/core/box/k8s/
func TestSkeletonShape(t *testing.T) {
	b, err := New(Config{GatewayHost: "gw.example.com", GatewaySSHPort: 22})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if b.Kind() != box.KindK8s {
		t.Fatalf("Kind() = %q, want %q", b.Kind(), box.KindK8s)
	}

	ctx := context.Background()
	ref := box.BoxRef{Tenant: "alice"}

	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Create err = %v, want ErrNotImplemented", err)
	}
	if _, err := b.Get(ctx, ref); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Get err = %v, want ErrNotImplemented", err)
	}
	if err := b.Start(ctx, ref); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Start err = %v, want ErrNotImplemented", err)
	}
	if err := b.SetAuthorizedKeys(ctx, ref, nil); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("SetAuthorizedKeys err = %v, want ErrNotImplemented", err)
	}

	// The skeleton must NOT advertise ExecCapable — K8s provisioning is
	// image-baked (ForceCommand), so there's no in-box exec seam.
	if _, ok := interface{}(b).(box.ExecCapable); ok {
		t.Error("k8s Backend should not implement box.ExecCapable")
	}
}
