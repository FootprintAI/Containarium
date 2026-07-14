//go:build k8s

package k8s

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	sandboxfake "sigs.k8s.io/agent-sandbox/clients/k8s/clientset/versioned/fake"

	"github.com/footprintai/containarium/pkg/core/box"
)

// TestSetTTLStampsShutdownTimeAndMeta verifies SetTTL writes both halves of
// the TTL contract in one patch: spec.shutdownTime (+ Retain policy) for the
// controller-side stop, and the ttl_expires_at meta annotation the daemon's
// sweeper reads via List/GetMeta.
func TestSetTTLStampsShutdownTimeAndMeta(t *testing.T) {
	b, _, sc := testBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "ttl-user"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x", AutoStart: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	expiresAt := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	if err := b.SetTTL(ctx, ref, &expiresAt); err != nil {
		t.Fatalf("SetTTL: %v", err)
	}

	sb := getSandbox(t, sc, "tenant-ttl-user")
	if sb.Spec.ShutdownTime == nil || !sb.Spec.ShutdownTime.Time.Equal(expiresAt) {
		t.Errorf("shutdownTime = %v, want %v", sb.Spec.ShutdownTime, expiresAt)
	}
	if sb.Spec.ShutdownPolicy == nil || *sb.Spec.ShutdownPolicy != sandboxv1beta1.ShutdownPolicyRetain {
		t.Errorf("shutdownPolicy = %v, want Retain (Delete would orphan the daemon-owned Pipe/Secrets/PVC)", sb.Spec.ShutdownPolicy)
	}

	// The sweeper reads the expiry off box meta (BoxStatus.Labels via List).
	meta, err := b.GetMeta(ctx, ref)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	got, perr := time.Parse(time.RFC3339, meta[metaTTLExpiresAtKey])
	if perr != nil || !got.Equal(expiresAt) {
		t.Errorf("meta %s = %q (parse err %v), want %v", metaTTLExpiresAtKey, meta[metaTTLExpiresAtKey], perr, expiresAt)
	}

	// Clear: both halves removed.
	if err := b.SetTTL(ctx, ref, nil); err != nil {
		t.Fatalf("SetTTL(clear): %v", err)
	}
	sb = getSandbox(t, sc, "tenant-ttl-user")
	if sb.Spec.ShutdownTime != nil {
		t.Errorf("shutdownTime not cleared: %v", sb.Spec.ShutdownTime)
	}
	meta, _ = b.GetMeta(ctx, ref)
	if _, ok := meta[metaTTLExpiresAtKey]; ok {
		t.Errorf("meta %s not cleared: %q", metaTTLExpiresAtKey, meta[metaTTLExpiresAtKey])
	}
}

// TestTTLCapableAssertion pins the capability discovery the server relies on:
// the k8s backend must satisfy box.TTLCapable via a plain type assertion.
func TestTTLCapableAssertion(t *testing.T) {
	b := NewWithClientset(fake.NewSimpleClientset(), sandboxfake.NewSimpleClientset(), Config{})
	if _, ok := interface{}(b).(box.TTLCapable); !ok {
		t.Fatal("k8s Backend must implement box.TTLCapable")
	}
}
