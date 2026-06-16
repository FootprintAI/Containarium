//go:build k8s

package k8s

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestE2E_BoxLifecycle drives the reconciler against a REAL apiserver (a kind
// cluster in CI). It is gated on CONTAINARIUM_K8S_E2E so it never runs in the
// plain unit suite — only scripts/k8s-e2e.sh (and the k8s-e2e workflow) set it,
// with KUBECONFIG pointing at the cluster.
//
//	CONTAINARIUM_K8S_E2E=1 KUBECONFIG=... go test -tags k8s -run TestE2E ./pkg/core/box/k8s/
func TestE2E_BoxLifecycle(t *testing.T) {
	if os.Getenv("CONTAINARIUM_K8S_E2E") == "" {
		t.Skip("set CONTAINARIUM_K8S_E2E=1 (and KUBECONFIG) to run the kind e2e")
	}

	b, err := New(Config{
		Kubeconfig:  os.Getenv("KUBECONFIG"),
		BoxImage:    "registry.k8s.io/pause:3.9",
		GatewayHost: "gateway.example.com",
	})
	if err != nil {
		t.Fatalf("New (is the cluster reachable?): %v", err)
	}

	ctx := context.Background()
	ref := box.BoxRef{Tenant: "e2e"}
	t.Cleanup(func() { _ = b.Delete(context.Background(), ref, true) })

	// Create reconciles namespace + Secret + Service + NetworkPolicy + StatefulSet.
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:       ref,
		Image:     "registry.k8s.io/pause:3.9",
		SSHKeys:   []string{"ssh-ed25519 AAAAExampleKeyForE2E test@e2e"},
		AutoStart: true,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Poll until the pod is Ready (the apiserver + kubelet actually schedule it).
	st := waitForState(t, b, ref, pb.ContainerState_CONTAINER_STATE_RUNNING, 3*time.Minute)
	if st.IPAddress == "" {
		t.Errorf("running box has no pod IP")
	}

	// Stop scales to 0 → STOPPED.
	if err := b.Stop(ctx, ref, false); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	waitForState(t, b, ref, pb.ContainerState_CONTAINER_STATE_STOPPED, time.Minute)

	// Start scales back to 1 → RUNNING.
	if err := b.Start(ctx, ref); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForState(t, b, ref, pb.ContainerState_CONTAINER_STATE_RUNNING, 3*time.Minute)

	// SetAuthorizedKeys upserts the Secret without error.
	if err := b.SetAuthorizedKeys(ctx, ref, []string{"ssh-ed25519 BBBBRotatedKey test@e2e"}); err != nil {
		t.Fatalf("SetAuthorizedKeys: %v", err)
	}

	// Delete removes the namespace; Get eventually reports absent.
	if err := b.Delete(ctx, ref, true); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		got, gerr := b.Get(ctx, ref)
		if gerr == nil && got == nil {
			return // gone
		}
		time.Sleep(3 * time.Second)
	}
	t.Error("box still present 2m after Delete")
}

func waitForState(t *testing.T, b *Backend, ref box.BoxRef, want pb.ContainerState, timeout time.Duration) *box.BoxStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last *box.BoxStatus
	for time.Now().Before(deadline) {
		st, err := b.Get(context.Background(), ref)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		last = st
		if st != nil && st.State == want {
			return st
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("box did not reach %v within %s (last: %+v)", want, timeout, last)
	return nil
}
