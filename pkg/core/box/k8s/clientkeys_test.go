//go:build k8s

package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	sandboxfake "sigs.k8s.io/agent-sandbox/clients/k8s/clientset/versioned/fake"

	"github.com/footprintai/containarium/pkg/core/box"
)

// gatewayUpstreamBackend builds a backend in gateway-upstream mode (box
// authorizes the gateway key; agent key lives in client_keys / the Pipe).
func gatewayUpstreamBackend() (*Backend, *fake.Clientset, *sandboxfake.Clientset) {
	cs := fake.NewSimpleClientset()
	sc := sandboxfake.NewSimpleClientset()
	scheme := runtime.NewScheme()
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{pipeGVR: "PipeList"})
	b := NewWithClients(cs, sc, dyn, Config{
		BoxImage:                 "registry.k8s.io/pause:3.9",
		GatewayNamespace:         "agent-gateway",
		GatewayService:           "sshpiper",
		GatewayUpstreamPublicKey: "ssh-ed25519 GATEWAYPUB gateway",
		GatewayUpstreamKeySecret: "sshpiper-upstream-key",
	})
	return b, cs, sc
}

func mustCreateNodePortService(t *testing.T, cs *fake.Clientset, ns, name string, nodePort int32) {
	t.Helper()
	_, err := cs.CoreV1().Services(ns).Create(context.Background(), &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{{Name: "ssh", Port: 22, NodePort: nodePort}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create nodeport service: %v", err)
	}
}

// TestClientKeysRecordedSeparately verifies Create records the agent's keys
// under client_keys (for the sentinel sync) distinct from authorized_keys
// (what the box authorizes). In gateway-upstream mode the two MUST differ:
// authorized_keys is the gateway key, client_keys is the agent key.
func TestClientKeysRecordedSeparately(t *testing.T) {
	b, cs, _ := testBackend()
	ctx := context.Background()
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:     box.BoxRef{Tenant: "alice"},
		Image:   "x",
		SSHKeys: []string{"ssh-ed25519 AGENTKEY agent@laptop"},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	sec, err := cs.CoreV1().Secrets("tenant-alice").Get(ctx, secretName("alice"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	// No gateway upstream configured in testBackend → box authorizes the
	// agent key directly, and client_keys mirrors it.
	if got := string(sec.Data[clientKeysKey]); got != "ssh-ed25519 AGENTKEY agent@laptop\n" {
		t.Errorf("client_keys = %q, want the agent key", got)
	}

	keys, err := b.ListClientKeys(ctx)
	if err != nil {
		t.Fatalf("ListClientKeys: %v", err)
	}
	if keys["alice"] != "ssh-ed25519 AGENTKEY agent@laptop\n" {
		t.Errorf("ListClientKeys[alice] = %q", keys["alice"])
	}
}

// TestClientKeysGatewayModeSplit: with a gateway upstream key configured,
// authorized_keys holds the GATEWAY key while client_keys holds the AGENT
// key — the split the sentinel sync relies on.
func TestClientKeysGatewayModeSplit(t *testing.T) {
	b, cs, _ := gatewayUpstreamBackend()
	ctx := context.Background()
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:     box.BoxRef{Tenant: "bob"},
		Image:   "x",
		SSHKeys: []string{"ssh-ed25519 AGENTKEY agent@laptop"},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	sec, _ := cs.CoreV1().Secrets("tenant-bob").Get(ctx, secretName("bob"), metav1.GetOptions{})
	if got := string(sec.Data[authorizedKeysKey]); got != "ssh-ed25519 GATEWAYPUB gateway\n" {
		t.Errorf("authorized_keys = %q, want the gateway key", got)
	}
	if got := string(sec.Data[clientKeysKey]); got != "ssh-ed25519 AGENTKEY agent@laptop\n" {
		t.Errorf("client_keys = %q, want the agent key", got)
	}
}

// TestSetAuthorizedKeysUpdatesClientKeys: a key rotation must update the
// client_keys record so the sentinel sees the new agent key.
func TestSetAuthorizedKeysUpdatesClientKeys(t *testing.T) {
	b, cs, _ := testBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "carol"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x", SSHKeys: []string{"old-key"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.SetAuthorizedKeys(ctx, ref, []string{"rotated-key"}); err != nil {
		t.Fatalf("SetAuthorizedKeys: %v", err)
	}
	sec, _ := cs.CoreV1().Secrets("tenant-carol").Get(ctx, secretName("carol"), metav1.GetOptions{})
	if got := string(sec.Data[clientKeysKey]); got != "rotated-key\n" {
		t.Errorf("client_keys after rotation = %q, want rotated-key", got)
	}
}

// TestGatewayIngressPortResolvesNodePort verifies the SSH-ingress resolver
// reads the gateway Service's NodePort, and honors the explicit override.
func TestGatewayIngressPortResolvesNodePort(t *testing.T) {
	b, cs, _ := gatewayUpstreamBackend() // GatewayNamespace=agent-gateway, GatewayService=sshpiper
	ctx := context.Background()
	mustCreateNodePortService(t, cs, "agent-gateway", "sshpiper", 32022)

	if got := b.GatewayIngressPort(ctx); got != 32022 {
		t.Errorf("GatewayIngressPort = %d, want 32022", got)
	}

	// Explicit override wins over the Service lookup.
	b.cfg.GatewayAdvertisePort = 40000
	if got := b.GatewayIngressPort(ctx); got != 40000 {
		t.Errorf("GatewayIngressPort with override = %d, want 40000", got)
	}
}

// TestGatewayIngressPortMissingService: no Service, no override → 0 (advertise
// nothing; sentinel falls back to its legacy convention).
func TestGatewayIngressPortMissingService(t *testing.T) {
	b, _, _ := gatewayUpstreamBackend()
	if got := b.GatewayIngressPort(context.Background()); got != 0 {
		t.Errorf("GatewayIngressPort with no service = %d, want 0", got)
	}
}
