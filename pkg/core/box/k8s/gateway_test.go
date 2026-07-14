//go:build k8s

package k8s

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	sandboxfake "sigs.k8s.io/agent-sandbox/clients/k8s/clientset/versioned/fake"

	"github.com/footprintai/containarium/pkg/core/box"
)

// gatewayBackend wires a Backend with both a fake typed clientset and a fake
// dynamic client that knows the Pipe GVR, with the gateway namespace set so
// Pipe reconciliation is active.
func gatewayBackend() (*Backend, *dynfake.FakeDynamicClient) {
	scheme := runtime.NewScheme()
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{pipeGVR: "PipeList"})
	b := NewWithClients(fake.NewSimpleClientset(), sandboxfake.NewSimpleClientset(), dyn, Config{
		GatewayNamespace: "sshpiper",
		GatewayHost:      "gw.example.com",
	})
	return b, dyn
}

func getPipe(t *testing.T, dyn *dynfake.FakeDynamicClient, tenant string) *unstructured.Unstructured {
	t.Helper()
	p, err := dyn.Resource(pipeGVR).Namespace("sshpiper").Get(context.Background(), pipeName(tenant), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pipe %s: %v", pipeName(tenant), err)
	}
	return p
}

func TestCreateProgramsPipe(t *testing.T) {
	b, dyn := gatewayBackend()
	ctx := context.Background()
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:       box.BoxRef{Tenant: "alice"},
		Image:     "x",
		SSHKeys:   []string{"ssh-ed25519 AAAA"},
		AutoStart: true,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	p := getPipe(t, dyn, "alice")

	from, _, _ := unstructured.NestedSlice(p.Object, "spec", "from")
	if len(from) != 1 {
		t.Fatalf("spec.from len = %d, want 1", len(from))
	}
	f0 := from[0].(map[string]any)
	if f0["username"] != "alice" {
		t.Errorf("from.username = %v, want alice", f0["username"])
	}
	wantKeys := base64.StdEncoding.EncodeToString([]byte("ssh-ed25519 AAAA\n"))
	if f0["authorized_keys_data"] != wantKeys {
		t.Errorf("authorized_keys_data = %v, want %v", f0["authorized_keys_data"], wantKeys)
	}

	host, _, _ := unstructured.NestedString(p.Object, "spec", "to", "host")
	if host != "box.tenant-alice.svc.cluster.local:2222" {
		t.Errorf("to.host = %q", host)
	}
	user, _, _ := unstructured.NestedString(p.Object, "spec", "to", "username")
	if user != "agent" {
		t.Errorf("to.username = %q, want agent", user)
	}

	// Host-key pinning: known_hosts_data set (exact format), ignore_hostkey gone.
	if _, ignore, _ := unstructured.NestedBool(p.Object, "spec", "to", "ignore_hostkey"); ignore {
		t.Error("Pipe should not set ignore_hostkey when pinning")
	}
	khd, _, _ := unstructured.NestedString(p.Object, "spec", "to", "known_hosts_data")
	if khd == "" {
		t.Fatal("Pipe should pin the box host key via known_hosts_data")
	}
	raw, _ := base64.StdEncoding.DecodeString(khd)
	// Both host keys pinned (sshpiper may negotiate either), bracketed [host]:port.
	if !strings.Contains(string(raw), "[box.tenant-alice.svc.cluster.local]:2222 ssh-ed25519 ") {
		t.Errorf("known_hosts missing ed25519 line: %q", raw)
	}
	if !strings.Contains(string(raw), "[box.tenant-alice.svc.cluster.local]:2222 ssh-rsa ") {
		t.Errorf("known_hosts missing rsa line: %q", raw)
	}
}

func TestSetAuthorizedKeysUpdatesPipe(t *testing.T) {
	b, dyn := gatewayBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "bob"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x", SSHKeys: []string{"old"}, AutoStart: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.SetAuthorizedKeys(ctx, ref, []string{"rotated-key"}); err != nil {
		t.Fatalf("SetAuthorizedKeys: %v", err)
	}
	p := getPipe(t, dyn, "bob")
	from, _, _ := unstructured.NestedSlice(p.Object, "spec", "from")
	f0 := from[0].(map[string]any)
	want := base64.StdEncoding.EncodeToString([]byte("rotated-key\n"))
	if f0["authorized_keys_data"] != want {
		t.Errorf("rotated authorized_keys_data = %v, want %v", f0["authorized_keys_data"], want)
	}
}

func TestDeleteRemovesPipe(t *testing.T) {
	b, dyn := gatewayBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "carol"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x", AutoStart: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	getPipe(t, dyn, "carol") // present
	if err := b.Delete(ctx, ref, true); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := dyn.Resource(pipeGVR).Namespace("sshpiper").Get(ctx, pipeName("carol"), metav1.GetOptions{}); err == nil {
		t.Error("pipe still present after Delete")
	}
}

func TestGatewayUpstreamCredential(t *testing.T) {
	scheme := runtime.NewScheme()
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{pipeGVR: "PipeList"})
	cs := fake.NewSimpleClientset()
	b := NewWithClients(cs, sandboxfake.NewSimpleClientset(), dyn, Config{
		GatewayNamespace:         "sshpiper",
		GatewayHost:              "gw.example.com",
		GatewayUpstreamPublicKey: "ssh-ed25519 GATEWAYPUB gateway",
		GatewayUpstreamKeySecret: "sshpiper-upstream-key",
	})
	ctx := context.Background()
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:       box.BoxRef{Tenant: "alice"},
		Image:     "x",
		SSHKeys:   []string{"ssh-ed25519 AGENTPUB agent"},
		AutoStart: true,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The box authorizes the GATEWAY's key (so sshpiper can log in), NOT the
	// agent's key.
	sec, err := cs.CoreV1().Secrets("tenant-alice").Get(ctx, secretName("alice"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get box secret: %v", err)
	}
	if got := string(sec.Data[authorizedKeysKey]); got != "ssh-ed25519 GATEWAYPUB gateway\n" {
		t.Errorf("box authorized_keys = %q, want the gateway key", got)
	}

	// The Pipe authenticates the client with the agent's key (from) and
	// references the upstream private key (to.private_key_secret).
	p := getPipe(t, dyn, "alice")
	from, _, _ := unstructured.NestedSlice(p.Object, "spec", "from")
	wantAgent := base64.StdEncoding.EncodeToString([]byte("ssh-ed25519 AGENTPUB agent\n"))
	if f0 := from[0].(map[string]any); f0["authorized_keys_data"] != wantAgent {
		t.Errorf("from.authorized_keys_data = %v, want agent key", f0["authorized_keys_data"])
	}
	keyName, _, _ := unstructured.NestedString(p.Object, "spec", "to", "private_key_secret", "name")
	if keyName != "sshpiper-upstream-key" {
		t.Errorf("to.private_key_secret.name = %q, want sshpiper-upstream-key", keyName)
	}
}

func TestGatewayDisabledSkipsPipe(t *testing.T) {
	// No dynamic client (NewWithClientset) → gateway off → Create still succeeds
	// and programs no Pipe.
	b := NewWithClientset(fake.NewSimpleClientset(), sandboxfake.NewSimpleClientset(), Config{GatewayNamespace: "sshpiper"})
	if b.gatewayEnabled() {
		t.Fatal("gateway should be disabled without a dynamic client")
	}
	if _, err := b.Create(context.Background(), box.BoxSpec{Ref: box.BoxRef{Tenant: "dave"}, Image: "x", AutoStart: true}); err != nil {
		t.Fatalf("Create with gateway off: %v", err)
	}
}
