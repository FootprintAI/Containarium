//go:build k8s

package k8s

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/footprintai/containarium/pkg/core/box"
)

// TestSetSentinelKeyAppendsToPipes: authorizing the sentinel key adds it to
// every box's Pipe from-keys alongside the agent's key, and persists it in
// the gateway-namespace Secret so it survives a daemon restart.
func TestSetSentinelKeyAppendsToPipes(t *testing.T) {
	b, cs, _ := gatewayUpstreamBackend()
	ctx := context.Background()
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:     box.BoxRef{Tenant: "alice"},
		Image:   "x",
		SSHKeys: []string{"ssh-ed25519 AGENTKEY agent@laptop"},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, rotated, err := b.SetSentinelKey(ctx, "ssh-ed25519 SENTINELKEY sentinel@fleet")
	if err != nil {
		t.Fatalf("SetSentinelKey: %v", err)
	}
	if updated != 1 || rotated != 0 {
		t.Errorf("SetSentinelKey = (updated %d, rotated %d), want (1, 0)", updated, rotated)
	}

	// Persisted in the gateway namespace.
	sec, err := cs.CoreV1().Secrets("agent-gateway").Get(ctx, sentinelKeySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("sentinel key secret not stored: %v", err)
	}
	if !strings.Contains(string(sec.Data[sentinelKeysField]), "SENTINELKEY") {
		t.Errorf("stored sentinel key = %q", sec.Data[sentinelKeysField])
	}

	// The Pipe's from-keys now contain BOTH the agent and the sentinel key.
	from := pipeFromKeys(t, b, "alice")
	if !strings.Contains(from, "AGENTKEY") {
		t.Errorf("pipe from-keys lost the agent key: %q", from)
	}
	if !strings.Contains(from, "SENTINELKEY") {
		t.Errorf("pipe from-keys missing the sentinel key: %q", from)
	}
}

// TestSetSentinelKeyRotation: posting a different key reports rotated=1 and
// replaces the old one (not append).
func TestSetSentinelKeyRotation(t *testing.T) {
	b, _, _ := gatewayUpstreamBackend()
	ctx := context.Background()
	if _, err := b.Create(ctx, box.BoxSpec{Ref: box.BoxRef{Tenant: "bob"}, Image: "x", SSHKeys: []string{"agent"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, err := b.SetSentinelKey(ctx, "ssh-ed25519 OLD old@fleet"); err != nil {
		t.Fatalf("first SetSentinelKey: %v", err)
	}
	_, rotated, err := b.SetSentinelKey(ctx, "ssh-ed25519 NEW new@fleet")
	if err != nil {
		t.Fatalf("rotate SetSentinelKey: %v", err)
	}
	if rotated != 1 {
		t.Errorf("rotated = %d, want 1", rotated)
	}
	from := pipeFromKeys(t, b, "bob")
	if strings.Contains(from, "OLD") {
		t.Errorf("old sentinel key not replaced: %q", from)
	}
	if !strings.Contains(from, "NEW") {
		t.Errorf("new sentinel key missing: %q", from)
	}
}

// TestSetSentinelKeyRequiresGatewayMode: direct mode (no gateway upstream)
// must reject a sentinel key with a clear error.
func TestSetSentinelKeyRequiresGatewayMode(t *testing.T) {
	b, _, _ := testBackend() // no gateway upstream, no dynamic client
	if _, _, err := b.SetSentinelKey(context.Background(), "ssh-ed25519 K sentinel"); err == nil {
		t.Fatal("SetSentinelKey in direct mode should error")
	} else if !strings.Contains(err.Error(), "gateway-upstream mode") {
		t.Errorf("error = %v, want a gateway-upstream-mode message", err)
	}
}

// pipeFromKeys decodes the base64 from.authorized_keys_data of a tenant's Pipe.
func pipeFromKeys(t *testing.T, b *Backend, tenant string) string {
	t.Helper()
	p, err := b.dyn.Resource(pipeGVR).Namespace(b.cfg.GatewayNamespace).Get(context.Background(), pipeName(tenant), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pipe %s: %v", pipeName(tenant), err)
	}
	from, _, _ := unstructured.NestedSlice(p.Object, "spec", "from")
	if len(from) == 0 {
		t.Fatalf("pipe %s has no from", tenant)
	}
	f0 := from[0].(map[string]any)
	raw, _ := base64.StdEncoding.DecodeString(f0["authorized_keys_data"].(string))
	return string(raw)
}
