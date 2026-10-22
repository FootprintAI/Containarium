//go:build integration

// Postgres-backed owner revocation, end to end through the daemon's own
// wiring (#2111): removing a tenant's provider key revokes that owner's
// tokens, and the revocation survives a daemon restart.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/server/
package server

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The restart case the owner cutoff exists for: a token minted before the key
// was removed must not resolve through the daemon-global ProviderKeys fallback
// after the daemon comes back up.
func TestDeleteTenantProviderKey_PostgresBacked_RevokesAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	secret := []byte("model-gateway-test-secret-at-least-32-bytes")
	owner := modelgateway.UserKeyOwner("alice")

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"model":"m","usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	t.Cleanup(up.Close)

	// newDaemonGateway builds the gateway the way dual_server.go does, from a
	// store constructed on a fresh pool — each call is one daemon lifetime.
	// The daemon holds a GLOBAL key for the provider, which is exactly the
	// fallback a pre-removal token would otherwise spend.
	newDaemonGateway := func(keys *fakeGatewayKeyStore) *modelgateway.Gateway {
		t.Helper()
		pg, err := auth.NewPgOwnerRevocationStore(ctx, testPool(t))
		if err != nil {
			t.Fatalf("NewPgOwnerRevocationStore: %v", err)
		}
		return modelgateway.New(modelgateway.Config{
			Secret:           secret,
			Logger:           log.New(io.Discard, "", 0),
			Providers:        map[string]*modelgateway.Provider{"kafeido": modelgateway.NewOpenAICompatibleProvider("kafeido", up.URL)},
			ProviderKeys:     map[string]string{"kafeido": "sk-daemon-global"},
			KeyResolver:      keys,
			OwnerRevocations: gatewayOwnerRevocations(pg),
		})
	}
	call := func(gw *modelgateway.Gateway, tok string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/model/kafeido/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	pool := testPool(t)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS gateway_owner_revocations`); err != nil {
		t.Fatalf("reset: %v", err)
	}

	keys := newFakeGatewayKeyStore()
	keys.keys[keys.k(owner, "kafeido")] = "sk-alice"
	gw := newDaemonGateway(keys)

	// iat is second-granular and the cutoff kills at-or-before, so mint in a
	// second strictly before the revocation to prove the kill is the cutoff's
	// doing, not a same-second tie.
	tok, err := modelgateway.MintToken(secret, modelgateway.GatewayClaims{Tenant: "alice-box", Provider: "kafeido", KeyOwner: owner}, time.Hour)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if got := call(gw, tok); got != http.StatusOK {
		t.Fatalf("before removal: token got %d, want 200", got)
	}
	time.Sleep(1100 * time.Millisecond)

	srv := NewModelGatewayServer(keys, &fakeBoxAttribution{}, gw, secret, "10.0.0.1", 8080)
	resp, err := srv.DeleteTenantProviderKey(
		ctxWithScopes("operator", true, auth.ScopeGatewayAdmin),
		&pb.DeleteTenantProviderKeyRequest{KeyOwner: owner, Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO})
	if err != nil {
		t.Fatalf("DeleteTenantProviderKey: %v", err)
	}
	if !resp.TokensRevoked {
		t.Error("tokens_revoked = false on a Postgres-backed daemon; the durable store can record the revocation")
	}
	if got := call(gw, tok); got != http.StatusUnauthorized {
		t.Errorf("after removal, same daemon: token got %d, want 401", got)
	}

	// Restart: nothing in-process survives — a new pool, a new store, a new
	// gateway. The owner's key is gone, so without the durable cutoff this
	// token would resolve through the daemon-global key and get a 200.
	restarted := newDaemonGateway(keys)
	if got := call(restarted, tok); got != http.StatusUnauthorized {
		t.Errorf("after restart: pre-removal token got %d, want 401 — the restart forgot the owner revocation "+
			"and the token fell through to the daemon-global key", got)
	}

	// And the cutoff is not a permanent ban: a token minted after it works.
	time.Sleep(1100 * time.Millisecond)
	fresh, err := modelgateway.MintToken(secret, modelgateway.GatewayClaims{Tenant: "alice-box", Provider: "kafeido", KeyOwner: owner}, time.Hour)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if got := call(restarted, fresh); got != http.StatusOK {
		t.Errorf("token minted after the cutoff got %d, want 200", got)
	}
}
