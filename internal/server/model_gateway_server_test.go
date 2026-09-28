package server

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
	"github.com/footprintai/containarium/internal/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// ModelGatewayService (#1726) — the authz + ownership matrix is the whole point
// of this service, so these tests are organised around it rather than around the
// handlers: who may call what, whose key gets spent, and what a caller can learn
// about a box that is not theirs.

// ---------- fakes ----------

// fakeGatewayKeyStore is an in-memory GatewayKeyStore. Keyed exactly as the real
// store is — (key_owner, provider) — so a test can assert per-owner isolation.
type fakeGatewayKeyStore struct {
	keys   map[string]string    // "owner|provider" -> key
	setAt  map[string]time.Time //
	setErr error
	delErr error
}

func newFakeGatewayKeyStore() *fakeGatewayKeyStore {
	return &fakeGatewayKeyStore{keys: map[string]string{}, setAt: map[string]time.Time{}}
}

func (f *fakeGatewayKeyStore) k(owner, provider string) string { return owner + "|" + provider }

func (f *fakeGatewayKeyStore) SetGatewayProviderKey(_ context.Context, owner, provider, key string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.keys[f.k(owner, provider)] = key
	f.setAt[f.k(owner, provider)] = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	return nil
}

func (f *fakeGatewayKeyStore) DeleteGatewayProviderKey(_ context.Context, owner, provider string) error {
	if f.delErr != nil {
		return f.delErr
	}
	if _, ok := f.keys[f.k(owner, provider)]; !ok {
		return secrets.ErrNotFound
	}
	delete(f.keys, f.k(owner, provider))
	return nil
}

func (f *fakeGatewayKeyStore) GatewayProviderKeyStatus(_ context.Context, owner, provider string) (secrets.GatewayKeyStatus, error) {
	key, ok := f.keys[f.k(owner, provider)]
	if !ok {
		return secrets.GatewayKeyStatus{}, nil
	}
	return secrets.GatewayKeyStatus{Set: true, Fingerprint: secrets.GatewayKeyFingerprint(key), SetAt: f.setAt[f.k(owner, provider)]}, nil
}

func (f *fakeGatewayKeyStore) KeyFor(_ context.Context, owner, provider string) (string, bool) {
	key, ok := f.keys[f.k(owner, provider)]
	return key, ok
}

// fakeBoxAttribution answers "does this box exist, and is it org-attributed".
type fakeBoxAttribution struct {
	orgs map[string]string // tenant -> cloud_org_id ("" = box exists, unstamped)
	err  error
}

func (f *fakeBoxAttribution) BoxAttribution(_ context.Context, tenant string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	org, ok := f.orgs[tenant]
	if !ok {
		return "", ErrBoxNotFound
	}
	return org, nil
}

// ---------- harness ----------

type mgHarness struct {
	srv      *ModelGatewayServer
	keys     *fakeGatewayKeyStore
	boxes    *fakeBoxAttribution
	upstream *httptest.Server
}

// newModelGatewayHarness builds a fully wired ModelGatewayServer over an
// OpenAI-shaped fake upstream registered as the provider "kafeido".
func newModelGatewayHarness(t *testing.T) *mgHarness {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"m-small"},{"id":"m-large"}]}`)
	}))
	t.Cleanup(up.Close)

	keys := newFakeGatewayKeyStore()
	boxes := &fakeBoxAttribution{orgs: map[string]string{
		"alice": "",                                     // self-hosted box, no attribution
		"bob":   "11111111-2222-3333-4444-555555555555", // cloud-attributed box
	}}
	gw := modelgateway.New(modelgateway.Config{
		Secret:      []byte("model-gateway-test-secret-at-least-32-bytes"),
		Logger:      log.New(io.Discard, "", 0),
		Providers:   map[string]*modelgateway.Provider{"kafeido": modelgateway.NewOpenAICompatibleProvider("kafeido", up.URL)},
		KeyResolver: keys,
		// Same store the daemon wires (dual_server.go), so the delete verb's
		// revocation half is exercised rather than stubbed out.
		OwnerRevocations: modelgateway.NewMemOwnerRevocations(),
	})
	srv := NewModelGatewayServer(keys, boxes, gw,
		[]byte("model-gateway-test-secret-at-least-32-bytes"), "10.0.0.1", 8080)
	return &mgHarness{srv: srv, keys: keys, boxes: boxes, upstream: up}
}

// ctxWithScopes builds an authenticated caller with an explicit scope grant.
// Explicit, never wildcard: a wildcard token would pass every gate here and
// prove nothing about the gates.
func ctxWithScopes(username string, admin bool, scopes ...string) context.Context {
	roles := []string{}
	if admin {
		roles = []string{auth.RoleAdmin}
	}
	return auth.ContextWithClaims(context.Background(), &auth.Claims{
		Username: username, Roles: roles, Scopes: scopes,
	})
}

const testOrgID = "11111111-2222-3333-4444-555555555555"

// ---------- scope gates ----------

// TestModelGateway_ScopeGates walks every RPC against a caller holding the
// WRONG scope. The two scopes must not substitute for one another: a token that
// may register a real provider key must not be able to mint, and vice versa.
func TestModelGateway_ScopeGates(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.keys.keys[h.keys.k(modelgateway.UserKeyOwner("alice"), "kafeido")] = "sk-alice"

	mintOnly := ctxWithScopes("alice", true, auth.ScopeGatewayMint)
	adminOnly := ctxWithScopes("alice", true, auth.ScopeGatewayAdmin)

	tests := []struct {
		name string
		call func(ctx context.Context) error
		// ctx holding a scope that must NOT be enough for this RPC
		wrong context.Context
		// ctx holding the scope that must be enough
		right context.Context
	}{
		{
			name: "SetTenantProviderKey needs gateway:admin",
			call: func(ctx context.Context) error {
				_, err := h.srv.SetTenantProviderKey(ctx, &pb.SetTenantProviderKeyRequest{
					KeyOwner: modelgateway.UserKeyOwner("alice"),
					Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
					ApiKey:   "sk-new",
				})
				return err
			},
			wrong: mintOnly, right: adminOnly,
		},
		{
			name: "GetTenantProviderKeyStatus needs gateway:admin",
			call: func(ctx context.Context) error {
				_, err := h.srv.GetTenantProviderKeyStatus(ctx, &pb.GetTenantProviderKeyStatusRequest{
					KeyOwner: modelgateway.UserKeyOwner("alice"),
					Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
				})
				return err
			},
			wrong: mintOnly, right: adminOnly,
		},
		{
			name: "DeleteTenantProviderKey needs gateway:admin",
			call: func(ctx context.Context) error {
				_, err := h.srv.DeleteTenantProviderKey(ctx, &pb.DeleteTenantProviderKeyRequest{
					KeyOwner: modelgateway.UserKeyOwner("alice"),
					Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
				})
				return err
			},
			wrong: mintOnly, right: adminOnly,
		},
		{
			name: "MintGatewayToken needs gateway:mint",
			call: func(ctx context.Context) error {
				_, err := h.srv.MintGatewayToken(ctx, &pb.MintGatewayTokenRequest{
					Box:      "alice",
					Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
				})
				return err
			},
			wrong: adminOnly, right: mintOnly,
		},
		{
			name: "ListGatewayModels needs gateway:mint",
			call: func(ctx context.Context) error {
				_, err := h.srv.ListGatewayModels(ctx, &pb.ListGatewayModelsRequest{
					Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
					Box:      "alice",
				})
				return err
			},
			wrong: adminOnly, right: mintOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(tt.wrong); status.Code(err) != codes.PermissionDenied {
				t.Errorf("wrong scope: code = %v (%v), want PermissionDenied", status.Code(err), err)
			}
			if err := tt.call(tt.right); status.Code(err) == codes.PermissionDenied {
				t.Errorf("right scope was still denied: %v", err)
			}
		})
	}
}

// TestModelGateway_UnauthenticatedIsRefused — no subject at all must not read as
// "unrestricted" on any of these RPCs.
func TestModelGateway_UnauthenticatedIsRefused(t *testing.T) {
	h := newModelGatewayHarness(t)
	ctx := context.Background()

	if _, err := h.srv.MintGatewayToken(ctx, &pb.MintGatewayTokenRequest{Box: "alice", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("MintGatewayToken: code = %v, want Unauthenticated", status.Code(err))
	}
	if _, err := h.srv.SetTenantProviderKey(ctx, &pb.SetTenantProviderKeyRequest{KeyOwner: modelgateway.UserKeyOwner("alice"), Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO, ApiKey: "k"}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("SetTenantProviderKey: code = %v, want Unauthenticated", status.Code(err))
	}
}

// ---------- cross-tenant: NotFound, never PermissionDenied ----------

// TestMintGatewayToken_OtherTenantsBoxIsNotFound is the cross-tenant sentry.
//
// A box name is `<username>-container`, i.e. derivable from a username, so
// PermissionDenied here would be a working oracle for "does tenant X have a box
// on this daemon". Not-yours and not-there must be indistinguishable.
func TestMintGatewayToken_OtherTenantsBoxIsNotFound(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.keys.keys[h.keys.k(modelgateway.OrgKeyOwner(testOrgID), "kafeido")] = "sk-bob-org"

	alice := ctxWithScopes("alice", false, auth.ScopeGatewayMint)

	// bob's box exists and has a usable key — everything except ownership is fine.
	_, err := h.srv.MintGatewayToken(alice, &pb.MintGatewayTokenRequest{
		Box:      "bob",
		Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
	})
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("mint for another tenant's box: code = %v (%v), want NotFound", got, err)
	}

	// A box that genuinely does not exist must be INDISTINGUISHABLE from the above.
	_, errAbsent := h.srv.MintGatewayToken(alice, &pb.MintGatewayTokenRequest{
		Box:      "nosuchtenant",
		Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
	})
	if status.Code(errAbsent) != codes.NotFound {
		t.Fatalf("mint for an absent box: code = %v, want NotFound", status.Code(errAbsent))
	}
	if err.Error() != errAbsent.Error() {
		t.Errorf("cross-tenant and absent-box errors differ, which leaks existence:\n  cross-tenant: %v\n  absent:       %v", err, errAbsent)
	}
}

// The same rule on the read verb — listing models for someone else's box must
// not confirm the box.
func TestListGatewayModels_OtherTenantsBoxIsNotFound(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.keys.keys[h.keys.k(modelgateway.OrgKeyOwner(testOrgID), "kafeido")] = "sk-bob-org"

	alice := ctxWithScopes("alice", false, auth.ScopeGatewayMint)
	_, err := h.srv.ListGatewayModels(alice, &pb.ListGatewayModelsRequest{
		Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		Box:      "bob",
	})
	if got := status.Code(err); got != codes.NotFound {
		t.Errorf("code = %v (%v), want NotFound", got, err)
	}
}

// An admin may mint for any box — the ownership check is a tenant check, not a
// blanket one.
func TestMintGatewayToken_AdminMayMintForAnyBox(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.keys.keys[h.keys.k(modelgateway.OrgKeyOwner(testOrgID), "kafeido")] = "sk-bob-org"

	operator := ctxWithScopes("operator", true, auth.ScopeGatewayMint)
	resp, err := h.srv.MintGatewayToken(operator, &pb.MintGatewayTokenRequest{
		Box:      "bob",
		Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
	})
	if err != nil {
		t.Fatalf("admin mint: %v", err)
	}
	if resp.Token == "" {
		t.Error("admin mint returned no token")
	}
}

// ---------- key_owner resolution: attribution vs username ----------

// TestMintGatewayToken_KeyOwnerResolution is the design's "org attribution when
// stamped, else the username" rule, asserted on the claim actually signed into
// the token rather than on the response alone.
func TestMintGatewayToken_KeyOwnerResolution(t *testing.T) {
	tests := []struct {
		name         string
		box          string
		caller       string
		admin        bool
		wantKeyOwner string
	}{
		{
			name:         "unstamped box resolves to the owning username",
			box:          "alice",
			caller:       "alice",
			wantKeyOwner: modelgateway.UserKeyOwner("alice"),
		},
		{
			name:         "cloud-org-attributed box resolves to the org",
			box:          "bob",
			caller:       "bob",
			wantKeyOwner: modelgateway.OrgKeyOwner(testOrgID),
		},
		{
			name:         "the -container suffix names the same box",
			box:          "bob-container",
			caller:       "bob",
			wantKeyOwner: modelgateway.OrgKeyOwner(testOrgID),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newModelGatewayHarness(t)
			h.keys.keys[h.keys.k(tt.wantKeyOwner, "kafeido")] = "sk-" + tt.wantKeyOwner

			resp, err := h.srv.MintGatewayToken(
				ctxWithScopes(tt.caller, tt.admin, auth.ScopeGatewayMint),
				&pb.MintGatewayTokenRequest{Box: tt.box, Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
			)
			if err != nil {
				t.Fatalf("MintGatewayToken: %v", err)
			}
			if resp.KeyOwner != tt.wantKeyOwner {
				t.Errorf("response key_owner = %q, want %q", resp.KeyOwner, tt.wantKeyOwner)
			}
			claims, verr := modelgateway.VerifyToken([]byte("model-gateway-test-secret-at-least-32-bytes"), resp.Token)
			if verr != nil {
				t.Fatalf("minted token does not verify: %v", verr)
			}
			if claims.KeyOwner != tt.wantKeyOwner {
				t.Errorf("claim key_owner = %q, want %q", claims.KeyOwner, tt.wantKeyOwner)
			}
			if claims.Provider != "kafeido" {
				t.Errorf("claim provider = %q, want kafeido", claims.Provider)
			}
		})
	}
}

// A key registered for the box's USERNAME must not be spendable by a token
// minted for a box attributed to an ORG (and vice versa) — the namespaces are
// disjoint, and the mint path is where that becomes observable.
func TestMintGatewayToken_AttributionSwitchesWhichKeyIsRequired(t *testing.T) {
	h := newModelGatewayHarness(t)
	// bob's box is org-attributed; register a key under bob's USERNAME only.
	h.keys.keys[h.keys.k(modelgateway.UserKeyOwner("bob"), "kafeido")] = "sk-bob-personal"

	_, err := h.srv.MintGatewayToken(
		ctxWithScopes("bob", false, auth.ScopeGatewayMint),
		&pb.MintGatewayTokenRequest{Box: "bob", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
	)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v (%v), want FailedPrecondition — the org has no key, and bob's personal key must not stand in for it", got, err)
	}
}

// ---------- dry run ----------

// TestMintGatewayToken_DryRunIssuesNoToken — `code install` uses dry_run to name
// a misconfiguration at install time. It must validate everything and hand back
// nothing usable.
func TestMintGatewayToken_DryRunIssuesNoToken(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.keys.keys[h.keys.k(modelgateway.UserKeyOwner("alice"), "kafeido")] = "sk-alice"

	resp, err := h.srv.MintGatewayToken(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.MintGatewayTokenRequest{
			Box:      "alice",
			Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
			DryRun:   true,
		})
	if err != nil {
		t.Fatalf("dry-run mint: %v", err)
	}
	if resp.Token != "" {
		t.Error("dry_run returned a token")
	}
	if resp.TokenId != "" {
		t.Error("dry_run returned a token_id")
	}
	if resp.ExpiresAt != nil {
		t.Error("dry_run returned an expires_at — nothing was issued, so nothing expires")
	}
	// It still has to tell the caller what it validated.
	if resp.KeyOwner != modelgateway.UserKeyOwner("alice") {
		t.Errorf("dry_run key_owner = %q, want the resolved owner", resp.KeyOwner)
	}
	if resp.BaseUrl == "" {
		t.Error("dry_run should still report the base_url a real mint would return")
	}
}

// A dry run must fail for the same reasons a real mint would — otherwise it is
// not a preflight.
func TestMintGatewayToken_DryRunStillEnforcesEverything(t *testing.T) {
	h := newModelGatewayHarness(t)

	// No key for the owner.
	if _, err := h.srv.MintGatewayToken(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.MintGatewayTokenRequest{Box: "alice", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO, DryRun: true},
	); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("dry-run with no key: code = %v, want FailedPrecondition", status.Code(err))
	}

	// Another tenant's box.
	h.keys.keys[h.keys.k(modelgateway.OrgKeyOwner(testOrgID), "kafeido")] = "sk-bob"
	if _, err := h.srv.MintGatewayToken(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.MintGatewayTokenRequest{Box: "bob", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO, DryRun: true},
	); status.Code(err) != codes.NotFound {
		t.Errorf("dry-run for another tenant's box: code = %v, want NotFound", status.Code(err))
	}

	// Wrong scope.
	if _, err := h.srv.MintGatewayToken(
		ctxWithScopes("alice", false, auth.ScopeGatewayAdmin),
		&pb.MintGatewayTokenRequest{Box: "alice", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO, DryRun: true},
	); status.Code(err) != codes.PermissionDenied {
		t.Errorf("dry-run with the wrong scope: code = %v, want PermissionDenied", status.Code(err))
	}
}

// ---------- TTL cap ----------

// TestMintGatewayToken_TTLIsCappedServerSide — a caller asking for a year must
// get the cap, and expires_at must agree with the signed exp. The cap is the
// server's, not a suggestion the client can raise.
func TestMintGatewayToken_TTLIsCappedServerSide(t *testing.T) {
	tests := []struct {
		name    string
		ttl     *durationpb.Duration
		wantTTL time.Duration
	}{
		{name: "unset takes the default", ttl: nil, wantTTL: DefaultGatewayTokenTTL},
		{name: "zero takes the default", ttl: durationpb.New(0), wantTTL: DefaultGatewayTokenTTL},
		{name: "under the cap is honoured", ttl: durationpb.New(30 * time.Minute), wantTTL: 30 * time.Minute},
		{name: "over the cap is capped", ttl: durationpb.New(365 * 24 * time.Hour), wantTTL: MaxGatewayTokenTTL},
		{name: "negative takes the default", ttl: durationpb.New(-time.Hour), wantTTL: DefaultGatewayTokenTTL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newModelGatewayHarness(t)
			h.keys.keys[h.keys.k(modelgateway.UserKeyOwner("alice"), "kafeido")] = "sk-alice"

			before := time.Now()
			resp, err := h.srv.MintGatewayToken(
				ctxWithScopes("alice", false, auth.ScopeGatewayMint),
				&pb.MintGatewayTokenRequest{
					Box:      "alice",
					Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
					Ttl:      tt.ttl,
				})
			if err != nil {
				t.Fatalf("MintGatewayToken: %v", err)
			}
			got := resp.ExpiresAt.AsTime().Sub(before)
			// One second of slack for the JWT's second-granularity iat/exp.
			if got > tt.wantTTL+2*time.Second || got < tt.wantTTL-2*time.Second {
				t.Errorf("effective TTL = %v, want ~%v", got, tt.wantTTL)
			}
			if got > MaxGatewayTokenTTL+2*time.Second {
				t.Errorf("effective TTL %v exceeds the server cap %v", got, MaxGatewayTokenTTL)
			}
			// The response must not promise a longer life than the token has.
			claims, verr := modelgateway.VerifyToken([]byte("model-gateway-test-secret-at-least-32-bytes"), resp.Token)
			if verr != nil {
				t.Fatalf("verify: %v", verr)
			}
			if !claims.ExpiresAt.Equal(resp.ExpiresAt.AsTime()) {
				t.Errorf("response expires_at %v != signed exp %v", resp.ExpiresAt.AsTime(), claims.ExpiresAt.Time)
			}
		})
	}
}

// ---------- run_id / allowed_models binding ----------

func TestMintGatewayToken_BindsRunIDAndAllowedModels(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.keys.keys[h.keys.k(modelgateway.UserKeyOwner("alice"), "kafeido")] = "sk-alice"

	resp, err := h.srv.MintGatewayToken(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.MintGatewayTokenRequest{
			Box:           "alice",
			Provider:      pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
			RunId:         "run-42",
			AllowedModels: []string{"m-small"},
		})
	if err != nil {
		t.Fatalf("MintGatewayToken: %v", err)
	}
	claims, err := modelgateway.VerifyToken([]byte("model-gateway-test-secret-at-least-32-bytes"), resp.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.RunID != "run-42" {
		t.Errorf("claim run_id = %q, want run-42", claims.RunID)
	}
	if len(claims.AllowedModels) != 1 || claims.AllowedModels[0] != "m-small" {
		t.Errorf("claim allowed_models = %v, want [m-small]", claims.AllowedModels)
	}
	if claims.Tenant != "alice-container" {
		t.Errorf("claim tenant = %q, want the box name", claims.Tenant)
	}
	if resp.TokenId == "" || claims.ID != resp.TokenId {
		t.Errorf("token_id %q must equal the signed jti %q so the caller can revoke it", resp.TokenId, claims.ID)
	}
	if resp.BaseUrl != "http://10.0.0.1:8080/v1/model/kafeido" {
		t.Errorf("base_url = %q, want the gateway's per-provider base", resp.BaseUrl)
	}
}

// ---------- key set / status / delete ----------

func TestSetAndGetTenantProviderKeyStatus_NeverReturnsTheKey(t *testing.T) {
	h := newModelGatewayHarness(t)
	admin := ctxWithScopes("operator", true, auth.ScopeGatewayAdmin)
	owner := modelgateway.OrgKeyOwner(testOrgID)
	const theKey = "sk-super-secret-value"

	setResp, err := h.srv.SetTenantProviderKey(admin, &pb.SetTenantProviderKeyRequest{
		KeyOwner: owner,
		Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		ApiKey:   theKey,
	})
	if err != nil {
		t.Fatalf("SetTenantProviderKey: %v", err)
	}
	wantFP := secrets.GatewayKeyFingerprint(theKey)
	if setResp.Fingerprint != wantFP {
		t.Errorf("set fingerprint = %q, want %q", setResp.Fingerprint, wantFP)
	}
	if setResp.SetAt == nil {
		t.Error("set_at is unset")
	}

	statusResp, err := h.srv.GetTenantProviderKeyStatus(admin, &pb.GetTenantProviderKeyStatusRequest{
		KeyOwner: owner,
		Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
	})
	if err != nil {
		t.Fatalf("GetTenantProviderKeyStatus: %v", err)
	}
	if !statusResp.Set {
		t.Error("status.set = false after a successful set")
	}
	if statusResp.Fingerprint != wantFP {
		t.Errorf("status fingerprint = %q, want %q", statusResp.Fingerprint, wantFP)
	}
	// The whole point: nothing on either wire message may carry the key.
	for name, msg := range map[string]interface{ String() string }{
		"SetTenantProviderKeyResponse":       setResp,
		"GetTenantProviderKeyStatusResponse": statusResp,
	} {
		if s := msg.String(); mgResponseContains(s, theKey) {
			t.Errorf("%s contains the raw key: %s", name, s)
		}
	}
}

func TestGetTenantProviderKeyStatus_UnsetIsNotAnError(t *testing.T) {
	h := newModelGatewayHarness(t)
	resp, err := h.srv.GetTenantProviderKeyStatus(
		ctxWithScopes("operator", true, auth.ScopeGatewayAdmin),
		&pb.GetTenantProviderKeyStatusRequest{
			KeyOwner: modelgateway.OrgKeyOwner(testOrgID),
			Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		})
	if err != nil {
		t.Fatalf("status for an unset key: %v", err)
	}
	if resp.Set || resp.Fingerprint != "" {
		t.Errorf("unset key reported as set=%v fingerprint=%q", resp.Set, resp.Fingerprint)
	}
}

func TestDeleteTenantProviderKey_RevokesTheOwnersLiveTokens(t *testing.T) {
	h := newModelGatewayHarness(t)
	admin := ctxWithScopes("operator", true, auth.ScopeGatewayAdmin)
	owner := modelgateway.UserKeyOwner("alice")
	h.keys.keys[h.keys.k(owner, "kafeido")] = "sk-alice"

	resp, err := h.srv.DeleteTenantProviderKey(admin, &pb.DeleteTenantProviderKeyRequest{
		KeyOwner: owner,
		Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
	})
	if err != nil {
		t.Fatalf("DeleteTenantProviderKey: %v", err)
	}
	if !resp.TokensRevoked {
		t.Error("tokens_revoked = false; removing a key must also kill the owner's live tokens")
	}
	if _, ok := h.keys.keys[h.keys.k(owner, "kafeido")]; ok {
		t.Error("key still present after delete")
	}
}

// A daemon whose gateway holds no revocable owner-revocation store must say so
// rather than imply a clean revocation: the owner's already-issued tokens outlive
// the key until they expire, and an operator has to know that.
func TestDeleteTenantProviderKey_ReportsWhenTokensCannotBeRevoked(t *testing.T) {
	keys := newFakeGatewayKeyStore()
	owner := modelgateway.UserKeyOwner("alice")
	keys.keys[keys.k(owner, "kafeido")] = "sk-alice"
	// A gateway with no OwnerRevocations store at all.
	gw := modelgateway.New(modelgateway.Config{
		Logger:    log.New(io.Discard, "", 0),
		Providers: map[string]*modelgateway.Provider{"kafeido": modelgateway.NewOpenAICompatibleProvider("kafeido", "http://127.0.0.1:1")},
	})
	srv := NewModelGatewayServer(keys, &fakeBoxAttribution{}, gw, []byte("s"), "10.0.0.1", 8080)

	resp, err := srv.DeleteTenantProviderKey(
		ctxWithScopes("operator", true, auth.ScopeGatewayAdmin),
		&pb.DeleteTenantProviderKeyRequest{KeyOwner: owner, Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO})
	if err != nil {
		t.Fatalf("DeleteTenantProviderKey: %v", err)
	}
	if resp.TokensRevoked {
		t.Error("tokens_revoked = true with no revocable store — that is a false assurance")
	}
	if _, ok := keys.keys[keys.k(owner, "kafeido")]; ok {
		t.Error("the key must still be removed even when the tokens cannot be revoked")
	}
}

func TestDeleteTenantProviderKey_AbsentKeyIsNotFound(t *testing.T) {
	h := newModelGatewayHarness(t)
	_, err := h.srv.DeleteTenantProviderKey(
		ctxWithScopes("operator", true, auth.ScopeGatewayAdmin),
		&pb.DeleteTenantProviderKeyRequest{
			KeyOwner: modelgateway.UserKeyOwner("nobody"),
			Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v (%v), want NotFound", status.Code(err), err)
	}
}

// ---------- argument validation ----------

func TestModelGateway_RejectsMalformedArguments(t *testing.T) {
	h := newModelGatewayHarness(t)
	admin := ctxWithScopes("operator", true, auth.ScopeGatewayAdmin)
	minter := ctxWithScopes("alice", false, auth.ScopeGatewayMint)

	tests := []struct {
		name string
		err  error
	}{
		{
			name: "unprefixed key_owner",
			err: func() error {
				_, err := h.srv.SetTenantProviderKey(admin, &pb.SetTenantProviderKeyRequest{
					KeyOwner: "acme", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO, ApiKey: "k",
				})
				return err
			}(),
		},
		{
			name: "key_owner with a path separator",
			err: func() error {
				_, err := h.srv.SetTenantProviderKey(admin, &pb.SetTenantProviderKeyRequest{
					KeyOwner: "org:a/b", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO, ApiKey: "k",
				})
				return err
			}(),
		},
		{
			name: "empty api_key",
			err: func() error {
				_, err := h.srv.SetTenantProviderKey(admin, &pb.SetTenantProviderKeyRequest{
					KeyOwner: modelgateway.UserKeyOwner("alice"), Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
				})
				return err
			}(),
		},
		{
			name: "unspecified provider on set",
			err: func() error {
				_, err := h.srv.SetTenantProviderKey(admin, &pb.SetTenantProviderKeyRequest{
					KeyOwner: modelgateway.UserKeyOwner("alice"), ApiKey: "k",
				})
				return err
			}(),
		},
		{
			name: "unspecified provider on mint",
			err: func() error {
				_, err := h.srv.MintGatewayToken(minter, &pb.MintGatewayTokenRequest{Box: "alice"})
				return err
			}(),
		},
		{
			name: "empty box on mint",
			err: func() error {
				_, err := h.srv.MintGatewayToken(minter, &pb.MintGatewayTokenRequest{
					Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
				})
				return err
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if status.Code(tt.err) != codes.InvalidArgument {
				t.Errorf("code = %v (%v), want InvalidArgument", status.Code(tt.err), tt.err)
			}
		})
	}
}

// A provider the daemon does not serve must not read as "your key is missing".
func TestMintGatewayToken_ProviderNotServedByThisDaemon(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.keys.keys[h.keys.k(modelgateway.UserKeyOwner("alice"), "anthropic")] = "sk-alice"

	_, err := h.srv.MintGatewayToken(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.MintGatewayTokenRequest{Box: "alice", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_ANTHROPIC},
	)
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v (%v), want FailedPrecondition", status.Code(err), err)
	}
}

// ---------- gateway not configured at all ----------

// A daemon that does not serve the model gateway must say so, not return a
// token that can never be used.
func TestModelGateway_InertWhenTheGatewayIsNotServed(t *testing.T) {
	keys := newFakeGatewayKeyStore()
	keys.keys[keys.k(modelgateway.UserKeyOwner("alice"), "kafeido")] = "sk-alice"
	srv := NewModelGatewayServer(keys, &fakeBoxAttribution{orgs: map[string]string{"alice": ""}}, nil, nil, "", 0)

	if _, err := srv.MintGatewayToken(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.MintGatewayTokenRequest{Box: "alice", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
	); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("mint without a gateway: code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := srv.ListGatewayModels(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.ListGatewayModelsRequest{Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
	); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("list without a gateway: code = %v, want FailedPrecondition", status.Code(err))
	}
}

// A daemon with no secrets store cannot hold per-owner keys at all.
func TestModelGateway_UnavailableWithoutAKeyStore(t *testing.T) {
	srv := NewModelGatewayServer(nil, &fakeBoxAttribution{}, nil, nil, "", 0)
	if _, err := srv.SetTenantProviderKey(
		ctxWithScopes("operator", true, auth.ScopeGatewayAdmin),
		&pb.SetTenantProviderKeyRequest{KeyOwner: modelgateway.UserKeyOwner("a"), Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO, ApiKey: "k"},
	); status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", status.Code(err))
	}
}

// ---------- ListGatewayModels ----------

func TestListGatewayModels_UsesTheResolvedOwnersKey(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.keys.keys[h.keys.k(modelgateway.UserKeyOwner("alice"), "kafeido")] = "sk-alice"

	resp, err := h.srv.ListGatewayModels(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.ListGatewayModelsRequest{Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO, Box: "alice"},
	)
	if err != nil {
		t.Fatalf("ListGatewayModels: %v", err)
	}
	if len(resp.Models) != 2 || resp.Models[0].Id != "m-small" {
		t.Errorf("models = %v", resp.Models)
	}
	if resp.KeyOwner != modelgateway.UserKeyOwner("alice") {
		t.Errorf("key_owner = %q", resp.KeyOwner)
	}
}

// With no box named, the caller's own owner id is used — the CLI's
// `containarium gateway models --provider …` shape.
func TestListGatewayModels_NoBoxUsesTheCallersOwnOwner(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.keys.keys[h.keys.k(modelgateway.UserKeyOwner("carol"), "kafeido")] = "sk-carol"

	resp, err := h.srv.ListGatewayModels(
		ctxWithScopes("carol", false, auth.ScopeGatewayMint),
		&pb.ListGatewayModelsRequest{Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
	)
	if err != nil {
		t.Fatalf("ListGatewayModels: %v", err)
	}
	if resp.KeyOwner != modelgateway.UserKeyOwner("carol") {
		t.Errorf("key_owner = %q, want the caller's own", resp.KeyOwner)
	}
}

func TestListGatewayModels_NoKeyIsFailedPrecondition(t *testing.T) {
	h := newModelGatewayHarness(t)
	_, err := h.srv.ListGatewayModels(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.ListGatewayModelsRequest{Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
	)
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v (%v), want FailedPrecondition", status.Code(err), err)
	}
}

// An upstream 401 is the customer's key being wrong — it must not surface as an
// internal error, or the operator gets paged for a customer's typo.
func TestListGatewayModels_UpstreamUnauthorizedMapsToFailedPrecondition(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"bad key"}`)
	}))
	defer up.Close()

	keys := newFakeGatewayKeyStore()
	keys.keys[keys.k(modelgateway.UserKeyOwner("alice"), "kafeido")] = "sk-stale"
	gw := modelgateway.New(modelgateway.Config{
		Logger:      log.New(io.Discard, "", 0),
		Providers:   map[string]*modelgateway.Provider{"kafeido": modelgateway.NewOpenAICompatibleProvider("kafeido", up.URL)},
		KeyResolver: keys,
	})
	srv := NewModelGatewayServer(keys, &fakeBoxAttribution{orgs: map[string]string{"alice": ""}}, gw, []byte("s"), "10.0.0.1", 8080)

	_, err := srv.ListGatewayModels(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.ListGatewayModelsRequest{Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
	)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v (%v), want FailedPrecondition", got, err)
	}
}

// ---------- box lookup failures ----------

// A box-store failure is Internal, not NotFound: reporting "no such box" when
// the lookup itself broke would send a caller chasing the wrong problem.
func TestMintGatewayToken_BoxLookupFailureIsInternal(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.boxes.err = errors.New("incus is down")
	_, err := h.srv.MintGatewayToken(
		ctxWithScopes("alice", false, auth.ScopeGatewayMint),
		&pb.MintGatewayTokenRequest{Box: "alice", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
	)
	if status.Code(err) != codes.Internal {
		t.Errorf("code = %v (%v), want Internal", status.Code(err), err)
	}
}

// A malformed cloud_org_id label must not become a malformed key_owner — the
// prefix discipline #1725 established has to hold at the mint boundary too.
func TestMintGatewayToken_MalformedOrgAttributionIsRefused(t *testing.T) {
	h := newModelGatewayHarness(t)
	h.boxes.orgs["dave"] = "org/with/slashes"
	h.keys.keys[h.keys.k(modelgateway.UserKeyOwner("dave"), "kafeido")] = "sk-dave"

	_, err := h.srv.MintGatewayToken(
		ctxWithScopes("dave", false, auth.ScopeGatewayMint),
		&pb.MintGatewayTokenRequest{Box: "dave", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
	)
	if status.Code(err) != codes.Internal {
		t.Errorf("code = %v (%v), want Internal — a bad attribution label must not silently fall back to the username's key", status.Code(err), err)
	}
}

func mgResponseContains(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
