package server

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/modelgateway"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Skill/crew run gateway tokens carry a key_owner claim (#2134).
//
// Every skill run, crew member and queue worker is provisioned through
// provisionSkillBox, which mints the run's gateway token with
// mintRunGatewayToken. Before #2134 that mint left KeyOwner empty, so every
// run resolved through the daemon-global key (keyowner.go resolveKey case 1)
// no matter which owner had registered a key, and RevokeByKeyOwner could not
// reach a run's token at all.

// ownerKeyResolver is a fake modelgateway.KeyResolver over a fixed
// (keyOwner, provider) table that records every lookup, so a test can assert
// which owner was consulted — and that an unowned run never reaches it.
type ownerKeyResolver struct {
	mu    sync.Mutex
	keys  map[string]string // "<keyOwner>|<provider>" -> real key
	calls []string
}

func (r *ownerKeyResolver) KeyFor(_ context.Context, keyOwner, provider string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, keyOwner+"|"+provider)
	k, ok := r.keys[keyOwner+"|"+provider]
	return k, ok
}

func (r *ownerKeyResolver) lookups() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// runGatewayRig is a real modelgateway.Gateway in front of a fake upstream
// that records the Authorization header it was handed, sharing its HMAC
// secret with an AgentSkillServer's gatewayProvisioning — so a token minted on
// the run path can be spent through the real gateway and the key that reached
// the upstream observed.
type runGatewayRig struct {
	s        *AgentSkillServer
	gw       *modelgateway.Gateway
	resolver *ownerKeyResolver
	url      string

	mu       sync.Mutex
	upAuth   []string
	upstream *httptest.Server
}

func newRunGatewayRig(t *testing.T, ownerKeys map[string]string) *runGatewayRig {
	t.Helper()
	rig := &runGatewayRig{resolver: &ownerKeyResolver{keys: ownerKeys}}
	rig.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.mu.Lock()
		rig.upAuth = append(rig.upAuth, r.Header.Get("Authorization"))
		rig.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"model":"m","usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	t.Cleanup(rig.upstream.Close)

	secret := []byte("test-shared-secret")
	providers := modelgateway.DefaultProviders()
	providers["openai"].UpstreamURL = rig.upstream.URL
	rig.gw = modelgateway.New(modelgateway.Config{
		Secret:           secret,
		Providers:        providers,
		ProviderKeys:     map[string]string{"openai": "DAEMON-GLOBAL"},
		KeyResolver:      rig.resolver,
		OwnerRevocations: modelgateway.NewMemOwnerRevocations(),
		Logger:           log.New(io.Discard, "", 0),
	})
	srv := httptest.NewServer(rig.gw.Handler())
	t.Cleanup(srv.Close)
	rig.url = srv.URL + "/v1/model/openai/v1/chat/completions"

	rig.s = &AgentSkillServer{
		gateway: &gatewayProvisioning{provider: "openai", httpPort: 8080, secret: secret},
	}
	return rig
}

// call spends tok through the gateway and returns the status and body.
func (rig *runGatewayRig) call(t *testing.T, tok string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rig.url, strings.NewReader(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (rig *runGatewayRig) upstreamAuth() []string {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	return append([]string(nil), rig.upAuth...)
}

// boxWithLabels is the *pb.Container provisionSkillBox holds for the run's box.
func boxWithLabels(labels map[string]string) *pb.Container {
	return &pb.Container{Labels: labels}
}

// TestRunKeyOwner is the resolution table for a run's key_owner: the box's
// cloud-org attribution when stamped (as MintGatewayToken resolves it), else
// the dispatching caller's username, else no owner at all. An owner that does
// not validate is never stamped.
func TestRunKeyOwner(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		box  *pb.Container
		want string
	}{
		{"owned run, no attribution -> the caller's username", ctxAs("alice", false), boxWithLabels(nil), "user:alice"},
		{"admin-dispatched run is the admin's", ctxAs("ops", true), boxWithLabels(nil), "user:ops"},
		{"cloud attribution wins over the caller", ctxAs("alice", false), boxWithLabels(map[string]string{cloudOrgIDLabel: "org-123"}), "org:org-123"},
		{"blank attribution is not attribution", ctxAs("alice", false), boxWithLabels(map[string]string{cloudOrgIDLabel: "  "}), "user:alice"},
		{"nil box falls back to the caller", ctxAs("alice", false), nil, "user:alice"},
		{"system context (no subject) has no owner", context.Background(), boxWithLabels(nil), ""},
		{"system context still honors a stamped attribution", context.Background(), boxWithLabels(map[string]string{cloudOrgIDLabel: "org-123"}), "org:org-123"},
		{"malformed attribution is never stamped", ctxAs("alice", false), boxWithLabels(map[string]string{cloudOrgIDLabel: "a/b"}), ""},
		{"malformed username is never stamped", ctxAs("bad name", false), boxWithLabels(nil), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runKeyOwner(tc.ctx, tc.box)
			if got != tc.want {
				t.Errorf("runKeyOwner = %q, want %q", got, tc.want)
			}
			if got != "" {
				if err := modelgateway.ValidateKeyOwner(got); err != nil {
					t.Errorf("runKeyOwner returned an owner that does not validate: %v", err)
				}
			}
		})
	}
}

// TestMintRunGatewayToken_OwnedRunCarriesKeyOwner: the token the run path mints
// for an owned run carries key_owner, alongside the claims it always had.
func TestMintRunGatewayToken_OwnedRunCarriesKeyOwner(t *testing.T) {
	rig := newRunGatewayRig(t, nil)

	tok, minted, err := rig.s.mintRunGatewayToken(ctxAs("alice", false), "agent-hello", "hello", "run-1", boxWithLabels(nil))
	if err != nil {
		t.Fatalf("mintRunGatewayToken: %v", err)
	}
	if minted.JTI == "" {
		t.Error("minted jti is empty; the run lease could not revoke this token")
	}
	claims, err := modelgateway.VerifyToken(rig.s.gateway.secret, tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.KeyOwner != "user:alice" {
		t.Errorf("key_owner = %q, want %q", claims.KeyOwner, "user:alice")
	}
	if claims.Tenant != "agent-hello" || claims.SkillID != "hello" || claims.RunID != "run-1" || claims.Provider != "openai" {
		t.Errorf("run claims changed: tenant=%q skill=%q run=%q provider=%q", claims.Tenant, claims.SkillID, claims.RunID, claims.Provider)
	}
}

// TestMintRunGatewayToken_SpendsOwnersKey: a run's model call goes out on the
// owner's registered key — the resolver is asked for exactly that owner, and
// the daemon-global key never reaches the upstream.
func TestMintRunGatewayToken_SpendsOwnersKey(t *testing.T) {
	rig := newRunGatewayRig(t, map[string]string{
		"user:alice|openai": "ALICE-KEY",
		"user:bob|openai":   "BOB-KEY",
	})

	tok, _, err := rig.s.mintRunGatewayToken(ctxAs("alice", false), "agent-hello", "hello", "run-1", boxWithLabels(nil))
	if err != nil {
		t.Fatalf("mintRunGatewayToken: %v", err)
	}
	if code, body := rig.call(t, tok); code != http.StatusOK {
		t.Fatalf("model call status = %d, want 200 (%s)", code, body)
	}
	if got := rig.resolver.lookups(); len(got) != 1 || got[0] != "user:alice|openai" {
		t.Errorf("resolver lookups = %v, want [user:alice|openai]", got)
	}
	if got := rig.upstreamAuth(); len(got) != 1 || got[0] != "Bearer ALICE-KEY" {
		t.Errorf("upstream Authorization = %v, want [Bearer ALICE-KEY] (the daemon-global key must not be spent for an owned run)", got)
	}
}

// TestMintRunGatewayToken_UnownedRunKeepsGlobalKeyAndLogsOnce pins the decided
// no-owner behavior (FootprintAI/Containarium-cloud#1917, 2026-09-29): a run
// started with no attributable owner mints no key_owner claim, resolves
// through the daemon-global key as before, and says so in the log exactly
// once for the run — not once per model call.
func TestMintRunGatewayToken_UnownedRunKeepsGlobalKeyAndLogsOnce(t *testing.T) {
	rig := newRunGatewayRig(t, map[string]string{"user:alice|openai": "ALICE-KEY"})

	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	tok, _, err := rig.s.mintRunGatewayToken(context.Background(), "agent-hello", "hello", "run-sys", boxWithLabels(nil))
	if err != nil {
		t.Fatalf("mintRunGatewayToken: %v", err)
	}
	claims, err := modelgateway.VerifyToken(rig.s.gateway.secret, tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.KeyOwner != "" {
		t.Errorf("unowned run minted key_owner = %q, want none", claims.KeyOwner)
	}

	for i := 0; i < 3; i++ {
		if code, body := rig.call(t, tok); code != http.StatusOK {
			t.Fatalf("model call %d status = %d, want 200 (%s)", i, code, body)
		}
	}
	if got := rig.resolver.lookups(); len(got) != 0 {
		t.Errorf("resolver lookups = %v, want none for an unowned run", got)
	}
	for _, a := range rig.upstreamAuth() {
		if a != "Bearer DAEMON-GLOBAL" {
			t.Errorf("upstream Authorization = %q, want the daemon-global key", a)
		}
	}

	logged := strings.Count(buf.String(), "run-sys")
	if logged != 1 {
		t.Errorf("run run-sys logged %d time(s), want exactly 1:\n%s", logged, buf.String())
	}
	if !strings.Contains(buf.String(), "daemon-global") {
		t.Errorf("log line does not say the run is billed to the daemon-global key:\n%s", buf.String())
	}
}

// TestMintRunGatewayToken_RevokeByKeyOwnerKillsLiveRunToken: now that a run's
// token carries key_owner, removing the owner's key kills the tokens already
// issued to their runs — and the refusal the run sees says it was an
// intentional revocation, not an unexplained 401. Another owner's run and an
// unowned run are untouched.
func TestMintRunGatewayToken_RevokeByKeyOwnerKillsLiveRunToken(t *testing.T) {
	rig := newRunGatewayRig(t, map[string]string{
		"user:alice|openai": "ALICE-KEY",
		"user:bob|openai":   "BOB-KEY",
	})

	mint := func(ctx context.Context, runID string) string {
		t.Helper()
		tok, _, err := rig.s.mintRunGatewayToken(ctx, "agent-hello", "hello", runID, boxWithLabels(nil))
		if err != nil {
			t.Fatalf("mintRunGatewayToken(%s): %v", runID, err)
		}
		return tok
	}
	alice, bob, sys := mint(ctxAs("alice", false), "run-a"), mint(ctxAs("bob", false), "run-b"), mint(context.Background(), "run-s")
	for name, tok := range map[string]string{"alice": alice, "bob": bob, "system": sys} {
		if code, body := rig.call(t, tok); code != http.StatusOK {
			t.Fatalf("before revocation: %s run got %d, want 200 (%s)", name, code, body)
		}
	}

	if err := rig.gw.RevokeByKeyOwner(context.Background(), "user:alice", "provider key deleted"); err != nil {
		t.Fatalf("RevokeByKeyOwner: %v", err)
	}

	code, body := rig.call(t, alice)
	if code != http.StatusUnauthorized {
		t.Fatalf("revoked owner's live run token got %d, want 401", code)
	}
	if !strings.Contains(body, modelgateway.OwnerRevokedMessage) {
		t.Errorf("revocation body = %q, want it to carry %q", body, modelgateway.OwnerRevokedMessage)
	}
	if !strings.Contains(strings.ToLower(modelgateway.OwnerRevokedMessage), "intentional") {
		t.Errorf("OwnerRevokedMessage = %q does not say the revocation was intentional", modelgateway.OwnerRevokedMessage)
	}
	if code, body := rig.call(t, bob); code != http.StatusOK {
		t.Errorf("another owner's run got %d after alice's revocation, want 200 (%s)", code, body)
	}
	if code, body := rig.call(t, sys); code != http.StatusOK {
		t.Errorf("unowned run got %d after alice's revocation, want 200 (%s)", code, body)
	}
}
