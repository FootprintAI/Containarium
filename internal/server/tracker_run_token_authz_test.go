package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/internal/tracker"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ---- A REAL run token on the tracker verbs (#2268) ---------------------
//
// Every other tracker verb test builds the run's context by hand with the
// TENANT as the subject (kmsKeyTestCtx(user, ...) + a run_id claim). A
// real run token is not minted that way: provisionSkillBoxWith mints it
// for the BOX's subject (agent-<skill-id>, no roles) with the dispatching
// tenant only in its `act` audit claim — see mintRunToken. The tracker
// verbs then authorize req.Username (the tenant, from the dispatch input)
// against the token's subject. These tests put the two together with a
// token from the real mint path, through the real HTTP auth middleware,
// so the hand-built shortcut can no longer hide a mismatch between what
// is minted and what the verbs check.

// realRunTokenMinter is the minimal AgentSkillServer the mint path needs:
// the token manager and the catalog. Nothing here touches a box.
func realRunTokenMinter(t *testing.T) (*AgentSkillServer, *auth.TokenManager, *pb.AgentSkill) {
	t.Helper()
	tm, err := auth.NewTokenManager("test-secret-must-be-at-least-32-bytes-long-ok", "test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	catalog := skills.GetDefault()
	skill, err := catalog.Get("product-define")
	if err != nil {
		t.Fatalf("product-define not in the catalog: %v", err)
	}
	return &AgentSkillServer{catalog: catalog, tokens: tm}, tm, skill
}

// dispatchCallerCtx is the context the tracker dispatcher starts a run
// under: the tenant's OWN token (requireDispatchCaller), which must also
// pass provisionBoxOnly's AuthorizeTenant on the agent box — so, in
// production, an admin-role token for the tenant. No scopes claim, so the
// run receives exactly the skill manifest's scopes (#1676).
func dispatchCallerCtx(user string) context.Context {
	return kmsKeyTestCtx(user, auth.RoleAdmin, "")
}

// mintRealRunToken mints a run token for `user`, bound to connection
// `conn`, through the same code provisionSkillBoxWith runs for a real
// dispatched run, and returns the raw JWT.
func mintRealRunToken(t *testing.T, user, runID, conn string) (string, *auth.TokenManager) {
	t.Helper()
	agents, tm, skill := realRunTokenMinter(t)
	tok, cred, err := agents.mintRunToken(dispatchCallerCtx(user), skill, runID, conn)
	if err != nil {
		t.Fatalf("mintRunToken: %v", err)
	}
	if cred.Kind != runlease.KindPlatformJWT || cred.JTI == "" {
		t.Fatalf("lease credential = %+v, want the platform JWT with its jti", cred)
	}
	return tok, tm
}

// contextFromBearer presents the token the way the in-box platform MCP
// does — `Authorization: Bearer <jwt>` on a REST call — and returns the
// request context the real auth middleware hands to grpc-gateway, which
// forwards it in-process to the gRPC handler. Every auth.*FromGRPCContext
// accessor reads the claims off that context (the in-process fallback the
// gateway annotator mirrors into metadata; the hop itself is pinned by
// internal/gateway's *_EndToEndPropagation tests). No claim is hand-built:
// everything the verb sees came from validating the real token.
func contextFromBearer(t *testing.T, tm *auth.TokenManager, token, path string) context.Context {
	t.Helper()
	var captured context.Context
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Context()
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	auth.NewAuthMiddleware(tm).HTTPMiddleware(stub).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("auth middleware rejected the real run token: status=%d body=%s", rec.Code, rec.Body.String())
	}
	return captured
}

// realRunCtx is a gRPC context carrying a real run token minted for
// `user` on connection "default" with run id runID.
func realRunCtx(t *testing.T, user, runID string) context.Context {
	t.Helper()
	tok, tm := mintRealRunToken(t, user, runID, "default")
	return contextFromBearer(t, tm, tok, "/v1/tracker/connections/"+user+"/default/issues/42")
}

// TestTrackerVerbs_RealRunToken_AuthorizesOwnTenant is the #2268 "Done
// means" test: a tracker read verb and a tracker write verb, called with
// a token the real run-token mint path produced, succeed for the tenant
// the run was started for — the tenant named in the dispatch input and
// passed back as req.Username by the in-box tracker_* tools.
func TestTrackerVerbs_RealRunToken_AuthorizesOwnTenant(t *testing.T) {
	const user = "tracker-real-run-token-own-tenant"
	issue := tracker.Issue{Number: 42, Title: "idea", Body: "Please write a PRD.", Labels: []string{"scope:product"},
		State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN}
	provider := &fakeWriterProvider{fakeReaderProvider: fakeReaderProvider{issue: issue, issues: []tracker.Issue{issue}}}
	s, _, _ := setUpCreateConnection(t, user, provider, nil)
	const runID = "run-real-token-own"
	s.runRegistry.Register(runID, runlease.Info{SkillID: "product-define", Model: "fable"})
	run := realRunCtx(t, user, runID)

	// Read verb.
	got, err := s.GetTrackerIssue(run, &pb.GetTrackerIssueRequest{Username: user, Connection: "default", Number: 42})
	if err != nil {
		t.Fatalf("GetTrackerIssue with a real run token for its own tenant: %v (code %v), want success", err, status.Code(err))
	}
	if got.GetIssue().GetNumber() != 42 {
		t.Fatalf("GetTrackerIssue = %+v, want issue #42", got.GetIssue())
	}

	// Write verb: the comment lands on the forge, stamped with the run's
	// identity (run id + skill), not the box's subject.
	if _, err := s.CommentOnTrackerIssue(run, &pb.CommentOnTrackerIssueRequest{
		Username: user, Connection: "default", Number: 42, Body: "Claimed; starting the PRD.",
	}); err != nil {
		t.Fatalf("CommentOnTrackerIssue with a real run token for its own tenant: %v (code %v), want success", err, status.Code(err))
	}
	if len(provider.commentNumbers) != 1 || provider.commentNumbers[0] != 42 {
		t.Fatalf("comments on the forge = %v, want exactly one on #42", provider.commentNumbers)
	}
	if !strings.Contains(provider.commentBody, runID) || !strings.Contains(provider.commentBody, "product-define") {
		t.Errorf("comment stamp = %q, want it to name run %s and skill product-define", provider.commentBody, runID)
	}
}

// TestTrackerVerbs_RealRunToken_RefusedOnOtherTenantsConnection is the
// negative half: a run token minted for tenant A is still refused on
// tenant B's connection — even one with the same name, which exists, so
// the refusal can only be the tenant check — and nothing reaches B's
// forge.
func TestTrackerVerbs_RealRunToken_RefusedOnOtherTenantsConnection(t *testing.T) {
	const tenantA = "tracker-real-run-token-tenant-a"
	const tenantB = "tracker-real-run-token-tenant-b"
	issue := tracker.Issue{Number: 7, Title: "B's private issue", State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN}
	providerB := &fakeWriterProvider{fakeReaderProvider: fakeReaderProvider{issue: issue, issues: []tracker.Issue{issue}}}
	// Both tenants have a connection named "default" in the same store.
	setUpCreateConnection(t, tenantA, &fakeWriterProvider{}, nil)
	s, _, _ := setUpCreateConnection(t, tenantB, providerB, nil)
	const runID = "run-real-token-cross-tenant"
	s.runRegistry.Register(runID, runlease.Info{SkillID: "product-define", Model: "fable"})
	// A's run, bound to A's "default".
	run := realRunCtx(t, tenantA, runID)

	_, err := s.GetTrackerIssue(run, &pb.GetTrackerIssueRequest{Username: tenantB, Connection: "default", Number: 7})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetTrackerIssue on tenant B with A's run token: code = %v (%v), want PermissionDenied", status.Code(err), err)
	}
	_, err = s.CommentOnTrackerIssue(run, &pb.CommentOnTrackerIssueRequest{
		Username: tenantB, Connection: "default", Number: 7, Body: "hello from A's run",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CommentOnTrackerIssue on tenant B with A's run token: code = %v (%v), want PermissionDenied", status.Code(err), err)
	}
	if len(providerB.commentNumbers) != 0 {
		t.Fatalf("comments reached tenant B's forge: %v, want none", providerB.commentNumbers)
	}
}
