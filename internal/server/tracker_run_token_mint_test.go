package server

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestMintRunToken_CarriesTenantRunAndConnection pins what the real run
// token says (#2268), with no Postgres: the subject is the BOX, the tenant
// the run was started for is the run_tenant claim (derived from the
// dispatching caller's verified subject, the same identity the connection
// was validated under), alongside run_id, tracker_conn, the act audit
// chain, and exactly the manifest's scopes.
func TestMintRunToken_CarriesTenantRunAndConnection(t *testing.T) {
	const user = "tracker-real-run-token-claims"
	agents, tm, skill := realRunTokenMinter(t)
	tok, _, err := agents.mintRunToken(dispatchCallerCtx(user), skill, "run-claims", "default")
	if err != nil {
		t.Fatalf("mintRunToken: %v", err)
	}
	claims, err := tm.ValidateAccessToken(tok)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.Username != agentBoxPrefix+skill.Id {
		t.Errorf("subject = %q, want the box %q", claims.Username, agentBoxPrefix+skill.Id)
	}
	if len(claims.Roles) != 0 {
		t.Errorf("roles = %v, want none (a run token must never carry a role)", claims.Roles)
	}
	if claims.RunTenant != user {
		t.Errorf("run_tenant = %q, want the dispatching tenant %q", claims.RunTenant, user)
	}
	if claims.RunID != "run-claims" || claims.TrackerConn != "default" {
		t.Errorf("run_id/tracker_conn = %q/%q, want run-claims/default", claims.RunID, claims.TrackerConn)
	}
	if claims.Act == nil || claims.Act.Subject != user {
		t.Errorf("act = %+v, want the dispatching tenant as the delegation subject", claims.Act)
	}
	if got := strings.Join(claims.Scopes, ","); got != strings.Join(skill.AllowedScopes, ",") {
		t.Errorf("scopes = %q, want exactly the manifest's %q", got, strings.Join(skill.AllowedScopes, ","))
	}

	// The two checks the verbs rely on, on the context the middleware
	// builds from this token: the tracker authorizer passes for the run's
	// tenant and nobody else; the generic tenant check still refuses the
	// run token even for its own tenant — it is the box, and must not
	// reach the tenant's containers, secrets or anything else.
	run := contextFromBearer(t, tm, tok, "/v1/tracker/"+user+"/default/issues/1")
	if err := auth.AuthorizeTrackerTenant(run, user); err != nil {
		t.Errorf("AuthorizeTrackerTenant(run, its tenant): %v, want nil", err)
	}
	if err := auth.AuthorizeTrackerTenant(run, "someone-else"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("AuthorizeTrackerTenant(run, another tenant): code = %v, want PermissionDenied", status.Code(err))
	}
	if err := auth.AuthorizeTenant(run, user); status.Code(err) != codes.PermissionDenied {
		t.Errorf("AuthorizeTenant(run, its tenant): code = %v (%v), want PermissionDenied — the run token is the box, not the tenant", status.Code(err), err)
	}
}

// TestMintRunToken_TenantIsTheCallerNotTheRequest: the run_tenant claim
// is derived from the caller's verified subject only. There is no request
// field to forge it through — the test can only vary the caller, and the
// claim follows.
func TestMintRunToken_TenantIsTheCallerNotTheRequest(t *testing.T) {
	agents, tm, skill := realRunTokenMinter(t)
	for _, caller := range []string{"tenant-one", "tenant-two"} {
		tok, _, err := agents.mintRunToken(dispatchCallerCtx(caller), skill, "run-x", "")
		if err != nil {
			t.Fatalf("mintRunToken(%s): %v", caller, err)
		}
		claims, err := tm.ValidateAccessToken(tok)
		if err != nil {
			t.Fatalf("ValidateAccessToken: %v", err)
		}
		if claims.RunTenant != caller {
			t.Errorf("run_tenant = %q, want the caller %q", claims.RunTenant, caller)
		}
		if claims.TrackerConn != "" {
			t.Errorf("tracker_conn = %q for a run not bound to a connection, want empty", claims.TrackerConn)
		}
	}
}
