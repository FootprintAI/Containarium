package server

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
)

func runOrgCtx(scopes string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		auth.MDKeyUsername, "oss-primary",
		auth.MDKeyRoles, auth.RoleAdmin,
		auth.MDKeyScopes, scopes,
	))
}

// TestAuthorizeRunOrg pins who may attribute a run to an org (#3028): only a
// credential holding the literal agents:run-for-org scope. The wildcard, an
// unscoped admin token, and a plain agents:run token must not, or any caller
// could spend another org's provider key.
func TestAuthorizeRunOrg(t *testing.T) {
	const org = "7f3c2b1e-0000-4000-8000-000000000001"
	tests := []struct {
		name     string
		ctx      context.Context
		orgID    string
		want     string
		wantCode codes.Code
	}{
		{"unset is a no-op for anyone", runOrgCtx(auth.ScopeAgentsRun), "", "", codes.OK},
		{"literal scope is accepted", runOrgCtx(auth.ScopeAgentsRun + "," + auth.ScopeAgentsRunForOrg), org, org, codes.OK},
		{"surrounding spaces are trimmed", runOrgCtx(auth.ScopeAgentsRunForOrg), " " + org + " ", org, codes.OK},
		{"agents:run alone is refused", runOrgCtx(auth.ScopeAgentsRun), org, "", codes.PermissionDenied},
		{"wildcard is refused", runOrgCtx(auth.ScopeWildcard), org, "", codes.PermissionDenied},
		{"unscoped admin token is refused", metadata.NewIncomingContext(context.Background(),
			metadata.Pairs(auth.MDKeyUsername, "root", auth.MDKeyRoles, auth.RoleAdmin)), org, "", codes.PermissionDenied},
		{"a malformed id is invalid", runOrgCtx(auth.ScopeAgentsRunForOrg), "org:evil/../x", "", codes.InvalidArgument},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := authorizeRunOrg(tc.ctx, tc.orgID)
			if code := status.Code(err); code != tc.wantCode {
				t.Fatalf("code = %v (%v), want %v", code, err, tc.wantCode)
			}
			if got != tc.want {
				t.Errorf("org = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRunKeyOwner_RequestOrgWins pins the precedence: the request's org beats
// the shared box's cloud_org_id label, which beats the calling identity.
func TestRunKeyOwner_RequestOrgWins(t *testing.T) {
	ctx := runOrgCtx(auth.ScopeAgentsRunForOrg)
	labelled := boxWithLabels(map[string]string{cloudOrgIDLabel: "label-org"})
	if got := runKeyOwner(ctx, labelled, "req-org"); got != "org:req-org" {
		t.Errorf("request org over label: got %q, want org:req-org", got)
	}
	if got := runKeyOwner(ctx, labelled, ""); got != "org:label-org" {
		t.Errorf("label when no request org: got %q, want org:label-org", got)
	}
	if got := runKeyOwner(ctx, boxWithLabels(nil), ""); got != "user:oss-primary" {
		t.Errorf("caller identity when neither: got %q, want user:oss-primary", got)
	}
}
