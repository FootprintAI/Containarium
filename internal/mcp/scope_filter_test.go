package mcp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

// makeUnsignedJWT crafts a JWT with the given claims and a
// dummy signature segment. scopesFromJWT doesn't verify the
// signature (the daemon does that on the actual API call),
// so this is enough for the MCP-side filter tests.
func makeUnsignedJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	enc := func(b []byte) string {
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return strings.Join([]string{enc(hb), enc(pb), "sig"}, ".")
}

func TestScopesFromJWT_PresentClaim(t *testing.T) {
	tok := makeUnsignedJWT(t, map[string]interface{}{
		"username": "alice",
		"scopes":   []string{"containers:read", "secrets:read"},
	})
	got, ok := scopesFromJWT(tok)
	if !ok {
		t.Fatal("expected parsed=true")
	}
	if len(got) != 2 || got[0] != "containers:read" || got[1] != "secrets:read" {
		t.Fatalf("scopes = %v", got)
	}
}

func TestScopesFromJWT_AbsentClaim(t *testing.T) {
	tok := makeUnsignedJWT(t, map[string]interface{}{
		"username": "alice",
	})
	got, ok := scopesFromJWT(tok)
	if !ok {
		t.Fatal("expected parsed=true even without scopes claim")
	}
	if got != nil {
		t.Fatalf("scopes should be nil when claim absent; got %v", got)
	}
}

func TestScopesFromJWT_OpaqueToken(t *testing.T) {
	// Not a JWT — caller should treat unparseable tokens as
	// "no restriction" (the daemon's verified check still
	// applies on the real call).
	got, ok := scopesFromJWT("opaque-bearer-token")
	if ok {
		t.Fatal("expected parsed=false for non-JWT")
	}
	if got != nil {
		t.Fatalf("scopes should be nil for non-JWT; got %v", got)
	}
}

func TestToolAllowed_NilGrantsLetEverythingThrough(t *testing.T) {
	tool := &Tool{Name: "create_container", RequiredScope: auth.ScopeContainersWrite}
	if !toolAllowed(nil, tool) {
		t.Fatal("nil grants should be unrestricted (backwards compat)")
	}
}

func TestToolAllowed_RequiredScopeChecked(t *testing.T) {
	tool := &Tool{Name: "create_container", RequiredScope: auth.ScopeContainersWrite}
	if !toolAllowed([]string{auth.ScopeContainersWrite}, tool) {
		t.Fatal("granted scope should pass")
	}
	if toolAllowed([]string{auth.ScopeContainersRead}, tool) {
		t.Fatal("wrong scope should be rejected")
	}
}

func TestToolAllowed_EmptyRequiredAlwaysPasses(t *testing.T) {
	tool := &Tool{Name: "list_backends", RequiredScope: ""}
	if !toolAllowed([]string{}, tool) {
		t.Fatal("zero-scope tool should pass even on empty grants")
	}
}

// TestEveryToolHasScope guards against regressions where a
// new tool is added to registerTools without a scope
// assignment. The mapping in toolScopeAssignments() must
// list every registered tool. Compiles a fresh registry by
// constructing a server with a minimal config and reading
// its tools.
func TestEveryToolHasScope(t *testing.T) {
	// Tools with intentionally empty scope (zero-priv
	// introspection that any token can call) go here. Keep
	// this list narrow — adding tools to it widens the
	// MCP-side blast radius.
	exemptions := map[string]bool{}

	assignments := toolScopeAssignments()
	srv := &Server{}
	srv.registerTools()
	if len(srv.tools) == 0 {
		t.Fatal("no tools registered — test harness broken")
	}
	for _, tool := range srv.tools {
		if exemptions[tool.Name] {
			continue
		}
		assigned, ok := assignments[tool.Name]
		if !ok {
			t.Errorf("tool %q has no entry in toolScopeAssignments() — add one before merging", tool.Name)
			continue
		}
		if assigned == "" {
			t.Errorf("tool %q maps to empty scope; either give it a real scope or add to exemptions", tool.Name)
		}
		if tool.RequiredScope != assigned {
			t.Errorf("tool %q RequiredScope=%q but table says %q", tool.Name, tool.RequiredScope, assigned)
		}
	}
}

// verify_backup requires backups:verify after the v0.120.1 migration
// window (#3219); backups:write remains the grant for the write tools.
func TestVerifyBackupToolAcceptsVerifyScope(t *testing.T) {
	srv := &Server{}
	srv.registerTools()
	byName := map[string]*Tool{}
	for i := range srv.tools {
		byName[srv.tools[i].Name] = &srv.tools[i]
	}
	verifyOnly := []string{auth.ScopeBackupsRead, auth.ScopeBackupsVerify}
	if !toolAllowed(verifyOnly, byName["verify_backup"]) {
		t.Error("backups:verify must allow verify_backup")
	}
	for _, tc := range []struct {
		name   string
		scopes []string
		want   bool
	}{
		{"legacy write", []string{auth.ScopeBackupsWrite}, false},
		{"legacy read and write", []string{auth.ScopeBackupsRead, auth.ScopeBackupsWrite}, false},
		{"read", []string{auth.ScopeBackupsRead}, false},
		{"empty", []string{}, false},
		{"verify", []string{auth.ScopeBackupsVerify}, true},
		{"both", []string{auth.ScopeBackupsWrite, auth.ScopeBackupsVerify}, true},
		{"wildcard", []string{auth.ScopeWildcard}, true},
		{"unscoped", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := toolAllowed(tc.scopes, byName["verify_backup"]); got != tc.want {
				t.Errorf("verify_backup allowed = %v, want %v", got, tc.want)
			}
		})
	}
	for _, n := range []string{"create_backup", "restore_backup"} {
		if toolAllowed(verifyOnly, byName[n]) {
			t.Errorf("backups:verify must not allow %s", n)
		}
		if !toolAllowed([]string{auth.ScopeBackupsWrite}, byName[n]) {
			t.Errorf("backups:write must still allow %s", n)
		}
	}
}

// The denial text names only the accepted scope, so a legacy verifier
// learns it needs backups:verify (#3219).
func TestRequiredScopeText(t *testing.T) {
	if got := requiredScopeText(&Tool{RequiredScope: "a:b"}); got != `"a:b"` {
		t.Errorf("single scope text = %s", got)
	}
	srv := &Server{}
	srv.registerTools()
	for i := range srv.tools {
		if srv.tools[i].Name == "verify_backup" {
			got := requiredScopeText(&srv.tools[i])
			if got != `"backups:verify"` {
				t.Errorf("verify_backup denial text = %s, want only backups:verify", got)
			}
			return
		}
	}
	t.Fatal("verify_backup not registered")
}
