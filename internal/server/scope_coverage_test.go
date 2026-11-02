package server

import (
	"context"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// scopeGuardFuncs are the calls that enforce a TOKEN SCOPE. RequireRoleOrScope
// is deliberately NOT here: it returns nil for an admin whatever the token's
// scopes, so it does not narrow an admin token (RequireRoleOrScopeNarrowed does).
//
// TestEveryRPCHasAuthGuard accepts a role or tenant check as "guarded", but those ignore a token's scopes:
// a read-only or narrowly-scoped token held by an admin or by the tenant owner still
// passes. A mutating or privileged RPC therefore needs one of these.
var scopeGuardFuncs = map[string]bool{
	"RequireScope":               true,
	"RequireAnyScope":            true,
	"RequireExplicitScope":       true,
	"RequireRoleOrScopeNarrowed": true, // role OR scope, but a scoped token must hold the scope even as admin
}

// scopeBaseline lists RPCs deliberately without a scope check, each with the
// reason. A new entry needs a stated, reviewed reason; the default for a new
// RPC is to add a scope check.
var scopeBaseline = map[string]string{
	"AnonymousBoxService/GetAnonymousDoorConfig":              "read path: RequireRoleOrScope lets an admin in by role whatever the token's scopes, which is the documented behavior (#621) and is asserted by tests; narrowing reads is a separate decision.",
	"AnonymousBoxService/ListAnonymousBoxes":                  "read path: RequireRoleOrScope lets an admin in by role whatever the token's scopes, which is the documented behavior (#621) and is asserted by tests; narrowing reads is a separate decision.",
	"NetworkPolicyService/GetNetworkPolicy":                   "read path: RequireRoleOrScope lets an admin in by role whatever the token's scopes, which is the documented behavior (#621) and is asserted by tests; narrowing reads is a separate decision.",
	"NetworkPolicyService/GetNetworkPolicyStatus":             "read path: RequireRoleOrScope lets an admin in by role whatever the token's scopes, which is the documented behavior (#621) and is asserted by tests; narrowing reads is a separate decision.",
	"NetworkPolicyService/ListNetworkPolicies":                "read path: RequireRoleOrScope lets an admin in by role whatever the token's scopes, which is the documented behavior (#621) and is asserted by tests; narrowing reads is a separate decision.",
	"NetworkPolicyService/ListNetworkPolicySignatures":        "read path: RequireRoleOrScope lets an admin in by role whatever the token's scopes, which is the documented behavior (#621) and is asserted by tests; narrowing reads is a separate decision.",
	"NetworkPolicyService/PlanNetworkPolicy":                  "read path: RequireRoleOrScope lets an admin in by role whatever the token's scopes, which is the documented behavior (#621) and is asserted by tests; narrowing reads is a separate decision.",
	"ProofPackService/VerifyProofPack":                        "read path: RequireRoleOrScope lets an admin in by role whatever the token's scopes, which is the documented behavior (#621) and is asserted by tests; narrowing reads is a separate decision.",
	"TokensService/GetUnscopedTokenReport":                    "read path: RequireRoleOrScope lets an admin in by role whatever the token's scopes, which is the documented behavior (#621) and is asserted by tests; narrowing reads is a separate decision.",
	"TokensService/ListRevokedTokens":                         "read path: RequireRoleOrScope lets an admin in by role whatever the token's scopes, which is the documented behavior (#621) and is asserted by tests; narrowing reads is a separate decision.",
	"CodingToolEgressPolicyService/GetCodingToolEgressPolicy": "by design: a tenant reads its own policy with code-egress:read, an admin by role (RequireRoleOrScope)",
	"TokensService/RefreshToken":                              "authenticated by the refresh token itself, not a scope",
}

func TestEveryRPCHasScopeGuard(t *testing.T) {
	saved := authGuardFuncs
	authGuardFuncs = scopeGuardFuncs
	defer func() { authGuardFuncs = saved }()
	guarded := guardedMethods(t)
	authGuardFuncs = saved

	var missing []string
	seen := map[string]bool{}
	for _, svc := range registeredServices {
		service := serviceShortName(svc.desc.ServiceName)
		var names []string
		for _, m := range svc.desc.Methods {
			names = append(names, m.MethodName)
		}
		for _, s := range svc.desc.Streams {
			names = append(names, s.StreamName)
		}
		for _, name := range names {
			key := rpcKey(service, name)
			seen[key] = true
			_, baselined := scopeBaseline[key]
			switch {
			case guarded[svc.receiver+"."+name] && baselined:
				t.Errorf("%s now has a scope check; remove it from scopeBaseline", key)
			case guarded[svc.receiver+"."+name]:
			case baselined:
			default:
				missing = append(missing, key)
			}
		}
	}
	sort.Strings(missing)
	if os.Getenv("DUMP_SCOPE_GAPS") != "" {
		t.Logf("RPCs without a scope guard (%d):\n%s", len(missing), strings.Join(missing, "\n"))
		return
	}
	for _, k := range missing {
		t.Errorf("%s has no RequireScope/RequireAnyScope/RequireExplicitScope/RequireRoleOrScopeNarrowed; add one or a scopeBaseline entry with a reason", k)
	}
	for k := range scopeBaseline {
		if !seen[k] {
			t.Errorf("scopeBaseline[%q] names no registered RPC; remove it", k)
		}
	}
}

// containerScopeRPCs maps each ContainerService RPC that was missing a scope
// check to the scope it now requires.
var containerScopeRPCs = map[string]string{
	"AddCollaborator": auth.ScopeContainersWrite, "RemoveCollaborator": auth.ScopeContainersWrite,
	"AdoptMigratedContainer": auth.ScopeContainersWrite, "CleanupDisk": auth.ScopeContainersWrite,
	"DeleteTenantStorage": auth.ScopeContainersWrite, "InstallStack": auth.ScopeContainersWrite,
	"MoveContainer": auth.ScopeContainersWrite, "PrepareEncryptedMigration": auth.ScopeContainersWrite,
	"RewrapContainer": auth.ScopeContainersWrite, "SetMetricsExport": auth.ScopeContainersWrite,
	"AdvertiseCapacity": auth.ScopeContainersWrite, "WithdrawCapacity": auth.ScopeContainersWrite,
	"ValidateGPU": auth.ScopeContainersWrite, "ProfileBackend": auth.ScopeContainersWrite,
	"DebugContainer": auth.ScopeContainersRead, "GetConsoleLog": auth.ScopeContainersRead,
	"GetCapabilityProfile": auth.ScopeContainersRead, "GetCapacityHeadroom": auth.ScopeContainersRead,
	"GetLatestRelease": auth.ScopeContainersRead, "GetMetricsExport": auth.ScopeContainersRead,
	"GetSelfMeasurement": auth.ScopeContainersRead, "GetSystemInfo": auth.ScopeContainersRead,
	"ListBackends": auth.ScopeContainersRead, "ListCollaborators": auth.ScopeContainersRead,
}

// Slice 2: NetworkService and CodingToolEgressPolicyService.
var networkScopeRPCs = map[string]string{
	"AddPassthroughRoute": auth.ScopeRoutesWrite, "DeletePassthroughRoute": auth.ScopeRoutesWrite,
	"UpdatePassthroughRoute": auth.ScopeRoutesWrite, "UpdateContainerACL": auth.ScopeRoutesWrite,
	"GetContainerACL": auth.ScopeRoutesRead, "GetNetworkGuardStatus": auth.ScopeSecurityRead,
	"GetNetworkTopology": auth.ScopeRoutesRead, "ListDNSRecords": auth.ScopeRoutesRead,
	"ListPassthroughRoutes": auth.ScopeRoutesRead,
}

var egressScopeRPCs = map[string]string{
	"SetCodingToolEgressPolicy":    auth.ScopeNetworkPolicyWrite,
	"DeleteCodingToolEgressPolicy": auth.ScopeNetworkPolicyWrite,
}

// assertScopeGate calls every RPC in rpcs on srv as an admin holding only
// wrong scopes and requires PermissionDenied before any dependency is used.
func assertScopeGate(t *testing.T, srv any, rpcs map[string]string, wrong ...string) {
	t.Helper()
	for name := range rpcs {
		t.Run(name, func(t *testing.T) {
			ctx := auth.ContextWithTestSubjectScopes(context.Background(), "ops", []string{auth.RoleAdmin}, wrong)
			m := reflect.ValueOf(srv).MethodByName(name)
			if !m.IsValid() {
				t.Fatalf("no method %s", name)
			}
			out := m.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.New(m.Type().In(1).Elem())})
			err, _ := out[1].Interface().(error)
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("%s with scopes %v: got %v, want PermissionDenied", name, wrong, err)
			}
		})
	}
}

func TestNetworkServiceScopeGate(t *testing.T) {
	// A containers:* scope must not unlock routes/network RPCs, and read must not write.
	assertScopeGate(t, &NetworkServer{}, networkScopeRPCs, auth.ScopeContainersWrite, auth.ScopeBackupsWrite)
	writes := map[string]string{}
	for k, v := range networkScopeRPCs {
		if v == auth.ScopeRoutesWrite {
			writes[k] = v
		}
	}
	assertScopeGate(t, &NetworkServer{}, writes, auth.ScopeRoutesRead)
}

func TestEgressPolicyScopeGate(t *testing.T) {
	assertScopeGate(t, &CodingToolEgressPolicyServer{}, egressScopeRPCs, auth.ScopeCodeEgressRead, auth.ScopeNetworkPolicyRead)
}

// Slice 3 (reads): retention reads reuse audit:read, as ProofPack already does.
func TestRetentionReadsRequireAuditRead(t *testing.T) {
	reads := map[string]string{
		"GetRetentionPolicy": auth.ScopeAuditRead, "GetRetentionMode": auth.ScopeAuditRead,
		"ListLegalHolds": auth.ScopeAuditRead, "GetRetentionReport": auth.ScopeAuditRead,
	}
	assertScopeGate(t, &RetentionServer{}, reads, auth.ScopeContainersRead, auth.ScopeAuditIngest)
}

// Retention writes need retention:write, and audit:read must NOT be enough:
// a token that can read the audit log cannot shorten a window or release a hold.
func TestRetentionWritesRequireRetentionWrite(t *testing.T) {
	writes := map[string]string{
		"SetRetentionPolicy": auth.ScopeRetentionWrite, "SetRetentionMode": auth.ScopeRetentionWrite,
		"SetLegalHold": auth.ScopeRetentionWrite, "ReleaseLegalHold": auth.ScopeRetentionWrite,
	}
	assertScopeGate(t, &RetentionServer{}, writes, auth.ScopeAuditRead, auth.ScopeAuditIngest, auth.ScopeContainersWrite)
}

// An ADMIN token holding only an unrelated scope must be refused before the
// handler touches any dependency (the server below has none, so reaching the
// body would nil-deref). A token with just the wrong half of containers:* is
// refused too: read cannot write.
func TestContainerServiceScopeGate(t *testing.T) {
	srv := &ContainerServer{}
	for name, want := range containerScopeRPCs {
		for label, scopes := range map[string][]string{
			"unrelated scope": {auth.ScopeBackupsRead},
			"other half":      {otherHalf(want)},
		} {
			t.Run(name+"/"+label, func(t *testing.T) {
				ctx := auth.ContextWithTestSubjectScopes(context.Background(), "ops", []string{auth.RoleAdmin}, scopes)
				m := reflect.ValueOf(srv).MethodByName(name)
				if !m.IsValid() {
					t.Fatalf("no method %s", name)
				}
				req := reflect.New(m.Type().In(1).Elem())
				out := m.Call([]reflect.Value{reflect.ValueOf(ctx), req})
				err, _ := out[1].Interface().(error)
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("%s with %v: got %v, want PermissionDenied", name, scopes, err)
				}
			})
		}
	}
}

func otherHalf(scope string) string {
	if scope == auth.ScopeContainersWrite {
		return auth.ScopeContainersRead
	}
	return auth.ScopeContainersWrite
}

// The three mutating anonymous-box RPCs hold a SCOPED token to its scope even
// for an admin; an unrelated-scope admin token is refused before any work.
func TestAnonymousBoxMutationsNarrowScopedAdmins(t *testing.T) {
	rpcs := map[string]string{
		"ClaimAnonymousBox": auth.ScopeAnonAdmin, "SetAnonymousDoorConfig": auth.ScopeAnonAdmin,
		"EnsureAnonymousBox": auth.ScopeAnonDoor,
	}
	assertScopeGate(t, &AnonymousBoxServer{}, rpcs, auth.ScopeContainersRead)
}
