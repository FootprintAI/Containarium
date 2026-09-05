package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #1685: authorization here is an explicit per-handler call
// (auth.RequireScope / RequireRole / RequireRoleOrScope / AuthorizeTenant /
// AuthorizeSecretTenant) at the top of each RPC implementation — there is no
// interceptor or method→scope table that gates by default. That design's
// one failure mode is a handler that omits the call: it is not denied, it is
// ungated for every caller, and nothing detects that.
//
// TestEveryRPCHasAuthGuard is the backstop. It has no access to a live
// server (constructing DualServer needs Incus, stores, and other
// dependencies this test intentionally avoids), so it works from two purely
// static sources instead:
//
//   - registeredServices below names every proto service dual_server.go
//     wires onto the authenticated grpc.Server, paired with the Go receiver
//     type that implements it (from dual_server.go's
//     pb.RegisterXServiceServer(grpcServer, <value>) call sites). Each
//     service's generated *_ServiceDesc gives the exact RPC method/stream
//     names actually registered — the true surface, not a hand-recount of
//     the .proto files.
//   - guardedMethods AST-scans every non-test .go file in this package for
//     a method whose body calls one of authGuardFuncs, keyed by
//     "ReceiverType.MethodName".
//
// A registered RPC with no guarded method and no authExemptions entry fails
// the test. This catches a forgotten guard on a NEW rpc automatically —
// registeredServices only needs an update when a whole new SERVICE is wired
// in dual_server.go, which is rare and visible in review.

// authGuardFuncs are the auth-package calls that gate an RPC. Presence of
// ANY of these anywhere in a handler's body counts as guarded — this proves
// a guard call EXISTS, not that it runs before every side effect; ordering
// and correctness of the check itself are what internal/auth's own tests
// and ordinary review cover.
var authGuardFuncs = map[string]bool{
	"RequireScope":          true,
	"RequireRole":           true,
	"RequireRoleOrScope":    true,
	"AuthorizeTenant":       true,
	"AuthorizeSecretTenant": true,
}

// rpcSurface pairs one registered service's generated descriptor with the Go
// type (no "*") whose methods implement it.
type rpcSurface struct {
	desc     grpc.ServiceDesc
	receiver string
}

// registeredServices is every proto service dual_server.go registers onto
// the authenticated daemon grpc.Server. Two proto services are deliberately
// absent, not oversights:
//
//   - SpawnService: served on a private unix socket with its own bare
//     grpc.NewServer() and no interceptor chain at all
//     (internal/agentbox/spawn_listener.go) — a filesystem-permission
//     boundary, not a scope boundary, and never reachable through the
//     mTLS-gated daemon surface this test audits.
//   - EventService: not registered anywhere in dual_server.go as of this
//     writing. That may be a real gap rather than a deliberate omission;
//     tracked separately (this test only audits what IS wired, so an
//     unregistered service is out of its scope by construction).
//
// Update this list when dual_server.go registers a new SERVICE — a new RPC
// on an existing service needs no change here, since it's picked up from
// that service's ServiceDesc automatically.
var registeredServices = []rpcSurface{
	{pb.ContainerService_ServiceDesc, "ContainerServer"},
	{pb.ComposeAutostartService_ServiceDesc, "ComposeAutostartServer"},
	{pb.NetworkService_ServiceDesc, "NetworkServer"},
	{pb.RecipeService_ServiceDesc, "RecipeServer"},
	{pb.NetworkPolicyService_ServiceDesc, "NetworkPolicyServer"},
	{pb.AgentSkillService_ServiceDesc, "AgentSkillServer"},
	{pb.CrewService_ServiceDesc, "CrewServer"},
	{pb.BackupService_ServiceDesc, "BackupServer"},
	{pb.VolumeService_ServiceDesc, "VolumeServer"},
	{pb.SandboxService_ServiceDesc, "SandboxServer"},
	{pb.ClusterService_ServiceDesc, "ClusterServer"},
	{pb.KmsService_ServiceDesc, "KmsServer"},
	{pb.TrafficService_ServiceDesc, "TrafficServer"},
	{pb.AppService_ServiceDesc, "AppServer"},
	{pb.SecurityService_ServiceDesc, "SecurityServer"},
	{pb.PentestService_ServiceDesc, "PentestServer"},
	{pb.ZapService_ServiceDesc, "ZapServer"},
	{pb.TokensService_ServiceDesc, "TokensServer"},
	{pb.ThreatDetectionService_ServiceDesc, "ThreatDetectionServer"},
}

// authExemptions lists every registered RPC whose handler carries no auth
// guard call, and why. A registered RPC missing from BOTH the AST scan's
// guarded set and this map fails TestEveryRPCHasAuthGuard.
//
// Keep this narrow and reasoned — per #1685, "the exemption list states WHY
// for each entry, not just THAT." Adding an entry widens what an
// unauthenticated caller can reach; it must be a deliberate, reviewed
// choice, never a way to silence a red test.
//
// Every entry below except RefreshToken is a REAL finding from this audit,
// not a deliberate design choice — each is filed as its own issue and
// tracked here only until that issue's fix lands, at which point the
// exemption is removed (the test will then start requiring the guard it
// currently lacks). Grouped by the issue that tracks the fix, not by RPC,
// since #1716 and #1718 each cover several RPCs sharing one root cause.
var authExemptions = map[string]string{
	// #1685 itself: refresh is self-authenticating via the refresh_token
	// payload's own signature (validated by tokenManager.ValidateRefreshToken)
	// — requiring a bearer scope would be circular, since refresh exists
	// precisely because the caller's access token has already expired. Not a
	// gap; the design this coverage test's own model doesn't have a category
	// for ("guarded by a credential that isn't a scoped bearer token").
	"TokensService/RefreshToken": "self-authenticating via the refresh_token payload's own signature, not a bearer scope — see #1685",

	// #1716: ComposeAutostartService accepts an arbitrary username with no
	// scope or tenant check on any of its 4 RPCs — cross-tenant read/write.
	"ComposeAutostartService/Discover": "KNOWN GAP, tracked in #1716 — no scope/tenant check, not fixed here",
	"ComposeAutostartService/Enable":   "KNOWN GAP, tracked in #1716 — no scope/tenant check, not fixed here",
	"ComposeAutostartService/Disable":  "KNOWN GAP, tracked in #1716 — no scope/tenant check, not fixed here",
	"ComposeAutostartService/Status":   "KNOWN GAP, tracked in #1716 — no scope/tenant check, not fixed here",

	// #1717: mutates the platform-wide threat-detection blocklist with no
	// role check — more severe than the read-only findings below.
	"ThreatDetectionService/AddBadDestination":    "KNOWN GAP, tracked in #1717 — mutates the platform blocklist with no role check, not fixed here",
	"ThreatDetectionService/RemoveBadDestination": "KNOWN GAP, tracked in #1717 — mutates the platform blocklist with no role check, not fixed here",

	// #1718: read-only, static/platform (not per-tenant) data, but still
	// reachable with zero guard.
	"ContainerService/ListStacks":                "KNOWN GAP, tracked in #1718 — static catalog, no guard, not fixed here",
	"ContainerService/GetMonitoringInfo":         "KNOWN GAP, tracked in #1718 — platform config disclosure, no guard, not fixed here",
	"ContainerService/GetAlertingInfo":           "KNOWN GAP, tracked in #1718 — platform config disclosure, no guard, not fixed here",
	"ContainerService/ListDefaultAlertRules":     "KNOWN GAP, tracked in #1718 — static catalog, no guard, not fixed here",
	"NetworkService/ListACLPresets":              "KNOWN GAP, tracked in #1718 — static catalog, no guard, not fixed here",
	"PentestService/GetPentestConfig":            "KNOWN GAP, tracked in #1718 — platform config disclosure, no guard, not fixed here",
	"ZapService/GetZapConfig":                    "KNOWN GAP, tracked in #1718 — platform config disclosure, no guard, not fixed here",
	"ThreatDetectionService/GetSentryStatus":     "KNOWN GAP, tracked in #1718 — platform config disclosure, no guard, not fixed here",
	"ThreatDetectionService/ListBadDestinations": "KNOWN GAP, tracked in #1718 — platform config disclosure, no guard, not fixed here",
}

func rpcKey(service, method string) string { return service + "/" + method }

// serviceShortName strips ServiceDesc.ServiceName's "containarium.v1."
// package prefix, leaving e.g. "ContainerService".
func serviceShortName(full string) string {
	if i := strings.LastIndex(full, "."); i >= 0 {
		return full[i+1:]
	}
	return full
}

// funcInfo is one function or method's own (non-transitive) auth signals,
// plus the bare names of the local functions/methods it calls — the edges a
// transitive walk follows to find a guard applied through a helper (e.g.
// CreateContainerSnapshot's guard lives in the shared snapshotDatasetFor,
// not in CreateContainerSnapshot's own body).
type funcInfo struct {
	recv        string // "" for a free function
	name        string
	directGuard bool // calls auth.<one of authGuardFuncs> in ITS OWN body
	// manualGuardLinked is the GetMetrics/ListContainers-shaped pattern: an
	// `if !ok { ...codes.Unauthenticated/PermissionDenied... }` whose
	// condition negates the ok returned by auth.SubjectFromGRPCContext. Both
	// halves must be linked by that ONE if-statement — a function that
	// merely calls SubjectFromGRPCContext (for logging, say) and separately,
	// coincidentally, returns an unrelated PermissionDenied elsewhere does
	// NOT set this (tightened per CodeRabbit review on PR #1719: the
	// original "both signals anywhere in the same body" version couldn't
	// tell the two apart).
	manualGuardLinked bool
	calls             []string
}

// selfGuarded is true when a function's OWN body — not any callee's — is
// enough to call it guarded: either a direct canonical guard call, or the
// manual, control-flow-linked pattern described on manualGuardLinked.
func (f funcInfo) selfGuarded() bool {
	return f.directGuard || f.manualGuardLinked
}

// guardedMethods AST-scans every non-test .go file in this directory,
// builds a package-local call graph, and returns the set of
// "ReceiverType.MethodName" pairs that are guarded either directly or
// transitively through a same-package helper call.
//
// Two functions in this package can share a bare name (e.g. ContainerServer's
// real ListContainers RPC handler vs. PeerPool.ListContainers, an unrelated
// internal helper) — Go allows that freely since they hang off different
// receivers. A call site like `s.helper(...)` names its callee by selector
// only, and resolving which of several same-named candidates it actually
// means would need real type information (go/types), which this test
// deliberately avoids to stay fast and dependency-free. So:
//
//   - Each RPC candidate's OWN self-guard (does ITS OWN body call a guard
//     directly?) is checked against its own, specific AST node — never
//     confused with a same-named function elsewhere. This is what keeps
//     ContainerServer.ListContainers correctly "guarded" regardless of
//     PeerPool's unrelated same-named method existing in the same package.
//   - Transitive resolution (does it call a HELPER that guards?) only
//     follows a callee name when exactly one function in the whole scan
//     carries that name. An ambiguous or unknown name contributes nothing —
//     neither guarded nor not — so ambiguity can only ever cost a false
//     "ungated" (caught by a human adding a reasoned exemption), never
//     silently pass a truly-unguarded handler by resolving to the wrong,
//     coincidentally-guarded namesake.
func guardedMethods(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob *.go: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no .go files found — test not running from internal/server")
	}
	fset := token.NewFileSet()
	byName := map[string][]*funcInfo{} // bare name -> every FuncDecl sharing it
	var rpcCandidates []*funcInfo      // only those with a receiver
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		node, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range node.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			recv := ""
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				recv = receiverTypeName(fn.Recv.List[0].Type)
			}
			info := analyzeFunc(fn.Body)
			info.recv, info.name = recv, fn.Name.Name
			byName[fn.Name.Name] = append(byName[fn.Name.Name], info)
			if recv != "" {
				rpcCandidates = append(rpcCandidates, info)
			}
		}
	}

	var guardedFrom func(f *funcInfo, visited map[*funcInfo]bool) bool
	guardedFrom = func(f *funcInfo, visited map[*funcInfo]bool) bool {
		if visited[f] {
			return false
		}
		visited[f] = true
		if f.selfGuarded() {
			return true
		}
		for _, callee := range f.calls {
			cands := byName[callee]
			if len(cands) != 1 { // unknown or ambiguous — do not resolve
				continue
			}
			if guardedFrom(cands[0], visited) {
				return true
			}
		}
		return false
	}

	out := map[string]bool{}
	for _, m := range rpcCandidates {
		if guardedFrom(m, map[*funcInfo]bool{}) {
			out[m.recv+"."+m.name] = true
		}
	}
	return out
}

// receiverTypeName returns "Foo" for both "f Foo" and "f *Foo" receivers.
func receiverTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// inspectSkippingFuncLit is ast.Inspect that refuses to descend into a
// nested *ast.FuncLit. A guard call declared inside a callback/closure does
// not gate the ENCLOSING handler unless something guarantees that closure
// runs before the handler's real work — which this static scan cannot
// verify (it might run in a goroutine, a deferred cleanup, or never run at
// all if the callback is merely passed as an unused argument). Tightened
// per CodeRabbit review on PR #1719.
func inspectSkippingFuncLit(n ast.Node, visit func(ast.Node) bool) {
	ast.Inspect(n, func(node ast.Node) bool {
		if _, isFuncLit := node.(*ast.FuncLit); isFuncLit {
			return false
		}
		return visit(node)
	})
}

// analyzeFunc walks body, collecting this function's own auth signals and
// the bare names of every local function/method it calls. Two passes:
// the first collects direct guard calls, callee names, and the LHS
// identifiers of any auth.SubjectFromGRPCContext assignment; the second
// looks for an if-statement that negates one of those identifiers and
// itself constructs a PermissionDenied/Unauthenticated status, which is
// what actually links "read the subject" to "deny if absent" (see
// manualGuardLinked's doc comment).
func analyzeFunc(body *ast.BlockStmt) *funcInfo {
	info := &funcInfo{}
	var subjectOkVars []string
	inspectSkippingFuncLit(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Rhs) == 1 {
				if call, ok := node.Rhs[0].(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						if pkgIdent, ok := sel.X.(*ast.Ident); ok && pkgIdent.Name == "auth" &&
							sel.Sel.Name == "SubjectFromGRPCContext" {
							// (username, roles, ok) — the LHS names, in
							// whatever order the source actually wrote them.
							for _, lhs := range node.Lhs {
								if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
									subjectOkVars = append(subjectOkVars, id.Name)
								}
							}
						}
					}
				}
			}
		case *ast.CallExpr:
			switch fn := node.Fun.(type) {
			case *ast.SelectorExpr:
				if pkgIdent, ok := fn.X.(*ast.Ident); ok && pkgIdent.Name == "auth" {
					if authGuardFuncs[fn.Sel.Name] {
						info.directGuard = true
					}
					return true
				}
				// A local method call (s.foo(...), recv unresolved — see
				// guardedMethods' doc comment on why bare-name matching is
				// good enough here).
				info.calls = append(info.calls, fn.Sel.Name)
			case *ast.Ident:
				info.calls = append(info.calls, fn.Name)
			}
		}
		return true
	})

	if info.directGuard || len(subjectOkVars) == 0 {
		return info
	}
	okSet := make(map[string]bool, len(subjectOkVars))
	for _, v := range subjectOkVars {
		okSet[v] = true
	}
	inspectSkippingFuncLit(body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || !negatesOneOf(ifStmt.Cond, okSet) {
			return true
		}
		if ifStmt.Body != nil && containsDenialCode(ifStmt.Body) {
			info.manualGuardLinked = true
		}
		return true
	})
	return info
}

// negatesOneOf reports whether cond is `!x` or `x == false` for some x in
// okVars — the two ways this codebase's handlers write "the subject lookup
// failed".
func negatesOneOf(cond ast.Expr, okVars map[string]bool) bool {
	switch c := cond.(type) {
	case *ast.UnaryExpr:
		id, ok := c.X.(*ast.Ident)
		return c.Op == token.NOT && ok && okVars[id.Name]
	case *ast.BinaryExpr:
		if c.Op != token.EQL {
			return false
		}
		// NOTE: `a, b := x.(T), y` is NOT the comma-ok form — that requires
		// the type assertion to be the assignment's ONLY right-hand
		// expression. Written the compact way, c.X.(*ast.Ident) panics
		// instead of failing gracefully whenever c.X isn't an *ast.Ident
		// (e.g. `s.field == false`). Each assertion gets its own
		// comma-ok statement instead.
		if id, ok := c.X.(*ast.Ident); ok && okVars[id.Name] && isFalseLit(c.Y) {
			return true
		}
		if id, ok := c.Y.(*ast.Ident); ok && okVars[id.Name] && isFalseLit(c.X) {
			return true
		}
		return false
	}
	return false
}

func isFalseLit(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "false"
}

// containsDenialCode reports whether n references codes.PermissionDenied or
// codes.Unauthenticated as a value (status.Error(codes.X, ...)) anywhere
// within it.
func containsDenialCode(n ast.Node) bool {
	found := false
	inspectSkippingFuncLit(n, func(node ast.Node) bool {
		sel, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkgIdent, ok := sel.X.(*ast.Ident); ok && pkgIdent.Name == "codes" &&
			(sel.Sel.Name == "PermissionDenied" || sel.Sel.Name == "Unauthenticated") {
			found = true
		}
		return true
	})
	return found
}

// TestEveryRPCHasAuthGuard is #1685's lock-in: a newly-added RPC with
// neither a guard call nor a recorded exemption fails CI, closing the gap
// the per-handler auth model otherwise leaves silent.
//
// It also rejects a STALE exemption — one naming an RPC that is now
// guarded — rather than silently accepting it. Checking guarded status
// first and returning early (the original shape) let an exemption entry
// survive its own fix forever: nothing failed, so nothing forced its
// removal, and if a later change accidentally removed the real guard again
// the stale entry would mask the regression by making the RPC "exempt"
// again instead of failing (CodeRabbit review on PR #1719).
func TestEveryRPCHasAuthGuard(t *testing.T) {
	guarded := guardedMethods(t)
	seenKeys := map[string]bool{}
	checked := 0
	check := func(service, receiver, method string) {
		checked++
		key := rpcKey(service, method)
		seenKeys[key] = true
		reason, exempted := authExemptions[key]
		switch {
		case guarded[receiver+"."+method] && exempted:
			t.Errorf("%s: has a guard AND a stale authExemptions entry (%q) — "+
				"remove the exemption now that it's guarded", key, reason)
		case guarded[receiver+"."+method]:
			// guarded, no exemption on record: the normal, expected case.
		case exempted:
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s: exemption recorded with no reason — state WHY, not just THAT", key)
			}
		default:
			t.Errorf("%s (%s.%s): no auth.RequireScope/RequireRole/RequireRoleOrScope/"+
				"AuthorizeTenant/AuthorizeSecretTenant call found, and no authExemptions entry — "+
				"add a guard, or add authExemptions[%q] with a reason before merging",
				key, receiver, method, key)
		}
	}
	for _, svc := range registeredServices {
		service := serviceShortName(svc.desc.ServiceName)
		for _, m := range svc.desc.Methods {
			check(service, svc.receiver, m.MethodName)
		}
		for _, s := range svc.desc.Streams {
			check(service, svc.receiver, s.StreamName)
		}
	}
	if checked == 0 {
		t.Fatal("no RPCs checked — registeredServices or its ServiceDescs are empty; test harness broken")
	}
	// An exemption naming an RPC that doesn't exist on the audited surface
	// (typo'd service/method, or the RPC was renamed/removed) is dead data
	// that nobody will ever be forced to clean up otherwise.
	for key := range authExemptions {
		if !seenKeys[key] {
			t.Errorf("authExemptions[%q] does not name any RPC in registeredServices — "+
				"typo, or the RPC was renamed/removed; remove or fix this entry", key)
		}
	}
	t.Logf("checked %d RPCs across %d services", checked, len(registeredServices))
}

// registerCallPattern matches a dual_server.go call like
// pb.RegisterContainerServiceServer(...), capturing "Container" so it maps
// back to registeredServices' "ContainerService" naming.
var registerCallPattern = regexp.MustCompile(`^Register(.+)ServiceServer$`)

// TestRegisteredServicesMatchesDualServer is #1685's other lock-in
// (CodeRabbit review on PR #1719): registeredServices above is a manually
// maintained list. Without this test, a new pb.RegisterXServiceServer call
// landing in dual_server.go with no matching registeredServices entry would
// leave that service's entire RPC surface unaudited, and
// TestEveryRPCHasAuthGuard would have no way to notice — it only ever looks
// at what registeredServices tells it to.
func TestRegisteredServicesMatchesDualServer(t *testing.T) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "dual_server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse dual_server.go: %v", err)
	}
	tracked := make(map[string]bool, len(registeredServices))
	for _, svc := range registeredServices {
		tracked[serviceShortName(svc.desc.ServiceName)] = true
	}
	found := 0
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "pb" {
			return true
		}
		m := registerCallPattern.FindStringSubmatch(sel.Sel.Name)
		if m == nil {
			return true
		}
		found++
		service := m[1] + "Service"
		if !tracked[service] {
			t.Errorf("dual_server.go registers %s (%s) but registeredServices has no entry for it — "+
				"add {pb.%s_ServiceDesc, \"<ReceiverType>\"} so TestEveryRPCHasAuthGuard audits its RPCs",
				sel.Sel.Name, service, service)
		}
		return true
	})
	if found == 0 {
		t.Fatal("found no pb.RegisterXServiceServer( call in dual_server.go — test harness broken")
	}
	t.Logf("dual_server.go registers %d services, all present in registeredServices", found)
}
