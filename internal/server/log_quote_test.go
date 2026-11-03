//go:build !containarium_client

package server

// #3455: server log lines that interpolate a tenant-controlled string
// (username, box name, connection / project / volume name, process name,
// token id, ...) format it with %q, so a value carrying a newline cannot
// forge a second log line and a value carrying ESC cannot drive the
// operator's terminal. Two layers of coverage:
//
//   - per handler family, a behavioural test drives a real code path with a
//     hostile value and inspects what reached the standard logger;
//   - TestLogQuote_NoTenantValueWithBareVerb parses every non-test file in
//     this package and refuses a log.Printf that binds one of the known
//     tenant-controlled expressions to a bare %s / %v, so a new call cannot
//     reintroduce the injection.

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// hostileTenantValue is a tenant-supplied string that, logged raw, starts a
// forged line and clears the operator's terminal.
const hostileTenantValue = "evil\n[forged] admin login ok\x1b[2J"

// assertHostileValueContained fails unless out carries the hostile value in
// its escaped form only: no raw control byte, no line starting with the
// forged prefix, and the escaped value present (so the check is not passing
// on a path that never logged it).
func assertHostileValueContained(t *testing.T, out string) {
	t.Helper()
	if !strings.Contains(out, `evil\n[forged]`) {
		t.Fatalf("hostile value not logged in escaped form; got %q", out)
	}
	for i := 0; i < len(out); i++ {
		if b := out[i]; (b < 0x20 && b != '\n') || b == 0x7f {
			t.Errorf("raw control byte 0x%02x in log output %q", b, out)
			break
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "[forged]") {
			t.Errorf("tenant value forged a log line: %q (full output %q)", line, out)
		}
	}
}

type failingAuditLogger struct{}

func (failingAuditLogger) Log(context.Context, *audit.AuditEntry) error {
	return errors.New("audit store down")
}

// Container lifecycle family: per-box policy RPCs and the CPU admission gate.
func TestLogQuote_ContainerFamily(t *testing.T) {
	seed := func() map[string]*incus.ContainerInfo {
		name := hostileTenantValue + "-container"
		return map[string]*incus.ContainerInfo{name: {Name: name, Tenant: hostileTenantValue, State: "Running"}}
	}
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"delete policy protect", func(t *testing.T) {
			s, _ := newDeletePolicyTestServer(t, seed())
			if _, err := s.SetContainerDeletePolicy(testCtx(), &pb.SetContainerDeletePolicyRequest{
				Name: hostileTenantValue, DeletePolicy: pb.DeletePolicy_DELETE_POLICY_PROTECTED,
			}); err != nil {
				t.Fatalf("SetContainerDeletePolicy: %v", err)
			}
		}},
		{"delete policy unprotect", func(t *testing.T) {
			s, _ := newDeletePolicyTestServer(t, seed())
			if _, err := s.SetContainerDeletePolicy(testCtx(), &pb.SetContainerDeletePolicyRequest{
				Name: hostileTenantValue, DeletePolicy: pb.DeletePolicy_DELETE_POLICY_UNSPECIFIED,
			}); err != nil {
				t.Fatalf("SetContainerDeletePolicy: %v", err)
			}
		}},
		{"tool access set", func(t *testing.T) {
			s, _, _ := newToolAccessTestServer(t, seed())
			if _, err := s.SetContainerToolAccess(testCtx(), &pb.SetContainerToolAccessRequest{
				Name: hostileTenantValue, ToolAccess: pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE,
			}); err != nil {
				t.Fatalf("SetContainerToolAccess: %v", err)
			}
		}},
		{"tool access clear", func(t *testing.T) {
			s, _, _ := newToolAccessTestServer(t, seed())
			if _, err := s.SetContainerToolAccess(testCtx(), &pb.SetContainerToolAccessRequest{
				Name: hostileTenantValue, ToolAccess: pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED,
			}); err != nil {
				t.Fatalf("SetContainerToolAccess: %v", err)
			}
		}},
		{"ttl set", func(t *testing.T) {
			s, _, _ := newTTLTestServer(t, seed())
			if _, err := s.SetContainerTTL(testCtx(), &pb.SetContainerTTLRequest{
				Name: hostileTenantValue, DurationSeconds: 3600,
			}); err != nil {
				t.Fatalf("SetContainerTTL: %v", err)
			}
		}},
		{"ttl clear", func(t *testing.T) {
			s, _, _ := newTTLTestServer(t, seed())
			if _, err := s.SetContainerTTL(testCtx(), &pb.SetContainerTTLRequest{
				Name: hostileTenantValue, DurationSeconds: 0,
			}); err != nil {
				t.Fatalf("SetContainerTTL: %v", err)
			}
		}},
		{"cpu admission reject", func(t *testing.T) {
			s := seedServer(t, 2, nil)
			s.SetCPUOvercommitPolicy(1, true)
			if _, err := s.admitCPUCapacity(hostileTenantValue, "8"); err == nil {
				t.Fatal("over-ceiling create was admitted")
			}
		}},
		{"cpu admission advisory", func(t *testing.T) {
			s := seedServer(t, 2, nil)
			s.SetCPUOvercommitPolicy(1, false)
			if _, err := s.admitCPUCapacity(hostileTenantValue, "8"); err != nil {
				t.Fatalf("advisory gate rejected: %v", err)
			}
		}},
		{"cpu admission fail open", func(t *testing.T) {
			s := seedServer(t, 2, nil)
			s.SetCPUOvercommitPolicy(1, true)
			s.hostCoresFn = func() (float64, error) { return 0, errors.New("no cores") }
			if _, err := s.admitCPUCapacity(hostileTenantValue, "8"); err != nil {
				t.Fatalf("fail-open gate rejected: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertHostileValueContained(t, captureLog(t, func() { tc.run(t) }))
		})
	}
}

// Cluster family: the owner is the caller's subject, logged on create.
func TestLogQuote_ClusterFamily(t *testing.T) {
	s := clusterTestServer()
	out := captureLog(t, func() {
		if _, err := s.CreateCluster(tenantCtx(hostileTenantValue), &pb.CreateClusterRequest{Name: "demo"}); err != nil {
			t.Fatalf("CreateCluster: %v", err)
		}
	})
	assertHostileValueContained(t, out)
}

// Tokens family: the jti of a revoke request is caller-supplied.
func TestLogQuote_TokensFamily(t *testing.T) {
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "ops",
		[]string{auth.RoleAdmin}, []string{auth.ScopeTokensWrite})
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("store_fails=%v", fail), func(t *testing.T) {
			store := newFakeRevocationStore()
			store.failNext = fail
			srv := newTestTokensServer(t, store)
			out := captureLog(t, func() {
				_, _ = srv.RevokeToken(ctx, &pb.RevokeTokenRequest{Jti: hostileTenantValue})
			})
			assertHostileValueContained(t, out)
		})
	}
}

// Process-responder family: the box name on a finding is tenant-chosen.
func TestLogQuote_ProcessResponderFamily(t *testing.T) {
	cases := []struct {
		name string
		run  func()
	}{
		{"queued response skipped", func() {
			r := &ProcessResponder{}
			r.auditSkip(context.Background(), responseJob{f: &threatdetect.Finding{ID: 7, Container: hostileTenantValue}}, "stale")
		}},
		{"audit write failed", func() {
			r := &ProcessResponder{audit: failingAuditLogger{}}
			r.auditLog(context.Background(), "kill", hostileTenantValue, "detail")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertHostileValueContained(t, captureLog(t, tc.run))
		})
	}
}

// Code-egress family: the tenant a policy belongs to is logged on audit failure.
func TestLogQuote_CodeEgressFamily(t *testing.T) {
	s := NewCodingToolEgressPolicyServer(NewMemCodingToolEgressPolicyStore())
	s.SetAuditStore(failingAuditLogger{})
	out := captureLog(t, func() {
		s.auditChange(context.Background(), "code_egress_policy.set", "ops", hostileTenantValue, codeEgressAuditDetail{})
	})
	assertHostileValueContained(t, out)
}

// Model-gateway family: tenant and skill names in a policy transition.
func TestLogQuote_ModelGatewayFamily(t *testing.T) {
	for _, ev := range []modelgateway.PolicyEvent{
		{Tenant: hostileTenantValue, Skill: "review"},
		{Tenant: "alice", Skill: hostileTenantValue},
	} {
		out := captureLog(t, func() { gatewayPolicyLogSink{}.PolicyTransition(ev) })
		assertHostileValueContained(t, out)
	}
}

// Move family: a pre-flight refusal reason is built from the box name.
func TestLogQuote_MoveFamily(t *testing.T) {
	out := captureLog(t, func() { _ = refused("container %s is not encrypted", hostileTenantValue) })
	assertHostileValueContained(t, out)
}

// Run-checkout sweep family: the box and in-box user names it reports.
func TestLogQuote_RunCheckoutSweepFamily(t *testing.T) {
	logs := &logRecorder{}
	sw := runCheckoutSweep{
		exec: func(string, string) (string, error) { return "X\n", nil },
		box:  hostileTenantValue, logf: logs.logf,
	}
	if _, err := sw.sweepHome(hostileTenantValue, "/home/alice"); err != nil {
		t.Fatalf("sweepHome: %v", err)
	}
	assertHostileValueContained(t, logs.all())
}

// tenantLoggedExprs are the argument expressions in this package that carry
// a tenant-controlled string. Keyed "<expr>" for every call site, or
// "<file>:<expr>" where the same identifier also names an operator value
// elsewhere in the package.
var tenantLoggedExprs = map[string]bool{
	"containerName": true, "req.Username": true, "username": true, "req.Name": true,
	"f.Container": true, "row.Container": true, "rec.Username": true, "conn.Username": true,
	"conn.Name": true, "req.Connection": true, "r.FullDomain": true, "owner": true,
	"c.Owner": true, "c.Name": true, "rec.Database": true, "info.Ref.Name": true,
	"job.f.Container": true, "connection": true, "box.Container": true, "user": true,
	"tenant": true, "spec.LocalName": true, "skill.Id": true, "r.Username": true,
	"req.Volume": true, "req.Scope": true, "req.Jti": true, "req.GetUsername()": true,
	"req.Container": true, "rec.Destination": true, "boxName": true, "r.Database": true,
	"r.Destination": true, "req.SkillId": true, "req.Project": true, "req.MountPath": true,
	"req.GetTenant()": true, "r.Domain": true, "p.Run": true, "standing.Container": true,
	"h.unconfirmed.Container": true, "h.applied.Container": true, "in.ContainerName": true,
	"ex.Matched": true, "ex.Comm": true, "ev.Tenant": true, "ev.Skill": true,
	"ev.Container": true, "claims.Username": true, "accountName": true, "v.Name": true,
	"v.Pool": true, "v.TargetContainer": true, "ch.Server": true, "change.URL": true,
	"a.name": true, "r.name": true, "req.GithubTag": true, "req.TargetBackendId": true,
	"pkgName": true, "oldVersion": true, "scrubInBoxText(stderr)": true,
	"strings.TrimSpace(stderr)": true, `strings.Join(warnings, "; ")`: true,
	"runID": true, "lease.RunID": true, "run.runID": true, "run.GetId()": true,
	"container": true, "box": true, "target": true, "resourceID": true,
	"encStoragePool": true, "dataset": true, "root": true, "snapshot": true,
	"from": true, "to": true, "pool": true, "box.ReleasedBy": true,

	"pentest_server.go:binaryPath": true, "pentest_server.go:msg": true,
	"backup_server.go:f": true, "code_egress_server.go:id": true,
	"prepare_encrypted_migration.go:reason": true, "process_responder.go:reason": true,
	"sentinel_key_notify.go:reason": true, "secrets_server.go:k": true,
	"agent_gateway.go:name": true, "agent_server.go:name": true, "backup_server.go:name": true,
	"encryption_hooks.go:name": true, "exec_watcher.go:name": true, "network_server.go:name": true,
	"passthrough_store_access.go:name": true, "run_journal_reaper.go:name": true,
	"sandbox_ttlsweeper_adapter.go:name": true, "ttlsweeper_adapter.go:name": true,
}

// TestLogQuote_NoTenantValueWithBareVerb walks every log.Printf / Fatalf /
// Panicf in this package's non-test sources and fails on any that binds a
// tenant-controlled expression to %s or %v.
func TestLogQuote_NoTenantValueWithBareVerb(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var bad []string
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isStdLogPrintf(call) || len(call.Args) == 0 {
				return true
			}
			format, ok := constFormat(call.Args[0])
			if !ok {
				return true
			}
			verbs, ok := printfVerbs(format)
			if !ok {
				t.Errorf("%s: format uses explicit argument indexes; extend the check", fset.Position(call.Pos()))
				return true
			}
			for i, v := range verbs {
				if i+1 >= len(call.Args) {
					break
				}
				arg := call.Args[i+1]
				expr := types.ExprString(arg)
				if !tenantLoggedExprs[expr] && !tenantLoggedExprs[f+":"+expr] {
					continue
				}
				checked++
				if v == 's' || v == 'v' {
					bad = append(bad, fmt.Sprintf("%s: %s logged with %%%c", fset.Position(arg.Pos()), expr, v))
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no tenant-valued log argument found; the walker is not seeing the package")
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s: log a tenant-controlled string with %%q (#3455)", b)
	}
}

func isStdLogPrintf(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Printf", "Fatalf", "Panicf":
	default:
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "log"
}

// constFormat returns the value of a string literal or a "+" concatenation
// of string literals.
func constFormat(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		a, ok1 := constFormat(x.X)
		b, ok2 := constFormat(x.Y)
		return a + b, ok1 && ok2
	case *ast.ParenExpr:
		return constFormat(x.X)
	}
	return "", false
}

// printfVerbs returns, per consumed argument, the verb that consumes it
// ('*' for a width/precision argument). ok is false for explicit indexes.
func printfVerbs(format string) (verbs []byte, ok bool) {
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		if i < len(format) && format[i] == '%' {
			continue
		}
		for i < len(format) && strings.IndexByte("+-# 0123456789.*[", format[i]) >= 0 {
			switch format[i] {
			case '[':
				return nil, false
			case '*':
				verbs = append(verbs, '*')
			}
			i++
		}
		if i < len(format) {
			verbs = append(verbs, format[i])
		}
	}
	return verbs, true
}
