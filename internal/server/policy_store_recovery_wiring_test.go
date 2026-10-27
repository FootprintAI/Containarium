package server

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// NewDualServer needs a database and Incus, so the #2483 wiring is checked
// over the parsed AST: the health service is registered on the gRPC server,
// the recovery is built over both policy servers, its readiness is published
// at startup, and its retry runs in the background.
func TestNewDualServer_WiresPolicyStoreRecoveryAndHealth(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "dual_server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse dual_server.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "NewDualServer" {
			fn = f
		}
	}
	if fn == nil {
		t.Fatal("NewDualServer not found")
	}
	src := func(n ast.Node) string {
		var b strings.Builder
		_ = printer.Fprint(&b, fset, n)
		return b.String()
	}
	var registered, built, synced, started bool
	ast.Inspect(fn, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GoStmt:
			if strings.HasPrefix(src(x.Call), "policyStoreRetry.Run(") {
				started = true
			}
		case *ast.CallExpr:
			s := src(x)
			switch {
			case strings.HasPrefix(s, "healthpb.RegisterHealthServer(grpcServer, policyStoreHealth)"):
				registered = true
			case strings.HasPrefix(s, "newPolicyStoreRecovery(guardrailPolicyServer, codeEgressServer, policyStoreHealth, postgresConnString)"):
				built = true
			case s == "policyStoreRetry.syncHealth()":
				synced = true
			}
		}
		return true
	})
	if !registered {
		t.Error("grpc.health.v1 is not registered on grpcServer (healthpb.RegisterHealthServer(grpcServer, policyStoreHealth))")
	}
	if !built {
		t.Error("newPolicyStoreRecovery(guardrailPolicyServer, codeEgressServer, policyStoreHealth, postgresConnString) missing")
	}
	if !synced {
		t.Error("policyStoreRetry.syncHealth() missing: readiness would be unknown until the first retry")
	}
	if !started {
		t.Error("go policyStoreRetry.Run(...) missing: a store unavailable at startup would never be retried")
	}
}
