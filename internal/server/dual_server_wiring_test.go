package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Startup-wiring guards for the metrics-export path (#1077, finding 1).
//
// The behaviour of the resume path is already well covered:
// TestStartMetricsExportIfEnabled_ResumesFromPersistedConfig,
// TestMetricsExport_LateStoreWiring_NotCachedAsDisabled (#1070) and
// TestCurrentExportLabels / ..._ResumeCapturesLiveIdentity (#1080) all
// pin what ContainerServer does *given* the calls.
//
// None of them can catch the failure #1077 was actually filed about: a
// wiring call silently disappearing from dual_server.go. That is not
// hypothetical — #1075 shipped with a comment claiming a call existed at
// a call site where it did not, and no test noticed, because the tests
// hand-injected the dependency instead of exercising the real startup
// path.
//
// NewDualServer needs a database, an incus connection and a filled
// DualServerConfig, so constructing one in a unit test is not realistic.
// These tests assert over the parsed AST of dual_server.go instead. That
// is a narrow tool and deliberately so: it answers exactly one question
// — is the call still there, in the right function — which is the whole
// of the regression class. It reads the AST rather than matching text,
// so reformatting, renamed locals and moved comments do not disturb it.

// dualServerFuncCalls returns the method names called inside the named
// top-level function of dual_server.go, in source order.
func dualServerFuncCalls(t *testing.T, funcName string) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "dual_server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse dual_server.go: %v", err)
	}

	var target *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == funcName {
			target = fn
			break
		}
	}
	if target == nil {
		t.Fatalf("function %q not found in dual_server.go — it was renamed or removed, "+
			"and these wiring guards need updating with it", funcName)
	}

	var calls []string
	ast.Inspect(target, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			// x.Foo()
			calls = append(calls, fn.Sel.Name)
		case *ast.Ident:
			// Foo() — plain function calls, which constructors are. Without
			// this the guards could only see method calls, so a dropped
			// NewXxx(...) was invisible to them.
			calls = append(calls, fn.Name)
		}
		return true
	})
	return calls
}

// dualServerSourceContains reports whether dual_server.go contains the given
// text. Used where the call shape matters (a method on a field) rather than
// just the callee name.
func dualServerSourceContains(t *testing.T, want string) bool {
	t.Helper()
	b, err := os.ReadFile("dual_server.go")
	if err != nil {
		t.Fatalf("read dual_server.go: %v", err)
	}
	return strings.Contains(string(b), want)
}

func indexOfCall(calls []string, name string) int {
	for i, c := range calls {
		if c == name {
			return i
		}
	}
	return -1
}

// NewDualServer must wire the export sinks and the daemon-config store.
//
// Without SetMetricsExportSinks, SetMetricsExport falls through the
// nil-sink path and returns Unimplemented even with valid credentials
// (#1069). Without SetDaemonConfigStore, the resume path later reads a
// nil store, hydrates the disabled default, and export silently never
// resumes after a restart (#1070) — the store used to arrive only via
// SetAlertManager, far later in startup, which is precisely how that bug
// shipped.
func TestNewDualServerWiresMetricsExportDependencies(t *testing.T) {
	calls := dualServerFuncCalls(t, "NewDualServer")

	for _, required := range []string{
		"SetMetricsExportSinks",
		"SetDaemonConfigStore",
	} {
		if indexOfCall(calls, required) < 0 {
			t.Errorf("NewDualServer no longer calls %s — metrics export will fail silently at runtime, "+
				"not at startup. See #1069/#1070 for how each of these shipped broken before.", required)
		}
	}
}

// The resume call must NOT be in NewDualServer.
//
// This is the #1080 regression, and it is the reason the ordering is
// worth a test rather than a comment: a resumed collector snapshots the
// daemon's backend_id/region when it is built, and neither is populated
// this early — localBackendID() returns "local" and region is "" until
// SetPeerPool / SetCapabilityIdentity run in Start(). Resuming here
// re-emitted every host's series under a second ("local"/"") identity
// after each restart, splitting dashboards and alerts keyed on
// backend_id.
//
// Moving the call back "for tidiness" would reintroduce that, and the
// symptom appears in Grafana days later rather than in CI.
func TestNewDualServerDoesNotResumeMetricsExport(t *testing.T) {
	calls := dualServerFuncCalls(t, "NewDualServer")

	if indexOfCall(calls, "StartMetricsExportIfEnabled") >= 0 {
		t.Error("NewDualServer calls StartMetricsExportIfEnabled — the resumed collector would " +
			"snapshot the placeholder identity (backend_id \"local\", empty region) because " +
			"SetCapabilityIdentity/SetPeerPool have not run yet. This is #1080; resume belongs in Start().")
	}
}

// Start must resume export, and must do so after identity is wired.
//
// The ordering is the substance: resuming before SetCapabilityIdentity
// produces a collector labelled with the placeholder identity, which is
// #1080 again, just relocated.
func TestStartResumesMetricsExportAfterIdentityIsWired(t *testing.T) {
	calls := dualServerFuncCalls(t, "Start")

	resume := indexOfCall(calls, "StartMetricsExportIfEnabled")
	if resume < 0 {
		t.Fatal("DualServer.Start no longer calls StartMetricsExportIfEnabled — metrics export " +
			"will not resume after a daemon restart, and nothing at runtime will say so (#1070)")
	}

	identity := indexOfCall(calls, "SetCapabilityIdentity")
	if identity < 0 {
		t.Fatal("DualServer.Start no longer calls SetCapabilityIdentity — the resumed collector " +
			"has no real identity to snapshot")
	}

	if resume < identity {
		t.Errorf("StartMetricsExportIfEnabled runs before SetCapabilityIdentity (positions %d < %d): "+
			"the resumed collector would snapshot the placeholder identity rather than the daemon's "+
			"real backend_id/region (#1080)", resume, identity)
	}
}

// The K8s tenant-policy reconciler must be constructed in NewDualServer and
// started in Start (#1188).
//
// Split for the same reason the metrics-export wiring is: it needs the policy
// store, which is a local in NewDualServer, but starting a loop belongs with
// the other loops in Start. Neither half is visible at runtime if it goes
// missing — a dropped construction leaves the reconciler nil and every K8s
// tenant silently running without the egress policy they configured, which is
// the exact bug #1188 exists to fix.
func TestNewDualServerWiresK8sNetworkPolicyReconciler(t *testing.T) {
	newCalls := dualServerFuncCalls(t, "NewDualServer")
	if indexOfCall(newCalls, "NewK8sNetworkPolicyReconciler") < 0 {
		t.Error("NewDualServer no longer constructs the K8s network-policy reconciler — every K8s " +
			"tenant would silently run without the egress policy they configured (#1188)")
	}

	startCalls := dualServerFuncCalls(t, "Start")
	if indexOfCall(startCalls, "Start") < 0 {
		t.Error("Start makes no Start() calls at all — the parse is wrong, not the wiring")
	}
	// The reconciler is started via the field, so look for the guarded call
	// shape rather than a bare constructor name.
	if !dualServerSourceContains(t, "ds.k8sNetPolicyReconciler.Start(ctx)") {
		t.Error("Start no longer starts the K8s network-policy reconciler — it would be constructed " +
			"and never run, which looks identical to a daemon with no tenant policies (#1188)")
	}
}

// #1189: on a K8s deployment the SSH collector used to be built only if an
// incus client could be created — which on a K8s host it cannot. The result
// was a fleet that recorded no logins at all, indistinguishable from one
// nobody logged into. The guard is that the K8s branch exists and picks the
// pod-log source.
func TestNewDualServerWiresTheK8sSessionSource(t *testing.T) {
	newCalls := dualServerFuncCalls(t, "NewDualServer")
	if indexOfCall(newCalls, "NewK8sSessionSource") < 0 {
		t.Error("NewDualServer never constructs the K8s session source — a K8s deployment would " +
			"record no SSH logins, which reads exactly like a fleet nobody logged into (#1189)")
	}
	if indexOfCall(newCalls, "NewSSHCollector") < 0 {
		t.Error("NewDualServer no longer constructs the LXC SSH collector — the incus path would " +
			"stop auditing logins (#1189)")
	}

	// Both sources must remain reachable: a single collector built from
	// whichever source happens to be first would leave one backend unaudited.
	if !dualServerSourceContains(t, "containerServer.boxes().Kind() == box.KindK8s") {
		t.Error("the SSH collector no longer selects its source by backend kind")
	}
	if !dualServerSourceContains(t, "audit.NewSSHCollectorWithSource(") {
		t.Error("the K8s branch no longer builds the collector from a source — it would fall back " +
			"to the incus constructor, which cannot reach a K8s box (#1189)")
	}
}

// Everything the daemon starts must also be stopped on shutdown.
//
// The shutdown block stops thirteen components by name. Adding a fourteenth
// Start without the matching Stop is a one-line omission that nothing catches:
// the daemon still boots, still serves, still passes every test, and only
// leaks a goroutine that keeps writing to the apiserver after Start has
// returned. That is exactly how k8sNetPolicyReconciler shipped in #1264 —
// started, never stopped, and the only one of thirteen missing.
//
// Checked against the source rather than at runtime because the omission is
// in the wiring, and the wiring is what a runtime test would have to stand up
// in full to observe.
func TestEverythingStartedIsAlsoStopped(t *testing.T) {
	b, err := os.ReadFile("dual_server.go")
	if err != nil {
		t.Fatalf("read dual_server.go: %v", err)
	}
	src := string(b)

	// Components with no Stop method at all, and why. A ctx-driven blocking
	// Start needs no separate stop — it returns when the context is done.
	noStopMethod := map[string]string{
		"gatewayServer": "Start(ctx) blocks and returns when ctx is done; GatewayServer has no Stop",
		// threatDetectNotifier.Start is called with the same sweepCtx as the
		// threat-detect sweep ticker (startThreatDetectSweep, #1643) —
		// ds.threatDetectSweepStop() cancels that shared context on
		// shutdown, which stops the notifier's delivery-worker goroutine
		// too. WebhookNotifier has no separate Stop method by design.
		"threatDetectNotifier": "Start(sweepCtx) — shares threatDetectSweepStop's context; no separate Stop needed",
	}

	started := regexp.MustCompile(`ds\.(\w+)\.Start\(`).FindAllStringSubmatch(src, -1)
	if len(started) == 0 {
		t.Fatal("found no ds.<field>.Start( calls — the pattern changed, so this guard is blind")
	}

	var missing []string
	for _, m := range started {
		field := m[1]
		if reason, ok := noStopMethod[field]; ok {
			t.Logf("%s: not stopped, by design (%s)", field, reason)
			continue
		}
		if !strings.Contains(src, "ds."+field+".Stop()") {
			missing = append(missing, field)
		}
	}

	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these components are started and never stopped on shutdown:\n  %s\n"+
			"Each keeps its goroutines running after Start returns. Add a Stop() call to the "+
			"ctx.Done() block, or record it in noStopMethod above with the reason.",
			strings.Join(missing, "\n  "))
	}
}

// A reconciliation nothing calls does not happen.
//
// The durable crew-run store makes RUNNING survive a restart, so the daemon
// has to clear it at start or GetCrewRun answers RUNNING forever for a run
// that can never finish (#1182 AC4). #1320 had to fix exactly this shape for
// these stores once already — constructed, never wired — so it is guarded
// rather than trusted.
func TestNewDualServerReconcilesStrandedCrewRuns(t *testing.T) {
	if !dualServerSourceContains(t, "FailStranded(") {
		t.Error("the daemon never reconciles stranded crew runs — a run the previous daemon was " +
			"driving stays RUNNING in the store forever, and nothing reports it (#1182 AC4)")
	}
	// It has to run against the durable store, not the memory one that is
	// empty at start anyway.
	if !dualServerSourceContains(t, "runStore.FailStranded(") {
		t.Error("reconciliation does not run against the Postgres store it exists for")
	}
}
