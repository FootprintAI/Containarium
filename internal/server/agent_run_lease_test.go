package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeSeedWiper records the wipe exec runlease.End issues. The production
// Wiper is *container.Manager, whose Exec type-asserts its backend to the
// concrete *incus.Client, so the runlease.Wiper interface is the only seam a
// unit test can reach the wipe through.
type fakeSeedWiper struct {
	mu    sync.Mutex
	boxes []string
	cmds  [][]string
}

func (w *fakeSeedWiper) Exec(box string, cmd []string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.boxes = append(w.boxes, box)
	w.cmds = append(w.cmds, cmd)
	return nil
}

func (w *fakeSeedWiper) calls() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.cmds)
}

// ctxAwareRevoker is fakeRevocationStore with the one behavior the real
// Postgres store has and the fake does not: it fails a revoke whose context is
// already done. Without it a cancelled-caller test passes even when the lease
// ends on the RPC's own (cancelled) context, because the fake ignores ctx.
type ctxAwareRevoker struct{ *fakeRevocationStore }

func (r ctxAwareRevoker) Revoke(ctx context.Context, jti string, expiresAt time.Time, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.fakeRevocationStore.Revoke(ctx, jti, expiresAt, reason)
}

// listRevocations reads the fake store's contents through its own locking.
func listRevocations(t *testing.T, store *fakeRevocationStore) []auth.Revocation {
	t.Helper()
	out, err := store.List(context.Background(), auth.ListRevocationsParams{})
	if err != nil {
		t.Fatalf("List revocations: %v", err)
	}
	return out
}

// fakeAuditLogger records the audit entries this server writes. *audit.Store
// needs a live Postgres pool, so the auditLogger interface is the only way to
// assert on what actually lands in audit_logs — the action, the resource type,
// and the run_id column this feature is the first writer of.
//
// Log refuses an already-done context, the way a real pool does. That is what
// makes the detached-write assertions real: without it a cancelled caller's row
// is still recorded and the test passes even with context.WithoutCancel
// removed — the same trap ctxAwareRevoker exists for.
//
// blockUntilDone makes Log wait for its context instead of returning, which is
// how the bounded-write test stands in for a wedged Postgres holding the
// audit chain's global advisory lock.
type fakeAuditLogger struct {
	mu             sync.Mutex
	entries        []audit.AuditEntry
	err            error
	blockUntilDone bool
}

func (f *fakeAuditLogger) Log(ctx context.Context, e *audit.AuditEntry) error {
	if f.blockUntilDone {
		<-ctx.Done()
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, *e)
	return f.err
}

func (f *fakeAuditLogger) byAction(action string) []audit.AuditEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []audit.AuditEntry
	for _, e := range f.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// testLease is a two-credential lease shaped like the one provisionSkillBox
// hands back for a gateway-mode run.
func testLease(runID string) runlease.Lease {
	exp := time.Now().Add(agentTokenTTL)
	return runlease.Lease{
		RunID:   runID,
		Box:     "agent-hello-agent-container",
		SeedDir: seedDirFor(runID),
		Credentials: []runlease.Credential{
			{Kind: runlease.KindPlatformJWT, JTI: "jti-platform", ExpiresAt: exp},
			{Kind: runlease.KindGatewayToken, JTI: "jti-gateway", ExpiresAt: exp},
		},
	}
}

func TestResolveRunID_Table(t *testing.T) {
	maxID := strings.Repeat("a", 128)
	cases := []struct {
		name     string
		in       string
		wantEcho bool // echoes the input verbatim
		wantCode codes.Code
	}{
		{name: "empty generates a uuid", in: ""},
		{name: "simple id echoes", in: "run-1", wantEcho: true},
		{name: "every allowed class echoes", in: "Run_9.a-Z", wantEcho: true},
		{name: "128 chars echoes", in: maxID, wantEcho: true},
		{name: "129 chars rejected", in: maxID + "a", wantCode: codes.InvalidArgument},
		{name: "slash rejected", in: "run/1", wantCode: codes.InvalidArgument},
		{name: "shell metachars rejected", in: "run;rm -rf /", wantCode: codes.InvalidArgument},
		{name: "space rejected", in: "run 1", wantCode: codes.InvalidArgument},
		{name: "newline rejected", in: "run\n1", wantCode: codes.InvalidArgument},
		// #1860: a run id becomes a single path segment under
		// /etc/containarium/agent/runs and /workspace/runs — "." and ".."
		// both match runIDPattern's character class but must never resolve
		// to the roots themselves.
		{name: "dot rejected", in: ".", wantCode: codes.InvalidArgument},
		{name: "dot-dot rejected", in: "..", wantCode: codes.InvalidArgument},
		{name: "dot as a real id segment still echoes", in: "run.1", wantEcho: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveRunID(tc.in)
			if tc.wantCode != codes.OK {
				if status.Code(err) != tc.wantCode {
					t.Fatalf("resolveRunID(%q) error = %v (code %v), want code %v", tc.in, err, status.Code(err), tc.wantCode)
				}
				if got != "" {
					t.Errorf("rejected input must yield no run id, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveRunID(%q): unexpected error %v", tc.in, err)
			}
			if tc.wantEcho {
				if got != tc.in {
					t.Errorf("resolveRunID(%q) = %q, want the input echoed", tc.in, got)
				}
				return
			}
			if _, perr := uuid.Parse(got); perr != nil {
				t.Errorf("resolveRunID(%q) = %q, want a generated uuid: %v", tc.in, got, perr)
			}
		})
	}
}

// TestEndRunLease_UsesDetachedContext is the caller-cancel exit path: the RPC
// context is already dead when the lease ends, and both credentials must still
// be revoked and the seed files still wiped. Without context.WithoutCancel the
// revokes would fail with context.Canceled.
func TestEndRunLease_UsesDetachedContext(t *testing.T) {
	store := newFakeRevocationStore()
	s := &AgentSkillServer{}
	s.SetRevocationStore(ctxAwareRevoker{store})
	w := &fakeSeedWiper{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the caller is gone before the lease ends

	s.endRunLease(ctx, testLease("run-detached"), w, runExitReason)

	for _, jti := range []string{"jti-platform", "jti-gateway"} {
		revoked, err := store.IsRevoked(context.Background(), jti)
		if err != nil {
			t.Fatalf("IsRevoked(%s): %v", jti, err)
		}
		if !revoked {
			t.Errorf("%s was not revoked — the lease did not end under a detached context", jti)
		}
	}
	// Reasons come back through List rather than store.revoked[jti]: the map is
	// mutex-guarded and reading it bare would be a race the moment anything in
	// this package revokes concurrently.
	for _, r := range listRevocations(t, store) {
		if r.Reason != runExitReason {
			t.Errorf("%s revoked with reason %q, want %q", r.JTI, r.Reason, runExitReason)
		}
	}
	// #1860: endRunLease now runs a second Exec (rm -rf the seed dir) after
	// the file wipe; wipe stays cmds[0], the dirs removal is cmds[1].
	if w.calls() != 2 {
		t.Fatalf("exec calls = %d, want 2 (wipe files, then remove dirs)", w.calls())
	}
	seedDir := seedDirFor("run-detached")
	wantCmd := []string{"rm", "-f", seedDir + "/token", seedDir + "/gateway.env"}
	if strings.Join(w.cmds[0], " ") != strings.Join(wantCmd, " ") {
		t.Errorf("wipe cmd = %v, want %v", w.cmds[0], wantCmd)
	}
	wantRemoveCmd := []string{"rm", "-rf", seedDir}
	if strings.Join(w.cmds[1], " ") != strings.Join(wantRemoveCmd, " ") {
		t.Errorf("remove dirs cmd = %v, want %v", w.cmds[1], wantRemoveCmd)
	}
	if w.boxes[0] != "agent-hello-agent-container" {
		t.Errorf("wipe box = %q, want the lease's box", w.boxes[0])
	}
}

// TestEndRunLease_UnregistersFromRunRegistry pins the #1922 wiring: a
// run's entry in the shared run registry is removed exactly when its
// lease ends, so a tracker write RPC can no longer resolve or claim
// liveness for a run that has finished.
func TestEndRunLease_UnregistersFromRunRegistry(t *testing.T) {
	registry := runlease.NewRegistry()
	registry.Register("run-registry-cleanup", runlease.Info{SkillID: "hello-agent", Model: "sonnet"})

	s := &AgentSkillServer{}
	s.SetRunRegistry(registry)
	w := &fakeSeedWiper{}

	if !registry.Live("run-registry-cleanup") {
		t.Fatal("setup: run should be live before endRunLease")
	}
	s.endRunLease(context.Background(), testLease("run-registry-cleanup"), w, runExitReason)

	if registry.Live("run-registry-cleanup") {
		t.Error("run still shows as live in the registry after endRunLease")
	}
}

// TestEndRunLease_NilRunRegistry_DoesNotPanic covers a daemon where
// dual_server.go's SetRunRegistry wiring hasn't run (e.g. tests
// constructing AgentSkillServer directly) — the nil-guard at the call
// site must make this a no-op, not a crash.
func TestEndRunLease_NilRunRegistry_DoesNotPanic(t *testing.T) {
	s := &AgentSkillServer{} // runs field left nil
	w := &fakeSeedWiper{}
	s.endRunLease(context.Background(), testLease("run-no-registry"), w, runExitReason)
}

// TestEndRunLease_LogsWhenUnrevoked covers the no-Postgres daemon: the run
// still completes and the files are still wiped, but the operator gets exactly
// one line naming the run whose credentials will now live to their expiry.
func TestEndRunLease_LogsWhenUnrevoked(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	s := &AgentSkillServer{} // no revocation store wired
	w := &fakeSeedWiper{}
	s.endRunLease(context.Background(), testLease("run-nostore"), w, runExitReason)

	out := buf.String()
	if !strings.Contains(out, "run-nostore") {
		t.Errorf("log must name the run, got %q", out)
	}
	// Counted by substring, not "one line in the buffer": log output is
	// process-global, so a stray line from another test's background goroutine
	// would otherwise turn this into an unreadable CI flake instead of a
	// failure. One line per run is still exactly what is asserted.
	if n := strings.Count(out, "could not be revoked"); n != 1 {
		t.Errorf("want exactly one unrevoked-credentials line per run, got %d:\n%s", n, out)
	}
	// #1860: wipe files, then remove dirs — both still run without a store.
	if w.calls() != 2 {
		t.Errorf("files must still be wiped and dirs removed without a store; exec calls = %d", w.calls())
	}
}

// TestRunLeaseAuditPayloads pins the Detail JSON of both audit rows: it is
// marshalled from named Go structs (never map[string]string) and carries the
// run id plus every minted jti, which is what makes "revoke everything this
// run was given" answerable from the audit trail alone.
func TestRunLeaseAuditPayloads(t *testing.T) {
	lease := testLease("run-audit")

	var issue runLeaseIssueDetail
	if err := json.Unmarshal([]byte(runLeaseIssuePayload(lease)), &issue); err != nil {
		t.Fatalf("unmarshal issue payload: %v", err)
	}
	if issue.RunID != "run-audit" {
		t.Errorf("issue run_id = %q, want run-audit", issue.RunID)
	}
	if issue.Box != lease.Box {
		t.Errorf("issue box = %q, want %q", issue.Box, lease.Box)
	}
	if len(issue.Credentials) != 2 {
		t.Fatalf("issue credentials = %d, want both minted credentials", len(issue.Credentials))
	}
	for i, want := range []runLeaseCredential{
		{Kind: string(runlease.KindPlatformJWT), JTI: "jti-platform"},
		{Kind: string(runlease.KindGatewayToken), JTI: "jti-gateway"},
	} {
		if issue.Credentials[i].Kind != want.Kind || issue.Credentials[i].JTI != want.JTI {
			t.Errorf("issue credential %d = %+v, want kind %q jti %q", i, issue.Credentials[i], want.Kind, want.JTI)
		}
		if issue.Credentials[i].Exp == "" {
			t.Errorf("issue credential %d has no exp — an auditor cannot tell when it dies on its own", i)
		}
	}

	out := runlease.Outcome{
		Revoked:     []string{"jti-platform"},
		Unrevoked:   []string{"jti-gateway"},
		Wiped:       true,
		DirsRemoved: true,
		Errs:        []error{errors.New("runlease: revoke jti-gateway: boom")},
	}
	raw := runLeaseEndPayload(lease, runExitReason, out)
	var end runLeaseEndDetail
	if err := json.Unmarshal([]byte(raw), &end); err != nil {
		t.Fatalf("unmarshal end payload: %v", err)
	}
	if end.RunID != "run-audit" || end.Reason != runExitReason {
		t.Errorf("end run_id/reason = %q/%q, want run-audit/%s", end.RunID, end.Reason, runExitReason)
	}
	if len(end.Revoked) != 1 || end.Revoked[0] != "jti-platform" {
		t.Errorf("end revoked = %v, want [jti-platform]", end.Revoked)
	}
	if len(end.Unrevoked) != 1 || end.Unrevoked[0] != "jti-gateway" {
		t.Errorf("end unrevoked = %v, want [jti-gateway]", end.Unrevoked)
	}
	if !end.Wiped {
		t.Error("end wiped = false, want true")
	}
	// #1860
	if !end.DirsRemoved {
		t.Error("end dirs_removed = false, want true")
	}
	if len(end.Errors) != 1 || !strings.Contains(end.Errors[0], "jti-gateway") {
		t.Errorf("end errors = %v, want the revoke failure recorded", end.Errors)
	}
	// Empty slices must serialize as [], not null: an operator reading the row
	// should see "nothing failed", not a missing field. DirsRemoved false is
	// its own correct zero value here, not something to paper over.
	clean := runLeaseEndPayload(lease, runExitReason, runlease.Outcome{Wiped: true})
	for _, want := range []string{`"unrevoked":[]`, `"errors":[]`, `"revoked":[]`, `"dirs_removed":false`} {
		if !strings.Contains(clean, want) {
			t.Errorf("clean end payload %s must contain %s", clean, want)
		}
	}
}

// runLeaseCallerCtx is an authorized context that also carries a caller jti, so audit
// attribution has something real to pick up. Username/roles come from the
// claims (SubjectFromGRPCContext falls through to them when the metadata
// carries no username), the jti from metadata — the path the HTTP→gateway→gRPC
// hop actually uses.
func runLeaseCallerCtx() context.Context {
	return metadata.NewIncomingContext(ctxAs("operator", true), metadata.Pairs(auth.MDKeyJTI, "caller-jti"))
}

// TestRunLeaseAuditRows pins the ENVELOPE of the two run-lease rows — the half
// of design §5 that runLeaseIssuePayload/runLeaseEndPayload do not cover.
// `ResourceType: "agent_run"`, or RunID left empty, would ship green without
// this: audit_logs.run_id has no other writer yet, and #1825's query is its
// only reader.
func TestRunLeaseAuditRows(t *testing.T) {
	assertEnvelope := func(t *testing.T, e audit.AuditEntry, action, runID string) {
		t.Helper()
		if e.Action != action {
			t.Errorf("action = %q, want %q", e.Action, action)
		}
		if e.ResourceType != "agent_skill_run" {
			t.Errorf("resource_type = %q, want agent_skill_run", e.ResourceType)
		}
		if e.ResourceID != runID {
			t.Errorf("resource_id = %q, want the run id %q", e.ResourceID, runID)
		}
		if e.RunID != runID {
			t.Errorf("run_id column = %q, want %q — this row is its first writer", e.RunID, runID)
		}
		// The caller's jti, never a minted one: "what did this credential do"
		// has to keep meaning the credential that made the call.
		if e.TokenID != "caller-jti" {
			t.Errorf("token_id = %q, want the caller's jti", e.TokenID)
		}
		if strings.Contains(e.TokenID, "jti-platform") || strings.Contains(e.TokenID, "jti-gateway") {
			t.Errorf("token_id = %q must not be a minted jti", e.TokenID)
		}
	}

	t.Run("end row through RunAgentSkill", func(t *testing.T) {
		audits := &fakeAuditLogger{}
		s, skill := newSkillBoxHarness(t, newFakeRevocationStore())
		s.audit = audits

		if _, err := s.RunAgentSkill(runLeaseCallerCtx(), &pb.RunAgentSkillRequest{SkillId: skill.Id, RunId: "run-rows"}); err == nil {
			t.Fatal("expected the seed exec to fail on the fake backend")
		}

		end := audits.byAction("agent.run_lease_end")
		if len(end) != 1 {
			t.Fatalf("agent.run_lease_end rows = %d, want 1", len(end))
		}
		assertEnvelope(t, end[0], "agent.run_lease_end", "run-rows")

		var detail runLeaseEndDetail
		if err := json.Unmarshal([]byte(end[0].Detail), &detail); err != nil {
			t.Fatalf("end detail is not the typed struct: %v", err)
		}
		if detail.Reason != provisionFailedReason {
			t.Errorf("reason = %q, want %q", detail.Reason, provisionFailedReason)
		}
		// The orphan end row documented at the seed-failure branch: the issue
		// row is written only after a successful seed, so this path has none.
		if n := len(audits.byAction("agent.run_lease_issue")); n != 0 {
			t.Errorf("issue rows on a failed provision = %d, want 0", n)
		}
	})

	t.Run("issue row survives a cancelled caller", func(t *testing.T) {
		audits := &fakeAuditLogger{}
		s := &AgentSkillServer{audit: audits}
		ctx, cancel := context.WithCancel(runLeaseCallerCtx())
		cancel() // the caller is gone before the row is written

		// Exactly the call provisionSkillBox makes after a successful seed.
		lease := testLease("run-issue")
		s.auditRunLease(ctx, "agent.run_lease_issue", lease.RunID, runLeaseIssuePayload(lease))

		issue := audits.byAction("agent.run_lease_issue")
		if len(issue) != 1 {
			t.Fatalf("agent.run_lease_issue rows = %d, want 1 — a cancelled caller must not lose the row", len(issue))
		}
		assertEnvelope(t, issue[0], "agent.run_lease_issue", "run-issue")
		if !strings.Contains(issue[0].Detail, "jti-platform") || !strings.Contains(issue[0].Detail, "jti-gateway") {
			t.Errorf("issue detail must list both minted jtis, got %s", issue[0].Detail)
		}
	})

	t.Run("a wedged store cannot hang the run", func(t *testing.T) {
		// audit.Store.Log takes a global pg_advisory_xact_lock with no timeout
		// of its own. Without auditWriteBudget this write inherits no deadline
		// at all (context.WithoutCancel carries none), and RunAgentSkill blocks
		// in its own defer for as long as Postgres takes.
		s := &AgentSkillServer{audit: &fakeAuditLogger{blockUntilDone: true}}
		done := make(chan time.Duration, 1)
		go func() {
			start := time.Now()
			s.auditRunLease(context.Background(), "agent.run_lease_end", "run-wedged", "{}")
			done <- time.Since(start)
		}()
		select {
		case elapsed := <-done:
			if elapsed < auditWriteBudget/2 {
				t.Errorf("returned after %s — the write was not actually attempted", elapsed)
			}
			if elapsed > auditWriteBudget*2 {
				t.Errorf("returned after %s, want bounded by auditWriteBudget (%s)", elapsed, auditWriteBudget)
			}
		case <-time.After(auditWriteBudget * 3):
			t.Fatalf("audit write did not return within %s — it is unbounded", auditWriteBudget*3)
		}
	})
}

// newSkillBoxHarness wires an AgentSkillServer over a map-backed incus fake.
// The box is pre-created so provisionSkillBox takes its reuse path (no deploy),
// which puts the test straight on the mint→seed path under test.
//
// (*container.Manager).Exec type-asserts its backend to the concrete
// *incus.Client, so the seed exec ALWAYS fails on a fake backend — which is
// exactly the failure this harness exists to exercise.
func newSkillBoxHarness(t *testing.T, store auth.RevocationStore) (*AgentSkillServer, *pb.AgentSkill) {
	t.Helper()
	s, skill, _ := newSkillBoxHarnessInspectable(t, store)
	return s, skill
}

// newSkillBoxHarnessInspectable is newSkillBoxHarness plus the fake backend
// itself, for tests that need to assert on the SEQUENCE of commands issued
// (cloud#1733's kill-then-launch fix) rather than just an outcome.
func newSkillBoxHarnessInspectable(t *testing.T, store auth.RevocationStore) (*AgentSkillServer, *pb.AgentSkill, *fakeSandboxBackend) {
	t.Helper()
	tm, err := auth.NewTokenManager("test-secret-must-be-at-least-32-bytes-long-ok", "test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	backend := newFakeSandboxBackend()
	catalog := skills.GetDefault()
	skill, err := catalog.Get("hello-agent")
	if err != nil {
		t.Fatalf("catalog hello-agent: %v", err)
	}
	if err := backend.CreateContainer(incus.ContainerConfig{Name: "agent-" + skill.Id + "-container"}); err != nil {
		t.Fatalf("seed fake backend: %v", err)
	}
	cs := &ContainerServer{manager: container.NewWithBackend(backend)}
	s := &AgentSkillServer{
		catalog: catalog,
		recipes: NewRecipeServer(cs, nil),
		tokens:  tm,
		gateway: &gatewayProvisioning{provider: "anthropic", httpPort: 8080, secret: []byte("test-shared-secret")},
	}
	s.SetRevocationStore(store)
	return s, skill, backend
}

// TestProvisionSkillBox_EndsPartialLeaseOnSeedFailure: a run whose seed exec
// fails after both credentials are minted must not leave live credentials
// behind. provisionSkillBox owns that cleanup, because RunAgentSkill's defer
// is only armed once provisioning has succeeded.
func TestProvisionSkillBox_EndsPartialLeaseOnSeedFailure(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill := newSkillBoxHarness(t, store)

	_, _, lease, _, _, err := s.provisionSkillBox(ctxAs("admin", true), skill, "", "", "{}", "run-partial", "", "", "", "")
	if err == nil {
		t.Fatal("provisionSkillBox must fail when the seed exec fails")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("seed failure code = %v, want Internal", status.Code(err))
	}
	if lease.RunID != "" || len(lease.Credentials) != 0 {
		t.Errorf("a failed provision must return no live lease, got %+v", lease)
	}

	revoked, err := store.List(context.Background(), auth.ListRevocationsParams{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(revoked) != 2 {
		t.Fatalf("revoked %d credential(s), want both the platform JWT and the gateway token: %+v", len(revoked), revoked)
	}
	for _, r := range revoked {
		if r.Reason != provisionFailedReason {
			t.Errorf("jti %s revoked with reason %q, want %q", r.JTI, r.Reason, provisionFailedReason)
		}
	}
}

// TestRunAgentSkill_ResponseCarriesRunID pins the run_id half of the RPC
// contract against the GENERATED pb types, so a stale regeneration fails to
// compile rather than passing quietly.
//
// The RPC cannot be driven to a successful response from a unit test: the seed
// step goes through (*container.Manager).Exec, which type-asserts its backend
// to the concrete *incus.Client and so fails on every fake (see
// newSkillBoxHarness). What is asserted here is that req.run_id is read and
// validated BEFORE any box work, and that a resolved run id round-trips
// through the generated response message. The returned value on a real run is
// covered by the Verify-on-dev step of #1817.
func TestRunAgentSkill_ResponseCarriesRunID(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill := newSkillBoxHarness(t, store)
	ctx := ctxAs("admin", true)

	// A bad run id is rejected at the boundary, before the box is touched.
	if _, err := s.RunAgentSkill(ctx, &pb.RunAgentSkillRequest{SkillId: skill.Id, RunId: "bad id"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad run_id: code = %v, want InvalidArgument", status.Code(err))
	}
	// A well-formed one is not: the run proceeds and fails later, in the box.
	if _, err := s.RunAgentSkill(ctx, &pb.RunAgentSkillRequest{SkillId: skill.Id, RunId: "run-ok"}); status.Code(err) == codes.InvalidArgument {
		t.Errorf("valid run_id must not be rejected: %v", err)
	}

	for _, in := range []string{"", "run-echoed"} {
		runID, err := resolveRunID(in)
		if err != nil {
			t.Fatalf("resolveRunID(%q): %v", in, err)
		}
		resp := &pb.RunAgentSkillResponse{RunId: runID, ArtifactJson: "{}"}
		if resp.GetRunId() != runID {
			t.Errorf("response run_id = %q, want %q", resp.GetRunId(), runID)
		}
		if in != "" && resp.GetRunId() != in {
			t.Errorf("response run_id = %q, want the caller's %q echoed", resp.GetRunId(), in)
		}
	}
}

// TestStartServeMode_StopsPriorInstanceBeforeLaunching is cloud#1733's fix: a
// crew member box is reused across runs, and RunCrew re-mints a fresh gateway
// token + reseeds it to disk on every call — but startServeMode used to
// background a new agent-runtime unconditionally, with nothing to stop an
// earlier instance first. Since the OSS image's A2A server binds a fixed
// port, every relaunch after the first crashed on EADDRINUSE (confirmed
// live: OSS agent-runtime.log on the asia workhorse), so the box kept
// serving whatever token its FIRST-EVER launch read, until that token's
// 30-minute TTL passed — after which every run against a box more than
// agentTokenTTL old failed "invalid gateway token: expired" regardless of
// what was actually reseeded.
//
// What this test CAN observe against the fake backend: the kill step runs
// (it uses ExecWithExitCode, part of the incus.Backend interface, unlike
// ExecWithOutput which type-asserts to the concrete client and always fails
// on a mock — see Manager.ExecWithOutput's own doc comment). What it CANNOT
// observe: the subsequent launch call, because startServeMode's launch step
// deliberately keeps using ExecWithOutput (unchanged production behavior),
// which fails against every fake backend by construction — the same
// limitation TestProvisionSkillBox_GitSourceSet_SeedFailsBeforeFetch
// documents for the seed step. That a kill actually frees the port and lets
// a fresh process bind it was verified live on the asia workhorse (restart
// both stale boxes, confirm a single fresh agent-runtime process replaces
// the ~25h-old one) rather than in this unit test.
func TestStartServeMode_StopsPriorInstanceBeforeLaunching(t *testing.T) {
	store := newFakeRevocationStore()
	s, _, backend := newSkillBoxHarnessInspectable(t, store)

	s.startServeMode("agent-hello-agent", "/etc/containarium/agent/runs/run-1")

	if len(backend.execCalls) != 1 {
		t.Fatalf("execCalls = %d, want 1 (the kill step — the launch step uses ExecWithOutput, unreachable on this fake); got %+v",
			len(backend.execCalls), backend.execCalls)
	}
	kill := backend.execCalls[0]
	if kill.ContainerName != "agent-hello-agent" {
		t.Errorf("kill container = %q, want agent-hello-agent", kill.ContainerName)
	}
	killScript := strings.Join(kill.Command, " ")
	if !strings.Contains(killScript, "agent-runtime") || !strings.Contains(killScript, "pkill") {
		t.Errorf("kill command = %v, want it to pkill a prior agent-runtime instance", kill.Command)
	}

	// A second call (a later run against the same reused box) must kill
	// again — the fix is not a one-shot guard, it runs on every call.
	s.startServeMode("agent-hello-agent", "/etc/containarium/agent/runs/run-2")
	if len(backend.execCalls) != 2 {
		t.Fatalf("after a second call, execCalls = %d, want 2", len(backend.execCalls))
	}
}
