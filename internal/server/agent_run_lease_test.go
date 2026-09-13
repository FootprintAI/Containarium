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
		SeedDir: agentSeedDir,
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
	if w.calls() != 1 {
		t.Fatalf("wipe exec calls = %d, want 1", w.calls())
	}
	wantCmd := []string{"rm", "-f", agentSeedDir + "/token", agentSeedDir + "/gateway.env"}
	if strings.Join(w.cmds[0], " ") != strings.Join(wantCmd, " ") {
		t.Errorf("wipe cmd = %v, want %v", w.cmds[0], wantCmd)
	}
	if w.boxes[0] != "agent-hello-agent-container" {
		t.Errorf("wipe box = %q, want the lease's box", w.boxes[0])
	}
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
	if w.calls() != 1 {
		t.Errorf("files must still be wiped without a store; wipe calls = %d", w.calls())
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
		Revoked:   []string{"jti-platform"},
		Unrevoked: []string{"jti-gateway"},
		Wiped:     true,
		Errs:      []error{errors.New("runlease: revoke jti-gateway: boom")},
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
	if len(end.Errors) != 1 || !strings.Contains(end.Errors[0], "jti-gateway") {
		t.Errorf("end errors = %v, want the revoke failure recorded", end.Errors)
	}
	// Empty slices must serialize as [], not null: an operator reading the row
	// should see "nothing failed", not a missing field.
	clean := runLeaseEndPayload(lease, runExitReason, runlease.Outcome{Wiped: true})
	for _, want := range []string{`"unrevoked":[]`, `"errors":[]`, `"revoked":[]`} {
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
	return s, skill
}

// TestProvisionSkillBox_EndsPartialLeaseOnSeedFailure: a run whose seed exec
// fails after both credentials are minted must not leave live credentials
// behind. provisionSkillBox owns that cleanup, because RunAgentSkill's defer
// is only armed once provisioning has succeeded.
func TestProvisionSkillBox_EndsPartialLeaseOnSeedFailure(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill := newSkillBoxHarness(t, store)

	_, _, lease, err := s.provisionSkillBox(ctxAs("admin", true), skill, "", "", "{}", "run-partial")
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
