package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// queueFor queues a miner-signature finding from box, with no worker
// running. Every box uses the same subject, so all of one tenant's boxes
// share one finding, as miner-signature findings do in production.
func queueFor(t *testing.T, fx *responderFixture, sink *ActingSink, box string) responseJob {
	t.Helper()
	if _, err := sink.Upsert(context.Background(), &threatdetect.Finding{Rule: ruleMinerSignature,
		Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, TenantID: "tenant-a", Container: box, Subject: "name:xmrig"}); err != nil {
		t.Fatal(err)
	}
	select {
	case job := <-fx.r.queue:
		if job.f.Container != box {
			t.Fatalf("queued job is for %q, want %q", job.f.Container, box)
		}
		return job
	default:
		t.Fatal("nothing queued")
		return responseJob{}
	}
}

func openAction(fx *responderFixture, box string) (*threatdetect.SecurityAction, error) {
	return fx.actions.Open(context.Background(), box)
}

// TestQueuedResponse_SharedFindingReleaseIsPerContainer (#2766): two boxes of
// one tenant match the same signature and share one finding. A release is
// judged against the job's own container: releasing (or expiring) box A
// leaves box B's queued response to run, releasing box B skips it, and a
// resolve of the finding itself skips every box's job.
func TestQueuedResponse_SharedFindingReleaseIsPerContainer(t *testing.T) {
	cases := []struct {
		name string
		// run sets the scene and returns the jobs the worker then runs, in
		// order.
		run func(t *testing.T, fx *responderFixture, sink *ActingSink) []responseJob
		// applied: the boxes that must end with an open THROTTLE.
		applied []string
		// skipped: the substring each expected response-skipped audit row
		// carries, one entry per row.
		skipped []string
		// findingOpen: the shared finding's state after the jobs ran.
		findingOpen bool
		// responseApplied: the finding's response ends APPLIED (the queued
		// response ran and recorded itself).
		responseApplied bool
	}{
		{
			name: "operator release of A leaves B's queued response applied",
			run: func(t *testing.T, fx *responderFixture, sink *ActingSink) []responseJob {
				fx.r.runJob(context.Background(), queueFor(t, fx, sink, "box-a"))
				jobB := queueFor(t, fx, sink, "box-b")
				if _, _, err := fx.r.Release(context.Background(), "box-a"); err != nil {
					t.Fatal(err)
				}
				return []responseJob{jobB}
			},
			applied:         []string{"box-b"},
			findingOpen:     true,
			responseApplied: true,
		},
		{
			name: "TTL release of A leaves B's queued response applied",
			run: func(t *testing.T, fx *responderFixture, sink *ActingSink) []responseJob {
				fx.r.runJob(context.Background(), queueFor(t, fx, sink, "box-a"))
				jobB := queueFor(t, fx, sink, "box-b")
				if n := fx.r.SweepExpired(context.Background(), fx.clock.Add(2*time.Hour)); n != 1 {
					t.Fatalf("SweepExpired released %d, want 1", n)
				}
				return []responseJob{jobB}
			},
			applied:         []string{"box-b"},
			findingOpen:     true,
			responseApplied: true,
		},
		{
			name: "operator release of B skips B's queued response",
			run: func(t *testing.T, fx *responderFixture, sink *ActingSink) []responseJob {
				ctx := context.Background()
				fx.r.runJob(ctx, queueFor(t, fx, sink, "box-a"))
				fx.r.runJob(ctx, queueFor(t, fx, sink, "box-b"))
				jobB := queueFor(t, fx, sink, "box-b") // B's rule re-fires while throttled
				jobA := queueFor(t, fx, sink, "box-a") // and A's, so the finding stays open
				if _, _, err := fx.r.Release(ctx, "box-b"); err != nil {
					t.Fatal(err)
				}
				return []responseJob{jobB, jobA}
			},
			applied:     []string{"box-a"},
			skipped:     []string{"action on box-b released by operator"},
			findingOpen: true,
		},
		{
			name: "resolving the finding skips both boxes' queued responses",
			run: func(t *testing.T, fx *responderFixture, sink *ActingSink) []responseJob {
				jobA := queueFor(t, fx, sink, "box-a")
				jobB := queueFor(t, fx, sink, "box-b")
				if jobA.f.ID != jobB.f.ID {
					t.Fatalf("finding ids %d and %d: the boxes must share one finding", jobA.f.ID, jobB.f.ID)
				}
				if _, err := fx.findings.Resolve(context.Background(), jobA.f.ID); err != nil {
					t.Fatal(err)
				}
				return []responseJob{jobA, jobB}
			},
			skipped: []string{"no longer open", "no longer open"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fx, sink := queuedThrottle(t)
			jobs := tc.run(t, fx, sink)
			for _, job := range jobs {
				fx.r.runJob(ctx, job)
			}

			for _, box := range []string{"box-a", "box-b"} {
				row, err := openAction(fx, box)
				want := false
				for _, b := range tc.applied {
					want = want || b == box
				}
				switch {
				case want && (err != nil || row.Action != pb.ProcessAction_PROCESS_ACTION_THROTTLE):
					t.Errorf("%s: open action = %+v, %v; want THROTTLE", box, row, err)
				case !want && !errors.Is(err, threatdetect.ErrNoOpenAction):
					t.Errorf("%s: open action = %+v, %v; want none", box, row, err)
				}
			}
			d := auditDetails(fx.audit, "response-skipped")
			if len(d) != len(tc.skipped) {
				t.Fatalf("response-skipped audit = %v, want %d row(s)", d, len(tc.skipped))
			}
			for i, want := range tc.skipped {
				if !strings.Contains(d[i], want) {
					t.Errorf("response-skipped[%d] = %q, want it to contain %q", i, d[i], want)
				}
			}
			f, err := fx.findings.Get(ctx, jobs[0].f.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got := f.State == threatdetect.FindingStateOpen; got != tc.findingOpen {
				t.Fatalf("finding state = %s, want open=%t", f.State, tc.findingOpen)
			}
			if tc.responseApplied &&
				(f.Response == nil || f.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED) {
				t.Fatalf("response = %+v, want APPLIED for the box still acted on", f.Response)
			}
		})
	}
}

// TestRelease_SharedFindingResolvedWithLastBox: releasing box A while box B
// has a response queued keeps the shared finding open (audited as
// finding_kept_open=true); once B's response ran, releasing B resolves it.
func TestRelease_SharedFindingResolvedWithLastBox(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	fx.r.runJob(ctx, queueFor(t, fx, sink, "box-a"))
	jobB := queueFor(t, fx, sink, "box-b")
	if _, _, err := fx.r.Release(ctx, "box-a"); err != nil {
		t.Fatal(err)
	}
	if d := auditDetails(fx.audit, "release"); len(d) != 1 || !strings.Contains(d[0], "finding_kept_open=true") {
		t.Fatalf("release audit = %v, want finding_kept_open=true", d)
	}
	fx.r.runJob(ctx, jobB)
	f, _, err := fx.r.Release(ctx, "box-b")
	if err != nil {
		t.Fatal(err)
	}
	if f == nil || f.State != threatdetect.FindingStateResolved {
		t.Fatalf("finding after the last box's release = %+v, want resolved", f)
	}
	if d := auditDetails(fx.audit, "release"); len(d) != 2 || !strings.Contains(d[1], "finding_kept_open=false") {
		t.Fatalf("release audit = %v, want the second with finding_kept_open=false", d)
	}
}

// TestQueuedResponse_ReleaseBetweenReadAndLockSkipsKill pins the re-check
// under r.mu before the kill: a release or resolve that lands after the
// worker's unlocked read, but before it takes the lock, must still stop the
// kill. The afterQueuedRead seam lands it in exactly that window; without the
// locked re-check the process would be killed.
func TestQueuedResponse_ReleaseBetweenReadAndLockSkipsKill(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, fx *responderFixture, sink *ActingSink)
		land   func(t *testing.T, fx *responderFixture, job responseJob)
		reason string
	}{
		{
			name: "finding resolved",
			land: func(t *testing.T, fx *responderFixture, job responseJob) {
				if _, err := fx.findings.Resolve(context.Background(), job.f.ID); err != nil {
					t.Fatal(err)
				}
			},
			reason: "no longer open",
		},
		{
			name: "own container's action expired",
			setup: func(t *testing.T, fx *responderFixture, sink *ActingSink) {
				fx.r.runJob(context.Background(), queueFor(t, fx, sink, "box-a"))
			},
			land: func(t *testing.T, fx *responderFixture, _ responseJob) {
				if n := fx.r.SweepExpired(context.Background(), fx.clock.Add(2*time.Hour)); n != 1 {
					t.Fatalf("SweepExpired released %d, want 1", n)
				}
			},
			reason: "action on box-a released by ttl",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fx, sink := queuedThrottle(t)
			if tc.setup != nil {
				tc.setup(t, fx, sink)
			}
			fx.setKill(t, "", true)
			killer := &fakeKiller{}
			fx.r.SetProcessKiller(killer)
			job := queueSignature(t, fx, sink, 4242)
			landed := 0
			fx.r.afterQueuedRead = func() {
				landed++
				tc.land(t, fx, job)
			}

			fx.r.runJob(ctx, job)

			if landed != 1 {
				t.Fatalf("seam ran %d time(s), want 1 (the unlocked read must pass first)", landed)
			}
			if len(killer.calls) != 0 || len(auditDetails(fx.audit, "kill")) != 0 {
				t.Fatalf("killed %v after a %s landed before the locked re-check", killer.calls, tc.name)
			}
			if d := auditDetails(fx.audit, "response-skipped"); len(d) != 1 || !strings.Contains(d[0], tc.reason) {
				t.Fatalf("response-skipped audit = %v, want one containing %q", d, tc.reason)
			}
		})
	}
}

// flakyPolicyKV is a policy config store whose reads can be made to fail.
type flakyPolicyKV struct {
	mu   sync.Mutex
	m    map[string]string
	fail bool
}

func (k *flakyPolicyKV) Get(_ context.Context, key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return "", errors.New("config store unavailable")
	}
	v, ok := k.m[key]
	if !ok {
		return "", app.ErrDaemonConfigNotFound
	}
	return v, nil
}

func (k *flakyPolicyKV) Set(_ context.Context, key, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[key] = value
	return nil
}

// TestProcessKilledRecorded_PolicyReadFailsAfterKill (#2766): the kill ran
// and was audited, then the policy read for the policy action failed. The
// policy action is skipped, but the finding must still say the process was
// killed.
func TestProcessKilledRecorded_PolicyReadFailsAfterKill(t *testing.T) {
	ctx := context.Background()
	fx := newResponderFixture(t, false)
	kv := &flakyPolicyKV{m: map[string]string{}}
	fx.policies = threatdetect.NewProcessPolicyStore(kv)
	fx.r.policies = fx.policies
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	fx.setKill(t, "", true)
	fx.r.SetProcessKiller(killerFunc(func(string, uint32) error {
		kv.mu.Lock()
		kv.fail = true // the store goes away right after the kill
		kv.mu.Unlock()
		return nil
	}))

	out := fx.fireSignature(t, "box-a", 4242)

	if len(auditDetails(fx.audit, "kill")) != 1 {
		t.Fatalf("kill audits = %v, want one", auditDetails(fx.audit, "kill"))
	}
	if out == nil || out.Response == nil || !out.Response.ProcessKilled {
		t.Fatalf("returned finding = %+v, want process_killed=true", out)
	}
	f, _ := fx.findings.Get(ctx, out.ID)
	if f.Response == nil || !f.Response.ProcessKilled {
		t.Fatalf("stored response = %+v, want process_killed=true", f.Response)
	}
	if setCPUCalls(fx) != 0 {
		t.Fatal("applied a policy action with an unreadable policy")
	}
}

// TestProcessKilledRecorded_SurvivesRelease (#2766): a kill recorded while
// another action stood on the box (killed_pid is not on that row) must not
// be wiped by the release that later rewrites the finding's response.
func TestProcessKilledRecorded_SurvivesRelease(t *testing.T) {
	ctx := context.Background()
	fx := newResponderFixture(t, false)
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	fx.r.SetProcessKiller(&fakeKiller{})
	fx.fireSignature(t, "box-a", 100) // throttled, kill off: killed_pid 0
	fx.setKill(t, "", true)
	f := fx.fireSignature(t, "box-a", 101) // throttle stands, the kill is recorded
	if f == nil || f.Response == nil || !f.Response.ProcessKilled {
		t.Fatalf("after the kill: %+v, want process_killed=true", f)
	}

	released, _, err := fx.r.Release(ctx, "box-a")
	if err != nil {
		t.Fatal(err)
	}
	if released == nil || released.Response == nil || !released.Response.ProcessKilled {
		t.Fatalf("after release: %+v, want process_killed still true", released)
	}
}

// TestRelease_SharedFindingHeldByAppliedAction (#2772 review 1): box-a and
// box-b are both throttled by one finding and both jobs already ran, so
// nothing is queued. Release(box-a) must still leave the finding open, since
// box-b's action is open on it (read from the store, not from the queue);
// Release(box-b) then resolves it as the last box.
func TestRelease_SharedFindingHeldByAppliedAction(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	fx.r.runJob(ctx, queueFor(t, fx, sink, "box-a"))
	jobB := queueFor(t, fx, sink, "box-b")
	fx.r.runJob(ctx, jobB)
	if fx.r.pendingElsewhere(jobB.f.ID, "") {
		t.Fatal("a job is still pending: this test must rely on the store, not the queue")
	}

	f, kept, err := fx.r.Release(ctx, "box-a")
	if err != nil {
		t.Fatal(err)
	}
	if !kept || f == nil || f.State != threatdetect.FindingStateOpen {
		t.Fatalf("Release(box-a) = kept_open=%t, finding %+v; want kept open while box-b's throttle stands", kept, f)
	}
	if row, err := openAction(fx, "box-b"); err != nil || row.Action != pb.ProcessAction_PROCESS_ACTION_THROTTLE {
		t.Fatalf("box-b's action after box-a's release = %+v, %v; want THROTTLE still open", row, err)
	}
	if d := auditDetails(fx.audit, "release"); len(d) != 1 || !strings.Contains(d[0], "finding_kept_open=true") {
		t.Fatalf("release audit = %v, want finding_kept_open=true", d)
	}

	f, kept, err = fx.r.Release(ctx, "box-b")
	if err != nil {
		t.Fatal(err)
	}
	if kept || f == nil || f.State != threatdetect.FindingStateResolved {
		t.Fatalf("Release(box-b) = kept_open=%t, finding %+v; want resolved: it was the last box", kept, f)
	}
}

// TestQueuedResponse_ReleaseOfAnotherFindingDoesNotSkip (#2772 review 2):
// box-a is throttled for a mining-behavior finding; a signature finding with
// kill_process then fires on box-a and queues; the operator releases the
// mining-behavior throttle after that. The release belongs to the other
// finding, so the signature job must still run: the miner is killed and the
// signature finding gets its own action.
func TestQueuedResponse_ReleaseOfAnotherFindingDoesNotSkip(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	first := fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH) // sync: throttled now
	if row, err := openAction(fx, "box-a"); err != nil || row.FindingID != first.ID {
		t.Fatalf("open action after the mining-behavior finding = %+v, %v", row, err)
	}
	fx.setKill(t, "", true)
	killer := &fakeKiller{}
	fx.r.SetProcessKiller(killer)
	job := queueSignature(t, fx, sink, 4242)
	if job.f.ID == first.ID {
		t.Fatal("the signature finding must be a finding of its own")
	}
	fx.clock = fx.clock.Add(time.Minute)
	if _, _, err := fx.r.Release(ctx, "box-a"); err != nil { // releases the OTHER finding's throttle, after the job was queued
		t.Fatal(err)
	}

	fx.r.runJob(ctx, job)

	if len(killer.calls) != 1 || len(auditDetails(fx.audit, "kill")) != 1 {
		t.Fatalf("kills = %v, kill audits = %v; want one of each: the release was of another finding's action", killer.calls, auditDetails(fx.audit, "kill"))
	}
	if d := auditDetails(fx.audit, "response-skipped"); len(d) != 0 {
		t.Fatalf("response-skipped audit = %v, want none", d)
	}
	row, err := openAction(fx, "box-a")
	if err != nil || row.FindingID != job.f.ID || row.Action != pb.ProcessAction_PROCESS_ACTION_THROTTLE || row.KilledPID != 4242 {
		t.Fatalf("open action after the job = %+v, %v; want the signature finding's own THROTTLE with killed_pid 4242", row, err)
	}
	f, _ := fx.findings.Get(ctx, job.f.ID)
	if f.State != threatdetect.FindingStateOpen || f.Response == nil || f.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED || !f.Response.ProcessKilled {
		t.Fatalf("signature finding = state %s response %+v, want open, APPLIED, process_killed", f.State, f.Response)
	}
	if g, _ := fx.findings.Get(ctx, first.ID); g.State != threatdetect.FindingStateResolved {
		t.Fatalf("mining-behavior finding = %s, want resolved by its release", g.State)
	}
}

// releasedWhileQueued throttles box-a, queues box-b's response for the
// shared finding and releases box-a: the finding is kept open for box-b's
// job, which is returned.
func releasedWhileQueued(t *testing.T, fx *responderFixture, sink *ActingSink) responseJob {
	t.Helper()
	ctx := context.Background()
	fx.r.runJob(ctx, queueFor(t, fx, sink, "box-a"))
	jobB := queueFor(t, fx, sink, "box-b")
	_, kept, err := fx.r.Release(ctx, "box-a")
	if err != nil {
		t.Fatal(err)
	}
	if !kept {
		t.Fatal("Release(box-a) resolved the finding although box-b's response is queued")
	}
	return jobB
}

// TestQueuedResponse_LastJobWithoutActionResolvesReleasedFinding (#2772
// review 3): Release(box-a) kept the shared finding open for box-b's queued
// job; that job then ends without an action on box-b. Nothing is left to
// release, so the worker must resolve the finding itself, whichever way the
// job ended, rather than leave it open with no response to release.
func TestQueuedResponse_LastJobWithoutActionResolvesReleasedFinding(t *testing.T) {
	cases := []struct {
		name string
		// arrange sets the scene and returns box-b's job, with whatever makes
		// it end without an action in place.
		arrange func(t *testing.T, fx *responderFixture, sink *ActingSink) responseJob
		// skipped: box-b's job is itself skipped (the response-skipped audit
		// row contains this) rather than run.
		skipped string
	}{
		{
			name: "ALERT override on box-b",
			arrange: func(t *testing.T, fx *responderFixture, sink *ActingSink) responseJob {
				job := releasedWhileQueued(t, fx, sink)
				if err := fx.policies.SetOverride(context.Background(), "box-b", &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_ALERT}); err != nil {
					t.Fatal(err)
				}
				return job
			},
		},
		{
			name: "policy read error",
			arrange: func(t *testing.T, fx *responderFixture, sink *ActingSink) responseJob {
				kv := &flakyPolicyKV{m: map[string]string{}}
				fx.policies = threatdetect.NewProcessPolicyStore(kv)
				fx.r.policies = fx.policies
				fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
				job := releasedWhileQueued(t, fx, sink)
				kv.mu.Lock()
				kv.fail = true
				kv.mu.Unlock()
				return job
			},
		},
		{
			name: "degraded backend",
			arrange: func(t *testing.T, fx *responderFixture, sink *ActingSink) responseJob {
				job := releasedWhileQueued(t, fx, sink)
				fx.r.degraded = true
				return job
			},
		},
		{
			name: "failed apply on box-b",
			arrange: func(t *testing.T, fx *responderFixture, sink *ActingSink) responseJob {
				job := releasedWhileQueued(t, fx, sink)
				fx.act.fail = errors.New("incus: boom")
				return job
			},
		},
		{
			name:    "box-b's job skipped: box-b released after it was queued",
			skipped: "released by operator",
			arrange: func(t *testing.T, fx *responderFixture, sink *ActingSink) responseJob {
				ctx := context.Background()
				fx.r.runJob(ctx, queueFor(t, fx, sink, "box-a"))
				fx.r.runJob(ctx, queueFor(t, fx, sink, "box-b"))
				jobB := queueFor(t, fx, sink, "box-b") // re-fires while throttled
				fx.clock = fx.clock.Add(time.Minute)
				if _, kept, err := fx.r.Release(ctx, "box-b"); err != nil || !kept {
					t.Fatalf("Release(box-b) = kept_open=%t, %v; want kept open: box-a's throttle stands", kept, err)
				}
				if _, kept, err := fx.r.Release(ctx, "box-a"); err != nil || !kept {
					t.Fatalf("Release(box-a) = kept_open=%t, %v; want kept open: box-b's response is queued", kept, err)
				}
				return jobB
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fx, sink := queuedThrottle(t)
			job := tc.arrange(t, fx, sink)

			fx.r.runJob(ctx, job)

			for _, box := range []string{"box-a", "box-b"} {
				if row, err := openAction(fx, box); !errors.Is(err, threatdetect.ErrNoOpenAction) {
					t.Errorf("%s: open action = %+v, %v; want none", box, row, err)
				}
			}
			f, err := fx.findings.Get(ctx, job.f.ID)
			if err != nil {
				t.Fatal(err)
			}
			if f.State != threatdetect.FindingStateResolved {
				t.Fatalf("finding = state %s response %+v; want resolved: nothing is left to release", f.State, f.Response)
			}
			if d := auditDetails(fx.audit, "resolve"); len(d) != 1 || !strings.Contains(d[0], fmt.Sprintf("finding=%d", job.f.ID)) {
				t.Fatalf("resolve audit = %v, want one for finding %d", d, job.f.ID)
			}
			d := auditDetails(fx.audit, "response-skipped")
			switch {
			case tc.skipped == "" && len(d) != 0:
				t.Fatalf("response-skipped audit = %v, want none", d)
			case tc.skipped != "" && (len(d) != 1 || !strings.Contains(d[0], tc.skipped)):
				t.Fatalf("response-skipped audit = %v, want one containing %q", d, tc.skipped)
			}
			if fx.r.pendingElsewhere(job.f.ID, "") {
				t.Fatal("a job is still counted as pending after it ran")
			}
		})
	}
}

// TestQueuedResponse_AlertOnlyFindingStaysOpen is the control for the test
// above: a finding no operator released is not resolved when its job ends
// without an action. An alert-only finding stays open for the operator, as
// it always has.
func TestQueuedResponse_AlertOnlyFindingStaysOpen(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	if err := fx.policies.SetOverride(ctx, "box-a", &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_ALERT}); err != nil {
		t.Fatal(err)
	}
	job := queueFor(t, fx, sink, "box-a")
	fx.r.runJob(ctx, job)
	f, _ := fx.findings.Get(ctx, job.f.ID)
	if f.State != threatdetect.FindingStateOpen || f.Response == nil || f.Response.Action != pb.ProcessAction_PROCESS_ACTION_ALERT {
		t.Fatalf("finding = state %s response %+v; want open with an ALERT response", f.State, f.Response)
	}
	if d := auditDetails(fx.audit, "resolve"); len(d) != 0 {
		t.Fatalf("resolve audit = %v, want none: no operator released this finding", d)
	}
}

// flakyActions is an ActionStore whose ListByFinding (the worker's scoped
// release lookup for a queued job) fails the first `failures` times, as a
// Postgres hiccup would make it.
type flakyActions struct {
	threatdetect.ActionStore
	mu       sync.Mutex
	failures int
}

func (s *flakyActions) ListByFinding(ctx context.Context, id int64) ([]*threatdetect.SecurityAction, error) {
	s.mu.Lock()
	fail := s.failures > 0
	if fail {
		s.failures--
	}
	s.mu.Unlock()
	if fail {
		return nil, errors.New("pg: connection refused")
	}
	return s.ActionStore.ListByFinding(ctx, id)
}

// flakyFindings is a findingLifecycle whose Get fails the first `failures`
// times.
type flakyFindings struct {
	findingLifecycle
	mu       sync.Mutex
	failures int
}

func (s *flakyFindings) Get(ctx context.Context, id int64) (*threatdetect.Finding, error) {
	s.mu.Lock()
	fail := s.failures > 0
	if fail {
		s.failures--
	}
	s.mu.Unlock()
	if fail {
		return nil, errors.New("pg: connection refused")
	}
	return s.findingLifecycle.Get(ctx, id)
}

// TestQueuedResponse_StoreReadErrorDoesNotSkip (#2772 review 5): a store
// read that fails while the worker checks a queued job is neither a release
// nor a resolve. The job must go on: the locked read tries once more, and if
// the store is still down the job acts on its queued copy. A Postgres hiccup
// never costs the kill, which nothing would re-fire (the process does not
// exec again).
func TestQueuedResponse_StoreReadErrorDoesNotSkip(t *testing.T) {
	const forever = 1 << 20
	cases := []struct {
		name     string
		wire     func(fx *responderFixture, failures int)
		failures int
	}{
		{"action lookup fails once", wireFlakyActions, 1},
		{"action lookup fails every time", wireFlakyActions, forever},
		{"finding read fails once", wireFlakyFindings, 1},
		{"finding read fails every time", wireFlakyFindings, forever},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fx, sink := queuedThrottle(t)
			fx.setKill(t, "", true)
			killer := &fakeKiller{}
			fx.r.SetProcessKiller(killer)
			job := queueSignature(t, fx, sink, 4242)
			tc.wire(fx, tc.failures) // after the queueing write, which is not under test

			fx.r.runJob(ctx, job)

			if len(killer.calls) != 1 || len(auditDetails(fx.audit, "kill")) != 1 {
				t.Fatalf("kills = %v, kill audits = %v; want one of each: a read error is not a release", killer.calls, auditDetails(fx.audit, "kill"))
			}
			if d := auditDetails(fx.audit, "response-skipped"); len(d) != 0 {
				t.Fatalf("response-skipped audit = %v, want none", d)
			}
			row, err := openAction(fx, "box-a")
			if err != nil || row.Action != pb.ProcessAction_PROCESS_ACTION_THROTTLE || row.KilledPID != 4242 {
				t.Fatalf("open action = %+v, %v; want THROTTLE with killed_pid 4242", row, err)
			}
		})
	}
}

func wireFlakyActions(fx *responderFixture, failures int) {
	fx.r.actions = &flakyActions{ActionStore: fx.actions, failures: failures}
}

func wireFlakyFindings(fx *responderFixture, failures int) {
	fx.r.findings = &flakyFindings{findingLifecycle: fx.findings, failures: failures}
}

// TestProcessKilled_ReleaseRecordIsPerBox (#2772 review 6): box-b's kill
// must not make box-a's release record say box-a's process was killed. The
// record box-a's release writes carries only box-a's own killed_pid (none);
// the finding keeps box-b's kill on record because the store keeps
// process_killed once set.
func TestProcessKilled_ReleaseRecordIsPerBox(t *testing.T) {
	ctx := context.Background()
	fx := newResponderFixture(t, false)
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	fx.r.SetProcessKiller(&fakeKiller{})
	fx.fireSignature(t, "box-a", 100) // kill off: throttled, nothing killed
	fx.setKill(t, "", true)
	f := fx.fireSignature(t, "box-b", 200) // the same finding: throttled, pid 200 killed
	if f == nil || f.Response == nil || !f.Response.ProcessKilled {
		t.Fatalf("after box-b's kill: %+v, want process_killed=true", f)
	}
	if rowA, err := openAction(fx, "box-a"); err != nil || rowA.KilledPID != 0 {
		t.Fatalf("box-a's row = %+v, %v; want killed_pid 0", rowA, err)
	}
	if rowB, err := openAction(fx, "box-b"); err != nil || rowB.KilledPID != 200 || rowB.FindingID != f.ID {
		t.Fatalf("box-b's row = %+v, %v; want killed_pid 200 on finding %d", rowB, err, f.ID)
	}

	released, kept, err := fx.r.Release(ctx, "box-a")
	if err != nil {
		t.Fatal(err)
	}
	if !kept {
		t.Fatal("box-b's throttle still stands: the finding must be kept open")
	}
	if w := fx.findings.lastWrite(); w.State != pb.ResponseState_RESPONSE_STATE_RELEASED || w.ProcessKilled {
		t.Fatalf("box-a's release record = %+v, want RELEASED with process_killed=false: box-a killed nothing", w)
	}
	if released == nil || released.Response == nil || !released.Response.ProcessKilled {
		t.Fatalf("finding after box-a's release = %+v, want process_killed kept: box-b's kill is on record", released)
	}

	if _, _, err := fx.r.Release(ctx, "box-b"); err != nil {
		t.Fatal(err)
	}
	if w := fx.findings.lastWrite(); w.State != pb.ResponseState_RESPONSE_STATE_RELEASED || !w.ProcessKilled {
		t.Fatalf("box-b's release record = %+v, want RELEASED with process_killed=true: its own row has killed_pid 200", w)
	}
}
