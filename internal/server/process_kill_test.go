package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeProc writes /proc/<pid>/cgroup files under a temp root.
func fakeProc(t *testing.T, cgroups map[int]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, path := range cgroups {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::"+path+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

type fakePIDHandle struct {
	killed *[]int
	pid    int
	err    error
}

func (h fakePIDHandle) Kill() error {
	if h.err != nil {
		return h.err
	}
	*h.killed = append(*h.killed, h.pid)
	return nil
}
func (fakePIDHandle) Close() error { return nil }

// TestHostProcessKiller_CgroupRecheck: the kill reaches a pid only while it
// is still under the container's cgroup; a reused pid (another box, the
// host), the container's init, and a pid that is gone are all refused
// without a signal.
func TestHostProcessKiller_CgroupRecheck(t *testing.T) {
	const initPID = 100
	proc := fakeProc(t, map[int]string{
		initPID: "/lxc.payload.box-a/init.scope",
		4242:    "/lxc.payload.box-a/system.slice/ssh.service",
		5000:    "/lxc.payload.box-b/user.slice",
		6000:    "/system.slice/cron.service",
	})
	tests := []struct {
		name    string
		pid     uint32
		openErr error
		killErr error
		wantErr error // nil = killed
	}{
		{name: "same container is killed", pid: 4242},
		{name: "pid now in another box", pid: 5000, wantErr: errKillPIDReused},
		{name: "pid now a host process", pid: 6000, wantErr: errKillPIDReused},
		{name: "container init is never killed", pid: initPID, wantErr: errKillContainerInit},
		{name: "pid vanished before the re-check", pid: 7777, wantErr: errKillProcessGone},
		{name: "pid exited before the open", pid: 4242, openErr: errKillProcessGone, wantErr: errKillProcessGone},
		{name: "exited between check and signal", pid: 4242, killErr: errKillProcessGone, wantErr: errKillProcessGone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var killed []int
			k := &hostProcessKiller{
				procRoot: proc,
				initPID:  func(string) (int64, error) { return initPID, nil },
				open: func(pid int) (pidHandle, error) {
					if tt.openErr != nil {
						return nil, tt.openErr
					}
					return fakePIDHandle{killed: &killed, pid: pid, err: tt.killErr}, nil
				},
			}
			err := k.KillInContainer("box-a", tt.pid)
			if tt.wantErr == nil {
				if err != nil || len(killed) != 1 || killed[0] != int(tt.pid) {
					t.Fatalf("err=%v killed=%v, want pid %d killed", err, killed, tt.pid)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if len(killed) != 0 {
				t.Fatalf("signalled %v on a refused kill", killed)
			}
		})
	}
}

func TestHostProcessKiller_RefusesLowPIDsAndStoppedBox(t *testing.T) {
	k := &hostProcessKiller{procRoot: t.TempDir(),
		initPID: func(string) (int64, error) { return 0, nil },
		open:    func(int) (pidHandle, error) { t.Fatal("must not open"); return nil, nil }}
	for _, pid := range []uint32{0, 1} {
		if err := k.KillInContainer("box-a", pid); err == nil {
			t.Errorf("pid %d: kill not refused", pid)
		}
	}
	if err := k.KillInContainer("box-a", 4242); !errors.Is(err, errKillProcessGone) {
		t.Errorf("stopped box: err = %v, want errKillProcessGone", err)
	}
	k.initPID = func(string) (int64, error) { return 0, errors.New("incus down") }
	if err := k.KillInContainer("box-a", 4242); err == nil {
		t.Error("init pid lookup failure must refuse the kill")
	}
}

// fakeKiller records KillInContainer calls; err scripts a refusal.
type fakeKiller struct {
	calls []string
	err   error
}

func (k *fakeKiller) KillInContainer(container string, pid uint32) error {
	k.calls = append(k.calls, fmt.Sprintf("%s:%d", container, pid))
	return k.err
}

func (fx *responderFixture) fireSignature(t *testing.T, container string, pid uint32) *threatdetect.Finding {
	t.Helper()
	out, err := NewActingSink(fx.findings, fx.r).Upsert(context.Background(), &threatdetect.Finding{
		Rule: ruleMinerSignature, Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, TenantID: "tenant-a",
		Container: container, Subject: "name:xmrig",
		Evidence: threatdetect.Evidence{Execs: []threatdetect.ExecEvidence{{PID: pid, Comm: "xmrig", Filename: "/tmp/xmrig",
			Argv: "./xmrig --donate-level 1", Matched: "name:xmrig"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (fx *responderFixture) setKill(t *testing.T, container string, on bool) {
	t.Helper()
	// Keep whatever is stored at that level (e.g. a THROTTLE default) and
	// only set kill_process, as the server's field-by-field merge does.
	ctx := context.Background()
	var p *pb.ProcessPolicy
	var err error
	if container == "" {
		p, err = fx.policies.Default(ctx)
	} else {
		p, err = fx.policies.Override(ctx, container)
	}
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		p = &pb.ProcessPolicy{}
	}
	p.KillProcess = &on
	if container == "" {
		err = fx.policies.SetDefault(ctx, p)
	} else {
		err = fx.policies.SetOverride(ctx, container, p)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func auditDetails(a *fakeAudit, action string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.entries {
		if e.ResourceType == actionAuditResourceType && e.Action == action {
			out = append(out, e.Detail)
		}
	}
	return out
}

// TestProcessResponder_KillProcess: kill_process off (the default) never
// signals; on, the matched pid is killed, audited by pid, flagged on the
// finding, and the box's policy action still applies.
func TestProcessResponder_KillProcess(t *testing.T) {
	t.Run("default off never kills", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{}
		fx.r.SetProcessKiller(k)
		f := fx.fireSignature(t, "box-a", 4242)
		if len(k.calls) != 0 || f.Response.ProcessKilled {
			t.Fatalf("kills=%v killed=%v, want none", k.calls, f.Response.ProcessKilled)
		}
	})
	t.Run("on with ALERT kills and audits the pid", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{}
		fx.r.SetProcessKiller(k)
		fx.setKill(t, "", true)
		f := fx.fireSignature(t, "box-a", 4242)
		if len(k.calls) != 1 || k.calls[0] != "box-a:4242" {
			t.Fatalf("kills = %v", k.calls)
		}
		if f.Response == nil || !f.Response.ProcessKilled || f.Response.Action != pb.ProcessAction_PROCESS_ACTION_ALERT {
			t.Fatalf("response = %+v, want ALERT with process_killed", f.Response)
		}
		if f.Response.KilledPID != 4242 {
			t.Fatalf("killed_pid = %d, want 4242 (#2775: the webhook names it)", f.Response.KilledPID)
		}
		d := auditDetails(fx.audit, "kill")
		if len(d) != 1 || !strings.Contains(d[0], "pid=4242") || !strings.Contains(d[0], `matched="name:xmrig"`) {
			t.Fatalf("kill audit = %v", d)
		}
	})
	t.Run("on with THROTTLE kills and still throttles", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{}
		fx.r.SetProcessKiller(k)
		fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
		fx.setKill(t, "", true)
		f := fx.fireSignature(t, "box-a", 4242)
		if len(k.calls) != 1 || f.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED || !f.Response.ProcessKilled {
			t.Fatalf("kills=%v response=%+v", k.calls, f.Response)
		}
		if f.Response.KilledPID != 4242 {
			t.Fatalf("killed_pid = %d, want 4242", f.Response.KilledPID)
		}
		row, err := fx.actions.Open(context.Background(), "box-a")
		if err != nil || row.KilledPID != 4242 || row.Action != pb.ProcessAction_PROCESS_ACTION_THROTTLE {
			t.Fatalf("action row = %+v, %v; want THROTTLE with killed_pid 4242", row, err)
		}
		// A second miner exec while the throttle is open: killed too, no
		// second action.
		f = fx.fireSignature(t, "box-a", 5151)
		if len(k.calls) != 2 || k.calls[1] != "box-a:5151" || !f.Response.ProcessKilled {
			t.Fatalf("second exec: kills=%v response=%+v", k.calls, f.Response)
		}
	})
	t.Run("container override false beats backend true", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{}
		fx.r.SetProcessKiller(k)
		fx.setKill(t, "", true)
		fx.setKill(t, "box-a", false)
		fx.fireSignature(t, "box-a", 4242)
		if len(k.calls) != 0 {
			t.Fatalf("kills = %v, want none", k.calls)
		}
	})
	t.Run("refused kill is audited as skipped, finding not flagged", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{err: fmt.Errorf("pid 4242: %w", errKillPIDReused)}
		fx.r.SetProcessKiller(k)
		fx.setKill(t, "", true)
		f := fx.fireSignature(t, "box-a", 4242)
		if f.Response == nil || f.Response.ProcessKilled {
			t.Fatalf("response = %+v, want not killed", f.Response)
		}
		if f.Response.KillSkipReason != pb.KillSkipReason_KILL_SKIP_REASON_PID_REUSED || f.Response.KilledPID != 0 {
			t.Fatalf("kill_skip_reason = %s killed_pid = %d, want PID_REUSED and no pid (#2775)", f.Response.KillSkipReason, f.Response.KilledPID)
		}
		d := auditDetails(fx.audit, "kill-skipped")
		if len(d) != 1 || !strings.Contains(d[0], "pid reused") || len(auditDetails(fx.audit, "kill")) != 0 {
			t.Fatalf("audit kill-skipped=%v", d)
		}
	})
	t.Run("mining-behavior never kills", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{}
		fx.r.SetProcessKiller(k)
		fx.setKill(t, "", true)
		fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
		if len(k.calls) != 0 {
			t.Fatalf("kills = %v", k.calls)
		}
	})
	t.Run("degraded backend never kills", func(t *testing.T) {
		fx := newResponderFixture(t, true)
		k := &fakeKiller{}
		fx.r.SetProcessKiller(k)
		fx.setKill(t, "", true)
		fx.fireSignature(t, "box-a", 4242)
		if len(k.calls) != 0 {
			t.Fatalf("kills = %v", k.calls)
		}
	})
}

func TestHashProcExe(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "4242")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "exe"), []byte("hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum, err := hashProcExe(root, 4242, 1<<20, time.Second)
	if err != nil || sum != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("sum=%q err=%v", sum, err)
	}
	if _, err := hashProcExe(root, 4242, 3, time.Second); !errors.Is(err, errExecHashTooLarge) {
		t.Fatalf("size cap: err = %v", err)
	}
	if _, err := hashProcExe(root, 9999, 1<<20, time.Second); err == nil {
		t.Fatal("missing process hashed")
	}

	// The worker redelivers with SHA256 set; a gone process is dropped.
	var got []threatdetect.ExecEvent
	h := newExecHasher(func(ev threatdetect.ExecEvent) { got = append(got, ev) })
	h.procRoot = root
	h.process(threatdetect.ExecEvent{PID: 4242, Container: "box-a"})
	h.process(threatdetect.ExecEvent{PID: 9999})
	if len(got) != 1 || got[0].SHA256 != sum || got[0].Container != "box-a" {
		t.Fatalf("redelivered %+v", got)
	}
	for i := 0; i < execHashQueue+5; i++ {
		h.Request(threatdetect.ExecEvent{PID: 1})
	}
	if h.dropped.Load() != 5 {
		t.Fatalf("dropped = %d, want 5 (Request must never block)", h.dropped.Load())
	}
}

// #2775 review: the kill facts a webhook post carries stay true across
// respawns, a second exec while an action is open, and a release.
func TestProcessResponder_KillFactsAcrossRespawns(t *testing.T) {
	ctx := context.Background()
	stored := func(t *testing.T, fx *responderFixture, id int64) *threatdetect.FindingResponse {
		t.Helper()
		g, err := fx.findings.Get(ctx, id)
		if err != nil || g.Response == nil {
			t.Fatalf("get finding %d: %v %+v", id, err, g)
		}
		return g.Response
	}
	t.Run("a second distinct skip under ALERT is written, the same kind is not", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{err: fmt.Errorf("pid 1: %w", errKillPIDReused)}
		fx.r.SetProcessKiller(k)
		fx.setKill(t, "", true)
		f := fx.fireSignature(t, "box-a", 1)
		if got := stored(t, fx, f.ID).KillSkipReason; got != pb.KillSkipReason_KILL_SKIP_REASON_PID_REUSED {
			t.Fatalf("first skip = %s", got)
		}
		k.err = fmt.Errorf("pid 2: %w", errKillProcessGone)
		fx.fireSignature(t, "box-a", 2)
		if got := stored(t, fx, f.ID).KillSkipReason; got != pb.KillSkipReason_KILL_SKIP_REASON_PROCESS_GONE {
			t.Fatalf("second, different skip = %s, want PROCESS_GONE", got)
		}
	})
	t.Run("a skip while an action is open is recorded", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{}
		fx.r.SetProcessKiller(k)
		fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
		fx.setKill(t, "", true)
		f := fx.fireSignature(t, "box-a", 1)
		k.err = fmt.Errorf("pid 2: %w", errKillContainerInit)
		fx.fireSignature(t, "box-a", 2)
		r := stored(t, fx, f.ID)
		if r.KillSkipReason != pb.KillSkipReason_KILL_SKIP_REASON_CONTAINER_INIT || r.State != pb.ResponseState_RESPONSE_STATE_APPLIED || r.KilledPID != 1 {
			t.Fatalf("response = %+v, want APPLIED, pid 1 kept, skip CONTAINER_INIT", r)
		}
	})
	t.Run("a release after later kills names the latest pid and the count", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{}
		fx.r.SetProcessKiller(k)
		fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
		fx.setKill(t, "", true)
		f := fx.fireSignature(t, "box-a", 1)
		fx.fireSignature(t, "box-a", 2)
		fx.fireSignature(t, "box-a", 3)
		if r := stored(t, fx, f.ID); r.KilledPID != 3 || r.Kills != 3 {
			t.Fatalf("before release: pid=%d kills=%d, want 3 and 3", r.KilledPID, r.Kills)
		}
		if _, _, err := fx.r.Release(ctx, "box-a"); err != nil {
			t.Fatal(err)
		}
		r := stored(t, fx, f.ID)
		if r.State != pb.ResponseState_RESPONSE_STATE_RELEASED || !r.ProcessKilled || r.KilledPID != 3 || r.Kills != 3 {
			t.Fatalf("released response = %+v, want RELEASED with pid 3, kills 3", r)
		}
	})
}

// #2775 x #2766: two boxes of a tenant share one finding; each has a kill
// recorded. Releasing either box writes the finding's current kill facts (the
// latest pid, the count), never a pid of 0 and never the released box's first
// pid. The other box is still throttled, so the finding keeps showing its
// APPLIED record with the same kill facts (#2820), and the release record
// (what the webhook gets) names the released box.
func TestProcessResponder_SharedFindingReleaseCarriesCurrentKill(t *testing.T) {
	ctx := context.Background()
	for _, released := range []string{"box-a", "box-b"} {
		t.Run("release "+released, func(t *testing.T) {
			fx := newResponderFixture(t, false)
			fx.r.SetProcessKiller(&fakeKiller{})
			fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
			fx.setKill(t, "", true)
			f := fx.fireSignature(t, "box-a", 11)
			g := fx.fireSignature(t, "box-b", 22)
			if f.ID != g.ID {
				t.Fatalf("finding ids %d and %d: the boxes must share one finding", f.ID, g.ID)
			}
			if _, _, err := fx.r.Release(ctx, released); err != nil {
				t.Fatal(err)
			}
			cur, err := fx.findings.Get(ctx, f.ID)
			if err != nil || cur.Response == nil {
				t.Fatalf("get: %v", err)
			}
			other := map[string]string{"box-a": "box-b", "box-b": "box-a"}[released]
			r := cur.Response
			if r.State != pb.ResponseState_RESPONSE_STATE_APPLIED || r.Container != other || !r.ProcessKilled || r.KilledPID != 22 || r.Kills != 2 {
				t.Fatalf("response after releasing %s = %+v, want %s's APPLIED, killed, pid 22, kills 2", released, r, other)
			}
			w := fx.findings.lastWrite()
			if w.State != pb.ResponseState_RESPONSE_STATE_RELEASED || w.Container != released {
				t.Fatalf("release record = %+v, want RELEASED on %s", w, released)
			}
			if w.KeepKillOf(cur.Response); !w.ProcessKilled || w.KilledPID != 22 || w.Kills != 2 {
				t.Fatalf("release record as delivered = %+v, want killed, pid 22, kills 2", w)
			}
		})
	}
}

// #2772 x #2775: box-b killed nothing; releasing it must not blank or
// duplicate box-a's kill on the shared finding.
func TestProcessResponder_SharedFindingReleaseOfNonKillerKeepsKill(t *testing.T) {
	ctx := context.Background()
	fx := newResponderFixture(t, false)
	fx.r.SetProcessKiller(&fakeKiller{})
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	fx.setKill(t, "", true)
	f := fx.fireSignature(t, "box-a", 11) // killed on box-a
	fx.setKill(t, "", false)
	fx.fireSignature(t, "box-b", 22) // throttled, nothing killed
	if _, _, err := fx.r.Release(ctx, "box-b"); err != nil {
		t.Fatal(err)
	}
	if w := fx.findings.lastWrite(); w.ProcessKilled || w.KilledPID != 0 {
		t.Fatalf("box-b's release record = %+v, want no kill of its own", w)
	}
	cur, err := fx.findings.Get(ctx, f.ID)
	if err != nil || cur.Response == nil {
		t.Fatalf("get: %v", err)
	}
	if r := cur.Response; !r.ProcessKilled || r.KilledPID != 11 || r.Kills != 1 {
		t.Fatalf("finding after box-b's release = %+v, want box-a's kill whole: pid 11, kills 1", r)
	}
}

// #2775 review: a re-fire that adds nothing to the kill facts on record is
// not rewritten. Every SetResponse on the real stores emits the finding and
// hands it to the webhook notifier, so an unchanged write is a Postgres
// UPDATE plus a webhook attempt for nothing; the fake records every write.
func TestProcessResponder_RecordKillWritesOnlyNews(t *testing.T) {
	writes := func(fx *responderFixture) int {
		fx.findings.mu.Lock()
		defer fx.findings.mu.Unlock()
		return len(fx.findings.writes)
	}
	t.Run("while a throttle stands", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{}
		fx.r.SetProcessKiller(k)
		fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
		fx.setKill(t, "", true)
		fx.fireSignature(t, "box-a", 1) // throttled, pid 1 killed
		if n := writes(fx); n != 1 {
			t.Fatalf("writes after the first kill = %d, want 1", n)
		}
		// The miner respawns and exits before the signal: the skip is news
		// once.
		k.err = fmt.Errorf("pid 2: %w", errKillProcessGone)
		fx.fireSignature(t, "box-a", 2)
		if n := writes(fx); n != 2 {
			t.Fatalf("writes after the first skip = %d, want 2", n)
		}
		if w := fx.findings.lastWrite(); !w.ProcessKilled || w.KilledPID != 1 || w.Kills != 1 || w.KillSkipReason != pb.KillSkipReason_KILL_SKIP_REASON_PROCESS_GONE {
			t.Fatalf("skip write = %+v, want pid 1 kept, kills 1, PROCESS_GONE", w)
		}
		fx.fireSignature(t, "box-a", 3) // the same skip again: nothing new
		fx.fireSignature(t, "box-a", 4)
		if n := writes(fx); n != 2 {
			t.Fatalf("writes after repeated PROCESS_GONE skips = %d, want 2: nothing changed", n)
		}
		// The operator turns kill_process off: no attempt, nothing to record.
		k.err = nil
		fx.setKill(t, "", false)
		fx.fireSignature(t, "box-a", 5)
		if n := writes(fx); n != 2 || len(k.calls) != 4 {
			t.Fatalf("writes after a re-fire with kill_process off = %d (kill calls %d), want 2 and 4", n, len(k.calls))
		}
		// A kill is always news: it raises the count.
		fx.setKill(t, "", true)
		fx.fireSignature(t, "box-a", 6)
		if n := writes(fx); n != 3 {
			t.Fatalf("writes after another kill = %d, want 3", n)
		}
		if w := fx.findings.lastWrite(); w.KilledPID != 6 || w.Kills != 2 || w.KillSkipReason != pb.KillSkipReason_KILL_SKIP_REASON_UNSPECIFIED {
			t.Fatalf("kill write = %+v, want pid 6, kills 2, skip cleared", w)
		}
	})
	t.Run("under ALERT", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		k := &fakeKiller{}
		fx.r.SetProcessKiller(k)
		fx.setKill(t, "", true)
		fx.fireSignature(t, "box-a", 1)
		fx.setKill(t, "", false)
		fx.fireSignature(t, "box-a", 2)
		fx.fireSignature(t, "box-a", 3)
		if n := writes(fx); n != 1 {
			t.Fatalf("writes = %d, want 1: re-fires with kill_process off add nothing", n)
		}
	})
}

// #2775 review: a recorded skip reason survives the release, expiry and
// orphan-sweep writes. A box whose kill was refused has no kill of its own
// on its action row (#2772: the record is per box), but the reason on record
// is the finding's current state and is carried, not blanked.
func TestProcessResponder_ReleaseKeepsSkipReason(t *testing.T) {
	ctx := context.Background()
	const initSkip = pb.KillSkipReason_KILL_SKIP_REASON_CONTAINER_INIT
	setup := func(t *testing.T) (*responderFixture, int64) {
		t.Helper()
		fx := newResponderFixture(t, false)
		fx.r.SetProcessKiller(&fakeKiller{err: fmt.Errorf("pid 1: %w", errKillContainerInit)})
		fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
		fx.setKill(t, "", true)
		f := fx.fireSignature(t, "box-a", 1)
		if f.Response == nil || f.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED || f.Response.ProcessKilled || f.Response.KillSkipReason != initSkip {
			t.Fatalf("after the refused kill: %+v, want APPLIED with CONTAINER_INIT", f.Response)
		}
		return fx, f.ID
	}
	t.Run("operator release", func(t *testing.T) {
		fx, _ := setup(t)
		if _, _, err := fx.r.Release(ctx, "box-a"); err != nil {
			t.Fatal(err)
		}
		if w := fx.findings.lastWrite(); w.State != pb.ResponseState_RESPONSE_STATE_RELEASED || w.ProcessKilled || w.KillSkipReason != initSkip {
			t.Fatalf("release write = %+v, want RELEASED, not killed, CONTAINER_INIT kept", w)
		}
	})
	t.Run("ttl expiry", func(t *testing.T) {
		fx, _ := setup(t)
		if n := fx.r.SweepExpired(ctx, fx.clock.Add(2*time.Hour)); n != 1 {
			t.Fatalf("expired = %d, want 1", n)
		}
		if w := fx.findings.lastWrite(); w.State != pb.ResponseState_RESPONSE_STATE_EXPIRED || w.ProcessKilled || w.KillSkipReason != initSkip {
			t.Fatalf("expiry write = %+v, want EXPIRED, not killed, CONTAINER_INIT kept", w)
		}
	})
	t.Run("the row is the fallback when the finding is gone", func(t *testing.T) {
		fx, id := setup(t)
		fx.findings.mu.Lock()
		delete(fx.findings.rows, id)
		fx.findings.mu.Unlock()
		row, err := fx.actions.Open(ctx, "box-a")
		if err != nil {
			t.Fatal(err)
		}
		if got := fx.r.releaseKill(ctx, row); got != (killNote{}) {
			t.Fatalf("releaseKill with no finding and no row pid = %+v, want nothing", got)
		}
		row.KilledPID = 7
		if got := fx.r.releaseKill(ctx, row); got != (killNote{killed: true, pid: 7, count: 1}) {
			t.Fatalf("releaseKill from the row = %+v, want pid 7, one kill", got)
		}
	})
}
