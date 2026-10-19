package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeExecSource stands in for the ExecWatcher behind the server.
type fakeExecSource struct {
	status string
	lost   int64
	replay []ExecEventRecord
	live   chan ExecEventRecord
	subs   []struct {
		container string
		since     time.Duration
	}
	cancelled int
}

func (f *fakeExecSource) Status() string { return f.status }
func (f *fakeExecSource) Lost() int64    { return f.lost }
func (f *fakeExecSource) Subscribe(container string, since time.Duration, _ int) ([]ExecEventRecord, <-chan ExecEventRecord, func()) {
	f.subs = append(f.subs, struct {
		container string
		since     time.Duration
	}{container, since})
	var out []ExecEventRecord
	for _, r := range f.replay {
		if container == "" || r.Container == container {
			out = append(out, r)
		}
	}
	return out, f.live, func() { f.cancelled++ }
}

// fakeExecStream captures what the handler sends. Send runs on the handler's
// goroutine while the follow test reads from its own, so the slice is
// guarded.
type fakeExecStream struct {
	grpc.ServerStream
	ctx  context.Context
	mu   sync.Mutex
	sent []*pb.ExecEvent
	err  error
}

func (s *fakeExecStream) Context() context.Context { return s.ctx }
func (s *fakeExecStream) Send(resp *pb.StreamExecEventsResponse) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	s.sent = append(s.sent, resp.GetEvent())
	s.mu.Unlock()
	return nil
}

func (s *fakeExecStream) snapshot() []*pb.ExecEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*pb.ExecEvent(nil), s.sent...)
}

func execAdminCtx() context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), "ops",
		[]string{auth.RoleAdmin}, []string{auth.ScopeSecurityRead})
}

func rec(container string, pid uint32, at time.Time) ExecEventRecord {
	return ExecEventRecord{Container: container, TenantID: "t-" + container, At: at,
		Event: netbpf.ExecEvent{HostPID: pid, PPID: 1, UID: 1000, CgroupID: 7, Comm: "sh", Filename: "/bin/sh", Argv: []string{"sh", "-c", "true"}}}
}

// TestGetSentryStatus_ExecTelemetry: exec_telemetry and exec_events_lost
// ride the status response while the sentry is running — "unavailable (not
// started)" until a watcher is wired, then whatever the watcher reports.
func TestGetSentryStatus_ExecTelemetry(t *testing.T) {
	tests := []struct {
		name       string
		src        *fakeExecSource
		wantStatus string
		wantLost   int64
	}{
		{name: "no watcher wired", wantStatus: "unavailable (not started)"},
		{name: "running", src: &fakeExecSource{status: "ok", lost: 0}, wantStatus: "ok"},
		{name: "running with losses", src: &fakeExecSource{status: "ok", lost: 8729}, wantStatus: "ok", wantLost: 8729},
		{name: "object failed to load", src: &fakeExecSource{status: "unavailable (netbpf: execwatch: load collection: BTF not found)"}, wantStatus: "unavailable (netbpf: execwatch: load collection: BTF not found)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := threatdetect.NewEngine(&fakeFindingSink{}, "backend-1", false, nil, nil)
			s := NewThreatDetectionServer(engine, true, true, "")
			if tc.src != nil {
				s.SetExecTelemetry(tc.src)
			}
			resp, err := s.GetSentryStatus(secReadCtx(), &pb.GetSentryStatusRequest{})
			if err != nil {
				t.Fatalf("GetSentryStatus: %v", err)
			}
			if resp.ExecTelemetry != tc.wantStatus || resp.ExecEventsLost != tc.wantLost {
				t.Fatalf("exec_telemetry/lost = %q/%d, want %q/%d", resp.ExecTelemetry, resp.ExecEventsLost, tc.wantStatus, tc.wantLost)
			}
			// The flow side is unaffected by exec telemetry's state.
			if resp.State != pb.SentryState_SENTRY_STATE_OK {
				t.Fatalf("state = %v, want OK regardless of exec telemetry", resp.State)
			}
		})
	}
}

func TestStreamExecEvents_RequiresAdminAndScope(t *testing.T) {
	s := NewThreatDetectionServer(threatdetect.NewEngine(&fakeFindingSink{}, "b", false, nil, nil), true, true, "")
	s.SetExecTelemetry(&fakeExecSource{status: "ok"})
	for name, ctx := range map[string]context.Context{
		"read scope without admin": secReadCtx(),
		"admin without read scope": auth.ContextWithTestSubjectScopes(context.Background(), "ops", []string{auth.RoleAdmin}, []string{auth.ScopeSecurityWrite}),
		"anonymous":                context.Background(),
	} {
		err := s.StreamExecEvents(&pb.StreamExecEventsRequest{}, &fakeExecStream{ctx: ctx})
		if err == nil {
			t.Errorf("%s: streamed without the gate", name)
			continue
		}
		if c := status.Code(err); c != codes.PermissionDenied && c != codes.Unauthenticated {
			t.Errorf("%s: code = %v, want PermissionDenied/Unauthenticated", name, c)
		}
	}
}

// Unavailable exec telemetry → UNAVAILABLE carrying the status line, so the
// CLI shows the same reason `sentry status` does; the flow rules are not
// consulted at all.
func TestStreamExecEvents_UnavailableWhenNotRunning(t *testing.T) {
	s := NewThreatDetectionServer(threatdetect.NewEngine(&fakeFindingSink{}, "b", false, nil, nil), true, true, "")
	err := s.StreamExecEvents(&pb.StreamExecEventsRequest{}, &fakeExecStream{ctx: execAdminCtx()})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("no watcher: err = %v, want Unavailable", err)
	}
	s.SetExecTelemetry(&fakeExecSource{status: "unavailable (netbpf: execwatch: load collection: BTF not found)"})
	err = s.StreamExecEvents(&pb.StreamExecEventsRequest{}, &fakeExecStream{ctx: execAdminCtx()})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "BTF not found") {
		t.Fatalf("failed watcher: err = %v, want Unavailable naming the reason", err)
	}
}

// Replay only (no follow): the handler sends the replay for the container
// and window and returns; the subscription is released.
func TestStreamExecEvents_ReplayThenReturn(t *testing.T) {
	now := time.Unix(1700000000, 0)
	src := &fakeExecSource{status: "ok", live: make(chan ExecEventRecord), replay: []ExecEventRecord{rec("box-a", 1, now), rec("box-b", 2, now), rec("box-a", 3, now)}}
	s := NewThreatDetectionServer(threatdetect.NewEngine(&fakeFindingSink{}, "b", false, nil, nil), true, true, "")
	s.SetExecTelemetry(src)
	st := &fakeExecStream{ctx: execAdminCtx()}
	err := s.StreamExecEvents(&pb.StreamExecEventsRequest{Container: "box-a", Since: durationpb.New(5 * time.Minute)}, st)
	if err != nil {
		t.Fatalf("StreamExecEvents: %v", err)
	}
	if len(src.subs) != 1 || src.subs[0].container != "box-a" || src.subs[0].since != 5*time.Minute {
		t.Fatalf("subscribe args = %+v", src.subs)
	}
	if len(st.sent) != 2 || st.sent[0].Exec.Pid != 1 || st.sent[1].Exec.Pid != 3 {
		t.Fatalf("sent = %+v, want box-a's two replayed events", st.sent)
	}
	ev := st.sent[0]
	if ev.Container != "box-a" || ev.TenantId != "t-box-a" || !ev.At.AsTime().Equal(now) || ev.Exec.Comm != "sh" || ev.Exec.Argv != "sh -c true" || ev.Exec.Uid != 1000 || ev.Exec.Ppid != 1 {
		t.Fatalf("event = %+v", ev)
	}
	if src.cancelled != 1 {
		t.Fatalf("cancelled = %d, want the subscription released", src.cancelled)
	}
}

// Follow: live events are forwarded until the client's context ends; two
// handlers on the same source each get their own subscription.
func TestStreamExecEvents_FollowUntilClientGone(t *testing.T) {
	src := &fakeExecSource{status: "ok", live: make(chan ExecEventRecord, 4)}
	s := NewThreatDetectionServer(threatdetect.NewEngine(&fakeFindingSink{}, "b", false, nil, nil), true, true, "")
	s.SetExecTelemetry(src)
	ctx, cancel := context.WithCancel(execAdminCtx())
	st := &fakeExecStream{ctx: ctx}
	src.live <- rec("box-a", 10, time.Now())
	src.live <- rec("box-a", 11, time.Now())
	done := make(chan error, 1)
	go func() { done <- s.StreamExecEvents(&pb.StreamExecEventsRequest{Follow: true}, st) }()
	deadline := time.After(2 * time.Second)
	for len(st.snapshot()) < 2 {
		select {
		case <-deadline:
			t.Fatalf("sent %d live events, want 2", len(st.snapshot()))
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("follow returned %v after client cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return after the client went away")
	}
	if sent := st.snapshot(); sent[0].Exec.Pid != 10 || sent[1].Exec.Pid != 11 {
		t.Fatalf("live order = %+v", sent)
	}
}

// A subscriber the watcher dropped (closed channel) ends the stream with
// RESOURCE_EXHAUSTED instead of hanging or returning success.
func TestStreamExecEvents_DroppedSubscriberIsResourceExhausted(t *testing.T) {
	live := make(chan ExecEventRecord)
	close(live)
	src := &fakeExecSource{status: "ok", live: live}
	s := NewThreatDetectionServer(threatdetect.NewEngine(&fakeFindingSink{}, "b", false, nil, nil), true, true, "")
	s.SetExecTelemetry(src)
	err := s.StreamExecEvents(&pb.StreamExecEventsRequest{Follow: true}, &fakeExecStream{ctx: execAdminCtx()})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v, want ResourceExhausted", err)
	}
}

// A send failure (client gone mid-replay) surfaces as the error and still
// releases the subscription.
func TestStreamExecEvents_SendErrorReleases(t *testing.T) {
	src := &fakeExecSource{status: "ok", live: make(chan ExecEventRecord), replay: []ExecEventRecord{rec("box-a", 1, time.Now())}}
	s := NewThreatDetectionServer(threatdetect.NewEngine(&fakeFindingSink{}, "b", false, nil, nil), true, true, "")
	s.SetExecTelemetry(src)
	boom := errors.New("transport closed")
	err := s.StreamExecEvents(&pb.StreamExecEventsRequest{Since: durationpb.New(time.Minute)}, &fakeExecStream{ctx: execAdminCtx(), err: boom})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the send error", err)
	}
	if src.cancelled != 1 {
		t.Fatalf("cancelled = %d, want 1", src.cancelled)
	}
}
