package sshauthz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

// Bounds on the device-approval poll loop (#3084): it stops when the client
// drops, it runs for at most 3 logins' worth of connections per login and 10
// per source IP at once, an approval the client never answered is audited,
// and the approval URL's host is logged.

func challengeEnter(string, string, string, bool) (string, error) { return "", nil }

// sshpiperd only learns that a client is gone when the SSH connection is
// used, so each poll cycle sends a zero-prompt keyboard-interactive request
// (RFC 4256 lets the client answer it with no responses, and OpenSSH shows
// nothing for an empty name and instruction). A dropped client then fails
// in sshpiperd, which reports PipeCreateError for the client's address, and
// the poll for that address stops at once.
func TestDeviceApprovalPollStopsWhenClientDrops(t *testing.T) {
	f := newRouterFixture(t, "")
	wire := f.alice.PublicKey().Marshal()
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	pending := pendingRes(start.Add(5*time.Minute), 5*time.Second)
	for _, tt := range []struct {
		name   string
		remote string // the address sshpiperd reports
		calls  int    // Authorize calls, the offer included
		gone   bool
	}{
		{name: "the client's own drop stops polling", remote: "203.0.113.1:1234", calls: 3, gone: true},
		{name: "another connection's failure does not", remote: "203.0.113.9:1", calls: 13},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newApprovalHarness(t, f, true, pending, []*pb.AuthorizeSSHResponse{pending}, nil)
			if h.cfg.PipeCreateErrorCallback == nil {
				t.Fatal("PipeCreateErrorCallback not registered: a dropped client is never seen")
			}
			h.sleepHook = func(n int) {
				if n == 2 {
					h.cfg.PipeCreateErrorCallback(tt.remote, errors.New("EOF"))
				}
			}
			conn := &libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.1:1234", UniqId: "conn-1"}
			if up, err := h.cfg.PublicKeyCallback(conn, wire); err != nil || up.GetRetryCurrentPlugin() == nil {
				t.Fatalf("pending: %v %v", up, err)
			}
			up, err := h.cfg.KeyboardInteractiveCallback(conn, challengeEnter)
			if err == nil || up != nil {
				t.Fatalf("must deny: %v %v", up, err)
			}
			if len(h.reqs) != tt.calls {
				t.Fatalf("Authorize calls = %d, want %d", len(h.reqs), tt.calls)
			}
			if tt.gone && !h.clock.Before(start.Add(MaxApprovalWait)) {
				t.Fatalf("polled until %v: the drop did not stop the loop", h.clock.Sub(start))
			}
			n := len(h.sink.recs)
			if n == 0 || h.sink.recs[n-1].Phase != sshsession.SessionPhaseDenied || h.sink.recs[n-1].DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING {
				t.Fatalf("denied record: %+v", h.sink.recs)
			}
			if logs := strings.Join(h.logs, "\n"); strings.Contains(logs, "client gone during device approval") != tt.gone {
				t.Fatalf("gone=%v, logs: %s", tt.gone, logs)
			}
			if m := h.methods(t, conn); m != "publickey" {
				t.Fatalf("methods after the outcome = %q", m)
			}
		})
	}
}

// Every poll cycle probes the client with a zero-prompt request and nothing
// else: the user still sees exactly one prompt and no extra text.
func TestDeviceApprovalProbesClientEachPoll(t *testing.T) {
	f := newRouterFixture(t, "")
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	pending := pendingRes(start.Add(5*time.Minute), 5*time.Second)
	h := newApprovalHarness(t, f, true, pending, []*pb.AuthorizeSSHResponse{pending, pending, allowed("user-1")}, nil)
	conn := &libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.1:1234", UniqId: "conn-1"}
	if _, err := h.cfg.PublicKeyCallback(conn, f.alice.PublicKey().Marshal()); err != nil {
		t.Fatal(err)
	}
	var prompts, probes []string
	up, err := h.cfg.KeyboardInteractiveCallback(conn, func(user, instr, question string, echo bool) (string, error) {
		if question == "" {
			probes = append(probes, user+"|"+instr)
			return "", nil
		}
		prompts = append(prompts, question)
		return "", nil
	})
	if err != nil || up.GetOrGenerateUri() == "" {
		t.Fatalf("approval: %v %v", up, err)
	}
	// Polls at 0s, 5s, 10s: two waits, one probe after each, before the re-poll.
	if len(prompts) != 1 || len(probes) != 2 {
		t.Fatalf("prompts=%q probes=%q, want one prompt and a probe per wait", prompts, probes)
	}
	for _, p := range probes {
		if p != "|" {
			t.Fatalf("probe shows text %q: an empty name and instruction print nothing", p)
		}
	}
	t.Run("a broken stream on the probe stops polling", func(t *testing.T) {
		h := newApprovalHarness(t, f, true, pending, []*pb.AuthorizeSSHResponse{pending}, nil)
		if _, err := h.cfg.PublicKeyCallback(conn, f.alice.PublicKey().Marshal()); err != nil {
			t.Fatal(err)
		}
		up, err := h.cfg.KeyboardInteractiveCallback(conn, func(_, _, question string, _ bool) (string, error) {
			if question == "" {
				return "", errors.New("transport is closing")
			}
			return "", nil
		})
		if err == nil || up != nil || len(h.reqs) != 2 {
			t.Fatalf("must deny after the first poll: %v %v calls=%d", up, err, len(h.reqs))
		}
	})
}

// capHarness holds polls open: Sleep parks each poll until gate closes, so
// several connections are in the approval stage at once.
type capHarness struct {
	p        *Plugin
	cfg      libplugin.SshPiperPluginConfig
	mu       sync.Mutex
	logs     []string
	sink     *recordSink
	entered  chan struct{}
	gate     chan struct{}
	released atomic.Bool
}

func newCapHarness(t *testing.T, f routerFixture) *capHarness {
	t.Helper()
	h := &capHarness{sink: &recordSink{}, entered: make(chan struct{}, 64), gate: make(chan struct{})}
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	pending := pendingRes(start.Add(5*time.Minute), 5*time.Second)
	p, err := New(Config{Enforce: true, Recorder: &lockedSink{h: h}, Now: func() time.Time { return start },
		Sleep: func(time.Duration) { h.entered <- struct{}{}; <-h.gate },
		Logf: func(format string, args ...any) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.logs = append(h.logs, fmt.Sprintf(format, args...))
		},
		Resolver: resolverFunc(func(context.Context, string) (string, bool, error) { return "backend-1", true, nil }),
		Authorizer: authorizerFunc(func(_ context.Context, _ string, r *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
			if r.GetApprovalId() == "" || !h.released.Load() {
				return pending, nil
			}
			return denyRes(pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_DENIED), nil
		}),
		Router: NewRouter(f.config), Target: sshsession.NewTargetResolver(f.config)})
	if err != nil {
		t.Fatal(err)
	}
	h.p, h.cfg = p, p.PluginConfig()
	return h
}

type lockedSink struct{ h *capHarness }

func (s *lockedSink) Record(r sshsession.Record) error {
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	s.h.sink.recs = append(s.h.sink.recs, r)
	return nil
}

// hold offers the key on conn and enters the approval stage in a goroutine,
// which then parks in the first poll wait.
func (h *capHarness) hold(t *testing.T, wire []byte, conn *libplugin.ConnMeta, wg *sync.WaitGroup) {
	t.Helper()
	if up, err := h.cfg.PublicKeyCallback(conn, wire); err != nil || up.GetRetryCurrentPlugin() == nil {
		t.Fatalf("%s: pending: %v %v", conn.UniqId, up, err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = h.cfg.KeyboardInteractiveCallback(conn, challengeEnter)
	}()
	select {
	case <-h.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never reached the poll wait", conn.UniqId)
	}
}

// attempt offers the key and runs the approval stage; it reports whether the
// user was prompted. The prompt answers with an error so the stage ends at
// once without a poll.
func (h *capHarness) attempt(t *testing.T, wire []byte, conn *libplugin.ConnMeta) (prompted bool) {
	t.Helper()
	if up, err := h.cfg.PublicKeyCallback(conn, wire); err != nil || up.GetRetryCurrentPlugin() == nil {
		t.Fatalf("%s: the offer must still be answered PENDING: %v %v", conn.UniqId, up, err)
	}
	up, err := h.cfg.KeyboardInteractiveCallback(conn, func(string, string, string, bool) (string, error) {
		prompted = true
		return "", errors.New("control: client gone")
	})
	if err == nil || up != nil {
		t.Fatalf("%s: must deny: %v %v", conn.UniqId, up, err)
	}
	return prompted
}

func (h *capHarness) lastRecord(t *testing.T) sshsession.Record {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sink.recs) == 0 {
		t.Fatal("no record")
	}
	return h.sink.recs[len(h.sink.recs)-1]
}

// More approvals than the cap are refused at the approval stage, before any
// prompt, with a denied record and a log line naming the cap, while other
// logins and other source addresses go on; a freed slot is reused.
func TestDeviceApprovalConcurrencyCaps(t *testing.T) {
	f := newRouterFixture(t, "")
	wire := f.alice.PublicKey().Marshal()
	// The caps are the decided values (#3084): 3 per login, 10 per source IP.
	t.Run("per login", func(t *testing.T) {
		h := newCapHarness(t, f)
		var wg sync.WaitGroup
		for i := range 3 {
			h.hold(t, wire, &libplugin.ConnMeta{UserName: "alice", FromAddr: fmt.Sprintf("203.0.113.%d:4000", i+1), UniqId: fmt.Sprint("alice-", i)}, &wg)
		}
		over := &libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.50:4000", UniqId: "alice-over"}
		if h.attempt(t, wire, over) {
			t.Fatal("the fourth approval for the login was prompted; the cap is 3")
		}
		if rec := h.lastRecord(t); rec.SessionID != "alice-over" || rec.Phase != sshsession.SessionPhaseDenied || rec.DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING || !rec.Enforced {
			t.Fatalf("denied record: %+v", rec)
		}
		h.mu.Lock()
		logs := strings.Join(h.logs, "\n")
		h.mu.Unlock()
		if !strings.Contains(logs, "3 device approvals already in progress for this login (cap 3)") {
			t.Fatalf("logs: %s", logs)
		}
		if !h.attempt(t, f.bob.PublicKey().Marshal(), &libplugin.ConnMeta{UserName: "bob", FromAddr: "203.0.113.1:4001", UniqId: "bob-1"}) {
			t.Fatal("another login from the same addresses was refused")
		}
		h.released.Store(true)
		close(h.gate)
		wg.Wait()
		if !h.attempt(t, wire, &libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.51:4000", UniqId: "alice-after"}) {
			t.Fatal("the slots were not released when the polls ended")
		}
	})
	t.Run("per source address", func(t *testing.T) {
		h := newCapHarness(t, f)
		var wg sync.WaitGroup
		for i := range 10 {
			h.hold(t, wire, &libplugin.ConnMeta{UserName: fmt.Sprint("user-", i), FromAddr: fmt.Sprintf("203.0.113.7:%d", 5000+i), UniqId: fmt.Sprint("ip-", i)}, &wg)
		}
		over := &libplugin.ConnMeta{UserName: "user-over", FromAddr: "203.0.113.7:5999", UniqId: "ip-over"}
		if h.attempt(t, wire, over) {
			t.Fatal("the eleventh approval from the address was prompted; the cap is 10")
		}
		if rec := h.lastRecord(t); rec.SessionID != "ip-over" || rec.DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING || rec.ClientIP != "203.0.113.7" {
			t.Fatalf("denied record: %+v", rec)
		}
		h.mu.Lock()
		logs := strings.Join(h.logs, "\n")
		h.mu.Unlock()
		if !strings.Contains(logs, "10 device approvals already in progress from this address (cap 10)") {
			t.Fatalf("logs: %s", logs)
		}
		if !h.attempt(t, wire, &libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.8:5000", UniqId: "other-ip"}) {
			t.Fatal("another address was refused")
		}
		h.released.Store(true)
		close(h.gate)
		wg.Wait()
	})
}

// A client that offered the pending key and then ended the connection
// without answering the prompt (a BatchMode client that cannot do
// keyboard-interactive, or one that walked away) gets a denied record, as
// does an approval still unconsumed when it expires.
func TestDeviceApprovalUnansweredPromptIsRecorded(t *testing.T) {
	f := newRouterFixture(t, "")
	wire := f.alice.PublicKey().Marshal()
	fp := ssh.FingerprintSHA256(f.alice.PublicKey())
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	pending := pendingRes(start.Add(5*time.Minute), 5*time.Second)
	conn := &libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.1:1234", UniqId: "conn-1"}
	checkRecord := func(t *testing.T, h *approvalHarness) {
		t.Helper()
		if len(h.sink.recs) != 1 {
			t.Fatalf("records: %+v, want exactly one", h.sink.recs)
		}
		rec := h.sink.recs[0]
		if rec.Phase != sshsession.SessionPhaseDenied || rec.SessionID != "conn-1" || rec.Login != "alice" || rec.ClientIP != "203.0.113.1" || rec.ClientPort != 1234 ||
			rec.KeyFingerprint != fp || rec.AuthMethod != sshsession.AuthMethodPublicKey || rec.UserID != "user-1" ||
			rec.DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING || !rec.Enforced || !rec.OccurredAt.Equal(h.clock) {
			t.Fatalf("denied record: %+v", rec)
		}
		if h.p.hasApproval("conn-1") {
			t.Fatal("the approval outlived the connection")
		}
		if logs := strings.Join(h.logs, "\n"); strings.Contains(logs, "appr-secret-2526") || strings.Contains(logs, "CODE-2526") {
			t.Fatalf("approval id or code logged: %s", logs)
		}
	}
	newHarness := func(t *testing.T) *approvalHarness {
		t.Helper()
		// The harness answers every later request from polls: the second
		// offer below gets PENDING too.
		h := newApprovalHarness(t, f, true, pending, []*pb.AuthorizeSSHResponse{pending}, nil)
		if h.cfg.PipeCreateErrorCallback == nil {
			t.Fatal("PipeCreateErrorCallback not registered")
		}
		return h
	}
	t.Run("the connection ends with the prompt unanswered", func(t *testing.T) {
		h := newHarness(t)
		if _, err := h.cfg.PublicKeyCallback(conn, wire); err != nil {
			t.Fatal(err)
		}
		h.cfg.PipeCreateErrorCallback("203.0.113.1:1234", errors.New("EOF"))
		checkRecord(t, h)
		if logs := strings.Join(h.logs, "\n"); !strings.Contains(logs, "ended before the device approval prompt was answered") {
			t.Fatalf("logs: %s", logs)
		}
		if _, err := h.cfg.KeyboardInteractiveCallback(conn, challengeEnter); err == nil || len(h.reqs) != 1 {
			t.Fatalf("keyboard-interactive after the connection ended: %v calls=%d", err, len(h.reqs))
		}
	})
	t.Run("an approval past its deadline is recorded when swept", func(t *testing.T) {
		h := newHarness(t)
		if _, err := h.cfg.PublicKeyCallback(conn, wire); err != nil {
			t.Fatal(err)
		}
		h.clock = h.clock.Add(MaxApprovalWait + time.Second)
		if _, err := h.cfg.PublicKeyCallback(&libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.2:1", UniqId: "conn-2"}, wire); err != nil {
			t.Fatal(err)
		}
		checkRecord(t, h)
		if !h.p.hasApproval("conn-2") {
			t.Fatal("the new approval was not stored")
		}
	})
	t.Run("another connection's failure leaves the approval", func(t *testing.T) {
		h := newHarness(t)
		if _, err := h.cfg.PublicKeyCallback(conn, wire); err != nil {
			t.Fatal(err)
		}
		h.cfg.PipeCreateErrorCallback("203.0.113.2:1234", errors.New("EOF"))
		if len(h.sink.recs) != 0 || !h.p.hasApproval("conn-1") {
			t.Fatalf("records=%+v approval kept=%v", h.sink.recs, h.p.hasApproval("conn-1"))
		}
	})
	t.Run("a consumed approval is recorded once", func(t *testing.T) {
		h := newHarness(t)
		if _, err := h.cfg.PublicKeyCallback(conn, wire); err != nil {
			t.Fatal(err)
		}
		if _, err := h.cfg.KeyboardInteractiveCallback(conn, func(string, string, string, bool) (string, error) { return "", errors.New("closed") }); err == nil {
			t.Fatal("must deny")
		}
		h.cfg.PipeCreateErrorCallback("203.0.113.1:1234", errors.New("EOF"))
		if len(h.sink.recs) != 1 {
			t.Fatalf("records: %+v, want one", h.sink.recs)
		}
	})
}

// The approval URL's host is logged with the pending decision, so an
// operator can see where users are sent; the id and code still are not.
func TestDeviceApprovalLogsApprovalHost(t *testing.T) {
	f := newRouterFixture(t, "")
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	h := newApprovalHarness(t, f, true, pendingRes(start.Add(5*time.Minute), 5*time.Second), nil, nil)
	if _, err := h.cfg.PublicKeyCallback(&libplugin.ConnMeta{UserName: "alice", UniqId: "conn-1"}, f.alice.PublicKey().Marshal()); err != nil {
		t.Fatal(err)
	}
	logs := strings.Join(h.logs, "\n")
	if !strings.Contains(logs, `approval_host="approve.example.com"`) {
		t.Fatalf("approval host not logged: %s", logs)
	}
	if strings.Contains(logs, "appr-secret-2526") || strings.Contains(logs, "CODE-2526") || strings.Contains(logs, "/d") {
		t.Fatalf("approval id, code or path logged: %s", logs)
	}
}
