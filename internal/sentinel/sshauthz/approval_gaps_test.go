package sshauthz

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"
)

// A full approval store denies the offer instead of prompting (#3083). The
// store is bounded so a flood of unsigned publickey queries cannot grow the
// plugin without limit; entries past their deadline are swept first, so
// expired approvals never hold the store full.
func TestDeviceApprovalStoreIsBounded(t *testing.T) {
	f := newRouterFixture(t, "")
	wire := f.alice.PublicKey().Marshal()
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	fill := func(h *approvalHarness, deadline time.Time) {
		for i := range maxPending {
			h.p.approvals[fmt.Sprint("other-", i)] = pendingApproval{deadline: deadline}
		}
	}
	t.Run("a full store denies the offer", func(t *testing.T) {
		h := newApprovalHarness(t, f, true, pendingRes(start.Add(5*time.Minute), 5*time.Second), nil, nil)
		fill(h, start.Add(time.Minute))
		conn := &libplugin.ConnMeta{UserName: "alice", UniqId: "conn-1"}
		up, err := h.cfg.PublicKeyCallback(conn, wire)
		if err == nil || up != nil {
			t.Fatalf("a full store must deny: %v %v", up, err)
		}
		if m := h.methods(t, conn); m != "publickey" {
			t.Fatalf("methods = %q, a denied offer must not enter the approval stage", m)
		}
		if h.p.hasApproval("conn-1") || len(h.p.approvals) != maxPending {
			t.Fatalf("store holds %d approvals, want %d and none for conn-1", len(h.p.approvals), maxPending)
		}
		if n := len(h.sink.recs); n != 1 || h.sink.recs[0].Phase != sshsession.SessionPhaseDenied || h.sink.recs[0].DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING {
			t.Fatalf("records: %+v", h.sink.recs)
		}
		if logs := strings.Join(h.logs, "\n"); !strings.Contains(logs, "too many pending device approvals") {
			t.Fatalf("logs: %s", logs)
		}
		if _, err := h.cfg.KeyboardInteractiveCallback(conn, func(string, string, string, bool) (string, error) {
			t.Fatal("no challenge expected")
			return "", nil
		}); err == nil {
			t.Fatal("keyboard-interactive must be refused")
		}
		if len(h.reqs) != 1 {
			t.Fatalf("Authorize calls = %d, want only the offer", len(h.reqs))
		}
	})
	t.Run("expired approvals are swept to make room", func(t *testing.T) {
		h := newApprovalHarness(t, f, true, pendingRes(start.Add(5*time.Minute), 5*time.Second), nil, nil)
		fill(h, start) // deadline == now: expired
		conn := &libplugin.ConnMeta{UserName: "alice", UniqId: "conn-1"}
		up, err := h.cfg.PublicKeyCallback(conn, wire)
		if err != nil || up.GetRetryCurrentPlugin() == nil {
			t.Fatalf("expired entries must not block a new approval: %v %v", up, err)
		}
		if len(h.p.approvals) != 1 || !h.p.hasApproval("conn-1") {
			t.Fatalf("store holds %d approvals, want only conn-1", len(h.p.approvals))
		}
	})
}

// The approval URL reaches the user's terminal; a URL with userinfo can pass
// for a different site (https://approve.example.com@evil.example/), so it is
// refused at the offer like plain http.
func TestDeviceApprovalRefusesUserinfoInURL(t *testing.T) {
	f := newRouterFixture(t, "")
	wire := f.alice.PublicKey().Marshal()
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	for _, u := range []string{
		"https://approve.example.com@evil.example/d",
		"https://user:secret@approve.example.com/d",
		"https://:secret@approve.example.com/d",
	} {
		t.Run(u, func(t *testing.T) {
			res := pendingRes(start.Add(5*time.Minute), 5*time.Second)
			res.Approval.Url = u
			h := newApprovalHarness(t, f, true, res, nil, nil)
			conn := &libplugin.ConnMeta{UserName: "alice", UniqId: "conn-1"}
			if up, err := h.cfg.PublicKeyCallback(conn, wire); err == nil || up != nil {
				t.Fatalf("a URL with userinfo must be refused at the offer: %v %v", up, err)
			}
			if m := h.methods(t, conn); m != "publickey" {
				t.Fatalf("methods = %q", m)
			}
			if h.p.hasApproval("conn-1") {
				t.Fatal("approval stored")
			}
		})
	}
	if _, ok := newApproval(pendingRes(start.Add(time.Minute), time.Second), start); !ok {
		t.Fatal("control: the same response without userinfo must be accepted")
	}
}

// An ALLOW on a poll is a positive like an ALLOW at the offer: it is cached,
// so the next connection with the same key skips the prompt.
func TestDeviceApprovalCachesPolledAllow(t *testing.T) {
	f := newRouterFixture(t, "")
	wire := f.alice.PublicKey().Marshal()
	fp := ssh.FingerprintSHA256(f.alice.PublicKey())
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	allow := allowed("user-polled")
	allow.CacheTtl = durationpb.New(time.Minute)
	h := newApprovalHarness(t, f, true, pendingRes(start.Add(5*time.Minute), 5*time.Second), []*pb.AuthorizeSSHResponse{allow}, nil)
	h.p.cfg.Cache = NewCache(DefaultGrace, 10, func() time.Time { return h.clock })
	ck := CacheKey{Backend: "backend-1", Login: "alice", Fingerprint: fp}
	conn := &libplugin.ConnMeta{UserName: "alice", UniqId: "conn-1"}
	if _, err := h.cfg.PublicKeyCallback(conn, wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.p.cfg.Cache.Get(ck, false); ok {
		t.Fatal("control: nothing cached before the approval")
	}
	if up, err := h.cfg.KeyboardInteractiveCallback(conn, func(string, string, string, bool) (string, error) { return "", nil }); err != nil || up.GetOrGenerateUri() == "" {
		t.Fatalf("approval: %v %v", up, err)
	}
	if user, ok := h.p.cfg.Cache.Get(ck, false); !ok || user != "user-polled" {
		t.Fatalf("Cache.Get = %q, %v; want the polled ALLOW's user", user, ok)
	}
	// A new connection offering the same key is admitted from the cache with
	// no further daemon call and no prompt.
	calls := len(h.reqs)
	next := &libplugin.ConnMeta{UserName: "alice", UniqId: "conn-2"}
	if up, err := h.cfg.PublicKeyCallback(next, wire); err != nil || up.GetOrGenerateUri() == "" || up.GetRetryCurrentPlugin() != nil || len(h.reqs) != calls {
		t.Fatalf("cached positive: %v %v calls=%d->%d", up, err, calls, len(h.reqs))
	}
}
