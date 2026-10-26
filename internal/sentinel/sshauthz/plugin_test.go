package sshauthz

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type resolverFunc func(context.Context, string) (string, bool, error)

func (f resolverFunc) ResolveBackend(ctx context.Context, login string) (string, bool, error) {
	return f(ctx, login)
}

type authorizerFunc func(context.Context, string, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error)

func (f authorizerFunc) Authorize(ctx context.Context, b string, r *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	return f(ctx, b, r)
}

func testKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestAuditOnlyMatrix(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	signer := testKey(t)
	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, testKey(t)); err != nil {
		t.Fatal(err)
	}
	key := signer.PublicKey().Marshal()
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	type row struct {
		name                   string
		wire                   []byte
		unknown, resolverError bool
		age                    time.Duration
		seeded                 bool
		res                    *pb.AuthorizeSSHResponse
		err                    error
		decision               sshsession.AuthzDecision
		reason                 sshsession.DenyReason
		user                   string
		calls                  int
		retained, fresh        bool
	}
	allow := allowed("user-1")
	allow.CacheTtl = durationpb.New(30 * time.Second)
	rows := []row{
		{name: "certificate", wire: cert.Marshal()},
		{name: "malformed key", wire: []byte("bad")},
		{name: "unknown login", unknown: true},
		{name: "broken bridge", resolverError: true, decision: sshsession.AuthzDeny, reason: sshsession.DenyUpstreamUnavailable},
		{name: "allow", res: allow, decision: sshsession.AuthzAllow, user: "user-1", calls: 1, retained: true, fresh: true},
		{name: "cache hit", seeded: true, age: time.Second, decision: sshsession.AuthzAllow, user: "cached-user", retained: true, fresh: true},
		{name: "stale revalidated", seeded: true, age: 31 * time.Second, res: allow, decision: sshsession.AuthzAllow, user: "user-1", calls: 1, retained: true, fresh: true},
		{name: "transport inside grace", seeded: true, age: 31 * time.Second, err: errors.New("offline"), decision: sshsession.AuthzAllow, user: "cached-user", calls: 1, retained: true},
		{name: "transport at grace boundary", seeded: true, age: DefaultGrace, err: errors.New("offline"), decision: sshsession.AuthzDeny, reason: sshsession.DenyUpstreamUnavailable, calls: 1},
		{name: "transport outside grace", seeded: true, age: DefaultGrace + time.Second, err: errors.New("offline"), decision: sshsession.AuthzDeny, reason: sshsession.DenyUpstreamUnavailable, calls: 1},
		{name: "transport without cache", err: errors.New("offline"), decision: sshsession.AuthzDeny, reason: sshsession.DenyUpstreamUnavailable, calls: 1},
		{name: "5xx inside grace", seeded: true, age: 31 * time.Second, err: &HTTPError{503}, decision: sshsession.AuthzAllow, user: "cached-user", calls: 1, retained: true},
		{name: "401 never grace", seeded: true, age: 31 * time.Second, err: &HTTPError{401}, decision: sshsession.AuthzDeny, reason: sshsession.DenyUpstreamUnavailable, calls: 1},
		{name: "cloud outage inside grace", seeded: true, age: 31 * time.Second, res: unavailable(), decision: sshsession.AuthzAllow, user: "cached-user", calls: 1, retained: true},
		{name: "nil response", seeded: true, age: 31 * time.Second, decision: sshsession.AuthzDeny, reason: sshsession.DenyUpstreamUnavailable, calls: 1},
		{name: "unspecified decision", res: &pb.AuthorizeSSHResponse{}, decision: sshsession.AuthzDeny, reason: sshsession.DenyUpstreamUnavailable, calls: 1},
		{name: "invalid TTL", res: &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, CacheTtl: durationpb.New(-time.Second)}, decision: sshsession.AuthzDeny, reason: sshsession.DenyUpstreamUnavailable, calls: 1},
		{name: "zero TTL", res: allowed("user-1"), decision: sshsession.AuthzAllow, user: "user-1", calls: 1, retained: true},
	}
	for number := int32(1); number <= 7; number++ {
		reason := pb.SSHDenyReason(number)
		r := row{name: "deny " + reason.String(), seeded: true, age: 31 * time.Second, res: &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: reason, UserId: "known-user"}, decision: sshsession.AuthzDeny, reason: sshsession.ReasonFromProto(reason), user: "known-user", calls: 1}
		if reason == pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE {
			r.seeded = false
		}
		rows = append(rows, r)
	}
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			clock := now
			c := NewCache(DefaultGrace, 10, func() time.Time { return clock })
			ck := CacheKey{"backend-1", "alice", fp}
			if tt.seeded {
				c.Put(ck, "cached-user", 30*time.Second)
				clock = clock.Add(tt.age)
			}
			calls := 0
			p, err := New(Config{Cache: c, SentinelID: "sentinel-test", Resolver: resolverFunc(func(context.Context, string) (string, bool, error) {
				if tt.resolverError {
					return "", false, errors.New("broken")
				}
				return "backend-1", !tt.unknown, nil
			}), Authorizer: authorizerFunc(func(ctx context.Context, b string, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
				calls++
				if b != "backend-1" || req.GetLogin() != "alice" || req.GetClientIp() != "203.0.113.1" || req.GetSentinelId() != "sentinel-test" || req.GetCredential().GetPublicKey().GetFingerprintSha256() != fp || req.GetCredential().GetPublicKey().GetKeyType() != pb.SSHKeyType_SSH_KEY_TYPE_ED25519 {
					t.Fatalf("bad request: %v %v", b, req)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("missing deadline")
				}
				return tt.res, tt.err
			})})
			if err != nil {
				t.Fatal(err)
			}
			wire := tt.wire
			if wire == nil {
				wire = key
			}
			up, err := p.PluginConfig().PublicKeyCallback(&libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.1:1234"}, wire)
			if err != nil || up.GetNextPlugin() == nil {
				t.Fatalf("audit-only must defer: %v %v", up, err)
			}
			meta := up.GetNextPlugin().Meta
			if meta[sshsession.MetaUserID] != tt.user || meta[sshsession.MetaAuthzDecision] != string(tt.decision) || meta[sshsession.MetaDenyReason] != string(tt.reason) {
				t.Fatalf("metadata = %v", meta)
			}
			if calls != tt.calls {
				t.Fatalf("authorizer calls = %d, want %d", calls, tt.calls)
			}
			if _, ok := c.Get(ck, false); ok != tt.fresh {
				t.Fatalf("fresh = %v want %v", ok, tt.fresh)
			}
			if _, ok := c.Get(ck, true); ok != tt.retained {
				t.Fatalf("retained = %v want %v", ok, tt.retained)
			}
		})
	}
}

func TestGraceNeverRenewsAndDenyInvalidates(t *testing.T) {
	now := time.Now()
	c := NewCache(DefaultGrace, 10, func() time.Time { return now })
	key := CacheKey{"backend", "alice", "fp"}
	c.Put(key, "user", time.Second)
	now = now.Add(time.Minute)
	for range 4 {
		if _, ok := c.Get(key, true); !ok {
			t.Fatal("lost grace")
		}
		now = now.Add(time.Minute)
	}
	if _, ok := c.Get(key, true); ok {
		t.Fatal("grace read renewed positive")
	}
	c.Put(key, "user", time.Second)
	c.Delete(key)
	if _, ok := c.Get(key, true); ok {
		t.Fatal("denial retained positive")
	}
}

func TestCacheTTLIsolationAndEviction(t *testing.T) {
	now := time.Now()
	c := NewCache(DefaultGrace, 2, func() time.Time { return now })
	a := CacheKey{"a", "alice", "fp"}
	b := CacheKey{"b", "alice", "fp"}
	c.Put(a, "user-a", 2*time.Second)
	now = now.Add(time.Second)
	c.Put(b, "user-b", 10*time.Second)
	for _, k := range []CacheKey{{"a", "bob", "fp"}, {"a", "alice", "different"}} {
		if _, ok := c.Get(k, true); ok {
			t.Fatal("cache key collision")
		}
	}
	now = now.Add(time.Second)
	if _, ok := c.Get(a, false); ok {
		t.Fatal("TTL boundary must expire")
	}
	if user, ok := c.Get(b, false); !ok || user != "user-b" {
		t.Fatal("backends not isolated")
	}
	c.Put(CacheKey{"c", "alice", "fp"}, "user-c", time.Minute)
	if _, ok := c.Get(a, true); ok {
		t.Fatal("oldest entry not evicted")
	}
	now = now.Add(DefaultGrace)
	c.Get(b, true)
	if len(c.entries) != 0 {
		t.Fatal("expired entries not pruned")
	}
}

// A control plane's TTL must not stretch the outage-admit window past grace:
// an ALLOW is reused for at most min(ttl, grace) after it was checked.
func TestCacheCapsAllowTTLAtGrace(t *testing.T) {
	const grace = 2 * time.Minute
	for _, tt := range []struct {
		name      string
		ttl, want time.Duration // want: the effective TTL
	}{
		{name: "above grace is capped", ttl: 10 * time.Minute, want: grace},
		{name: "equal to grace is unchanged", ttl: grace, want: grace},
		{name: "below grace is unchanged", ttl: 30 * time.Second, want: 30 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
			now := start
			c := NewCache(grace, 10, func() time.Time { return now })
			key := CacheKey{"backend", "alice", "fp"}
			c.Put(key, "user", tt.ttl)
			now = start.Add(tt.want - time.Nanosecond)
			if _, ok := c.Get(key, false); !ok {
				t.Fatal("positive expired before its effective TTL")
			}
			now = start.Add(tt.want)
			if _, ok := c.Get(key, false); ok {
				t.Fatalf("positive still fresh at its effective TTL %v", tt.want)
			}
			if _, ok := c.Get(key, true); ok != (tt.want < grace) {
				t.Fatalf("outage read at %v = %v, want %v", tt.want, ok, tt.want < grace)
			}
		})
	}
}

func TestAuthorizationDeadline(t *testing.T) {
	p, err := New(Config{Timeout: 10 * time.Millisecond, Resolver: resolverFunc(func(context.Context, string) (string, bool, error) { return "backend", true, nil }), Authorizer: authorizerFunc(func(ctx context.Context, _ string, _ *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})})
	if err != nil {
		t.Fatal(err)
	}
	up, err := p.PluginConfig().PublicKeyCallback(&libplugin.ConnMeta{UserName: "alice"}, testKey(t).PublicKey().Marshal())
	if err != nil || up.GetNextPlugin().Meta[sshsession.MetaDenyReason] != string(sshsession.DenyUpstreamUnavailable) {
		t.Fatalf("timeout did not defer with denial: %v %v", up, err)
	}
}

func TestOfferedKeyTypes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		key  ssh.PublicKey
		want pb.SSHKeyType
	}{
		{testKey(t).PublicKey(), pb.SSHKeyType_SSH_KEY_TYPE_ED25519},
		{rsaPub, pb.SSHKeyType_SSH_KEY_TYPE_RSA},
	}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, struct {
			key  ssh.PublicKey
			want pb.SSHKeyType
		}{pub, pb.SSHKeyType_SSH_KEY_TYPE_ECDSA})
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	skED, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Type        string
		Key         []byte
		Application string
	}{ssh.KeyAlgoSKED25519, edKey.Public().(ed25519.PublicKey), "ssh:test"}))
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	skEC, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Type, Curve string
		Key         []byte
		Application string
	}{ssh.KeyAlgoSKECDSA256, "nistp256", ecKey.PublicKey().Bytes(), "ssh:test"}))
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, struct {
		key  ssh.PublicKey
		want pb.SSHKeyType
	}{skED, pb.SSHKeyType_SSH_KEY_TYPE_SK_ED25519}, struct {
		key  ssh.PublicKey
		want pb.SSHKeyType
	}{skEC, pb.SSHKeyType_SSH_KEY_TYPE_SK_ECDSA})
	for _, row := range rows {
		t.Run(row.key.Type(), func(t *testing.T) {
			got := pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED
			p, err := New(Config{Resolver: resolverFunc(func(context.Context, string) (string, bool, error) { return "backend", true, nil }), Authorizer: authorizerFunc(func(_ context.Context, _ string, r *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
				got = r.GetCredential().GetPublicKey().GetKeyType()
				return allowed("user"), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.PluginConfig().PublicKeyCallback(&libplugin.ConnMeta{UserName: "alice"}, row.key.Marshal())
			if err != nil || got != row.want {
				t.Fatalf("key type: %v %v", got, err)
			}
		})
	}
}

// pendingRes is the daemon's APPROVAL_PENDING answer for a new device. Its
// approval id and code must never reach the logs.
func pendingRes(expires time.Time, poll time.Duration) *pb.AuthorizeSSHResponse {
	return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING, UserId: "user-1",
		Approval: &pb.SSHDeviceApproval{ApprovalId: "appr-secret-2526", Code: "CODE-2526", Url: "https://approve.example.com/d",
			PollAfter: durationpb.New(poll), ExpiresAt: timestamppb.New(expires)}}
}

func denyRes(reason pb.SSHDenyReason) *pb.AuthorizeSSHResponse {
	return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: reason, UserId: "user-1"}
}

// approvalHarness is an enforcing plugin on a fake clock: Sleep advances the
// clock, so a 60-second poll runs instantly. The first Authorize answers the
// publickey offer with first; polls answer the re-polls, the last repeating.
type approvalHarness struct {
	p     *Plugin
	cfg   libplugin.SshPiperPluginConfig
	clock time.Time
	reqs  []*pb.AuthorizeSSHRequest
	logs  []string
	sink  *recordSink
}

func newApprovalHarness(t *testing.T, f routerFixture, enforce bool, first *pb.AuthorizeSSHResponse, polls []*pb.AuthorizeSSHResponse, pollErr error) *approvalHarness {
	t.Helper()
	h := &approvalHarness{clock: time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC), sink: &recordSink{}}
	cfg := Config{Enforce: enforce, Recorder: h.sink, Now: func() time.Time { return h.clock }, Sleep: func(d time.Duration) { h.clock = h.clock.Add(d) },
		Logf:     func(format string, args ...any) { h.logs = append(h.logs, fmt.Sprintf(format, args...)) },
		Resolver: resolverFunc(func(context.Context, string) (string, bool, error) { return "backend-1", true, nil }),
		Authorizer: authorizerFunc(func(_ context.Context, _ string, r *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
			h.reqs = append(h.reqs, r)
			if len(h.reqs) == 1 {
				return first, nil
			}
			if pollErr != nil {
				return nil, pollErr
			}
			return polls[min(len(h.reqs)-2, len(polls)-1)], nil
		})}
	if enforce {
		cfg.Router, cfg.Target = NewRouter(f.config), sshsession.NewTargetResolver(f.config)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.p, h.cfg = p, p.PluginConfig()
	return h
}

func (h *approvalHarness) methods(t *testing.T, conn libplugin.ConnMetadata) string {
	t.Helper()
	m, err := h.cfg.NextAuthMethodsCallback(conn)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(m, ",")
}

// Device approval (#2526): a PENDING answer keeps the chain cursor on this
// plugin with a retry, sshpiperd turns it into publickey partial success once
// the key has signed, and the keyboard-interactive callback shows the URL and
// code, waits for Enter, and polls with approval_id. It fails closed on
// APPROVAL_DENIED, at expires_at, at the 60-second cap, and on any poll error.
func TestDeviceApproval(t *testing.T) {
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	f := newRouterFixture(t, "")
	wire := f.alice.PublicKey().Marshal()
	fp := ssh.FingerprintSHA256(f.alice.PublicKey())
	pending := pendingRes(start.Add(5*time.Minute), 5*time.Second)
	withApproval := func(edit func(*pb.SSHDeviceApproval)) *pb.AuthorizeSSHResponse {
		res := pendingRes(start.Add(5*time.Minute), 5*time.Second)
		edit(res.Approval)
		return res
	}
	type row struct {
		name        string
		first       *pb.AuthorizeSSHResponse
		polls       []*pb.AuthorizeSSHResponse
		pollErr     error
		answerDelay time.Duration // the user presses Enter this late
		answerErr   error         // the client went away during the prompt
		noPrompt    bool          // refused at the publickey offer
		routed      bool
		calls       int // Authorize calls, the offer included
		reason      pb.SSHDenyReason
		maxElapsed  time.Duration // the clock never passes start+maxElapsed
	}
	rows := []row{
		{name: "authorize returns PENDING then ALLOW, so the keyboard-interactive callback completes with an upstream", first: pending, polls: []*pb.AuthorizeSSHResponse{allowed("user-1")}, routed: true, calls: 2},
		{name: "ALLOW on a later poll completes", first: pending, polls: []*pb.AuthorizeSSHResponse{pending, pending, allowed("user-1")}, routed: true, calls: 4, maxElapsed: 10 * time.Second},
		{name: "APPROVAL_DENIED stops polling", first: pending, polls: []*pb.AuthorizeSSHResponse{pending, denyRes(pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_DENIED)}, calls: 3, reason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_DENIED},
		// Polls at 0s, 5s and 10s; the wait after the last one is cut to the 12s expiry.
		{name: "polling stops at expires_at", first: pendingRes(start.Add(12*time.Second), 5*time.Second), polls: []*pb.AuthorizeSSHResponse{pendingRes(start.Add(12*time.Second), 5*time.Second)}, calls: 4, reason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING, maxElapsed: 12 * time.Second},
		// expires_at is ten minutes out; polls at 0s, 5s .. 55s, then the cap.
		{name: "polling stops at the 60-second cap", first: pending, polls: []*pb.AuthorizeSSHResponse{pending}, calls: 13, reason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING, maxElapsed: MaxApprovalWait},
		{name: "an answer after the cap never polls", first: pending, answerDelay: MaxApprovalWait + time.Second, calls: 1, reason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING},
		{name: "client gone during the prompt never polls", first: pending, answerErr: errors.New("connection closed"), calls: 1, reason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING},
		{name: "poll transport error fails closed", first: pending, pollErr: errors.New("offline"), calls: 2, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE},
		{name: "invalid poll response fails closed", first: pending, polls: []*pb.AuthorizeSSHResponse{{}}, calls: 2, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE},
		{name: "outage reported by the daemon fails closed", first: pending, polls: []*pb.AuthorizeSSHResponse{denyRes(pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE)}, calls: 2, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE},
		{name: "pending without an approval is refused", first: denyRes(pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING), noPrompt: true, calls: 1, reason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING},
		{name: "approval without an id is refused", first: withApproval(func(a *pb.SSHDeviceApproval) { a.ApprovalId = "" }), noPrompt: true, calls: 1, reason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING},
		{name: "plain-http approval URL is refused", first: withApproval(func(a *pb.SSHDeviceApproval) { a.Url = "http://approve.example.com/d" }), noPrompt: true, calls: 1, reason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING},
		{name: "terminal escape in the code is refused", first: withApproval(func(a *pb.SSHDeviceApproval) { a.Code = "CODE\x1b[2J" }), noPrompt: true, calls: 1, reason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING},
		{name: "approval already expired is refused", first: withApproval(func(a *pb.SSHDeviceApproval) { a.ExpiresAt = timestamppb.New(start) }), noPrompt: true, calls: 1, reason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING},
	}
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			h := newApprovalHarness(t, f, true, tt.first, tt.polls, tt.pollErr)
			conn := &libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.1:1234", UniqId: "conn-1"}
			up, err := h.cfg.PublicKeyCallback(conn, wire)
			var instruction string
			var prompts []string
			if tt.noPrompt {
				if err == nil || up != nil {
					t.Fatalf("unusable approval must be refused at the offer: %v %v", up, err)
				}
			} else {
				if err != nil || up.GetRetryCurrentPlugin() == nil {
					t.Fatalf("PENDING must retry the current plugin: %v %v", up, err)
				}
				if m := h.methods(t, conn); m != "keyboard-interactive" {
					t.Fatalf("methods after PENDING = %q", m)
				}
				up, err = h.cfg.KeyboardInteractiveCallback(conn, func(user, instr, question string, echo bool) (string, error) {
					instruction, prompts = instr, append(prompts, question)
					h.clock = h.clock.Add(tt.answerDelay)
					return "", tt.answerErr
				})
				if instruction != "Approve this device at https://approve.example.com/d, code CODE-2526" || len(prompts) != 1 || prompts[0] != "press Enter once approved: " {
					t.Fatalf("challenge: instruction %q prompts %q", instruction, prompts)
				}
			}
			if len(h.reqs) != tt.calls {
				t.Fatalf("Authorize calls = %d, want %d", len(h.reqs), tt.calls)
			}
			for i, r := range h.reqs {
				want := ""
				if i > 0 {
					want = "appr-secret-2526"
				}
				if r.GetApprovalId() != want || r.GetLogin() != "alice" || r.GetCredential().GetPublicKey().GetFingerprintSha256() != fp {
					t.Fatalf("request %d: %v", i, r)
				}
			}
			if tt.maxElapsed > 0 && h.clock.After(start.Add(tt.maxElapsed)) {
				t.Fatalf("polled until %v, past %v", h.clock.Sub(start), tt.maxElapsed)
			}
			if tt.routed {
				if err != nil || up.GetOrGenerateUri() != "tcp://192.0.2.10:2222" || up.GetPrivateKey() == nil {
					t.Fatalf("ALLOW must complete with the routed upstream: %v %v", up, err)
				}
				h.cfg.PipeStartCallback(conn)
				if len(h.sink.recs) != 1 || h.sink.recs[0].UserID != "user-1" || h.sink.recs[0].AuthzDecision != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW || h.sink.recs[0].KeyFingerprint != fp || !h.sink.recs[0].Enforced {
					t.Fatalf("open record: %+v", h.sink.recs)
				}
			} else {
				if err == nil || up != nil {
					t.Fatalf("must deny: %v %v", up, err)
				}
				if n := len(h.sink.recs); n == 0 || h.sink.recs[n-1].Phase != sshsession.SessionPhaseDenied || h.sink.recs[n-1].DenyReason != tt.reason || h.sink.recs[n-1].KeyFingerprint != fp {
					t.Fatalf("denied record: %+v, want reason %v", h.sink.recs, tt.reason)
				}
			}
			// The approval is consumed either way: no state outlives the outcome.
			if m := h.methods(t, conn); m != "publickey" {
				t.Fatalf("methods after the outcome = %q", m)
			}
			if logs := strings.Join(h.logs, "\n"); strings.Contains(logs, "appr-secret-2526") || strings.Contains(logs, "CODE-2526") {
				t.Fatalf("approval id or code logged: %s", logs)
			}
		})
	}
}

// Only the key that signed reaches keyboard-interactive. sshpiperd stores a
// retry's metadata even for an unsigned publickey query, so the approval is
// kept here by connection and every later offer clears it: a client that
// queries someone's public key, then signs with another key, gets no prompt.
// Certificate holders never enter the path, and audit-only mode logs and defers.
func TestDeviceApprovalBoundaries(t *testing.T) {
	f := newRouterFixture(t, "")
	pending := pendingRes(time.Date(2026, 10, 26, 0, 5, 0, 0, time.UTC), 5*time.Second)
	refuseChallenge := func(string, string, string, bool) (string, error) {
		t.Fatal("no challenge expected")
		return "", nil
	}
	t.Run("another offer after PENDING clears the approval", func(t *testing.T) {
		h := newApprovalHarness(t, f, true, pending, []*pb.AuthorizeSSHResponse{denyRes(pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY)}, nil)
		conn := &libplugin.ConnMeta{UserName: "alice", UniqId: "conn-1"}
		if up, err := h.cfg.PublicKeyCallback(conn, f.alice.PublicKey().Marshal()); err != nil || up.GetRetryCurrentPlugin() == nil {
			t.Fatalf("pending: %v %v", up, err)
		}
		if _, err := h.cfg.PublicKeyCallback(conn, testKey(t).PublicKey().Marshal()); err == nil {
			t.Fatal("denied key accepted")
		}
		if m := h.methods(t, conn); m != "publickey" {
			t.Fatalf("methods = %q", m)
		}
		if up, err := h.cfg.KeyboardInteractiveCallback(conn, refuseChallenge); err == nil || up != nil || len(h.reqs) != 2 {
			t.Fatalf("keyboard-interactive after another offer: %v %v calls=%d", up, err, len(h.reqs))
		}
	})
	t.Run("approvals are per connection", func(t *testing.T) {
		h := newApprovalHarness(t, f, true, pending, nil, nil)
		if _, err := h.cfg.PublicKeyCallback(&libplugin.ConnMeta{UserName: "alice", UniqId: "conn-1"}, f.alice.PublicKey().Marshal()); err != nil {
			t.Fatal(err)
		}
		other := &libplugin.ConnMeta{UserName: "alice", UniqId: "conn-2"}
		if m := h.methods(t, other); m != "publickey" {
			t.Fatalf("methods on another connection = %q", m)
		}
		if _, err := h.cfg.KeyboardInteractiveCallback(other, refuseChallenge); err == nil {
			t.Fatal("another connection used the approval")
		}
	})
	t.Run("certificate never enters the path", func(t *testing.T) {
		h := newApprovalHarness(t, f, true, pending, nil, nil)
		conn := &libplugin.ConnMeta{UserName: "alice", UniqId: "conn-1"}
		up, err := h.cfg.PublicKeyCallback(conn, routerCert(t, testKey(t).PublicKey(), f.ca, "alice", ssh.CertTimeInfinity))
		if err != nil || up.GetRetryCurrentPlugin() != nil || up.GetOrGenerateUri() != "tcp://192.0.2.10:2222" || len(h.reqs) != 0 {
			t.Fatalf("certificate: %v %v calls=%d", up, err, len(h.reqs))
		}
		if m := h.methods(t, conn); m != "publickey" {
			t.Fatalf("methods = %q", m)
		}
	})
	t.Run("audit-only logs and defers", func(t *testing.T) {
		h := newApprovalHarness(t, f, false, pending, nil, nil)
		conn := &libplugin.ConnMeta{UserName: "alice", UniqId: "conn-1"}
		up, err := h.cfg.PublicKeyCallback(conn, f.alice.PublicKey().Marshal())
		if err != nil || up.GetNextPlugin() == nil || up.GetNextPlugin().Meta[sshsession.MetaDenyReason] != string(sshsession.DenyApprovalPending) {
			t.Fatalf("audit-only must defer with the pending reason: %v %v", up, err)
		}
		if logs := strings.Join(h.logs, "\n"); !strings.Contains(logs, "reason=APPROVAL_PENDING") || strings.Contains(logs, "appr-secret-2526") || strings.Contains(logs, "CODE-2526") {
			t.Fatalf("logs: %s", logs)
		}
		if m := h.methods(t, conn); m != "publickey" {
			t.Fatalf("methods = %q", m)
		}
		if _, err := h.cfg.KeyboardInteractiveCallback(conn, refuseChallenge); err == nil || len(h.reqs) != 1 {
			t.Fatalf("audit-only keyboard-interactive: %v calls=%d", err, len(h.reqs))
		}
	})
}
