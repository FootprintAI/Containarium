package sshauthz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

type recordSink struct{ recs []sshsession.Record }

func (s *recordSink) Record(r sshsession.Record) error {
	s.recs = append(s.recs, r)
	return nil
}

// In enforce mode every DENY returns an error, so sshpiperd keeps the chain on
// this plugin and never consults ssh-session-plugin or yaml for that key.
// Every other offer is routed by this plugin, as yaml would route it, and is
// never deferred: the chain cannot advance past it (#2629). The routed
// connection's open and close records carry the decision this plugin made.
func TestEnforceMatrix(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	f := newRouterFixture(t, "")
	signer := f.alice
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	type row struct {
		name                   string
		wire                   []byte
		unknown, resolverError bool
		seededAge              time.Duration // >0 seeds a positive this old
		res                    *pb.AuthorizeSSHResponse
		err                    error
		denied                 bool
		refused                bool // refused by routing: no upstream, no record
		decision               sshsession.AuthzDecision
		reason                 pb.SSHDenyReason
		user                   string
	}
	rows := []row{
		{name: "trusted certificate is routed", wire: routerCert(t, testKey(t).PublicKey(), f.ca, "alice", ssh.CertTimeInfinity)},
		{name: "untrusted certificate refused", wire: routerCert(t, testKey(t).PublicKey(), testKey(t), "alice", ssh.CertTimeInfinity), refused: true},
		{name: "malformed refused", wire: []byte("bad"), refused: true},
		{name: "unknown login is routed", unknown: true},
		{name: "allow is routed", res: allowed("user-1"), decision: sshsession.AuthzAllow, user: "user-1"},
		{name: "allowed key outside authorized_keys refused", wire: testKey(t).PublicKey().Marshal(), res: allowed("user-1"), refused: true},
		{name: "outage inside grace is routed", seededAge: time.Minute, err: errors.New("offline"), decision: sshsession.AuthzAllow, user: "cached-user"},
		{name: "broken bridge refused", resolverError: true, denied: true, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE},
		{name: "outage outside grace refused", seededAge: DefaultGrace + time.Second, err: errors.New("offline"), denied: true, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE},
		{name: "invalid response refused", res: &pb.AuthorizeSSHResponse{}, denied: true, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE},
	}
	for number := int32(1); number <= 7; number++ {
		reason := pb.SSHDenyReason(number)
		rows = append(rows, row{name: "deny " + reason.String() + " refused", res: &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: reason, UserId: "known-user"}, denied: true, reason: reason, user: "known-user"})
	}
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			clock := now
			c := NewCache(DefaultGrace, 10, func() time.Time { return clock })
			if tt.seededAge > 0 {
				c.Put(CacheKey{"backend-1", "alice", fp}, "cached-user", 30*time.Second)
				clock = clock.Add(tt.seededAge)
			}
			sink := &recordSink{}
			p, err := New(Config{Enforce: true, Recorder: sink, Cache: c, Now: func() time.Time { return clock },
				Router: NewRouter(f.config), Target: sshsession.NewTargetResolver(f.config),
				Resolver: resolverFunc(func(context.Context, string) (string, bool, error) {
					if tt.resolverError {
						return "", false, errors.New("broken")
					}
					return "backend-1", !tt.unknown, nil
				}),
				Authorizer: authorizerFunc(func(context.Context, string, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
					return tt.res, tt.err
				})})
			if err != nil {
				t.Fatal(err)
			}
			wire := tt.wire
			if wire == nil {
				wire = signer.PublicKey().Marshal()
			}
			conn := &libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.1:1234", UniqId: "conn-1"}
			cfg := p.PluginConfig()
			up, err := cfg.PublicKeyCallback(conn, wire)
			if tt.refused {
				if err == nil || up != nil {
					t.Fatalf("must be refused: %v %v", up, err)
				}
				cfg.PipeStartCallback(conn) // nothing was routed for conn-1
				if len(sink.recs) != 0 {
					t.Fatalf("refused offer wrote records: %+v", sink.recs)
				}
				return
			}
			if !tt.denied {
				if err != nil || up.GetNextPlugin() != nil || up.GetOrGenerateUri() != "tcp://192.0.2.10:2222" || up.GetPrivateKey() == nil {
					t.Fatalf("must route, never defer: %v %v", up, err)
				}
				if len(sink.recs) != 0 {
					t.Fatalf("routed offer wrote a record before the pipe started: %+v", sink.recs)
				}
				cfg.PipeStartCallback(conn)
				cfg.PipeErrorCallback(conn, nil)
				method, cred, _ := sshsession.ExtractCredential(wire)
				want := sshsession.Record{
					SessionID: "conn-1", Phase: sshsession.SessionPhaseOpen, OccurredAt: clock,
					ClientIP: "203.0.113.1", ClientPort: 1234, Login: "alice", Target: "192.0.2.10:2222",
					AuthMethod: method, Credential: cred,
					UserID: tt.user, AuthzDecision: sshsession.DecisionToProto(tt.decision), Enforced: tt.decision != "",
				}
				if len(sink.recs) != 2 || sink.recs[0] != want {
					t.Fatalf("records = %+v\nwant open %+v", sink.recs, want)
				}
				want.Phase, want.CloseReason = sshsession.SessionPhaseClose, sshsession.CloseReasonNormal
				if sink.recs[1] != want {
					t.Fatalf("close record:\n got %+v\nwant %+v", sink.recs[1], want)
				}
				return
			}
			if err == nil || up != nil {
				t.Fatalf("enforced denial must return an error and no upstream: %v %v", up, err)
			}
			if len(sink.recs) != 1 {
				t.Fatalf("records = %+v, want one denied record", sink.recs)
			}
			want := sshsession.Record{
				SessionID: "conn-1", Phase: sshsession.SessionPhaseDenied, OccurredAt: clock,
				ClientIP: "203.0.113.1", ClientPort: 1234, Login: "alice",
				AuthMethod: sshsession.AuthMethodPublicKey, Credential: sshsession.Credential{KeyFingerprint: fp},
				UserID: tt.user, AuthzDecision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: tt.reason, Enforced: true,
			}
			if got := sink.recs[0]; got != want {
				t.Fatalf("denied record:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

// Audit-only keeps #2518's behavior: a denial defers, carries no enforced
// marker, and writes no denied record even with a recorder configured.
func TestAuditOnlyDenyDefersWithoutRecord(t *testing.T) {
	sink := &recordSink{}
	p, err := New(Config{Recorder: sink,
		Resolver: resolverFunc(func(context.Context, string) (string, bool, error) { return "backend-1", true, nil }),
		Authorizer: authorizerFunc(func(context.Context, string, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
			return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY}, nil
		})})
	if err != nil {
		t.Fatal(err)
	}
	up, err := p.PluginConfig().PublicKeyCallback(&libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.1:1234"}, testKey(t).PublicKey().Marshal())
	if err != nil || up.GetNextPlugin() == nil {
		t.Fatalf("audit-only must defer: %v %v", up, err)
	}
	if up.GetNextPlugin().Meta[sshsession.MetaEnforced] != "" || len(sink.recs) != 0 {
		t.Fatalf("audit-only marked enforcement: meta=%v records=%+v", up.GetNextPlugin().Meta, sink.recs)
	}
}

// A pipe that starts for a connection whose decision was evicted from the
// bounded stash gets no session records from either plugin, so the gap is
// logged with the connection id and never with credential material.
func TestEnforceLogsPipeWithoutPendingDecision(t *testing.T) {
	clock := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	var logs []string
	sink := &recordSink{}
	p, err := New(Config{Enforce: true, Recorder: sink, Router: NewRouter("unused"), Now: func() time.Time { return clock },
		Logf:     func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
		Resolver: resolverFunc(nil), Authorizer: authorizerFunc(nil)})
	if err != nil {
		t.Fatal(err)
	}
	p.remember("evicted-conn", map[string]string{sshsession.MetaUserID: "secret-user"})
	clock = clock.Add(time.Second)
	for i := range maxPending {
		p.remember(fmt.Sprint(i), nil)
	}
	p.PluginConfig().PipeStartCallback(&libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.1:1234", UniqId: "evicted-conn"})
	if len(sink.recs) != 0 {
		t.Fatalf("records = %+v", sink.recs)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], `session="evicted-conn"`) || !strings.Contains(logs[0], "no pending decision") || strings.Contains(logs[0], "secret-user") {
		t.Fatalf("logs = %q", logs)
	}
}

// Audit-only mode leaves the session records to ssh-session-plugin.
func TestAuditOnlyWritesNoSessionRecords(t *testing.T) {
	p, err := New(Config{Resolver: resolverFunc(nil), Authorizer: authorizerFunc(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if cfg := p.PluginConfig(); cfg.PipeStartCallback != nil || cfg.PipeErrorCallback != nil {
		t.Fatal("audit-only plugin must not observe pipes")
	}
}

// Enforce mode cannot fail open on a missing router: there is nothing to defer to.
func TestEnforceRequiresRouter(t *testing.T) {
	if _, err := New(Config{Enforce: true, Resolver: resolverFunc(nil), Authorizer: authorizerFunc(nil)}); err == nil {
		t.Fatal("enforce mode without a router must be refused")
	}
}

// The pipe's records name the credential routed last on the connection: the
// SSH server re-runs the callback for the key that finally signs unless that
// key was the last one checked. A proxy shutdown closes the open session once.
func TestEnforceSessionRecordsLastRoutedCredentialAndShutdown(t *testing.T) {
	f := newRouterFixture(t, "")
	sink := &recordSink{}
	p, err := New(Config{Enforce: true, Recorder: sink, Router: NewRouter(f.config),
		Resolver: resolverFunc(func(context.Context, string) (string, bool, error) { return "backend-1", true, nil }),
		Authorizer: authorizerFunc(func(context.Context, string, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
			return allowed("user-1"), nil
		})})
	if err != nil {
		t.Fatal(err)
	}
	cfg := p.PluginConfig()
	conn := &libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.1:1234", UniqId: "conn-1"}
	for _, wire := range [][]byte{routerCert(t, testKey(t).PublicKey(), f.ca, "alice", ssh.CertTimeInfinity), f.alice.PublicKey().Marshal()} {
		if _, err := cfg.PublicKeyCallback(conn, wire); err != nil {
			t.Fatal(err)
		}
	}
	cfg.PipeStartCallback(conn)
	p.Shutdown()
	p.Shutdown()
	if len(sink.recs) != 2 {
		t.Fatalf("records = %+v, want open and one shutdown close", sink.recs)
	}
	for _, rec := range sink.recs {
		if rec.AuthMethod != sshsession.AuthMethodPublicKey || rec.KeyFingerprint != ssh.FingerprintSHA256(f.alice.PublicKey()) || rec.UserID != "user-1" || !rec.Enforced {
			t.Fatalf("record: %+v", rec)
		}
	}
	if sink.recs[1].Phase != sshsession.SessionPhaseClose || sink.recs[1].CloseReason != sshsession.CloseReasonProxyShutdown {
		t.Fatalf("shutdown close: %+v", sink.recs[1])
	}
}

// A connection routed on a query that never authenticates leaves its pending
// decision behind; the per-connection stash stays bounded in size and age.
func TestEnforcePendingIsBounded(t *testing.T) {
	clock := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	p, err := New(Config{Enforce: true, Router: NewRouter("unused"), Now: func() time.Time { return clock },
		Resolver: resolverFunc(nil), Authorizer: authorizerFunc(nil)})
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxPending + 5 {
		p.remember(fmt.Sprint(i), nil)
	}
	if len(p.pending) != maxPending {
		t.Fatalf("pending = %d, want %d", len(p.pending), maxPending)
	}
	clock = clock.Add(pendingTTL + time.Second)
	p.remember("late", nil)
	if len(p.pending) != 1 {
		t.Fatalf("expired entries kept: %d", len(p.pending))
	}
}
