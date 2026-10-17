package sshauthz

import (
	"context"
	"crypto/rand"
	"errors"
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
// Skipped credentials and allows still defer.
func TestEnforceMatrix(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	signer := testKey(t)
	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, testKey(t)); err != nil {
		t.Fatal(err)
	}
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	type row struct {
		name                   string
		wire                   []byte
		unknown, resolverError bool
		seededAge              time.Duration // >0 seeds a positive this old
		res                    *pb.AuthorizeSSHResponse
		err                    error
		denied                 bool
		decision               sshsession.AuthzDecision
		reason                 pb.SSHDenyReason
		user                   string
	}
	rows := []row{
		{name: "certificate defers", wire: cert.Marshal()},
		{name: "malformed defers", wire: []byte("bad")},
		{name: "unknown login defers", unknown: true},
		{name: "allow defers", res: allowed("user-1"), decision: sshsession.AuthzAllow, user: "user-1"},
		{name: "outage inside grace defers", seededAge: time.Minute, err: errors.New("offline"), decision: sshsession.AuthzAllow, user: "cached-user"},
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
			up, err := p.PluginConfig().PublicKeyCallback(&libplugin.ConnMeta{UserName: "alice", FromAddr: "203.0.113.1:1234", UniqId: "conn-1"}, wire)
			if !tt.denied {
				if err != nil || up.GetNextPlugin() == nil {
					t.Fatalf("must defer: %v %v", up, err)
				}
				meta := up.GetNextPlugin().Meta
				wantEnforced := ""
				if tt.decision != "" {
					wantEnforced = "true"
				}
				if meta[sshsession.MetaAuthzDecision] != string(tt.decision) || meta[sshsession.MetaUserID] != tt.user || meta[sshsession.MetaEnforced] != wantEnforced {
					t.Fatalf("metadata = %v", meta)
				}
				if len(sink.recs) != 0 {
					t.Fatalf("deferred offer wrote a denied record: %+v", sink.recs)
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
