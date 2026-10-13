package sshauthz_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	authz "github.com/footprintai/containarium/internal/sentinel/sshauthz"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"
)

type authorizerFunc func(context.Context, string, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error)

func (f authorizerFunc) Authorize(ctx context.Context, b string, r *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	return f(ctx, b, r)
}

type resolver map[string]string

func (r resolver) BackendForLogin(login string) (string, bool) { id, ok := r[login]; return id, ok }

func offeredKey(t *testing.T) (ssh.Signer, *ssh.Certificate) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, KeyId: "user-a", ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	return signer, cert
}
func allow(ttl time.Duration) *pb.AuthorizeSSHResponse {
	return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, UserId: "user-a", CacheTtl: durationpb.New(ttl)}
}

func TestAuditOnlyEveryCallbackOutcome(t *testing.T) {
	signer, cert := offeredKey(t)
	type testCase struct {
		name          string
		wire          []byte
		unknown, seed bool
		age           time.Duration
		response      *pb.AuthorizeSSHResponse
		err           error
		decision      pb.SSHAuthzDecision
		reason        pb.SSHDenyReason
		user          string
		calls         int
		fresh         bool
	}
	tests := []testCase{
		{name: "certificate", wire: cert.Marshal()},
		{name: "malformed", wire: []byte("bad")},
		{name: "unknown login", unknown: true},
		{name: "fresh positive", seed: true, age: time.Second, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, user: "cached-user", fresh: true},
		{name: "allow", response: allow(time.Minute), decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, user: "user-a", calls: 1, fresh: true},
		{name: "stale allow refresh", seed: true, age: time.Minute, response: allow(2 * time.Minute), decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, user: "user-a", calls: 1, fresh: true},
		{name: "transport inside grace", seed: true, age: time.Minute, err: authz.ErrUpstreamUnavailable, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, user: "cached-user", calls: 1},
		{name: "transport at grace boundary", seed: true, age: authz.DefaultGrace, err: authz.ErrUpstreamUnavailable, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, calls: 1},
		{name: "transport outside grace", seed: true, age: 6 * time.Minute, err: authz.ErrUpstreamUnavailable, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, calls: 1},
		{name: "transport without success", err: authz.ErrUpstreamUnavailable, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, calls: 1},
		{name: "HTTP auth failure gets no grace", seed: true, age: time.Minute, err: errors.New("HTTP 401"), decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, calls: 1},
		{name: "nil response", decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, calls: 1},
		{name: "unspecified decision", response: &pb.AuthorizeSSHResponse{}, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, calls: 1},
		{name: "unknown decision", response: &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision(99)}, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, calls: 1},
		{name: "allow with deny reason", response: &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING}, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, calls: 1},
	}
	tests = append(tests,
		testCase{name: "default TTL", response: &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, UserId: "user-a"}, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, user: "user-a", calls: 1, fresh: true},
		testCase{name: "zero TTL", response: allow(0), decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, user: "user-a", calls: 1},
		testCase{name: "negative TTL", response: allow(-time.Second), decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, user: "user-a", calls: 1},
		testCase{name: "unknown deny reason", response: &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason(99)}, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, calls: 1},
	)
	for n := range pb.SSHDenyReason_name {
		tests = append(tests, testCase{name: "deny " + pb.SSHDenyReason(n).String(), seed: true, age: time.Minute, response: &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason(n), UserId: "denied-user"}, decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, reason: pb.SSHDenyReason(n), user: "denied-user", calls: 1})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			cache := authz.NewPositiveCache(16, authz.DefaultGrace, func() time.Time { return now })
			ck := authz.CacheKey{Backend: "backend-a", Login: "alice", Fingerprint: ssh.FingerprintSHA256(signer.PublicKey())}
			if tc.seed {
				cache.Put(ck, "cached-user", 30*time.Second)
			}
			now = now.Add(tc.age)
			routes := resolver{"alice": "backend-a"}
			if tc.unknown {
				routes = resolver{}
			}
			calls := 0
			logs := ""
			p := &authz.Plugin{Cache: cache, Resolver: routes, SentinelID: "sentinel-a", Logf: func(f string, a ...any) { logs += fmt.Sprintf(f, a...) }, Authorizer: authorizerFunc(func(ctx context.Context, b string, r *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > authz.DefaultTimeout || time.Until(deadline) <= 0 {
					t.Error("three-second default deadline missing")
				}
				if b != "backend-a" || r.Login != "alice" || r.ClientIp != "192.0.2.1" || r.SentinelId != "sentinel-a" || r.GetCredential().GetPublicKey().GetFingerprintSha256() != ck.Fingerprint {
					t.Errorf("request %+v backend=%s", r, b)
				}
				return tc.response, tc.err
			})}
			wire := tc.wire
			if wire == nil {
				wire = signer.PublicKey().Marshal()
			}
			conn := &libplugin.ConnMeta{UserName: "alice", FromAddr: "192.0.2.1:4000", Metadata: map[string]string{authz.MetaUserID: "old-identity"}}
			up, err := p.Config().PublicKeyCallback(conn, wire)
			if err != nil || up == nil || up.GetNextPlugin() == nil {
				t.Fatalf("must ALWAYS defer: up=%v err=%v", up, err)
			}
			meta := up.GetNextPlugin().Meta
			if calls != tc.calls {
				t.Fatalf("calls=%d want=%d", calls, tc.calls)
			}
			decision, _ := strconv.Atoi(meta[authz.MetaDecision])
			reason, _ := strconv.Atoi(meta[authz.MetaDenyReason])
			if decision != int(tc.decision) || reason != int(tc.reason) || meta[authz.MetaUserID] != tc.user || meta[authz.MetaEnforced] != "false" {
				t.Fatalf("meta=%v", meta)
			}
			if _, ok := cache.Fresh(ck); ok != tc.fresh {
				t.Fatalf("fresh cached=%v want=%v", ok, tc.fresh)
			}
			if tc.response != nil && tc.response.Decision == pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY {
				if _, ok := cache.Grace(ck); ok {
					t.Fatal("deny left positive eligible for grace")
				}
			}
			if tc.reason == pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING && !strings.Contains(logs, "APPROVAL_PENDING") {
				t.Fatal("approval pending was not logged")
			}
		})
	}
}

func TestED25519CredentialType(t *testing.T) {
	signer, _ := offeredKey(t)
	p := &authz.Plugin{Resolver: resolver{"alice": "a"}, Authorizer: authorizerFunc(func(_ context.Context, _ string, r *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
		if r.GetCredential().GetPublicKey().KeyType != pb.SSHKeyType_SSH_KEY_TYPE_ED25519 {
			t.Fatal("wrong key type")
		}
		return allow(0), nil
	})}
	up, err := p.Config().PublicKeyCallback(&libplugin.ConnMeta{UserName: "alice"}, signer.PublicKey().Marshal())
	if err != nil || up.GetNextPlugin() == nil {
		t.Fatal(err)
	}
}
