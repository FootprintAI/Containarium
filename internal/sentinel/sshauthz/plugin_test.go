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
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"
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
