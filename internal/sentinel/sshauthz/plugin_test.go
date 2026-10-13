package sshauthz_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// fakeResolver maps login → URL for tests.
type fakeResolver struct {
	entries map[string]string
}

func (r *fakeResolver) ResolveLogin(login string) (string, bool) {
	if r.entries == nil {
		return "", false
	}
	u, ok := r.entries[login]
	return u, ok
}

// fakeAuthorizer returns a pre-configured result or error.
type fakeAuthorizer struct {
	result sshauthz.Result
	err    error
	calls  int
}

func (a *fakeAuthorizer) Authorize(_ context.Context, _, _, _, _ string) (sshauthz.Result, error) {
	a.calls++
	return a.result, a.err
}

// fakeConn implements libplugin.ConnMetadata for testing.
type fakeConn struct {
	user   string
	remote string
	id     string
	meta   map[string]string
}

func (c *fakeConn) User() string       { return c.user }
func (c *fakeConn) RemoteAddr() string { return c.remote }
func (c *fakeConn) UniqueID() string   { return c.id }
func (c *fakeConn) GetMeta(key string) string {
	if c.meta == nil {
		return ""
	}
	return c.meta[key]
}

// marshalPublicKey returns the wire-format bytes for a raw public key.
func marshalPublicKey(t *testing.T) ([]byte, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub, err := ssh.NewPublicKey(priv.Public())
	require.NoError(t, err)
	return pub.Marshal(), ssh.FingerprintSHA256(pub)
}

// marshalCertificate returns wire bytes for a certificate (not a raw key).
func marshalCertificate(t *testing.T) []byte {
	t.Helper()
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caKey, err := ssh.NewSignerFromKey(signer)
	require.NoError(t, err)

	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	userPub, err := ssh.NewPublicKey(userPriv.Public())
	require.NoError(t, err)

	cert := &ssh.Certificate{
		Key:         userPub,
		CertType:    ssh.UserCert,
		ValidBefore: ssh.CertTimeInfinity,
		KeyId:       "test-cert",
	}
	require.NoError(t, cert.SignCert(rand.Reader, caKey))
	return cert.Marshal()
}

// buildPlugin creates a Plugin with the given authorizer and resolver.
func buildPlugin(t *testing.T, auth sshauthz.Authorizer, resolver sshauthz.BackendResolver, cache *sshauthz.Cache) *sshauthz.Plugin {
	t.Helper()
	p, err := sshauthz.New(sshauthz.Config{
		Resolver:   resolver,
		Authorizer: auth,
		Cache:      cache,
		Grace:      5 * time.Minute,
		Timeout:    3 * time.Second,
		Logf:       func(string, ...any) {}, // silent in tests
	})
	require.NoError(t, err)
	return p
}

// invokeCallback calls the plugin's PublicKeyCallback and returns the metadata
// map from the NextPlugin upstream auth result.
func invokeCallback(t *testing.T, p *sshauthz.Plugin, conn libplugin.ConnMetadata, keyBytes []byte) map[string]string {
	t.Helper()
	cfg := p.PluginConfig()
	require.NotNil(t, cfg.PublicKeyCallback, "PublicKeyCallback must be set")
	upstream, err := cfg.PublicKeyCallback(conn, keyBytes)
	require.NoError(t, err, "publicKeyCallback must never error (audit-only)")
	require.NotNil(t, upstream, "upstream must not be nil")
	np, ok := upstream.Auth.(*libplugin.Upstream_NextPlugin)
	require.True(t, ok, "result must be NextPlugin (defer)")
	return np.NextPlugin.Meta
}

// ── table test ───────────────────────────────────────────────────────────────

func TestPublicKeyCallback(t *testing.T) {
	const backendURL = "http://10.0.0.2:8080"
	const login = "alice"

	conn := &fakeConn{user: login, remote: "203.0.113.5:54321", id: "sess-1"}
	keyBytes, fingerprint := marshalPublicKey(t)
	certBytes := marshalCertificate(t)

	// fixedNow is the reference time used by tests that inject a clock.
	fixedNow := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fixedClock := func() time.Time { return fixedNow }

	rows := []struct {
		name string

		// inputs
		keyBytes   []byte
		login      string
		resolver   sshauthz.BackendResolver
		authResult sshauthz.Result
		authErr    error
		cacheSetup func(c *sshauthz.Cache) // populate cache before the call

		// expectations
		wantDecision   string
		wantDenyReason string
		wantUserID     string
		wantDeferred   bool // always true (audit-only)
		wantAuthCalls  int
	}{
		{
			name:          "certificate — skip authz, defer",
			keyBytes:      certBytes,
			login:         login,
			resolver:      &fakeResolver{entries: map[string]string{login: backendURL}},
			wantDecision:  "", // no decision set for certs
			wantDeferred:  true,
			wantAuthCalls: 0,
		},
		{
			name:          "unknown login — defer without authz",
			keyBytes:      keyBytes,
			login:         "nobody",
			resolver:      &fakeResolver{}, // empty map
			wantDecision:  "",
			wantDeferred:  true,
			wantAuthCalls: 0,
		},
		{
			name:     "cache hit — defer with ALLOW, no authz call",
			keyBytes: keyBytes,
			login:    login,
			resolver: &fakeResolver{entries: map[string]string{login: backendURL}},
			cacheSetup: func(c *sshauthz.Cache) {
				c.Put(backendURL, login, fingerprint, "user-cached", time.Hour)
			},
			wantDecision:  sshauthz.DecisionAllow.String(),
			wantUserID:    "user-cached",
			wantDeferred:  true,
			wantAuthCalls: 0,
		},
		{
			name:     "cache stale — hits upstream",
			keyBytes: keyBytes,
			login:    login,
			resolver: &fakeResolver{entries: map[string]string{login: backendURL}},
			cacheSetup: func(c *sshauthz.Cache) {
				// Put an entry with a 1ns TTL so it expires before the call.
				c.Put(backendURL, login, fingerprint, "user-stale", time.Nanosecond)
			},
			authResult:    sshauthz.Result{Decision: sshauthz.DecisionAllow, UserID: "user-fresh", CacheTTL: time.Hour},
			wantDecision:  sshauthz.DecisionAllow.String(),
			wantUserID:    "user-fresh",
			wantDeferred:  true,
			wantAuthCalls: 1,
		},
		{
			name:          "allow — stash user_id, cache, defer",
			keyBytes:      keyBytes,
			login:         login,
			resolver:      &fakeResolver{entries: map[string]string{login: backendURL}},
			authResult:    sshauthz.Result{Decision: sshauthz.DecisionAllow, UserID: "user-42", CacheTTL: 30 * time.Minute},
			wantDecision:  sshauthz.DecisionAllow.String(),
			wantUserID:    "user-42",
			wantDeferred:  true,
			wantAuthCalls: 1,
		},
		{
			name:           "deny UNKNOWN_KEY — stash reason, defer",
			keyBytes:       keyBytes,
			login:          login,
			resolver:       &fakeResolver{entries: map[string]string{login: backendURL}},
			authResult:     sshauthz.Result{Decision: sshauthz.DecisionDeny, DenyReason: sshauthz.DenyReasonUnknownKey},
			wantDecision:   sshauthz.DecisionDeny.String(),
			wantDenyReason: sshauthz.DenyReasonUnknownKey.String(),
			wantDeferred:   true,
			wantAuthCalls:  1,
		},
		{
			name:           "deny USER_DISABLED — defer",
			keyBytes:       keyBytes,
			login:          login,
			resolver:       &fakeResolver{entries: map[string]string{login: backendURL}},
			authResult:     sshauthz.Result{Decision: sshauthz.DecisionDeny, DenyReason: sshauthz.DenyReasonUserDisabled},
			wantDecision:   sshauthz.DecisionDeny.String(),
			wantDenyReason: sshauthz.DenyReasonUserDisabled.String(),
			wantDeferred:   true,
			wantAuthCalls:  1,
		},
		{
			name:           "deny ORG_POLICY — defer",
			keyBytes:       keyBytes,
			login:          login,
			resolver:       &fakeResolver{entries: map[string]string{login: backendURL}},
			authResult:     sshauthz.Result{Decision: sshauthz.DecisionDeny, DenyReason: sshauthz.DenyReasonOrgPolicy},
			wantDecision:   sshauthz.DecisionDeny.String(),
			wantDenyReason: sshauthz.DenyReasonOrgPolicy.String(),
			wantDeferred:   true,
			wantAuthCalls:  1,
		},
		{
			name:           "deny APPROVAL_DENIED — defer",
			keyBytes:       keyBytes,
			login:          login,
			resolver:       &fakeResolver{entries: map[string]string{login: backendURL}},
			authResult:     sshauthz.Result{Decision: sshauthz.DecisionDeny, DenyReason: sshauthz.DenyReasonApprovalDenied},
			wantDecision:   sshauthz.DecisionDeny.String(),
			wantDenyReason: sshauthz.DenyReasonApprovalDenied.String(),
			wantDeferred:   true,
			wantAuthCalls:  1,
		},
		{
			name:           "deny APPROVAL_EXPIRED — defer",
			keyBytes:       keyBytes,
			login:          login,
			resolver:       &fakeResolver{entries: map[string]string{login: backendURL}},
			authResult:     sshauthz.Result{Decision: sshauthz.DecisionDeny, DenyReason: sshauthz.DenyReasonApprovalExpired},
			wantDecision:   sshauthz.DecisionDeny.String(),
			wantDenyReason: sshauthz.DenyReasonApprovalExpired.String(),
			wantDeferred:   true,
			wantAuthCalls:  1,
		},
		{
			name:           "APPROVAL_PENDING — treat as deny, defer",
			keyBytes:       keyBytes,
			login:          login,
			resolver:       &fakeResolver{entries: map[string]string{login: backendURL}},
			authResult:     sshauthz.Result{Decision: sshauthz.DecisionApprovalPending},
			wantDecision:   sshauthz.DecisionDeny.String(),
			wantDenyReason: sshauthz.DenyReasonApprovalDenied.String(),
			wantDeferred:   true,
			wantAuthCalls:  1,
		},
		{
			name:     "transport error inside grace — use grace cache, defer with ALLOW",
			keyBytes: keyBytes,
			login:    login,
			resolver: &fakeResolver{entries: map[string]string{login: backendURL}},
			cacheSetup: func(c *sshauthz.Cache) {
				// Entry expires 1s in the future from fixedNow — still within 5m grace.
				// We set up so it looks expired relative to fixedNow+tiny bit,
				// but within the grace window.
				// Actually Put with a TTL of 1ns relative to fixedNow so it's
				// already expired but within grace.
				c.Put(backendURL, login, fingerprint, "user-grace", time.Nanosecond)
			},
			authErr:       errors.New("connection refused"),
			wantDecision:  sshauthz.DecisionAllow.String(),
			wantUserID:    "user-grace",
			wantDeferred:  true,
			wantAuthCalls: 1,
		},
		{
			name:           "transport error outside grace — UPSTREAM_UNAVAILABLE, defer",
			keyBytes:       keyBytes,
			login:          login,
			resolver:       &fakeResolver{entries: map[string]string{login: backendURL}},
			authErr:        errors.New("connection refused"),
			wantDecision:   sshauthz.DecisionDeny.String(),
			wantDenyReason: sshauthz.DenyReasonUpstreamUnavailable.String(),
			wantDeferred:   true,
			wantAuthCalls:  1,
		},
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			auth := &fakeAuthorizer{result: row.authResult, err: row.authErr}

			testLogin := row.login
			if testLogin == "" {
				testLogin = login
			}
			testConn := &fakeConn{user: testLogin, remote: conn.remote, id: conn.id}

			cache := sshauthz.NewCache(fixedClock)
			if row.cacheSetup != nil {
				row.cacheSetup(cache)
			}

			resolver := row.resolver
			if resolver == nil {
				resolver = &fakeResolver{entries: map[string]string{login: backendURL}}
			}

			p := buildPlugin(t, auth, resolver, cache)
			meta := invokeCallback(t, p, testConn, row.keyBytes)

			// Every row must defer (audit-only).
			assert.Equal(t, row.wantDeferred, true, "must always defer")
			assert.Equal(t, "false", meta[sshauthz.MetaEnforced], "enforced must be false in audit-only mode")

			if row.wantDecision != "" {
				assert.Equal(t, row.wantDecision, meta[sshauthz.MetaDecision], "decision mismatch")
			}
			if row.wantDenyReason != "" {
				assert.Equal(t, row.wantDenyReason, meta[sshauthz.MetaDenyReason], "deny_reason mismatch")
			}
			if row.wantUserID != "" {
				assert.Equal(t, row.wantUserID, meta[sshauthz.MetaUserID], "user_id mismatch")
			}
			assert.Equal(t, row.wantAuthCalls, auth.calls, "unexpected number of Authorize calls")
		})
	}
}
