//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/spf13/cobra"
)

const sentinelDeregisterTokenTestSecret = "cli-deregister-admin-secret-32-bytes!!"

// resetSentinelDeregisterTokenFlags clears the package-level flag vars
// between tests, so one test's settings cannot leak into another's.
func resetSentinelDeregisterTokenFlags() {
	sentinelDeregisterTokenSentinelURL = ""
	sentinelDeregisterTokenToken = ""
	sentinelDeregisterTokenTokenPrefix = ""
	sentinelDeregisterTokenSecret = ""
}

func newSentinelDeregisterTokenTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetContext(context.Background())
	return cmd
}

// TestSentinelDeregisterTokenCmd_RequiresTokenOrPrefix pins the CLI-first
// requirement (#1963): the command must reject a call that supplies
// neither identifier, mirroring the handler's own 400.
func TestSentinelDeregisterTokenCmd_RequiresTokenOrPrefix(t *testing.T) {
	t.Cleanup(resetSentinelDeregisterTokenFlags)
	resetSentinelDeregisterTokenFlags()
	sentinelDeregisterTokenSentinelURL = "http://unused.invalid"
	sentinelDeregisterTokenSecret = sentinelDeregisterTokenTestSecret

	err := runSentinelDeregisterToken(newSentinelDeregisterTokenTestCmd(), nil)
	if err == nil {
		t.Fatal("want an error when neither --token nor --token-prefix is set")
	}
	if !strings.Contains(err.Error(), "--token") {
		t.Errorf("error = %q, want it to mention --token/--token-prefix", err)
	}
}

// TestSentinelDeregisterTokenCmd_RejectsBothTokenAndPrefix mirrors the
// handler's ambiguous-request 400.
func TestSentinelDeregisterTokenCmd_RejectsBothTokenAndPrefix(t *testing.T) {
	t.Cleanup(resetSentinelDeregisterTokenFlags)
	resetSentinelDeregisterTokenFlags()
	sentinelDeregisterTokenSentinelURL = "http://unused.invalid"
	sentinelDeregisterTokenSecret = sentinelDeregisterTokenTestSecret
	sentinelDeregisterTokenToken = "host-a.secret1"
	sentinelDeregisterTokenTokenPrefix = "host-a."

	err := runSentinelDeregisterToken(newSentinelDeregisterTokenTestCmd(), nil)
	if err == nil {
		t.Fatal("want an error when both --token and --token-prefix are set")
	}
}

// TestSentinelDeregisterTokenCmd_RequiresSecret mirrors register-token's own
// guard against calling out with no admin secret at all.
func TestSentinelDeregisterTokenCmd_RequiresSecret(t *testing.T) {
	t.Cleanup(resetSentinelDeregisterTokenFlags)
	resetSentinelDeregisterTokenFlags()
	sentinelDeregisterTokenSentinelURL = "http://unused.invalid"
	sentinelDeregisterTokenToken = "host-a.secret1"

	err := runSentinelDeregisterToken(newSentinelDeregisterTokenTestCmd(), nil)
	if err == nil {
		t.Fatal("want an error when no admin secret is configured")
	}
}

// TestSentinelDeregisterTokenCmd_EndToEndExactToken drives the real
// operator path for the unchanged exact-token form: the cobra command signs
// a DELETE, the real sentinel handler serves it behind the real HMAC
// middleware, and the token stops validating.
func TestSentinelDeregisterTokenCmd_EndToEndExactToken(t *testing.T) {
	var mgr sentinel.Manager
	mgr.SetAdminSecret([]byte(sentinelDeregisterTokenTestSecret))
	policy := sentinel.NewTokenPolicy()
	policy.Allow("live-token", sentinel.PoolAny)
	mgr.SetTunnelPolicy(policy)
	mgr.SetTunnelTokenStorePath(t.TempDir() + "/tunnel-tokens.json")

	mux := newSentinelTunnelTokenTestMux(&mgr)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Cleanup(resetSentinelDeregisterTokenFlags)
	resetSentinelDeregisterTokenFlags()
	sentinelDeregisterTokenSentinelURL = srv.URL
	sentinelDeregisterTokenToken = "live-token"
	sentinelDeregisterTokenSecret = sentinelDeregisterTokenTestSecret

	if err := runSentinelDeregisterToken(newSentinelDeregisterTokenTestCmd(), nil); err != nil {
		t.Fatalf("runSentinelDeregisterToken: %v", err)
	}
	if err := policy.Validate("live-token", ""); err == nil {
		t.Fatal("token still valid after CLI deregistration")
	}
}

// TestSentinelDeregisterTokenCmd_EndToEndTokenPrefix is the CLI-first
// coverage for #1963's actual point: decommissioning a host by id, removing
// both its original join token and a reissued reconnect token, without the
// caller ever supplying either plaintext token.
func TestSentinelDeregisterTokenCmd_EndToEndTokenPrefix(t *testing.T) {
	var mgr sentinel.Manager
	mgr.SetAdminSecret([]byte(sentinelDeregisterTokenTestSecret))
	policy := sentinel.NewTokenPolicy()
	policy.Allow("host-a.secret1", sentinel.PoolAny)
	policy.Allow("host-a.secret2", sentinel.PoolAny)
	policy.Allow("host-b.secret1", sentinel.PoolAny)
	mgr.SetTunnelPolicy(policy)
	mgr.SetTunnelTokenStorePath(t.TempDir() + "/tunnel-tokens.json")

	mux := newSentinelTunnelTokenTestMux(&mgr)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Cleanup(resetSentinelDeregisterTokenFlags)
	resetSentinelDeregisterTokenFlags()
	sentinelDeregisterTokenSentinelURL = srv.URL
	sentinelDeregisterTokenTokenPrefix = "host-a."
	sentinelDeregisterTokenSecret = sentinelDeregisterTokenTestSecret

	if err := runSentinelDeregisterToken(newSentinelDeregisterTokenTestCmd(), nil); err != nil {
		t.Fatalf("runSentinelDeregisterToken: %v", err)
	}
	if err := policy.Validate("host-a.secret1", ""); err == nil {
		t.Fatal("original join token still valid after CLI prefix deregistration")
	}
	if err := policy.Validate("host-a.secret2", ""); err == nil {
		t.Fatal("reissued reconnect token still valid after CLI prefix deregistration")
	}
	if err := policy.Validate("host-b.secret1", ""); err != nil {
		t.Fatalf("a different host's token must survive: %v", err)
	}
}

// TestSentinelDeregisterTokenCmd_RejectsPrefixWithoutTrailingDot confirms
// the CLI surfaces the sentinel's 400 (rather than, say, swallowing it) so
// an operator sees why a malformed --token-prefix was refused.
func TestSentinelDeregisterTokenCmd_RejectsPrefixWithoutTrailingDot(t *testing.T) {
	var mgr sentinel.Manager
	mgr.SetAdminSecret([]byte(sentinelDeregisterTokenTestSecret))
	policy := sentinel.NewTokenPolicy()
	policy.Allow("abcd.xyz", sentinel.PoolAny)
	mgr.SetTunnelPolicy(policy)
	mgr.SetTunnelTokenStorePath(t.TempDir() + "/tunnel-tokens.json")

	mux := newSentinelTunnelTokenTestMux(&mgr)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Cleanup(resetSentinelDeregisterTokenFlags)
	resetSentinelDeregisterTokenFlags()
	sentinelDeregisterTokenSentinelURL = srv.URL
	sentinelDeregisterTokenTokenPrefix = "abc" // no trailing dot
	sentinelDeregisterTokenSecret = sentinelDeregisterTokenTestSecret

	err := runSentinelDeregisterToken(newSentinelDeregisterTokenTestCmd(), nil)
	if err == nil {
		t.Fatal("want an error surfaced from the sentinel's 400")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error = %q, want it to mention the sentinel's 400", err)
	}
	if verr := policy.Validate("abcd.xyz", ""); verr != nil {
		t.Fatalf("rejected prefix must not have touched the policy: %v", verr)
	}
}

// newSentinelTunnelTokenTestMux mounts both tunnel-token handlers on a
// single mux the way internal/cmd/sentinel.go wires them in production
// (POST=register, DELETE=deregister on the same path), behind the real HMAC
// admin-secret gate. mgr must already have been given
// sentinelDeregisterTokenTestSecret via SetAdminSecret.
func newSentinelTunnelTokenTestMux(mgr *sentinel.Manager) *http.ServeMux {
	secret := []byte(sentinelDeregisterTokenTestSecret)
	mux := http.NewServeMux()
	mux.Handle("/sentinel/tunnel-tokens", auth.SentinelHMACMiddleware(secret, mgr.TunnelTokenRegisterHandler()))
	mux.Handle("DELETE /sentinel/tunnel-tokens", auth.SentinelHMACMiddleware(secret, mgr.TunnelTokenDeregisterHandler()))
	return mux
}
