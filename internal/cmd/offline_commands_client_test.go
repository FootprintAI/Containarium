//go:build containarium_client

package cmd

import "testing"

// TestOfflineCommands_SucceedWithNoServerConfigured is #1776's Done-when:
// cert generate, token inspect, token generate, and version must all
// succeed under containarium_client with no --server, no
// CONTAINARIUM_SERVER, and no credentials.json anywhere — because none of
// them ever constructs a client. This is what "the server requirement
// lives at the dial seam, not in pre-run" means in practice: adding
// resolveServerAddr to PersistentPreRunE (server_resolve_client.go) must
// not turn into an accidental pre-run gate on these.
func TestOfflineCommands_SucceedWithNoServerConfigured(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no credentials.json anywhere
	serverAddr, httpMode, authToken = "", false, ""

	t.Run("cert generate", func(t *testing.T) {
		certOutputDir = t.TempDir()
		certOrganization = "test-org"
		certDNSNames = nil
		certIPAddresses = nil
		if err := runCertGenerate(testCmd(), nil); err != nil {
			t.Errorf("runCertGenerate: %v", err)
		}
	})

	t.Run("token generate", func(t *testing.T) {
		tokenSecretFlag = "test-secret-at-least-32-bytes-long-for-hmac"
		tokenSecretFile = ""
		tokenUsername = "test-user"
		tokenRoles = nil
		tokenScopes = nil
		tokenType = ""
		tokenExpiry = "1h"
		if err := runTokenGenerate(testCmd(), nil); err != nil {
			t.Errorf("runTokenGenerate: %v", err)
		}
	})

	t.Run("token inspect", func(t *testing.T) {
		tok := makeJWT(t, map[string]any{"username": "test-user"})
		inspectTokenSecretFlag = ""
		inspectTokenSecretFile = ""
		if err := runTokenInspect(testCmd(), []string{tok}); err != nil {
			t.Errorf("runTokenInspect: %v", err)
		}
	})

	t.Run("version", func(t *testing.T) {
		versionCheck = false
		// version's Run doesn't return an error; success is "doesn't panic".
		versionCmd.Run(testCmd(), nil)
	})
}
