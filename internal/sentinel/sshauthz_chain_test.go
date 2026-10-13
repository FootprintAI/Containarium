package sentinel

import (
	"os"
	"strings"
	"testing"
)

// The integration harness builds a chain explicitly; check that the deployed
// tenant unit also places authz before session auditing and routing, using the
// daemon binary (the split client build excludes sentinel plugins).
func TestTenantSSHPiperAuthorizationChain(t *testing.T) {
	for _, path := range []string{
		"../../terraform/modules/containarium/scripts/sshpiper.service.tmpl",
		"../../terraform/gce/scripts/startup-sentinel.sh",
	} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			unit := string(data)
			authz := strings.Index(unit, "/usr/local/bin/containariumd sentinel ssh-authz-plugin")
			session := strings.Index(unit, "/usr/local/bin/containariumd sentinel ssh-session-plugin")
			if authz < 0 || session <= authz {
				t.Fatal("tenant chain must run daemon authz before session audit")
			}
			remainder := unit[session:]
			if !strings.Contains(remainder, "yaml") {
				t.Fatal("routing plugin missing after audit")
			}
			if strings.Contains(unit, "--ssh-authz-enforce") {
				t.Fatal("enforcement must not be configured by #2518")
			}
		})
	}
}
