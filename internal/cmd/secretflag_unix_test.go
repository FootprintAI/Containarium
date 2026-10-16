//go:build !windows && !containarium_client

package cmd

import "testing"

// Covers the secret-bearing flags that only exist in the full (non-client)
// build.
func TestSecretFlagsHaveNoDisplayedDefault_FullBuild(t *testing.T) {
	if f := poolJoinCmd.Flags().Lookup("sentinel-auth-secret"); f == nil || f.DefValue != "" {
		t.Fatalf("pool join --sentinel-auth-secret displayed default = %v", f)
	}
	for _, c := range nodeCmd.Commands() {
		if f := c.Flags().Lookup("tunnel-token"); f != nil && f.DefValue != "" {
			t.Errorf("%s --tunnel-token displayed default %q", c.Name(), f.DefValue)
		}
	}
}
