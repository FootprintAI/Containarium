package cmd

import (
	"context"

	"github.com/spf13/cobra"
)

// testCmd returns a *cobra.Command with a real context — a bare
// &cobra.Command{} has a nil Context() (unlike OutOrStdout/ErrOrStderr,
// which do fall back), which panics deep inside net/context on first use.
//
// Deliberately untagged (both build sets): originally lived in
// pool_join_test.go, but security_sentry_test.go/security_findings_test.go/
// security_bad_destinations_test.go — tests for commands that stay in both
// binaries — depend on it too, so it can't move behind
// !containarium_client with the rest of pool_join_test.go (#1774).
func testCmd() *cobra.Command {
	c := &cobra.Command{}
	c.SetContext(context.Background())
	return c
}
