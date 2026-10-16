package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestHideSecretFlagDefaults pins #2595: a flag whose default is read from
// an env var carrying a credential must not render that value in usage /
// --help output, while the variable still carries it (flag > env precedence
// is unchanged).
func TestHideSecretFlagDefaults(t *testing.T) {
	const secret = "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0.c2ln"
	var tok string
	c := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return nil }}
	c.Flags().StringVar(&tok, "token", secret, "JWT")
	hideSecretFlagDefaults(c.Flags(), "token")

	var buf bytes.Buffer
	c.SetOut(&buf)
	c.SetErr(&buf)
	_ = c.Usage()
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("usage leaks the env-supplied secret:\n%s", buf.String())
	}
	if tok != secret {
		t.Fatalf("variable lost the env value: got %q", tok)
	}
	// An explicit flag still wins over the env-derived value.
	if err := c.ParseFlags([]string{"--token", "explicit"}); err != nil {
		t.Fatal(err)
	}
	if tok != "explicit" {
		t.Fatalf("explicit flag did not override: got %q", tok)
	}
}

// TestSecretFlagsHaveNoDisplayedDefault guards the real registrations: every
// secret-bearing flag in the command tree must render an empty default.
func TestSecretFlagsHaveNoDisplayedDefault(t *testing.T) {
	cases := []struct {
		cmd  *cobra.Command
		flag string
	}{
		{rootCmd, "token"},
	}
	for _, tc := range cases {
		f := tc.cmd.Flags().Lookup(tc.flag)
		if f == nil {
			f = tc.cmd.PersistentFlags().Lookup(tc.flag)
		}
		if f == nil {
			t.Fatalf("flag %q not found on %q", tc.flag, tc.cmd.Name())
		}
		if f.DefValue != "" {
			t.Errorf("--%s on %q has displayed default %q (would print in usage)", tc.flag, tc.cmd.Name(), f.DefValue)
		}
	}
}
