package cmd

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestSecretEnvFlag_UsageNeverPrintsTheValue pins #2595: a secret taken from
// the environment must still be the flag's value, but cobra's usage and
// --help must not render it as the flag's default.
func TestSecretEnvFlag_UsageNeverPrintsTheValue(t *testing.T) {
	const secret = "eyJhbGciOiJIUzI1NiJ9.super-secret-payload.sig"
	t.Setenv("CONTAINARIUM_TEST_SECRET", secret)

	var got string
	c := &cobra.Command{Use: "probe"}
	secretEnvFlag(c.Flags(), &got, "token", "CONTAINARIUM_TEST_SECRET", "a token")

	if got != secret {
		t.Fatalf("flag value = %q, want the env value (it must still apply)", got)
	}
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	_ = c.Usage()
	_ = c.Help()
	if strings.Contains(out.String(), secret) || strings.Contains(out.String(), "super-secret") {
		t.Fatalf("usage/help leaks the secret:\n%s", out.String())
	}
}

var secretFlagName = regexp.MustCompile(`(?i)(token|secret|password|passwd)`)

// notAValue names flags that merely point at a secret (a path) rather than
// carry one; their default is not sensitive.
var notAValue = regexp.MustCompile(`(?i)(-file|-path|-dir)$`)

// TestNoSecretFlagAdvertisesADefault walks the whole command tree: any string
// flag whose name says it carries a secret must render with an empty default,
// whatever the environment held when the process started (#2595). Flags that
// only name a file holding a secret (--token-file) are exempt.
func TestNoSecretFlagAdvertisesADefault(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		check := func(f *pflag.Flag) {
			if f.Value.Type() == "string" && secretFlagName.MatchString(f.Name) && !notAValue.MatchString(f.Name) && f.DefValue != "" {
				t.Errorf("%s: flag --%s advertises default %q in usage; secrets must default to empty (use secretEnvFlag)", c.CommandPath(), f.Name, f.DefValue)
			}
		}
		c.LocalFlags().VisitAll(check)
		c.PersistentFlags().VisitAll(check)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}
