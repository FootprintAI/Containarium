package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newSecretInputProbe builds a command carrying the flag trio every
// token-taking command shares, so the helper is exercised the way commands use
// it: through parsed flags.
func newSecretInputProbe(stdin string) (*cobra.Command, *secretInputFlags, *bytes.Buffer) {
	var f secretInputFlags
	c := &cobra.Command{Use: "probe", RunE: func(*cobra.Command, []string) error { return nil }}
	c.Flags().StringVar(&f.Token, "token", "", "")
	addSecretInputFlags(c, &f)
	var stderr bytes.Buffer
	c.SetIn(strings.NewReader(stdin))
	c.SetErr(&stderr)
	c.SetOut(&stderr)
	return c, &f, &stderr
}

func TestResolveSecretInput(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", "  s3cret-value \n")
	empty := write("empty", " \n\t\n")
	missing := filepath.Join(dir, "does-not-exist")

	tests := []struct {
		name       string
		args       []string
		stdin      string
		want       string
		wantErr    string // substring; "" = success
		wantWarn   bool
		secretLeak string // must never appear in stderr
	}{
		{name: "no source", want: ""},
		{name: "token file", args: []string{"--token-file", good}, want: "s3cret-value"},
		{name: "stdin", args: []string{"--stdin"}, stdin: "from-stdin\n", want: "from-stdin"},
		{name: "token alone warns and works", args: []string{"--token", "flag-secret"}, want: "flag-secret", wantWarn: true, secretLeak: "flag-secret"},
		{name: "token with token-file refused", args: []string{"--token", "x", "--token-file", good}, wantErr: "mutually exclusive"},
		{name: "token with stdin refused", args: []string{"--token", "x", "--stdin"}, stdin: "y", wantErr: "mutually exclusive"},
		{name: "token-file with stdin refused", args: []string{"--token-file", good, "--stdin"}, stdin: "y", wantErr: "mutually exclusive"},
		{name: "unreadable file", args: []string{"--token-file", missing}, wantErr: "--token-file"},
		{name: "empty file", args: []string{"--token-file", empty}, wantErr: "empty"},
		{name: "empty stdin", args: []string{"--stdin"}, stdin: "\n", wantErr: "empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, f, stderr := newSecretInputProbe(tc.stdin)
			if err := c.ParseFlags(tc.args); err != nil {
				t.Fatalf("parse: %v", err)
			}
			got, err := resolveSecretInput(c, "token", f)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("returned %q alongside an error", got)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if warned := strings.Contains(stderr.String(), "deprecated"); warned != tc.wantWarn {
				t.Fatalf("deprecation warning = %v, want %v (stderr %q)", warned, tc.wantWarn, stderr.String())
			}
			for _, leak := range []string{"s3cret-value", "from-stdin", tc.secretLeak} {
				if leak != "" && strings.Contains(stderr.String(), leak) {
					t.Fatalf("stderr leaks the secret: %q", stderr.String())
				}
			}
		})
	}
}

// An env-derived --token default is not "passing --token": it must neither
// warn nor conflict with --token-file.
func TestResolveSecretInput_EnvDefaultIsNotAFlag(t *testing.T) {
	good := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(good, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, f, stderr := newSecretInputProbe("")
	f.Token = "env-derived" // as secretEnvFlag does before parsing
	if err := c.ParseFlags([]string{"--token-file", good}); err != nil {
		t.Fatal(err)
	}
	got, err := resolveSecretInput(c, "token", f)
	if err != nil || got != "file-secret" {
		t.Fatalf("got %q, %v; want file-secret, nil", got, err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

// Every command that takes the trio must expose all three flags.
func TestSecretInputFlagsRegistered(t *testing.T) {
	for name, c := range map[string]*cobra.Command{
		"tunnel":             tunnelCmd,
		"hypervisor-agent":   hypervisorAgentCmd,
		"token delegate":     tokenDelegateCmd,
		"token revoke":       tokenRevokeCmd,
		"token list-revoked": tokenListRevokedCmd,
	} {
		for _, fl := range []string{"token-file", "stdin"} {
			if c.Flags().Lookup(fl) == nil {
				t.Errorf("%s: missing --%s", name, fl)
			}
		}
	}
}
