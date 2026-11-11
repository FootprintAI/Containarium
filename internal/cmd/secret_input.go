package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// maxSecretInputBytes bounds how much of a token file or stdin is read; no
// real credential comes near it.
const maxSecretInputBytes = 64 << 10

// secretInputFlags is the flag trio every command that takes a secret on its
// command line offers: the legacy --token (visible in process listings), plus
// --token-file and --stdin which keep the value off argv. Token is filled by
// the caller's own --token binding.
type secretInputFlags struct {
	Token string
	File  string
	Stdin bool
}

// addSecretInputFlags registers --token-file and --stdin on c.
func addSecretInputFlags(c *cobra.Command, f *secretInputFlags) {
	c.Flags().StringVar(&f.File, "token-file", "", "Read the token from this file (trailing whitespace trimmed; error if empty). Keeps the token out of process listings; mutually exclusive with --token and --stdin")
	c.Flags().BoolVar(&f.Stdin, "stdin", false, "Read the token from standard input. Keeps the token out of process listings; mutually exclusive with --token and --token-file")
}

// resolveSecretInput applies the one rule for every command that takes a
// secret: --token, --token-file and --stdin are mutually exclusive.
//
//   - --token-file / --stdin: the secret is read there; an unreadable or empty
//     source is an error, returned before the caller makes any request.
//   - --token alone: a deprecation warning goes to stderr (the value is never
//     echoed) and the value is returned unchanged.
//   - none: the --token flag's value (empty, or an environment-derived
//     default) is returned so the caller can fall back to its environment
//     variable or fail with its own message.
//
// tokenFlag names the --token flag; "was it passed" comes from the parsed
// flag set, not from the value, because a flag defaulted from the environment
// (secretEnvFlag) has a value without having been passed.
func resolveSecretInput(c *cobra.Command, tokenFlag string, f *secretInputFlags) (string, error) {
	tokenPassed := c.Flags().Changed(tokenFlag)
	n := 0
	for _, set := range []bool{tokenPassed, f.File != "", f.Stdin} {
		if set {
			n++
		}
	}
	if n > 1 {
		return "", fmt.Errorf("--%s, --token-file and --stdin are mutually exclusive; use only one", tokenFlag)
	}

	switch {
	case f.File != "":
		file, err := os.Open(f.File) // #nosec G304 -- operator-provided token path
		if err != nil {
			return "", fmt.Errorf("read --token-file: %w", err)
		}
		defer func() { _ = file.Close() }()
		return readSecret(file, "--token-file "+f.File)
	case f.Stdin:
		return readSecret(c.InOrStdin(), "stdin")
	case tokenPassed:
		_, _ = fmt.Fprintf(c.ErrOrStderr(), "warning: --%s is deprecated: the value is visible in process listings and shell history; use --token-file or --stdin\n", tokenFlag)
		return f.Token, nil
	}
	return f.Token, nil
}

func readSecret(r io.Reader, where string) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSecretInputBytes))
	if err != nil {
		return "", fmt.Errorf("read token from %s: %w", where, err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("token from " + where + " is empty")
	}
	return s, nil
}
