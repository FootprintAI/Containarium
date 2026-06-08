package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/spf13/cobra"
)

// Phase 1.x — operator-facing token decoder.
//
// `containarium token inspect <token>` prints the JWT's
// claims in human-readable form. Pairs with the existing
// generate / revoke / refresh / list-revoked commands so
// operators have a complete read+write surface for the
// token lifecycle from the CLI.
//
// Two modes:
//   - Decode-only (default): base64-decodes the payload
//     segment and prints. No signature verification, no
//     daemon contact. Useful for "what's the jti I need
//     to revoke" or "what scopes does this token grant"
//     without needing the signing secret.
//   - Validate: with --secret / --secret-file, runs the
//     same ValidateToken path the daemon uses. Confirms
//     iss / aud / exp / signature all check out. Helpful
//     when debugging "why does the daemon reject this".

var (
	inspectTokenSecretFlag string
	inspectTokenSecretFile string
)

var tokenInspectCmd = &cobra.Command{
	Use:   "inspect <token>",
	Short: "Decode a JWT and print its claims",
	Long: `Print the JWT's claims in human-readable form. Default mode is
decode-only — base64-decodes the payload segment without any
signature check. Useful for finding the jti before revoking a
leaked token, or for checking what scopes / roles / token-type
a generated token actually carries.

Pass --secret (or --secret-file) to additionally run the daemon's
ValidateToken path — confirms signature, issuer, audience, and
expiry. This is the same validation the daemon performs at
auth time, so failures here mirror what the daemon would log.

The token never leaves the local machine. No daemon contact.`,
	Example: `  # Quick decode — what's the jti?
  containarium token inspect "$LEAKED_TOKEN"

  # Decode + signature/iss/aud/exp validate
  containarium token inspect "$TOKEN" --secret-file /etc/containarium/jwt.secret

  # Pipe through jq for scripting
  containarium token inspect "$TOKEN" --raw | jq .`,
	Args: cobra.ExactArgs(1),
	RunE: runTokenInspect,
}

// reuse the global tokenRaw flag from token.go for --raw

func init() {
	tokenCmd.AddCommand(tokenInspectCmd)
	tokenInspectCmd.Flags().StringVar(&inspectTokenSecretFlag, "secret", "", "JWT signing secret (enables signature/iss/aud/exp validation)")
	tokenInspectCmd.Flags().StringVar(&inspectTokenSecretFile, "secret-file", "", "Path to file containing the JWT signing secret")
}

// inspectedClaims is what we print. Mirrors the Claims
// struct shape but is the local CLI-facing JSON shape —
// stable independent of the auth package's internals.
type inspectedClaims struct {
	Username    string    `json:"username,omitempty"`
	Roles       []string  `json:"roles,omitempty"`
	Scopes      []string  `json:"scopes,omitempty"`
	TokenType   string    `json:"tt,omitempty"`
	Issuer      string    `json:"iss,omitempty"`
	Audience    []string  `json:"aud,omitempty"`
	JTI         string    `json:"jti,omitempty"`
	IssuedAt    time.Time `json:"iat,omitempty"`
	NotBefore   time.Time `json:"nbf,omitempty"`
	Expiry      time.Time `json:"exp,omitempty"`
	Subject     string    `json:"sub,omitempty"`
	SignatureOK bool      `json:"signature_ok"`
	Validated   bool      `json:"validated"`
}

func runTokenInspect(cmd *cobra.Command, args []string) error {
	token := strings.TrimSpace(args[0])
	if token == "" {
		return fmt.Errorf("token is empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a JWT — expected three dot-separated segments, got %d", len(parts))
	}

	// Decode the payload segment. JWT uses base64url with
	// no padding; tolerant decode tries the padded form
	// too in case someone hand-edited the token.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return fmt.Errorf("decode payload: %w", err)
		}
	}

	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return fmt.Errorf("parse payload JSON: %w", err)
	}

	inspected := claimsFromRaw(raw)

	// Optional signature validation.
	secret := inspectTokenSecretFlag
	if inspectTokenSecretFile != "" {
		b, err := os.ReadFile(inspectTokenSecretFile)
		if err != nil {
			return fmt.Errorf("read secret file: %w", err)
		}
		secret = strings.TrimSpace(string(b))
	}
	if secret != "" {
		tm, err := auth.NewTokenManager(secret, "containarium")
		if err != nil {
			return fmt.Errorf("token manager: %w", err)
		}
		if _, verr := tm.ValidateToken(token); verr == nil {
			inspected.SignatureOK = true
			inspected.Validated = true
		} else {
			inspected.Validated = true
			// SignatureOK stays false; the validator's
			// generic "invalid token" error is intentional
			// and we surface that fact rather than
			// inventing a more-specific reason.
		}
	}

	if tokenRaw {
		// JSON output for scripting / jq.
		out, _ := json.MarshalIndent(inspected, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	// Human-readable banner.
	fmt.Printf("\n═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  JWT Inspection\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")
	if inspected.Username != "" {
		fmt.Printf("  Username:  %s\n", inspected.Username)
	}
	if inspected.Subject != "" && inspected.Subject != inspected.Username {
		fmt.Printf("  Subject:   %s\n", inspected.Subject)
	}
	if len(inspected.Roles) > 0 {
		fmt.Printf("  Roles:     %v\n", inspected.Roles)
	}
	if len(inspected.Scopes) > 0 {
		fmt.Printf("  Scopes:    %v\n", inspected.Scopes)
	} else {
		fmt.Printf("  Scopes:    <none> (unrestricted)\n")
	}
	if inspected.TokenType != "" {
		fmt.Printf("  Type:      %s\n", inspected.TokenType)
	} else {
		fmt.Printf("  Type:      <unset> (legacy / access semantics)\n")
	}
	if inspected.Issuer != "" {
		fmt.Printf("  Issuer:    %s\n", inspected.Issuer)
	}
	if len(inspected.Audience) > 0 {
		fmt.Printf("  Audience:  %v\n", inspected.Audience)
	}
	if inspected.JTI != "" {
		fmt.Printf("  JTI:       %s\n", inspected.JTI)
	}
	if !inspected.IssuedAt.IsZero() {
		fmt.Printf("  Issued:    %s\n", inspected.IssuedAt.Format(time.RFC3339))
	}
	if !inspected.Expiry.IsZero() {
		now := time.Now()
		remaining := inspected.Expiry.Sub(now).Round(time.Second)
		if remaining > 0 {
			fmt.Printf("  Expires:   %s (in %s)\n", inspected.Expiry.Format(time.RFC3339), remaining)
		} else {
			fmt.Printf("  Expires:   %s (EXPIRED %s ago)\n", inspected.Expiry.Format(time.RFC3339), -remaining)
		}
	}
	if !inspected.NotBefore.IsZero() {
		fmt.Printf("  NotBefore: %s\n", inspected.NotBefore.Format(time.RFC3339))
	}
	fmt.Println()
	if inspected.Validated {
		if inspected.SignatureOK {
			fmt.Printf("  ✓ Signature valid (iss + aud + exp all check out)\n")
		} else {
			fmt.Printf("  ✗ Signature INVALID (or iss/aud/exp mismatch)\n")
		}
	} else {
		fmt.Printf("  (signature not validated — pass --secret or --secret-file to check)\n")
	}
	fmt.Println()
	return nil
}

// claimsFromRaw extracts the well-known claim names from
// the decoded payload. Tolerant — missing fields just
// stay zero. The JWT spec says exp/iat/nbf can be either
// numeric (seconds since epoch) or RFC3339; the json
// package gives us a float64 for the numeric case, which
// we coerce.
func claimsFromRaw(raw map[string]any) inspectedClaims {
	out := inspectedClaims{}
	if v, ok := raw["username"].(string); ok {
		out.Username = v
	}
	if v, ok := raw["sub"].(string); ok {
		out.Subject = v
	}
	if v, ok := raw["roles"].([]any); ok {
		for _, r := range v {
			if s, ok := r.(string); ok {
				out.Roles = append(out.Roles, s)
			}
		}
	}
	if v, ok := raw["scopes"].([]any); ok {
		for _, s := range v {
			if str, ok := s.(string); ok {
				out.Scopes = append(out.Scopes, str)
			}
		}
	}
	if v, ok := raw["tt"].(string); ok {
		out.TokenType = v
	}
	if v, ok := raw["iss"].(string); ok {
		out.Issuer = v
	}
	switch v := raw["aud"].(type) {
	case string:
		if v != "" {
			out.Audience = []string{v}
		}
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok {
				out.Audience = append(out.Audience, s)
			}
		}
	}
	if v, ok := raw["jti"].(string); ok {
		out.JTI = v
	}
	if v, ok := raw["iat"].(float64); ok {
		out.IssuedAt = time.Unix(int64(v), 0).UTC()
	}
	if v, ok := raw["nbf"].(float64); ok {
		out.NotBefore = time.Unix(int64(v), 0).UTC()
	}
	if v, ok := raw["exp"].(float64); ok {
		out.Expiry = time.Unix(int64(v), 0).UTC()
	}
	return out
}
