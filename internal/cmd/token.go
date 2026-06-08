package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/client"
	"github.com/spf13/cobra"
)

var (
	tokenUsername   string
	tokenRoles      []string
	tokenScopes     []string // Phase 1.7 — least-privilege scope list
	tokenType       string   // Phase 1.6 — "access" (default) or "refresh"
	tokenExpiry     string
	tokenSecretFlag string
	tokenSecretFile string
	tokenRaw        bool

	// `token revoke` flags
	revokeJTI       string
	revokeReason    string
	revokeExpiresAt string

	// `token refresh` flags (Phase 1.6 part B)
	refreshTokenIn   string
	refreshTokenFile string

	// `token list-revoked` flags
	listRevokedLimit          int32
	listRevokedIncludeExpired bool
	listRevokedJTIPrefix      string
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage API tokens for REST API authentication",
	Long: `Generate and manage JWT tokens for REST API authentication.

Tokens are required to authenticate REST API requests. Each token contains:
  - Username: Identity of the user
  - Roles: Permissions/roles assigned to the user
  - Expiry: When the token expires (optional)

Tokens are signed with a secret key that must match the daemon's JWT secret.`,
}

var tokenGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new API token",
	Long: `Generate a new JWT token for REST API authentication.

The generated token can be used in the Authorization header:
  Authorization: Bearer <token>

Token Expiry:
  - Use standard duration format: 24h, 168h, 720h, etc.
  - Use 0 or empty string for non-expiring tokens
  - Recommended expiry times:
    - Admin tokens: 720h (30 days)
    - User tokens: 168h (7 days)
    - Service tokens: 8760h (1 year)
    - Development tokens: 24h

Security:
  - Store tokens securely
  - Never commit tokens to version control
  - Rotate tokens periodically
  - Use short expiry times when possible`,
	Example: `  # Generate token for admin user (30 days expiry)
  containarium token generate --username admin --roles admin --expiry 720h --secret <JWT_SECRET>

  # Generate token from secret file
  containarium token generate --username alice --secret-file /etc/containarium/jwt.secret

  # Generate non-expiring service token
  containarium token generate --username service-account --roles admin,service --expiry 0 --secret <SECRET>

  # Generate development token (24h expiry)
  containarium token generate --username dev --roles user,developer --expiry 24h --secret dev-secret`,
	RunE: runTokenGenerate,
}

// tokenRevokeCmd implements `containarium token revoke` — the
// admin-facing CLI for the JWT revocation list landed in
// Phase 1.2 (PR #248). It talks to the daemon over the
// canonical HTTP gateway; the daemon does the actual write
// and enforces the admin role.
//
// Operators get the jti either from the audit trail
// (every authenticated request logs `jti=<id>`) or by
// decoding the JWT they want to kill.
var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a JWT by its jti (admin-only)",
	Long: `Add a JWT's jti to the daemon's revocation list.

The token will be rejected on the next request that names it.
Idempotent — repeated revokes preserve the original reason.

Admin-only on the server side. The daemon must be reachable
via --server, and --token must name an admin JWT.

Locate the jti to revoke either from the audit log (every
authenticated request logs jti=<id>) or by base64-decoding
the JWT payload (the 'jti' claim).`,
	Example: `  # Revoke a leaked token
  containarium token revoke \
    --jti AbCdEfGh... \
    --reason "leaked_to_public_gist_2026_05" \
    --server https://<cluster>.example.com \
    --token $ADMIN_TOKEN

  # Revoke with explicit cleanup horizon (the token's own exp)
  containarium token revoke \
    --jti AbCdEfGh... \
    --expires-at 2026-06-19T12:34:56Z \
    --server https://<cluster>.example.com \
    --token $ADMIN_TOKEN`,
	RunE: runTokenRevoke,
}

// tokenRefreshCmd implements `containarium token refresh` —
// Phase 1.6 part B. Exchanges a long-lived refresh token
// for a new short-lived access token (and a new refresh
// token, since refresh tokens are single-use). The old
// refresh token is revoked server-side on success.
var tokenRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Exchange a refresh token for a new (access, refresh) pair",
	Long: `Trade a long-lived refresh token for a new short-lived access
token. The server also issues a fresh refresh token because
refresh tokens are single-use (rotation) — save the new one
for the next exchange.

The refresh-exchange endpoint is unauthenticated: the
refresh-token body IS the credential. Do not pass --token.

Use the access token in subsequent API calls:
  Authorization: Bearer <access_token>`,
	Example: `  # From an environment variable
  containarium token refresh \
    --refresh-token "$REFRESH" \
    --server https://<cluster>.example.com

  # From a file (mode 0600 recommended)
  containarium token refresh \
    --refresh-token-file ~/.containarium/refresh \
    --server https://<cluster>.example.com`,
	RunE: runTokenRefresh,
}

// tokenListRevokedCmd implements `containarium token
// list-revoked` — admin enumeration of the revocation
// list. Confirms a revoke landed; surfaces what got killed
// during an incident window.
var tokenListRevokedCmd = &cobra.Command{
	Use:   "list-revoked",
	Short: "List active JWT revocations (admin-only)",
	Long: `Enumerate the revocation list. By default returns only
revocations whose token exp is still in the future ("active
kill-switches"); pass --include-expired for forensic queries
that need the full history.

Admin role + tokens:write scope required.`,
	Example: `  # Confirm the last revoke landed
  containarium token list-revoked --server $S --token $T

  # All revocations for a partial jti you remember
  containarium token list-revoked --jti-prefix "AbCd" --server $S --token $T

  # Forensic: every row, including expired
  containarium token list-revoked --include-expired --limit 500 --server $S --token $T`,
	RunE: runTokenListRevoked,
}

func init() {
	rootCmd.AddCommand(tokenCmd)
	tokenCmd.AddCommand(tokenGenerateCmd)
	tokenCmd.AddCommand(tokenRevokeCmd)
	tokenCmd.AddCommand(tokenRefreshCmd)
	tokenCmd.AddCommand(tokenListRevokedCmd)

	tokenRefreshCmd.Flags().StringVar(&refreshTokenIn, "refresh-token", "", "Refresh token to exchange (mutually exclusive with --refresh-token-file)")
	tokenRefreshCmd.Flags().StringVar(&refreshTokenFile, "refresh-token-file", "", "Path to file containing the refresh token (mode 0600 recommended)")

	tokenRevokeCmd.Flags().StringVar(&revokeJTI, "jti", "", "jti claim of the token to revoke (required)")
	_ = tokenRevokeCmd.MarkFlagRequired("jti")
	tokenRevokeCmd.Flags().StringVar(&revokeReason, "reason", "", "Free-form reason recorded for forensics (default: 'operator_revoke')")
	tokenRevokeCmd.Flags().StringVar(&revokeExpiresAt, "expires-at", "", "Token's own exp claim in RFC3339 (controls cleanup horizon; default: daemon max lifetime)")

	tokenListRevokedCmd.Flags().Int32Var(&listRevokedLimit, "limit", 100, "Max rows to return (server caps at 1000)")
	tokenListRevokedCmd.Flags().BoolVar(&listRevokedIncludeExpired, "include-expired", false, "Include rows whose token exp is already past (default: active only)")
	tokenListRevokedCmd.Flags().StringVar(&listRevokedJTIPrefix, "jti-prefix", "", "Narrow results to jtis with this prefix (default: all)")

	// Required flags
	tokenGenerateCmd.Flags().StringVar(&tokenUsername, "username", "", "Username for the token (required)")
	_ = tokenGenerateCmd.MarkFlagRequired("username")

	// Secret flags (one required)
	tokenGenerateCmd.Flags().StringVar(&tokenSecretFlag, "secret", "", "JWT secret key")
	tokenGenerateCmd.Flags().StringVar(&tokenSecretFile, "secret-file", "", "Path to file containing JWT secret key")

	// Optional flags
	tokenGenerateCmd.Flags().StringSliceVar(&tokenRoles, "roles", []string{"user"}, "Roles for the token (comma-separated)")
	tokenGenerateCmd.Flags().StringSliceVar(&tokenScopes, "scopes", nil, "Phase 1.7: least-privilege scopes (comma-separated; e.g. containers:read,secrets:read). Omit for an unrestricted token; pass '*' for the wildcard.")
	tokenGenerateCmd.Flags().StringVar(&tokenType, "token-type", "", "Phase 1.6: 'access' (short-lived API token) or 'refresh' (long-lived token for exchange). Empty = legacy issuance (still acts as access on the API surface).")
	tokenGenerateCmd.Flags().StringVar(&tokenExpiry, "expiry", "24h", "Token expiry duration (e.g., 24h, 168h, 720h, 0 for no expiry)")
	tokenGenerateCmd.Flags().BoolVar(&tokenRaw, "raw", false, "Output only the raw token (for scripting)")
}

func runTokenGenerate(cmd *cobra.Command, args []string) error {
	// Load JWT secret
	secret := tokenSecretFlag
	if tokenSecretFile != "" {
		secretBytes, err := os.ReadFile(tokenSecretFile)
		if err != nil {
			return fmt.Errorf("failed to read JWT secret file: %w", err)
		}
		secret = strings.TrimSpace(string(secretBytes))
	}

	if secret == "" {
		return fmt.Errorf("JWT secret is required. Use --secret or --secret-file")
	}

	// Parse expiry duration
	var expiresIn time.Duration
	var err error
	if tokenExpiry != "0" && tokenExpiry != "" {
		expiresIn, err = time.ParseDuration(tokenExpiry)
		if err != nil {
			return fmt.Errorf("invalid expiry duration '%s': %w\nExamples: 24h, 168h, 720h, 0", tokenExpiry, err)
		}
	}

	// Create token manager
	tm, err := auth.NewTokenManager(secret, "containarium")
	if err != nil {
		return fmt.Errorf("token manager: %w", err)
	}

	// Generate token. Phase 1.7 — scopes pass through as a
	// variadic; an empty slice (no --scopes) leaves the
	// claim unset, matching pre-1.7 behavior. Phase 1.6 —
	// --token-type selects access/refresh; default is the
	// legacy untagged path so existing scripts keep working.
	var token string
	switch tokenType {
	case "", "any", "legacy":
		token, err = tm.GenerateToken(tokenUsername, tokenRoles, expiresIn, tokenScopes...)
	case auth.TokenTypeAccess:
		token, err = tm.GenerateAccessToken(tokenUsername, tokenRoles, expiresIn, tokenScopes...)
	case auth.TokenTypeRefresh:
		token, err = tm.GenerateRefreshToken(tokenUsername, tokenRoles, expiresIn, tokenScopes...)
	default:
		return fmt.Errorf("invalid --token-type %q (expected: '', 'access', 'refresh')", tokenType)
	}
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	// Raw output mode for scripting
	if tokenRaw {
		fmt.Print(token)
		return nil
	}

	// Output token information
	fmt.Printf("\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  API Token Generated Successfully\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")
	fmt.Printf("Token:\n%s\n", token)
	fmt.Printf("\n")
	fmt.Printf("Details:\n")
	fmt.Printf("  Username: %s\n", tokenUsername)
	fmt.Printf("  Roles:    %v\n", tokenRoles)
	if len(tokenScopes) > 0 {
		fmt.Printf("  Scopes:   %v\n", tokenScopes)
	} else {
		fmt.Printf("  Scopes:   <none> (unrestricted)\n")
	}
	if tokenType != "" {
		fmt.Printf("  Type:     %s\n", tokenType)
	}
	if expiresIn > 0 {
		expiryTime := time.Now().Add(expiresIn)
		fmt.Printf("  Expires:  %s (%s from now)\n", expiryTime.Format(time.RFC3339), expiresIn)
	} else {
		fmt.Printf("  Expires:  Never\n")
	}
	fmt.Printf("\n")
	fmt.Printf("Usage Examples:\n")
	fmt.Printf("\n")
	fmt.Printf("  # List containers\n")
	fmt.Printf("  curl -H \"Authorization: Bearer %s\" \\\n", token)
	fmt.Printf("    http://localhost:8080/v1/containers\n")
	fmt.Printf("\n")
	fmt.Printf("  # Create container\n")
	fmt.Printf("  curl -X POST \\\n")
	fmt.Printf("    -H \"Authorization: Bearer %s\" \\\n", token)
	fmt.Printf("    -H \"Content-Type: application/json\" \\\n")
	fmt.Printf("    -d '{\"username\":\"john\",\"resources\":{\"cpu\":\"4\",\"memory\":\"8GB\",\"disk\":\"100GB\"}}' \\\n")
	fmt.Printf("    http://localhost:8080/v1/containers\n")
	fmt.Printf("\n")
	fmt.Printf("  # Environment variable (recommended)\n")
	fmt.Printf("  export TOKEN=\"%s\"\n", token)
	fmt.Printf("  curl -H \"Authorization: Bearer $TOKEN\" http://localhost:8080/v1/containers\n")
	fmt.Printf("\n")
	fmt.Printf("Security Reminder:\n")
	fmt.Printf("  • Store this token securely\n")
	fmt.Printf("  • Never commit tokens to version control\n")
	fmt.Printf("  • Rotate tokens periodically\n")
	fmt.Printf("  • Use HTTPS in production\n")
	fmt.Printf("\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")

	return nil
}

// runTokenRefresh POSTs the refresh token to /v1/tokens/refresh
// and prints the new (access, refresh) pair. The endpoint is
// unauthenticated — no --token flag needed.
func runTokenRefresh(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required (the daemon does the exchange)")
	}

	refresh := refreshTokenIn
	if refreshTokenFile != "" {
		if refresh != "" {
			return fmt.Errorf("--refresh-token and --refresh-token-file are mutually exclusive")
		}
		b, err := os.ReadFile(refreshTokenFile)
		if err != nil {
			return fmt.Errorf("read refresh token file: %w", err)
		}
		refresh = strings.TrimSpace(string(b))
	}
	if refresh == "" {
		return fmt.Errorf("--refresh-token or --refresh-token-file is required")
	}

	// The refresh endpoint is unauthenticated; create an
	// HTTP client with an empty Authorization to avoid
	// surprising header propagation.
	httpClient, err := client.NewHTTPClient(serverAddr, "")
	if err != nil {
		return fmt.Errorf("create http client: %w", err)
	}
	defer func() { _ = httpClient.Close() }()

	access, newRefresh, accessExp, refreshExp, err := httpClient.RefreshToken(refresh)
	if err != nil {
		return err
	}

	fmt.Printf("\n═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  Tokens rotated\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")
	fmt.Printf("Access token (use as Authorization: Bearer):\n%s\n\n", access)
	if accessExp > 0 {
		fmt.Printf("  Access expires:  %s\n", time.Unix(accessExp, 0).Format(time.RFC3339))
	}
	fmt.Printf("\nNEW refresh token (the one you sent is now revoked — save this):\n%s\n\n", newRefresh)
	if refreshExp > 0 {
		fmt.Printf("  Refresh expires: %s\n", time.Unix(refreshExp, 0).Format(time.RFC3339))
	}
	fmt.Printf("\n═══════════════════════════════════════════════════════════════\n\n")
	return nil
}

// runTokenRevoke POSTs to /v1/tokens/revoke. The daemon does
// the admin-role check and the actual revocation list write.
func runTokenRevoke(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required (the daemon does the revocation, not the CLI)")
	}
	if authToken == "" {
		return fmt.Errorf("--token is required (must name an admin JWT)")
	}
	if strings.TrimSpace(revokeJTI) == "" {
		return fmt.Errorf("--jti is required")
	}

	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return fmt.Errorf("create http client: %w", err)
	}
	defer func() { _ = httpClient.Close() }()

	msg, err := httpClient.RevokeToken(revokeJTI, revokeReason, revokeExpiresAt)
	if err != nil {
		return err
	}
	if msg == "" {
		msg = "jti added to revocation list"
	}
	fmt.Printf("Revoked: %s\n%s\n", revokeJTI, msg)
	return nil
}

// runTokenListRevoked GETs /v1/tokens/revoked and prints
// the rows. Admin-only on the server side; the CLI does
// the same flag-validation gate as runTokenRevoke.
func runTokenListRevoked(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	if authToken == "" {
		return fmt.Errorf("--token is required (must name an admin JWT)")
	}

	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return fmt.Errorf("create http client: %w", err)
	}
	defer func() { _ = httpClient.Close() }()

	revs, err := httpClient.ListRevokedTokens(listRevokedLimit, listRevokedIncludeExpired, listRevokedJTIPrefix)
	if err != nil {
		return err
	}
	if len(revs) == 0 {
		fmt.Println("(no revocations match)")
		return nil
	}
	fmt.Printf("%-24s  %-25s  %-25s  %s\n", "JTI", "REVOKED AT", "EXPIRES AT", "REASON")
	for _, r := range revs {
		fmt.Printf("%-24s  %-25s  %-25s  %s\n", r.JTI, r.RevokedAt, r.ExpiresAt, r.Reason)
	}
	return nil
}
