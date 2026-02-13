package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/spf13/cobra"
)

var (
	tokenUsername   string
	tokenRoles      []string
	tokenExpiry     string
	tokenSecretFlag string
	tokenSecretFile string
	tokenRaw        bool
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

func init() {
	rootCmd.AddCommand(tokenCmd)
	tokenCmd.AddCommand(tokenGenerateCmd)

	// Required flags
	tokenGenerateCmd.Flags().StringVar(&tokenUsername, "username", "", "Username for the token (required)")
	tokenGenerateCmd.MarkFlagRequired("username")

	// Secret flags (one required)
	tokenGenerateCmd.Flags().StringVar(&tokenSecretFlag, "secret", "", "JWT secret key")
	tokenGenerateCmd.Flags().StringVar(&tokenSecretFile, "secret-file", "", "Path to file containing JWT secret key")

	// Optional flags
	tokenGenerateCmd.Flags().StringSliceVar(&tokenRoles, "roles", []string{"user"}, "Roles for the token (comma-separated)")
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
	tm := auth.NewTokenManager(secret, "containarium")

	// Generate token
	token, err := tm.GenerateToken(tokenUsername, tokenRoles, expiresIn)
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
