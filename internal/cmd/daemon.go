package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/mtls"
	"github.com/footprintai/containarium/internal/server"
	"github.com/spf13/cobra"
)

var (
	daemonAddress      string
	daemonPort         int
	daemonHTTPPort     int
	enableMTLS         bool
	enableREST         bool
	daemonCertsDir     string
	jwtSecret          string
	jwtSecretFile      string
	swaggerDir         string
	networkSubnet      string
	skipInfraInit      bool
	enableAppHosting   bool
	postgresConnString string
	baseDomain         string
	caddyAdminURL      string
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run Containarium as a dual-protocol daemon service (gRPC + REST)",
	Long: `Start the Containarium daemon with both gRPC and REST/HTTP APIs for container management.

The daemon provides both gRPC and REST APIs for maximum flexibility:
  - gRPC API for high-performance programmatic access (mTLS authentication)
  - REST/HTTP API for web clients and easy integration (Bearer token authentication)
  - Interactive Swagger UI for API exploration and testing
  - OpenAPI spec generation for client code generation

Security:
  - gRPC: Uses mutual TLS (mTLS) for certificate-based authentication
  - REST: Uses Bearer tokens (JWT) for HTTP authentication
  - Both protocols can run simultaneously on different ports

Examples:
  # Run with both gRPC and REST APIs
  containarium daemon --mtls --rest --jwt-secret your-secret-key

  # Run gRPC only (original behavior)
  containarium daemon --mtls --rest=false

  # Run REST only (development)
  containarium daemon --rest --jwt-secret dev-secret

  # Use JWT secret from file
  containarium daemon --mtls --rest --jwt-secret-file /etc/containarium/jwt.secret

  # Custom ports
  containarium daemon --port 50051 --http-port 8080 --rest --jwt-secret secret

  # Run as systemd service (recommended for production)
  sudo systemctl start containarium`,
	RunE: runDaemon,
}

func init() {
	rootCmd.AddCommand(daemonCmd)

	// gRPC settings
	daemonCmd.Flags().StringVar(&daemonAddress, "address", "0.0.0.0", "Address to listen on")
	daemonCmd.Flags().IntVar(&daemonPort, "port", 50051, "gRPC port to listen on")
	daemonCmd.Flags().BoolVar(&enableMTLS, "mtls", false, "Enable mutual TLS authentication for gRPC (recommended)")
	daemonCmd.Flags().StringVar(&daemonCertsDir, "certs-dir", mtls.DefaultCertsDir, "Directory containing TLS certificates")

	// HTTP/REST settings
	daemonCmd.Flags().IntVar(&daemonHTTPPort, "http-port", 8080, "HTTP/REST port to listen on")
	daemonCmd.Flags().BoolVar(&enableREST, "rest", true, "Enable HTTP/REST API gateway")

	// Authentication settings
	daemonCmd.Flags().StringVar(&jwtSecret, "jwt-secret", "", "JWT secret key for REST API authentication")
	daemonCmd.Flags().StringVar(&jwtSecretFile, "jwt-secret-file", "", "Path to file containing JWT secret key")

	// Swagger/OpenAPI settings
	daemonCmd.Flags().StringVar(&swaggerDir, "swagger-dir", "api/swagger", "Directory containing Swagger/OpenAPI files")

	// Infrastructure settings
	daemonCmd.Flags().StringVar(&networkSubnet, "network-subnet", "10.100.0.1/24", "IPv4 subnet for container network (CIDR format, e.g., 10.100.0.1/24)")
	daemonCmd.Flags().BoolVar(&skipInfraInit, "skip-infra-init", false, "Skip automatic infrastructure initialization (storage, network, profile)")

	// App hosting settings
	daemonCmd.Flags().BoolVar(&enableAppHosting, "app-hosting", false, "Enable app hosting feature (requires PostgreSQL)")
	daemonCmd.Flags().StringVar(&postgresConnString, "postgres", "", "PostgreSQL connection string for app hosting (e.g., postgres://user:pass@host:5432/db)")
	daemonCmd.Flags().StringVar(&baseDomain, "base-domain", "containarium.dev", "Base domain for app subdomains (e.g., containarium.dev)")
	daemonCmd.Flags().StringVar(&caddyAdminURL, "caddy-admin-url", "http://localhost:2019", "Caddy admin API URL for reverse proxy configuration")
}

func runDaemon(cmd *cobra.Command, args []string) error {
	// Check Incus version before starting daemon
	incusClient, err := incus.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w", err)
	}

	if warning, err := incusClient.CheckVersion(); err != nil {
		return fmt.Errorf("failed to check Incus version: %w", err)
	} else if warning != "" {
		// Print warning but continue - don't block daemon startup
		log.Printf("\n%s\n", warning)
	} else {
		// Version is OK, log it
		serverInfo, _ := incusClient.GetServerInfo()
		if serverInfo != nil {
			log.Printf("Incus version: %s (OK)", serverInfo.Environment.ServerVersion)
		}
	}

	// Initialize infrastructure (storage, network, profile) unless skipped
	if !skipInfraInit {
		log.Printf("Initializing infrastructure...")
		networkConfig := incus.NetworkConfig{
			Name:        "incusbr0",
			IPv4Address: networkSubnet,
			IPv4NAT:     true,
		}
		if err := incusClient.InitializeInfrastructure(networkConfig); err != nil {
			return fmt.Errorf("failed to initialize infrastructure: %w", err)
		}
		log.Printf("  Network: incusbr0 (%s)", networkSubnet)
		log.Printf("  Storage: default (dir)")
		log.Printf("  Profile: default (configured)")
	}

	// Load or generate JWT secret if REST is enabled
	var finalJWTSecret string
	var isRandomSecret bool
	if enableREST {
		// Priority 1: Environment variable (silent - production use)
		if envSecret := os.Getenv("CONTAINARIUM_JWT_SECRET"); envSecret != "" {
			finalJWTSecret = envSecret
			log.Printf("Using JWT secret from CONTAINARIUM_JWT_SECRET environment variable")
		} else if jwtSecretFile != "" {
			// Priority 2: Secret file (production use)
			secretBytes, err := os.ReadFile(jwtSecretFile)
			if err != nil {
				return fmt.Errorf("failed to read JWT secret file %s: %w", jwtSecretFile, err)
			}
			finalJWTSecret = strings.TrimSpace(string(secretBytes))
			log.Printf("Loaded JWT secret from file: %s", jwtSecretFile)
		} else if jwtSecret != "" {
			// Priority 3: Command-line flag (testing use)
			finalJWTSecret = jwtSecret
			log.Printf("Using JWT secret from --jwt-secret flag")
		} else {
			// Priority 4: Generate random (development use)
			finalJWTSecret = generateRandomSecret()
			isRandomSecret = true
		}
	}

	// Create dual server config
	config := &server.DualServerConfig{
		GRPCAddress:        daemonAddress,
		GRPCPort:           daemonPort,
		EnableMTLS:         enableMTLS,
		CertsDir:           daemonCertsDir,
		HTTPPort:           daemonHTTPPort,
		EnableREST:         enableREST,
		JWTSecret:          finalJWTSecret,
		SwaggerDir:         swaggerDir,
		EnableAppHosting:   enableAppHosting,
		PostgresConnString: postgresConnString,
		BaseDomain:         baseDomain,
		CaddyAdminURL:      caddyAdminURL,
	}

	// Create dual server
	dualServer, err := server.NewDualServer(config)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nReceived shutdown signal")
		cancel()
	}()

	// Start servers
	log.Printf("Containarium daemon starting...")
	log.Printf("  gRPC: %s:%d", daemonAddress, daemonPort)
	if enableMTLS {
		log.Printf("  gRPC authentication: mTLS (certificate-based)")
	} else {
		log.Printf("  gRPC authentication: INSECURE (no authentication)")
	}
	if enableREST {
		log.Printf("  HTTP/REST: %s:%d", daemonAddress, daemonHTTPPort)
		log.Printf("  REST authentication: Bearer tokens (JWT)")
		log.Printf("  Swagger UI: http://localhost:%d/swagger-ui/", daemonHTTPPort)
		log.Printf("  OpenAPI spec: http://localhost:%d/swagger.json", daemonHTTPPort)

		// If using random secret, print it prominently for easy token generation
		if isRandomSecret {
			log.Printf("")
			log.Printf("═══════════════════════════════════════════════════════════════")
			log.Printf("  🔐 JWT Secret (Auto-Generated)")
			log.Printf("═══════════════════════════════════════════════════════════════")
			log.Printf("")
			log.Printf("  %s", finalJWTSecret)
			log.Printf("")
			log.Printf("⚠️  This secret is random and temporary!")
			log.Printf("   • Tokens will be invalid after daemon restart")
			log.Printf("   • For production, use one of these methods:")
			log.Printf("     - Environment: export CONTAINARIUM_JWT_SECRET='your-secret'")
			log.Printf("     - File: --jwt-secret-file /etc/containarium/jwt.secret")
			log.Printf("     - Flag: --jwt-secret 'your-secret'")
			log.Printf("")
			log.Printf("Generate a token:")
			log.Printf("  containarium token generate --username admin --secret '%s'", finalJWTSecret)
			log.Printf("")
			log.Printf("═══════════════════════════════════════════════════════════════")
			log.Printf("")
		}
	}
	log.Printf("Press Ctrl+C to stop")

	return dualServer.Start(ctx)
}

// generateRandomSecret generates a random secret for development mode
func generateRandomSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
