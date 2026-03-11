package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/container"
	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/mtls"
	"github.com/footprintai/containarium/internal/network"
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
	caddyCertDir       string
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
	daemonCmd.Flags().StringVar(&caddyAdminURL, "caddy-admin-url", "", "Caddy admin API URL for reverse proxy configuration (leave empty for auto-setup with --app-hosting)")
	daemonCmd.Flags().StringVar(&caddyCertDir, "caddy-cert-dir", "/var/lib/caddy/.local/share/caddy", "Caddy certificate directory (for sentinel cert sync via /certs endpoint)")
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

	// Wait for core containers (postgres, caddy) to be ready before proceeding.
	// This prevents the race condition where the daemon starts before core
	// containers are fully booted after a spot VM preemption/restart.
	if err := waitForCoreContainers(incusClient, 2*time.Minute); err != nil {
		log.Printf("Warning: %v", err)
		log.Printf("  Proceeding anyway — some features may be unavailable")
	}

	// Backfill role labels on core containers (for upgrades from older versions)
	backfillCoreContainerLabels(incusClient)

	// Reconcile base scripts on all running containers (best-effort, runs in background)
	go reconcileBaseScripts(incusClient)

	// Always auto-detect Caddy container IP if no URL specified
	// This ensures port forwarding (80/443 → Caddy) and route sync work
	// even without --app-hosting (e.g., after VM recreation)
	if caddyAdminURL == "" {
		log.Printf("Auto-detecting Caddy container IP...")
		if caddyInfo, err := incusClient.FindContainerByRole(incus.RoleCaddy); err != nil {
			log.Printf("Warning: Could not auto-detect Caddy container: %v", err)
			log.Printf("  Features requiring Caddy (routes, TLS, port forwarding) will not work")
			log.Printf("  To fix: ensure core Caddy container is running,")
			log.Printf("  or specify --caddy-admin-url explicitly")
		} else {
			caddyAdminURL = fmt.Sprintf("http://%s:2019", caddyInfo.IPAddress)
			log.Printf("  Detected Caddy at: %s", caddyAdminURL)

			// Set up port forwarding from host to Caddy for Let's Encrypt and HTTPS
			if network.CheckIPTablesAvailable() {
				portForwarder := network.NewPortForwarder(caddyInfo.IPAddress)
				if err := portForwarder.SetupPortForwarding(); err != nil {
					log.Printf("Warning: Failed to setup port forwarding: %v", err)
					log.Printf("  External HTTPS for app domains may not work")
					log.Printf("  You may need to manually configure iptables - see docs/CADDY-SETUP.md")
				}
			} else {
				log.Printf("Warning: iptables not available, skipping port forwarding setup")
				log.Printf("  External HTTPS for app domains may not work without manual configuration")
			}
		}
	}

	// Auto-detect VictoriaMetrics container IP
	var victoriaMetricsURL string
	if vmInfo, err := incusClient.FindContainerByRole(incus.RoleVictoriaMetrics); err == nil {
		victoriaMetricsURL = fmt.Sprintf("http://%s:%d", vmInfo.IPAddress, server.DefaultVMPort)
		log.Printf("Detected VictoriaMetrics at: %s", victoriaMetricsURL)
	} else {
		log.Printf("VictoriaMetrics auto-detect: no core-victoriametrics container found")
	}

	// Auto-detect PostgreSQL container IP if no --postgres flag specified
	if postgresConnString == "" {
		if pgInfo, err := incusClient.FindContainerByRole(incus.RolePostgres); err == nil && pgInfo.IPAddress != "" {
			postgresConnString = fmt.Sprintf(
				"postgres://%s:%s@%s:%d/%s?sslmode=disable",
				server.DefaultPostgresUser, server.DefaultPostgresPassword,
				pgInfo.IPAddress, server.DefaultPostgresPort, server.DefaultPostgresDB)
			log.Printf("Detected PostgreSQL at: %s", pgInfo.IPAddress)
		} else {
			log.Printf("PostgreSQL auto-detect: no core-postgres container found or has no IP")
		}
	}

	// Load persisted daemon config from PostgreSQL (values saved by previous runs).
	// CLI flags that were explicitly set always override DB values.
	// Uses retry logic to handle post-restart races with PostgreSQL.
	var daemonConfigStore *app.DaemonConfigStore
	if postgresConnString != "" {
		var pool *pgxpool.Pool
		var poolErr error
		for attempt := 1; attempt <= 5; attempt++ {
			pool, poolErr = pgxpool.New(context.Background(), postgresConnString)
			if poolErr != nil {
				if attempt < 5 {
					log.Printf("PostgreSQL config connection attempt %d/5 failed: %v (retrying in 3s)", attempt, poolErr)
					time.Sleep(3 * time.Second)
				}
				continue
			}
			if pingErr := pool.Ping(context.Background()); pingErr != nil {
				pool.Close()
				pool = nil
				poolErr = pingErr
				if attempt < 5 {
					log.Printf("PostgreSQL config ping attempt %d/5 failed: %v (retrying in 3s)", attempt, pingErr)
					time.Sleep(3 * time.Second)
				}
				continue
			}
			break
		}
		if pool != nil {
			cs, csErr := app.NewDaemonConfigStore(context.Background(), pool)
			if csErr == nil {
				daemonConfigStore = cs
				savedConfig, loadErr := cs.GetAll(context.Background())
				if loadErr == nil && len(savedConfig) > 0 {
					log.Printf("Loaded daemon config from PostgreSQL (%d keys)", len(savedConfig))
					if !cmd.Flags().Changed("base-domain") {
						if v, ok := savedConfig["base_domain"]; ok {
							baseDomain = v
							log.Printf("  base-domain = %s (from DB)", v)
						}
					}
					if !cmd.Flags().Changed("http-port") {
						if v, ok := savedConfig["http_port"]; ok {
							if parsed, err := strconv.Atoi(v); err == nil {
								daemonHTTPPort = parsed
								log.Printf("  http-port = %d (from DB)", parsed)
							}
						}
					}
					if !cmd.Flags().Changed("port") {
						if v, ok := savedConfig["grpc_port"]; ok {
							if parsed, err := strconv.Atoi(v); err == nil {
								daemonPort = parsed
								log.Printf("  port = %d (from DB)", parsed)
							}
						}
					}
					if !cmd.Flags().Changed("address") {
						if v, ok := savedConfig["listen_address"]; ok {
							daemonAddress = v
							log.Printf("  address = %s (from DB)", v)
						}
					}
					if !cmd.Flags().Changed("mtls") {
						if v, ok := savedConfig["enable_mtls"]; ok {
							if parsed, err := strconv.ParseBool(v); err == nil {
								enableMTLS = parsed
								log.Printf("  mtls = %v (from DB)", parsed)
							}
						}
					}
					if !cmd.Flags().Changed("rest") {
						if v, ok := savedConfig["enable_rest"]; ok {
							if parsed, err := strconv.ParseBool(v); err == nil {
								enableREST = parsed
								log.Printf("  rest = %v (from DB)", parsed)
							}
						}
					}
					if !cmd.Flags().Changed("app-hosting") {
						if v, ok := savedConfig["enable_app_hosting"]; ok {
							if parsed, err := strconv.ParseBool(v); err == nil {
								enableAppHosting = parsed
								log.Printf("  app-hosting = %v (from DB)", parsed)
							}
						}
					}
				} else if loadErr != nil {
					log.Printf("Warning: Failed to load daemon config from DB: %v", loadErr)
				}
			} else {
				log.Printf("Warning: Failed to create daemon config store: %v", csErr)
				pool.Close()
			}
		} else {
			log.Printf("Warning: Failed to connect to PostgreSQL for config after 5 attempts: %v", poolErr)
		}
	}

	// Save recovery config to persistent storage (for disaster recovery)
	if err := saveRecoveryConfigToPersistentStorage(networkSubnet, baseDomain, caddyAdminURL, jwtSecretFile, enableAppHosting); err != nil {
		// Log warning but don't fail - recovery config is optional
		log.Printf("Warning: Failed to save recovery config: %v", err)
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
		GRPCAddress:          daemonAddress,
		GRPCPort:             daemonPort,
		EnableMTLS:           enableMTLS,
		CertsDir:             daemonCertsDir,
		HTTPPort:             daemonHTTPPort,
		EnableREST:           enableREST,
		JWTSecret:            finalJWTSecret,
		SwaggerDir:           swaggerDir,
		EnableAppHosting:     enableAppHosting,
		PostgresConnString:   postgresConnString,
		BaseDomain:           baseDomain,
		CaddyAdminURL:        caddyAdminURL,
		HostIP:               hostIPFromCIDR(networkSubnet),
		DaemonConfigStore:    daemonConfigStore,
		CaddyCertDir:         caddyCertDir,
		VictoriaMetricsURL:   victoriaMetricsURL,
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

// hostIPFromCIDR extracts the host IP address from a CIDR notation string.
// e.g., "10.100.0.1/24" → "10.100.0.1"
func hostIPFromCIDR(cidr string) string {
	if idx := strings.Index(cidr, "/"); idx > 0 {
		return cidr[:idx]
	}
	return cidr
}

// backfillCoreContainerLabels ensures role labels and boot priority are set on
// core containers. This handles upgrades from older versions that lack labels.
func backfillCoreContainerLabels(incusClient *incus.Client) {
	type coreContainer struct {
		name     string
		role     incus.Role
		priority string
	}
	cores := []coreContainer{
		{server.CorePostgresContainer, incus.RolePostgres, "100"},
		{server.CoreCaddyContainer, incus.RoleCaddy, "90"},
		{server.CoreVictoriaMetricsContainer, incus.RoleVictoriaMetrics, "80"},
		{server.CoreSecurityContainer, incus.RoleSecurity, "70"},
	}
	for _, c := range cores {
		cfg, _, err := incusClient.GetRawInstance(c.name)
		if err != nil {
			continue // container doesn't exist
		}
		if cfg[incus.RoleKey] == "" {
			if err := incusClient.UpdateContainerConfig(c.name, incus.RoleKey, string(c.role)); err == nil {
				log.Printf("Backfilled role=%s on %s", c.role, c.name)
			}
		}
		if cfg["boot.autostart.priority"] == "" {
			incusClient.UpdateContainerConfig(c.name, "boot.autostart.priority", c.priority)
		}
		if cfg["boot.autostart"] == "" {
			incusClient.UpdateContainerConfig(c.name, "boot.autostart", "true")
		}
	}
}

// reconcileBaseScripts ensures all running containers have base scripts applied.
// It runs in the background at daemon startup. Containers that already have the
// scripts are fast (apt-get install is a no-op for already-installed packages).
func reconcileBaseScripts(incusClient *incus.Client) {
	log.Printf("Reconciling base scripts on all running containers...")

	mgr, err := container.New()
	if err != nil {
		log.Printf("Warning: base script reconciliation failed: %v", err)
		return
	}

	containers, err := incusClient.ListContainers()
	if err != nil {
		log.Printf("Warning: base script reconciliation failed: %v", err)
		return
	}

	for _, c := range containers {
		if c.State != "Running" {
			continue
		}

		// Derive the lookup name for InstallStack:
		// - "hsin-container" → pass "hsin" (InstallStack adds "-container" back)
		// - "containarium-core-caddy" → pass as-is (fallback to literal name)
		lookupName := c.Name
		if strings.HasSuffix(c.Name, "-container") {
			lookupName = strings.TrimSuffix(c.Name, "-container")
		}

		if err := mgr.InstallStack(lookupName, "ntp"); err != nil {
			log.Printf("Warning: failed to apply ntp to %s: %v", c.Name, err)
		}
	}

	log.Printf("Base script reconciliation complete")
}

// waitForCoreContainers discovers core containers by role label and waits for
// each to be healthy (TCP-reachable on their primary port). This prevents the
// daemon from proceeding before PostgreSQL and Caddy are ready after a
// spot VM preemption/restart.
func waitForCoreContainers(incusClient *incus.Client, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	log.Printf("Waiting for core containers to be ready...")

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for core containers to be ready")
		default:
		}

		allReady := true

		// Check PostgreSQL (TCP 5432)
		if info, err := incusClient.FindContainerByRole(incus.RolePostgres); err == nil {
			conn, err := net.DialTimeout("tcp", info.IPAddress+":5432", 2*time.Second)
			if err != nil {
				allReady = false
			} else {
				conn.Close()
			}
		} else {
			allReady = false
		}

		// Check Caddy (HTTP admin API on 2019)
		if info, err := incusClient.FindContainerByRole(incus.RoleCaddy); err == nil {
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Get("http://" + info.IPAddress + ":2019/config/")
			if err != nil {
				allReady = false
			} else {
				resp.Body.Close()
			}
		} else {
			allReady = false
		}

		// Check VictoriaMetrics (HTTP health on 8428) — lenient: skip if container doesn't exist
		if info, err := incusClient.FindContainerByRole(incus.RoleVictoriaMetrics); err == nil {
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Get("http://" + info.IPAddress + ":8428/health")
			if err != nil {
				allReady = false
			} else {
				resp.Body.Close()
			}
		}
		// If VM container doesn't exist, don't block — it's optional

		if allReady {
			log.Printf("All core containers ready")
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

// saveRecoveryConfigToPersistentStorage saves recovery config to persistent disk
// This enables auto-recovery after instance recreation
func saveRecoveryConfigToPersistentStorage(networkCIDR, baseDomain, caddyAdminURL, jwtSecretFile string, appHosting bool) error {
	// Only save if the persistent storage path exists
	persistentDir := "/mnt/incus-data"
	if _, err := os.Stat(persistentDir); os.IsNotExist(err) {
		// Persistent storage not mounted, skip
		return nil
	}

	// Try to get ZFS source from current storage pool
	zfsSource := ""
	cmd := exec.Command("incus", "storage", "get", "default", "source")
	output, err := cmd.Output()
	if err == nil {
		zfsSource = strings.TrimSpace(string(output))
	}

	config := &RecoveryConfig{
		NetworkName:     "incusbr0",
		NetworkCIDR:     networkCIDR,
		StoragePoolName: "default",
		StorageDriver:   "zfs",
		ZFSSource:       zfsSource,
		DaemonFlags: DaemonConfig{
			Address:       daemonAddress,
			Port:          daemonPort,
			HTTPPort:      daemonHTTPPort,
			BaseDomain:    baseDomain,
			CaddyAdminURL: caddyAdminURL,
			JWTSecretFile: jwtSecretFile,
			AppHosting:    appHosting,
			SkipInfraInit: true, // Always skip on recovery
		},
	}

	return SaveRecoveryConfig(config, DefaultRecoveryConfigPath)
}
