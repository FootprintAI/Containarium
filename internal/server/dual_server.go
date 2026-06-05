package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/alert"
	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/autosleep"
	"github.com/footprintai/containarium/internal/cloud"
	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/gateway"
	"github.com/footprintai/containarium/internal/guacamole"
	"github.com/footprintai/containarium/internal/metrics"
	"github.com/footprintai/containarium/internal/mtls"
	"github.com/footprintai/containarium/internal/pentest"
	secretsstore "github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/internal/security"
	"github.com/footprintai/containarium/internal/traffic"
	"github.com/footprintai/containarium/internal/ttlsweeper"
	"github.com/footprintai/containarium/internal/wake"
	zapscanner "github.com/footprintai/containarium/internal/zap"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/network"
	corecryptosecrets "github.com/footprintai/containarium/pkg/core/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// DualServerConfig holds configuration for the dual server
type DualServerConfig struct {
	// gRPC settings
	GRPCAddress string
	GRPCPort    int
	EnableMTLS  bool
	CertsDir    string

	// HTTP/REST settings
	HTTPPort   int
	EnableREST bool

	// Authentication settings
	JWTSecret string

	// Swagger settings
	SwaggerDir string

	// App hosting settings (optional)
	EnableAppHosting   bool
	PostgresConnString string
	BaseDomain         string
	CaddyAdminURL      string

	// Route sync settings
	RouteSyncInterval time.Duration // Interval for syncing routes to Caddy (default 5s)

	// Caddy certificate directory for /certs endpoint (sentinel cert sync)
	CaddyCertDir string

	// VictoriaMetrics URL (auto-detected or provided)
	VictoriaMetricsURL string

	// OTelDropLabels are operator-supplied attribute keys that the
	// app-side OTel collector drops in addition to the built-in
	// PII/cardinality defaults (see DefaultOTelDropLabels). Empty
	// means "defaults only."
	OTelDropLabels []string

	// Host IP (extracted from network CIDR, e.g., "10.100.0.1")
	HostIP string

	// DaemonConfigStore for persisting daemon config to PostgreSQL (optional)
	DaemonConfigStore *app.DaemonConfigStore

	// Standalone mode: skip all PostgreSQL/core container dependencies
	Standalone bool

	// Multi-backend peer settings
	SentinelURL    string   // URL for auto-discovering tunnel peers (e.g., "http://10.128.0.5:8081")
	Peers          []string // Static peer addresses (e.g., ["10.128.0.5:18001"])
	LocalBackendID string   // This daemon's backend ID (defaults to hostname)
	Pool           string   // Pool name to filter sentinel peer discovery (empty = no filter)

	// Sentinel primary registration (multi-pool routing). Empty PublicHostname
	// disables registration; the daemon still works as a single-pool primary.
	PublicHostname    string   // primary's own subdomain (e.g. prod.example.com)
	PublicAliases     []string // additional hostnames the primary's Caddy serves (e.g. api.example.com, voice.example.com)
	PublicBaseDomains []string // suffix-match anchors advertised to the sentinel; <anything>.<one-of-these> routes here. List multiple to host workloads under different parent domains on the same backend (see docs/PER-POOL-BASE-DOMAIN.md)
	PublicPort        int      // TLS port the sentinel forwards to (typically 443)

	// SSHHost is the public host clients dial to SSH into this daemon's
	// containers — the sentinel's SSH endpoint (e.g. region-a.example.com),
	// from --ssh-host. Surfaced on each Container.ssh_host so clients build
	// the connect target username@ssh_host without inferring it. Empty =
	// direct mode: ssh_host is left empty and clients use the container IP.
	SSHHost string

	// Alerting settings
	AlertWebhookURL    string // Webhook URL for alert notifications (optional)
	AlertWebhookSecret string // HMAC-SHA256 signing secret for webhook payloads (optional)

	// PROXY protocol: when true, configure Caddy with [proxy_protocol, tls]
	// listener_wrappers and trusted_proxies so containers receive the real
	// client IP via X-Forwarded-For. ProxyProtocolTrusted lists the CIDRs
	// allowed to send PROXY headers (typically the sentinel's VPC IP/32).
	ProxyProtocol        bool
	ProxyProtocolTrusted []string
}

// managementRouteDomains returns the domains the daemon serves its own
// management UI/API apex on. These are the PublicBaseDomains — the same
// list advertised to the sentinel for suffix routing — so what Caddy
// serves and what the sentinel routes here stay identical by construction
// (#213). Falls back to the single BaseDomain when PublicBaseDomains is
// unset (e.g. configs built without resolvePublicBaseDomains), keeping
// single-domain deployments unchanged.
func managementRouteDomains(cfg *DualServerConfig) []string {
	if cfg == nil {
		return nil
	}
	if len(cfg.PublicBaseDomains) > 0 {
		return cfg.PublicBaseDomains
	}
	if cfg.BaseDomain != "" {
		return []string{cfg.BaseDomain}
	}
	return nil
}

// DualServer runs both gRPC and HTTP/REST servers
type DualServer struct {
	config                *DualServerConfig
	grpcServer            *grpc.Server
	containerServer       *ContainerServer
	appServer             *AppServer
	networkServer         *NetworkServer
	trafficServer         *TrafficServer
	trafficCollector      *traffic.Collector
	gatewayServer         *gateway.GatewayServer
	tokenManager          *auth.TokenManager
	authMiddleware        *auth.AuthMiddleware
	routeStore            *app.RouteStore
	routeSyncJob          *app.RouteSyncJob
	passthroughStore      network.PassthroughStore
	passthroughSyncJob    *network.PassthroughSyncJob
	collaboratorStore     *collaborator.Store
	daemonConfigStore     *app.DaemonConfigStore
	metricsCollector      *metrics.Collector
	securityScanner       *security.Scanner
	securityStore         *security.Store
	securityServer        *SecurityServer
	auditStore            *audit.Store
	auditEventSubscriber  *audit.EventSubscriber
	sshCollector          *audit.SSHCollector
	revocationStore       *auth.PgRevocationStore // Phase 1.2 — kill-switch for issued JWTs
	alertStore            *alert.Store
	alertManager          *alert.Manager
	alertDeliveryStore    *alert.DeliveryStore
	pentestManager        *pentest.Manager
	pentestStore          *pentest.Store
	zapManager            *zapscanner.Manager
	zapStore              *zapscanner.Store
	peerPool              *PeerPool
	autoSleepManager      *autosleep.Manager
	ttlSweeperManager     *ttlsweeper.Manager    // ephemeral CI box auto-delete (#299)
	secretsReconciler     *secretsReconciler     // Phase 4.3 Phase B-3
	networkPolicyEnforcer *NetworkPolicyEnforcer // #315 Phase A — eBPF per-tenant net policy (off unless configured)
	cloudClient           *cloud.Client          // #354 — cloud-actuation client (nil unless host is enrolled)
	startTime             time.Time
}

// NewDualServer creates a new dual server instance
func NewDualServer(config *DualServerConfig) (*DualServer, error) {
	// Audit C-MED-1: when --proxy-protocol is on, the daemon
	// trusts PROXY v2 headers from the configured CIDR list. An
	// empty or wildcard list means anyone on the network can
	// spoof the X-Forwarded-For chain. The L4 proxy layer
	// already refuses these inputs (l4_proxy.go:65-72) but only
	// at the point Caddy is reconfigured — by then the daemon
	// has been live for a while. Validate at startup so the
	// failure is visible at boot.
	if config.ProxyProtocol {
		if err := validateProxyProtocolTrusted(config.ProxyProtocolTrusted); err != nil {
			return nil, fmt.Errorf("proxy-protocol-trusted misconfigured: %w", err)
		}
	}

	// Create container server
	containerServer, err := NewContainerServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create container server: %w", err)
	}

	// Create token manager. Refuses to start if the JWT secret is
	// shorter than auth.MinSecretKeyLen — fail-closed on weak crypto
	// (audit finding A-MED-2).
	tokenManager, err := auth.NewTokenManager(config.JWTSecret, "containarium")
	if err != nil {
		return nil, fmt.Errorf("token manager: %w", err)
	}

	// Create auth middleware
	authMiddleware := auth.NewAuthMiddleware(tokenManager)

	// Create gRPC server with optional mTLS.
	//
	// Audit C-HIGH-2: when EnableMTLS=true the gRPC server must
	// REJECT calls whose peer wasn't actually authenticated via
	// mTLS — the JWT-passthrough interceptor that lived here
	// before would happily forward an insecure-dialed client.
	// auth.RequireMTLSUnaryInterceptor inspects peer.AuthInfo and
	// returns Unauthenticated if no verified client cert is
	// present.
	var grpcServer *grpc.Server
	if config.EnableMTLS {
		certPaths := mtls.CertPathsFromDir(config.CertsDir)
		if !mtls.CertsExist(certPaths) {
			return nil, fmt.Errorf("TLS certificates not found in %s", config.CertsDir)
		}

		creds, err := mtls.LoadServerCredentials(certPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}

		grpcServer = grpc.NewServer(
			grpc.Creds(creds),
			grpc.UnaryInterceptor(auth.RequireMTLSUnaryInterceptor()),
			grpc.StreamInterceptor(auth.RequireMTLSStreamInterceptor()),
		)
		log.Printf("gRPC server: mTLS enabled (interceptor verifies peer cert on every call)")
	} else {
		grpcServer = grpc.NewServer(
			grpc.UnaryInterceptor(authMiddleware.GRPCUnaryInterceptor()),
			grpc.StreamInterceptor(authMiddleware.GRPCStreamInterceptor()),
		)
		log.Printf("WARNING: gRPC server running in INSECURE mode")
	}

	// Register container service
	pb.RegisterContainerServiceServer(grpcServer, containerServer)

	// ComposeAutostartService — operator-side RPC that execs
	// `agent-box compose <verb>` inside the tenant's LXC. Uses a
	// dedicated incus client (cheap; the gRPC server keeps the
	// reference for the process lifetime). Skipped on incus init
	// failure — the service is opt-in to the deploy that has incus.
	if composeIncusClient, err := incus.New(); err == nil {
		pb.RegisterComposeAutostartServiceServer(grpcServer, NewComposeAutostartServer(composeIncusClient))
		log.Printf("ComposeAutostartService registered (POST /v1/tenants/{username}/compose/{discover,enable,disable,status})")
	} else {
		log.Printf("Warning: ComposeAutostartService disabled — incus client init failed: %v", err)
	}

	// Create NetworkServer (always available for network topology)
	var networkServer *NetworkServer
	networkCIDR := "10.100.0.0/24" // Default, will be updated from incus
	networkIncusClient, err := incus.New()
	if err != nil {
		log.Printf("Warning: Failed to create incus client for network service: %v", err)
	} else {
		// Get actual network CIDR from incus
		if subnet, err := networkIncusClient.GetNetworkSubnet("incusbr0"); err == nil {
			if len(subnet) > 0 {
				networkCIDR = subnet
			}
		}
		// NetworkServer without app hosting dependencies (no proxy manager or app store)
		networkServer = NewNetworkServer(
			networkIncusClient,
			nil, // proxyManager - will be updated if app hosting is enabled
			nil, // appStore - will be updated if app hosting is enabled
			networkCIDR,
			"", // Proxy IP determined dynamically
		)
		pb.RegisterNetworkServiceServer(grpcServer, networkServer)
		log.Printf("Network service enabled")
	}

	// Register RecipeService — one-command deployment of declarative
	// GPU/app recipes. Pure orchestration over the container + network
	// servers; networkServer may be nil (expose then degrades to a warning).
	pb.RegisterRecipeServiceServer(grpcServer, NewRecipeServer(containerServer, networkServer))
	log.Printf("Recipe service enabled")

	// Register BackupService — logical (pg_dump) database backups for the
	// databases running inside containers, stored off-host (local dir or
	// GCS). Orchestration over the container manager; the GCS uploader is
	// best-effort (LOCAL-only if `gcloud` is absent). See
	// docs/DB-BACKUP-OPERATIONS.md.
	pb.RegisterBackupServiceServer(grpcServer, NewBackupServer(containerServer))
	log.Printf("Backup service enabled")

	// Register VolumeService — shared, multi-writer CephFS volumes (#384).
	// Capability-gated: create/attach are rejected unless the host has a
	// cephfs storage pool (single-node ZFS hosts get a clear error).
	pb.RegisterVolumeServiceServer(grpcServer, NewVolumeServer())
	log.Printf("Volume service enabled")

	// NetworkPolicyService — Phase A control-plane CRUD for per-tenant network
	// isolation policies (#315). Registered here (before the Postgres pool is
	// set up below) with an in-memory store; persistence (swap to
	// PostgresNetworkPolicyStore once the pool exists) and the per-veth
	// TC_INGRESS BPF loader that consumes these policies are follow-up
	// increments. Admin-gated in the handler.
	npServer := NewNetworkPolicyServer(NewMemNetworkPolicyStore())
	pb.RegisterNetworkPolicyServiceServer(grpcServer, npServer)
	log.Printf("NetworkPolicy service enabled (in-memory store; Phase A)")

	// Cloud-actuation client (#354) is constructed later, once routeStore is
	// finalized — the container actuator needs it to expose cloud routes at the
	// host edge. Declared here so it's in scope for the DualServer assembly.
	var cloudClient *cloud.Client

	// Create TrafficServer (always available, but conntrack only works on Linux)
	var trafficServer *TrafficServer
	var trafficCollector *traffic.Collector
	if networkIncusClient != nil {
		// Traffic collector needs PostgreSQL - will be set up later if app hosting enabled
		// For now, create without store and update later
		emitter := events.NewEmitter(events.GetBus())
		collectorConfig := traffic.DefaultCollectorConfig()
		collectorConfig.NetworkCIDR = networkCIDR

		// Create collector without store initially
		trafficCollector, err = traffic.NewCollector(collectorConfig, networkIncusClient, nil, emitter)
		if err != nil {
			log.Printf("Warning: Failed to create traffic collector: %v", err)
		} else {
			trafficServer = NewTrafficServer(trafficCollector)
			pb.RegisterTrafficServiceServer(grpcServer, trafficServer)
			if trafficCollector.IsAvailable() {
				log.Printf("Traffic monitoring service enabled (conntrack available)")
			} else {
				log.Printf("Traffic monitoring service enabled (conntrack unavailable - Linux only)")
			}
		}
	}

	// Create and register AppServer if app hosting is enabled
	var appServer *AppServer
	var routeStore *app.RouteStore
	var routeSyncJob *app.RouteSyncJob
	// coreServices is hoisted so alert setup can reference it later
	var coreServices *CoreServices
	// postgresConnString is hoisted so collaborator init (after skipAppHosting) can use it
	postgresConnString := config.PostgresConnString
	if config.EnableAppHosting {
		incusClient, err := incus.New()
		if err != nil {
			log.Printf("Warning: Failed to create incus client for app hosting: %v. App hosting disabled.", err)
		} else {
			// Determine PostgreSQL connection string and Caddy admin URL
			caddyAdminURL := config.CaddyAdminURL
			networkCIDR := "10.100.0.0/24"

			// Get actual network CIDR from incus
			if subnet, err := incusClient.GetNetworkSubnet("incusbr0"); err == nil {
				// Convert "10.100.0.1/24" to "10.100.0.0/24"
				parts := subnet
				if len(parts) > 0 {
					networkCIDR = subnet
				}
			}

			// If no external PostgreSQL/Caddy provided, set up core services
			if postgresConnString == "" || caddyAdminURL == "" {
				log.Printf("Setting up core services (PostgreSQL, Caddy) in containers...")

				coreServices = NewCoreServices(incusClient, CoreServicesConfig{
					NetworkCIDR: networkCIDR,
				})

				// Setup PostgreSQL if not provided
				if postgresConnString == "" {
					connString, err := coreServices.EnsurePostgres(context.Background())
					if err != nil {
						log.Printf("Warning: Failed to setup PostgreSQL: %v. App hosting disabled.", err)
						goto skipAppHosting
					}
					postgresConnString = connString
					log.Printf("PostgreSQL ready: %s", coreServices.GetPostgresIP())
				}

				// Setup Caddy if not provided
				if caddyAdminURL == "" && config.BaseDomain != "" {
					adminURL, err := coreServices.EnsureCaddy(context.Background(), config.BaseDomain)
					if err != nil {
						log.Printf("Warning: Failed to setup Caddy: %v. Proxy features disabled.", err)
					} else {
						caddyAdminURL = adminURL
						caddyIP := coreServices.GetCaddyIP()
						log.Printf("Caddy ready: %s", caddyIP)

						// Now that Caddy exists, set up host:80/443 → caddy port
						// forwarding. The earlier auto-detect at daemon startup
						// (see cmd/daemon.go:199) ran BEFORE Caddy was spawned
						// on first install, so it skipped this step. Re-running
						// it here makes first-install work without requiring a
						// daemon restart.
						if network.CheckIPTablesAvailable() {
							pf := network.NewPortForwarderWithNetwork(caddyIP, networkCIDR)
							if err := pf.SetupPortForwarding(); err != nil {
								log.Printf("Warning: Failed to setup port forwarding after Caddy bring-up: %v", err)
								log.Printf("  External HTTPS for %s may not work", config.BaseDomain)
							}
						}

						// Add DNS override so containers resolve *.baseDomain to Caddy
						// internally instead of going through the external IP (hairpin NAT).
						dnsOverride := fmt.Sprintf("address=/%s/%s", config.BaseDomain, caddyIP)
						if out, err := exec.Command("incus", "network", "set", "incusbr0", "raw.dnsmasq", dnsOverride).CombinedOutput(); err != nil { // #nosec G204 -- dnsOverride is constructed from trusted BaseDomain and CaddyIP config values
							log.Printf("Warning: failed to set DNS override for %s: %v (%s)", config.BaseDomain, err, string(out))
						} else {
							log.Printf("DNS override: *.%s -> %s (internal hairpin)", config.BaseDomain, caddyIP)
						}
					}
				}
			}

			// Setup VictoriaMetrics + Grafana if no URL provided
			victoriaMetricsURL := config.VictoriaMetricsURL
			if victoriaMetricsURL == "" {
				// Determine PostgreSQL IP for Grafana config DB
				var postgresIP string
				if coreServices != nil {
					postgresIP = coreServices.GetPostgresIP()
				}
				// If coreServices wasn't created (core containers were pre-detected),
				// look up the PostgreSQL IP from the existing container
				if postgresIP == "" {
					if pgInfo, err := incusClient.FindContainerByRole(incus.RolePostgres); err == nil {
						postgresIP = pgInfo.IPAddress
					}
				}
				if postgresIP != "" {
					// Ensure coreServices exists for EnsureVictoriaMetrics
					if coreServices == nil {
						coreServices = NewCoreServices(incusClient, CoreServicesConfig{
							NetworkCIDR: networkCIDR,
						})
					}
					vmIP, err := coreServices.EnsureVictoriaMetrics(context.Background(), postgresIP)
					if err != nil {
						log.Printf("Warning: Failed to setup VictoriaMetrics: %v. Monitoring disabled.", err)
					} else {
						victoriaMetricsURL = fmt.Sprintf("http://%s:%d", vmIP, DefaultVMPort)
						log.Printf("VictoriaMetrics ready: %s", vmIP)
					}
				}
			}
			config.VictoriaMetricsURL = victoriaMetricsURL

			// Setup alerting (vmalert + Alertmanager) if VictoriaMetrics is available
			if victoriaMetricsURL != "" {
				if coreServices == nil {
					coreServices = NewCoreServices(incusClient, CoreServicesConfig{
						NetworkCIDR: networkCIDR,
					})
				}
				// If a signing secret is configured, route Alertmanager through the
				// daemon's relay endpoint so payloads get HMAC-signed before forwarding.
				alertTargetURL := config.AlertWebhookURL
				if config.AlertWebhookSecret != "" && config.AlertWebhookURL != "" && config.HostIP != "" {
					alertTargetURL = fmt.Sprintf("http://%s:%d/internal/alert-relay", config.HostIP, config.HTTPPort)
				}
				if err := coreServices.SetupAlerting(context.Background(), alertTargetURL); err != nil {
					log.Printf("Warning: Failed to setup alerting: %v. Alerting disabled.", err)
				} else {
					log.Printf("Alerting ready (vmalert + Alertmanager)")
				}
			}

			// Setup the app-side OTel collector. Brings up
			// otelcol-contrib as a core LXC, points its OTLP
			// exporter at the local VictoriaMetrics, and wires the
			// resulting OTLP/HTTP endpoint into ContainerServer so
			// new monitoring=true containers get OTEL_*
			// env-stamping (see PR #175). Only runs when VM is
			// available — without a sink there's nothing for the
			// collector to forward to.
			if victoriaMetricsURL != "" && coreServices != nil {
				vmIP := coreServices.GetVictoriaMetricsIP()
				if vmIP == "" {
					if pgInfo, err := incusClient.FindContainerByRole(incus.RoleVictoriaMetrics); err == nil {
						vmIP = pgInfo.IPAddress
					}
				}
				if vmIP != "" {
					if _, err := coreServices.EnsureOTelCollector(context.Background(), vmIP, config.OTelDropLabels); err != nil {
						log.Printf("Warning: Failed to setup OTel collector: %v. App-emitted telemetry disabled.", err)
					} else {
						endpoint := coreServices.GetOTelCollectorEndpoint()
						containerServer.SetOTelCollectorEndpoint(endpoint)
						containerServer.SetCoreServices(coreServices)
						log.Printf("OTel collector ready: %s (drop-labels=%v)", endpoint, config.OTelDropLabels)
					}
				}
			}

			// Set up the tenant secrets store. Mirrors the
			// app-store path: shares Postgres but holds its own
			// pgxpool. Failure here only disables the secrets
			// API; the rest of the daemon keeps running.
			if secretsPool, secretsErr := connectToPostgres(postgresConnString, 5, 3*time.Second); secretsErr != nil {
				log.Printf("Warning: Failed to connect to Postgres for secrets store: %v", secretsErr)
			} else {
				key, created, kerr := corecryptosecrets.LoadOrCreateMasterKey("/etc/containarium/secrets.key")
				if kerr != nil {
					log.Printf("Warning: Failed to load secrets master key: %v. Secrets disabled.", kerr)
					secretsPool.Close()
				} else {
					if created {
						log.Printf("[secrets] NEW MASTER KEY generated at /etc/containarium/secrets.key — back this up off-host, losing it means every stored secret is unrecoverable ciphertext")
					}
					cipher, cerr := corecryptosecrets.NewCipher(key)
					if cerr != nil {
						log.Printf("Warning: Failed to construct secrets cipher: %v. Secrets disabled.", cerr)
						secretsPool.Close()
					} else {
						// Phase 4.1 — KMS backend selection via env
						// CONTAINARIUM_KMS_BACKEND=none|inproc|vault.
						// On err the store still opens in legacy mode
						// (no envelope) — operators see the WARNING
						// rather than the daemon refusing to start.
						kms, kdesc, kerr := corecryptosecrets.LoadKMSClient(key)
						if kerr != nil {
							log.Printf("Warning: KMS backend config error: %v. Secrets store falling back to legacy mode.", kerr)
							kms = nil
							kdesc = "disabled (config error)"
						}
						// Phase 4.1 Phase-E — master-key retirement
						// gate. CONTAINARIUM_REQUIRE_ENVELOPE=true
						// means every decrypt must go through KMS;
						// legacy rows are rejected. Refuse to wire
						// the Store if the gate is on but no KMS
						// backend is configured — fail-closed at
						// startup is the only safe shape.
						requireEnvelope := envBool("CONTAINARIUM_REQUIRE_ENVELOPE")
						if requireEnvelope && kms == nil {
							log.Printf("FATAL: CONTAINARIUM_REQUIRE_ENVELOPE=true but no KMS backend is configured. Set CONTAINARIUM_KMS_BACKEND=vault (or inproc for dev) before enabling retirement mode. Secrets disabled.")
							secretsPool.Close()
						} else {
							var opts []secretsstore.Option
							if kms != nil {
								opts = append(opts, secretsstore.WithKMS(kms))
							}
							if requireEnvelope {
								opts = append(opts, secretsstore.WithRequireEnvelope(true))
							}
							if store, serr := secretsstore.NewStore(context.Background(), secretsPool, cipher, opts...); serr != nil {
								log.Printf("Warning: Failed to init secrets store: %v. Secrets disabled.", serr)
								secretsPool.Close()
							} else {
								containerServer.SetSecretsStore(store)
								retirement := ""
								if requireEnvelope {
									retirement = " [legacy-rejected]"
								}
								log.Printf("Secrets store ready (file-keyed AES-256-GCM, envelope: %s%s)", kdesc, retirement)
							}
						}
					}
				}
			}

			// Connect to app store
			appStore, err := app.NewStore(context.Background(), postgresConnString)
			if err != nil {
				log.Printf("Warning: Failed to connect to app store: %v. App hosting disabled.", err)
			} else {
				appManager := app.NewManager(appStore, incusClient, app.ManagerConfig{
					BaseDomain:    config.BaseDomain,
					CaddyAdminURL: caddyAdminURL,
				})
				appServer = NewAppServer(appManager, appStore)
				pb.RegisterAppServiceServer(grpcServer, appServer)
				log.Printf("App hosting service enabled")

				// Update NetworkServer with app hosting dependencies
				if networkServer != nil {
					var proxyManager *app.ProxyManager

					if caddyAdminURL != "" {
						proxyManager = app.NewProxyManager(caddyAdminURL, config.BaseDomain).WithDNSChallenge(app.DNSChallengeFromEnv())
						// Ensure Caddy has basic server config for routes
						if err := proxyManager.EnsureServerConfig(); err != nil {
							log.Printf("Warning: Failed to ensure Caddy server config: %v", err)
						}
						if config.ProxyProtocol {
							if err := proxyManager.EnableProxyProtocol(config.ProxyProtocolTrusted); err != nil {
								log.Printf("Warning: Failed to enable PROXY protocol on Caddy: %v", err)
							} else {
								log.Printf("Caddy listener_wrappers: PROXY v2 enabled, trusted=%v", config.ProxyProtocolTrusted)
							}
						}

						// With DNS-01 configured, provision a single `*.<base-domain>`
						// wildcard so every per-region / subdomain endpoint
						// (region-a.<base>, …) gets a cert from one issuance — no
						// per-hostname HTTP-01, which sidesteps both the HTTP-01
						// redirect failure and Let's Encrypt per-domain rate limits
						// as regions scale (#389). Best-effort; per-route ProvisionTLS
						// still covers individual hostnames if this is skipped.
						if proxyManager.HasDNSChallenge() {
							if err := proxyManager.ProvisionWildcardTLS(); err != nil {
								log.Printf("Warning: failed to provision wildcard TLS (*.%s): %v", config.BaseDomain, err)
							} else {
								log.Printf("Caddy TLS: provisioned wildcard *.%s via DNS-01", config.BaseDomain)
							}
						}

						// Create L4ProxyManager for TLS passthrough (SNI-based) routing
						l4ProxyManager := app.NewL4ProxyManager(caddyAdminURL)
						if config.ProxyProtocol {
							if err := l4ProxyManager.EnableL4ProxyProtocol(config.ProxyProtocolTrusted); err != nil {
								log.Printf("Warning: Failed to enable PROXY protocol on caddy-l4: %v", err)
							}
						}

						// Create RouteStore for persistent route storage
						routeStore, err = app.NewRouteStore(context.Background(), appStore.Pool())
						if err != nil {
							log.Printf("Warning: Failed to create route store: %v", err)
						} else {
							// Create RouteSyncJob to sync PostgreSQL -> Caddy
							syncInterval := config.RouteSyncInterval
							if syncInterval == 0 {
								syncInterval = 5 * time.Second
							}
							routeSyncJob = app.NewRouteSyncJob(routeStore, proxyManager, syncInterval)
							routeSyncJob.SetL4ProxyManager(l4ProxyManager)
							log.Printf("Route persistence enabled with %v sync interval", syncInterval)
						}
					}
					networkServer.proxyManager = proxyManager
					networkServer.appStore = appStore
					networkServer.routeStore = routeStore
					networkServer.baseDomain = config.BaseDomain
					log.Printf("Network service updated with app hosting features")

					// ContainerServer also needs route store + proxy
					// manager so DeleteContainer can cascade-clean.
					containerServer.SetRouteCleanupDeps(routeStore, proxyManager)
				}

				// Update TrafficCollector with store for persistence
				if trafficCollector != nil && postgresConnString != "" {
					trafficStore, err := traffic.NewStore(context.Background(), postgresConnString)
					if err != nil {
						log.Printf("Warning: Failed to create traffic store: %v. Traffic persistence disabled.", err)
					} else {
						// Re-create collector with store
						emitter := events.NewEmitter(events.GetBus())
						collectorConfig := traffic.DefaultCollectorConfig()
						collectorConfig.NetworkCIDR = networkCIDR
						collectorConfig.PostgresConnString = postgresConnString

						newCollector, err := traffic.NewCollector(collectorConfig, incusClient, trafficStore, emitter)
						if err != nil {
							log.Printf("Warning: Failed to update traffic collector with store: %v", err)
						} else {
							trafficCollector = newCollector
							trafficServer = NewTrafficServer(trafficCollector)
							log.Printf("Traffic monitoring updated with persistence")
						}
					}
				}
			}
		}
	}
skipAppHosting:

	// For standalone peers (or any daemon without app hosting), ensure
	// core-postgres is provisioned so security scanning and other DB-dependent
	// features work. This follows the federated architecture where each node
	// is self-sufficient.
	if postgresConnString == "" && !config.EnableAppHosting {
		if envPG := os.Getenv("CONTAINARIUM_POSTGRES_URL"); envPG != "" {
			postgresConnString = envPG
		} else {
			// Try to auto-detect existing postgres container first
			if incusClient, err := incus.New(); err == nil {
				if pgInfo, err := incusClient.FindContainerByRole(incus.RolePostgres); err == nil && pgInfo.IPAddress != "" {
					postgresConnString = fmt.Sprintf(
						"postgres://%s:%s@%s:%d/%s?sslmode=disable",
						DefaultPostgresUser, DefaultPostgresPassword,
						pgInfo.IPAddress, DefaultPostgresPort, DefaultPostgresDB)
					log.Printf("Detected existing PostgreSQL at: %s", pgInfo.IPAddress)
					// Re-apply the systemd Restart=on-failure override even
					// for pre-existing containers. The non-app-hosting code
					// path doesn't go through EnsurePostgres (which would
					// normally apply this), so containers provisioned before
					// the restart-policy code existed — or rebuilt from a
					// template that pre-dates it — will silently lack
					// auto-restart on OOM. Idempotent.
					cs := NewCoreServices(incusClient, CoreServicesConfig{})
					cs.ensurePostgresRestartPolicy()
				} else {
					// No postgres container found — provision one
					log.Printf("Provisioning core-postgres for local security scanning...")
					networkCIDR := "10.100.0.0/24"
					if subnet, err := incusClient.GetNetworkSubnet("incusbr0"); err == nil {
						networkCIDR = subnet
					}
					cs := NewCoreServices(incusClient, CoreServicesConfig{
						NetworkCIDR: networkCIDR,
					})
					connString, err := cs.EnsurePostgres(context.Background())
					if err != nil {
						log.Printf("Warning: Failed to provision core-postgres: %v. DB-dependent features disabled.", err)
					} else {
						postgresConnString = connString
						log.Printf("Core PostgreSQL ready: %s", cs.GetPostgresIP())
						// Keep coreServices reference for security container provisioning
						if coreServices == nil {
							coreServices = cs
						}
					}
				}
			}
		}
	}

	// Setup collaborator store and manager (independent of app hosting)
	// postgresConnString was set by app hosting setup above, or from config
	if postgresConnString == "" {
		postgresConnString = os.Getenv("CONTAINARIUM_POSTGRES_URL")
		if postgresConnString == "" {
			postgresConnString = "postgres://containarium:containarium@10.100.0.2:5432/containarium?sslmode=disable" // #nosec G101 -- default dev credentials for local Incus container Postgres
		}
	}

	var collabStore *collaborator.Store
	if postgresConnString != "" {
		for attempt := 1; attempt <= 5; attempt++ {
			collabStore, err = collaborator.NewStore(context.Background(), postgresConnString)
			if err == nil {
				break
			}
			if attempt < 5 {
				log.Printf("Collaborator store attempt %d/5 failed: %v (retrying in 3s)", attempt, err)
				time.Sleep(3 * time.Second)
			}
		}
		if err != nil {
			log.Printf("Warning: Failed to create collaborator store: %v. Collaborator features disabled.", err)
		} else {
			collaboratorMgr := container.NewCollaboratorManager(containerServer.GetManager(), collabStore)
			containerServer.SetCollaboratorManager(collaboratorMgr)
			log.Printf("Collaborator management service enabled")
		}
	}

	// Setup route persistence and Caddy sync (independent of app hosting).
	// When app hosting is enabled, routeStore/routeSyncJob are already created above.
	// When it's not, we still need them for the management route to work after VM recreation.
	caddyAdminURL := config.CaddyAdminURL
	if routeStore == nil && postgresConnString != "" && caddyAdminURL != "" && config.BaseDomain != "" {
		pool, poolErr := connectToPostgres(postgresConnString, 5, 3*time.Second)
		if poolErr != nil {
			log.Printf("Warning: Failed to connect to PostgreSQL for route store: %v", poolErr)
		} else {
			routeStore, err = app.NewRouteStore(context.Background(), pool)
			if err != nil {
				log.Printf("Warning: Failed to create route store: %v", err)
				pool.Close()
			} else {
				proxyManager := app.NewProxyManager(caddyAdminURL, config.BaseDomain).WithDNSChallenge(app.DNSChallengeFromEnv())
				if err := proxyManager.EnsureServerConfig(); err != nil {
					log.Printf("Warning: Failed to ensure Caddy server config: %v", err)
				}
				if config.ProxyProtocol {
					if err := proxyManager.EnableProxyProtocol(config.ProxyProtocolTrusted); err != nil {
						log.Printf("Warning: Failed to enable PROXY protocol on Caddy: %v", err)
					} else {
						log.Printf("Caddy listener_wrappers: PROXY v2 enabled, trusted=%v", config.ProxyProtocolTrusted)
					}
				}

				// Create L4ProxyManager for TLS passthrough (SNI-based) routing.
				// L4 is activated lazily by RouteSyncJob when passthrough routes exist.
				l4ProxyManager := app.NewL4ProxyManager(caddyAdminURL)
				if config.ProxyProtocol {
					if err := l4ProxyManager.EnableL4ProxyProtocol(config.ProxyProtocolTrusted); err != nil {
						log.Printf("Warning: Failed to enable PROXY protocol on caddy-l4: %v", err)
					}
				}

				syncInterval := config.RouteSyncInterval
				if syncInterval == 0 {
					syncInterval = 5 * time.Second
				}
				routeSyncJob = app.NewRouteSyncJob(routeStore, proxyManager, syncInterval)
				routeSyncJob.SetL4ProxyManager(l4ProxyManager)
				log.Printf("Route persistence enabled (standalone) with %v sync interval", syncInterval)

				// Update NetworkServer so the /v1/network/routes API returns routes from PostgreSQL
				if networkServer != nil {
					networkServer.routeStore = routeStore
					networkServer.proxyManager = proxyManager
					networkServer.baseDomain = config.BaseDomain
					log.Printf("Network service updated with route store (standalone)")
				}
			}
		}
	}

	// Cloud-actuation client (#354): if this host is enrolled with a cloud
	// control plane, run the actuation client — heartbeat + WatchAssignments,
	// syncing each org's egress policy into the NetworkPolicyServer store
	// (closing the #315 loop), reconciling assigned containers, and exposing their
	// routes at the host edge via routeStore. Unenrolled (no cloud.yaml) → the
	// daemon is single-tenant and makes no outbound calls. Built here (not at
	// npServer setup) so the actuator has the finalized routeStore.
	cloudCfgPath := os.Getenv("CONTAINARIUM_CLOUD_CONFIG")
	if cloudCfgPath == "" {
		if p, perr := cloud.DefaultPath(); perr == nil {
			cloudCfgPath = p
		}
	}
	if cloudCfg, cerr := cloud.Load(cloudCfgPath); cerr != nil {
		log.Printf("Warning: failed to read cloud-actuation config %s: %v (running single-tenant)", cloudCfgPath, cerr)
	} else if cloudCfg != nil {
		cloudDeps := cloud.Deps{Policies: newCloudPolicySink(npServer)}
		if cloudActuator, actErr := newCloudContainerActuator(routeStore); actErr != nil {
			log.Printf("Warning: cloud container actuator unavailable (%v); policy sync only", actErr)
		} else {
			cloudDeps.Containers = cloudActuator // only set when non-nil (avoid nil-iface trap)
		}
		if cc, nerr := cloud.New(cloudCfg, cloudDeps); nerr != nil {
			log.Printf("Warning: cloud-actuation config invalid: %v (running single-tenant)", nerr)
		} else {
			cloudClient = cc
			log.Printf("Cloud-actuation client configured (host=%s control-plane=%s); starts with the daemon",
				cloudCfg.HostID, cloudCfg.ControlPlane)
		}
	}

	// Setup passthrough route persistence and iptables sync.
	// This mirrors the route store pattern but for TCP/UDP passthrough routes.
	var passthroughStore network.PassthroughStore
	var passthroughSyncJob *network.PassthroughSyncJob
	if postgresConnString != "" && networkServer != nil {
		pool, poolErr := connectToPostgres(postgresConnString, 5, 3*time.Second)
		if poolErr != nil {
			log.Printf("Warning: Failed to connect to PostgreSQL for passthrough store: %v", poolErr)
		} else {
			passthroughStore, err = network.NewPassthroughStore(context.Background(), pool)
			if err != nil {
				log.Printf("Warning: Failed to create passthrough store: %v", err)
				pool.Close()
			} else {
				syncInterval := config.RouteSyncInterval
				if syncInterval == 0 {
					syncInterval = 5 * time.Second
				}
				passthroughSyncJob = network.NewPassthroughSyncJob(passthroughStore, networkServer.passthroughManager, syncInterval)
				networkServer.passthroughStore = passthroughStore
				log.Printf("Passthrough route persistence enabled with %v sync interval", syncInterval)
			}
		}
	}

	// Upgrade the NetworkPolicy service from its initial in-memory store to a
	// Postgres-backed one now that postgresConnString is finalized. Best-effort:
	// on any failure we keep the in-memory store (policies won't survive a
	// restart, but the service stays up). Swap happens before grpcServer.Serve,
	// so it races with no live RPCs.
	if postgresConnString != "" {
		pool, poolErr := connectToPostgres(postgresConnString, 5, 3*time.Second)
		if poolErr != nil {
			log.Printf("Warning: Failed to connect to PostgreSQL for network policy store: %v", poolErr)
		} else if pgStore, npErr := NewPostgresNetworkPolicyStore(context.Background(), pool); npErr != nil {
			log.Printf("Warning: Failed to create Postgres network policy store: %v", npErr)
			pool.Close()
		} else {
			npServer.SetStore(pgStore)
			log.Printf("NetworkPolicy persistence enabled (Postgres store)")
		}
	}

	reflection.Register(grpcServer)

	// Create OTel metrics collector if VictoriaMetrics URL is available
	var metricsCollector *metrics.Collector
	if config.VictoriaMetricsURL != "" {
		metricsIncusClient, err := incus.New()
		if err != nil {
			log.Printf("Warning: Failed to create incus client for metrics: %v", err)
		} else {
			collectorConfig := metrics.DefaultCollectorConfig()
			collectorConfig.VictoriaMetricsURL = config.VictoriaMetricsURL
			collectorConfig.LocalBackendID = config.LocalBackendID
			mc, err := metrics.NewCollector(collectorConfig, metricsIncusClient)
			if err != nil {
				log.Printf("Warning: Failed to create OTel metrics collector: %v", err)
			} else {
				metricsCollector = mc
				log.Printf("OTel metrics collector configured (target: %s)", config.VictoriaMetricsURL)
			}
		}
	}

	// Set monitoring URLs on container server so GetMonitoringInfo works.
	// Grafana is served via reverse proxy at /grafana/ on the same host,
	// so the public URL is relative to the server's own origin.
	if config.VictoriaMetricsURL != "" {
		// The web UI derives the full Grafana URL from its own origin + /grafana/
		grafanaURL := "/grafana"
		containerServer.SetMonitoringURLs(config.VictoriaMetricsURL, grafanaURL)
	}

	// Setup ClamAV security scanner
	var securityScanner *security.Scanner
	var securityStore *security.Store
	var securityServerInstance *SecurityServer
	if postgresConnString != "" {
		securityPool, poolErr := connectToPostgres(postgresConnString, 5, 3*time.Second)
		if poolErr != nil {
			log.Printf("Warning: Failed to connect to PostgreSQL for security store: %v", poolErr)
		} else {
			securityStore, err = security.NewStore(context.Background(), securityPool)
			if err != nil {
				log.Printf("Warning: Failed to create security store: %v", err)
				securityPool.Close()
			} else {
				// Register SecurityService gRPC handler
				securityIncusClient, incusErr := incus.New()
				if incusErr != nil {
					log.Printf("Warning: Failed to create incus client for security: %v", incusErr)
				} else {
					// Create scanner first so we can pass it to the server
					securityScanner = security.NewScanner(securityIncusClient, securityStore)

					securityServerInstance = NewSecurityServer(securityStore, securityIncusClient, securityScanner)
					pb.RegisterSecurityServiceServer(grpcServer, securityServerInstance)
					log.Printf("Security service enabled")

					// Ensure security container exists (background, non-blocking)
					go func() {
						coreServices := NewCoreServices(securityIncusClient, CoreServicesConfig{
							NetworkCIDR: networkCIDR,
						})
						if err := coreServices.EnsureSecurity(context.Background()); err != nil {
							log.Printf("Warning: Failed to setup security container: %v. ClamAV scanning disabled.", err)
						} else {
							log.Printf("Security container ready")
						}
					}()
				}
			}
		}
	}

	// Setup pentest manager
	var pentestManager *pentest.Manager
	var pentestStore *pentest.Store
	if postgresConnString != "" {
		pentestPool, poolErr := connectToPostgres(postgresConnString, 5, 3*time.Second)
		if poolErr != nil {
			log.Printf("Warning: Failed to connect to PostgreSQL for pentest store: %v", poolErr)
		} else {
			pentestStore, err = pentest.NewStore(context.Background(), pentestPool)
			if err != nil {
				log.Printf("Warning: Failed to create pentest store: %v", err)
				pentestPool.Close()
			} else {
				pentestIncusClient, incusErr := incus.New()
				if incusErr != nil {
					log.Printf("Warning: Failed to create incus client for pentest: %v", incusErr)
				} else {
					var meterProvider *sdkmetric.MeterProvider
					if metricsCollector != nil {
						meterProvider = metricsCollector.MeterProvider()
					}
					pentestManager = pentest.NewManager(
						pentestStore,
						pentestIncusClient,
						routeStore,
						meterProvider,
						pentest.ManagerConfig{},
					)
					pentestServer := NewPentestServer(pentestStore, pentestManager)
					pb.RegisterPentestServiceServer(grpcServer, pentestServer)
					log.Printf("Pentest service enabled")
				}
			}
		}
	}

	// Setup ZAP scanner manager
	var zapManager *zapscanner.Manager
	var zapStore *zapscanner.Store
	if postgresConnString != "" {
		zapPool, poolErr := connectToPostgres(postgresConnString, 5, 3*time.Second)
		if poolErr != nil {
			log.Printf("Warning: Failed to connect to PostgreSQL for ZAP store: %v", poolErr)
		} else {
			zapStore, err = zapscanner.NewStore(context.Background(), zapPool)
			if err != nil {
				log.Printf("Warning: Failed to create ZAP store: %v", err)
				zapPool.Close()
			} else {
				zapManager = zapscanner.NewManager(
					zapStore,
					routeStore,
					zapscanner.ManagerConfig{},
				)
				zapServer := NewZapServer(zapStore, zapManager)
				pb.RegisterZapServiceServer(grpcServer, zapServer)
				log.Printf("ZAP service enabled")
			}
		}
	}

	// Setup audit logging store and event subscriber
	var auditStore *audit.Store
	var auditEventSubscriber *audit.EventSubscriber
	var revocationStoreLocal *auth.PgRevocationStore
	if postgresConnString != "" {
		auditPool, poolErr := connectToPostgres(postgresConnString, 5, 3*time.Second)
		if poolErr != nil {
			log.Printf("Warning: Failed to connect to PostgreSQL for audit store: %v", poolErr)
		} else {
			auditStore, err = audit.NewStore(context.Background(), auditPool)
			if err != nil {
				log.Printf("Warning: Failed to create audit store: %v", err)
				auditPool.Close()
			} else {
				auditEventSubscriber = audit.NewEventSubscriber(events.GetBus(), auditStore)
				log.Printf("Audit logging service enabled")
			}

			// Phase 1.2 — JWT revocation list. Same pool as
			// audit so we don't open a second connection just
			// for one hot-path lookup. Cleanup goroutine is
			// launched from Start() so its lifetime tracks
			// the daemon's serving context.
			revStore, revErr := auth.NewPgRevocationStore(context.Background(), auditPool)
			if revErr != nil {
				log.Printf("Warning: Failed to create JWT revocation store: %v", revErr)
			} else {
				tokenManager.SetRevocationStore(revStore)
				revocationStoreLocal = revStore
				log.Printf("JWT revocation list enabled")

				// Phase 1.2 follow-up — TokensService RPC
				// for operator revocation via CLI / MCP.
				tokensServer := NewTokensServer(tokenManager, revStore, 0)
				pb.RegisterTokensServiceServer(grpcServer, tokensServer)
				log.Printf("TokensService registered (POST /v1/tokens/revoke)")
			}
		}
	}

	// Setup SSH login collector (requires audit store + incus client)
	var sshCollector *audit.SSHCollector
	if auditStore != nil {
		sshIncusClient, incusErr := incus.New()
		if incusErr != nil {
			log.Printf("Warning: Failed to create incus client for SSH collector: %v", incusErr)
		} else {
			sshCollector = audit.NewSSHCollector(sshIncusClient, auditStore)
			log.Printf("SSH login collector configured")
		}
	}

	// Setup the eBPF network-policy enforcer (#315 Phase A). OFF by default:
	// only constructed when CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT points at a
	// compiled netpolicy.bpf.o. When unset, an existing deployment is entirely
	// unaffected. Observation-only — the program never drops, it audits
	// would-deny flows. The tenant→u32 ID registry is persisted in Postgres when
	// available (IDs must be stable across restarts) and in-memory otherwise.
	var networkPolicyEnforcer *NetworkPolicyEnforcer
	if bpfObj := os.Getenv("CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT"); bpfObj != "" && networkIncusClient != nil {
		var tenantRegistry TenantRegistry
		if postgresConnString != "" {
			if regPool, perr := connectToPostgres(postgresConnString, 5, 3*time.Second); perr != nil {
				log.Printf("Warning: tenant registry Postgres connect failed (%v); using in-memory IDs", perr)
				tenantRegistry = NewMemTenantRegistry()
			} else if pgReg, rerr := NewPostgresTenantRegistry(context.Background(), regPool); rerr != nil {
				log.Printf("Warning: tenant registry init failed (%v); using in-memory IDs", rerr)
				regPool.Close()
				tenantRegistry = NewMemTenantRegistry()
			} else {
				tenantRegistry = pgReg
			}
		} else {
			tenantRegistry = NewMemTenantRegistry()
		}
		// Second opt-in: enforcement (packet drops) only happens when the operator
		// also arms it. Without this, even a stored `--mode enforce` policy stays
		// observation-only — so an operator soaks in log_only, watches the
		// would-deny logs, finishes the allow-list, then arms enforce.
		enforceArmed := false
		switch strings.ToLower(strings.TrimSpace(os.Getenv("CONTAINARIUM_NETWORK_POLICY_ENFORCE"))) {
		case "1", "true", "yes", "on":
			enforceArmed = true
		}
		networkPolicyEnforcer = NewNetworkPolicyEnforcer(bpfObj, npServer.Store(), tenantRegistry, networkIncusClient, auditStore, events.GetBus(), enforceArmed)
		if enforceArmed {
			log.Printf("NetworkPolicy enforcer configured (obj=%s); ENFORCE ARMED — enforce-mode policies will drop packets", bpfObj)
		} else {
			log.Printf("NetworkPolicy enforcer configured (obj=%s); observation-only (set CONTAINARIUM_NETWORK_POLICY_ENFORCE=1 to arm drops)", bpfObj)
		}
	}

	// Setup alert store and manager
	var alertStore *alert.Store
	var alertManager *alert.Manager
	if postgresConnString != "" && config.VictoriaMetricsURL != "" {
		alertPool, poolErr := connectToPostgres(postgresConnString, 5, 3*time.Second)
		if poolErr != nil {
			log.Printf("Warning: Failed to connect to PostgreSQL for alert store: %v", poolErr)
		} else {
			alertStore, err = alert.NewStore(context.Background(), alertPool)
			if err != nil {
				log.Printf("Warning: Failed to create alert store: %v", err)
				alertPool.Close()
			} else {
				// Create incus client for alert manager
				alertIncusClient, incusErr := incus.New()
				if incusErr != nil {
					log.Printf("Warning: Failed to create incus client for alert manager: %v", incusErr)
				} else {
					alertManager = alert.NewManager(alertStore, alertIncusClient, CoreVictoriaMetricsContainer)
					containerServer.SetAlertManager(alertStore, alertManager, config.AlertWebhookURL, config.AlertWebhookSecret, coreServices, config.DaemonConfigStore)

					// Create delivery store on the same pool
					alertDeliveryStore, delivErr := alert.NewDeliveryStore(context.Background(), alertPool)
					if delivErr != nil {
						log.Printf("Warning: Failed to create delivery store: %v", delivErr)
					} else {
						containerServer.SetAlertDeliveryStore(alertDeliveryStore)
					}

					log.Printf("Alert management service enabled")

					// Initial sync of custom rules
					if err := alertManager.SyncRules(context.Background()); err != nil {
						log.Printf("Warning: Initial alert rules sync failed: %v", err)
					}
				}
			}
		}
	}

	// Create gateway server if REST is enabled
	var gatewayServer *gateway.GatewayServer
	if config.EnableREST {
		// Gateway needs to connect to gRPC server, so use 127.0.0.1 instead of bind address (0.0.0.0)
		grpcConnectAddr := config.GRPCAddress
		if grpcConnectAddr == "0.0.0.0" || grpcConnectAddr == "" {
			grpcConnectAddr = "127.0.0.1"
		}
		grpcAddr := fmt.Sprintf("%s:%d", grpcConnectAddr, config.GRPCPort)

		// Pass certsDir if mTLS is enabled so gateway can connect securely
		certsDir := ""
		if config.EnableMTLS {
			certsDir = config.CertsDir
		}

		gatewayServer = gateway.NewGatewayServer(
			grpcAddr,
			config.HTTPPort,
			authMiddleware,
			config.SwaggerDir,
			certsDir,
			config.CaddyCertDir,
		)

		// Sentinel-facing HMAC secret for /certs, /authorized-keys,
		// /authorized-keys/sentinel. If unset (or shorter than the
		// minimum) the gateway fails closed — every request returns
		// 401 — so an operator running without the env var sees the
		// keysync error loudly and configures it. Don't paper over.
		if secret := strings.TrimSpace(os.Getenv("CONTAINARIUM_SENTINEL_AUTH_SECRET")); secret != "" {
			if len(secret) < auth.SentinelMinSecretLen {
				log.Printf("WARNING: CONTAINARIUM_SENTINEL_AUTH_SECRET is %d bytes, want >=%d — sentinel endpoints will refuse all requests until this is fixed",
					len(secret), auth.SentinelMinSecretLen)
			}
			gatewayServer.SetSentinelAuthSecret([]byte(secret))
		} else {
			log.Printf("WARNING: CONTAINARIUM_SENTINEL_AUTH_SECRET is unset — /certs, /authorized-keys, /authorized-keys/sentinel will return 401 until configured")
		}

		// Orphan filter for /authorized-keys (#343). When a container
		// is deleted but its host user / home dir survives (userdel
		// failed under lock contention, or the user was provisioned
		// outside the normal flow), the keys endpoint used to return
		// the stale entry — sshpiper would accept the client's key
		// and then the relay would fail with "Container X not found"
		// inside the SSH session. Filtering at read time drops those
		// entries AND logs a per-orphan WARNING so operators can clean
		// up.
		if mgr := containerServer.GetManager(); mgr != nil {
			gatewayServer.SetContainerExistsFn(func(username string) bool {
				return mgr.ContainerExists(username + "-container")
			})
		}

		// Wire security store for CSV export
		if securityStore != nil {
			gatewayServer.SetSecurityStore(securityStore)
		}

		// Wire audit store for HTTP audit middleware
		if auditStore != nil {
			gatewayServer.SetAuditStore(auditStore)
		}

		// Wire Grafana reverse proxy if VictoriaMetrics is configured
		if config.VictoriaMetricsURL != "" {
			vmIP := stripHostFromURL(config.VictoriaMetricsURL)
			if vmIP != "" {
				grafanaBackend := fmt.Sprintf("http://%s:%d", vmIP, DefaultGrafanaPort)
				gatewayServer.SetGrafanaBackendURL(grafanaBackend)

				// Wire Alertmanager reverse proxy
				alertmanagerBackend := fmt.Sprintf("http://%s:%d", vmIP, DefaultAlertmanagerPort)
				gatewayServer.SetAlertmanagerBackendURL(alertmanagerBackend)
			}
		}

		// Wire Guacamole reverse proxy and API client if core Guacamole container is running
		if coreServices != nil {
			if guacIP := coreServices.GetGuacamoleIP(); guacIP != "" {
				guacBackend := fmt.Sprintf("http://%s:8080", guacIP)
				gatewayServer.SetGuacamoleBackendURL(guacBackend)

				// Wire Guacamole client into container server for auto-registration
				guacClient := guacamole.New(guacBackend)
				containerServer.SetGuacamoleClient(guacClient, "guacadmin", "guacadmin")

				log.Printf("Guacamole reverse proxy and API client configured: %s", guacBackend)
			}
		}

		// Wire alert relay config for HMAC signing
		if config.AlertWebhookURL != "" {
			gatewayServer.SetAlertRelayConfig(config.AlertWebhookURL, config.AlertWebhookSecret)
		}

		// Wire delivery recording callback into gateway for relay deliveries
		if containerServer.alertDeliveryStore != nil {
			ds := containerServer.alertDeliveryStore
			gatewayServer.SetRecordDeliveryFn(func(ctx context.Context, alertName, source, webhookURL string, success bool, httpStatus int, errMsg string, payloadSize, durationMs int) {
				d := &alert.WebhookDelivery{
					AlertName:    alertName,
					Source:       source,
					WebhookURL:   webhookURL,
					Success:      success,
					HTTPStatus:   httpStatus,
					ErrorMessage: errMsg,
					PayloadSize:  payloadSize,
					DurationMs:   durationMs,
				}
				if err := ds.Record(ctx, d); err != nil {
					log.Printf("Warning: failed to record relay delivery: %v", err)
				}
			})
		}

		log.Printf("HTTP/REST gateway enabled on port %d", config.HTTPPort)
	}

	// Wire the relay URL + callback into the container server so runtime
	// UpdateAlertingConfig can update the gateway relay config dynamically.
	if gatewayServer != nil && config.HostIP != "" {
		relayURL := fmt.Sprintf("http://%s:%d/internal/alert-relay", config.HostIP, config.HTTPPort)
		containerServer.SetAlertRelayConfig(relayURL, func(webhookURL, secret string) {
			gatewayServer.SetAlertRelayConfig(webhookURL, secret)
		})
	}

	// Phase 3 — wake-on-HTTP wiring. Requires the route store, the
	// proxy manager (both come from the app-hosting block above), the
	// container server (always present), and the gateway server (only
	// when --enable-rest). When any of those is missing, the wiring
	// degrades to a no-op: containers still auto-sleep, but they
	// won't wake on request — which mirrors the daemon's behaviour
	// before Phase 3.
	if routeStore != nil && routeSyncJob != nil && routeSyncJob.ProxyManager() != nil && config.HostIP != "" {
		wakeTracker := wake.New()
		wakeRouter := wake.NewRouter(routeSyncJob.ProxyManager(), wakeTracker, config.HostIP, config.HTTPPort)
		routeSyncJob.SetWakeTracker(wakeTracker)
		containerServer.SetWakeRouter(wakeRouter)

		if gatewayServer != nil {
			var wakeAudit wake.AuditLogger
			if auditStore != nil {
				// Reuse the autosleep adapter for symmetry with
				// the sleep side — both events land in audit_logs
				// with action="autosleep.*".
				wakeAudit = &autosleep.AuditStoreAdapter{Store: auditStore}
			}
			wakeProxy := wake.NewWakeProxy(
				NewWakeStarter(containerServer, 30),
				&routeLookupAdapter{store: routeStore},
				routeStore,
				wakeRouter,
				wakeAudit,
				30*time.Second,
			)
			// Phase 1.9 — source-IP allowlist (audit A-MED-5).
			// Loopback is always accepted; the env var adds
			// remote Caddy hosts when the daemon and Caddy are
			// on different VMs.
			if trustedProxies, err := wake.LoadTrustedProxies(); err != nil {
				log.Fatalf("wake: invalid CONTAINARIUM_WAKE_TRUSTED_PROXIES: %v", err)
			} else {
				wakeProxy.SetTrustedProxies(trustedProxies)
			}
			gatewayServer.SetWakeHandler(wakeProxy)
			log.Printf("Wake-on-HTTP enabled (wakeHost=%s wakePort=%d)", config.HostIP, config.HTTPPort)
		}
	}

	ds := &DualServer{
		config:                config,
		grpcServer:            grpcServer,
		containerServer:       containerServer,
		appServer:             appServer,
		networkServer:         networkServer,
		trafficServer:         trafficServer,
		trafficCollector:      trafficCollector,
		gatewayServer:         gatewayServer,
		tokenManager:          tokenManager,
		authMiddleware:        authMiddleware,
		routeStore:            routeStore,
		routeSyncJob:          routeSyncJob,
		passthroughStore:      passthroughStore,
		passthroughSyncJob:    passthroughSyncJob,
		collaboratorStore:     collabStore,
		daemonConfigStore:     config.DaemonConfigStore,
		metricsCollector:      metricsCollector,
		securityScanner:       securityScanner,
		securityStore:         securityStore,
		securityServer:        securityServerInstance,
		auditStore:            auditStore,
		auditEventSubscriber:  auditEventSubscriber,
		sshCollector:          sshCollector,
		revocationStore:       revocationStoreLocal,
		alertStore:            alertStore,
		alertManager:          alertManager,
		alertDeliveryStore:    containerServer.alertDeliveryStore,
		pentestManager:        pentestManager,
		pentestStore:          pentestStore,
		zapManager:            zapManager,
		zapStore:              zapStore,
		peerPool:              NewPeerPool(config.LocalBackendID, config.SentinelURL, config.Peers, config.Pool),
		networkPolicyEnforcer: networkPolicyEnforcer,
		cloudClient:           cloudClient,
		startTime:             time.Now(),
	}

	// Auto-sleep ticker is constructed in Start() once the traffic
	// collector has finalized its store wiring.
	return ds, nil
}

// Start starts both gRPC and HTTP servers
// backendsHandler serves /v1/backends/{id}/system-info — forwarding a
// per-backend system-info request to a specific peer. The list
// (GET /v1/backends) is no longer here: it is now the proto-first
// ContainerService.ListBackends RPC served via the grpc-gateway (#354),
// so this handler is mounted on the /v1/backends/ subtree only.
//
// Admin-only (Phase 1.4 / audit finding A-MED-4). The endpoint
// discloses fleet topology — peer IDs, hostnames, OS versions,
// GPU inventories — which is operator-grade info, not tenant-
// grade. The wrapping JWT middleware already validates the
// token; the inline RequireRole check refuses non-admin tokens
// with 403 before any backend is even enumerated.
func (ds *DualServer) backendsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := auth.RequireRole(r.Context(), auth.RoleAdmin); err != nil {
			http.Error(w, `{"error":"admin role required","code":403}`, http.StatusForbidden)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1/backends")
		path = strings.TrimPrefix(path, "/")

		// /v1/backends/{id}/system-info — forward system info request to specific backend
		if strings.Contains(path, "/system-info") {
			backendID := strings.Split(path, "/")[0]
			ds.handleBackendSystemInfo(w, r, backendID)
			return
		}

		http.NotFound(w, r)
	}
}

// runRevocationCleanup prunes expired JWT revocation rows on a
// fixed cadence. Phase 1.2 — once an hour is plenty; the table
// only grows when a token is actually revoked (rare), and even
// if the daemon falls behind the worst case is some extra rows
// on a B-tree lookup. One initial pass at startup catches
// anything orphaned by a prior daemon lifetime.
func (ds *DualServer) runRevocationCleanup(ctx context.Context) {
	const interval = 1 * time.Hour

	prune := func() {
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		n, err := ds.revocationStore.CleanupExpired(c, time.Now())
		if err != nil {
			log.Printf("[revocation-cleanup] failed: %v", err)
			return
		}
		if n > 0 {
			log.Printf("[revocation-cleanup] pruned %d expired rows", n)
		}
	}

	prune()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}

// handleBackendSystemInfo returns system info for a specific backend.
// For the local backend, it returns the local system info.
// For peer backends, it forwards the request to the peer.
func (ds *DualServer) handleBackendSystemInfo(w http.ResponseWriter, r *http.Request, backendID string) {
	if ds.peerPool == nil {
		http.Error(w, `{"error":"no backends configured"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Local backend — use the gRPC system info endpoint
	if backendID == ds.peerPool.LocalBackendID() {
		// Forward to local system info endpoint
		authToken := r.Header.Get("Authorization")
		if authToken == "" {
			authToken = "Bearer " + r.URL.Query().Get("token")
		}
		// Use the internal gRPC client path by proxying to ourselves
		client := &http.Client{Timeout: 10 * time.Second}
		req, _ := http.NewRequestWithContext(r.Context(), "GET", fmt.Sprintf("http://localhost:%d/v1/system/info", ds.config.HTTPPort), nil)
		req.Header.Set("Authorization", authToken)
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"failed to get local system info: %v"}`, err), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	// Peer backend — forward to peer
	peer := ds.peerPool.Get(backendID)
	if peer == nil {
		http.Error(w, fmt.Sprintf(`{"error":"backend %q not found"}`, backendID), http.StatusNotFound)
		return
	}
	if !peer.Healthy {
		http.Error(w, fmt.Sprintf(`{"error":"backend %q is not healthy"}`, backendID), http.StatusServiceUnavailable)
		return
	}

	authToken := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		authToken = authHeader[7:]
	}

	respBody, statusCode, err := peer.ForwardRequest("GET", "/v1/system/info", authToken, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to get system info from peer: %v"}`, err), http.StatusBadGateway)
		return
	}
	w.WriteHeader(statusCode)
	w.Write(respBody)
}

func (ds *DualServer) Start(ctx context.Context) error {
	// Register this primary with the sentinel (no-op if --public-hostname is unset).
	runPrimaryRegistration(ctx, PrimaryRegisterConfig{
		SentinelURL:       ds.config.SentinelURL,
		Pool:              ds.config.Pool,
		PublicHostname:    ds.config.PublicHostname,
		PublicAliases:     ds.config.PublicAliases,
		PublicBaseDomains: ds.config.PublicBaseDomains,
		Port:              ds.config.PublicPort,
		BackendID:         ds.config.LocalBackendID,
	})

	// Surface the SSH host on every Container.ssh_host. Independent of peer
	// discovery (a single-backend daemon still fronts a sentinel), so wire
	// it unconditionally; empty --ssh-host leaves ssh_host empty.
	if ds.containerServer != nil {
		ds.containerServer.SetSSHHost(ds.config.SSHHost)
	}

	// Start peer discovery for multi-backend support
	if ds.peerPool != nil {
		// Phase 0.5: bootstrap the daemon's peer-CA + leaf cert
		// BEFORE discovery starts. On success, every subsequent
		// peer-to-peer call (and the discovery poll itself) uses
		// HTTPS pinned to the sentinel-issued CA. Failure here is
		// not fatal — the daemon stays on plain HTTP (pre-0.5
		// behavior) and logs the reason.
		if err := ds.peerPool.BootstrapPKI(); err != nil {
			log.Printf("[peer-pki] bootstrap failed (%v) — staying on HTTP for peer-to-peer (audit C-CRIT-1 still open until configured)", err)
		} else {
			ds.peerPool.StartCertRenewal(ctx)
		}
		ds.peerPool.StartDiscovery(ctx)
		ds.containerServer.SetPeerPool(ds.peerPool)
		// Local-backend uptime for ListBackends (GET /v1/backends).
		ds.containerServer.SetStartTime(ds.startTime)

		// Migration runner: shells out to `incus snapshot/copy/...`.
		// Only useful in conjunction with peerPool (you can't migrate
		// to a peer you can't discover), so wire it in the same block.
		ds.containerServer.SetMigrationRunner(&incus.ExecRunner{})

		// Wire peer pool into traffic server for peer container queries
		if ds.trafficServer != nil {
			ds.trafficServer.SetPeerPool(ds.peerPool)
		}

		// Wire peer pool into security server so peer containers show in summaries
		if ds.securityServer != nil {
			ds.securityServer.SetPeerPool(ds.peerPool)
		}

		// Register /v1/backends endpoint on gateway
		if ds.gatewayServer != nil {
			ds.gatewayServer.SetBackendsHandler(ds.backendsHandler())
			// Enable terminal WebSocket proxying to peer backends
			ds.gatewayServer.SetTerminalPeerProxy(ds.peerPool)
		}
	}

	// Start traffic collector if available
	if ds.trafficCollector != nil {
		if err := ds.trafficCollector.Start(); err != nil {
			log.Printf("Warning: Failed to start traffic collector: %v", err)
		}
	}

	// Phase 1.2 — prune expired revocation rows hourly. Rows
	// whose token exp has already passed can no longer
	// authenticate anyway; keeping them around just bloats
	// the index. One pass at startup catches anything left
	// from a prior daemon lifetime.
	if ds.revocationStore != nil {
		go ds.runRevocationCleanup(ctx)
	}

	// Start auto-sleep ticker. Always-on by daemon policy; per-container
	// opt-in (AutoSleepEnabled) gates real stop behavior. Wired here so
	// the traffic collector's store, finalized during NewDualServer's
	// app-hosting block, can feed network-activity signals if present.
	if incusClient, err := incus.New(); err != nil {
		log.Printf("[autosleep] incus client unavailable: %v (ticker disabled)", err)
	} else {
		var trafficSrc autosleep.TrafficSource
		if ds.trafficCollector != nil {
			if store := ds.trafficCollector.GetStore(); store != nil {
				if pool := store.Pool(); pool != nil {
					trafficSrc = autosleep.NewTrafficStoreAdapter(pool)
				}
			}
		}
		var auditAdapter autosleep.AuditLogger
		if ds.auditStore != nil {
			auditAdapter = &autosleep.AuditStoreAdapter{Store: ds.auditStore}
		}
		ds.autoSleepManager = autosleep.NewManager(incusClient, trafficSrc, ds.containerServer, auditAdapter, autosleep.Options{})
		ds.autoSleepManager.Start(ctx)
	}

	// Start TTL sweeper (#299 scaffold + this PR's wiring). Reads
	// user.containarium.ttl_expires_at off each container's Incus
	// config every 60s; when the wall clock crosses the stamped
	// expiry (minus a 30s clock-skew grace), routes the deletion
	// through DeleteContainer so the audit + event + Caddy-cascade
	// hooks all fire. Always-on by daemon policy; per-container
	// opt-in (the TTL key must be set explicitly via SetContainerTTL).
	// Naturally cooperates with autosleep — if both ticks decide on
	// the same container in the same second, deletion is final and
	// the autosleep stop becomes a no-op against a missing container.
	if incusClient, err := incus.New(); err != nil {
		log.Printf("[ttlsweeper] incus client unavailable: %v (sweeper disabled)", err)
	} else {
		ds.ttlSweeperManager = ttlsweeper.NewManager(
			&ttlsweeperIncusAdapter{ic: incusClient},
			&ttlsweeperDeleter{cs: ds.containerServer},
			ttlsweeper.Options{},
		)
		ds.ttlSweeperManager.Start(ctx)
	}

	// Phase 4.3 Phase B-3 — file-mode secret reconciler.
	// Periodically re-stamps tmpfs secrets on running
	// containers so a bare `incus restart` not routed
	// through the daemon doesn't leave an app without its
	// /run/secrets files until the next daemon-driven
	// touch. Owned alongside the autosleep manager —
	// same shape, same lifetime.
	if ds.containerServer != nil && ds.containerServer.secretsStore != nil {
		if ic, err := incus.New(); err != nil {
			log.Printf("[secrets-reconciler] incus client unavailable: %v (reconciler disabled)", err)
		} else {
			rec := newSecretsReconciler(
				ds.containerServer.secretsStore,
				ic,
				ds.containerServer.stampSecretsOnLXC,
				0, // default interval
			)
			rec.Start(ctx)
			ds.secretsReconciler = rec
		}
	}

	// Start OTel metrics collector if available
	if ds.metricsCollector != nil {
		// Wire peer metrics fetcher so peer container metrics are pushed to VictoriaMetrics
		if ds.peerPool != nil {
			// Generate a long-lived service token for internal peer API calls
			serviceToken, err := ds.tokenManager.GenerateToken("_system", []string{"admin"}, 30*24*time.Hour)
			if err != nil {
				log.Printf("Warning: failed to generate service token for peer metrics: %v", err)
			} else {
				ds.metricsCollector.SetPeerFetcher(&PeerMetricsFetcherAdapter{
					Pool:         ds.peerPool,
					ServiceToken: serviceToken,
				})
			}
		}
		ds.metricsCollector.Start()
	}

	// Start security scanner if available
	if ds.securityScanner != nil {
		ds.securityScanner.Start(ctx)
		log.Printf("Security scanner started")

		// Subscribe to container creation events to auto-scan new containers
		go func() {
			sub := events.GetBus().Subscribe(&pb.SubscribeEventsRequest{
				ResourceTypes: []pb.ResourceType{pb.ResourceType_RESOURCE_TYPE_CONTAINER},
			})
			defer events.GetBus().Unsubscribe(sub.ID)
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-sub.Events:
					if !ok {
						return
					}
					if event.Type == pb.EventType_EVENT_TYPE_CONTAINER_CREATED {
						if ce := event.GetContainerEvent(); ce != nil && ce.Container != nil {
							name := ce.Container.Name
							// Skip core containers
							if !strings.HasPrefix(name, "containarium-core-") {
								ds.securityScanner.EnqueueNewContainer(name)
							}
						}
					}
				}
			}
		}()
	}

	// Start pentest manager if available
	if ds.pentestManager != nil {
		ds.pentestManager.Start(ctx)
		log.Printf("Pentest manager started")
	}

	// Start ZAP manager if available
	if ds.zapManager != nil {
		ds.zapManager.Start(ctx)
		log.Printf("ZAP manager started")
	}

	// Start audit event subscriber if available
	if ds.auditEventSubscriber != nil {
		ds.auditEventSubscriber.Start(ctx)
		log.Printf("Audit event subscriber started")
	}

	// Start SSH login collector if available
	if ds.sshCollector != nil {
		ds.sshCollector.Start(ctx)
		log.Printf("SSH login collector started")
	}

	// Log Grafana availability (served via reverse proxy at /grafana/ on the HTTP gateway)
	if ds.config.VictoriaMetricsURL != "" {
		log.Printf("Grafana available at /grafana/ (reverse proxy)")
	}

	// Start route sync job if available (syncs PostgreSQL -> Caddy)
	if ds.routeSyncJob != nil {
		ds.routeSyncJob.Start(ctx)
		log.Printf("Route sync job started")
	}

	// Start passthrough sync job if available (syncs PostgreSQL -> iptables)
	if ds.passthroughSyncJob != nil {
		ds.passthroughSyncJob.Start(ctx)
		log.Printf("Passthrough sync job started")
	}

	// Start the eBPF network-policy enforcer if configured (#315 Phase A). A
	// load failure (e.g. not on Linux, missing object, verifier reject) is
	// logged and the daemon continues without enforcement — it must never block
	// the daemon from serving.
	if ds.networkPolicyEnforcer != nil {
		if err := ds.networkPolicyEnforcer.Start(ctx); err != nil {
			log.Printf("Warning: network-policy enforcer failed to start: %v (continuing without it)", err)
			ds.networkPolicyEnforcer = nil
		} else {
			log.Printf("NetworkPolicy enforcer started")
		}
	}

	// Start the cloud-actuation client if the host is enrolled (#354). A dial
	// failure is logged and the daemon serves on — cloud connectivity must never
	// block local serving.
	if ds.cloudClient != nil {
		if err := ds.cloudClient.Start(ctx); err != nil {
			log.Printf("Warning: cloud-actuation client failed to start: %v (continuing without it)", err)
			ds.cloudClient = nil
		} else {
			log.Printf("Cloud-actuation client started")
		}
	}

	// Ensure a management route per served base domain persists in
	// PostgreSQL (RouteSyncJob pushes each to Caddy — host matcher + TLS
	// subject). One route per PublicBaseDomains entry, so the daemon
	// Caddies+serves the apex of every parent domain the sentinel routes
	// here (#213). Single-domain deployments resolve to [BaseDomain],
	// unchanged.
	if ds.routeStore != nil && ds.config.HostIP != "" {
		for _, domain := range managementRouteDomains(ds.config) {
			mgmtRoute := &app.RouteRecord{
				Subdomain:   domain,
				FullDomain:  domain,
				TargetIP:    ds.config.HostIP,
				TargetPort:  ds.config.HTTPPort,
				Protocol:    "http",
				Description: "Containarium management UI",
				Active:      true,
				CreatedBy:   string(app.RouteCreatorSystem),
			}
			if err := ds.routeStore.Save(ctx, mgmtRoute); err != nil {
				log.Printf("Warning: Failed to ensure management route for %s: %v", domain, err)
			} else {
				log.Printf("Management route ensured: %s -> %s:%d", domain, ds.config.HostIP, ds.config.HTTPPort)
			}
		}
	}

	// Persist current daemon config to PostgreSQL for future self-bootstrap
	if ds.daemonConfigStore != nil {
		configMap := map[string]string{
			"base_domain":        ds.config.BaseDomain,
			"http_port":          strconv.Itoa(ds.config.HTTPPort),
			"grpc_port":          strconv.Itoa(ds.config.GRPCPort),
			"listen_address":     ds.config.GRPCAddress,
			"enable_rest":        strconv.FormatBool(ds.config.EnableREST),
			"enable_mtls":        strconv.FormatBool(ds.config.EnableMTLS),
			"enable_app_hosting": strconv.FormatBool(ds.config.EnableAppHosting),
		}
		if err := ds.daemonConfigStore.SetAll(ctx, configMap); err != nil {
			log.Printf("Warning: Failed to save daemon config to PostgreSQL: %v", err)
		} else {
			log.Printf("Daemon config persisted to PostgreSQL")
		}
	}

	// Best-effort: install cgroup wrappers on existing containers
	go func() {
		count, err := ds.containerServer.GetManager().UpgradeCgroupWrappers()
		if err != nil {
			log.Printf("Warning: cgroup wrapper upgrade: %v", err)
		} else if count > 0 {
			log.Printf("Installed cgroup wrappers on %d existing container(s)", count)
		}
	}()

	// Start auto-updater if sentinel URL is configured
	if ds.config.SentinelURL != "" {
		updater := NewAutoUpdater(ds.config.SentinelURL, "/usr/local/bin/containarium", 5*time.Minute)
		go updater.Run(ctx)
	}

	// Start gRPC server
	grpcAddr := fmt.Sprintf("%s:%d", ds.config.GRPCAddress, ds.config.GRPCPort)
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", grpcAddr, err)
	}

	// Start gRPC in goroutine
	grpcErrChan := make(chan error, 1)
	go func() {
		log.Printf("gRPC server starting on %s", grpcAddr)
		if err := ds.grpcServer.Serve(lis); err != nil {
			grpcErrChan <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	// Start HTTP gateway if enabled
	httpErrChan := make(chan error, 1)
	if ds.config.EnableREST && ds.gatewayServer != nil {
		go func() {
			if err := ds.gatewayServer.Start(ctx); err != nil {
				httpErrChan <- fmt.Errorf("HTTP gateway error: %w", err)
			}
		}()
	}

	// Wait for errors or context cancellation
	select {
	case err := <-grpcErrChan:
		return err
	case err := <-httpErrChan:
		return err
	case <-ctx.Done():
		log.Println("Shutting down servers...")
		if ds.routeSyncJob != nil {
			ds.routeSyncJob.Stop()
		}
		if ds.passthroughSyncJob != nil {
			ds.passthroughSyncJob.Stop()
		}
		if ds.autoSleepManager != nil {
			ds.autoSleepManager.Stop()
		}
		if ds.ttlSweeperManager != nil {
			ds.ttlSweeperManager.Stop()
		}
		if ds.secretsReconciler != nil {
			ds.secretsReconciler.Stop()
		}
		if ds.trafficCollector != nil {
			ds.trafficCollector.Stop()
		}
		if ds.cloudClient != nil {
			ds.cloudClient.Stop()
		}
		if ds.networkPolicyEnforcer != nil {
			ds.networkPolicyEnforcer.Stop()
		}
		if ds.metricsCollector != nil {
			ds.metricsCollector.Stop()
		}
		if ds.securityScanner != nil {
			ds.securityScanner.Stop()
		}
		if ds.pentestManager != nil {
			ds.pentestManager.Stop()
		}
		if ds.pentestStore != nil {
			ds.pentestStore.Close()
		}
		if ds.zapManager != nil {
			ds.zapManager.Stop()
		}
		if ds.zapStore != nil {
			ds.zapStore.Close()
		}
		if ds.sshCollector != nil {
			ds.sshCollector.Stop()
		}
		if ds.auditEventSubscriber != nil {
			ds.auditEventSubscriber.Stop()
		}
		if ds.auditStore != nil {
			ds.auditStore.Close()
		}
		if ds.collaboratorStore != nil {
			ds.collaboratorStore.Close()
		}
		if ds.alertStore != nil {
			ds.alertStore.Close()
		}
		ds.grpcServer.GracefulStop()
		return nil
	}
}

// connectToPostgres connects to PostgreSQL with retries. It tries up to
// maxRetries times with retryInterval between attempts. This is defense in
// depth against the race condition where PostgreSQL is still booting.
func connectToPostgres(connString string, maxRetries int, retryInterval time.Duration) (*pgxpool.Pool, error) {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		pool, err := pgxpool.New(context.Background(), connString)
		if err != nil {
			lastErr = err
			if i < maxRetries-1 {
				log.Printf("PostgreSQL connection attempt %d/%d failed: %v (retrying in %v)", i+1, maxRetries, err, retryInterval)
				time.Sleep(retryInterval)
			}
			continue
		}
		if err := pool.Ping(context.Background()); err != nil {
			pool.Close()
			lastErr = err
			if i < maxRetries-1 {
				log.Printf("PostgreSQL ping attempt %d/%d failed: %v (retrying in %v)", i+1, maxRetries, err, retryInterval)
				time.Sleep(retryInterval)
			}
			continue
		}
		return pool, nil
	}
	return nil, fmt.Errorf("failed to connect to PostgreSQL after %d attempts: %w", maxRetries, lastErr)
}

// stripHostFromURL extracts the host (without port) from a URL like "http://10.100.0.5:8428"
func stripHostFromURL(rawURL string) string {
	// Remove protocol
	s := rawURL
	if len(s) > 8 && s[:8] == "https://" {
		s = s[8:]
	} else if len(s) > 7 && s[:7] == "http://" {
		s = s[7:]
	}
	// Remove port
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return s // no port, return as is
	}
	return host
}

// generateRandomSecret generates a random secret for development mode
func generateRandomSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
