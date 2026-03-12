package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/container"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/gateway"
	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/metrics"
	"github.com/footprintai/containarium/internal/mtls"
	"github.com/footprintai/containarium/internal/network"
	"github.com/footprintai/containarium/internal/security"
	"github.com/footprintai/containarium/internal/traffic"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
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
	EnableAppHosting     bool
	PostgresConnString   string
	BaseDomain           string
	CaddyAdminURL        string

	// Route sync settings
	RouteSyncInterval time.Duration // Interval for syncing routes to Caddy (default 5s)

	// Caddy certificate directory for /certs endpoint (sentinel cert sync)
	CaddyCertDir string

	// VictoriaMetrics URL (auto-detected or provided)
	VictoriaMetricsURL string

	// Host IP (extracted from network CIDR, e.g., "10.100.0.1")
	HostIP string

	// DaemonConfigStore for persisting daemon config to PostgreSQL (optional)
	DaemonConfigStore *app.DaemonConfigStore
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
	passthroughStore      *network.PassthroughStore
	passthroughSyncJob    *network.PassthroughSyncJob
	collaboratorStore     *collaborator.Store
	daemonConfigStore     *app.DaemonConfigStore
	metricsCollector      *metrics.Collector
	securityScanner       *security.Scanner
	securityStore         *security.Store
	auditStore            *audit.Store
	auditEventSubscriber  *audit.EventSubscriber
	sshCollector          *audit.SSHCollector
}

// NewDualServer creates a new dual server instance
func NewDualServer(config *DualServerConfig) (*DualServer, error) {
	// Create container server
	containerServer, err := NewContainerServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create container server: %w", err)
	}

	// Create token manager
	tokenManager := auth.NewTokenManager(config.JWTSecret, "containarium")

	// Create auth middleware
	authMiddleware := auth.NewAuthMiddleware(tokenManager)

	// Create gRPC server with optional mTLS
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
			grpc.UnaryInterceptor(authMiddleware.GRPCUnaryInterceptor()),
			grpc.StreamInterceptor(authMiddleware.GRPCStreamInterceptor()),
		)
		log.Printf("gRPC server: mTLS enabled")
	} else {
		grpcServer = grpc.NewServer(
			grpc.UnaryInterceptor(authMiddleware.GRPCUnaryInterceptor()),
			grpc.StreamInterceptor(authMiddleware.GRPCStreamInterceptor()),
		)
		log.Printf("WARNING: gRPC server running in INSECURE mode")
	}

	// Register container service
	pb.RegisterContainerServiceServer(grpcServer, containerServer)

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
			var coreServices *CoreServices
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
						log.Printf("Caddy ready: %s", coreServices.GetCaddyIP())
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
						proxyManager = app.NewProxyManager(caddyAdminURL, config.BaseDomain)
						// Ensure Caddy has basic server config for routes
						if err := proxyManager.EnsureServerConfig(); err != nil {
							log.Printf("Warning: Failed to ensure Caddy server config: %v", err)
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
							log.Printf("Route persistence enabled with %v sync interval", syncInterval)
						}
					}
					networkServer.proxyManager = proxyManager
					networkServer.appStore = appStore
					networkServer.routeStore = routeStore
					networkServer.baseDomain = config.BaseDomain
					log.Printf("Network service updated with app hosting features")
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

	// Setup collaborator store and manager (independent of app hosting)
	// postgresConnString was set by app hosting setup above, or from config
	if postgresConnString == "" {
		postgresConnString = os.Getenv("CONTAINARIUM_POSTGRES_URL")
	}
	if postgresConnString == "" {
		postgresConnString = "postgres://containarium:containarium@10.100.0.2:5432/containarium?sslmode=disable"
	}

	var collabStore *collaborator.Store
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
				proxyManager := app.NewProxyManager(caddyAdminURL, config.BaseDomain)
				if err := proxyManager.EnsureServerConfig(); err != nil {
					log.Printf("Warning: Failed to ensure Caddy server config: %v", err)
				}
				syncInterval := config.RouteSyncInterval
				if syncInterval == 0 {
					syncInterval = 5 * time.Second
				}
				routeSyncJob = app.NewRouteSyncJob(routeStore, proxyManager, syncInterval)
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

	// Setup passthrough route persistence and iptables sync.
	// This mirrors the route store pattern but for TCP/UDP passthrough routes.
	var passthroughStore *network.PassthroughStore
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

					securityServer := NewSecurityServer(securityStore, securityIncusClient, securityScanner)
					pb.RegisterSecurityServiceServer(grpcServer, securityServer)
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

	// Setup audit logging store and event subscriber
	var auditStore *audit.Store
	var auditEventSubscriber *audit.EventSubscriber
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
			}
		}

		log.Printf("HTTP/REST gateway enabled on port %d", config.HTTPPort)
	}

	return &DualServer{
		config:             config,
		grpcServer:         grpcServer,
		containerServer:    containerServer,
		appServer:          appServer,
		networkServer:      networkServer,
		trafficServer:      trafficServer,
		trafficCollector:   trafficCollector,
		gatewayServer:      gatewayServer,
		tokenManager:       tokenManager,
		authMiddleware:     authMiddleware,
		routeStore:         routeStore,
		routeSyncJob:       routeSyncJob,
		passthroughStore:   passthroughStore,
		passthroughSyncJob: passthroughSyncJob,
		collaboratorStore:  collabStore,
		daemonConfigStore:  config.DaemonConfigStore,
		metricsCollector:   metricsCollector,
		securityScanner:      securityScanner,
		securityStore:        securityStore,
		auditStore:           auditStore,
		auditEventSubscriber: auditEventSubscriber,
		sshCollector:         sshCollector,
	}, nil
}

// Start starts both gRPC and HTTP servers
func (ds *DualServer) Start(ctx context.Context) error {
	// Start traffic collector if available
	if ds.trafficCollector != nil {
		if err := ds.trafficCollector.Start(); err != nil {
			log.Printf("Warning: Failed to start traffic collector: %v", err)
		}
	}

	// Start OTel metrics collector if available
	if ds.metricsCollector != nil {
		ds.metricsCollector.Start()
	}

	// Start security scanner if available
	if ds.securityScanner != nil {
		ds.securityScanner.Start(ctx)
		log.Printf("Security scanner started")
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

	// Ensure management route persists in PostgreSQL (RouteSyncJob will push to Caddy)
	if ds.routeStore != nil && ds.config.BaseDomain != "" && ds.config.HostIP != "" {
		mgmtRoute := &app.RouteRecord{
			Subdomain:   ds.config.BaseDomain,
			FullDomain:  ds.config.BaseDomain,
			TargetIP:    ds.config.HostIP,
			TargetPort:  ds.config.HTTPPort,
			Protocol:    "http",
			Description: "Containarium management UI",
			Active:      true,
			CreatedBy:   string(app.RouteCreatorSystem),
		}
		if err := ds.routeStore.Save(ctx, mgmtRoute); err != nil {
			log.Printf("Warning: Failed to ensure management route: %v", err)
		} else {
			log.Printf("Management route ensured: %s -> %s:%d", ds.config.BaseDomain, ds.config.HostIP, ds.config.HTTPPort)
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
		if ds.trafficCollector != nil {
			ds.trafficCollector.Stop()
		}
		if ds.metricsCollector != nil {
			ds.metricsCollector.Stop()
		}
		if ds.securityScanner != nil {
			ds.securityScanner.Stop()
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
