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
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/container"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/gateway"
	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/mtls"
	"github.com/footprintai/containarium/internal/network"
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
			if postgresConnString == "" || caddyAdminURL == "" {
				log.Printf("Setting up core services (PostgreSQL, Caddy) in containers...")

				coreServices := NewCoreServices(incusClient, CoreServicesConfig{
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

// generateRandomSecret generates a random secret for development mode
func generateRandomSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
