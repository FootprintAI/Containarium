package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/gateway"
	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/mtls"
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
}

// DualServer runs both gRPC and HTTP/REST servers
type DualServer struct {
	config          *DualServerConfig
	grpcServer      *grpc.Server
	containerServer *ContainerServer
	appServer       *AppServer
	gatewayServer   *gateway.GatewayServer
	tokenManager    *auth.TokenManager
	authMiddleware  *auth.AuthMiddleware
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

	// Create and register AppServer if app hosting is enabled
	var appServer *AppServer
	if config.EnableAppHosting && config.PostgresConnString != "" {
		appStore, err := app.NewStore(context.Background(), config.PostgresConnString)
		if err != nil {
			log.Printf("Warning: Failed to connect to app store: %v. App hosting disabled.", err)
		} else {
			incusClient, err := incus.New()
			if err != nil {
				log.Printf("Warning: Failed to create incus client for app hosting: %v", err)
			} else {
				appManager := app.NewManager(appStore, incusClient, app.ManagerConfig{
					BaseDomain:    config.BaseDomain,
					CaddyAdminURL: config.CaddyAdminURL,
				})
				appServer = NewAppServer(appManager, appStore)
				pb.RegisterAppServiceServer(grpcServer, appServer)
				log.Printf("App hosting service enabled")
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
		)
		log.Printf("HTTP/REST gateway enabled on port %d", config.HTTPPort)
	}

	return &DualServer{
		config:          config,
		grpcServer:      grpcServer,
		containerServer: containerServer,
		appServer:       appServer,
		gatewayServer:   gatewayServer,
		tokenManager:    tokenManager,
		authMiddleware:  authMiddleware,
	}, nil
}

// Start starts both gRPC and HTTP servers
func (ds *DualServer) Start(ctx context.Context) error {
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
		ds.grpcServer.GracefulStop()
		return nil
	}
}

// generateRandomSecret generates a random secret for development mode
func generateRandomSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
