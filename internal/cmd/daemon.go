package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/footprintai/containarium/internal/mtls"
	"github.com/footprintai/containarium/internal/server"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	daemonAddress    string
	daemonPort       int
	enableMTLS       bool
	daemonCertsDir   string
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run Containarium as a gRPC daemon service",
	Long: `Start the Containarium gRPC API server for remote management.

The daemon provides a gRPC API that allows remote clients to manage containers
without needing SSH access to the jump server. This enables:
  - Remote container management from your laptop
  - API access for automation and scripting
  - Foundation for a Web UI
  - Multi-server management from a single client

The daemon runs on each jump server and listens for gRPC connections.

Security:
  By default, the daemon uses mutual TLS (mTLS) for authentication. Certificates
  must be generated first using 'containarium cert generate'.

Examples:
  # Run daemon with mTLS (recommended)
  containarium daemon --mtls

  # Run daemon without mTLS (insecure, for testing only)
  containarium daemon

  # Run on specific address and port
  containarium daemon --address 0.0.0.0 --port 50051 --mtls

  # Use custom certificate directory
  containarium daemon --mtls --certs-dir /custom/path/certs

  # Run as systemd service (recommended for production)
  sudo systemctl start containarium`,
	RunE: runDaemon,
}

func init() {
	rootCmd.AddCommand(daemonCmd)

	daemonCmd.Flags().StringVar(&daemonAddress, "address", "0.0.0.0", "Address to listen on")
	daemonCmd.Flags().IntVar(&daemonPort, "port", 50051, "Port to listen on")
	daemonCmd.Flags().BoolVar(&enableMTLS, "mtls", false, "Enable mutual TLS authentication (recommended)")
	daemonCmd.Flags().StringVar(&daemonCertsDir, "certs-dir", mtls.DefaultCertsDir, "Directory containing TLS certificates")
}

func runDaemon(cmd *cobra.Command, args []string) error {
	// Create listen address
	listenAddr := fmt.Sprintf("%s:%d", daemonAddress, daemonPort)

	// Create TCP listener
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	// Create gRPC server with optional mTLS
	var grpcServer *grpc.Server
	if enableMTLS {
		// Load TLS credentials
		certPaths := mtls.CertPathsFromDir(daemonCertsDir)

		// Check if certificates exist
		if !mtls.CertsExist(certPaths) {
			return fmt.Errorf("TLS certificates not found in %s. Generate them first with: containarium cert generate", daemonCertsDir)
		}

		// Load server credentials
		creds, err := mtls.LoadServerCredentials(certPaths)
		if err != nil {
			return fmt.Errorf("failed to load TLS credentials: %w", err)
		}

		// Create gRPC server with mTLS
		grpcServer = grpc.NewServer(grpc.Creds(creds))
		log.Printf("mTLS enabled - client certificate authentication required")
	} else {
		// Create insecure gRPC server (not recommended for production)
		grpcServer = grpc.NewServer()
		log.Printf("WARNING: mTLS disabled - daemon running in INSECURE mode")
		log.Printf("WARNING: Anyone can connect to the daemon without authentication")
		log.Printf("WARNING: Enable mTLS with --mtls flag for production use")
	}

	// Create and register container service
	containerServer, err := server.NewContainerServer()
	if err != nil {
		return fmt.Errorf("failed to create container server: %w", err)
	}
	pb.RegisterContainerServiceServer(grpcServer, containerServer)

	// Register reflection service (useful for grpcurl and debugging)
	reflection.Register(grpcServer)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Printf("Containarium daemon starting on %s", listenAddr)
		log.Printf("gRPC reflection enabled for debugging")
		log.Printf("Press Ctrl+C to stop")
		if err := grpcServer.Serve(lis); err != nil {
			errChan <- fmt.Errorf("failed to serve: %w", err)
		}
	}()

	// Wait for signal or error
	select {
	case <-sigChan:
		log.Println("\nReceived shutdown signal, stopping gracefully...")
		grpcServer.GracefulStop()
		log.Println("Daemon stopped")
		return nil
	case err := <-errChan:
		return err
	}
}
