package client

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/footprintai/containarium/internal/mtls"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// DefaultUserCertsDir is the default directory for user certificates
	DefaultUserCertsDir = "~/.config/containarium/certs"
)

// ClientOptions contains options for creating a gRPC client
type ClientOptions struct {
	// Server address (host:port)
	ServerAddress string
	// Enable mTLS
	UseMTLS bool
	// Certificate directory (defaults to ~/.config/containarium/certs)
	CertsDir string
}

// DefaultClientOptions returns default client options for local insecure connection
func DefaultClientOptions() ClientOptions {
	return ClientOptions{
		ServerAddress: "localhost:50051",
		UseMTLS:       false,
		CertsDir:      expandPath(DefaultUserCertsDir),
	}
}

// NewClient creates a new gRPC client connection to the Containarium daemon
func NewClient(opts ClientOptions) (pb.ContainerServiceClient, *grpc.ClientConn, error) {
	var dialOpts []grpc.DialOption

	if opts.UseMTLS {
		// Load client certificates for mTLS
		certPaths := mtls.CertPathsFromDir(opts.CertsDir)

		// Check if certificates exist
		if !mtls.CertsExist(certPaths) {
			return nil, nil, fmt.Errorf("client certificates not found in %s. Generate them first with: containarium cert generate", opts.CertsDir)
		}

		// Load client dial options with mTLS
		tlsDialOpts, err := mtls.LoadClientDialOptions(certPaths, opts.ServerAddress)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load mTLS credentials: %w", err)
		}

		dialOpts = append(dialOpts, tlsDialOpts...)
	} else {
		// Use insecure connection (no TLS)
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Create connection
	conn, err := grpc.NewClient(opts.ServerAddress, dialOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to daemon at %s: %w", opts.ServerAddress, err)
	}

	// Create client
	client := pb.NewContainerServiceClient(conn)

	return client, conn, nil
}

// Ping tests the connection to the daemon by calling GetSystemInfo
func Ping(ctx context.Context, client pb.ContainerServiceClient) error {
	_, err := client.GetSystemInfo(ctx, &pb.GetSystemInfoRequest{})
	if err != nil {
		return fmt.Errorf("daemon connection failed: %w", err)
	}
	return nil
}

// expandPath expands ~ to user's home directory
func expandPath(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}
