package mtls

import (
	"fmt"
	"os"

	certsmem "github.com/footprintai/go-certs/pkg/certs/mem"
	grpccerts "github.com/footprintai/go-certs/pkg/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// LoadServerCredentials loads server TLS credentials from certificate files
func LoadServerCredentials(paths CertPaths) (credentials.TransportCredentials, error) {
	// Read certificate files
	caCert, err := os.ReadFile(paths.CACert)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}
	clientCert, err := os.ReadFile(paths.ClientCert)
	if err != nil {
		return nil, fmt.Errorf("failed to read client cert: %w", err)
	}
	clientKey, err := os.ReadFile(paths.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key: %w", err)
	}
	serverCert, err := os.ReadFile(paths.ServerCert)
	if err != nil {
		return nil, fmt.Errorf("failed to read server cert: %w", err)
	}
	serverKey, err := os.ReadFile(paths.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read server key: %w", err)
	}

	// Create memory loader with all certificates
	// NewMemLoader expects: ca, clientKey, clientCert, serverKey, serverCert
	loader := certsmem.NewMemLoader(caCert, clientKey, clientCert, serverKey, serverCert)

	// Create gRPC certs handler
	grpcCerts := grpccerts.NewGrpcCerts(loader)

	// Create server TLS credentials with mTLS
	creds, err := grpcCerts.NewServerTLSCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to create server credentials: %w", err)
	}

	return creds, nil
}

// LoadClientDialOptions loads client dial options with mTLS from certificate files
func LoadClientDialOptions(paths CertPaths, target string) ([]grpc.DialOption, error) {
	// Create gRPC certs handler from files
	grpcCerts, err := grpccerts.NewGrpcCertsFromFiles(
		paths.CACert,
		paths.ClientCert,
		paths.ClientKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificates: %w", err)
	}

	// Parse target for authority override
	targetObj := grpccerts.NewTypeHostAndPort(target)

	// Create client dial options with mTLS
	dialOpts, err := grpcCerts.NewClientDialOptions(targetObj)
	if err != nil {
		return nil, fmt.Errorf("failed to create client dial options: %w", err)
	}

	return dialOpts, nil
}
