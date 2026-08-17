package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/footprintai/containarium/internal/auth"
	capb "github.com/footprintai/containarium/pkg/pb/thirdparty/externalgrpc"
)

// ClusterPKI is the dedicated certificate authority for the
// CA-provider mTLS surface (#1415, transport option 1). The stock
// cluster-autoscaler's externalgrpc client authenticates with client
// certificates ONLY, so each cluster's machine identity is a client
// cert whose CN is the same `k8s-cluster:<owner>/<name>` subject the
// provider server already enforces — an interceptor maps CN to the
// identity metadata, and every handler stays transport-agnostic.
//
// This CA is deliberately separate from the daemon's main mTLS PKI: a
// cluster credential can only ever authenticate to the CA-provider
// listener, never to the operator API.
type ClusterPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
}

// LoadOrCreateClusterPKI loads the cluster CA from dir, creating and
// persisting it (0600 key) on first use.
func LoadOrCreateClusterPKI(dir string) (*ClusterPKI, error) {
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	certPEM, cErr := os.ReadFile(certPath)
	keyPEM, kErr := os.ReadFile(keyPath)
	if cErr == nil && kErr == nil {
		return parseClusterPKI(certPEM, keyPEM)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "containarium managed-cluster autoscaler CA", Organization: []string{"Containarium"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return parseClusterPKI(certPEM, keyPEM)
}

func parseClusterPKI(certPEM, keyPEM []byte) (*ClusterPKI, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("cluster CA: malformed PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cluster CA cert: %w", err)
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cluster CA key: %w", err)
	}
	return &ClusterPKI{caCert: cert, caKey: key, caPEM: certPEM}, nil
}

func newSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err) // rand.Reader failing is unrecoverable
	}
	return serial
}

// CAPEM is the CA certificate the CA unit trusts the server with.
func (p *ClusterPKI) CAPEM() []byte { return p.caPEM }

// MintClientCert issues a client certificate whose CN is the cluster's
// machine subject. Valid 2 years — cluster deletion revokes access by
// tearing down the VM holding the key.
func (p *ClusterPKI) MintClientCert(owner, name string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: CASubject(owner, name), Organization: []string{"Containarium"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// serverTLSConfig builds the listener's mTLS config: a server cert for
// the given SANs signed by the cluster CA, client certs required and
// verified against the same CA.
func (p *ClusterPKI) serverTLSConfig(hosts []string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: "containarium ca-provider", Organization: []string{"Containarium"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(p.caCert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// caIdentityInterceptor maps the verified client certificate's CN into
// the same identity metadata the provider handlers already enforce —
// the transport becomes invisible above this line.
func caIdentityInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if pr, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := pr.AuthInfo.(credentials.TLSInfo); ok && len(tlsInfo.State.VerifiedChains) > 0 {
			cn := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
			md, _ := metadata.FromIncomingContext(ctx)
			md = md.Copy()
			md.Set(auth.MDKeyUsername, cn)
			md.Set(auth.MDKeyRoles, "machine")
			md.Set(auth.MDKeyScopes, auth.ScopeClustersScale)
			ctx = metadata.NewIncomingContext(ctx, md)
		}
	}
	return handler(ctx, req)
}

// StartClusterCAListener serves the CloudProvider contract on a
// dedicated mTLS listener. Returns the bound address and a stop
// function.
func StartClusterCAListener(addr string, sanHosts []string, pki *ClusterPKI, provider *CAProviderServer) (string, func(), error) {
	tlsCfg, err := pki.serverTLSConfig(sanHosts)
	if err != nil {
		return "", nil, err
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(caIdentityInterceptor),
	)
	capb.RegisterCloudProviderServer(gs, provider)
	go func() {
		if err := gs.Serve(lis); err != nil {
			log.Printf("[cluster] CA-provider listener stopped: %v", err)
		}
	}()
	log.Printf("[cluster] CA-provider mTLS listener on %s", lis.Addr())
	return lis.Addr().String(), gs.Stop, nil
}
