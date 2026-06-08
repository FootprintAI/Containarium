package sentinel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

//go:embed maintenance.html
var maintenancePage []byte

// maintenanceHandler returns the default maintenance page handler.
func maintenanceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write(maintenancePage)
	}
}

// NewMaintenanceServer creates an HTTP server that serves the maintenance page
// on all paths with a 503 status code. The /sentinel path serves the status page.
func NewMaintenanceServer(httpPort int, manager *Manager) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/sentinel", StatusHandler(manager))
	mux.HandleFunc("/", maintenanceHandler())

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", httpPort),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
}

// NewMaintenanceTLSServer creates an HTTPS server that uses the CertStore for
// TLS certificates (real LE certs when synced, self-signed fallback otherwise).
// The /sentinel path serves the status page.
func NewMaintenanceTLSServer(httpsPort int, certStore *CertStore, manager *Manager) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/sentinel", StatusHandler(manager))
	mux.HandleFunc("/", maintenanceHandler())

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if certStore != nil {
		tlsConfig.GetCertificate = certStore.GetCertificate
	} else {
		// No cert store — generate a one-time self-signed cert
		cert, err := generateSelfSignedCert()
		if err != nil {
			log.Printf("[sentinel] warning: failed to generate self-signed cert: %v", err)
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", httpsPort),
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
}

// generateSelfSignedCert creates a self-signed TLS certificate for the maintenance page.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Containarium Sentinel"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("0.0.0.0")},
		DNSNames:              []string{"localhost", "*"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// startMaintenanceServers starts both HTTP and HTTPS maintenance servers.
// Returns a function to stop both servers.
func startMaintenanceServers(httpPort, httpsPort int, certStore *CertStore, manager *Manager) (stop func(), err error) {
	httpSrv := NewMaintenanceServer(httpPort, manager)
	httpsSrv := NewMaintenanceTLSServer(httpsPort, certStore, manager)

	go func() {
		log.Printf("[sentinel] maintenance HTTP server listening on :%d", httpPort)
		if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("[sentinel] maintenance HTTP server error: %v", err)
		}
	}()

	go func() {
		log.Printf("[sentinel] maintenance HTTPS server listening on :%d", httpsPort)
		if err := httpsSrv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Printf("[sentinel] maintenance HTTPS server error: %v", err)
		}
	}()

	return func() {
		_ = httpSrv.Close()
		_ = httpsSrv.Close()
	}, nil
}
