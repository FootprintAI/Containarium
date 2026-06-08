package gateway

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// CertPair holds a domain's certificate and key in PEM format.
type CertPair struct {
	Domain  string `json:"domain"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// CertsResponse is the JSON response from the /certs endpoint.
type CertsResponse struct {
	Certs []CertPair `json:"certs"`
}

// ServeCerts returns an HTTP handler that walks Caddy's certificate directory
// and returns all cert/key pairs as JSON. This allows the sentinel to sync
// real Let's Encrypt certificates for use during maintenance mode.
//
// Caddy stores LE certs under:
//
//	<certBaseDir>/certificates/<issuer>/<domain>/<domain>.crt
//	<certBaseDir>/certificates/<issuer>/<domain>/<domain>.key
func ServeCerts(certBaseDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if certBaseDir == "" {
			http.Error(w, `{"error":"cert base dir not configured"}`, http.StatusServiceUnavailable)
			return
		}

		certsDir := filepath.Join(certBaseDir, "certificates")
		if _, err := os.Stat(certsDir); os.IsNotExist(err) {
			// No certificates directory yet — Caddy hasn't issued any certs
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(CertsResponse{Certs: []CertPair{}})
			return
		}

		var pairs []CertPair

		// Walk the certificates directory looking for .crt files
		err := filepath.Walk(certsDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".crt") {
				return nil
			}

			// Corresponding key file: same path but .key extension
			keyPath := strings.TrimSuffix(path, ".crt") + ".key"
			if _, err := os.Stat(keyPath); err != nil {
				return nil // no matching key, skip
			}

			certPEM, err := os.ReadFile(path)
			if err != nil {
				log.Printf("[certs] failed to read cert %s: %v", path, err)
				return nil
			}
			keyPEM, err := os.ReadFile(keyPath)
			if err != nil {
				log.Printf("[certs] failed to read key %s: %v", keyPath, err)
				return nil
			}

			// Domain name is the directory name containing the cert
			domain := filepath.Base(filepath.Dir(path))

			pairs = append(pairs, CertPair{
				Domain:  domain,
				CertPEM: string(certPEM),
				KeyPEM:  string(keyPEM),
			})
			return nil
		})
		if err != nil {
			log.Printf("[certs] failed to walk cert dir: %v", err)
			http.Error(w, `{"error":"failed to read certificates"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CertsResponse{Certs: pairs})
	}
}
