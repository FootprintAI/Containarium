package sentinel

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/version"
)

const defaultBinaryPath = "/usr/local/bin/containarium"

// StatusJSON is the JSON response for the /status endpoint.
type StatusJSON struct {
	State          string `json:"state"`
	SpotIP         string `json:"spot_ip"`
	PreemptCount   int    `json:"preempt_count"`
	OutageDuration string `json:"outage_duration,omitempty"`
	LastPreemption string `json:"last_preemption,omitempty"`
	CertSyncCount  int    `json:"cert_sync_count"`
	CertLastSync   string `json:"cert_last_sync,omitempty"`
	CertSyncError  string `json:"cert_sync_error,omitempty"`
	// SentinelAuthMisconfigured is true when CONTAINARIUM_SENTINEL_AUTH_SECRET
	// is unset or shorter than the minimum, which silently 401s every
	// keysync/certsync against the daemons. Surfaced here (in addition
	// to the startup + per-cycle log lines) so monitoring can alert on
	// it without scraping logs — alert on this being true. #341.
	SentinelAuthMisconfigured bool   `json:"sentinel_auth_misconfigured"`
	SentinelAuthDetail        string `json:"sentinel_auth_detail,omitempty"`
}

// StartBinaryServer starts an HTTP server that serves the containarium binary
// for the spot VM to download, plus a /status JSON endpoint.
// This runs on an internal-only port (default 8888).
func StartBinaryServer(port int, manager *Manager) (stop func(), err error) {
	binaryPath := defaultBinaryPath

	// Verify binary exists
	if _, err := os.Stat(binaryPath); err != nil {
		return nil, fmt.Errorf("binary not found at %s: %w", binaryPath, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/containarium", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=containarium")
		http.ServeFile(w, r, binaryPath)
	})
	mux.HandleFunc("/containarium/checksum", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(binaryPath)
		if err != nil {
			http.Error(w, "binary not found", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			http.Error(w, "checksum error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, hex.EncodeToString(h.Sum(nil)))
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Version endpoint (#354) — lets the webui's Versions panel show the
	// sentinel's running version alongside each backend's (from the
	// daemon's /v1/backends) and the latest GitHub release (from the
	// daemon's /v1/releases/latest). Unauthenticated: it reveals only the
	// build version, the same as the binary the sentinel already serves at
	// /containarium for peers to pull.
	mux.HandleFunc("/sentinel/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(version.Get())
	})

	// Peers endpoint — for daemon multi-backend discovery
	mux.HandleFunc("/sentinel/peers", manager.PeersHandler())

	// Primaries endpoints — populated by daemon self-registration.
	// One handler covers both /sentinel/primaries and /sentinel/primaries/{pool}.
	mux.HandleFunc("/sentinel/primaries", manager.PrimariesHandler())
	mux.HandleFunc("/sentinel/primaries/", manager.PrimariesHandler())

	// Phase 0.5: peer-CA distribution + leaf-cert issuance. Both
	// gated by the existing HMAC middleware — the same secret that
	// guards /authorized-keys and /certs. 503 when no CA is wired up
	// (rollout mode), so daemons can detect the sentinel's
	// capability without a separate feature flag.
	mux.Handle("/sentinel/ca", auth.SentinelHMACMiddleware(manager.hmacSecret, manager.CAHandler()))
	mux.Handle("/sentinel/peer-cert", auth.SentinelHMACMiddleware(manager.hmacSecret, manager.PeerCertHandler()))

	// Peer proxy — forwards /peer/<backend-id>/* to the tunnel backend's loopback
	// This allows the primary daemon to reach tunnel backends through the sentinel
	// without needing extra firewall rules for external ports.
	mux.HandleFunc("/peer/", func(w http.ResponseWriter, r *http.Request) {
		// Parse path: /peer/<backend-id>/v1/containers → backend-id, /v1/containers
		path := strings.TrimPrefix(r.URL.Path, "/peer/")
		slashIdx := strings.Index(path, "/")
		if slashIdx < 0 {
			http.Error(w, "invalid peer path", http.StatusBadRequest)
			return
		}
		backendID := path[:slashIdx]
		remainingPath := path[slashIdx:]

		// Find the backend's loopback IP
		backend := manager.backends.Get(backendID)
		if backend == nil {
			http.Error(w, fmt.Sprintf("backend %q not found", backendID), http.StatusNotFound)
			return
		}

		target := &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s:%d", backend.IP, manager.config.HealthPort),
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		r.URL.Path = remainingPath
		r.Host = target.Host
		proxy.ServeHTTP(w, r)
	})

	// Status JSON endpoint — always available
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		status := StatusJSON{
			State:         string(manager.CurrentState()),
			SpotIP:        manager.SpotIP(),
			PreemptCount:  manager.PreemptCount(),
			CertSyncCount: manager.certStore.SyncedCount(),
		}

		if od := manager.OutageDuration(); od > 0 {
			status.OutageDuration = od.Round(time.Second).String()
		}
		if lp := manager.LastPreemption(); !lp.IsZero() {
			status.LastPreemption = lp.Format(time.RFC3339)
		}
		if ls := manager.certStore.LastSync(); !ls.IsZero() {
			status.CertLastSync = ls.Format(time.RFC3339)
		}
		if err := manager.certStore.LastSyncErr(); err != nil {
			status.CertSyncError = err.Error()
		}
		if !manager.HMACSecretConfigured() {
			status.SentinelAuthMisconfigured = true
			status.SentinelAuthDetail = fmt.Sprintf(
				"CONTAINARIUM_SENTINEL_AUTH_SECRET unset or < %d bytes; keysync/certsync to daemons is failing with 401",
				auth.SentinelMinSecretLen)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	// Prometheus metrics for the spot preemption/recovery signal (#514
	// follow-up). Served from the always-on sentinel so an EXTERNAL
	// scraper can alert on the net — the on-spot VictoriaMetrics dies with
	// the spot it would be reporting on.
	mux.HandleFunc("/metrics", manager.MetricsHandler())

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second, // large file transfer
	}

	go func() {
		log.Printf("[sentinel] binary server listening on :%d (serving %s)", port, binaryPath)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("[sentinel] binary server error: %v", err)
		}
	}()

	// Phase 0.5: HTTPS variant on a separate port (default port+1)
	// when the sentinel has a peer-CA. Same handler set, so daemons
	// that point CONTAINARIUM_SENTINEL_URL at the https://… endpoint
	// get TLS-protected peer discovery + cert issuance + binary
	// download. Operators flip daemons over one at a time during
	// rollout; the HTTP listener stays up for the un-flipped ones.
	var httpsSrv *http.Server
	if certPEM, keyPEM := manager.SentinelServerCertPEM(); certPEM != nil && keyPEM != nil {
		httpsPort := port + 1
		if env := os.Getenv("CONTAINARIUM_SENTINEL_HTTPS_PORT"); env != "" {
			if p, perr := parsePort(env); perr == nil {
				httpsPort = p
			} else {
				// #nosec G706 -- env is strconv.Quote'd into the
				// format string; gosec's taint analysis doesn't
				// recognize Quote as a sanitizer.
				log.Printf("[sentinel] invalid CONTAINARIUM_SENTINEL_HTTPS_PORT=%s (%v) — defaulting to %d", strconv.Quote(env), perr, httpsPort)
			}
		}
		tlsCert, tlsErr := tls.X509KeyPair(certPEM, keyPEM)
		if tlsErr != nil {
			log.Printf("[sentinel] WARNING: failed to build TLS keypair for HTTPS listener (%v) — HTTPS disabled", tlsErr)
		} else {
			httpsSrv = &http.Server{
				Addr:         fmt.Sprintf(":%d", httpsPort),
				Handler:      mux,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 120 * time.Second,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{tlsCert},
					MinVersion:   tls.VersionTLS12,
				},
			}
			go func() {
				// #nosec G706 -- httpsPort is an int; taint chases
				// it back to the env value but %d on an int has no
				// log-injection vector.
				log.Printf("[sentinel] binary server HTTPS listener on :%d (Phase 0.5 — clients pin /sentinel/ca)", httpsPort)
				if err := httpsSrv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
					log.Printf("[sentinel] binary server HTTPS error: %v", err)
				}
			}()
		}
	}

	return func() {
		// Errors on shutdown are not actionable — the process is
		// going away — but acknowledge them explicitly so static
		// analysis doesn't flag the unhandled returns.
		_ = srv.Close()
		if httpsSrv != nil {
			_ = httpsSrv.Close()
		}
	}, nil
}

// parsePort is a tiny helper so the HTTPS-port override can come
// from a string env var without pulling in strconv at every site.
func parsePort(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	if n <= 0 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return n, nil
}
