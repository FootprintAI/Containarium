package sentinel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
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

	// Peers endpoint — for daemon multi-backend discovery
	mux.HandleFunc("/sentinel/peers", manager.PeersHandler())

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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

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

	return func() { srv.Close() }, nil
}
