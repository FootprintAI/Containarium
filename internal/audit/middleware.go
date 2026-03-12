package audit

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// skipPaths are request paths that should not be audit-logged (noisy/non-sensitive)
var skipPaths = []string{
	"/health",
	"/v1/events/subscribe",
	"/swagger-ui/",
	"/webui/",
	"/grafana/",
	"/certs",
	"/authorized-keys",
	"/swagger.json",
}

// skipGETPaths are GET-only paths that generate too much noise from UI polling.
// These are read-only listing/status endpoints called every few seconds.
var skipGETPaths = []string{
	"/v1/containers",
	"/v1/apps",
	"/v1/metrics",
	"/v1/network/routes",
	"/v1/network/passthrough",
	"/v1/network/topology",
	"/v1/network/acl-presets",
	"/v1/network/dns-records",
	"/v1/system/info",
	"/v1/system/monitoring",
	"/v1/system/core-services",
	"/v1/security/clamav-summary",
	"/v1/security/clamav-reports",
	"/v1/security/scan-status",
	"/v1/audit/logs",
}

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// HTTPAuditMiddleware wraps an HTTP handler to record audit log entries for API requests
func HTTPAuditMiddleware(next http.Handler, store *Store) http.Handler {
	// Buffered channel for async writes
	entryCh := make(chan *AuditEntry, 256)

	// Background writer goroutine
	go func() {
		for entry := range entryCh {
			if err := store.Log(context.Background(), entry); err != nil {
				log.Printf("audit: failed to write log: %v", err)
			}
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip noisy paths
		for _, prefix := range skipPaths {
			if strings.HasPrefix(r.URL.Path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Skip read-only GET polling endpoints (UI refreshes every few seconds)
		if r.Method == http.MethodGet {
			for _, prefix := range skipGETPaths {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		start := time.Now()
		rw := newResponseWriter(w)

		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		// Extract username from context (set by auth middleware)
		username, _ := auth.UsernameFromContext(r.Context())

		// Extract source IP
		sourceIP := extractSourceIP(r)

		// Use method-specific action for better filtering and UI color-coding
		action := "api_" + strings.ToLower(r.Method) // api_get, api_post, api_put, api_delete

		entry := &AuditEntry{
			Timestamp:    start,
			Username:     username,
			Action:       action,
			ResourceType: "api",
			ResourceID:   fmt.Sprintf("%s %s", r.Method, r.URL.Path),
			Detail:       fmt.Sprintf("duration=%s", duration),
			SourceIP:     sourceIP,
			StatusCode:   rw.statusCode,
		}

		// Non-blocking send
		select {
		case entryCh <- entry:
		default:
			// Channel full, drop entry to avoid blocking the request
		}
	})
}

// extractSourceIP extracts the client IP from the request, preferring
// X-Forwarded-For (set by load balancers/proxies) over RemoteAddr.
func extractSourceIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (original client)
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
