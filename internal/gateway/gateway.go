package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
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
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/mtls"
	"github.com/footprintai/containarium/internal/security"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

// GatewayServer implements the HTTP/REST gateway for the gRPC service
type GatewayServer struct {
	grpcAddress        string
	httpPort           int
	authMiddleware     *auth.AuthMiddleware
	swaggerDir         string
	certsDir           string // Optional: for mTLS connection to gRPC server
	caddyCertDir       string // Optional: Caddy certificate directory for /certs endpoint
	grafanaBackendURL      string // Optional: internal Grafana URL for reverse proxy (e.g., "http://10.0.3.229:3000")
	alertmanagerBackendURL string // Optional: internal Alertmanager URL for reverse proxy (e.g., "http://10.0.3.229:9093")
	securityStore      *security.Store // Optional: for CSV export endpoint
	auditStore         *audit.Store    // Optional: for HTTP audit middleware
	terminalHandler     *TerminalHandler
	labelHandler        *LabelHandler
	eventHandler        *EventHandler
	coreServicesHandler *CoreServicesHandler

	// Alert relay (no auth — internal network only)
	alertRelayMu     sync.RWMutex
	alertRelayURL    string // external webhook URL to forward to
	alertRelaySecret string // HMAC-SHA256 signing secret

	// Callback to record relay delivery attempts (set by dual_server)
	recordDeliveryFn func(ctx context.Context, alertName, source, webhookURL string, success bool, httpStatus int, errMsg string, payloadSize, durationMs int)
}

// NewGatewayServer creates a new gateway server
func NewGatewayServer(grpcAddress string, httpPort int, authMiddleware *auth.AuthMiddleware, swaggerDir string, certsDir string, caddyCertDir string) *GatewayServer {
	// Try to create terminal handler (may fail if Incus not available)
	terminalHandler, err := NewTerminalHandler()
	if err != nil {
		log.Printf("Warning: Terminal handler not available: %v", err)
	}

	// Try to create label handler (may fail if Incus not available)
	labelHandler, err := NewLabelHandler()
	if err != nil {
		log.Printf("Warning: Label handler not available: %v", err)
	}

	// Try to create core services handler (may fail if Incus not available)
	coreServicesHandler, err := NewCoreServicesHandler()
	if err != nil {
		log.Printf("Warning: Core services handler not available: %v", err)
	}

	// Create event handler with global event bus
	eventHandler := NewEventHandler(events.GetBus())

	return &GatewayServer{
		grpcAddress:     grpcAddress,
		httpPort:        httpPort,
		authMiddleware:  authMiddleware,
		swaggerDir:      swaggerDir,
		certsDir:        certsDir,
		caddyCertDir:    caddyCertDir,
		terminalHandler:     terminalHandler,
		labelHandler:        labelHandler,
		eventHandler:        eventHandler,
		coreServicesHandler: coreServicesHandler,
	}
}

// SetGrafanaBackendURL sets the internal Grafana URL for the reverse proxy
func (gs *GatewayServer) SetGrafanaBackendURL(backendURL string) {
	gs.grafanaBackendURL = backendURL
}

// SetAlertmanagerBackendURL sets the internal Alertmanager URL for the reverse proxy
func (gs *GatewayServer) SetAlertmanagerBackendURL(backendURL string) {
	gs.alertmanagerBackendURL = backendURL
}

// SetSecurityStore sets the security store for the CSV export endpoint
func (gs *GatewayServer) SetSecurityStore(store *security.Store) {
	gs.securityStore = store
}

// SetAuditStore sets the audit store for the HTTP audit middleware
func (gs *GatewayServer) SetAuditStore(store *audit.Store) {
	gs.auditStore = store
}

// SetRecordDeliveryFn sets the callback used to record relay delivery attempts
func (gs *GatewayServer) SetRecordDeliveryFn(fn func(ctx context.Context, alertName, source, webhookURL string, success bool, httpStatus int, errMsg string, payloadSize, durationMs int)) {
	gs.recordDeliveryFn = fn
}

// SetAlertRelayConfig sets the external webhook URL and HMAC signing secret
// for the alert relay handler. Thread-safe; can be called at any time.
func (gs *GatewayServer) SetAlertRelayConfig(webhookURL, secret string) {
	gs.alertRelayMu.Lock()
	defer gs.alertRelayMu.Unlock()
	gs.alertRelayURL = webhookURL
	gs.alertRelaySecret = secret
}

// handleAlertRelay receives Alertmanager webhook POSTs (from the local VictoriaMetrics
// container), signs them with HMAC-SHA256, and forwards them to the external webhook URL.
// No JWT auth is required — this endpoint is only reachable from the local container network.
func (gs *GatewayServer) handleAlertRelay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	gs.alertRelayMu.RLock()
	webhookURL := gs.alertRelayURL
	secret := gs.alertRelaySecret
	gs.alertRelayMu.RUnlock()

	if webhookURL == "" {
		http.Error(w, `{"error":"no webhook URL configured"}`, http.StatusServiceUnavailable)
		return
	}

	// Read the body from Alertmanager
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}

	// Extract alert name from Alertmanager JSON payload (best-effort)
	alertName := extractAlertName(body)

	// Create forwarding request
	fwdReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"failed to create forwarding request"}`, http.StatusInternalServerError)
		return
	}
	fwdReq.Header.Set("Content-Type", "application/json")

	// Sign payload with HMAC-SHA256 if secret is configured
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		fwdReq.Header.Set("X-Containarium-Signature", sig)
	}

	// Forward to external webhook
	start := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(fwdReq)
	durationMs := int(time.Since(start).Milliseconds())
	if err != nil {
		log.Printf("Alert relay: failed to forward to %s: %v", webhookURL, err)
		gs.recordRelayDelivery(r.Context(), alertName, webhookURL, false, 0, fmt.Sprintf("failed to forward: %v", err), len(body), durationMs)
		http.Error(w, fmt.Sprintf(`{"error":"failed to forward: %v"}`, err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	errMsg := ""
	if !success {
		errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	gs.recordRelayDelivery(r.Context(), alertName, webhookURL, success, resp.StatusCode, errMsg, len(body), durationMs)

	// Mirror the upstream status code back to Alertmanager
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}

// extractAlertName extracts the first alert name from an Alertmanager webhook payload
func extractAlertName(body []byte) string {
	var payload struct {
		CommonLabels map[string]string `json:"commonLabels"`
		Alerts       []struct {
			Labels map[string]string `json:"labels"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	if name, ok := payload.CommonLabels["alertname"]; ok {
		return name
	}
	if len(payload.Alerts) > 0 {
		if name, ok := payload.Alerts[0].Labels["alertname"]; ok {
			return name
		}
	}
	return ""
}

// maskRelayURL masks a URL for display (shows scheme + host, hides path)
func maskRelayURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parts := strings.SplitN(rawURL, "//", 2)
	if len(parts) < 2 {
		return "***"
	}
	hostPart := parts[1]
	if idx := strings.Index(hostPart, "/"); idx > 0 {
		return parts[0] + "//" + hostPart[:idx] + "/***"
	}
	return rawURL
}

// recordRelayDelivery records a relay delivery attempt via the callback
func (gs *GatewayServer) recordRelayDelivery(ctx context.Context, alertName, webhookURL string, success bool, httpStatus int, errMsg string, payloadSize, durationMs int) {
	if gs.recordDeliveryFn != nil {
		gs.recordDeliveryFn(ctx, alertName, "relay", maskRelayURL(webhookURL), success, httpStatus, errMsg, payloadSize, durationMs)
	}
}

// Start starts the HTTP gateway server
func (gs *GatewayServer) Start(ctx context.Context) error {
	// Create grpc-gateway mux with custom options
	mux := runtime.NewServeMux(
		runtime.WithErrorHandler(customErrorHandler),
		runtime.WithMetadata(annotateContext),
		// Marshal options for better JSON formatting
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   false,
				EmitUnpopulated: true,
				UseEnumNumbers:  false,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: true,
			},
		}),
	)

	// Setup connection to gRPC server
	var opts []grpc.DialOption
	if gs.certsDir != "" {
		// Use mTLS to connect to gRPC server
		certPaths := mtls.CertPathsFromDir(gs.certsDir)
		dialOpts, err := mtls.LoadClientDialOptions(certPaths, gs.grpcAddress)
		if err != nil {
			return fmt.Errorf("failed to load mTLS credentials for gateway: %w", err)
		}
		opts = dialOpts
		log.Printf("Gateway connecting to gRPC server with mTLS")
	} else {
		// Use insecure connection (local development)
		opts = []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}
		log.Printf("Gateway connecting to gRPC server without TLS")
	}

	// Register gateway handlers
	if err := pb.RegisterContainerServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register container service gateway: %w", err)
	}

	// Register AppService gateway handler
	if err := pb.RegisterAppServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register app service gateway: %w", err)
	}

	// Register NetworkService gateway handler
	if err := pb.RegisterNetworkServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register network service gateway: %w", err)
	}

	// Register TrafficService gateway handler
	if err := pb.RegisterTrafficServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register traffic service gateway: %w", err)
	}

	// Register SecurityService gateway handler
	if err := pb.RegisterSecurityServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register security service gateway: %w", err)
	}

	// Register PentestService gateway handler
	if err := pb.RegisterPentestServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register pentest service gateway: %w", err)
	}

	// Create HTTP handler with authentication middleware, then audit middleware.
	// Audit wraps the inner handler so auth runs first (sets username in context),
	// then audit captures the response on the way out.
	var handler http.Handler = mux
	if gs.auditStore != nil {
		handler = audit.HTTPAuditMiddleware(handler, gs.auditStore)
	}
	handler = gs.authMiddleware.HTTPMiddleware(handler)

	// Add CORS support with configurable origins (secure by default)
	// Set CONTAINARIUM_ALLOWED_ORIGINS env var to configure allowed origins
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   getAllowedOrigins(),
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           300,
	}).Handler(handler)

	// Create HTTP mux for routing
	httpMux := http.NewServeMux()

	// Terminal WebSocket route (with authentication via query param)
	if gs.terminalHandler != nil {
		// Wrap terminal handler with CORS (using configurable origins)
		terminalWithCORS := cors.New(cors.Options{
			AllowedOrigins:   getAllowedOrigins(),
			AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders:   []string{"Authorization", "Content-Type", "Upgrade", "Connection"},
			AllowCredentials: true,
		}).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Validate auth token from query param (WebSocket can't use headers easily)
			token := r.URL.Query().Get("token")
			if token == "" {
				// Try Authorization header as fallback
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					token = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			// SECURITY FIX: Authentication is MANDATORY for terminal access
			if token == "" {
				http.Error(w, `{"error": "unauthorized: token required for terminal access", "code": 401}`, http.StatusUnauthorized)
				return
			}

			claims, err := gs.authMiddleware.ValidateToken(token)
			if err != nil {
				http.Error(w, `{"error": "unauthorized: invalid token", "code": 401}`, http.StatusUnauthorized)
				return
			}

			// Log terminal access to audit store
			if gs.auditStore != nil {
				// Extract container name from URL path (e.g. /v1/containers/{name}/terminal)
				parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
				containerName := ""
				for i, p := range parts {
					if p == "containers" && i+1 < len(parts) {
						containerName = parts[i+1]
						break
					}
				}
				auditUsername := ""
				if claims != nil {
					auditUsername = claims.Username
				}
				sourceIP := r.Header.Get("X-Forwarded-For")
				if sourceIP == "" {
					sourceIP = r.RemoteAddr
				}
				gs.auditStore.Log(r.Context(), &audit.AuditEntry{
					Username:     auditUsername,
					Action:       "terminal_access",
					ResourceType: "container",
					ResourceID:   containerName,
					SourceIP:     sourceIP,
				})
			}

			gs.terminalHandler.HandleTerminal(w, r)
		}))

		// Handler for container routes
		containerHandler := func(w http.ResponseWriter, r *http.Request) {
			// Check if this is a terminal request
			if strings.HasSuffix(r.URL.Path, "/terminal") {
				terminalWithCORS.ServeHTTP(w, r)
				return
			}
			// Check if this is a labels request
			if strings.Contains(r.URL.Path, "/labels") && gs.labelHandler != nil {
				switch r.Method {
				case http.MethodGet:
					gs.labelHandler.HandleGetLabels(w, r)
					return
				case http.MethodPut, http.MethodPost:
					gs.labelHandler.HandleSetLabels(w, r)
					return
				case http.MethodDelete:
					gs.labelHandler.HandleRemoveLabel(w, r)
					return
				}
			}
			// Not a terminal or labels request, pass to gRPC gateway with CORS
			corsHandler.ServeHTTP(w, r)
		}

		// Handle both with and without trailing slash to avoid redirects
		httpMux.HandleFunc("/v1/containers/", containerHandler)
		httpMux.HandleFunc("/v1/containers", containerHandler)

		// Handle other /v1/ routes
		httpMux.Handle("/v1/", corsHandler)
	} else {
		// No terminal handler, just use CORS handler for all /v1/ routes
		httpMux.Handle("/v1/", corsHandler)
	}

	// Core services endpoint (with authentication via CORS handler)
	if gs.coreServicesHandler != nil {
		coreServicesCORS := cors.New(cors.Options{
			AllowedOrigins:   getAllowedOrigins(),
			AllowedMethods:   []string{"GET", "OPTIONS"},
			AllowedHeaders:   []string{"Authorization", "Content-Type"},
			AllowCredentials: true,
		}).Handler(gs.authMiddleware.HTTPMiddleware(http.HandlerFunc(gs.coreServicesHandler.HandleGetCoreServices)))
		httpMux.Handle("/v1/system/core-services", coreServicesCORS)
	}

	// Events SSE endpoint (with authentication)
	eventsWithCORS := cors.New(cors.Options{
		AllowedOrigins:   getAllowedOrigins(),
		AllowedMethods:   []string{"GET", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "Cache-Control"},
		AllowCredentials: true,
	}).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate auth token from query param or header
		token := r.URL.Query().Get("token")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if token == "" {
			http.Error(w, `{"error": "unauthorized: token required for events", "code": 401}`, http.StatusUnauthorized)
			return
		}

		_, err := gs.authMiddleware.ValidateToken(token)
		if err != nil {
			http.Error(w, `{"error": "unauthorized: invalid token", "code": 401}`, http.StatusUnauthorized)
			return
		}

		gs.eventHandler.HandleSSE(w, r)
	}))
	httpMux.Handle("/v1/events/subscribe", eventsWithCORS)

	// Swagger UI routes (no authentication required)
	httpMux.Handle("/swagger-ui/", http.StripPrefix("/swagger-ui", http.HandlerFunc(ServeSwaggerUI(gs.swaggerDir))))
	httpMux.HandleFunc("/swagger.json", ServeSwaggerSpec(gs.swaggerDir))

	// Web UI routes (no authentication required - auth handled client-side via tokens)
	httpMux.HandleFunc("/webui/", ServeWebUI())

	// Alert relay endpoint (no auth — internal network only, called by Alertmanager)
	httpMux.HandleFunc("/internal/alert-relay", gs.handleAlertRelay)

	// Health check endpoint (no auth required)
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Grafana reverse proxy (no auth — Grafana handles its own anonymous access)
	if gs.grafanaBackendURL != "" {
		grafanaTarget, err := url.Parse(gs.grafanaBackendURL)
		if err != nil {
			log.Printf("Warning: Invalid Grafana backend URL %q: %v", gs.grafanaBackendURL, err)
		} else {
			grafanaProxy := httputil.NewSingleHostReverseProxy(grafanaTarget)
			httpMux.HandleFunc("/grafana/", func(w http.ResponseWriter, r *http.Request) {
				grafanaProxy.ServeHTTP(w, r)
			})
			httpMux.HandleFunc("/grafana", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/grafana/", http.StatusMovedPermanently)
			})
			log.Printf("Grafana reverse proxy enabled at /grafana/ -> %s", gs.grafanaBackendURL)
		}
	}

	// Alertmanager reverse proxy (no auth — Alertmanager handles its own access)
	if gs.alertmanagerBackendURL != "" {
		amTarget, err := url.Parse(gs.alertmanagerBackendURL)
		if err != nil {
			log.Printf("Warning: Invalid Alertmanager backend URL %q: %v", gs.alertmanagerBackendURL, err)
		} else {
			amProxy := httputil.NewSingleHostReverseProxy(amTarget)
			httpMux.HandleFunc("/alertmanager/", func(w http.ResponseWriter, r *http.Request) {
				amProxy.ServeHTTP(w, r)
			})
			httpMux.HandleFunc("/alertmanager", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/alertmanager/", http.StatusMovedPermanently)
			})
			log.Printf("Alertmanager reverse proxy enabled at /alertmanager/ -> %s", gs.alertmanagerBackendURL)
		}
	}

	// Security CSV export endpoint (with auth via token query param or Authorization header)
	if gs.securityStore != nil {
		registerSecurityExport(httpMux, gs.securityStore, gs.authMiddleware)
		log.Printf("Security CSV export endpoint enabled at /v1/security/clamav-reports/export")
	}

	// Audit logs query endpoint (with auth via token query param or Authorization header)
	if gs.auditStore != nil {
		registerAuditEndpoint(httpMux, gs.auditStore, gs.authMiddleware)
		log.Printf("Audit logs endpoint enabled at /v1/audit/logs")
	}

	// Cert export endpoint (no auth — only reachable within VPC)
	httpMux.HandleFunc("/certs", ServeCerts(gs.caddyCertDir))

	// Authorized keys endpoints (no auth — VPC-internal only, same as /certs)
	// Used by sentinel to sync SSH keys for sshpiper configuration
	httpMux.HandleFunc("/authorized-keys", ServeAuthorizedKeys())
	httpMux.HandleFunc("/authorized-keys/sentinel", ServeSentinelKey())

	// Start HTTP server
	addr := fmt.Sprintf(":%d", gs.httpPort)
	log.Printf("Starting HTTP/REST gateway on %s", addr)
	log.Printf("Web UI available at http://localhost%s/webui/", addr)
	log.Printf("Swagger UI available at http://localhost%s/swagger-ui/", addr)
	log.Printf("OpenAPI spec available at http://localhost%s/swagger.json", addr)

	return http.ListenAndServe(addr, httpMux)
}

// customErrorHandler provides better error messages
func customErrorHandler(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	// Map gRPC codes to HTTP status codes
	httpStatus := runtime.HTTPStatusFromCode(grpc.Code(err))
	w.WriteHeader(httpStatus)

	// Format error response
	errorResp := map[string]interface{}{
		"error": err.Error(),
		"code":  httpStatus,
	}

	json.NewEncoder(w).Encode(errorResp)
}

// annotateContext adds metadata to context
func annotateContext(ctx context.Context, req *http.Request) metadata.MD {
	return metadata.Pairs(
		"x-forwarded-method", req.Method,
		"x-forwarded-path", req.URL.Path,
	)
}

// getAllowedOrigins returns the list of allowed CORS origins.
// Configurable via CONTAINARIUM_ALLOWED_ORIGINS environment variable (comma-separated).
// Defaults to localhost origins only for security.
func getAllowedOrigins() []string {
	envOrigins := os.Getenv("CONTAINARIUM_ALLOWED_ORIGINS")
	if envOrigins != "" {
		origins := strings.Split(envOrigins, ",")
		// Trim whitespace from each origin
		for i, origin := range origins {
			origins[i] = strings.TrimSpace(origin)
		}
		return origins
	}
	// Default to localhost only - secure by default
	return []string{
		"http://localhost:3000",
		"http://localhost:8080",
		"http://localhost",
	}
}
