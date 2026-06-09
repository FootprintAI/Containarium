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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/mtls"
	"github.com/footprintai/containarium/internal/releases"
	"github.com/footprintai/containarium/internal/security"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// GatewayServer implements the HTTP/REST gateway for the gRPC service
type GatewayServer struct {
	grpcAddress            string
	httpPort               int
	authMiddleware         *auth.AuthMiddleware
	swaggerDir             string
	certsDir               string          // Optional: for mTLS connection to gRPC server
	caddyCertDir           string          // Optional: Caddy certificate directory for /certs endpoint
	grafanaBackendURL      string          // Optional: internal Grafana URL for reverse proxy (e.g., "http://10.0.3.229:3000")
	alertmanagerBackendURL string          // Optional: internal Alertmanager URL for reverse proxy (e.g., "http://10.0.3.229:9093")
	securityStore          *security.Store // Optional: for CSV export endpoint
	auditStore             *audit.Store    // Optional: for HTTP audit middleware
	terminalHandler        *TerminalHandler
	labelHandler           *LabelHandler
	eventHandler           *EventHandler
	coreServicesHandler    *CoreServicesHandler

	// Guacamole reverse proxy (browser-based RDP for Windows VMs)
	guacamoleBackendURL string

	// Backends handler (for multi-backend support, set externally)
	backendsHandler http.HandlerFunc

	// sentinelAuthSecret is the shared HMAC secret used by the
	// sentinel to authenticate calls to /authorized-keys and /certs.
	// Set via CONTAINARIUM_SENTINEL_AUTH_SECRET. Nil/short means the
	// wrapped endpoints fail closed (401) — fail-open is never an
	// acceptable default for these endpoints (see audit C-CRIT-4 and
	// A-CRIT-4).
	sentinelAuthSecret []byte

	// containerExistsFn is the orphan filter used by
	// /authorized-keys (#343). When set, the handler drops users
	// whose container has been deleted but whose home dir survived.
	// Wired from dual_server using the container manager.
	containerExistsFn func(username string) bool

	// Wake handler (for serverless / wake-on-HTTP, set externally).
	// Mounted at /wake/ and at the root catch-all when the daemon's
	// wake feature is enabled. NOT wrapped by the JWT auth middleware
	// — Caddy forwards user traffic here, and that traffic doesn't
	// carry the daemon's JWT.
	wakeHandler http.Handler

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
		grpcAddress:         grpcAddress,
		httpPort:            httpPort,
		authMiddleware:      authMiddleware,
		swaggerDir:          swaggerDir,
		certsDir:            certsDir,
		caddyCertDir:        caddyCertDir,
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

// SetGuacamoleBackendURL sets the internal Guacamole URL for the reverse proxy
func (gs *GatewayServer) SetGuacamoleBackendURL(backendURL string) {
	gs.guacamoleBackendURL = backendURL
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
// SetSentinelAuthSecret configures the shared HMAC secret that the
// sentinel uses to sign its calls to /authorized-keys and /certs.
// Pass a slice that satisfies auth.SentinelMinSecretLen; shorter
// values cause those endpoints to fail closed (401 for every call).
// The expected source is CONTAINARIUM_SENTINEL_AUTH_SECRET on both
// the daemon and the sentinel.
func (gs *GatewayServer) SetSentinelAuthSecret(secret []byte) {
	gs.sentinelAuthSecret = secret
}

// SetContainerExistsFn wires the orphan filter for /authorized-keys.
// When set, sentinel keysync responses exclude entries whose container
// has been deleted — preventing the #343 "auth accepted, then
// disconnected" symptom.
func (gs *GatewayServer) SetContainerExistsFn(fn func(username string) bool) {
	gs.containerExistsFn = fn
}

// SetBackendsHandler sets the handler for the /v1/backends endpoint.
func (gs *GatewayServer) SetBackendsHandler(handler http.HandlerFunc) {
	gs.backendsHandler = handler
}

// SetWakeHandler sets the handler mounted at /wake/ — the wake-on-HTTP
// entry point Caddy forwards user traffic to while a container is
// auto-slept. The handler is unauthenticated (the auth middleware is
// for API callers, not for incoming user requests).
func (gs *GatewayServer) SetWakeHandler(handler http.Handler) {
	gs.wakeHandler = handler
}

// SetTerminalPeerProxy configures the terminal handler to proxy WebSocket
// connections to peer backends for multi-backend terminal support.
func (gs *GatewayServer) SetTerminalPeerProxy(proxy PeerTerminalProxy) {
	if gs.terminalHandler != nil {
		gs.terminalHandler.SetPeerProxy(proxy)
	}
}

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
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
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
				DiscardUnknown: false,
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

	// Register RecipeService gateway handler
	if err := pb.RegisterRecipeServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register recipe service gateway: %w", err)
	}

	// Register AgentSkillService gateway handler
	if err := pb.RegisterAgentSkillServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register agent-skill service gateway: %w", err)
	}

	// Register BackupService gateway handler
	if err := pb.RegisterBackupServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register backup service gateway: %w", err)
	}

	// Register VolumeService gateway handler (#384)
	if err := pb.RegisterVolumeServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register volume service gateway: %w", err)
	}

	// Register KmsService gateway handler (KMS status / envelope
	// coverage / migration).
	if err := pb.RegisterKmsServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register kms service gateway: %w", err)
	}

	// Register NetworkPolicyService gateway handler (#315)
	if err := pb.RegisterNetworkPolicyServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register network policy service gateway: %w", err)
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

	// Register ZapService gateway handler
	if err := pb.RegisterZapServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register zap service gateway: %w", err)
	}

	// Register TokensService gateway handler (Phase 1.2 follow-up)
	if err := pb.RegisterTokensServiceHandlerFromEndpoint(ctx, mux, gs.grpcAddress, opts); err != nil {
		return fmt.Errorf("failed to register tokens service gateway: %w", err)
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

	// Terminal WebSocket route.
	//
	// Phase 1.5 — auth token comes from the WebSocket
	// subprotocol header (`Sec-WebSocket-Protocol`) by
	// preference, since browsers can't attach arbitrary
	// headers to `new WebSocket(url)`. Authorization header
	// + `?token=` are kept as backwards-compat fallbacks;
	// query-param use is logged as a deprecation WARNING.
	// See internal/auth/ws_token.go.
	if gs.terminalHandler != nil {
		// Wrap terminal handler with CORS (using configurable origins)
		terminalWithCORS := cors.New(cors.Options{
			AllowedOrigins:   getAllowedOrigins(),
			AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders:   []string{"Authorization", "Content-Type", "Upgrade", "Connection", "Sec-WebSocket-Protocol"},
			AllowCredentials: true,
		}).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, src := auth.ExtractBearerForUpgrade(r)
			if src == auth.TokenSourceQueryParam {
				log.Printf("WARNING: terminal client used deprecated ?token= (remote=%s, host=%q) — switch to Sec-WebSocket-Protocol", r.RemoteAddr, r.Host)
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
				if err := gs.auditStore.Log(r.Context(), &audit.AuditEntry{
					Username:     auditUsername,
					Action:       "terminal_access",
					ResourceType: "container",
					ResourceID:   containerName,
					SourceIP:     sourceIP,
				}); err != nil {
					log.Printf("Failed to write audit log for terminal_access: %v", err)
				}
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

	// Wake-on-HTTP handler (no auth — Caddy forwards user traffic here
	// while a container is auto-slept, and that traffic carries no JWT).
	// /wake/* is the explicit smoke-test path; the daemon's path-based
	// routes (/v1/, /swagger-ui/, /webui/, etc.) take precedence in
	// http.ServeMux's "longest prefix wins" rule. Caddy itself sends
	// the original user path through unchanged, so wake-mode user
	// traffic arrives as / or /<app-path> — those are caught by the
	// fallback registered below at gateway-Start time.
	if gs.wakeHandler != nil {
		httpMux.Handle("/wake/", gs.wakeHandler)
		httpMux.Handle("/wake", gs.wakeHandler)
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

	// Events SSE endpoint.
	//
	// Phase 1.5 — Authorization header is the canonical
	// source. SSE is not a WebSocket, so the subprotocol
	// path is irrelevant — but ExtractBearerForUpgrade
	// still gives us a single audit-friendly extraction
	// point. `?token=` is accepted with a deprecation
	// WARNING so we can surface affected clients.
	eventsWithCORS := cors.New(cors.Options{
		AllowedOrigins:   getAllowedOrigins(),
		AllowedMethods:   []string{"GET", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "Cache-Control"},
		AllowCredentials: true,
	}).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, src := auth.ExtractBearerForUpgrade(r)
		if src == auth.TokenSourceQueryParam {
			log.Printf("WARNING: events SSE client used deprecated ?token= (remote=%s) — switch to Authorization: Bearer", r.RemoteAddr)
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

	// Swagger UI routes. Phase 5.1 (audit A-LOW-1) — both
	// the UI bundle and the spec discloses the full API
	// surface (route paths, request shapes, security
	// requirements). That's operator-tier knowledge, not
	// public. Wrap with HTTPMiddleware (auth gate) AND
	// requireAdminFromContext (role gate).
	swaggerUI := http.StripPrefix("/swagger-ui", http.HandlerFunc(ServeSwaggerUI(gs.swaggerDir)))
	httpMux.Handle("/swagger-ui/", gs.authMiddleware.HTTPMiddleware(requireAdminFromContext(swaggerUI)))
	httpMux.Handle("/swagger.json", gs.authMiddleware.HTTPMiddleware(requireAdminFromContext(http.HandlerFunc(ServeSwaggerSpec(gs.swaggerDir)))))

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

	mountInternalProxies(httpMux, gs)

	// Session-cookie set/clear endpoint. Lets the webui promote its
	// localStorage JWT into a cookie so iframe loads (notably the
	// /grafana/ proxy on the monitoring page) can authenticate.
	// Issue #338.
	registerCookieSession(httpMux, gs.authMiddleware)

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

	// Version-visibility endpoint (#354): this daemon's version + the latest
	// published GitHub release (cached 1h) so the webui / CLI can show drift.
	registerVersionEndpoints(httpMux, releases.NewClient(), gs.authMiddleware)
	log.Printf("Version endpoint enabled at /v1/releases/latest")

	// Backends endpoint. The LIST (GET /v1/backends) is now the proto-first
	// ContainerService.ListBackends RPC — it flows through the grpc-gateway
	// (corsHandler) like every other /v1/ route, so the wire shape is
	// generated from BackendInfo and can't drift from the CLI / MCP / cloud
	// consumers (#354, proto-first convention). We register the exact path
	// explicitly so http.ServeMux does NOT 301-redirect it into the
	// trailing-slash subtree below.
	//
	// The per-backend forward (GET /v1/backends/{id}/system-info) is still
	// the hand-coded handler — it proxies to a specific peer rather than
	// returning a generated message — mounted on the subtree only. Auth on
	// the RPC path is the gRPC ListBackends admin check + JWT interceptor
	// (RequireRole admin); the subtree keeps its own JWT middleware.
	httpMux.Handle("/v1/backends", corsHandler)
	if gs.backendsHandler != nil {
		authed := gs.authMiddleware.HTTPMiddleware(http.HandlerFunc(gs.backendsHandler))
		httpMux.Handle("/v1/backends/", authed)
	}

	// Sentinel-facing endpoints: /certs and /authorized-keys[/sentinel].
	// Previously "no auth — VPC-internal only"; that comment never
	// stopped a firewall misconfiguration. Now gated by HMAC over
	// CONTAINARIUM_SENTINEL_AUTH_SECRET (auth.SentinelHMACMiddleware).
	// Fail-closed: if the secret isn't configured, all requests get
	// 401. See findings A-CRIT-4 and A-HIGH-2.
	httpMux.Handle("/certs", auth.SentinelHMACMiddleware(gs.sentinelAuthSecret, ServeCerts(gs.caddyCertDir)))
	httpMux.Handle("/authorized-keys", auth.SentinelHMACMiddleware(gs.sentinelAuthSecret, ServeAuthorizedKeys("", gs.containerExistsFn)))
	httpMux.Handle("/authorized-keys/sentinel", auth.SentinelHMACMiddleware(gs.sentinelAuthSecret, ServeSentinelKey()))

	// Catch-all fallback: when wake-on-HTTP is enabled, Caddy
	// forwards user traffic to this daemon while a container is
	// auto-slept, and that traffic arrives at arbitrary paths (the
	// app's original URL, e.g. /api/whatever). Any path not matched
	// by a more specific handler above falls through to the wake
	// handler, which resolves the container by the incoming Host
	// header. When wake is disabled this registration is a no-op.
	if gs.wakeHandler != nil {
		httpMux.Handle("/", gs.wakeHandler)
	}

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
	httpStatus := runtime.HTTPStatusFromCode(status.Code(err))
	w.WriteHeader(httpStatus)

	// Format error response
	errorResp := map[string]interface{}{
		"error": err.Error(),
		"code":  httpStatus,
	}

	_ = json.NewEncoder(w).Encode(errorResp)
}

// annotateContext adds metadata that grpc-gateway forwards into the
// outgoing gRPC call. We use it to propagate the authenticated
// subject from AuthMiddleware (which lives on r.Context()) into
// gRPC metadata, where SubjectFromGRPCContext picks it up on the
// server side. Without this, gRPC handlers cannot enforce
// per-resource authorization.
// requireAdminFromContext rejects requests whose authenticated
// subject does not hold the admin role. Must run AFTER the
// auth middleware (which stamps username + roles into the
// request context). Phase 5.1 — used to gate /swagger-ui/
// and /swagger.json so the full API surface isn't disclosed
// to any reachable client.
func requireAdminFromContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roles, _ := auth.RolesFromContext(r.Context())
		if !auth.HasRole(roles, auth.RoleAdmin) {
			http.Error(w, `{"error":"admin role required","code":403}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func annotateContext(ctx context.Context, req *http.Request) metadata.MD {
	md := metadata.Pairs(
		"x-forwarded-method", req.Method,
		"x-forwarded-path", req.URL.Path,
	)
	if username, ok := auth.UsernameFromContext(ctx); ok && username != "" {
		md.Set(auth.MDKeyUsername, username)
	}
	if roles, ok := auth.RolesFromContext(ctx); ok && len(roles) > 0 {
		md.Set(auth.MDKeyRoles, strings.Join(roles, ","))
	}
	// Phase 1.7b — forward the optional `scopes` claim. Missing
	// claim → no metadata entry → RequireScope sees nil grants
	// → backwards-compat unrestricted.
	if scopes, ok := auth.ScopesFromContext(ctx); ok && len(scopes) > 0 {
		md.Set(auth.MDKeyScopes, strings.Join(scopes, ","))
	}
	return md
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
