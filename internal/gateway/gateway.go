package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/mtls"
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
	grpcAddress     string
	httpPort        int
	authMiddleware  *auth.AuthMiddleware
	swaggerDir      string
	certsDir        string // Optional: for mTLS connection to gRPC server
	terminalHandler *TerminalHandler
	labelHandler    *LabelHandler
	eventHandler    *EventHandler
}

// NewGatewayServer creates a new gateway server
func NewGatewayServer(grpcAddress string, httpPort int, authMiddleware *auth.AuthMiddleware, swaggerDir string, certsDir string) *GatewayServer {
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

	// Create event handler with global event bus
	eventHandler := NewEventHandler(events.GetBus())

	return &GatewayServer{
		grpcAddress:     grpcAddress,
		httpPort:        httpPort,
		authMiddleware:  authMiddleware,
		swaggerDir:      swaggerDir,
		certsDir:        certsDir,
		terminalHandler: terminalHandler,
		labelHandler:    labelHandler,
		eventHandler:    eventHandler,
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

	// Create HTTP handler with authentication middleware
	handler := gs.authMiddleware.HTTPMiddleware(mux)

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

			_, err := gs.authMiddleware.ValidateToken(token)
			if err != nil {
				http.Error(w, `{"error": "unauthorized: invalid token", "code": 401}`, http.StatusUnauthorized)
				return
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

	// Health check endpoint (no auth required)
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

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
