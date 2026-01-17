package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
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
}

// NewGatewayServer creates a new gateway server
func NewGatewayServer(grpcAddress string, httpPort int, authMiddleware *auth.AuthMiddleware, swaggerDir string, certsDir string) *GatewayServer {
	// Try to create terminal handler (may fail if Incus not available)
	terminalHandler, err := NewTerminalHandler()
	if err != nil {
		log.Printf("Warning: Terminal handler not available: %v", err)
	}

	return &GatewayServer{
		grpcAddress:     grpcAddress,
		httpPort:        httpPort,
		authMiddleware:  authMiddleware,
		swaggerDir:      swaggerDir,
		certsDir:        certsDir,
		terminalHandler: terminalHandler,
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

	// Create HTTP handler with authentication middleware
	handler := gs.authMiddleware.HTTPMiddleware(mux)

	// Add CORS support
	// TODO: Make this configurable via environment variable for production
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",  // Development (Next.js dev server)
			"http://localhost",       // Production (same host /webui path)
			"*",                      // Allow all for now - should be restricted in production
		},
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
		// Wrap terminal handler with CORS
		terminalWithCORS := cors.New(cors.Options{
			AllowedOrigins:   []string{"*"},
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
			if token != "" {
				_, err := gs.authMiddleware.ValidateToken(token)
				if err != nil {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
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
			// Not a terminal request, pass to gRPC gateway with CORS
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
