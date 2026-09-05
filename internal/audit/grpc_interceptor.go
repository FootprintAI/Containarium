package audit

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// GatewayForwardMDKey marks a gRPC call as one grpc-gateway made in-process
// while translating a REST request (internal/gateway/gateway.go's
// annotateContext sets it on every outgoing call). GRPCInterceptor checks
// incoming metadata for it and skips writing a row when present — the HTTP
// audit middleware already logged the same request at the REST layer, and
// without this guard every REST call would produce two audit_logs rows
// (#1605 acceptance criterion 4: "make sure that produces one row, not two").
const GatewayForwardMDKey = "x-containarium-gateway-forward"

// auditLogger is the write surface GRPCInterceptor needs from a *Store —
// narrowed to one method so tests can substitute a fake without a real
// Postgres connection. Production callers pass a *Store via SetStore.
type auditLogger interface {
	Log(ctx context.Context, entry *AuditEntry) error
}

// GRPCInterceptor audits the native gRPC server the way HTTPAuditMiddleware
// audits the REST/grpc-gateway path (#1605). Before this, audit_logs was fed
// by exactly one writer — the HTTP middleware — so an RPC served on the
// native gRPC port produced no row while the identical RPC served over REST
// produced one; which of the two an operator's action landed in depended on
// the client they happened to use, not on what the action was.
//
// The audit store isn't available until well after the gRPC server is
// constructed (dual_server.go's NewDualServer connects to Postgres later in
// the same function), so this holds a settable reference rather than a
// fixed one — the same shape as GatewayServer.SetAuditStore /
// ContainerServer.SetAuditStore. Register Unary()/Stream() with
// grpc.NewServer() immediately; they no-op until SetStore is called.
type GRPCInterceptor struct {
	mu      sync.RWMutex
	store   auditLogger
	entryCh chan *AuditEntry
}

// NewGRPCInterceptor returns an interceptor with no store attached yet and
// starts its background writer goroutine (same async-write shape as
// HTTPAuditMiddleware, so a slow Postgres write never adds latency to the
// RPC it's auditing). Safe to register with grpc.NewServer() right away.
func NewGRPCInterceptor() *GRPCInterceptor {
	g := &GRPCInterceptor{entryCh: make(chan *AuditEntry, 256)}
	go func() {
		for entry := range g.entryCh {
			st := g.getStore()
			if st == nil {
				continue
			}
			if err := st.Log(context.Background(), entry); err != nil {
				log.Printf("audit: failed to write grpc log: %v", err)
			}
		}
	}()
	return g
}

// SetStore attaches the audit store, arming the interceptor. Call once,
// from dual_server.go, right after the audit store connects.
func (g *GRPCInterceptor) SetStore(store *Store) {
	g.setLogger(store)
}

func (g *GRPCInterceptor) setLogger(l auditLogger) {
	g.mu.Lock()
	g.store = l
	g.mu.Unlock()
}

func (g *GRPCInterceptor) getStore() auditLogger {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.store
}

// Unary returns a grpc.UnaryServerInterceptor. Register it AFTER the auth
// interceptor in dual_server.go's grpc.NewServer() call — same ordering as
// gateway.go's "auth first (sets username in context), then audit" HTTP
// stack — so SubjectFromGRPCContext below actually finds something.
func (g *GRPCInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		reqID := requestIDFromMD(incomingMD(ctx))
		ctx = ContextWithRequestID(ctx, reqID)
		_ = grpc.SetHeader(ctx, metadata.Pairs(RequestIDHeader, reqID))

		resp, err := handler(ctx, req)

		g.record(ctx, info.FullMethod, "grpc_unary", reqID, start, err)
		return resp, err
	}
}

// Stream is the streaming counterpart of Unary.
func (g *GRPCInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		ctx := ss.Context()
		reqID := requestIDFromMD(incomingMD(ctx))
		ctx = ContextWithRequestID(ctx, reqID)
		_ = ss.SetHeader(metadata.Pairs(RequestIDHeader, reqID))

		err := handler(srv, &wrappedServerStream{ServerStream: ss, ctx: ctx})

		g.record(ctx, info.FullMethod, "grpc_stream", reqID, start, err)
		return err
	}
}

// wrappedServerStream overrides Context() so a stream handler (and anything
// it calls) sees the request-ID-bearing context, the same way the unary
// path passes its own modified ctx to handler(ctx, req).
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context { return w.ctx }

// record builds the audit entry and hands it to the async writer, unless
// the store isn't armed yet or buildEntry decides to skip this call.
func (g *GRPCInterceptor) record(ctx context.Context, fullMethod, action, reqID string, start time.Time, callErr error) {
	if g.getStore() == nil {
		return
	}
	entry := buildEntry(ctx, fullMethod, action, reqID, start, callErr)
	if entry == nil {
		return
	}
	select {
	case g.entryCh <- entry:
	default:
		// Channel full — drop rather than block the RPC. Same trade-off
		// HTTPAuditMiddleware makes.
	}
}

// buildEntry is a pure function (no I/O) so it's unit-testable without a
// store or a real gRPC call. Returns nil when this call shouldn't produce
// its own row — currently just the gateway-forward dedup case.
func buildEntry(ctx context.Context, fullMethod, action, reqID string, start time.Time, callErr error) *AuditEntry {
	md := incomingMD(ctx)
	if len(md.Get(GatewayForwardMDKey)) > 0 {
		return nil
	}

	username, roles, _ := auth.SubjectFromGRPCContext(ctx)

	peerAddr := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		peerAddr = p.Addr.String()
	}

	// Detail carries the same `request_id=... duration=...` shape as the
	// HTTP middleware, plus roles (the HTTP path doesn't carry these today,
	// but the issue asks for them here — no dedicated column, so they ride
	// in Detail like everything else that isn't a first-class field).
	detail := "request_id=" + reqID + " duration=" + time.Since(start).String()
	if len(roles) > 0 {
		detail += " roles=" + strings.Join(roles, ",")
	}

	return &AuditEntry{
		Timestamp:    start,
		Username:     username,
		Action:       action,
		ResourceType: "grpc",
		ResourceID:   fullMethod,
		Detail:       SanitizeDetail(detail),
		SourceIP:     peerAddr,
		StatusCode:   int(status.Code(callErr)),
	}
}

func incomingMD(ctx context.Context) metadata.MD {
	md, _ := metadata.FromIncomingContext(ctx)
	return md
}

// requestIDFromMD is requestIDHeader's gRPC-side counterpart: honor an
// inbound x-request-id (grpc metadata keys are case-insensitive/lowercased
// on both Set and Get) if it's shaped like one, otherwise mint a fresh one.
// Reuses the same validRequestID/newRequestID request_id.go already defines
// for the HTTP path.
func requestIDFromMD(md metadata.MD) string {
	if vals := md.Get(RequestIDHeader); len(vals) > 0 && validRequestID(vals[0]) {
		return vals[0]
	}
	return newRequestID()
}
