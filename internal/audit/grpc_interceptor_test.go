package audit

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// #1605 — the native gRPC server produced no audit_logs row for any RPC;
// only the HTTP/grpc-gateway path had a writer. These tests cover
// buildEntry (the pure decision logic: what would this call's row look
// like, or should it not get one at all) without a real Postgres store,
// plus one end-to-end pass through GRPCInterceptor.Unary() with a fake
// logger standing in for *Store.

func testPeerContext(ctx context.Context, ip string, port int) context.Context {
	return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: port}})
}

func TestBuildEntry_PopulatesFields(t *testing.T) {
	md := metadata.Pairs(
		auth.MDKeyUsername, "alice",
		auth.MDKeyRoles, "admin,ops",
		RequestIDHeader, "trace-abc123",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = testPeerContext(ctx, "10.1.2.3", 5555)

	start := time.Now().Add(-50 * time.Millisecond)
	entry := buildEntry(ctx, "/containarium.v1.SecretsService/GetSecret", "grpc_unary", "trace-abc123", start, nil)
	if entry == nil {
		t.Fatal("buildEntry returned nil, want a populated entry")
	}
	if entry.Username != "alice" {
		t.Errorf("Username = %q, want alice", entry.Username)
	}
	if entry.ResourceType != "grpc" {
		t.Errorf("ResourceType = %q, want grpc", entry.ResourceType)
	}
	if entry.ResourceID != "/containarium.v1.SecretsService/GetSecret" {
		t.Errorf("ResourceID = %q, want the FullMethod", entry.ResourceID)
	}
	if entry.Action != "grpc_unary" {
		t.Errorf("Action = %q, want grpc_unary", entry.Action)
	}
	if entry.StatusCode != int(codes.OK) {
		t.Errorf("StatusCode = %d, want %d (OK)", entry.StatusCode, codes.OK)
	}
	if entry.SourceIP != "10.1.2.3:5555" {
		t.Errorf("SourceIP = %q, want peer addr", entry.SourceIP)
	}
	if !strings.Contains(entry.Detail, "request_id=trace-abc123") {
		t.Errorf("Detail = %q, missing request_id", entry.Detail)
	}
	if !strings.Contains(entry.Detail, "roles=admin,ops") {
		t.Errorf("Detail = %q, missing roles", entry.Detail)
	}
	if !strings.Contains(entry.Detail, "duration=") {
		t.Errorf("Detail = %q, missing duration", entry.Detail)
	}
	// #1605 acceptance criterion: no request/response body ever reaches
	// detail — buildEntry never even sees req/resp, so this is really an
	// API-shape guarantee, but assert the field list stays small as a
	// tripwire against a future edit widening it.
	if strings.Contains(entry.Detail, "GetSecret") && strings.Count(entry.Detail, "=") > 3 {
		t.Errorf("Detail looks wider than request_id/duration/roles: %q", entry.Detail)
	}
}

func TestBuildEntry_StatusCodeFromError(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(auth.MDKeyUsername, "bob"))
	err := status.Error(codes.PermissionDenied, "scope required: secrets:read")
	entry := buildEntry(ctx, "/containarium.v1.SecretsService/GetSecret", "grpc_unary", "r1", time.Now(), err)
	if entry == nil {
		t.Fatal("buildEntry returned nil")
	}
	if entry.StatusCode != int(codes.PermissionDenied) {
		t.Errorf("StatusCode = %d, want %d (PermissionDenied)", entry.StatusCode, codes.PermissionDenied)
	}
}

func TestBuildEntry_SkipsGatewayForwardedCalls(t *testing.T) {
	// #1605 acceptance criterion 4: a REST call reaches gRPC through the
	// gateway in-process — it must not produce a second row on top of the
	// one HTTPAuditMiddleware already wrote.
	md := metadata.Pairs(
		auth.MDKeyUsername, "alice",
		GatewayForwardMDKey, "1",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	entry := buildEntry(ctx, "/containarium.v1.SecretsService/GetSecret", "grpc_unary", "r1", time.Now(), nil)
	if entry != nil {
		t.Fatalf("buildEntry = %+v, want nil for a gateway-forwarded call", entry)
	}
}

func TestBuildEntry_NoSubjectStillProducesARow(t *testing.T) {
	// A native gRPC client with no propagated identity (e.g. mTLS-only
	// peer-to-peer traffic) must still be recorded — empty subject, not a
	// skipped row. Coverage, not authentication, is the point.
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
	entry := buildEntry(ctx, "/containarium.v1.ContainerService/ListContainers", "grpc_unary", "r1", time.Now(), nil)
	if entry == nil {
		t.Fatal("buildEntry returned nil, want a row with an empty subject")
	}
	if entry.Username != "" {
		t.Errorf("Username = %q, want empty (no subject was propagated)", entry.Username)
	}
}

func TestRequestIDFromMD_HonorsInbound(t *testing.T) {
	md := metadata.Pairs(RequestIDHeader, "trace-12345-abcdef")
	if got := requestIDFromMD(md); got != "trace-12345-abcdef" {
		t.Fatalf("got %q, want trace-12345-abcdef", got)
	}
}

func TestRequestIDFromMD_RejectsMalformedInbound(t *testing.T) {
	cases := []string{"has spaces", "has;semicolons", strings.Repeat("a", 129)}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			md := metadata.Pairs(RequestIDHeader, in)
			got := requestIDFromMD(md)
			if got == in {
				t.Fatalf("malformed inbound %q should have been replaced", in)
			}
			if len(got) != 32 {
				t.Fatalf("generated ID = %q (len %d), want 32-char hex", got, len(got))
			}
		})
	}
}

func TestRequestIDFromMD_GeneratesWhenAbsent(t *testing.T) {
	got := requestIDFromMD(metadata.MD{})
	if len(got) != 32 {
		t.Fatalf("generated ID = %q (len %d), want 32-char hex", got, len(got))
	}
}

// fakeAuditLogger stands in for *Store — GRPCInterceptor only ever needs
// Log(ctx, *AuditEntry), so a fake satisfying just that lets this test run
// without a Postgres connection.
type fakeAuditLogger struct {
	mu      sync.Mutex
	entries []*AuditEntry
}

func (f *fakeAuditLogger) Log(_ context.Context, e *AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeAuditLogger) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

func (f *fakeAuditLogger) first() *AuditEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.entries) == 0 {
		return nil
	}
	return f.entries[0]
}

// waitForCount polls (no long sleep, bounded deadline) since the writer
// goroutine consumes entryCh asynchronously — same shape production
// accepts as a latency trade-off, see GRPCInterceptor's doc comment.
func waitForCount(t *testing.T, f *fakeAuditLogger, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.count() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d entries, got %d", want, f.count())
}

func TestGRPCInterceptor_Unary_NoStoreIsNoop(t *testing.T) {
	g := NewGRPCInterceptor() // store never attached
	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}
	resp, err := g.Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, handler)
	if err != nil || resp != "ok" {
		t.Fatalf("unexpected result: resp=%v err=%v", resp, err)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestGRPCInterceptor_Unary_WritesEntryWhenArmed(t *testing.T) {
	g := NewGRPCInterceptor()
	fake := &fakeAuditLogger{}
	g.setLogger(fake)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(auth.MDKeyUsername, "alice"))
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}
	_, err := g.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/containarium.v1.SecretsService/GetSecret"}, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	waitForCount(t, fake, 1)
	entry := fake.first()
	if entry.Username != "alice" {
		t.Errorf("Username = %q, want alice", entry.Username)
	}
	if entry.ResourceID != "/containarium.v1.SecretsService/GetSecret" {
		t.Errorf("ResourceID = %q, want the FullMethod", entry.ResourceID)
	}
}

func TestGRPCInterceptor_Unary_SkipsGatewayForwarded(t *testing.T) {
	g := NewGRPCInterceptor()
	fake := &fakeAuditLogger{}
	g.setLogger(fake)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		auth.MDKeyUsername, "alice",
		GatewayForwardMDKey, "1",
	))
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}
	if _, err := g.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, handler); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Give the (non-existent) write a moment it doesn't need, then assert
	// nothing landed — there is no positive signal to wait for here.
	time.Sleep(20 * time.Millisecond)
	if got := fake.count(); got != 0 {
		t.Fatalf("count = %d, want 0 (gateway-forwarded call must not double-log)", got)
	}
}
