package server

import (
	"testing"

	"github.com/footprintai/containarium/internal/sandbox/ratelimit"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestSpawnSandbox_DefaultRateLimiterAllowsUnbounded pins that a freshly
// constructed SandboxServer — no SetRateLimiter call at all — never
// throttles: NewSandboxServer's default must be ratelimit.Disabled(),
// not a nil pointer or an implicitly-zero (and therefore enforced)
// limiter.
func TestSpawnSandbox_DefaultRateLimiterAllowsUnbounded(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)

	for i := 0; i < 20; i++ {
		if _, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{}); err != nil {
			t.Fatalf("spawn %d with no rate limiter configured: %v", i, err)
		}
	}
}

// TestSpawnSandbox_RateLimitedTenantGetsResourceExhausted pins the core
// behavior: once a tenant exhausts its burst, the NEXT spawn is refused
// with ResourceExhausted, not silently served — an admission-control
// check that can't ever fail proves nothing.
func TestSpawnSandbox_RateLimitedTenantGetsResourceExhausted(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)
	s.SetRateLimiter(ratelimit.New(0.001, 2))

	for i := 0; i < 2; i++ {
		if _, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{}); err != nil {
			t.Fatalf("spawn %d within burst: %v", i, err)
		}
	}

	_, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{})
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted (burst exhausted)", got)
	}
}

// TestSpawnSandbox_RateLimitIsPerTenant is
// TestSpawnSandbox_RateLimitedTenantGetsResourceExhausted's sibling: a
// DIFFERENT tenant must not be affected by alice's exhausted bucket — a
// shared-not-per-subject limiter (or one keyed on the wrong field) would
// fail this while still passing the single-tenant test above.
func TestSpawnSandbox_RateLimitIsPerTenant(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)
	s.SetRateLimiter(ratelimit.New(0.001, 1))

	if _, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{}); err != nil {
		t.Fatalf("alice's first spawn: %v", err)
	}
	if _, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("alice's second spawn (over her burst of 1): code = %v, want ResourceExhausted", status.Code(err))
	}
	if _, err := s.SpawnSandbox(ctxAs("bob", false), &pb.SpawnSandboxRequest{}); err != nil {
		t.Errorf("bob's first spawn was refused by alice's rate limit: %v", err)
	}
}

// TestSpawnSandbox_PoisonedRateLimiterRefusesEveryone pins the
// fail-closed contract for a malformed operator config: every spawn is
// refused (Internal, distinct from a legitimate rate-limit
// ResourceExhausted — an operator misconfiguration is not the same
// class of error as "you're going too fast").
func TestSpawnSandbox_PoisonedRateLimiterRefusesEveryone(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)
	s.SetRateLimiter(ratelimit.NewFromEnv("not-a-number", ""))

	_, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{})
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal (poisoned/misconfigured rate limiter)", got)
	}
}

// TestSpawnSandbox_SetRateLimiterNilRestoresDisabled pins that passing
// nil to SetRateLimiter doesn't leave a real nil pointer that would
// panic on the next spawn — it must fall back to ratelimit.Disabled().
func TestSpawnSandbox_SetRateLimiterNilRestoresDisabled(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)
	s.SetRateLimiter(ratelimit.New(0.001, 1))
	s.SetRateLimiter(nil)

	for i := 0; i < 5; i++ {
		if _, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{}); err != nil {
			t.Fatalf("spawn %d after SetRateLimiter(nil): %v", i, err)
		}
	}
}
