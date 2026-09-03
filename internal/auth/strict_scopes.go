package auth

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// #1679 — scopes fail open by design (Phase 1.7 backwards compat: a token
// with no `scopes` claim is unrestricted). Strict mode is the opt-in
// backstop that flips that default for a daemon whose operator has decided
// every token must carry an explicit scope grant.
//
// Package-level state, not threaded through a config object, because
// RequireScope is a free function called from every gRPC handler across the
// tree — the same reason ScopesFromGRPCContext/etc. are package-level here.
// Set once at daemon startup (see internal/server/dual_server.go) from
// internal/config's CONTAINARIUM_STRICT_SCOPES; tests toggle it directly.
var strictScopesEnabled atomic.Bool

// SetStrictScopes arms or disarms strict-scope enforcement. Off (the
// zero value) is the default permissive posture — RequireScope keeps
// treating an absent scopes claim as unrestricted until this is called
// with true.
func SetStrictScopes(enabled bool) {
	strictScopesEnabled.Store(enabled)
}

// StrictScopesEnabled reports the current mode.
func StrictScopesEnabled() bool {
	return strictScopesEnabled.Load()
}

// strictScopesDenialPrefix marks a PermissionDenied error as originating
// from strict mode rejecting an unscoped token, as opposed to RequireScope's
// ordinary insufficient-scope denial. IsStrictScopesDenial checks for it.
// An operator grepping logs (or a caller inspecting the error) can tell the
// two apart — the AC this exists for.
const strictScopesDenialPrefix = "strict scope mode: unscoped token rejected"

// IsStrictScopesDenial reports whether err is RequireScope's strict-mode
// rejection of an unscoped token, as opposed to an ordinary
// insufficient-scope PermissionDenied.
func IsStrictScopesDenial(err error) bool {
	return err != nil && strings.Contains(err.Error(), strictScopesDenialPrefix)
}

// Unscoped-token-call measurement: an in-process counter so an operator can
// answer "how many recent calls used an unscoped token" before flipping
// CONTAINARIUM_STRICT_SCOPES on — the rollout is meant to be a measured
// decision, not a gamble. Recorded on every RequireScope call whose token
// carries no scopes claim, in BOTH modes — strict mode only changes whether
// the call is then rejected, not whether it's counted. Resets on daemon
// restart; there is no persistence layer for this, deliberately: it answers
// "what does traffic look like right now," not "what did it look like last
// month."
var unscopedCalls struct {
	mu    sync.Mutex
	count int64
	since time.Time
}

func recordUnscopedCall() {
	unscopedCalls.mu.Lock()
	defer unscopedCalls.mu.Unlock()
	if unscopedCalls.count == 0 {
		unscopedCalls.since = time.Now()
	}
	unscopedCalls.count++
}

// ResetUnscopedTokenCallsForTest clears the counter between test cases.
// Test-only: production has no legitimate reason to reset a measurement
// mid-flight. Exported (like ContextWithTestSubjectScopes) so other
// packages' tests — e.g. TokensServer's — can start from a clean count.
func ResetUnscopedTokenCallsForTest() {
	unscopedCalls.mu.Lock()
	defer unscopedCalls.mu.Unlock()
	unscopedCalls.count = 0
	unscopedCalls.since = time.Time{}
}

// UnscopedTokenCallReport is a point-in-time snapshot of the unscoped-token
// measurement, surfaced to operators via
// TokensService.GetUnscopedTokenReport.
type UnscopedTokenCallReport struct {
	// Count is the number of RequireScope calls observed whose token
	// carried no scopes claim, since Since (or 0 if none yet).
	Count int64
	// Since is when the first such call was observed. Zero if Count is 0.
	Since time.Time
}

// UnscopedTokenCalls returns the current unscoped-token-call measurement.
func UnscopedTokenCalls() UnscopedTokenCallReport {
	unscopedCalls.mu.Lock()
	defer unscopedCalls.mu.Unlock()
	return UnscopedTokenCallReport{Count: unscopedCalls.count, Since: unscopedCalls.since}
}
