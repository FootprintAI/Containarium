package auth

import "testing"

func TestSetStrictScopes_TogglesState(t *testing.T) {
	defer SetStrictScopes(false)

	SetStrictScopes(true)
	if !StrictScopesEnabled() {
		t.Fatal("StrictScopesEnabled() = false after SetStrictScopes(true)")
	}
	SetStrictScopes(false)
	if StrictScopesEnabled() {
		t.Fatal("StrictScopesEnabled() = true after SetStrictScopes(false)")
	}
}

func TestStrictScopesEnabled_DefaultsFalse(t *testing.T) {
	// Package-level default before anything calls SetStrictScopes — matches
	// the AC "default remains permissive."
	if StrictScopesEnabled() {
		t.Fatal("StrictScopesEnabled() = true with no SetStrictScopes call; default must be permissive")
	}
}

func TestUnscopedTokenCalls_TracksCountAndSince(t *testing.T) {
	ResetUnscopedTokenCallsForTest()

	if got := UnscopedTokenCalls(); got.Count != 0 || !got.Since.IsZero() {
		t.Fatalf("fresh report = %+v, want zero count and zero Since", got)
	}

	recordUnscopedCall()
	recordUnscopedCall()
	recordUnscopedCall()

	got := UnscopedTokenCalls()
	if got.Count != 3 {
		t.Fatalf("Count = %d, want 3", got.Count)
	}
	if got.Since.IsZero() {
		t.Fatal("Since is zero after recording a call, want the time of the first call")
	}
}

func TestUnscopedTokenCalls_SinceIsStableAcrossCalls(t *testing.T) {
	ResetUnscopedTokenCallsForTest()

	recordUnscopedCall()
	first := UnscopedTokenCalls().Since

	recordUnscopedCall()
	second := UnscopedTokenCalls().Since

	if !first.Equal(second) {
		t.Fatalf("Since changed from %v to %v across calls; want the FIRST call's timestamp to stick", first, second)
	}
}
