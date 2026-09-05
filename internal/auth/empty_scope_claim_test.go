package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

// #1722. An empty scopes claim arriving through gRPC metadata was reported as
// ABSENT, and an absent claim reads as unrestricted — so the two opposite
// intents, "this credential holds nothing" and "this credential is
// unrestricted", produced the same answer, and it was the permissive one.
//
// The context-value path never had this problem: it reports present for any
// non-nil slice, so an empty grant denies. These pin the two paths to the same
// answer.
//
// Not reachable in production — every writer of MDKeyScopes guards on
// len(scopes) > 0, and generate() omits the claim entirely for zero scopes.
// The harm is in tests: an assertion written as "a caller with no scopes is
// denied" passes whether or not the guard under test exists, because such a
// caller is read as unrestricted and the handler answers normally.

func TestScopesFromGRPCContext_EmptyClaimIsPresentNotAbsent(t *testing.T) {
	cases := []struct {
		name        string
		md          metadata.MD
		wantPresent bool
		wantLen     int
	}{
		{
			name:        "no scopes key at all — absent, the v0 unrestricted shape",
			md:          metadata.Pairs(MDKeyUsername, "alice"),
			wantPresent: false,
		},
		{
			name:        "scopes key carried but empty — an explicit empty grant",
			md:          metadata.Pairs(MDKeyUsername, "alice", MDKeyScopes, ""),
			wantPresent: true,
			wantLen:     0,
		},
		{
			name:        "scopes carried with a value",
			md:          metadata.Pairs(MDKeyUsername, "alice", MDKeyScopes, "containers:read"),
			wantPresent: true,
			wantLen:     1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), c.md)
			got, present := ScopesFromGRPCContext(ctx)
			if present != c.wantPresent {
				t.Errorf("present = %v, want %v", present, c.wantPresent)
			}
			if len(got) != c.wantLen {
				t.Errorf("scopes = %v (len %d), want len %d", got, len(got), c.wantLen)
			}
		})
	}
}

// The consequence that matters: an explicit empty grant must be DENIED, not
// waved through as unrestricted.
func TestRequireScope_DeniesAnExplicitEmptyGrant(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "alice", MDKeyRoles, "user", MDKeyScopes, ""))

	if err := RequireScope(ctx, ScopeContainersRead); err == nil {
		t.Fatal("a caller holding an explicit empty grant was allowed — " +
			"an empty grant is being read as unrestricted")
	}
}

// The backward-compatible case must NOT change: a token with no scopes claim
// stays unrestricted until strict mode is armed (#1679). Flipping this would
// reject every pre-scopes token in the fleet.
func TestRequireScope_AbsentClaimStaysUnrestricted(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "alice", MDKeyRoles, "user"))

	if err := RequireScope(ctx, ScopeContainersRead); err != nil {
		t.Fatalf("an absent scopes claim was denied: %v — this would reject "+
			"every token minted before scopes existed", err)
	}
}

// Both transports must agree. The same logical credential arriving as a
// context value or as metadata cannot get opposite answers.
func TestScopeTransports_AgreeOnAnEmptyGrant(t *testing.T) {
	viaMetadata := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "alice", MDKeyScopes, ""))
	viaContextValue := context.WithValue(context.Background(), ContextKeyScopes, []string{})

	_, mdPresent := ScopesFromGRPCContext(viaMetadata)
	_, cvPresent := ScopesFromGRPCContext(viaContextValue)

	if mdPresent != cvPresent {
		t.Errorf("metadata present=%v but context-value present=%v — the same "+
			"credential gets different authority depending on which hop it arrived through",
			mdPresent, cvPresent)
	}
}
