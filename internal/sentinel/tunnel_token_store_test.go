package sentinel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTunnelTokenStore_MissingFileIsNotError(t *testing.T) {
	entries, err := LoadTunnelTokenStore(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("missing file must not be an error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(entries))
	}
}

func TestSaveTunnelTokenStore_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnel-tokens.json")
	want := []TunnelTokenEntry{
		{Token: "tok-a", Pools: []Pool{PoolAny}},
		{Token: "tok-b", Pools: []Pool{"lab", "prod"}},
	}
	if err := SaveTunnelTokenStore(path, want); err != nil {
		t.Fatalf("SaveTunnelTokenStore: %v", err)
	}
	got, err := LoadTunnelTokenStore(path)
	if err != nil {
		t.Fatalf("LoadTunnelTokenStore: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("entry count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Token != want[i].Token {
			t.Errorf("entry %d token = %q, want %q", i, got[i].Token, want[i].Token)
		}
	}
}

func TestApplyTunnelTokenStore_MergesIntoPolicy(t *testing.T) {
	policy := NewTokenPolicy()
	entries := []TunnelTokenEntry{
		{Token: "tok-a", Pools: []Pool{PoolAny}},
		{Token: "tok-b", Pools: []Pool{"lab"}},
	}
	ApplyTunnelTokenStore(entries, policy)

	if err := policy.Validate("tok-a", "anything"); err != nil {
		t.Errorf("tok-a should validate for any pool: %v", err)
	}
	if err := policy.Validate("tok-b", "lab"); err != nil {
		t.Errorf("tok-b should validate for lab: %v", err)
	}
	if err := policy.Validate("tok-b", "prod"); err == nil {
		t.Error("tok-b should NOT validate for prod")
	}
	if err := policy.Validate("unknown", ""); err == nil {
		t.Error("an unregistered token must still be rejected")
	}
}

func TestUpsertTunnelTokenEntry_AppendsNew(t *testing.T) {
	entries := []TunnelTokenEntry{{Token: "existing", Pools: []Pool{PoolAny}}}
	got := upsertTunnelTokenEntry(entries, "new-token", []Pool{"lab"})
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[1].Token != "new-token" {
		t.Errorf("appended entry token = %q, want new-token", got[1].Token)
	}
}

func TestUpsertTunnelTokenEntry_ReplacesExistingPools(t *testing.T) {
	entries := []TunnelTokenEntry{{Token: "tok-a", Pools: []Pool{"lab"}}}
	got := upsertTunnelTokenEntry(entries, "tok-a", []Pool{"prod", "staging"})
	if len(got) != 1 {
		t.Fatalf("re-registering an existing token must not duplicate the entry, got %d entries", len(got))
	}
	if len(got[0].Pools) != 2 || got[0].Pools[0] != "prod" {
		t.Errorf("pools not replaced: %+v", got[0].Pools)
	}
}

func TestRemoveTunnelTokenEntry_DropsTheMatchingEntry(t *testing.T) {
	entries := []TunnelTokenEntry{
		{Token: "tok-a", Pools: []Pool{PoolAny}},
		{Token: "tok-b", Pools: []Pool{"lab"}},
	}
	got := removeTunnelTokenEntry(entries, "tok-a")
	if len(got) != 1 {
		t.Fatalf("expected 1 entry left, got %d: %+v", len(got), got)
	}
	if got[0].Token != "tok-b" {
		t.Errorf("wrong entry survived: %+v", got)
	}
}

// TestRemoveTunnelTokenEntry_DropsAllDuplicates: a persisted store should
// never carry duplicates for the same token, but if one somehow exists (a
// prior bug, a hand-edited file, a lost race), removal must not stop at
// the first match — a surviving duplicate would reappear on the next
// restart and silently undo the deregistration.
func TestRemoveTunnelTokenEntry_DropsAllDuplicates(t *testing.T) {
	entries := []TunnelTokenEntry{
		{Token: "tok-a", Pools: []Pool{PoolAny}},
		{Token: "tok-b", Pools: []Pool{"lab"}},
		{Token: "tok-a", Pools: []Pool{"prod"}},
	}
	got := removeTunnelTokenEntry(entries, "tok-a")
	if len(got) != 1 || got[0].Token != "tok-b" {
		t.Fatalf("expected only tok-b to survive, got %+v", got)
	}
}

func TestRemoveTunnelTokenEntry_UnknownTokenIsANoOp(t *testing.T) {
	entries := []TunnelTokenEntry{{Token: "tok-a", Pools: []Pool{PoolAny}}}
	got := removeTunnelTokenEntry(entries, "does-not-exist")
	if len(got) != 1 || got[0].Token != "tok-a" {
		t.Errorf("removing an unknown token changed the set: %+v", got)
	}
}

// TestRemoveTunnelTokenEntriesByPrefix_DropsEveryMatch is the store-layer
// counterpart of TokenPolicy.DenyPrefix (#1963): a host's join token AND any
// reissued reconnect token, both "<host-id>.<secret>", must both be dropped
// from the persisted store by one prefix removal — otherwise the removal
// wouldn't survive a restart even though DenyPrefix already updated the
// in-memory policy.
func TestRemoveTunnelTokenEntriesByPrefix_DropsEveryMatch(t *testing.T) {
	entries := []TunnelTokenEntry{
		{Token: "host-a.secret1", Pools: []Pool{PoolAny}},
		{Token: "host-a.secret2", Pools: []Pool{PoolAny}},
		{Token: "host-b.secret1", Pools: []Pool{PoolAny}},
	}
	got := removeTunnelTokenEntriesByPrefix(entries, "host-a.")
	if len(got) != 1 || got[0].Token != "host-b.secret1" {
		t.Fatalf("expected only host-b.secret1 to survive, got %+v", got)
	}
}

// TestRemoveTunnelTokenEntriesByPrefix_IsALiteralPrefixMatch documents that
// this helper is a plain strings.HasPrefix match with no opinion about a
// trailing "." — "abc" DOES match "abcd.xyz" at this layer. The #1963
// footgun ("abc" must not wrongly match "abcd.xyz") is guarded one layer
// up, by TunnelTokenDeregisterHandler rejecting any token_prefix that
// doesn't end with "." before it ever reaches this function (see
// TestTunnelTokenDeregisterHandler_400OnPrefixWithoutTrailingDot).
func TestRemoveTunnelTokenEntriesByPrefix_IsALiteralPrefixMatch(t *testing.T) {
	entries := []TunnelTokenEntry{{Token: "abcd.xyz", Pools: []Pool{PoolAny}}}
	got := removeTunnelTokenEntriesByPrefix(entries, "abc")
	if len(got) != 0 {
		t.Errorf("expected the entry to be removed by a plain prefix match, got %+v", got)
	}
}

func TestRemoveTunnelTokenEntriesByPrefix_UnknownPrefixIsANoOp(t *testing.T) {
	entries := []TunnelTokenEntry{{Token: "host-a.secret1", Pools: []Pool{PoolAny}}}
	got := removeTunnelTokenEntriesByPrefix(entries, "host-z.")
	if len(got) != 1 || got[0].Token != "host-a.secret1" {
		t.Errorf("removing an unmatched prefix changed the set: %+v", got)
	}
}

func TestSaveTunnelTokenStore_FileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnel-tokens.json")
	if err := SaveTunnelTokenStore(path, []TunnelTokenEntry{{Token: "tok-a", Pools: []Pool{PoolAny}}}); err != nil {
		t.Fatalf("SaveTunnelTokenStore: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("tunnel token store mode = %o, want 0600 (each entry is a bearer-equivalent secret)", info.Mode().Perm())
	}
}
