package sentinel

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenPolicy_Validate(t *testing.T) {
	p := NewTokenPolicy()
	p.Allow("legacy", PoolAny)
	p.Allow("prod-only", "prod")
	p.Allow("multi", "prod", "lab")
	p.Allow("unpooled-only", "")

	cases := []struct {
		name    string
		token   string
		pool    Pool
		wantErr string // substring; "" means expect success
	}{
		{name: "wildcard allows any pool", token: "legacy", pool: "prod"},
		{name: "wildcard allows empty pool", token: "legacy", pool: ""},
		{name: "single-pool token matches", token: "prod-only", pool: "prod"},
		{name: "single-pool token rejects other pool", token: "prod-only", pool: "lab", wantErr: "not authorized"},
		{name: "single-pool token rejects empty", token: "prod-only", pool: "", wantErr: "not authorized"},
		{name: "multi-pool token allows first", token: "multi", pool: "prod"},
		{name: "multi-pool token allows second", token: "multi", pool: "lab"},
		{name: "multi-pool token rejects unlisted", token: "multi", pool: "rogue", wantErr: "not authorized"},
		{name: "explicit unpooled token allows empty", token: "unpooled-only", pool: ""},
		{name: "explicit unpooled token rejects named", token: "unpooled-only", pool: "prod", wantErr: "not authorized"},
		{name: "unknown token rejected", token: "ghost", pool: "prod", wantErr: "invalid token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Validate(tc.token, tc.pool)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestTokenPolicy_AllowReplaces(t *testing.T) {
	p := NewTokenPolicy()
	p.Allow("t", "prod")
	assert.NoError(t, p.Validate("t", "prod"))

	// Re-Allow with different pools replaces (does not merge).
	p.Allow("t", "lab")
	assert.Error(t, p.Validate("t", "prod"))
	assert.NoError(t, p.Validate("t", "lab"))
}

func TestTokenPolicy_Deny(t *testing.T) {
	p := NewTokenPolicy()
	p.Allow("t", "prod")
	require.NoError(t, p.Validate("t", "prod"))

	p.Deny("t")
	err := p.Validate("t", "prod")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

// Denying a token nobody ever Allow'd must not panic and must leave the
// policy otherwise unaffected — a decommission racing (or repeating) a
// deregister is the normal case, not an error condition.
func TestTokenPolicy_DenyUnknownTokenIsANoOp(t *testing.T) {
	p := NewTokenPolicy()
	p.Allow("other", "prod")

	assert.NotPanics(t, func() { p.Deny("never-registered") })
	assert.NoError(t, p.Validate("other", "prod"))
}

// TestTokenPolicy_DenyPrefix_RemovesAllMatchingTokens is the core of #1963:
// a control plane that never retains the plaintext token can only identify
// the host it wants to decommission, not any specific token — so it must be
// able to remove every rule sharing that host-id prefix (the original join
// token AND any reissued reconnect token) in one call.
func TestTokenPolicy_DenyPrefix_RemovesAllMatchingTokens(t *testing.T) {
	p := NewTokenPolicy()
	p.Allow("host-a.secret1", PoolAny)
	p.Allow("host-a.secret2", PoolAny) // reissued reconnect token, same host
	p.Allow("host-b.secret1", PoolAny) // different host, must survive

	p.DenyPrefix("host-a.")

	assert.Error(t, p.Validate("host-a.secret1", ""))
	assert.Error(t, p.Validate("host-a.secret2", ""))
	assert.NoError(t, p.Validate("host-b.secret1", ""))
}

// TestTokenPolicy_DenyPrefix_IsALiteralPrefixMatch documents that DenyPrefix
// itself is a plain strings.HasPrefix match with no opinion about a
// trailing "." — "abc" DOES match "abcd.xyz" at this layer. The #1963
// footgun ("abc" must not wrongly match "abcd.xyz") is guarded one layer up,
// by TunnelTokenDeregisterHandler rejecting any token_prefix that doesn't
// end with "." before it ever reaches DenyPrefix (see
// TestTunnelTokenDeregisterHandler_400OnPrefixWithoutTrailingDot) — the same
// division of responsibility as Deny, which does no token-shape validation
// either and leaves that to its caller.
func TestTokenPolicy_DenyPrefix_IsALiteralPrefixMatch(t *testing.T) {
	p := NewTokenPolicy()
	p.Allow("abcd.xyz", PoolAny)

	p.DenyPrefix("abc")

	assert.Error(t, p.Validate("abcd.xyz", ""))
}

// TestTokenPolicy_DenyPrefix_UnknownPrefixIsANoOp mirrors
// TestTokenPolicy_DenyUnknownTokenIsANoOp for the prefix form.
func TestTokenPolicy_DenyPrefix_UnknownPrefixIsANoOp(t *testing.T) {
	p := NewTokenPolicy()
	p.Allow("host-a.secret1", PoolAny)

	assert.NotPanics(t, func() { p.DenyPrefix("host-z.") })
	assert.NoError(t, p.Validate("host-a.secret1", ""))
}

func TestPolicyFromCLI(t *testing.T) {
	t.Run("legacy token only", func(t *testing.T) {
		p, err := PolicyFromCLI("legacy", nil)
		require.NoError(t, err)
		assert.NoError(t, p.Validate("legacy", "anything"))
		assert.NoError(t, p.Validate("legacy", ""))
	})

	t.Run("policy specs only", func(t *testing.T) {
		p, err := PolicyFromCLI("", []string{"t1=prod,lab", "t2=lab"})
		require.NoError(t, err)
		assert.NoError(t, p.Validate("t1", "prod"))
		assert.NoError(t, p.Validate("t1", "lab"))
		assert.Error(t, p.Validate("t1", "rogue"))
		assert.NoError(t, p.Validate("t2", "lab"))
		assert.Error(t, p.Validate("t2", "prod"))
	})

	t.Run("legacy + specs combined", func(t *testing.T) {
		p, err := PolicyFromCLI("legacy", []string{"lab-only=lab"})
		require.NoError(t, err)
		assert.NoError(t, p.Validate("legacy", "prod"))  // wildcard
		assert.NoError(t, p.Validate("lab-only", "lab")) // restricted
		assert.Error(t, p.Validate("lab-only", "prod"))  // restricted rejects
	})

	t.Run("malformed spec", func(t *testing.T) {
		_, err := PolicyFromCLI("", []string{"no-equals-sign"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected token=pool")
	})

	t.Run("empty pool list rejected", func(t *testing.T) {
		_, err := PolicyFromCLI("", []string{"t1="})
		require.Error(t, err)
	})
}

// Smoke check that the TokenPolicy.rules map keys are unaffected by the
// shift to []Pool (regression for the slice 7b refactor).
func TestTokenPolicy_RulesKeyedByToken(t *testing.T) {
	p := NewTokenPolicy()
	p.Allow("dup", "a")
	p.Allow("dup", "b")
	// Second Allow replaced the first; only "b" should match.
	assert.Error(t, p.Validate("dup", "a"))
	assert.NoError(t, p.Validate("dup", "b"))
	// Token list with comma-separated pools roundtrips through PolicyFromCLI.
	p2, err := PolicyFromCLI("", []string{"dup=a,b,c"})
	require.NoError(t, err)
	assert.NoError(t, p2.Validate("dup", "a"))
	assert.NoError(t, p2.Validate("dup", "b"))
	assert.NoError(t, p2.Validate("dup", "c"))
	assert.Error(t, p2.Validate("dup", "d"))
	// Sanity: error messages mention the actual rejected pool name.
	err = p2.Validate("dup", "rogue")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), `"rogue"`), "error should quote the rejected pool name, got %q", err.Error())
}
