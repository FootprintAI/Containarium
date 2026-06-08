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
