package anonbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// claimHarness: a harness with claims enabled (per-box secret derived from
// the name, like DeriveSharedSecret would) and one box already ensured.
func claimHarness(t *testing.T, base string) (*harness, string, string) {
	t.Helper()
	h := newHarness(t, func(c *Config) {
		c.ClaimSecret = func(box string) string { return "secret-for-" + box }
		c.ClaimURLBase = base
	})
	key, fp := testKey(t)
	res, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	claimFile := fileNamed(t, h.boxes.files[res.BoxName], ClaimURLPath).content
	return h, res.BoxName, strings.TrimSpace(claimFile)
}

func tokenFromClaimFile(t *testing.T, content string) string {
	t.Helper()
	if i := strings.Index(content, "?token="); i >= 0 {
		return content[i+len("?token="):]
	}
	return content
}

func TestEnsure_WritesClaimURLWithMintedToken(t *testing.T) {
	h, boxName, content := claimHarness(t, "https://cloud.example.test/claim/")
	if !strings.HasPrefix(content, "https://cloud.example.test/claim?token=v1."+boxName+".") {
		t.Errorf("claim-url = %q", content)
	}
	tok, err := VerifyClaimToken("secret-for-"+boxName, tokenFromClaimFile(t, content), h.now)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	st, _ := h.m.findByName(context.Background(), boxName)
	if tok.TokenID != st.Labels[LabelClaimTokenID] || tok.FPHash != st.Labels[LabelFPHash] {
		t.Errorf("token %+v does not match labels %v", tok, st.Labels)
	}
	if !tok.ExpiresAt.Equal(h.now.Add(DefaultLimits().TTL)) {
		t.Errorf("token expiry %v, want the box TTL", tok.ExpiresAt)
	}
	if st.Labels[LabelPublicKey] == "" {
		t.Errorf("the claiming key must be kept on the box for Claim to preserve it")
	}
}

func TestEnsure_NoURLBase_WritesBareToken(t *testing.T) {
	_, boxName, content := claimHarness(t, "")
	if !strings.HasPrefix(content, "v1."+boxName+".") || strings.Contains(content, "?") {
		t.Errorf("claim-url without a base must be the bare token, got %q", content)
	}
}

func TestClaim_Valid_BindsTenantClearsTTLLiftsGuardAddsKeys(t *testing.T) {
	h, boxName, content := claimHarness(t, "https://cloud.example.test/claim")
	token := tokenFromClaimFile(t, content)
	h.now = h.now.Add(30 * time.Minute)

	res, err := h.m.Claim(context.Background(), ClaimRequest{Token: token, Tenant: "qa-claim", AuthorizedKeys: []string{"ssh-ed25519 AAAAtenant1 t@x", "ssh-ed25519 AAAAtenant1 t@x"}})
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if res.BoxName != boxName || res.Tenant != "qa-claim" || res.SSHUser != strings.TrimSuffix(boxName, "-container") {
		t.Errorf("result = %+v", res)
	}
	st, _ := h.m.findByName(context.Background(), boxName)
	if st.Labels[LabelClaimedAt] == "" || st.Labels[LabelClaimedBy] != "qa-claim" {
		t.Errorf("claimed labels = %v", st.Labels)
	}
	if _, has := h.boxes.ttls[boxName]; has {
		t.Errorf("TTL must be cleared on claim")
	}
	if h.boxes.owners[boxName] != "qa-claim" {
		t.Errorf("owner = %q, want qa-claim", h.boxes.owners[boxName])
	}
	keys := h.boxes.keys[boxName]
	if len(keys) != 2 || keys[0] != st.Labels[LabelPublicKey] || keys[1] != "ssh-ed25519 AAAAtenant1 t@x" {
		t.Errorf("keys = %v, want the claiming key kept + the tenant's key once", keys)
	}
	devKeys := h.acls.devKeys[boxName+"/eth0"]
	if devKeys["security.acls"] != "" || devKeys["security.acls.default.egress.action"] != "" {
		t.Errorf("egress guard still attached: %v", devKeys)
	}
	// Every write addressed the box by its own name, not the new tenant.
	for _, ref := range h.boxes.writes {
		if ref.Name != boxName || ref.Tenant != strings.TrimSuffix(boxName, "-container") {
			t.Errorf("write addressed %+v, want the box's own name/login", ref)
		}
	}
}

func TestClaim_ThenEnsureReturnsClaimedBoxWithoutTTL(t *testing.T) {
	h, boxName, content := claimHarness(t, "")
	if _, err := h.m.Claim(context.Background(), ClaimRequest{Token: tokenFromClaimFile(t, content), Tenant: "qa-claim"}); err != nil {
		t.Fatal(err)
	}
	// The fake reports the owner as Ref.Tenant after SetOwner, like the LXC backend.
	st, _ := h.m.findByName(context.Background(), boxName)
	key := st.Labels[LabelPublicKey]
	res, err := h.m.Ensure(context.Background(), EnsureRequest{PublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reused || res.BoxName != boxName || res.SSHUser != strings.TrimSuffix(boxName, "-container") || !res.TTLExpiresAt.IsZero() {
		t.Errorf("post-claim ensure = %+v, want the same box, its own login, no TTL", res)
	}
	if len(h.boxes.created) != 1 {
		t.Errorf("a claimed box must still be reused, not recreated")
	}
}

func TestClaim_Twice_AlreadyClaimed(t *testing.T) {
	h, _, content := claimHarness(t, "")
	token := tokenFromClaimFile(t, content)
	if _, err := h.m.Claim(context.Background(), ClaimRequest{Token: token, Tenant: "first"}); err != nil {
		t.Fatal(err)
	}
	_, err := h.m.Claim(context.Background(), ClaimRequest{Token: token, Tenant: "second"})
	if !errors.Is(err, ErrClaimAlreadyClaimed) {
		t.Errorf("second claim: %v, want AlreadyClaimed", err)
	}
	if h.boxes.owners[h.boxes.boxes[0].Ref.Name] != "first" {
		t.Errorf("owner changed on the second claim")
	}
}

func TestClaim_Rejections(t *testing.T) {
	h, boxName, content := claimHarness(t, "")
	token := tokenFromClaimFile(t, content)
	parts := strings.Split(token, ".")

	tests := []struct {
		name  string
		token string
		now   time.Duration // offset from h.now
		want  error
		mut   func()
	}{
		{"expired", token, DefaultLimits().TTL + time.Minute, ErrClaimExpired, nil},
		{"bad hmac", strings.TrimSuffix(token, parts[5]) + strings.Repeat("0", 64), 0, ErrClaimInvalid, nil},
		{"malformed", "v1.nope", 0, ErrClaimInvalid, nil},
		{"token id mismatch (box re-minted)", token, 0, ErrClaimInvalid, func() {
			st, _ := h.m.findByName(context.Background(), boxName)
			st.Labels[LabelClaimTokenID] = "ffffffffffffffffffffffffffffffff"
		}},
		{"box gone", token, 0, ErrClaimNotFound, func() { h.boxes.boxes = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mut != nil {
				tt.mut()
			}
			saved := h.now
			h.now = saved.Add(tt.now)
			_, err := h.m.Claim(context.Background(), ClaimRequest{Token: tt.token, Tenant: "qa"})
			h.now = saved
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			if st, _ := h.m.findByName(context.Background(), boxName); st != nil && st.Labels[LabelClaimedAt] != "" {
				t.Errorf("a rejected claim must not mark the box claimed")
			}
		})
	}
}

func TestClaim_InvalidTenantOrDisabled(t *testing.T) {
	h, _, content := claimHarness(t, "")
	token := tokenFromClaimFile(t, content)
	for _, tenant := range []string{"", "Alice", "9x", "a.b", strings.Repeat("a", 40)} {
		var inv InvalidRequestError
		if _, err := h.m.Claim(context.Background(), ClaimRequest{Token: token, Tenant: tenant}); !errors.As(err, &inv) {
			t.Errorf("tenant %q: err = %v, want InvalidRequestError", tenant, err)
		}
	}
	off := newHarness(t, func(c *Config) { c.ClaimSecret = nil })
	if _, err := off.m.Claim(context.Background(), ClaimRequest{Token: token, Tenant: "qa"}); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("claims disabled: err = %v", err)
	}
}
