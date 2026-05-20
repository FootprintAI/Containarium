package server

import (
	"strings"
	"testing"
)

// Phase 2.6 — daemon refuses to start with a misconfigured
// PROXY-v2 trust list (audit C-MED-1).

func TestValidateProxyProtocolTrusted_AcceptsRealCIDR(t *testing.T) {
	if err := validateProxyProtocolTrusted([]string{"10.0.0.5/32"}); err != nil {
		t.Fatalf("realistic sentinel CIDR should pass: %v", err)
	}
}

func TestValidateProxyProtocolTrusted_RejectsEmpty(t *testing.T) {
	err := validateProxyProtocolTrusted(nil)
	if err == nil {
		t.Fatal("nil list must be rejected")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error should mention empty: %v", err)
	}

	if err := validateProxyProtocolTrusted([]string{}); err == nil {
		t.Fatal("empty slice must be rejected")
	}
}

func TestValidateProxyProtocolTrusted_RejectsWildcardV4(t *testing.T) {
	err := validateProxyProtocolTrusted([]string{"0.0.0.0/0"})
	if err == nil {
		t.Fatal("0.0.0.0/0 must be rejected")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("error should name wildcard: %v", err)
	}
}

func TestValidateProxyProtocolTrusted_RejectsWildcardV6(t *testing.T) {
	if err := validateProxyProtocolTrusted([]string{"::/0"}); err == nil {
		t.Fatal("::/0 must be rejected")
	}
}

func TestValidateProxyProtocolTrusted_RejectsMixedWildcard(t *testing.T) {
	err := validateProxyProtocolTrusted([]string{"10.0.0.5/32", "0.0.0.0/0"})
	if err == nil {
		t.Fatal("any wildcard entry in a list must reject the whole list")
	}
}

func TestValidateProxyProtocolTrusted_RejectsMalformedCIDR(t *testing.T) {
	cases := []string{
		"not-a-cidr",
		"10.0.0.5",       // missing /mask
		"10.0.0.5/99",    // bad mask
		"10.0.0.5\\32",   // wrong slash
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if err := validateProxyProtocolTrusted([]string{c}); err == nil {
				t.Fatalf("malformed CIDR %q must be rejected", c)
			}
		})
	}
}

func TestValidateProxyProtocolTrusted_TrimsWhitespace(t *testing.T) {
	// Leading/trailing whitespace shouldn't be silently accepted —
	// netip.ParsePrefix rejects them after our trim, so we get a
	// clean error path rather than a weird "matches but doesn't"
	// case downstream.
	if err := validateProxyProtocolTrusted([]string{"  10.0.0.5/32  "}); err != nil {
		t.Fatalf("trimmed CIDR should pass: %v", err)
	}
}
