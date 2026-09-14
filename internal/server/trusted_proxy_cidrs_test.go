package server

import "testing"

func TestValidateTrustedProxyCIDRs_AcceptsEmpty(t *testing.T) {
	// The flag is optional: no CDN ranges is a valid (default) configuration.
	if err := validateTrustedProxyCIDRs(nil); err != nil {
		t.Fatalf("nil: %v", err)
	}
	if err := validateTrustedProxyCIDRs([]string{}); err != nil {
		t.Fatalf("empty: %v", err)
	}
}

func TestValidateTrustedProxyCIDRs_AcceptsRealCIDRs(t *testing.T) {
	if err := validateTrustedProxyCIDRs([]string{"173.245.48.0/20", "2400:cb00::/32"}); err != nil {
		t.Fatalf("real CIDRs rejected: %v", err)
	}
}

func TestValidateTrustedProxyCIDRs_RejectsWildcard(t *testing.T) {
	for _, w := range []string{"0.0.0.0/0", "::/0"} {
		if err := validateTrustedProxyCIDRs([]string{"104.16.0.0/13", w}); err == nil {
			t.Errorf("wildcard %q accepted", w)
		}
	}
}

func TestValidateTrustedProxyCIDRs_RejectsInvalidAndBlank(t *testing.T) {
	if err := validateTrustedProxyCIDRs([]string{"10.0.0.0\\8"}); err == nil {
		t.Error("malformed CIDR accepted")
	}
	if err := validateTrustedProxyCIDRs([]string{" "}); err == nil {
		t.Error("blank entry accepted")
	}
}

func TestValidateClientIPHeaders(t *testing.T) {
	if err := validateClientIPHeaders(nil); err != nil {
		t.Fatalf("nil headers should be fine (feature off): %v", err)
	}
	if err := validateClientIPHeaders([]string{"Cf-Connecting-Ip"}); err != nil {
		t.Fatalf("real header rejected: %v", err)
	}
	if err := validateClientIPHeaders([]string{"Cf-Connecting-Ip", " "}); err == nil {
		t.Error("blank header entry accepted")
	}
}
