package anonbox

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestEnsure_KillSwitch(t *testing.T) {
	h := newHarness(t, nil)
	key, fp := testKey(t)
	req := EnsureRequest{Fingerprint: fp, PublicKey: key}
	if _, err := h.m.Ensure(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	if err := h.m.SetDoorConfig(DoorConfig{Enabled: false, DisabledMessage: "closed for maintenance"}); err != nil {
		t.Fatal(err)
	}
	// Closed for new keys AND for reconnects.
	_, err := h.m.Ensure(context.Background(), req)
	var closed DoorClosedError
	if !errors.As(err, &closed) || closed.Message != "closed for maintenance" || !strings.Contains(err.Error(), "closed for maintenance") {
		t.Errorf("reconnect while closed: %v", err)
	}
	key2, fp2 := testKey(t)
	if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp2, PublicKey: key2}); !errors.As(err, &closed) {
		t.Errorf("new key while closed: %v", err)
	}
	if len(h.boxes.created) != 1 {
		t.Errorf("nothing may be created while closed")
	}

	if err := h.m.SetDoorConfig(DoorConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Ensure(context.Background(), req); err != nil {
		t.Errorf("after enable: %v", err)
	}
	if got := h.m.DoorConfig(); !got.Enabled {
		t.Errorf("DoorConfig = %+v", got)
	}
}

func TestEnsure_Banned(t *testing.T) {
	h := newHarness(t, nil)
	key, fp := testKey(t)
	if err := h.m.SetDoorConfig(DoorConfig{Enabled: true, BannedFingerprints: []string{fp}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key}); !errors.Is(err, ErrBanned) {
		t.Errorf("banned key: %v", err)
	}
	other, ofp := testKey(t)
	if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: ofp, PublicKey: other}); err != nil {
		t.Errorf("another key must still work: %v", err)
	}
	if err := h.m.SetDoorConfig(DoorConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key}); err != nil {
		t.Errorf("after unban: %v", err)
	}
}

func TestEnsure_RateLimitPerKey_CreatesOnly(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Limits.PerKeyPerMinute = 0.0001 // effectively no refill inside the test
		c.Limits.PerKeyBurst = 2
		c.Limits.PerIPPerMinute = 0
	})
	key, fp := testKey(t)
	req := EnsureRequest{Fingerprint: fp, PublicKey: key, SourceIP: "198.51.100.7"}

	for i := 0; i < 2; i++ {
		if _, err := h.m.Ensure(context.Background(), req); err != nil {
			t.Fatalf("create %d: %v", i+1, err)
		}
		// Reconnects never count.
		for j := 0; j < 5; j++ {
			if _, err := h.m.Ensure(context.Background(), req); err != nil {
				t.Fatalf("reconnect after create %d: %v", i+1, err)
			}
		}
		h.boxes.boxes = nil // the sweeper reaped it
	}
	if _, err := h.m.Ensure(context.Background(), req); !errors.Is(err, ErrRateLimited) {
		t.Errorf("third create inside the window: %v, want rate-limited", err)
	}
	if len(h.boxes.created) != 2 {
		t.Errorf("created %d, want 2", len(h.boxes.created))
	}
}

func TestEnsure_RateLimitPerIP(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Limits.PerKeyPerMinute = 0
		c.Limits.PerIPPerMinute = 0.0001
		c.Limits.PerIPBurst = 2
	})
	for i := 0; i < 2; i++ {
		key, fp := testKey(t)
		if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key, SourceIP: "198.51.100.7"}); err != nil {
			t.Fatalf("create %d: %v", i+1, err)
		}
	}
	key, fp := testKey(t)
	if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key, SourceIP: "198.51.100.7"}); !errors.Is(err, ErrRateLimited) {
		t.Errorf("third key from the same IP: %v, want rate-limited", err)
	}
	// A different address is unaffected.
	if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key, SourceIP: "203.0.113.9"}); err != nil {
		t.Errorf("other IP: %v", err)
	}
}

func TestEnsure_GlobalCap_CountsUnclaimedOnly(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.MaxBoxes = 1; c.Limits.PerKeyPerMinute = 0; c.Limits.PerIPPerMinute = 0 })
	key1, fp1 := testKey(t)
	first, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp1, PublicKey: key1})
	if err != nil {
		t.Fatal(err)
	}
	key2, fp2 := testKey(t)
	if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp2, PublicKey: key2}); !errors.Is(err, ErrAtCapacity) {
		t.Errorf("at cap: %v, want capacity error", err)
	}
	// The first key still reconnects at cap.
	if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp1, PublicKey: key1}); err != nil {
		t.Errorf("reconnect at cap: %v", err)
	}
	// A claimed box frees its slot.
	content := fileNamed(t, h.boxes.files[first.BoxName], ClaimURLPath).content
	if _, err := h.m.Claim(context.Background(), ClaimRequest{Token: tokenFromClaimFile(t, strings.TrimSpace(content)), Tenant: "qa"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp2, PublicKey: key2}); err != nil {
		t.Errorf("after a claim freed the slot: %v", err)
	}
}

func TestIsUnclaimedAnonymous(t *testing.T) {
	tests := []struct {
		labels map[string]string
		want   bool
	}{
		{map[string]string{LabelFingerprint: "SHA256:x"}, true},
		{map[string]string{LabelFingerprint: "SHA256:x", LabelClaimedAt: "2026-10-01T00:00:00Z"}, false},
		{map[string]string{"team": "x"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		if got := IsUnclaimedAnonymous(tt.labels); got != tt.want {
			t.Errorf("%v → %v, want %v", tt.labels, got, tt.want)
		}
	}
}
