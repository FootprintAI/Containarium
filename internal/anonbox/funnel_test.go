package anonbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

type recFunnel struct{ events []FunnelEvent }

func (r *recFunnel) Record(e FunnelEvent) { r.events = append(r.events, e) }

func (r *recFunnel) kinds() string {
	out := make([]string, 0, len(r.events))
	for _, e := range r.events {
		out = append(out, string(e.Kind))
	}
	return strings.Join(out, ",")
}

func funnelHarness(t *testing.T, mut func(*Config)) (*harness, *recFunnel) {
	t.Helper()
	f := &recFunnel{}
	h := newHarness(t, func(c *Config) {
		c.Funnel = f
		if mut != nil {
			mut(c)
		}
	})
	return h, f
}

// Every Ensure path records exactly the steps the design names, once.
func TestFunnel_EnsurePaths(t *testing.T) {
	t.Run("first create then reconnect", func(t *testing.T) {
		h, f := funnelHarness(t, nil)
		key, fp := testKey(t)
		req := EnsureRequest{Fingerprint: fp, PublicKey: key}
		// A clock that advances one second per read, so time-to-shell is > 0.
		cur := h.now
		h.m.cfg.Now = func() time.Time { t := cur; cur = cur.Add(time.Second); return t }
		if _, err := h.m.Ensure(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if got := f.kinds(); got != "connect,claim_link_issued,shell_ready" {
			t.Errorf("create: %s", got)
		}
		shell := f.events[2]
		if shell.BoxName == "" || shell.FPHash != fpHash(fp) || shell.Duration <= 0 {
			t.Errorf("shell_ready = %+v", shell)
		}
		for _, e := range f.events {
			if strings.Contains(e.FPHash, "SHA256:") || e.FPHash == fp {
				t.Errorf("raw fingerprint leaked: %+v", e)
			}
		}
		f.events = nil
		if _, err := h.m.Ensure(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if got := f.kinds(); got != "connect,reconnect" {
			t.Errorf("reconnect: %s", got)
		}
	})
	t.Run("door closed and banned", func(t *testing.T) {
		h, f := funnelHarness(t, nil)
		key, fp := testKey(t)
		_ = h.m.SetDoorConfig(DoorConfig{Enabled: false, DisabledMessage: "closed"})
		_, _ = h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
		_ = h.m.SetDoorConfig(DoorConfig{Enabled: true, BannedFingerprints: []string{fp}})
		_, _ = h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
		if got := f.kinds(); got != "connect,rejected_door,connect,rejected_door" {
			t.Errorf("%s", got)
		}
		if !strings.Contains(f.events[1].Reason, "closed") || !strings.Contains(f.events[3].Reason, "banned") {
			t.Errorf("reasons: %q / %q", f.events[1].Reason, f.events[3].Reason)
		}
	})
	t.Run("rate limit and capacity", func(t *testing.T) {
		h, f := funnelHarness(t, func(c *Config) {
			c.Limits.MaxBoxes = 1
			c.Limits.PerIPPerMinute = 0.0001
			c.Limits.PerIPBurst = 1
			c.Limits.PerKeyPerMinute = 0
		})
		k1, fp1 := testKey(t)
		k2, fp2 := testKey(t)
		if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp1, PublicKey: k1, SourceIP: "198.51.100.7"}); err != nil {
			t.Fatal(err)
		}
		f.events = nil
		_, _ = h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp2, PublicKey: k2, SourceIP: "198.51.100.7"}) // same IP: rate-limited
		_, _ = h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp2, PublicKey: k2, SourceIP: "203.0.113.9"})  // other IP: cap
		if got := f.kinds(); got != "connect,rejected_ratelimit,connect,rejected_capacity" {
			t.Errorf("%s", got)
		}
	})
	t.Run("nil funnel is fine", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.Funnel = nil })
		key, fp := testKey(t)
		if _, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFunnel_ClaimCompleted(t *testing.T) {
	h, f := funnelHarness(t, nil)
	key, fp := testKey(t)
	res, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	content := strings.TrimSpace(fileNamed(t, h.boxes.files[res.BoxName], ClaimURLPath).content)
	f.events = nil
	if _, err := h.m.Claim(context.Background(), ClaimRequest{Token: tokenFromClaimFile(t, content), Tenant: "qa"}); err != nil {
		t.Fatal(err)
	}
	if got := f.kinds(); got != "claim_completed" {
		t.Errorf("%s", got)
	}
	if f.events[0].BoxName != res.BoxName || f.events[0].FPHash != fpHash(fp) {
		t.Errorf("%+v", f.events[0])
	}
	// A failed claim records nothing.
	f.events = nil
	_, _ = h.m.Claim(context.Background(), ClaimRequest{Token: "v1.nope", Tenant: "qa"})
	if len(f.events) != 0 {
		t.Errorf("failed claim recorded %s", f.kinds())
	}
}

func TestObserve_ExpiredVsKilled(t *testing.T) {
	h, f := funnelHarness(t, func(c *Config) { c.Limits.PerKeyPerMinute = 0; c.Limits.PerIPPerMinute = 0 })
	k1, fp1 := testKey(t)
	k2, fp2 := testKey(t)
	k3, fp3 := testKey(t)
	a, _ := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp1, PublicKey: k1})
	b, _ := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp2, PublicKey: k2})
	c, _ := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp3, PublicKey: k3})
	if err := h.m.Observe(context.Background()); err != nil { // seeds the known set
		t.Fatal(err)
	}
	f.events = nil

	// c is claimed, then all three disappear: a after its TTL, b before.
	content := strings.TrimSpace(fileNamed(t, h.boxes.files[c.BoxName], ClaimURLPath).content)
	if _, err := h.m.Claim(context.Background(), ClaimRequest{Token: tokenFromClaimFile(t, content), Tenant: "qa"}); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.events = nil
	h.boxes.boxes = nil
	h.now = h.now.Add(DefaultLimits().TTL + time.Minute)
	// b's expiry is pushed into the future so its disappearance is "early".
	h.m.mu.Lock()
	kb := h.m.known[b.BoxName]
	kb.expiresAt = h.now.Add(time.Hour)
	h.m.known[b.BoxName] = kb
	h.m.mu.Unlock()

	if err := h.m.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := map[string]FunnelEvent{}
	for _, e := range f.events {
		got[e.BoxName] = e
	}
	if e := got[a.BoxName]; e.Kind != FunnelExpired || e.FPHash != fpHash(fp1) {
		t.Errorf("a: %+v, want expired", e)
	}
	if e := got[b.BoxName]; e.Kind != FunnelKilledAbuse {
		t.Errorf("b: %+v, want killed_abuse", e)
	}
	if _, ok := got[c.BoxName]; ok {
		t.Errorf("claimed box c must not be reported: %+v", got[c.BoxName])
	}
	// Second tick: nothing new.
	f.events = nil
	if err := h.m.Observe(context.Background()); err != nil || len(f.events) != 0 {
		t.Errorf("repeat tick: %v %s", err, f.kinds())
	}
}
