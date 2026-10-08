package server

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// fakeTTLResolver is fake DNS that reports a record TTL with each answer (#2379).
type fakeTTLResolver struct {
	answers map[string]dnsAnswer
	errs    map[string]error
	calls   map[string]int
}

func (f *fakeTTLResolver) LookupAddrsTTL(_ context.Context, host string) (dnsAnswer, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[host]++
	if err := f.errs[host]; err != nil {
		return dnsAnswer{}, err
	}
	return f.answers[host], nil
}

// resolverClock is a settable clock for the resolver's refresh schedule.
type resolverClock struct{ t time.Time }

func (c *resolverClock) now() time.Time          { return c.t }
func (c *resolverClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newResolverClock() *resolverClock {
	return &resolverClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

func TestDomainResolver_RefreshIntervalIsMinTTLAnd60s(t *testing.T) {
	cases := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"short TTL drives the refresh", 20 * time.Second, 20 * time.Second},
		{"long TTL is capped at 60s", 300 * time.Second, 60 * time.Second},
		{"unknown TTL (stdlib path) uses 60s", ttlUnknown, 60 * time.Second},
		{"TTL 0 is floored, never a hot loop", 0, minDomainRefresh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newResolverClock()
			f := &fakeTTLResolver{answers: map[string]dnsAnswer{
				"a.example": {Addrs: addrs("192.0.2.1"), TTL: tc.ttl},
			}}
			r := newDomainResolver(f, clk.now)
			r.Refresh(context.Background(), []string{"a.example"})
			if got := r.NextRefreshDelay(); got != tc.want {
				t.Fatalf("NextRefreshDelay = %v, want %v", got, tc.want)
			}
			// Not due yet: a Refresh before the interval elapses does not re-query.
			clk.advance(tc.want - time.Millisecond)
			r.Refresh(context.Background(), []string{"a.example"})
			if f.calls["a.example"] != 1 {
				t.Fatalf("re-queried before the interval: %d calls", f.calls["a.example"])
			}
			// Due: the next Refresh re-queries.
			clk.advance(time.Millisecond)
			r.Refresh(context.Background(), []string{"a.example"})
			if f.calls["a.example"] != 2 {
				t.Fatalf("not re-queried once due: %d calls", f.calls["a.example"])
			}
		})
	}
}

func TestDomainResolver_NextRefreshDelay_EarliestDueName(t *testing.T) {
	clk := newResolverClock()
	f := &fakeTTLResolver{answers: map[string]dnsAnswer{
		"slow.example": {Addrs: addrs("192.0.2.1"), TTL: 50 * time.Second},
		"fast.example": {Addrs: addrs("192.0.2.2"), TTL: 10 * time.Second},
	}}
	r := newDomainResolver(f, clk.now)
	if got := r.NextRefreshDelay(); got != 60*time.Second {
		t.Fatalf("empty resolver delay = %v, want the 60s cap", got)
	}
	r.Refresh(context.Background(), []string{"slow.example", "fast.example"})
	clk.advance(4 * time.Second)
	if got := r.NextRefreshDelay(); got != 6*time.Second {
		t.Fatalf("delay = %v, want 6s (fast.example due first)", got)
	}
	clk.advance(6 * time.Second)
	r.Refresh(context.Background(), []string{"slow.example", "fast.example"})
	if f.calls["fast.example"] != 2 || f.calls["slow.example"] != 1 {
		t.Fatalf("only the due name should be re-queried, calls = %v", f.calls)
	}
}

func TestDomainResolver_OverlapOnRotation(t *testing.T) {
	clk := newResolverClock()
	f := &fakeTTLResolver{answers: map[string]dnsAnswer{
		"rot.example": {Addrs: addrs("192.0.2.1", "2001:db8::1"), TTL: 30 * time.Second},
	}}
	r := newDomainResolver(f, clk.now)
	r.Refresh(context.Background(), []string{"rot.example"})

	// Rotation: the lookup succeeds with a different set.
	clk.advance(30 * time.Second)
	f.answers["rot.example"] = dnsAnswer{Addrs: addrs("192.0.2.2", "2001:db8::2"), TTL: 30 * time.Second}
	r.Refresh(context.Background(), []string{"rot.example"})
	want := []string{"192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"}
	if got := addrStrings(r.Addrs("rot.example")); !slices.Equal(got, want) {
		t.Fatalf("right after rotation Addrs = %v, want old+new %v", got, want)
	}

	// One interval later (same answer): the old set is still kept.
	clk.advance(30 * time.Second)
	r.Refresh(context.Background(), []string{"rot.example"})
	clk.advance(29 * time.Second)
	if got := addrStrings(r.Addrs("rot.example")); !slices.Equal(got, want) {
		t.Fatalf("within two intervals Addrs = %v, want old+new %v", got, want)
	}

	// Two intervals after the rotation the old set is gone, even between refreshes.
	clk.advance(time.Second)
	want = []string{"192.0.2.2", "2001:db8::2"}
	if got := addrStrings(r.Addrs("rot.example")); !slices.Equal(got, want) {
		t.Fatalf("after two intervals Addrs = %v, want only new %v", got, want)
	}
}

func TestDomainResolver_RotationBackLeavesNoDuplicate(t *testing.T) {
	clk := newResolverClock()
	f := &fakeTTLResolver{answers: map[string]dnsAnswer{
		"flip.example": {Addrs: addrs("192.0.2.1"), TTL: 10 * time.Second},
	}}
	r := newDomainResolver(f, clk.now)
	r.Refresh(context.Background(), []string{"flip.example"})
	clk.advance(10 * time.Second)
	f.answers["flip.example"] = dnsAnswer{Addrs: addrs("192.0.2.2"), TTL: 10 * time.Second}
	r.Refresh(context.Background(), []string{"flip.example"})
	clk.advance(10 * time.Second)
	f.answers["flip.example"] = dnsAnswer{Addrs: addrs("192.0.2.1"), TTL: 10 * time.Second}
	r.Refresh(context.Background(), []string{"flip.example"})
	// 192.0.2.1 is current again (listed once); 192.0.2.2 is now in overlap.
	want := []string{"192.0.2.1", "192.0.2.2"}
	if got := addrStrings(r.Addrs("flip.example")); !slices.Equal(got, want) {
		t.Fatalf("Addrs = %v, want %v", got, want)
	}
	clk.advance(20 * time.Second)
	if got := addrStrings(r.Addrs("flip.example")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Fatalf("after overlap Addrs = %v, want [192.0.2.1]", got)
	}
}

func TestDomainResolver_FailedLookupKeepsPreviousSet(t *testing.T) {
	clk := newResolverClock()
	f := &fakeTTLResolver{answers: map[string]dnsAnswer{
		"x.example": {Addrs: addrs("192.0.2.7", "2001:db8::7"), TTL: 15 * time.Second},
	}}
	r := newDomainResolver(f, clk.now)
	r.Refresh(context.Background(), []string{"x.example"})
	f.errs = map[string]error{"x.example": errors.New("dns timeout")}
	// Fail across many intervals: the set is never dropped, and each failure
	// is retried on the name's interval (not a hot loop, not abandoned).
	for i := 0; i < 5; i++ {
		clk.advance(15 * time.Second)
		r.Refresh(context.Background(), []string{"x.example"})
	}
	if f.calls["x.example"] != 6 {
		t.Fatalf("failed lookups should retry each interval, calls = %d", f.calls["x.example"])
	}
	want := []string{"192.0.2.7", "2001:db8::7"}
	if got := addrStrings(r.Addrs("x.example")); !slices.Equal(got, want) {
		t.Fatalf("failed lookups must keep the previous set, got %v", got)
	}
	if got := r.NextRefreshDelay(); got != 15*time.Second {
		t.Fatalf("delay after failure = %v, want the name's 15s interval", got)
	}
}

func TestDomainResolver_ReturnsAAAA_IPsStaysIPv4(t *testing.T) {
	clk := newResolverClock()
	f := &fakeTTLResolver{answers: map[string]dnsAnswer{
		"dual.example": {Addrs: addrs("2001:db8::9", "192.0.2.9", "::ffff:192.0.2.10"), TTL: 30 * time.Second},
	}}
	r := newDomainResolver(f, clk.now)
	r.Refresh(context.Background(), []string{"dual.example"})
	if got, want := addrStrings(r.Addrs("dual.example")), []string{"192.0.2.9", "192.0.2.10", "2001:db8::9"}; !slices.Equal(got, want) {
		t.Fatalf("Addrs = %v, want dual-stack %v", got, want)
	}
	got := r.IPs("dual.example")
	if len(got) != 2 {
		t.Fatalf("IPs = %v, want the 2 IPv4 addresses", got)
	}
	for _, ip := range got {
		if !ip.Is4() {
			t.Fatalf("IPs (the IPv4-only enforcer view) returned %v", ip)
		}
	}
}
