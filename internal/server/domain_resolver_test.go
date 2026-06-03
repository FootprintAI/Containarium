package server

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// fakeIPResolver returns canned results per host.
type fakeIPResolver struct {
	results map[string][]netip.Addr
	errs    map[string]error
	calls   map[string]int
}

func (f *fakeIPResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[host]++
	if err := f.errs[host]; err != nil {
		return nil, err
	}
	return f.results[host], nil
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestDomainResolver_RefreshAndIPs(t *testing.T) {
	f := &fakeIPResolver{results: map[string][]netip.Addr{
		// unsorted + an IPv6 that must be filtered out
		"api.github.com": addrs("140.82.114.6", "140.82.112.3", "2606:50c0::1"),
	}}
	r := NewDomainResolver(f)
	r.Refresh(context.Background(), []string{"api.github.com", "api.github.com"}) // dup ignored

	got := r.IPs("api.github.com")
	if len(got) != 2 {
		t.Fatalf("expected 2 IPv4 (IPv6 filtered), got %v", got)
	}
	if got[0].String() != "140.82.112.3" || got[1].String() != "140.82.114.6" {
		t.Errorf("not sorted: %v", got)
	}
	if f.calls["api.github.com"] != 1 {
		t.Errorf("dup domain should resolve once, got %d calls", f.calls["api.github.com"])
	}
	if len(r.IPs("unknown.example")) != 0 {
		t.Errorf("unknown domain should be empty")
	}
}

func TestDomainResolver_KeepsPriorOnError(t *testing.T) {
	f := &fakeIPResolver{results: map[string][]netip.Addr{"x.example": addrs("1.2.3.4")}}
	r := NewDomainResolver(f)
	r.Refresh(context.Background(), []string{"x.example"})
	if len(r.IPs("x.example")) != 1 {
		t.Fatal("setup: expected 1 IP")
	}
	// Now lookups fail — prior cache must be retained, not dropped.
	f.errs = map[string]error{"x.example": errors.New("dns timeout")}
	r.Refresh(context.Background(), []string{"x.example"})
	if got := r.IPs("x.example"); len(got) != 1 || got[0].String() != "1.2.3.4" {
		t.Errorf("failed lookup must keep prior IPs, got %v", got)
	}
}

func TestDomainResolver_PrunesDropped(t *testing.T) {
	f := &fakeIPResolver{results: map[string][]netip.Addr{
		"a.example": addrs("1.1.1.1"),
		"b.example": addrs("2.2.2.2"),
	}}
	r := NewDomainResolver(f)
	r.Refresh(context.Background(), []string{"a.example", "b.example"})
	// Next refresh only requests a.example → b.example pruned.
	r.Refresh(context.Background(), []string{"a.example"})
	if len(r.IPs("a.example")) != 1 {
		t.Errorf("a.example should remain")
	}
	if len(r.IPs("b.example")) != 0 {
		t.Errorf("b.example should be pruned, got %v", r.IPs("b.example"))
	}
}
