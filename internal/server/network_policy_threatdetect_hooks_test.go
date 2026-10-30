package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
)

// pollFlows only runs its flow-hook call when e.loader is non-nil (a real
// eBPF object), which a unit test can't construct — so this exercises the
// hook plumbing directly instead, the same way pollFlows itself invokes it.
func TestFlowHook_InvokedWithActiveBatch(t *testing.T) {
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), nil, nil, nil, false)

	var got []netbpf.FlowRecord
	e.SetFlowHook(func(flows []netbpf.FlowRecord) { got = flows })
	if e.flowHook == nil {
		t.Fatal("SetFlowHook did not store the hook")
	}

	batch := []netbpf.FlowRecord{{Saddr: 1, Daddr: 2}}
	e.flowHook(batch)
	if len(got) != 1 || got[0] != batch[0] {
		t.Fatalf("flow hook received %+v, want %+v", got, batch)
	}
}

// #1640: OnDenyEvent must hand every deny event to a registered deny hook,
// in addition to (not instead of) its existing audit-log write.
func TestOnDenyEvent_CallsDenyHook(t *testing.T) {
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), nil, nil, nil, false)

	var got []netbpf.DenyEvent
	e.SetDenyHook(func(ev netbpf.DenyEvent) { got = append(got, ev) })

	ev := netbpf.DenyEvent{TenantID: 7, Dport: 443, Proto: 6}
	e.OnDenyEvent(context.Background(), ev)

	// No enforce entry for tenant 7, so the hook sees it as observation-only.
	want := ev
	want.LogOnly = true
	if len(got) != 1 || got[0] != want {
		t.Fatalf("deny hook calls = %+v, want exactly one call with %+v", got, want)
	}
}

// #2612: the hook must learn whether the tenant's policy is enforced, since
// the BPF program emits the event for a log_only would-deny exactly as for a
// drop.
func TestOnDenyEvent_HookCarriesTenantMode(t *testing.T) {
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), nil, nil, nil, false)
	e.mu.Lock()
	e.enforced[1] = true // tenant 1 enforced; tenant 2 observation-only
	e.mu.Unlock()

	var got []netbpf.DenyEvent
	e.SetDenyHook(func(ev netbpf.DenyEvent) { got = append(got, ev) })
	e.OnDenyEvent(context.Background(), netbpf.DenyEvent{TenantID: 1})
	e.OnDenyEvent(context.Background(), netbpf.DenyEvent{TenantID: 2})

	if len(got) != 2 || got[0].LogOnly || !got[1].LogOnly {
		t.Fatalf("LogOnly = enforced:%v observation:%v, want false/true (events %+v)", got[0].LogOnly, got[1].LogOnly, got)
	}
}

// A nil deny hook (the default — sentry disabled) must not panic OnDenyEvent.
func TestOnDenyEvent_NilHookIsNoop(t *testing.T) {
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), nil, nil, nil, false)
	e.OnDenyEvent(context.Background(), netbpf.DenyEvent{TenantID: 1}) // must not panic
}

// #1640: TenantForIP resolves via the enforcer's existing ip_tenant cache —
// the same cache the reconcile loop refreshes every 10s — without any new
// Incus or DB access.
func TestTenantForIP(t *testing.T) {
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), nil, nil, nil, false)
	e.mu.Lock()
	e.ipTenantInstalled[[4]byte{10, 0, 0, 5}] = 42
	e.idName[42] = "tenant-a"
	e.mu.Unlock()

	tenant, ok := e.TenantForIP(netip.MustParseAddr("10.0.0.5"))
	if !ok || tenant != "tenant-a" {
		t.Fatalf("TenantForIP(10.0.0.5) = (%q, %v), want (tenant-a, true)", tenant, ok)
	}

	_, ok = e.TenantForIP(netip.MustParseAddr("10.0.0.6"))
	if ok {
		t.Fatalf("TenantForIP(10.0.0.6) = ok, want !ok for an unrecognized IP")
	}

	_, ok = e.TenantForIP(netip.MustParseAddr("::1"))
	if ok {
		t.Fatalf("TenantForIP(::1) = ok, want !ok for a non-IPv4 address")
	}
}
