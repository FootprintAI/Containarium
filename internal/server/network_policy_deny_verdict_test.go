package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
)

// #2970 review: once mode and egress_mode differ, the tenant-wide mode no
// longer says what happened to a denied packet. OnDenyEvent, its audit row and
// the threat-detection hook must follow the verdict the program reported, and
// fall back to the tenant-wide mode only for an event without one.
func TestOnDenyEvent_FollowsProgramVerdict(t *testing.T) {
	tests := []struct {
		name         string
		tenantEnfrcd bool // e.enforced[tenant]: the tenant-wide mode is ENFORCE
		verdict      uint8
		wantDropped  bool
		wantAction   string
	}{
		{
			name:         "mode=ENFORCE, egress_mode=LOG_ONLY: allow-list miss is logged, not dropped",
			tenantEnfrcd: true, verdict: netbpf.DenyVerdictLogged,
			wantDropped: false, wantAction: "network_policy.deny_logged",
		},
		{
			name:         "mode=LOG_ONLY, egress_mode=ENFORCE: allow-list miss is dropped",
			tenantEnfrcd: false, verdict: netbpf.DenyVerdictDropped,
			wantDropped: true, wantAction: "network_policy.deny_dropped",
		},
		{
			name:         "older object (no verdict): falls back to the tenant-wide ENFORCE",
			tenantEnfrcd: true, verdict: netbpf.DenyVerdictUnknown,
			wantDropped: true, wantAction: "network_policy.deny_dropped",
		},
		{
			name:         "older object (no verdict): falls back to the tenant-wide LOG_ONLY",
			tenantEnfrcd: false, verdict: netbpf.DenyVerdictUnknown,
			wantDropped: false, wantAction: "network_policy.deny_logged",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), nil, nil, nil, false)
			e.mu.Lock()
			e.enforced[1] = tt.tenantEnfrcd
			e.idName[1] = "tenant-a"
			e.mu.Unlock()

			var got []netbpf.DenyEvent
			e.SetDenyHook(func(ev netbpf.DenyEvent) { got = append(got, ev) })
			ev := netbpf.DenyEvent{TenantID: 1, Proto: 6, Dport: 443, Verdict: tt.verdict}
			e.OnDenyEvent(context.Background(), ev)
			if len(got) != 1 {
				t.Fatalf("deny hook called %d times, want 1", len(got))
			}
			if got[0].LogOnly != !tt.wantDropped {
				t.Errorf("hook LogOnly = %v, want %v", got[0].LogOnly, !tt.wantDropped)
			}

			dropped := e.denyEventDropped(ev)
			if dropped != tt.wantDropped {
				t.Fatalf("denyEventDropped = %v, want %v", dropped, tt.wantDropped)
			}
			entry := denyAuditEntry(ev, "tenant-a", "", dropped)
			if entry.Action != tt.wantAction {
				t.Errorf("audit action = %q, want %q", entry.Action, tt.wantAction)
			}
			var detail struct {
				Dropped bool `json:"dropped"`
			}
			if err := json.Unmarshal([]byte(entry.Detail), &detail); err != nil {
				t.Fatalf("audit detail is not JSON: %v (%s)", err, entry.Detail)
			}
			if detail.Dropped != tt.wantDropped {
				t.Errorf("audit detail dropped = %v, want %v (%s)", detail.Dropped, tt.wantDropped, entry.Detail)
			}
			if entry.ResourceID != "tenant-a" {
				t.Errorf("audit resource = %q, want tenant-a", entry.ResourceID)
			}
		})
	}
}

// A signature match carries the verdict for the tenant's mode; the audit row
// keeps its own action and records the reported verdict.
func TestDenyAuditEntry_SignatureRecordsVerdict(t *testing.T) {
	ev := netbpf.DenyEvent{TenantID: 1, Proto: 6, Dport: 80, Reason: netbpf.DenyReasonSignature, SigID: 4, Verdict: netbpf.DenyVerdictLogged}
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), nil, nil, nil, false)
	e.mu.Lock()
	e.enforced[1] = true
	e.mu.Unlock()
	entry := denyAuditEntry(ev, "tenant-a", "log4shell", e.denyEventDropped(ev))
	if entry.Action != "network_policy.signature_match" {
		t.Errorf("audit action = %q, want network_policy.signature_match", entry.Action)
	}
	var detail struct {
		Dropped bool   `json:"dropped"`
		SigName string `json:"sig_name"`
	}
	if err := json.Unmarshal([]byte(entry.Detail), &detail); err != nil {
		t.Fatalf("audit detail is not JSON: %v (%s)", err, entry.Detail)
	}
	if detail.Dropped || detail.SigName != "log4shell" {
		t.Errorf("signature detail = %+v, want dropped=false sig_name=log4shell", detail)
	}
}
