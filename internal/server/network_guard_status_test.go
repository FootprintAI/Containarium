package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/coreguard"
	"github.com/footprintai/containarium/internal/nicguard"
	"github.com/footprintai/containarium/internal/tenantguard"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestTenantGuardStatusToProto(t *testing.T) {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	st := tenantguard.Status{
		Mode:           nicguard.ModeEnforce,
		FirewallDriver: "nftables",
		Entries: []tenantguard.Entry{
			{Container: "alice-container", Tenant: "alice", IP: "10.100.0.17", ACLName: "containarium-tenant-abc", Attached: true},
			{Container: "cld-1", Tenant: "org-a", LastError: "nic device: boom"},
		},
		Unresolved: []string{"mystery"},
		Tenants:    2,
		LastPass:   at,
	}
	got := tenantGuardStatusToProto(st)
	if got.Mode != pb.GuardMode_GUARD_MODE_ENFORCE || got.FirewallDriver != "nftables" || got.Unsupported {
		t.Errorf("header = %+v", got)
	}
	if got.LastPass != "2026-10-06T12:00:00Z" || got.StaleSince != "" {
		t.Errorf("times = %q / %q", got.LastPass, got.StaleSince)
	}
	if got.Subjects != 2 || len(got.Entries) != 2 || len(got.Unresolved) != 1 {
		t.Errorf("counts = %+v", got)
	}
	e := got.Entries[0]
	if e.Container != "alice-container" || e.Subject != "alice" || e.Ip != "10.100.0.17" || e.AclName != "containarium-tenant-abc" || !e.Attached {
		t.Errorf("entry[0] = %+v", e)
	}
	if got.Entries[1].LastError != "nic device: boom" || got.Entries[1].Attached {
		t.Errorf("entry[1] = %+v", got.Entries[1])
	}
}

func TestGuardStatusToProto_UnsupportedAndOff(t *testing.T) {
	ts := tenantguard.Status{Mode: nicguard.ModeEnforce, FirewallDriver: "xtables", Unsupported: true,
		LastError: "tenantguard: " + nicguard.ErrUnsupportedFirewall.Error() + " (driver=\"xtables\")", StaleSince: time.Unix(1, 0)}
	if got := tenantGuardStatusToProto(ts); !got.Unsupported || got.StaleSince == "" {
		t.Errorf("tenant unsupported not reported: %+v", got)
	}
	// The core guard keeps only the error text; the flag is derived from it.
	cs := coreguard.Status{Mode: nicguard.ModeEnforce, LastError: "coreguard: " + nicguard.ErrUnsupportedIncus.Error() + " (incus 6.0.0)"}
	if got := coreGuardStatusToProto(cs); !got.Unsupported {
		t.Errorf("core unsupported not derived from last error: %+v", got)
	}
	cs = coreguard.Status{Mode: nicguard.ModeEnforce, LastError: "coreguard: list containers: boom"}
	if got := coreGuardStatusToProto(cs); got.Unsupported {
		t.Errorf("an ordinary error must not read as unsupported: %+v", got)
	}
	off := tenantguard.Status{Mode: nicguard.ModeOff}
	if got := tenantGuardStatusToProto(off); got.Mode != pb.GuardMode_GUARD_MODE_OFF {
		t.Errorf("off mode = %v", got.Mode)
	}
	cs = coreguard.Status{Mode: nicguard.ModeEnforce, Entries: []coreguard.Entry{{Container: "containarium-core-postgres", Role: incus.RolePostgres, Attached: true}}, UnknownRoles: []incus.Role{"core-mystery"}}
	got := coreGuardStatusToProto(cs)
	if got.Subjects != 1 || got.Entries[0].Subject != string(incus.RolePostgres) || len(got.Unresolved) != 1 || got.Unresolved[0] != "core-mystery" {
		t.Errorf("core conversion = %+v", got)
	}
}

// Admin only, and a host without guards (no incus client) answers with
// both halves unset rather than an error.
func TestGetNetworkGuardStatus_AdminOnlyAndNilGuards(t *testing.T) {
	s := &NetworkServer{}
	_, err := s.GetNetworkGuardStatus(context.Background(), &pb.GetNetworkGuardStatusRequest{})
	if status.Code(err) != codes.PermissionDenied && status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected an auth error without an admin principal, got %v", err)
	}
	ctx := auth.ContextWithClaims(context.Background(), &auth.Claims{Username: "root", Roles: []string{auth.RoleAdmin}})
	got, err := s.GetNetworkGuardStatus(ctx, &pb.GetNetworkGuardStatusRequest{})
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	if got.Core != nil || got.Tenant != nil {
		t.Errorf("nil guards must yield unset halves: %+v", got)
	}
	if errors.Is(err, nil) && got == nil {
		t.Fatal("nil response")
	}
}
