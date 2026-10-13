package server

import (
	"context"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/coreguard"
	"github.com/footprintai/containarium/internal/nicguard"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/internal/tenantguard"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SetGuards hands the two NIC-ACL reconcilers to the network server so
// GetNetworkGuardStatus can report them. Either may be nil (no incus
// client on this host); its status then reads as mode UNSPECIFIED.
func (s *NetworkServer) SetGuards(core *coreguard.Reconciler, tenant *tenantguard.Reconciler) {
	s.coreGuard = core
	s.tenantGuard = tenant
}

// GetNetworkGuardStatus reports both guards' last-pass snapshots. Admin only:
// the entries name every tenant container on the host.
func (s *NetworkServer) GetNetworkGuardStatus(ctx context.Context, _ *pb.GetNetworkGuardStatusRequest) (*pb.NetworkGuardStatus, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	out := &pb.NetworkGuardStatus{}
	if s.coreGuard != nil {
		out.Core = coreGuardStatusToProto(s.coreGuard.Status())
	}
	if s.tenantGuard != nil {
		out.Tenant = tenantGuardStatusToProto(s.tenantGuard.Status())
	}
	return out, nil
}

func guardModeToProto(m nicguard.Mode) pb.GuardMode {
	switch m {
	case nicguard.ModeEnforce:
		return pb.GuardMode_GUARD_MODE_ENFORCE
	case nicguard.ModeOff:
		return pb.GuardMode_GUARD_MODE_OFF
	}
	return pb.GuardMode_GUARD_MODE_UNSPECIFIED
}

func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func coreGuardStatusToProto(st coreguard.Status) *pb.GuardStatus {
	out := &pb.GuardStatus{
		Mode:           guardModeToProto(st.Mode),
		FirewallDriver: st.FirewallDriver,
		Unsupported:    nicguard.UnsupportedReason(st.LastError),
		LastPass:       rfc3339OrEmpty(st.LastPass),
		LastError:      st.LastError,
		StaleSince:     rfc3339OrEmpty(st.StaleSince),
		Subjects:       safecast.I32(len(st.Entries)),
	}
	for _, e := range st.Entries {
		out.Entries = append(out.Entries, &pb.GuardEntry{
			Container: e.Container, Subject: string(e.Role), Ip: e.IP, AclName: e.ACLName,
			Attached: e.Attached, LastError: e.LastError,
		})
	}
	for _, r := range st.UnknownRoles {
		out.Unresolved = append(out.Unresolved, string(r))
	}
	return out
}

func tenantGuardStatusToProto(st tenantguard.Status) *pb.GuardStatus {
	out := &pb.GuardStatus{
		Mode:           guardModeToProto(st.Mode),
		FirewallDriver: st.FirewallDriver,
		Unsupported:    st.Unsupported,
		LastPass:       rfc3339OrEmpty(st.LastPass),
		LastError:      st.LastError,
		StaleSince:     rfc3339OrEmpty(st.StaleSince),
		Subjects:       safecast.I32(st.Tenants),
		Unresolved:     append([]string(nil), st.Unresolved...),
	}
	for _, e := range st.Entries {
		out.Entries = append(out.Entries, &pb.GuardEntry{
			Container: e.Container, Subject: e.Tenant, Ip: e.IP, AclName: e.ACLName,
			Attached: e.Attached, LastError: e.LastError,
		})
	}
	return out
}
