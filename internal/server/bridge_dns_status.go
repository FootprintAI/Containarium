package server

import (
	"context"
	"math"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/bridgedns"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// bridgeDNSStatusResponse maps the reconciler's last-pass snapshot to the wire
// type (#2188). The state is derived here and nowhere else, so every
// combination of reconciler fields has exactly one answer:
//
//   - no pass has finished       → PENDING (never a false "in sync")
//   - the record matches         → IN_SYNC
//   - anything else              → DEGRADED, with the last error as the reason
//
// A snapshot that is neither in sync nor carries an error should not occur;
// it is reported as DEGRADED rather than guessed to be fine.
func bridgeDNSStatusResponse(st bridgedns.Status) *pb.GetBridgeDNSStatusResponse {
	resp := &pb.GetBridgeDNSStatusResponse{
		Bridge:     st.Bridge,
		CaddyIp:    st.CaddyIP,
		Desired:    st.Desired,
		Current:    st.Current,
		LastError:  st.LastError,
		DriftCount: saturateInt32(st.DriftCount),
	}
	if !st.LastPass.IsZero() {
		resp.LastPass = timestamppb.New(st.LastPass)
	}
	if !st.LastApplied.IsZero() {
		resp.LastApplied = timestamppb.New(st.LastApplied)
	}
	switch {
	case st.LastPass.IsZero():
		resp.State = pb.BridgeDNSState_BRIDGE_DNS_STATE_PENDING
		resp.Reason = "the reconciler has not finished a pass yet"
	case st.InSync:
		resp.State = pb.BridgeDNSState_BRIDGE_DNS_STATE_IN_SYNC
	case st.LastError != "":
		resp.State = pb.BridgeDNSState_BRIDGE_DNS_STATE_DEGRADED
		resp.Reason = st.LastError
	default:
		resp.State = pb.BridgeDNSState_BRIDGE_DNS_STATE_DEGRADED
		resp.Reason = "the record differs from the desired value and the last pass recorded no error"
	}
	return resp
}

// saturateInt32 converts the reconciler's int counter to the wire's int32
// without wrapping: a counter that has run long enough clamps at MaxInt32, and
// a negative value (which the reconciler never produces) clamps to zero, so the
// value on the wire is never a nonsense negative count.
func saturateInt32(n int) int32 {
	switch {
	case n < 0:
		return 0
	case n > math.MaxInt32:
		return math.MaxInt32
	default:
		return int32(n)
	}
}

// SetBridgeDNSReconciler wires the reconciler GetBridgeDNSStatus reports on.
// nil (app hosting off, or core-caddy not managed by this daemon) makes the RPC
// answer NOT_MANAGED. Called once from DualServer setup.
func (s *ContainerServer) SetBridgeDNSReconciler(r *bridgedns.Reconciler) {
	s.bridgeDNS = r
}

// GetBridgeDNSStatus reports the bridge DNS reconciler's last pass (#2188).
// Admin-only: the desired and current record carry operator-configured
// hostnames and core-caddy's bridge address.
func (s *ContainerServer) GetBridgeDNSStatus(ctx context.Context, req *pb.GetBridgeDNSStatusRequest) (*pb.GetBridgeDNSStatusResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.bridgeDNS == nil {
		return &pb.GetBridgeDNSStatusResponse{
			State:  pb.BridgeDNSState_BRIDGE_DNS_STATE_NOT_MANAGED,
			Reason: "this daemon is not running the bridge DNS reconciler: app hosting is off, or core-caddy is not managed by this daemon",
		}, nil
	}
	return bridgeDNSStatusResponse(s.bridgeDNS.Status()), nil
}
