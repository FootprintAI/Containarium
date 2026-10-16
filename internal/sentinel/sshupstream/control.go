package sshupstream

import (
	"fmt"
	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
)

// Option configures the optional shared controller without altering child policy.
type Option func(*adapter)

// WithControl enables the process-shared backend admission and typed provenance.
func WithControl(peer *sshcontrol.Peer) Option { return func(a *adapter) { a.control = peer } }

// routeRef records controller provenance before invoking the authorization child.
type routeRef struct {
	ref   *pb.SSHUpstreamConnection
	token string
}

// begin resets exceptions even when the child rejects before selecting an upstream.
func (a *adapter) begin(c libplugin.ConnMetadata) error {
	if a.control == nil {
		return nil
	}
	ref := a.control.Find(c.UniqueID(), c.RemoteAddr())
	if ref == nil {
		return fmt.Errorf("unregistered upstream transport")
	}
	ctx, cancel := sshcontrol.CallContext(a.ctx)
	defer cancel()
	r, err := a.control.Client.BeginSSHUpstreamRoute(ctx, &pb.BeginSSHUpstreamRouteRequest{Connection: ref})
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, route := range a.routes {
		if a.control.Find(id, route.ref.RemoteAddr) == nil {
			delete(a.routes, id)
		}
	}
	if len(a.routes) >= 4096 {
		return fmt.Errorf("routing provenance capacity exhausted")
	}
	a.routes[c.UniqueID()] = routeRef{ref: ref, token: r.RouteToken}
	return nil
}

// report distinguishes an explicit stale-route rejection from a control outage.
func (a *adapter) report(b binding, outcome pb.SSHUpstreamOutcome) (bool, error) {
	ctx, cancel := sshcontrol.CallContext(a.ctx)
	defer cancel()
	r, err := a.control.Client.CompleteSSHUpstream(ctx, &pb.CompleteSSHUpstreamRequest{Connection: b.ref, RouteToken: b.route, LeaseToken: b.lease, Outcome: outcome})
	return r.GetAccepted(), err
}
