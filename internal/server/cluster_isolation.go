package server

// Node isolation gate (#1428). A cluster's isolation class decides what
// contains a tenant kernel exploit: a VM node keeps it inside the
// tenant's own kernel, a container node does not. The weaker class is
// therefore not tenant-selectable — the tenant *requests* it and the
// operator *permits* it, per host, with an env opt-in.
//
// Design: docs/architecture/cluster-container-node-pools.md.

import (
	"fmt"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/cluster"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// allowContainerNodesEnv is the operator's per-host assertion that
// everything on this host already shares one trust domain (a dev rung,
// a dedicated single-tenant machine, the operator's own CI). Unset on
// a shared multi-tenant host, container clusters are impossible there,
// so a tenant can never downgrade the boundary protecting another
// tenant.
const allowContainerNodesEnv = "CONTAINARIUM_CLUSTER_ALLOW_CONTAINER_NODES"

// isolationGate holds the parsed opt-in. Same fail-closed shape as
// clusterCaps: a configuration that cannot be parsed poisons the gate
// with configErr rather than leaving it open.
type isolationGate struct {
	allowContainer bool
	configErr      error
}

// parseIsolationGate reads the opt-in env. Unset is "not permitted"
// with no error (the default posture, not a misconfiguration); a value
// that is not a boolean is "not permitted AND say so", because a typo
// must refuse container creates rather than silently allow them.
func parseIsolationGate(v string) (isolationGate, error) {
	if v == "" {
		return isolationGate{}, nil
	}
	allow, err := strconv.ParseBool(v)
	if err != nil {
		return isolationGate{}, fmt.Errorf("%s %q: want true or false", allowContainerNodesEnv, v)
	}
	return isolationGate{allowContainer: allow}, nil
}

// SetIsolationGateFromEnv installs the gate from the operator's env
// value. A parse failure is recorded on the gate rather than returned:
// a typo must not open the gate, and must not stop the daemon serving
// VM clusters either.
func (s *ClusterServer) SetIsolationGateFromEnv(v string) {
	g, err := parseIsolationGate(v)
	if err != nil {
		s.isolation = isolationGate{configErr: err}
		return
	}
	s.isolation = g
}

// isolationFromProto maps a requested class onto the stored one.
// UNSPECIFIED resolves to VM — the safe default cannot be reached by
// omission of config. An unrecognized value is refused rather than
// defaulted: a caller who asked for something specific is never told
// "fine" and given something else.
func isolationFromProto(in pb.NodeIsolation) (cluster.Isolation, error) {
	switch in {
	case pb.NodeIsolation_NODE_ISOLATION_UNSPECIFIED, pb.NodeIsolation_NODE_ISOLATION_VM:
		return cluster.IsolationVM, nil
	case pb.NodeIsolation_NODE_ISOLATION_CONTAINER:
		return cluster.IsolationContainer, nil
	default:
		return "", status.Errorf(codes.InvalidArgument,
			"unknown node_isolation %v (want vm or container)", int32(in))
	}
}

// isolationToProto is the read direction. An isolation the API cannot
// express surfaces as UNSPECIFIED rather than as a silently-defaulted
// VM — an unknown boundary must not read as a strong one.
var isolationToProto = map[cluster.Isolation]pb.NodeIsolation{
	cluster.IsolationVM:        pb.NodeIsolation_NODE_ISOLATION_VM,
	cluster.IsolationContainer: pb.NodeIsolation_NODE_ISOLATION_CONTAINER,
}

// check admits an isolation class on this host. Only the weak class is
// gated; VM is always permitted (the gate's misconfiguration must not
// take the default class down with it).
func (g isolationGate) check(iso cluster.Isolation) error {
	if iso != cluster.IsolationContainer {
		return nil
	}
	if g.configErr != nil {
		return fmt.Errorf("container node isolation is gated by %s, which is misconfigured (%v); refusing until it is fixed",
			allowContainerNodesEnv, g.configErr)
	}
	if !g.allowContainer {
		return fmt.Errorf("container node isolation is not permitted on this host: the operator has not set %s=true. "+
			"Container nodes share the host kernel, so the opt-in is the operator asserting the host is a single trust domain",
			allowContainerNodesEnv)
	}
	return nil
}

// enforceIsolation resolves the requested class and admits it, or
// refuses with the typed error. FailedPrecondition, like the VM
// capability probe: the request is well-formed, the host will not
// serve it.
func (s *ClusterServer) enforceIsolation(req pb.NodeIsolation) (cluster.Isolation, error) {
	iso, err := isolationFromProto(req)
	if err != nil {
		return "", err
	}
	if err := s.isolation.check(iso); err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return iso, nil
}
