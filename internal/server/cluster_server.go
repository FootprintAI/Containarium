package server

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/cluster"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// KubeconfigReader reads a READY cluster's admin kubeconfig on demand
// from its control-plane VM. Implemented by the provisioner (#1414);
// the platform never persists kubeconfigs (design: managed-k8s-clusters,
// "Credentials").
type KubeconfigReader interface {
	ReadKubeconfig(ctx context.Context, c *cluster.Cluster) (string, error)
}

// ClusterServer implements ClusterService (#1413): managed-cluster
// lifecycle state. Provisioning is asynchronous by design — handlers
// record desired state and the reconciler (#1414) converges VMs — so
// this server stays thin: authz, validation, store transitions.
//
// Until the reconciler lands, DeleteCluster removes rows directly
// (nothing has provisioned VMs yet) and GetClusterKubeconfig answers
// Unimplemented on a READY cluster; #1414 replaces both seams.
type ClusterServer struct {
	pb.UnimplementedClusterServiceServer
	store      cluster.Store
	kubeconfig KubeconfigReader
}

// NewClusterServer builds the server on a Store (in-memory at startup;
// swapped to Postgres once the pool is up, same pattern as the network
// policy and crew-run stores).
func NewClusterServer(store cluster.Store) *ClusterServer {
	return &ClusterServer{store: store}
}

// SetStore swaps the backing store. Called before grpcServer.Serve, so
// it races with no live RPCs.
func (s *ClusterServer) SetStore(store cluster.Store) { s.store = store }

// SetKubeconfigReader wires the provisioner-backed kubeconfig path (#1414).
func (s *ClusterServer) SetKubeconfigReader(r KubeconfigReader) { s.kubeconfig = r }

// resolveOwner defaults an empty request owner to the authenticated
// subject and enforces tenant isolation for the resolved value.
func resolveOwner(ctx context.Context, reqOwner string) (string, error) {
	if reqOwner == "" {
		username, _, ok := auth.SubjectFromGRPCContext(ctx)
		if !ok {
			return "", status.Error(codes.Unauthenticated, "no authenticated subject")
		}
		reqOwner = username
	}
	if err := auth.AuthorizeTenant(ctx, reqOwner); err != nil {
		return "", err
	}
	return reqOwner, nil
}

func storeErr(err error) error {
	switch {
	case errors.Is(err, cluster.ErrNotFound):
		return status.Error(codes.NotFound, "cluster not found")
	case errors.Is(err, cluster.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, "cluster already exists")
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

// groupsFromProto converts and screens the typed node groups. GPU and
// per-box storage-class fields exist on the shared ResourceLimits
// message but have no meaning on a cluster node in v1 — GPU pools are
// a later phase, so requests carrying them are rejected loudly rather
// than silently dropped.
func groupsFromProto(in []*pb.NodeGroup) ([]cluster.NodeGroup, error) {
	out := make([]cluster.NodeGroup, 0, len(in))
	for _, g := range in {
		if g.Size == nil {
			return nil, status.Errorf(codes.InvalidArgument, "node group %q: size is required", g.Name)
		}
		if g.Size.Gpu != "" || len(g.Size.Gpus) > 0 { //nolint:staticcheck // deliberately reading the deprecated field to reject it
			return nil, status.Errorf(codes.InvalidArgument, "node group %q: GPU node pools are not supported yet (later phase)", g.Name)
		}
		out = append(out, cluster.NodeGroup{
			Name:     g.Name,
			Size:     cluster.Size{CPU: g.Size.Cpu, Memory: g.Size.Memory, Disk: g.Size.Disk},
			MinNodes: g.MinNodes,
			MaxNodes: g.MaxNodes,
		})
	}
	return out, nil
}

func groupToProto(g cluster.NodeGroup) *pb.NodeGroup {
	return &pb.NodeGroup{
		Name:     g.Name,
		Size:     &pb.ResourceLimits{Cpu: g.Size.CPU, Memory: g.Size.Memory, Disk: g.Size.Disk},
		MinNodes: g.MinNodes,
		MaxNodes: g.MaxNodes,
	}
}

var stateToProto = map[cluster.State]pb.ClusterState{
	cluster.StateProvisioning: pb.ClusterState_CLUSTER_STATE_PROVISIONING,
	cluster.StateReady:        pb.ClusterState_CLUSTER_STATE_READY,
	cluster.StateDegraded:     pb.ClusterState_CLUSTER_STATE_DEGRADED,
	cluster.StateDeleting:     pb.ClusterState_CLUSTER_STATE_DELETING,
	cluster.StateError:        pb.ClusterState_CLUSTER_STATE_ERROR,
}

var eventKindToProto = map[cluster.EventKind]pb.ScaleEventKind{
	cluster.EventScaleUp:      pb.ScaleEventKind_SCALE_EVENT_KIND_SCALE_UP,
	cluster.EventScaleDown:    pb.ScaleEventKind_SCALE_EVENT_KIND_SCALE_DOWN,
	cluster.EventRefused:      pb.ScaleEventKind_SCALE_EVENT_KIND_REFUSED,
	cluster.EventNodeReplaced: pb.ScaleEventKind_SCALE_EVENT_KIND_NODE_REPLACED,
}

func clusterToProto(c *cluster.Cluster) *pb.Cluster {
	out := &pb.Cluster{
		Name:        c.Name,
		Owner:       c.Owner,
		State:       stateToProto[c.State],
		StateReason: c.StateReason,
		K3SVersion:  c.K3sVersion,
		ApiEndpoint: c.APIEndpoint,
		CreatedAt:   timestamppb.New(c.CreatedAt),
	}
	for _, g := range c.NodeGroups {
		out.NodeGroups = append(out.NodeGroups, groupToProto(g))
	}
	return out
}

func nodeToProto(n *cluster.Node) *pb.ClusterNode {
	role := pb.ClusterNodeRole_CLUSTER_NODE_ROLE_WORKER
	if n.Role == cluster.RoleControlPlane {
		role = pb.ClusterNodeRole_CLUSTER_NODE_ROLE_CONTROL_PLANE
	}
	return &pb.ClusterNode{
		VmName:    n.VMName,
		Role:      role,
		NodeGroup: n.Group,
		State:     n.State,
		CreatedAt: timestamppb.New(n.CreatedAt),
	}
}

func (s *ClusterServer) CreateCluster(ctx context.Context, req *pb.CreateClusterRequest) (*pb.CreateClusterResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeClustersWrite); err != nil {
		return nil, err
	}
	owner, err := resolveOwner(ctx, req.Owner)
	if err != nil {
		return nil, err
	}
	if err := cluster.ValidateName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	groups, err := groupsFromProto(req.NodeGroups)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		groups = cluster.DefaultNodeGroups()
	}
	if err := cluster.ValidateNodeGroups(groups); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	now := time.Now().UTC()
	c := &cluster.Cluster{
		ID:         uuid.NewString(),
		Owner:      owner,
		Name:       req.Name,
		State:      cluster.StateProvisioning,
		NodeGroups: groups,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.store.Create(ctx, c); err != nil {
		return nil, storeErr(err)
	}
	log.Printf("[cluster] created owner=%s name=%s groups=%d", owner, req.Name, len(groups))
	return &pb.CreateClusterResponse{
		Cluster: clusterToProto(c),
		Message: "cluster recorded; provisioning runs asynchronously",
	}, nil
}

func (s *ClusterServer) ListClusters(ctx context.Context, req *pb.ListClustersRequest) (*pb.ListClustersResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeClustersRead); err != nil {
		return nil, err
	}
	owner := req.Owner
	if owner != "" {
		// An explicit filter must pass tenant isolation.
		if err := auth.AuthorizeTenant(ctx, owner); err != nil {
			return nil, err
		}
	} else {
		username, roles, ok := auth.SubjectFromGRPCContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no authenticated subject")
		}
		if !hasRole(roles, auth.RoleAdmin) {
			owner = username // non-admins list their own; admins list all
		}
	}
	clusters, err := s.store.List(ctx, owner)
	if err != nil {
		return nil, storeErr(err)
	}
	resp := &pb.ListClustersResponse{}
	for _, c := range clusters {
		resp.Clusters = append(resp.Clusters, clusterToProto(c))
	}
	return resp, nil
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func (s *ClusterServer) GetCluster(ctx context.Context, req *pb.GetClusterRequest) (*pb.GetClusterResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeClustersRead); err != nil {
		return nil, err
	}
	owner, err := resolveOwner(ctx, req.Owner)
	if err != nil {
		return nil, err
	}
	c, err := s.store.Get(ctx, owner, req.Name)
	if err != nil {
		return nil, storeErr(err)
	}
	return &pb.GetClusterResponse{Cluster: clusterToProto(c)}, nil
}

func (s *ClusterServer) DeleteCluster(ctx context.Context, req *pb.DeleteClusterRequest) (*pb.DeleteClusterResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeClustersWrite); err != nil {
		return nil, err
	}
	owner, err := resolveOwner(ctx, req.Owner)
	if err != nil {
		return nil, err
	}
	// Until the reconciler (#1414) exists nothing has provisioned VMs,
	// so removing rows IS the whole teardown. #1414 turns this into a
	// DELETING transition the reconciler drains.
	if err := s.store.Delete(ctx, owner, req.Name); err != nil {
		return nil, storeErr(err)
	}
	log.Printf("[cluster] deleted owner=%s name=%s", owner, req.Name)
	return &pb.DeleteClusterResponse{Message: "cluster deleted: " + req.Name}, nil
}

func (s *ClusterServer) GetClusterKubeconfig(ctx context.Context, req *pb.GetClusterKubeconfigRequest) (*pb.GetClusterKubeconfigResponse, error) {
	// Deliberately clusters:write, not read: the kubeconfig is
	// cluster-admin material — holding it mutates the cluster's
	// workloads — so an inspection-only token must not obtain it.
	if err := auth.RequireScope(ctx, auth.ScopeClustersWrite); err != nil {
		return nil, err
	}
	owner, err := resolveOwner(ctx, req.Owner)
	if err != nil {
		return nil, err
	}
	c, err := s.store.Get(ctx, owner, req.Name)
	if err != nil {
		return nil, storeErr(err)
	}
	if c.State != cluster.StateReady {
		return nil, status.Errorf(codes.FailedPrecondition, "cluster is %s; kubeconfig is available once READY", c.State)
	}
	if s.kubeconfig == nil {
		return nil, status.Error(codes.Unimplemented, "cluster provisioner not wired yet (#1414)")
	}
	kc, err := s.kubeconfig.ReadKubeconfig(ctx, c)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read kubeconfig: %v", err)
	}
	return &pb.GetClusterKubeconfigResponse{Kubeconfig: kc}, nil
}

const defaultEventsLimit = 20

func (s *ClusterServer) GetClusterStatus(ctx context.Context, req *pb.GetClusterStatusRequest) (*pb.GetClusterStatusResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeClustersRead); err != nil {
		return nil, err
	}
	owner, err := resolveOwner(ctx, req.Owner)
	if err != nil {
		return nil, err
	}
	c, err := s.store.Get(ctx, owner, req.Name)
	if err != nil {
		return nil, storeErr(err)
	}
	nodes, err := s.store.ListNodes(ctx, owner, req.Name)
	if err != nil {
		return nil, storeErr(err)
	}
	limit := int(req.EventsLimit)
	if limit <= 0 {
		limit = defaultEventsLimit
	}
	events, err := s.store.ListEvents(ctx, owner, req.Name, limit)
	if err != nil {
		return nil, storeErr(err)
	}

	resp := &pb.GetClusterStatusResponse{Cluster: clusterToProto(c)}
	perGroup := make(map[string]int32)
	for _, n := range nodes {
		resp.Nodes = append(resp.Nodes, nodeToProto(n))
		if n.Group != "" {
			perGroup[n.Group]++
		}
	}
	for _, g := range c.NodeGroups {
		resp.Groups = append(resp.Groups, &pb.NodeGroupStatus{
			Group:        groupToProto(g),
			CurrentNodes: perGroup[g.Name],
		})
	}
	for _, e := range events {
		resp.Events = append(resp.Events, &pb.ScaleEvent{
			At:        timestamppb.New(e.At),
			Kind:      eventKindToProto[e.Kind],
			NodeGroup: e.Group,
			Reason:    e.Reason,
		})
	}
	return resp, nil
}

func (s *ClusterServer) UpdateClusterNodePool(ctx context.Context, req *pb.UpdateClusterNodePoolRequest) (*pb.UpdateClusterNodePoolResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeClustersWrite); err != nil {
		return nil, err
	}
	owner, err := resolveOwner(ctx, req.Owner)
	if err != nil {
		return nil, err
	}
	groups, err := groupsFromProto(req.NodeGroups)
	if err != nil {
		return nil, err
	}
	if err := cluster.ValidateNodeGroups(groups); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := s.store.UpdateNodeGroups(ctx, owner, req.Name, groups); err != nil {
		return nil, storeErr(err)
	}
	c, err := s.store.Get(ctx, owner, req.Name)
	if err != nil {
		return nil, storeErr(err)
	}
	log.Printf("[cluster] node pool updated owner=%s name=%s groups=%d", owner, req.Name, len(groups))
	return &pb.UpdateClusterNodePoolResponse{
		Cluster: clusterToProto(c),
		Message: "node pool updated; the reconciler converges counts asynchronously",
	}, nil
}
