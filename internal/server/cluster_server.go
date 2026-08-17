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
// Without a reconciler wired (SetReconciler), DeleteCluster removes
// rows directly (nothing can have provisioned VMs) and
// GetClusterKubeconfig answers Unimplemented on a READY cluster.
type ClusterServer struct {
	pb.UnimplementedClusterServiceServer
	store      cluster.Store
	kubeconfig KubeconfigReader
	// vmCapable is the create-time capability probe (#1414): a host
	// that cannot run VMs refuses cluster creation with a typed
	// error instead of provisioning doomed records.
	vmCapable func() error
	// asyncDelete marks the reconciler as wired: DeleteCluster flips
	// records to DELETING for the reconciler to drain instead of
	// dropping rows that may have live VMs behind them.
	asyncDelete bool
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

// Store exposes the backing store so the reconciler shares it.
func (s *ClusterServer) Store() cluster.Store { return s.store }

// SetReconciler wires the #1414 reconciler: kubeconfig reads, the VM
// capability probe, and reconciler-drained deletes.
func (s *ClusterServer) SetReconciler(r *ClusterReconciler) {
	s.kubeconfig = r
	s.vmCapable = r.VMCapable
	s.asyncDelete = true
}

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
// a later phase and storage_class is a box-PVC concept — so requests
// carrying either are rejected loudly rather than silently dropped.
func groupsFromProto(in []*pb.NodeGroup) ([]cluster.NodeGroup, error) {
	out := make([]cluster.NodeGroup, 0, len(in))
	for _, g := range in {
		if g.Size == nil {
			return nil, status.Errorf(codes.InvalidArgument, "node group %q: size is required", g.Name)
		}
		if g.Size.Gpu != "" || len(g.Size.Gpus) > 0 { //nolint:staticcheck // deliberately reading the deprecated field to reject it
			return nil, status.Errorf(codes.InvalidArgument, "node group %q: GPU node pools are not supported yet (later phase)", g.Name)
		}
		if g.Size.StorageClass != "" {
			return nil, status.Errorf(codes.InvalidArgument, "node group %q: storage_class does not apply to cluster nodes", g.Name)
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

var nodeRoleToProto = map[string]pb.ClusterNodeRole{
	cluster.RoleControlPlane: pb.ClusterNodeRole_CLUSTER_NODE_ROLE_CONTROL_PLANE,
	cluster.RoleWorker:       pb.ClusterNodeRole_CLUSTER_NODE_ROLE_WORKER,
}

var nodeStateToProto = map[cluster.NodeState]pb.ClusterNodeState{
	cluster.NodeStateProvisioning: pb.ClusterNodeState_CLUSTER_NODE_STATE_PROVISIONING,
	cluster.NodeStateReady:        pb.ClusterNodeState_CLUSTER_NODE_STATE_READY,
	cluster.NodeStateDraining:     pb.ClusterNodeState_CLUSTER_NODE_STATE_DRAINING,
}

func nodeToProto(n *cluster.Node) *pb.ClusterNode {
	// Unknown role/state map to UNSPECIFIED — drift between the store
	// and the API surfaces as an explicit "unspecified", not as a
	// silently-defaulted worker.
	return &pb.ClusterNode{
		VmName:    n.VMName,
		Role:      nodeRoleToProto[n.Role],
		NodeGroup: n.Group,
		State:     nodeStateToProto[n.State],
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
	if s.vmCapable != nil {
		if err := s.vmCapable(); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
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
		if !auth.HasRole(roles, auth.RoleAdmin) {
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
	if s.asyncDelete {
		// The reconciler owns teardown: flip to DELETING and let it
		// drain VMs, the endpoint, and finally the rows.
		if _, err := s.store.Get(ctx, owner, req.Name); err != nil {
			return nil, storeErr(err)
		}
		if err := s.store.SetState(ctx, owner, req.Name, cluster.StateDeleting, ""); err != nil {
			return nil, storeErr(err)
		}
		log.Printf("[cluster] deletion requested owner=%s name=%s", owner, req.Name)
		return &pb.DeleteClusterResponse{Message: "cluster deletion in progress: " + req.Name}, nil
	}
	// No reconciler wired → nothing can have provisioned VMs, so
	// removing rows IS the whole teardown.
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

const (
	defaultEventsLimit = 20
	maxEventsLimit     = 1000 // house precedent: audit/traffic stores clamp both ends
)

// clampEventsLimit bounds a client-supplied events limit: non-positive
// values take the default, and the ceiling stops a tenant turning the
// append-only event history into a memory amplification per call.
func clampEventsLimit(v int32) int {
	if v <= 0 {
		return defaultEventsLimit
	}
	if v > maxEventsLimit {
		return maxEventsLimit
	}
	return int(v)
}

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
	events, err := s.store.ListEvents(ctx, owner, req.Name, clampEventsLimit(req.EventsLimit))
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
