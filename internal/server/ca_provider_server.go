package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/auth"
	clusterstore "github.com/footprintai/containarium/internal/cluster"
	clustercore "github.com/footprintai/containarium/pkg/core/cluster"
	capb "github.com/footprintai/containarium/pkg/pb/thirdparty/externalgrpc"
	corev1 "github.com/footprintai/containarium/pkg/pb/thirdparty/k8s.io/api/core/v1"
	resourcepb "github.com/footprintai/containarium/pkg/pb/thirdparty/k8s.io/apimachinery/pkg/api/resource"
	metav1 "github.com/footprintai/containarium/pkg/pb/thirdparty/k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CAProviderServer implements the upstream cluster-autoscaler
// externalgrpc CloudProvider contract (#1415) — the server side the
// stock CA binary speaks with --cloud-provider=externalgrpc. This is
// the "inherit, don't invent" seam: CA owns every scaling decision;
// this server only answers questions from the store and applies
// target-size changes the reconciler then executes.
//
// Identity: every call must carry the cluster's own machine identity
// (subject `k8s-cluster:<owner>/<name>`, scope clusters:scale). A
// token for cluster A calling about cluster B's node groups is
// PermissionDenied — the id embedded in each node-group id is
// verified against the authenticated cluster, never trusted.
//
// Model: NodeGroup.TargetNodes is the one piece of state CA owns.
// IncreaseSize raises it (bounded by max_nodes); the reconciler
// creates VMs up to it. DeleteNodes removes CA-drained nodes
// immediately and lowers the target. Nothing here ever creates a VM
// inline — provisioning stays in exactly one place.
type CAProviderServer struct {
	capb.UnimplementedCloudProviderServer
	store clusterstore.Store
	mgr   *clustercore.Manager
}

// NewCAProviderServer builds the provider over the shared store and
// manager.
func NewCAProviderServer(store clusterstore.Store, mgr *clustercore.Manager) *CAProviderServer {
	return &CAProviderServer{store: store, mgr: mgr}
}

// CASubjectPrefix marks the cluster machine identity's subject.
const CASubjectPrefix = "k8s-cluster:"

// CASubject renders the machine-identity subject for a cluster.
func CASubject(owner, name string) string {
	return CASubjectPrefix + owner + "/" + name
}

// caIdentity resolves and enforces the calling cluster's identity.
// Only the dedicated machine subject passes — an admin user token is
// deliberately NOT accepted on this surface (it is machine-to-machine
// only; humans use ClusterService).
func (s *CAProviderServer) caIdentity(ctx context.Context) (owner, name string, err error) {
	if err := auth.RequireScope(ctx, auth.ScopeClustersScale); err != nil {
		return "", "", err
	}
	subject, _, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok || !strings.HasPrefix(subject, CASubjectPrefix) {
		return "", "", status.Error(codes.PermissionDenied, "this surface accepts only a cluster machine identity")
	}
	owner, name, ok = strings.Cut(strings.TrimPrefix(subject, CASubjectPrefix), "/")
	if !ok || owner == "" || name == "" {
		return "", "", status.Error(codes.PermissionDenied, "malformed cluster machine identity")
	}
	return owner, name, nil
}

// groupID is "<owner>/<cluster>/<group>" — debuggable, and verified
// against the caller's identity on every use.
func groupID(owner, name, group string) string { return owner + "/" + name + "/" + group }

func (s *CAProviderServer) groupFromID(ctx context.Context, id string) (owner, name string, g clusterstore.NodeGroup, c *clusterstore.Cluster, err error) {
	owner, name, err = s.caIdentity(ctx)
	if err != nil {
		return "", "", g, nil, err
	}
	parts := strings.Split(id, "/")
	if len(parts) != 3 || parts[0] != owner || parts[1] != name {
		return "", "", g, nil, status.Errorf(codes.PermissionDenied, "node group %q does not belong to the authenticated cluster", id)
	}
	c, err = s.store.Get(ctx, owner, name)
	if err != nil {
		return "", "", g, nil, storeErr(err)
	}
	for _, cand := range c.NodeGroups {
		if cand.Name == parts[2] {
			return owner, name, cand, c, nil
		}
	}
	return "", "", g, nil, status.Errorf(codes.NotFound, "node group %q not found", id)
}

const providerIDPrefix = "containarium://"

// --- identity-shaped RPCs ---------------------------------------------

func (s *CAProviderServer) NodeGroups(ctx context.Context, _ *capb.NodeGroupsRequest) (*capb.NodeGroupsResponse, error) {
	owner, name, err := s.caIdentity(ctx)
	if err != nil {
		return nil, err
	}
	c, err := s.store.Get(ctx, owner, name)
	if err != nil {
		return nil, storeErr(err)
	}
	resp := &capb.NodeGroupsResponse{}
	for _, g := range c.NodeGroups {
		resp.NodeGroups = append(resp.NodeGroups, &capb.NodeGroup{
			Id:      groupID(owner, name, g.Name),
			MinSize: g.MinNodes,
			MaxSize: g.MaxNodes,
			Debug:   fmt.Sprintf("cpu=%s memory=%s disk=%s target=%d", g.Size.CPU, g.Size.Memory, g.Size.Disk, g.EffectiveTarget()),
		})
	}
	return resp, nil
}

func (s *CAProviderServer) NodeGroupForNode(ctx context.Context, req *capb.NodeGroupForNodeRequest) (*capb.NodeGroupForNodeResponse, error) {
	owner, name, err := s.caIdentity(ctx)
	if err != nil {
		return nil, err
	}
	nodes, err := s.store.ListNodes(ctx, owner, name)
	if err != nil {
		return nil, storeErr(err)
	}
	nodeName := req.Node.GetName()
	for _, n := range nodes {
		if n.VMName == nodeName && n.Role == clusterstore.RoleWorker {
			return &capb.NodeGroupForNodeResponse{NodeGroup: &capb.NodeGroup{Id: groupID(owner, name, n.Group)}}, nil
		}
	}
	// Not ours (or the control plane): empty id = CA skips the node.
	return &capb.NodeGroupForNodeResponse{NodeGroup: &capb.NodeGroup{Id: ""}}, nil
}

// --- size state --------------------------------------------------------

func (s *CAProviderServer) NodeGroupTargetSize(ctx context.Context, req *capb.NodeGroupTargetSizeRequest) (*capb.NodeGroupTargetSizeResponse, error) {
	_, _, g, _, err := s.groupFromID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return &capb.NodeGroupTargetSizeResponse{TargetSize: g.EffectiveTarget()}, nil
}

func (s *CAProviderServer) NodeGroupIncreaseSize(ctx context.Context, req *capb.NodeGroupIncreaseSizeRequest) (*capb.NodeGroupIncreaseSizeResponse, error) {
	owner, name, g, c, err := s.groupFromID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if req.Delta <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "delta must be positive, got %d", req.Delta)
	}
	target := g.EffectiveTarget() + req.Delta
	if target > g.MaxNodes {
		// Loud refusal, recorded — never clamped (PRD story 5).
		_ = s.store.AppendEvent(ctx, owner, name, clusterstore.Event{
			At: time.Now().UTC(), Kind: clusterstore.EventRefused, Group: g.Name,
			Reason: fmt.Sprintf("autoscaler asked for %d nodes; max_nodes is %d", target, g.MaxNodes),
		})
		return nil, status.Errorf(codes.ResourceExhausted, "target %d exceeds max_nodes %d for group %q", target, g.MaxNodes, g.Name)
	}
	if err := s.setTarget(ctx, c, g.Name, target); err != nil {
		return nil, err
	}
	_ = s.store.AppendEvent(ctx, owner, name, clusterstore.Event{
		At: time.Now().UTC(), Kind: clusterstore.EventScaleUp, Group: g.Name,
		Reason: fmt.Sprintf("autoscaler raised target to %d (pending pods)", target),
	})
	return &capb.NodeGroupIncreaseSizeResponse{}, nil
}

func (s *CAProviderServer) NodeGroupDeleteNodes(ctx context.Context, req *capb.NodeGroupDeleteNodesRequest) (*capb.NodeGroupDeleteNodesResponse, error) {
	owner, name, g, c, err := s.groupFromID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.ListNodes(ctx, owner, name)
	if err != nil {
		return nil, storeErr(err)
	}
	inGroup := make(map[string]bool)
	for _, n := range rows {
		if n.Group == g.Name {
			inGroup[n.VMName] = true
		}
	}
	// Validate the whole batch before deleting anything.
	for _, n := range req.Nodes {
		if !inGroup[n.GetName()] {
			return nil, status.Errorf(codes.NotFound, "node %q is not in group %q", n.GetName(), g.Name)
		}
	}
	// The target is lowered BEFORE anything is destroyed (#1498).
	//
	// The reconciler ticks independently and derives each group's
	// desired minimum from EffectiveTarget(), so any pass that lands
	// while the store still counts a node we have already destroyed
	// will faithfully rebuild it — and the rebuilt node reuses the
	// released name, which k3s refuses forever (see ForgetNode). Doing
	// this last left a window one DeleteVM wide, seconds against a 15s
	// tick, and run 21 landed in it.
	//
	// Ordering it this way makes the failure modes converge downward:
	// if a delete below fails, the group is left with a target lower
	// than its node count, which the reconciler will not act on
	// (it only creates up to Min, never scales down) and which the
	// autoscaler retries. The reverse — a target higher than reality —
	// is the one state that resurrects a drained node.
	// The target is derived from how many nodes the group ACTUALLY has,
	// not by subtracting the batch from the current target.
	//
	// Because the decrement is committed before anything is destroyed,
	// subtracting from the current target would move it again on every
	// retry of a delete that keeps failing — the node row survives a
	// failed delete, so the retry re-validates as legitimate and
	// subtracts a second time. Three retries walked a 3-node group's
	// target to MinNodes with all three instances still present.
	// Counting the rows makes the result idempotent: the same request,
	// repeated, lands on the same target.
	inGroupCount := int32(0)
	for _, n := range rows {
		if n.Group == g.Name {
			inGroupCount++
		}
	}
	target := inGroupCount - int32(len(req.Nodes)) //nolint:gosec // batch length is bounded by the group's int32 max_nodes (validated above)
	if target < g.MinNodes {
		target = g.MinNodes
	}
	if err := s.setTarget(ctx, c, g.Name, target); err != nil {
		return nil, err
	}
	var staleSecrets []string
	for _, n := range req.Nodes {
		// CA has already drained the node; removing the VM is safe.
		// ForgetNode also clears the control plane's node-password
		// secret, without which a later node of the same name can
		// never join (#1498).
		if err := s.mgr.ForgetNode(owner, name, n.GetName()); err != nil {
			if !errors.Is(err, clustercore.ErrNodePasswordNotCleared) {
				return nil, status.Errorf(codes.Internal, "delete %s: %v", n.GetName(), err)
			}
			// The instance IS gone, so the removal must not be
			// retried — but the residue is not harmless, and a log
			// line is not where anyone looks. Record it on the
			// cluster's own history.
			staleSecrets = append(staleSecrets, n.GetName())
		}
		_ = s.store.DeleteNode(ctx, owner, name, n.GetName())
	}
	reason := fmt.Sprintf("autoscaler removed %d drained node(s); target now %d", len(req.Nodes), target)
	if len(staleSecrets) > 0 {
		reason += fmt.Sprintf("; WARNING: node-password secret still present for %s — a future node of that name will be refused until it is removed",
			strings.Join(staleSecrets, ", "))
	}
	_ = s.store.AppendEvent(ctx, owner, name, clusterstore.Event{
		At: time.Now().UTC(), Kind: clusterstore.EventScaleDown, Group: g.Name,
		Reason: reason,
	})
	return &capb.NodeGroupDeleteNodesResponse{}, nil
}

func (s *CAProviderServer) NodeGroupDecreaseTargetSize(ctx context.Context, req *capb.NodeGroupDecreaseTargetSizeRequest) (*capb.NodeGroupDecreaseTargetSizeResponse, error) {
	owner, name, g, c, err := s.groupFromID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if req.Delta >= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "delta must be negative, got %d", req.Delta)
	}
	rows, err := s.store.ListNodes(ctx, owner, name)
	if err != nil {
		return nil, storeErr(err)
	}
	existing := int32(0)
	for _, n := range rows {
		if n.Group == g.Name {
			existing++
		}
	}
	target := g.EffectiveTarget() + req.Delta
	if target < existing {
		// Upstream contract: this call only cancels capacity that was
		// requested but never materialized — it must not delete nodes.
		return nil, status.Errorf(codes.InvalidArgument, "cannot decrease target below existing node count %d (use DeleteNodes)", existing)
	}
	if target < g.MinNodes {
		target = g.MinNodes
	}
	if err := s.setTarget(ctx, c, g.Name, target); err != nil {
		return nil, err
	}
	return &capb.NodeGroupDecreaseTargetSizeResponse{}, nil
}

func (s *CAProviderServer) setTarget(ctx context.Context, c *clusterstore.Cluster, group string, target int32) error {
	groups := append([]clusterstore.NodeGroup(nil), c.NodeGroups...)
	for i := range groups {
		if groups[i].Name == group {
			groups[i].TargetNodes = target
		}
	}
	if err := s.store.UpdateNodeGroups(ctx, c.Owner, c.Name, groups); err != nil {
		return storeErr(err)
	}
	return nil
}

// --- node listing / templates -----------------------------------------

func (s *CAProviderServer) NodeGroupNodes(ctx context.Context, req *capb.NodeGroupNodesRequest) (*capb.NodeGroupNodesResponse, error) {
	owner, name, g, _, err := s.groupFromID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.ListNodes(ctx, owner, name)
	if err != nil {
		return nil, storeErr(err)
	}
	resp := &capb.NodeGroupNodesResponse{}
	for _, n := range rows {
		if n.Group != g.Name {
			continue
		}
		st := capb.InstanceStatus_instanceRunning
		switch n.State {
		case clusterstore.NodeStateProvisioning:
			st = capb.InstanceStatus_instanceCreating
		case clusterstore.NodeStateDraining:
			st = capb.InstanceStatus_instanceDeleting
		}
		resp.Instances = append(resp.Instances, &capb.Instance{
			Id:     providerIDPrefix + n.VMName,
			Status: &capb.InstanceStatus{InstanceState: st},
		})
	}
	return resp, nil
}

// NodeGroupTemplateNodeInfo answers scale-from-zero fit simulation: a
// synthetic Node whose capacity is the group's typed size. Its
// truthfulness is the contract the whole size-class design leans on —
// the template MUST equal the size the reconciler will provision.
func (s *CAProviderServer) NodeGroupTemplateNodeInfo(ctx context.Context, req *capb.NodeGroupTemplateNodeInfoRequest) (*capb.NodeGroupTemplateNodeInfoResponse, error) {
	owner, name, g, _, err := s.groupFromID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	rl := sizeToResourceList(g.Size)
	templateName := clustercore.WorkerName(owner, name, g.Name, 0) // synthetic index
	node := &corev1.Node{
		Metadata: &metav1.ObjectMeta{
			Name: proto.String(templateName),
			Labels: map[string]string{
				"kubernetes.io/os":       "linux",
				"kubernetes.io/arch":     "amd64",
				"kubernetes.io/hostname": templateName,
			},
		},
		Status: &corev1.NodeStatus{
			Capacity:    rl,
			Allocatable: rl,
			Conditions: []*corev1.NodeCondition{{
				Type: proto.String("Ready"), Status: proto.String("True"),
			}},
		},
	}
	return &capb.NodeGroupTemplateNodeInfoResponse{NodeInfo: node}, nil
}

// sizeToResourceList converts the house size format into k8s quantity
// strings ("2" cpu; "4GB" memory → "4G" — k8s has no "GB" suffix).
// Quantities travel as strings on the wire; the CA parses them.
func sizeToResourceList(s clusterstore.Size) map[string]*resourcepb.Quantity {
	q := func(v string) *resourcepb.Quantity { return &resourcepb.Quantity{String_: proto.String(v)} }
	return map[string]*resourcepb.Quantity{
		"cpu":    q(s.CPU),
		"memory": q(strings.TrimSuffix(s.Memory, "B")),
		"pods":   q(strconv.Itoa(110)),
	}
}

// --- trivia the contract requires --------------------------------------

func (s *CAProviderServer) GPULabel(ctx context.Context, _ *capb.GPULabelRequest) (*capb.GPULabelResponse, error) {
	if _, _, err := s.caIdentity(ctx); err != nil {
		return nil, err
	}
	// GPU node pools are a later phase; the label is reserved now so
	// the contract doesn't change when they land.
	return &capb.GPULabelResponse{Label: "containarium.io/gpu"}, nil
}

func (s *CAProviderServer) GetAvailableGPUTypes(ctx context.Context, _ *capb.GetAvailableGPUTypesRequest) (*capb.GetAvailableGPUTypesResponse, error) {
	if _, _, err := s.caIdentity(ctx); err != nil {
		return nil, err
	}
	return &capb.GetAvailableGPUTypesResponse{}, nil
}

func (s *CAProviderServer) Cleanup(ctx context.Context, _ *capb.CleanupRequest) (*capb.CleanupResponse, error) {
	if _, _, err := s.caIdentity(ctx); err != nil {
		return nil, err
	}
	return &capb.CleanupResponse{}, nil
}

func (s *CAProviderServer) Refresh(ctx context.Context, _ *capb.RefreshRequest) (*capb.RefreshResponse, error) {
	if _, _, err := s.caIdentity(ctx); err != nil {
		return nil, err
	}
	return &capb.RefreshResponse{}, nil
}

// Pricing is deliberately unimplemented: CA treats it as "no pricing
// model" and falls back to its default expander behavior.
func (s *CAProviderServer) PricingNodePrice(ctx context.Context, _ *capb.PricingNodePriceRequest) (*capb.PricingNodePriceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "no pricing model")
}

func (s *CAProviderServer) PricingPodPrice(ctx context.Context, _ *capb.PricingPodPriceRequest) (*capb.PricingPodPriceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "no pricing model")
}

func (s *CAProviderServer) NodeGroupGetOptions(ctx context.Context, req *capb.NodeGroupAutoscalingOptionsRequest) (*capb.NodeGroupAutoscalingOptionsResponse, error) {
	if _, _, _, _, err := s.groupFromID(ctx, req.Id); err != nil {
		return nil, err
	}
	// Defaults are fine for v1; per-group tuning is a later phase.
	return &capb.NodeGroupAutoscalingOptionsResponse{NodeGroupAutoscalingOptions: req.Defaults}, nil
}
