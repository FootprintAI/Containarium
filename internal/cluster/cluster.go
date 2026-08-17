// Package cluster holds the record types, validation, and persistence for
// managed Kubernetes clusters (#1413) — a platform-operated k3s control
// plane plus worker VMs in typed size classes.
//
// Design: docs/architecture/managed-k8s-clusters.md. This package owns the
// store-shaped state; VM provisioning and reconciliation live in
// pkg/core/cluster (#1414) and only communicate with this package through
// the Store interface.
package cluster

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var (
	// ErrNotFound is returned when a cluster (or node) does not exist.
	ErrNotFound = errors.New("cluster not found")
	// ErrAlreadyExists is returned when creating a cluster whose
	// (owner, name) is already taken.
	ErrAlreadyExists = errors.New("cluster already exists")
)

// State is a cluster's lifecycle state. Mirrors pb.ClusterState; the
// string form is what the store persists.
type State string

const (
	StateProvisioning State = "provisioning"
	StateReady        State = "ready"
	StateDegraded     State = "degraded"
	StateDeleting     State = "deleting"
	StateError        State = "error"
)

// EventKind categorizes scale-history entries. Mirrors pb.ScaleEventKind.
type EventKind string

const (
	EventScaleUp      EventKind = "scale_up"
	EventScaleDown    EventKind = "scale_down"
	EventRefused      EventKind = "refused"
	EventNodeReplaced EventKind = "node_replaced"
)

// Node roles as persisted on node rows.
const (
	RoleControlPlane = "control-plane"
	RoleWorker       = "worker"
)

// Size is a node VM size in the house resource-limit format
// (cpu "4", memory "8GB", disk "80GB"). GPU fields are deliberately
// absent: GPU node pools are a later phase and requests carrying them
// are rejected at the API boundary.
type Size struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	Disk   string `json:"disk"`
}

// NodeGroup is a typed worker size class with autoscale bounds.
type NodeGroup struct {
	Name     string `json:"name"`
	Size     Size   `json:"size"`
	MinNodes int32  `json:"min_nodes"`
	MaxNodes int32  `json:"max_nodes"`
}

// Cluster is the persisted record of a managed cluster.
type Cluster struct {
	ID          string
	Owner       string
	Name        string
	State       State
	StateReason string
	K3sVersion  string
	APIEndpoint string
	NodeGroups  []NodeGroup
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Node is one VM belonging to a cluster.
type Node struct {
	Owner     string
	Cluster   string
	VMName    string
	Role      string
	Group     string
	State     string
	CreatedAt time.Time
}

// Event is one entry in a cluster's scale history.
type Event struct {
	At     time.Time
	Kind   EventKind
	Group  string
	Reason string
}

// DefaultNodeGroups are the platform's preset size classes. The
// autoscaler advertises one node group per class and picks the class
// whose template fits pending pods; presets exist so `cluster create`
// works with no size flags at all.
func DefaultNodeGroups() []NodeGroup {
	return []NodeGroup{
		{Name: "small", Size: Size{CPU: "2", Memory: "4GB", Disk: "40GB"}, MinNodes: 1, MaxNodes: 3},
		{Name: "medium", Size: Size{CPU: "4", Memory: "8GB", Disk: "80GB"}, MinNodes: 0, MaxNodes: 2},
		{Name: "large", Size: Size{CPU: "8", Memory: "16GB", Disk: "160GB"}, MinNodes: 0, MaxNodes: 1},
	}
}

// nameRE is DNS-label syntax capped at 20 chars: the VM naming scheme
// `<tenant>-k8s-<cluster>-<group>-<n>` has to stay inside Incus's
// 63-char instance-name limit with room for the tenant's own name.
var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,18}[a-z0-9])?$`)

// sizeRE matches the house memory/disk format ("4GB", "512MB", "1TB").
var sizeRE = regexp.MustCompile(`^[1-9][0-9]*(MB|GB|TB)$`)

// ValidateName checks cluster (and group) name syntax.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid name %q: must be a lowercase DNS label of at most 20 characters", name)
	}
	return nil
}

// ValidateNodeGroups checks a replacement set of node groups: at least
// one group, unique label-valid names, positive integer CPU, parseable
// memory/disk, 0 <= min <= max per group, and at least one schedulable
// node across the pool (sum of max >= 1).
func ValidateNodeGroups(groups []NodeGroup) error {
	if len(groups) == 0 {
		return errors.New("at least one node group is required")
	}
	seen := make(map[string]bool, len(groups))
	var totalMax int64
	for _, g := range groups {
		if err := ValidateName(g.Name); err != nil {
			return fmt.Errorf("node group: %w", err)
		}
		if seen[g.Name] {
			return fmt.Errorf("duplicate node group name %q", g.Name)
		}
		seen[g.Name] = true
		if cpu, err := strconv.Atoi(g.Size.CPU); err != nil || cpu <= 0 {
			return fmt.Errorf("node group %q: cpu must be a positive integer, got %q", g.Name, g.Size.CPU)
		}
		if !sizeRE.MatchString(g.Size.Memory) {
			return fmt.Errorf("node group %q: memory must look like \"8GB\", got %q", g.Name, g.Size.Memory)
		}
		if !sizeRE.MatchString(g.Size.Disk) {
			return fmt.Errorf("node group %q: disk must look like \"80GB\", got %q", g.Name, g.Size.Disk)
		}
		if g.MinNodes < 0 {
			return fmt.Errorf("node group %q: min_nodes must be >= 0, got %d", g.Name, g.MinNodes)
		}
		if g.MaxNodes < g.MinNodes {
			return fmt.Errorf("node group %q: max_nodes (%d) must be >= min_nodes (%d)", g.Name, g.MaxNodes, g.MinNodes)
		}
		totalMax += int64(g.MaxNodes)
	}
	if totalMax < 1 {
		return errors.New("node pool must allow at least one node (sum of max_nodes >= 1)")
	}
	return nil
}
