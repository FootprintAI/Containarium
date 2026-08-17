// Package cluster provisions and reconciles managed-Kubernetes-cluster
// VMs (#1414): a platform-owned k3s control-plane VM plus worker VMs in
// typed size classes, driven over the Incus API.
//
// Design: docs/architecture/managed-k8s-clusters.md. The package is
// deliberately split along testability seams: naming/labels (this
// file), artifact pins (artifacts.go), bootstrap renderers
// (bootstrap.go), and the reconcile decision function (reconcile.go)
// are pure; only manager.go touches a host, and it does so through the
// narrow VMHost interface so orchestration is unit-testable against a
// fake. Persistence stays behind internal/cluster's Store — this
// package never talks to Postgres.
package cluster

import "fmt"

// VM-name scheme. The "-k8s-" infix marks cluster VMs apart from
// tenant boxes ("<tenant>-container"); cluster and group names are
// validated DNS labels (internal/cluster.ValidateName) so the scheme
// stays inside Incus's 63-char instance-name limit.
const nameInfix = "-k8s-"

// CPName is the control-plane VM's name.
func CPName(tenant, clusterName string) string {
	return tenant + nameInfix + clusterName + "-cp"
}

// WorkerName is the n-th worker VM's name in a node group (1-based).
func WorkerName(tenant, clusterName, group string, n int) string {
	return fmt.Sprintf("%s%s%s-%s-%d", tenant, nameInfix, clusterName, group, n)
}

// Incus config labels stamped on every cluster VM, so the operator can
// answer "what is this VM and why does it exist" and the capacity
// policy can exclude cluster nodes by workload class.
const (
	LabelCluster       = "user.containarium.cluster"
	LabelClusterOwner  = "user.containarium.cluster_owner"
	LabelClusterRole   = "user.containarium.cluster_role"
	LabelNodeGroup     = "user.containarium.node_group"
	LabelWorkloadClass = "user.containarium.workload_class"

	RoleControlPlane = "control-plane"
	RoleWorker       = "worker"

	WorkloadClassK8sNode = "k8s-node"
)

// VMLabels builds the label set for one cluster VM. group is empty for
// the control plane.
func VMLabels(tenant, clusterName, role, group string) map[string]string {
	l := map[string]string{
		LabelCluster:       clusterName,
		LabelClusterOwner:  tenant,
		LabelClusterRole:   role,
		LabelWorkloadClass: WorkloadClassK8sNode,
	}
	if group != "" {
		l[LabelNodeGroup] = group
	}
	return l
}

// NodeSpec is everything the host needs to create one cluster VM.
type NodeSpec struct {
	Name   string
	CPU    string // e.g. "2"
	Memory string // e.g. "4GB"
	Disk   string // e.g. "40GB"
	Labels map[string]string
}
