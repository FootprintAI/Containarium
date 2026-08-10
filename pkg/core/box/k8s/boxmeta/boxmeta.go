// Package boxmeta holds the labels and names that identify a K8s box's
// Kubernetes objects.
//
// It is a leaf package on purpose. The daemon creates box pods (pkg/core/box/k8s)
// and the SSH session collector finds them again (internal/audit), and those two
// cannot import each other — the box backend reaches the gateway, which reaches
// the audit store. Without a shared leaf, the collector would have to restate
// the labels, and a drift between the two copies would show up as the collector
// finding no boxes at all: a backend reporting no logins is indistinguishable
// from one nobody logged into, which is the exact failure #1189 exists to fix.
package boxmeta

const (
	// ManagedByLabel / ManagedByValue mark every object the K8s box backend
	// owns.
	ManagedByLabel = "app.kubernetes.io/managed-by"
	ManagedByValue = "containarium"

	// TenantLabel carries the tenant a box belongs to. Objects the backend
	// owns that are not a tenant's box — the gateway, for one — do not have it.
	TenantLabel = "containarium.dev/tenant"

	// BoxContainerName is the box container inside the pod: the one running
	// dropbear, and so the one whose log carries the session records.
	BoxContainerName = "agent-box"
)
