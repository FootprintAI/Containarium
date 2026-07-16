package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BoxPhase is a high-level summary of a box's lifecycle, surfaced in
// Box.status.phase.
type BoxPhase string

const (
	// BoxPending — the Box has been accepted but its pod is not yet running.
	BoxPending BoxPhase = "Pending"
	// BoxRunning — the box pod is running and reachable.
	BoxRunning BoxPhase = "Running"
	// BoxSuspended — the box is parked (no pod) but its data is retained.
	BoxSuspended BoxPhase = "Suspended"
	// BoxTerminating — the Box is being deleted; its resources are being torn down.
	BoxTerminating BoxPhase = "Terminating"
	// BoxFailed — reconciliation could not realize the box.
	BoxFailed BoxPhase = "Failed"
)

// BoxResources is the requested CPU/memory/disk for a box. Values are
// substrate-native strings (e.g. "2", "4GB", "20GB"); empty fields take the
// daemon's defaults.
type BoxResources struct {
	// CPU request (e.g. "2").
	// +optional
	CPU string `json:"cpu,omitempty"`
	// Memory request (e.g. "4GB").
	// +optional
	Memory string `json:"memory,omitempty"`
	// Disk size for the box's workspace (e.g. "20GB").
	// +optional
	Disk string `json:"disk,omitempty"`
	// StorageClass for the box's workspace PVC. Empty = the daemon default.
	// +optional
	StorageClass string `json:"storageClass,omitempty"`
}

// BoxSpec is the declarative description of a box. The daemon's Box controller
// reconciles it into the per-tenant bundle (agent-sandbox Sandbox + gateway
// Pipe + authorized-keys Secret + NetworkPolicy).
type BoxSpec struct {
	// Tenant is the routing key / SSH username the gateway routes by. Empty
	// defaults to the Box's metadata.name.
	// +optional
	Tenant string `json:"tenant,omitempty"`

	// Image is the agent-box image to run. Empty uses the daemon's configured
	// default (CONTAINARIUM_K8S_BOX_IMAGE).
	// +optional
	Image string `json:"image,omitempty"`

	// Mode selects the box's SSH session behavior: "mcp" (default) pins every
	// session to the forced-command MCP server; "shell" gives an interactive
	// login shell (developer-box).
	// +kubebuilder:validation:Enum=mcp;shell
	// +optional
	Mode string `json:"mode,omitempty"`

	// SSHKeys are the authorized public keys for this box's tenant (the keys the
	// gateway authenticates the client against).
	// +optional
	SSHKeys []string `json:"sshKeys,omitempty"`

	// Resources requests CPU/memory/disk for the box.
	// +optional
	Resources BoxResources `json:"resources,omitempty"`

	// Stack is an optional provisioning stack baked into the box (e.g. "nodejs").
	// +optional
	Stack string `json:"stack,omitempty"`
	// StackParams are stack-specific parameters.
	// +optional
	StackParams map[string]string `json:"stackParams,omitempty"`

	// GitSource, when set, is fetched into WorkspacePath at create time.
	// +optional
	GitSource string `json:"gitSource,omitempty"`
	// GitRef is the branch/tag/commit to check out (default branch when empty).
	// +optional
	GitRef string `json:"gitRef,omitempty"`
	// WorkspacePath is where GitSource is checked out inside the box.
	// +optional
	WorkspacePath string `json:"workspacePath,omitempty"`

	// Labels are extra labels applied to the box.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// AutoStart runs the box immediately. Defaults to true; set false to create
	// the box suspended (no pod) until started.
	// +optional
	AutoStart *bool `json:"autoStart,omitempty"`

	// TTLSeconds, when set, expires the box that many seconds after creation.
	// +optional
	// +kubebuilder:validation:Minimum=0
	TTLSeconds *int64 `json:"ttlSeconds,omitempty"`
}

// BoxStatus is the observed state of a Box.
type BoxStatus struct {
	// Phase is a high-level lifecycle summary.
	// +optional
	Phase BoxPhase `json:"phase,omitempty"`

	// PodName is the box pod once the Sandbox controller creates it.
	// +optional
	PodName string `json:"podName,omitempty"`

	// Endpoint is the SSH connect target for the box (<tenant>@<gateway>).
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// ObservedGeneration is the .metadata.generation the status reflects.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions is the standard condition set (e.g. Ready).
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=box
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.spec.tenant`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.endpoint`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Box is a Containarium agent-box on Kubernetes: the daemon reconciles it into
// an agent-sandbox Sandbox plus the gateway routing (Pipe), authorized-keys
// Secret, and NetworkPolicy that make it SSH-reachable and MCP-native.
type Box struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BoxSpec   `json:"spec,omitempty"`
	Status BoxStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BoxList is a list of Box resources.
type BoxList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Box `json:"items"`
}
