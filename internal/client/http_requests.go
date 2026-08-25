package client

import pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"

// Request payload types for the REST client.
//
// These replace the `map[string]interface{}` literals that used to be
// built inline. Two reasons, in order of importance:
//
//  1. A map's shape is invisible to the compiler. Renaming a proto field
//     meant grepping for a string key; getting one wrong produced a
//     request the daemon silently ignored or rejected at runtime.
//  2. The maps were what let #887 happen. `doRequest` took
//     `interface{}` because a map is what it was handed; that same
//     signature accepted an already-encoded []byte and base64'd it into a
//     JSON string. With payloads named and `doRequest` taking []byte,
//     neither mistake is expressible.
//
// The JSON tags are the wire contract with grpc-gateway and must match
// the proto field names exactly — some endpoints use camelCase and some
// snake_case, mirroring how each was originally written. They are
// reproduced here verbatim rather than normalised; changing one would
// change the request the daemon receives.
//
// `omitempty` is used only where the previous code conditionally added a
// key. Fields that were always present stay always present, so the bytes
// on the wire are unchanged.

// containerResources is the nested resource block of a create request.
type containerResources struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	Disk   string `json:"disk"`
	// Only sent when a storage class was requested.
	StorageClass string `json:"storageClass,omitempty"`
}

// createContainerRequest is POST /v1/containers.
//
// The git and birth-lifecycle fields are pointers so that "set to empty"
// stays distinguishable from "not set". The previous code added all four
// git keys together whenever a source was given — including empty values
// for the other three — and omitted them entirely otherwise. Pointers
// reproduce that exactly; plain strings with omitempty would not.
type createContainerRequest struct {
	Username     string             `json:"username"`
	Resources    containerResources `json:"resources"`
	SSHKeys      []string           `json:"sshKeys"`
	Image        string             `json:"image"`
	EnablePodman bool               `json:"enablePodman"`
	Stack        string             `json:"stack"`
	GPUs         []string           `json:"gpus"`
	// The generated enum, not a string: json.Marshal emits its numeric
	// value, which is what the previous map sent and what protojson
	// accepts on the server side.
	OSType     pb.OSType `json:"osType"`
	Monitoring bool      `json:"monitoring"`
	Pool       string    `json:"pool"`
	BackendID  string    `json:"backendId"`

	GitSource     *string `json:"gitSource,omitempty"`
	GitRef        *string `json:"gitRef,omitempty"`
	GitCredential *string `json:"gitCredential,omitempty"`
	WorkspacePath *string `json:"workspacePath,omitempty"`

	// Per-tenant dataset encryption (#1198). Absent unless requested, so
	// a plain create's body is unchanged.
	Encrypted bool   `json:"encrypted,omitempty"`
	TenantID  string `json:"tenantId,omitempty"`

	// Birth TTL (#523), idle-stop (#524), stopped→delete (#525): absent
	// unless enabled, so a plain create's body is unchanged.
	TTLSeconds                int64 `json:"ttlSeconds,omitempty"`
	IdleStopMinutes           int32 `json:"idleStopMinutes,omitempty"`
	DeleteAfterStoppedSeconds int64 `json:"deleteAfterStoppedSeconds,omitempty"`
}

// toggleAutoSleepRequest is POST /v1/containers/{name}/autosleep.
type toggleAutoSleepRequest struct {
	Enabled              bool  `json:"enabled"`
	IdleThresholdMinutes int32 `json:"idle_threshold_minutes"`
}

// setContainerTTLRequest is POST /v1/containers/{name}/ttl.
type setContainerTTLRequest struct {
	DurationSeconds int64 `json:"duration_seconds"`
}

// setContainerDeletePolicyRequest is POST /v1/containers/{name}/delete-policy.
type setContainerDeletePolicyRequest struct {
	DeletePolicy string `json:"delete_policy"`
}

// setContainerAttributionRequest is POST /v1/containers/{name}/attribution.
type setContainerAttributionRequest struct {
	Labels map[string]string `json:"labels"`
}

// startContainerRequest is POST /v1/containers/{name}/start.
type startContainerRequest struct {
	WaitForReady        bool  `json:"wait_for_ready"`
	ReadyTimeoutSeconds int32 `json:"ready_timeout_seconds"`
}

// stopContainerRequest is POST /v1/containers/{name}/stop.
type stopContainerRequest struct {
	Force bool `json:"force"`
}

// resizeContainerRequest is PUT /v1/containers/{name}/resize.
//
// One of the three payloads that #887 broke: it was pre-encoded to
// []byte and then re-encoded by doRequest.
type resizeContainerRequest struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	Disk   string `json:"disk"`
}

// toggleMonitoringRequest is POST /v1/containers/{name}/monitoring.
// Also broken by #887.
type toggleMonitoringRequest struct {
	Enabled bool `json:"enabled"`
}

// setSecretRequest is POST /v1/secrets — the payload from the #887
// report. Delivery is omitted when unset so the daemon applies its own
// default rather than being handed an empty string.
type setSecretRequest struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Delivery string `json:"delivery,omitempty"`
}

// setMetricsExportRequest is POST /v1/system/metrics-export.
type setMetricsExportRequest struct {
	Enabled bool `json:"enabled"`
	// The enum's proto JSON name, so grpc-gateway decodes it into
	// CloudMetricsProvider.
	Provider string `json:"provider"`
	// Groups by their proto JSON names, for the repeated
	// CloudMetricsGroup enum (#1081). Omitted when empty so a host-only
	// call stays byte-identical to the pre-groups request and lets the
	// server apply its host default.
	Groups []string `json:"groups,omitempty"`
}

// refreshTokenRequest is POST /v1/tokens/refresh.
//
// The credential in the body is the entire point of this endpoint: the
// caller trades a refresh token for a new access token, so the token has
// to be marshalled and sent. gosec flags any marshalled field whose name
// looks like a secret, which is a useful default and a false positive
// here.
//
// Naming it something bland to dodge the rule would be worse: the field
// really does carry a credential, and a reader should see that. Note it
// is only ever sent over the client's HTTPS transport, and never logged —
// doRequest logs the path, not the body.
type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// revokeTokenRequest is POST /v1/tokens/revoke.
type revokeTokenRequest struct {
	JTI string `json:"jti"`
	// Both optional: the previous code added these keys only when
	// non-empty, letting the daemon default them.
	Reason    string `json:"reason,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// startEgressProxyRequest is POST /v1/network/egress-proxy (#808).
type startEgressProxyRequest struct {
	ContainerName string `json:"containerName"`
	UpstreamPort  int32  `json:"upstreamPort"`
	ProxyPort     int32  `json:"proxyPort"`
}

// installStackRequest is the stack-install payload. Note the camelCase
// key — preserved from the original map.
type installStackRequest struct {
	StackID string `json:"stackId"`
}

// setLabelsRequest is PUT /v1/containers/{name}/labels.
type setLabelsRequest struct {
	Labels map[string]string `json:"labels"`
}

// deployRecipeRequest is POST /v1/recipes/deploy.
type deployRecipeRequest struct {
	RecipeID   string            `json:"recipe_id"`
	Name       string            `json:"name"`
	GPU        string            `json:"gpu"`
	BackendID  string            `json:"backend_id"`
	Pool       string            `json:"pool"`
	Parameters map[string]string `json:"parameters"`
}

// runAgentSkillRequest is POST /v1/agent-skills/run.
type runAgentSkillRequest struct {
	SkillID   string `json:"skill_id"`
	BackendID string `json:"backend_id"`
	Pool      string `json:"pool"`
	InputJSON string `json:"input_json"`
}

// enqueueAgentTaskRequest is POST /v1/agent-tasks.
type enqueueAgentTaskRequest struct {
	SkillID   string `json:"skill_id"`
	InputJSON string `json:"input_json"`
}

// startAgentWorkerRequest starts a long-lived agent worker.
type startAgentWorkerRequest struct {
	SkillID   string `json:"skill_id"`
	BackendID string `json:"backend_id"`
	Pool      string `json:"pool"`
	WorkerID  string `json:"worker_id"`
}

// sendAgentTaskRequest is agent-to-agent dispatch.
type sendAgentTaskRequest struct {
	FromSkillID string `json:"from_skill_id"`
	ToPeerID    string `json:"to_peer_id"`
	InputJSON   string `json:"input_json"`
}

// runCrewRequest is POST /v1/crews/run.
type runCrewRequest struct {
	CrewID    string `json:"crew_id"`
	BackendID string `json:"backend_id"`
	Pool      string `json:"pool"`
	InputJSON string `json:"input_json"`
}

// addRouteRequest is POST /v1/network/routes.
type addRouteRequest struct {
	Domain        string `json:"domain"`
	TargetIP      string `json:"target_ip"`
	TargetPort    int32  `json:"target_port"`
	ContainerName string `json:"container_name"`
	Description   string `json:"description"`
}

// addPassthroughRouteRequest is POST /v1/network/passthrough.
type addPassthroughRouteRequest struct {
	ExternalPort  int32            `json:"external_port"`
	TargetIP      string           `json:"target_ip"`
	TargetPort    int32            `json:"target_port"`
	Protocol      pb.RouteProtocol `json:"protocol"`
	ContainerName string           `json:"container_name"`
	Description   string           `json:"description"`
}
