package k8s

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #1186: stateOf used to return STOPPED as soon as spec.operatingMode was set
// to Suspended — a *requested* state reported as an *observed* one. A caller
// polling for shutdown would see STOPPED while the pod was still terminating.
//
// agent-sandbox >= 0.5.4 always sets the Suspended condition after the first
// reconcile, so the observation is available. These tests pin both the new
// behavior and the pre-0.5.4 fallback, since bumping the Go module upgrades the
// API types but not the controller in an operator's cluster.

func sandboxWith(mode sandboxv1beta1.SandboxOperatingMode, conds ...metav1.Condition) *sandboxv1beta1.Sandbox {
	sb := &sandboxv1beta1.Sandbox{}
	sb.Spec.OperatingMode = mode
	sb.Status.Conditions = conds
	return sb
}

func cond(t string, s metav1.ConditionStatus, reason string) metav1.Condition {
	return metav1.Condition{Type: t, Status: s, Reason: reason}
}

const (
	condSuspended = string(sandboxv1beta1.SandboxConditionSuspended)
	condReady     = string(sandboxv1beta1.SandboxConditionReady)
	condFinished  = string(sandboxv1beta1.SandboxConditionFinished)
)

func TestStateOf(t *testing.T) {
	tests := []struct {
		name string
		sb   *sandboxv1beta1.Sandbox
		want pb.ContainerState
	}{
		{
			// The bug: suspend requested, pod still terminating. Must NOT be STOPPED.
			name: "suspend requested but pod still terminating reports RUNNING",
			sb: sandboxWith(sandboxv1beta1.SandboxOperatingModeSuspended,
				cond(condSuspended, metav1.ConditionFalse, sandboxv1beta1.SandboxReasonSuspendedPodTerminating)),
			want: pb.ContainerState_CONTAINER_STATE_RUNNING,
		},
		{
			name: "suspend observed complete reports STOPPED",
			sb: sandboxWith(sandboxv1beta1.SandboxOperatingModeSuspended,
				cond(condSuspended, metav1.ConditionTrue, sandboxv1beta1.SandboxReasonSuspendedPodTerminated)),
			want: pb.ContainerState_CONTAINER_STATE_STOPPED,
		},
		{
			// Pre-0.5.4 controller: no Suspended condition at all.
			name: "no Suspended condition falls back to desired state (0.5.3 controller)",
			sb:   sandboxWith(sandboxv1beta1.SandboxOperatingModeSuspended),
			want: pb.ContainerState_CONTAINER_STATE_STOPPED,
		},
		{
			// Reconcile failed — no usable observation, so trust the request.
			name: "Unknown Suspended condition falls back to desired state",
			sb: sandboxWith(sandboxv1beta1.SandboxOperatingModeSuspended,
				cond(condSuspended, metav1.ConditionUnknown, sandboxv1beta1.SandboxReasonSuspendedPodStateUnknown)),
			want: pb.ContainerState_CONTAINER_STATE_STOPPED,
		},
		{
			name: "running and ready reports RUNNING",
			sb: sandboxWith(sandboxv1beta1.SandboxOperatingModeRunning,
				cond(condSuspended, metav1.ConditionFalse, sandboxv1beta1.SandboxReasonNotSuspended),
				cond(condReady, metav1.ConditionTrue, "Ready")),
			want: pb.ContainerState_CONTAINER_STATE_RUNNING,
		},
		{
			name: "running but not yet ready reports PROVISIONING",
			sb: sandboxWith(sandboxv1beta1.SandboxOperatingModeRunning,
				cond(condSuspended, metav1.ConditionFalse, sandboxv1beta1.SandboxReasonNotSuspended),
				cond(condReady, metav1.ConditionFalse, "PodNotReady")),
			want: pb.ContainerState_CONTAINER_STATE_PROVISIONING,
		},
		{
			// Finished must still win for a running-mode box whose pod died.
			name: "finished pod reports STOPPED even in Running mode",
			sb: sandboxWith(sandboxv1beta1.SandboxOperatingModeRunning,
				cond(condSuspended, metav1.ConditionFalse, sandboxv1beta1.SandboxReasonNotSuspended),
				cond(condFinished, metav1.ConditionTrue, "PodSucceeded")),
			want: pb.ContainerState_CONTAINER_STATE_STOPPED,
		},
		{
			name: "freshly created sandbox with no conditions reports PROVISIONING",
			sb:   sandboxWith(sandboxv1beta1.SandboxOperatingModeRunning),
			want: pb.ContainerState_CONTAINER_STATE_PROVISIONING,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := stateOf(tc.sb); got != tc.want {
				t.Errorf("stateOf() = %v, want %v", got, tc.want)
			}
		})
	}
}
