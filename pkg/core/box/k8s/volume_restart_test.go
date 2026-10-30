//go:build k8s

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	sandboxfake "sigs.k8s.io/agent-sandbox/clients/k8s/clientset/versioned/fake"
)

func volumeRestartSandbox() *sandboxv1beta1.Sandbox {
	return &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "tenant-test", UID: "worker-id", Generation: 5},
		Spec:       sandboxv1beta1.SandboxSpec{OperatingMode: sandboxv1beta1.SandboxOperatingModeRunning},
	}
}

func volumeRestartClient(t *testing.T, sb *sandboxv1beta1.Sandbox) *sandboxfake.Clientset {
	t.Helper()
	sc := sandboxfake.NewSimpleClientset()
	if _, err := sc.AgentsV1beta1().Sandboxes(sb.Namespace).Create(context.Background(), sb, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestVolumeRestartWaitsForCurrentSuspension(t *testing.T) {
	sb := volumeRestartSandbox()
	b, _, _ := testBackend()
	sc := volumeRestartClient(t, sb)
	b.sandboxes = sc
	observations := 0
	resumed := false
	sc.PrependReactor("get", "sandboxes", func(action clienttesting.Action) (bool, runtime.Object, error) {
		current, err := sc.Tracker().Get(sandboxv1beta1.SchemeGroupVersion.WithResource("sandboxes"), sb.Namespace, sb.Name)
		if err != nil {
			return true, nil, err
		}
		got := current.(*sandboxv1beta1.Sandbox).DeepCopy()
		if got.Spec.OperatingMode != sandboxv1beta1.SandboxOperatingModeSuspended {
			t.Error("polled before requesting suspension")
		}
		observations++
		condition := metav1.Condition{Type: string(sandboxv1beta1.SandboxConditionSuspended), Status: metav1.ConditionTrue, ObservedGeneration: got.Generation}
		switch observations {
		case 1:
			condition.ObservedGeneration-- // A stale True must not resume the box.
		case 2:
			condition.Status = metav1.ConditionFalse // Pod is still terminating.
		}
		got.Status.Conditions = []metav1.Condition{condition}
		return true, got, nil
	})
	sc.PrependReactor("patch", "sandboxes", func(action clienttesting.Action) (bool, runtime.Object, error) {
		var patch struct {
			Spec struct {
				OperatingMode sandboxv1beta1.SandboxOperatingMode `json:"operatingMode"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(action.(clienttesting.PatchAction).GetPatch(), &patch); err != nil {
			t.Fatal(err)
		}
		if patch.Spec.OperatingMode == sandboxv1beta1.SandboxOperatingModeRunning {
			resumed = true
			if observations < 3 {
				t.Error("resumed before the current suspension was observed")
			}
		}
		return false, nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := b.restartSandboxForVolumeChange(ctx, "test", sb); err != nil {
		t.Fatal(err)
	}
	if !resumed || observations != 3 {
		t.Fatalf("resumed=%t observations=%d; want resume after three observations", resumed, observations)
	}
}

func TestVolumeRestartDoesNotResumeAfterWaitFailure(t *testing.T) {
	readErr := errors.New("sandbox read failed")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "API failure", err: readErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := volumeRestartSandbox()
			b, _, _ := testBackend()
			sc := volumeRestartClient(t, sb)
			b.sandboxes = sc
			if tc.err == readErr {
				sc.PrependReactor("get", "sandboxes", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, readErr
				})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			err := b.restartSandboxForVolumeChange(ctx, "test", sb)
			if !errors.Is(err, tc.err) {
				t.Fatalf("error=%v; want %v", err, tc.err)
			}
			current, err := sc.Tracker().Get(sandboxv1beta1.SchemeGroupVersion.WithResource("sandboxes"), sb.Namespace, sb.Name)
			if err != nil {
				t.Fatal(err)
			}
			if current.(*sandboxv1beta1.Sandbox).Spec.OperatingMode != sandboxv1beta1.SandboxOperatingModeSuspended {
				t.Fatal("resumed even though suspension was not confirmed")
			}
		})
	}
}

func TestVolumeChangeKeepsStoppedSandboxStopped(t *testing.T) {
	sb := volumeRestartSandbox()
	sb.Spec.OperatingMode = sandboxv1beta1.SandboxOperatingModeSuspended
	b, _, sc := testBackend()
	if err := b.restartSandboxForVolumeChange(context.Background(), "test", sb); err != nil {
		t.Fatal(err)
	}
	if len(sc.Actions()) != 0 {
		t.Fatal("volume change mutated a stopped Sandbox")
	}
}
