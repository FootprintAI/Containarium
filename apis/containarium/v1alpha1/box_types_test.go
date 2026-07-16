package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAddToScheme(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	for _, kind := range []string{"Box", "BoxList"} {
		if !s.Recognizes(GroupVersion.WithKind(kind)) {
			t.Errorf("scheme does not recognize %s", kind)
		}
	}
}

// TestBoxDeepCopy checks the hand-written deepcopy actually deep-copies every
// nested slice/map/pointer — a shallow copy would let a mutation to the copy
// leak back into the original.
func TestBoxDeepCopy(t *testing.T) {
	auto := true
	ttl := int64(3600)
	in := &Box{
		ObjectMeta: metav1.ObjectMeta{Name: "alice"},
		Spec: BoxSpec{
			Tenant:      "alice",
			Mode:        "shell",
			SSHKeys:     []string{"ssh-ed25519 AAA"},
			Resources:   BoxResources{CPU: "2", Memory: "4GB"},
			StackParams: map[string]string{"k": "v"},
			Labels:      map[string]string{"team": "dev"},
			AutoStart:   &auto,
			TTLSeconds:  &ttl,
		},
		Status: BoxStatus{
			Phase:      BoxRunning,
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
		},
	}
	out := in.DeepCopy()

	// Mutate every nested field on the copy; the original must be untouched.
	out.Spec.SSHKeys[0] = "changed"
	out.Spec.Labels["team"] = "changed"
	out.Spec.StackParams["k"] = "changed"
	*out.Spec.AutoStart = false
	*out.Spec.TTLSeconds = 0
	out.Status.Conditions[0].Type = "changed"

	if in.Spec.SSHKeys[0] != "ssh-ed25519 AAA" {
		t.Error("SSHKeys was not deep-copied")
	}
	if in.Spec.Labels["team"] != "dev" {
		t.Error("Labels was not deep-copied")
	}
	if in.Spec.StackParams["k"] != "v" {
		t.Error("StackParams was not deep-copied")
	}
	if !*in.Spec.AutoStart {
		t.Error("AutoStart pointer was not deep-copied")
	}
	if *in.Spec.TTLSeconds != 3600 {
		t.Error("TTLSeconds pointer was not deep-copied")
	}
	if in.Status.Conditions[0].Type != "Ready" {
		t.Error("Conditions was not deep-copied")
	}
	if _, ok := in.DeepCopyObject().(*Box); !ok {
		t.Error("DeepCopyObject did not return *Box")
	}
}
