package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/box"
)

// TestToProtoContainer_StackAndPodman (#2163): Stack is read from BoxStatus
// (empty when none is recorded, e.g. K8s or pre-existing boxes).
func TestToProtoContainer_StackAndPodman(t *testing.T) {
	withStack := toProtoContainer(&box.BoxStatus{Ref: box.BoxRef{Name: "a-container"}, Stack: "nodejs"})
	if withStack.Stack != "nodejs" {
		t.Errorf("Stack = %q, want nodejs", withStack.Stack)
	}
	without := toProtoContainer(&box.BoxStatus{Ref: box.BoxRef{Name: "b-container"}})
	if without.Stack != "" {
		t.Errorf("Stack = %q, want empty", without.Stack)
	}
}

// TestToProtoContainer_PodmanEnabledFollowsStatus (#2858): PodmanEnabled is
// what the backend read back, not a constant.
func TestToProtoContainer_PodmanEnabledFollowsStatus(t *testing.T) {
	for _, want := range []bool{true, false} {
		got := toProtoContainer(&box.BoxStatus{Ref: box.BoxRef{Name: "a-container"}, PodmanEnabled: want})
		if got.PodmanEnabled != want {
			t.Errorf("PodmanEnabled = %v, want %v", got.PodmanEnabled, want)
		}
	}
}
