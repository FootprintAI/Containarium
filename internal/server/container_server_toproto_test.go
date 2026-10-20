package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/box"
)

// TestToProtoContainer_StackAndPodman (#2163): Stack is read from BoxStatus
// (empty when none is recorded, e.g. K8s or pre-existing boxes); PodmanEnabled
// stays true because podman ships in every box image.
func TestToProtoContainer_StackAndPodman(t *testing.T) {
	withStack := toProtoContainer(&box.BoxStatus{Ref: box.BoxRef{Name: "a-container"}, Stack: "nodejs"})
	if withStack.Stack != "nodejs" {
		t.Errorf("Stack = %q, want nodejs", withStack.Stack)
	}
	without := toProtoContainer(&box.BoxStatus{Ref: box.BoxRef{Name: "b-container"}})
	if without.Stack != "" {
		t.Errorf("Stack = %q, want empty", without.Stack)
	}
	if !withStack.PodmanEnabled || !without.PodmanEnabled {
		t.Error("PodmanEnabled must be true for every box")
	}
}
