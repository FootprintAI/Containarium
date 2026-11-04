package runlease

import (
	"reflect"
	"testing"
)

func TestRegistryLiveInBox(t *testing.T) {
	r := NewRegistry()
	if got := r.LiveInBox("alice-container"); len(got) != 0 {
		t.Fatalf("empty registry: %v", got)
	}
	r.Register("run-b", Info{SkillID: "s", Box: "alice-container"})
	r.Register("run-a", Info{SkillID: "s", Box: "alice-container"})
	r.Register("run-x", Info{SkillID: "s", Box: "agent-x-container"})
	if got := r.LiveInBox("alice-container"); !reflect.DeepEqual(got, []string{"run-a", "run-b"}) {
		t.Errorf("LiveInBox = %v, want [run-a run-b] (sorted, this box only)", got)
	}
	if got := r.LiveInBox("bob-container"); len(got) != 0 {
		t.Errorf("another box: %v", got)
	}
	r.Unregister("run-a")
	r.Unregister("run-b")
	if got := r.LiveInBox("alice-container"); len(got) != 0 {
		t.Errorf("after lease end: %v", got)
	}
}
