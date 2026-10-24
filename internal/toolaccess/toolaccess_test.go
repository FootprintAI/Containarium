package toolaccess

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestRoundTrip(t *testing.T) {
	for _, a := range []pb.BoxToolAccess{
		pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE,
		pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS,
		pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO,
	} {
		v, ok := ConfigValue(a)
		if !ok || v == "" {
			t.Fatalf("%v has no config value", a)
		}
		if got := FromConfig(v); got != a {
			t.Errorf("%v -> %q -> %v", a, v, got)
		}
	}
}

func TestUnspecifiedAndUnknownAreNotLevels(t *testing.T) {
	if _, ok := ConfigValue(pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED); ok {
		t.Error("UNSPECIFIED must not have a config value (it clears the key)")
	}
	if _, ok := ConfigValue(pb.BoxToolAccess(99)); ok {
		t.Error("an unknown enum value must not have a config value")
	}
	for _, v := range []string{"", "root", "FULL_SUDO", "full-sudo", " none", "install_packages"} {
		if got := FromConfig(v); got != pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED {
			t.Errorf("FromConfig(%q) = %v, want UNSPECIFIED", v, got)
		}
	}
}
