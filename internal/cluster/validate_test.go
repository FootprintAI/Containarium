package cluster

import (
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		ok    bool
	}{
		{"simple", "demo", true},
		{"single char", "a", true},
		{"hyphenated", "web-1", true},
		{"max length 20", strings.Repeat("a", 20), true},
		{"empty", "", false},
		{"too long 21", strings.Repeat("a", 21), false},
		{"leading hyphen", "-a", false},
		{"trailing hyphen", "a-", false},
		{"uppercase", "Demo", false},
		{"underscore", "a_b", false},
		{"dot", "a.b", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateName(tc.input)
			if tc.ok && err != nil {
				t.Fatalf("ValidateName(%q) = %v, want nil", tc.input, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("ValidateName(%q) = nil, want error", tc.input)
			}
		})
	}
}

func validGroup(name string) NodeGroup {
	return NodeGroup{Name: name, Size: Size{CPU: "2", Memory: "4GB", Disk: "40GB"}, MinNodes: 0, MaxNodes: 1}
}

func TestValidateNodeGroups(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func() []NodeGroup
		ok      bool
		errFrag string // substring the error must carry, "" = don't care
	}{
		{"default presets are valid", DefaultNodeGroups, true, ""},
		{"single minimal group", func() []NodeGroup { return []NodeGroup{validGroup("small")} }, true, ""},
		{"empty set", func() []NodeGroup { return nil }, false, "at least one node group"},
		{"duplicate names", func() []NodeGroup {
			return []NodeGroup{validGroup("small"), validGroup("small")}
		}, false, "duplicate node group"},
		{"invalid group name", func() []NodeGroup {
			g := validGroup("Small")
			return []NodeGroup{g}
		}, false, "invalid name"},
		{"zero cpu", func() []NodeGroup {
			g := validGroup("small")
			g.Size.CPU = "0"
			return []NodeGroup{g}
		}, false, "cpu"},
		{"non-integer cpu", func() []NodeGroup {
			g := validGroup("small")
			g.Size.CPU = "two"
			return []NodeGroup{g}
		}, false, "cpu"},
		{"lowercase memory unit", func() []NodeGroup {
			g := validGroup("small")
			g.Size.Memory = "4gb"
			return []NodeGroup{g}
		}, false, "memory"},
		{"bare-number memory", func() []NodeGroup {
			g := validGroup("small")
			g.Size.Memory = "4096"
			return []NodeGroup{g}
		}, false, "memory"},
		{"missing disk", func() []NodeGroup {
			g := validGroup("small")
			g.Size.Disk = ""
			return []NodeGroup{g}
		}, false, "disk"},
		{"negative min", func() []NodeGroup {
			g := validGroup("small")
			g.MinNodes = -1
			return []NodeGroup{g}
		}, false, "min_nodes"},
		{"max below min", func() []NodeGroup {
			g := validGroup("small")
			g.MinNodes = 2
			g.MaxNodes = 1
			return []NodeGroup{g}
		}, false, "max_nodes"},
		{"pool allows zero nodes", func() []NodeGroup {
			g := validGroup("small")
			g.MinNodes = 0
			g.MaxNodes = 0
			return []NodeGroup{g}
		}, false, "at least one node"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNodeGroups(tc.mutate())
			if tc.ok && err != nil {
				t.Fatalf("ValidateNodeGroups() = %v, want nil", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("ValidateNodeGroups() = nil, want error")
				}
				if tc.errFrag != "" && !strings.Contains(err.Error(), tc.errFrag) {
					t.Fatalf("error %q does not mention %q", err, tc.errFrag)
				}
			}
		})
	}
}
