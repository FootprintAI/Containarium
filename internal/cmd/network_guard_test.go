package cmd

import "testing"

// An unguarded tenant is a failed guard even when the pass succeeded.
func TestGuardHealthy(t *testing.T) {
	ok := func() *guardStatusJSON {
		return &guardStatusJSON{Mode: "GUARD_MODE_ENFORCE", FirewallDriver: "nftables",
			Entries: []guardEntryJSON{{Container: "a", Attached: true}}}
	}
	tests := []struct {
		name string
		mut  func(*guardStatusJSON)
		want bool
	}{
		{"healthy", func(*guardStatusJSON) {}, true},
		{"off", func(g *guardStatusJSON) { g.Mode = "GUARD_MODE_OFF" }, false},
		{"unsupported host", func(g *guardStatusJSON) { g.Unsupported = true }, false},
		{"pass error", func(g *guardStatusJSON) { g.LastError = "boom" }, false},
		{"unresolved tenant", func(g *guardStatusJSON) { g.Unresolved = []string{"mystery"} }, false},
		{"unattached subject", func(g *guardStatusJSON) { g.Entries[0].Attached = false }, false},
		{"subject error", func(g *guardStatusJSON) { g.Entries[0].LastError = "nic device: boom" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := ok()
			tc.mut(g)
			if got := guardHealthy(g); got != tc.want {
				t.Errorf("guardHealthy = %v, want %v", got, tc.want)
			}
		})
	}
	if guardHealthy(nil) {
		t.Error("a missing guard must not read as healthy")
	}
}
