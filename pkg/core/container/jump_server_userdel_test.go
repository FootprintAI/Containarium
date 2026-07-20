package container

import "testing"

// TestUserdelBusy pins the one userdel failure the delete-cascade retries
// instead of surfacing (#1035): a live SSH session to the box that was just
// deleted. Everything else must stay a hard error — silently swallowing, say,
// a permission failure would leave an orphaned account with no log trail.
func TestUserdelBusy(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{"live session", "userdel: user alice is currently used by process 12345\n", true},
		{"permission denied", "userdel: Permission denied.\n", false},
		{"missing user", "userdel: user 'alice' does not exist\n", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := userdelBusy([]byte(c.output)); got != c.want {
				t.Fatalf("userdelBusy(%q) = %v, want %v", c.output, got, c.want)
			}
		})
	}
}
