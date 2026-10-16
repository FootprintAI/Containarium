package incus

import "testing"

// #2396: only a user.containarium.* key marks an instance as managed.
func TestHasContainariumConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config map[string]string
		want   bool
	}{
		{"nil config", nil, false},
		{"hand-made instance", map[string]string{"image.os": "ubuntu", "volatile.eth0.hwaddr": "00:16:3e:00:00:01"}, false},
		{"tenant label", map[string]string{TenantLabelKey: "alice"}, true},
		{"any containarium key", map[string]string{"user.containarium.auto_sleep_enabled": "true"}, true},
		{"unrelated user key", map[string]string{"user.owner": "x"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasContainariumConfig(tc.config); got != tc.want {
				t.Errorf("hasContainariumConfig = %v, want %v", got, tc.want)
			}
		})
	}
}
