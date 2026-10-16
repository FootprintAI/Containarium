package cmd

import (
	"strings"
	"testing"
	"time"
)

// #2592: `token generate` must fail loud instead of letting the auth layer
// silently clamp to the cap.
func TestResolveTokenExpiry(t *testing.T) {
	const max = 720 * time.Hour
	tests := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr string
	}{
		{"hours", "24h", 24 * time.Hour, ""},
		{"exactly the cap", "720h", max, ""},
		{"zero", "0", 0, "non-expiring tokens are not supported; maximum is 720h"},
		{"empty", "", 0, "non-expiring tokens are not supported; maximum is 720h"},
		{"negative", "-1h", 0, "must be positive"},
		{"over cap", "8760h", 0, "maximum is 720h"},
		{"garbage", "soon", 0, "invalid expiry duration"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveTokenExpiry(tc.in, max)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
