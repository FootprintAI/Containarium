package incus

import (
	"testing"
	"time"
)

// TestTTLExpiresAtKeyStable locks the user-* config key name. The
// ttlsweeper goroutine reads this key on every tick and the CLI's
// `containarium ttl get` calls into the same field via the proto
// read path, so renaming would silently break both consumers — pin
// the value here so the rename is caught in CI.
func TestTTLExpiresAtKeyStable(t *testing.T) {
	if TTLExpiresAtKey != "user.containarium.ttl_expires_at" {
		t.Errorf("TTLExpiresAtKey = %q, must remain stable across releases", TTLExpiresAtKey)
	}
}

// TestParseTTLExpiresAt mirrors TestParseLastStartedAt — missing,
// empty, or malformed values resolve to the zero time so a corrupt
// key (e.g. someone edited the Incus config by hand) never 5xx's the
// list endpoint and never tricks the sweeper into a false-positive
// deletion. The helper is intentionally permissive: never panics on
// garbage, never logs, never returns a non-zero time it can't justify
// from the input.
func TestParseTTLExpiresAt(t *testing.T) {
	ref := time.Date(2026, 5, 23, 18, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		cfg  map[string]string
		want time.Time
	}{
		{
			name: "missing key returns zero",
			cfg:  map[string]string{},
			want: time.Time{},
		},
		{
			name: "empty string returns zero",
			cfg:  map[string]string{TTLExpiresAtKey: ""},
			want: time.Time{},
		},
		{
			name: "valid RFC3339 round-trips",
			cfg:  map[string]string{TTLExpiresAtKey: ref.Format(time.RFC3339)},
			want: ref,
		},
		{
			name: "malformed garbage returns zero",
			cfg:  map[string]string{TTLExpiresAtKey: "not-a-timestamp"},
			want: time.Time{},
		},
		{
			name: "unsupported format (RFC1123) returns zero",
			cfg:  map[string]string{TTLExpiresAtKey: ref.Format(time.RFC1123)},
			want: time.Time{},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := parseTTLExpiresAt(tc.cfg)
			if !got.Equal(tc.want) {
				t.Errorf("parseTTLExpiresAt(%v) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}

// TestStackKeyStable locks the config key the create path writes and the
// read path consumes (#2163); renaming it orphans every existing box's stack.
func TestStackKeyStable(t *testing.T) {
	if StackKey != "user.containarium.stack" {
		t.Errorf("StackKey = %q, must remain stable across releases", StackKey)
	}
}

// TestPodmanEnabledKeyStable locks the config key (#2858).
func TestPodmanEnabledKeyStable(t *testing.T) {
	if PodmanEnabledKey != "user.containarium.podman_enabled" {
		t.Errorf("PodmanEnabledKey = %q, must remain stable across releases", PodmanEnabledKey)
	}
}

// TestPodmanEnabledFromConfig (#2858): a box created before the key existed
// has no stored value and keeps reporting true (what status always said); an
// explicit value wins.
func TestPodmanEnabledFromConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  map[string]string
		want bool
	}{
		{"absent (created before the key)", map[string]string{}, true},
		{"nil config", nil, true},
		{"true", map[string]string{PodmanEnabledKey: "true"}, true},
		{"false", map[string]string{PodmanEnabledKey: "false"}, false},
		{"garbage falls back to legacy value", map[string]string{PodmanEnabledKey: "maybe"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := podmanEnabledFromConfig(tc.cfg); got != tc.want {
				t.Errorf("podmanEnabledFromConfig = %v, want %v", got, tc.want)
			}
		})
	}
}
