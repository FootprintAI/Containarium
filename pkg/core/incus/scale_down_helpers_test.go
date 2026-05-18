package incus

import (
	"testing"
	"time"
)

// parseIdleThresholdMinutes reads the per-container idle threshold
// from the Incus config map. The helper falls back to
// DefaultIdleThresholdMinutes (15) for any value that fails to parse
// as a positive int — that includes missing keys, empty strings,
// non-numeric junk, zero, and negative numbers. Values are returned
// as int32 with no upper bound clamp.
func TestParseIdleThresholdMinutes(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]string
		want int32
	}{
		{"missing key falls back to default", map[string]string{}, DefaultIdleThresholdMinutes},
		{"empty string falls back to default", map[string]string{IdleThresholdMinutesKey: ""}, DefaultIdleThresholdMinutes},
		{"valid 15", map[string]string{IdleThresholdMinutesKey: "15"}, 15},
		{"valid 1440 (one day)", map[string]string{IdleThresholdMinutesKey: "1440"}, 1440},
		{"non-numeric garbage falls back", map[string]string{IdleThresholdMinutesKey: "abc"}, DefaultIdleThresholdMinutes},
		{"negative value falls back", map[string]string{IdleThresholdMinutesKey: "-5"}, DefaultIdleThresholdMinutes},
		{"zero falls back (n < 1)", map[string]string{IdleThresholdMinutesKey: "0"}, DefaultIdleThresholdMinutes},
		// No upper-bound clamp today — large values pass through.
		{"no upper bound clamp", map[string]string{IdleThresholdMinutesKey: "99999"}, 99999},
		// Atoi does not trim whitespace — " 30 " is unparseable.
		{"surrounding whitespace falls back", map[string]string{IdleThresholdMinutesKey: " 30 "}, DefaultIdleThresholdMinutes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseIdleThresholdMinutes(tc.cfg); got != tc.want {
				t.Errorf("parseIdleThresholdMinutes(%v) = %d, want %d", tc.cfg, got, tc.want)
			}
		})
	}
}

// Constants used by the auto-sleep feature should be stable so
// upgrade paths don't silently re-default operator config.
func TestAutoSleepConstants(t *testing.T) {
	if AutoSleepEnabledKey != "user.containarium.auto_sleep_enabled" {
		t.Errorf("AutoSleepEnabledKey = %q, must remain stable across releases", AutoSleepEnabledKey)
	}
	if IdleThresholdMinutesKey != "user.containarium.idle_threshold_minutes" {
		t.Errorf("IdleThresholdMinutesKey = %q, must remain stable across releases", IdleThresholdMinutesKey)
	}
	if DefaultIdleThresholdMinutes != 15 {
		t.Errorf("DefaultIdleThresholdMinutes = %d, want 15", DefaultIdleThresholdMinutes)
	}
	if LastStartedAtKey != "user.containarium.last_started_at" {
		t.Errorf("LastStartedAtKey = %q, must remain stable across releases", LastStartedAtKey)
	}
}

// parseLastStartedAt reads the Phase 2 anti-thrash timestamp from the
// Incus config map. Missing, empty, or malformed values resolve to the
// zero time so callers can distinguish "no last-start known" from a
// real moment in history. The helper is intentionally permissive: it
// never panics on garbage, never logs, and never returns a non-zero
// time it can't justify from the input.
func TestParseLastStartedAt(t *testing.T) {
	ref := time.Date(2026, 5, 18, 12, 30, 45, 0, time.UTC)
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
			cfg:  map[string]string{LastStartedAtKey: ""},
			want: time.Time{},
		},
		{
			name: "valid RFC3339 round-trips",
			cfg:  map[string]string{LastStartedAtKey: ref.Format(time.RFC3339)},
			want: ref,
		},
		{
			name: "malformed garbage returns zero",
			cfg:  map[string]string{LastStartedAtKey: "not-a-timestamp"},
			want: time.Time{},
		},
		{
			name: "go zero-time string parses to zero",
			cfg:  map[string]string{LastStartedAtKey: "0001-01-01T00:00:00Z"},
			want: time.Time{},
		},
		{
			name: "unsupported format (RFC1123) returns zero",
			cfg:  map[string]string{LastStartedAtKey: ref.Format(time.RFC1123)},
			want: time.Time{},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := parseLastStartedAt(tc.cfg)
			if !got.Equal(tc.want) {
				t.Errorf("parseLastStartedAt(%v) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}
