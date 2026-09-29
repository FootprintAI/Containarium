package server

import (
	"testing"
	"time"
)

func TestResolveIntegrityHeartbeatInterval(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		wantInterval time.Duration
		wantInvalid  bool
		wantClamped  bool
	}{
		{
			name:         "environment variable unset uses default",
			wantInterval: defaultIntegrityHeartbeatInterval,
		},
		{
			name:         "valid duration uses configured value",
			raw:          "1h",
			wantInterval: time.Hour,
		},
		{
			name:         "invalid duration uses default",
			raw:          "not-a-duration",
			wantInterval: defaultIntegrityHeartbeatInterval,
			wantInvalid:  true,
		},
		{
			name:         "zero duration uses default",
			raw:          "0s",
			wantInterval: defaultIntegrityHeartbeatInterval,
			wantInvalid:  true,
		},
		{
			name:         "negative duration uses default",
			raw:          "-1m",
			wantInterval: defaultIntegrityHeartbeatInterval,
			wantInvalid:  true,
		},
		{
			name:         "duration below floor is clamped",
			raw:          "29s",
			wantInterval: minIntegrityHeartbeatInterval,
			wantClamped:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// os.Getenv returns an empty string when the environment variable is unset.
			got := resolveIntegrityHeartbeatInterval(tt.raw)
			if got.interval != tt.wantInterval {
				t.Fatalf("interval = %s, want %s", got.interval, tt.wantInterval)
			}
			if got.invalid != tt.wantInvalid {
				t.Errorf("invalid = %v, want %v", got.invalid, tt.wantInvalid)
			}
			if got.clamped != tt.wantClamped {
				t.Errorf("clamped = %v, want %v", got.clamped, tt.wantClamped)
			}
		})
	}
}
