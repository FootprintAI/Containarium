package server

// #2325: when Incus' hardware scan cannot answer (it can hang on a saturated host), the CPU admission gate used to
// block every create on it, and when the read merely failed it silently skipped itself. The logical CPU count is
// hardware-static, so the gate falls back to the OS's count instead and keeps working through the outage.

import (
	"errors"
	"testing"
)

func TestCoresWithLocalFallback(t *testing.T) {
	boom := errors.New("incus: resources unavailable")
	tests := []struct {
		name     string
		read     func() (float64, error)
		local    int
		want     float64
		wantErr  bool
		wantUsed bool // whether the local count is expected to have been consulted
	}{
		{name: "incus answers: its count wins even if the OS reports another",
			read: func() (float64, error) { return 16, nil }, local: 8, want: 16},
		{name: "incus errors: fall back to the OS count",
			read: func() (float64, error) { return 0, boom }, local: 8, want: 8, wantUsed: true},
		{name: "incus reports zero CPUs: fall back to the OS count",
			read: func() (float64, error) { return 0, nil }, local: 8, want: 8, wantUsed: true},
		{name: "incus errors and the OS count is unusable: the error surfaces (the gate's fail-open path handles it)",
			read: func() (float64, error) { return 0, boom }, local: 0, wantErr: true, wantUsed: true},
		{name: "incus reports zero and the OS count is unusable: an error, not a zero-core host",
			read: func() (float64, error) { return 0, nil }, local: 0, wantErr: true, wantUsed: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			used := false
			got, err := coresWithLocalFallback(tc.read, func() int { used = true; return tc.local })
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("cores = %v, want %v", got, tc.want)
			}
			if used != tc.wantUsed {
				t.Errorf("local count consulted = %v, want %v (it must not be read when Incus answered)", used, tc.wantUsed)
			}
		})
	}
}
