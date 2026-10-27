//go:build !windows

package cloud

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDiskGB_ReportsPositiveTotal(t *testing.T) {
	// "/" (the fallback) always exists on a unix test host, so total disk
	// should be a positive GB figure and available should not exceed it.
	total, avail := diskGB()
	if total <= 0 {
		t.Errorf("total disk GB should be positive, got %d", total)
	}
	if avail < 0 || avail > total {
		t.Errorf("available disk GB %d out of range (total %d)", avail, total)
	}
}

func TestGPUInfo_NoGPUIsCleanZero(t *testing.T) {
	// On a GPU-less test host gpuInfo returns (0, ""). On a GPU host it
	// returns a positive count; either way it must not panic and the spec is
	// non-empty only when a GPU is present.
	count, spec := gpuInfo()
	if count < 0 {
		t.Errorf("gpu count should be non-negative, got %d", count)
	}
	if count == 0 && spec != "" {
		t.Errorf("no GPUs but got spec %q", spec)
	}
}

func TestProbe_PopulatesDisk(t *testing.T) {
	start := time.Now()
	st, err := DefaultStatusProbe{}.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if st.TotalDiskGB <= 0 {
		t.Errorf("probe should report positive total disk, got %d", st.TotalDiskGB)
	}
	if st.Posture == nil || len(st.Posture.Checks) == 0 {
		t.Fatal("real posture probe must populate the structured snapshot")
	}
	if st.Posture.MeasuredAt.Before(start) || st.Posture.MeasuredAt.After(time.Now()) {
		t.Errorf("measurement timestamp = %v, want within this probe", st.Posture.MeasuredAt)
	}
	var legacy []HostCheck
	for _, ck := range st.Checks {
		if strings.HasPrefix(ck.Name, "posture: ") {
			legacy = append(legacy, ck)
		}
	}
	if len(legacy) != len(st.Posture.Checks) {
		t.Fatalf("legacy posture checks = %d, structured = %d", len(legacy), len(st.Posture.Checks))
	}
	for i, ck := range st.Posture.Checks {
		if legacy[i] != (HostCheck{Name: "posture: " + ck.Name, OK: ck.OK, Detail: ck.Detail}) {
			t.Errorf("legacy and structured measurements differ: %+v / %+v", legacy[i], ck)
		}
	}
}
