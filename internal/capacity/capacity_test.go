package capacity

import (
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

func at(hour int) time.Time {
	return time.Date(2026, 6, 14, hour, 0, 0, 0, time.UTC)
}

func TestPolicyWindowOpen(t *testing.T) {
	cases := []struct {
		name  string
		p     Policy
		hour  int
		open  bool
	}{
		{"always open (equal)", Policy{}, 3, true},
		{"day window in", Policy{WindowStartHour: 9, WindowEndHour: 17}, 12, true},
		{"day window before", Policy{WindowStartHour: 9, WindowEndHour: 17}, 8, false},
		{"day window at end exclusive", Policy{WindowStartHour: 9, WindowEndHour: 17}, 17, false},
		{"overnight in late", Policy{WindowStartHour: 22, WindowEndHour: 6}, 23, true},
		{"overnight in early", Policy{WindowStartHour: 22, WindowEndHour: 6}, 2, true},
		{"overnight out midday", Policy{WindowStartHour: 22, WindowEndHour: 6}, 12, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.p.WindowOpen(at(c.hour)); got != c.open {
				t.Fatalf("WindowOpen(%d) = %v, want %v", c.hour, got, c.open)
			}
		})
	}
}

func TestComputeSpareWithReserve(t *testing.T) {
	st := HostState{
		AvailableCPUs:        10,
		AvailableMemoryBytes: 1000,
		AvailableDiskBytes:   2000,
		Now:                  at(12),
	}
	h := Compute(Policy{ReserveFraction: 0.2}, st)
	if h.SpareCPUs != 8 {
		t.Errorf("SpareCPUs = %d, want 8", h.SpareCPUs)
	}
	if h.SpareMemoryBytes != 800 {
		t.Errorf("SpareMemoryBytes = %d, want 800", h.SpareMemoryBytes)
	}
	if h.SpareDiskBytes != 1600 {
		t.Errorf("SpareDiskBytes = %d, want 1600", h.SpareDiskBytes)
	}
}

func TestComputeWindowClosedZeroesSpare(t *testing.T) {
	st := HostState{
		AvailableCPUs:        10,
		AvailableMemoryBytes: 1000,
		AvailableDiskBytes:   2000,
		Now:                  at(3),
	}
	h := Compute(Policy{WindowStartHour: 9, WindowEndHour: 17}, st)
	if h.SpareCPUs != 0 || h.SpareMemoryBytes != 0 || h.SpareDiskBytes != 0 {
		t.Fatalf("window closed should zero spare, got %+v", h)
	}
}

func TestHostIdleFractionAndExclusion(t *testing.T) {
	now := at(12)
	old := now.Add(-1 * time.Hour) // well past the 15m default threshold
	containers := []incus.ContainerInfo{
		// idle user container
		{Name: "a-container", State: "Running", LastStartedAt: old, IdleThresholdMinutes: 15},
		// active user container (recently started)
		{Name: "b-container", State: "Running", LastStartedAt: now.Add(-1 * time.Minute), IdleThresholdMinutes: 15},
		// excluded workload class — must not count toward considered or idle
		{Name: "c-container", State: "Running", LastStartedAt: old, IdleThresholdMinutes: 15,
			Labels: map[string]string{WorkloadClassLabel: "protected"}},
		// core container — never considered
		{Name: "postgres", State: "Running", LastStartedAt: old, Role: incus.RolePostgres},
		// stopped — never considered
		{Name: "d-container", State: "Stopped", LastStartedAt: old},
	}
	p := Policy{ExcludedWorkloadClasses: []string{"protected"}}
	st := HostState{Now: now, Containers: containers}
	h := Compute(p, st)
	// considered = a + b = 2; idle = a = 1 → 0.5
	if h.IdleFraction != 0.5 {
		t.Fatalf("IdleFraction = %v, want 0.5", h.IdleFraction)
	}
}

func TestStoreAdvertiseWithdrawIdempotent(t *testing.T) {
	s := NewStore()
	st := HostState{AvailableCPUs: 4, AvailableMemoryBytes: 100, Now: at(12)}

	// Initially nothing advertised.
	if cur := s.Current(st); cur.Advertised {
		t.Fatal("fresh store should not be advertised")
	}

	h := s.Advertise(Policy{ReserveFraction: 0.25}, st)
	if !h.Advertised || h.SpareCPUs != 3 {
		t.Fatalf("advertise = %+v, want advertised w/ 3 spare cpus", h)
	}
	if cur := s.Current(st); !cur.Advertised || cur.SpareCPUs != 3 {
		t.Fatalf("current after advertise = %+v", cur)
	}

	// Withdraw is idempotent.
	w1 := s.Withdraw()
	if w1.Advertised {
		t.Fatal("withdraw should clear advertised")
	}
	w2 := s.Withdraw()
	if w2.Advertised {
		t.Fatal("second withdraw should remain withdrawn (idempotent)")
	}
	if cur := s.Current(st); cur.Advertised || cur.SpareCPUs != 0 {
		t.Fatalf("current after withdraw = %+v, want withdrawn + zero spare", cur)
	}
	// Policy is retained across withdraw.
	if s.Policy().ReserveFraction != 0.25 {
		t.Fatalf("policy not retained: %+v", s.Policy())
	}
}
