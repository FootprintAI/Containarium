package cloud

import (
	"context"
	"errors"
	"testing"
)

const gib = int64(1024 * 1024 * 1024)

type fakePools struct {
	total, used int64
	pools       int
	err         error
	calls       int
}

func (f *fakePools) StoragePoolSpace(context.Context) (int64, int64, int, error) {
	f.calls++
	return f.total, f.used, f.pools, f.err
}

func TestProbeDisk_PoolsSummedNotRootDisk(t *testing.T) {
	// Two pools (1000 GiB + 500 GiB), 300 GiB used: the figure is the pool
	// sum, not whatever filesystem holds /var/lib/incus (#3449).
	f := &fakePools{total: 1500 * gib, used: 300 * gib, pools: 2}
	st, err := DefaultStatusProbe{Pools: f}.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalDiskGB != 1500 || st.AvailDiskGB != 1200 {
		t.Errorf("disk = %d total / %d avail GB, want 1500 / 1200", st.TotalDiskGB, st.AvailDiskGB)
	}
}

func TestProbeDisk_FallsBackToStatfs(t *testing.T) {
	statTotal, _ := diskGB()
	if statTotal <= 0 {
		t.Skip("statfs unavailable on this platform")
	}
	for name, f := range map[string]*fakePools{
		"pool error":                 {err: errors.New("incus unreachable")},
		"zero pools":                 {total: 0, used: 0, pools: 0},
		"zero total":                 {total: 0, pools: 1},
		"no pools but nonzero total": {total: 5 * gib, pools: 0},
	} {
		t.Run(name, func(t *testing.T) {
			st, err := DefaultStatusProbe{Pools: f}.Probe(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if st.TotalDiskGB != statTotal {
				t.Errorf("total = %d, want statfs fallback %d", st.TotalDiskGB, statTotal)
			}
		})
	}
}

func TestProbeDisk_NilSourceUsesStatfs(t *testing.T) {
	want, _ := diskGB()
	total, _ := DefaultStatusProbe{}.disk(context.Background())
	if total != want {
		t.Errorf("total = %d, want %d", total, want)
	}
}

func TestProbeDisk_AvailNeverExceedsTotal(t *testing.T) {
	// A pool reporting used > total (or negative used) must not yield a
	// negative or over-total availability.
	for _, used := range []int64{-5 * gib, 0, 10 * gib, 99 * gib} {
		f := &fakePools{total: 10 * gib, used: used, pools: 1}
		total, avail := DefaultStatusProbe{Pools: f}.disk(context.Background())
		if total != 10 {
			t.Fatalf("used=%d: total = %d, want 10", used, total)
		}
		if avail < 0 || avail > total {
			t.Errorf("used=%d: avail %d outside [0,%d]", used, avail, total)
		}
	}
}
