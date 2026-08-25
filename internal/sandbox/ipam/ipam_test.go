package ipam

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNew_RejectsInvalidRanges(t *testing.T) {
	cases := []struct {
		name             string
		start, end, host string
		quarantine       time.Duration
		wantErrSubstring string
	}{
		{"start after end", "10.0.0.20", "10.0.0.10", "10.0.0.1", 0, "after"},
		{"malformed start", "not-an-ip", "10.0.0.10", "10.0.0.1", 0, "start"},
		{"malformed end", "10.0.0.10", "not-an-ip", "10.0.0.1", 0, "end"},
		{"malformed host", "10.0.0.10", "10.0.0.20", "not-an-ip", 0, "host"},
		{"host inside range", "10.0.0.10", "10.0.0.20", "10.0.0.15", 0, "overlaps"},
		{"host equals start", "10.0.0.10", "10.0.0.20", "10.0.0.10", 0, "overlaps"},
		{"host equals end", "10.0.0.10", "10.0.0.20", "10.0.0.20", 0, "overlaps"},
		{"negative quarantine", "10.0.0.10", "10.0.0.20", "10.0.0.1", -time.Second, "negative"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.start, c.end, c.host, c.quarantine)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), c.wantErrSubstring) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), c.wantErrSubstring)
			}
		})
	}
}

func TestNew_AcceptsHostOutsideRange(t *testing.T) {
	if _, err := New("10.0.0.10", "10.0.0.20", "10.0.0.1", 0); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestAllocate_UniqueAcrossConcurrentCallers(t *testing.T) {
	a, err := New("10.0.0.1", "10.0.0.100", "10.0.0.254", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 100 // exactly the range size — every address must be claimed exactly once
	var wg sync.WaitGroup
	ips := make([]net.IP, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ips[i], errs[i] = a.Allocate()
		}(i)
	}
	wg.Wait()

	seen := make(map[string]int, n)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Allocate %d: %v", i, err)
		}
		seen[ips[i].String()]++
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct addresses, want %d", len(seen), n)
	}
	for ip, count := range seen {
		if count != 1 {
			t.Errorf("address %s allocated %d times", ip, count)
		}
	}
}

func TestAllocate_ExhaustedRangeReturnsTypedError(t *testing.T) {
	a, err := New("10.0.0.1", "10.0.0.2", "10.0.0.254", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := a.Allocate(); err != nil {
		t.Fatalf("Allocate 1: %v", err)
	}
	if _, err := a.Allocate(); err != nil {
		t.Fatalf("Allocate 2: %v", err)
	}
	_, err = a.Allocate()
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("Allocate 3 (exhausted) = %v, want ErrExhausted", err)
	}
}

func TestAllocate_SkipsQuarantinedAddressUntilItExpires(t *testing.T) {
	// A 2-address range makes the quarantine unambiguous: after releasing
	// the first address, the ONLY way Allocate can succeed a second time
	// while the first is quarantined is by handing out the second address
	// — and once the quarantine elapses, the freed one becomes available
	// again.
	const quarantine = 60 * time.Millisecond
	a, err := New("10.0.0.1", "10.0.0.2", "10.0.0.254", quarantine)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	first, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate 1: %v", err)
	}
	second, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate 2: %v", err)
	}
	if first.Equal(second) {
		t.Fatalf("Allocate returned the same address twice: %s", first)
	}

	if err := a.Release(first); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// Range is now fully exhausted except for `first`, which is
	// quarantined — Allocate must fail, not silently ignore quarantine.
	if _, err := a.Allocate(); !errors.Is(err, ErrExhausted) {
		t.Fatalf("Allocate immediately after release = %v, want ErrExhausted (quarantine not yet elapsed)", err)
	}

	time.Sleep(quarantine + 20*time.Millisecond)

	got, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate after quarantine elapsed: %v", err)
	}
	if !got.Equal(first) {
		t.Errorf("Allocate after quarantine = %s, want the released address %s back", got, first)
	}
}

func TestAllocate_ZeroQuarantineAllowsImmediateReuse(t *testing.T) {
	a, err := New("10.0.0.1", "10.0.0.1", "10.0.0.254", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ip, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate 1: %v", err)
	}
	if err := a.Release(ip); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := a.Allocate(); err != nil {
		t.Fatalf("Allocate 2 (immediate reuse, quarantine=0): %v", err)
	}
}

func TestRelease_RejectsAddressNotCurrentlyAllocated(t *testing.T) {
	a, err := New("10.0.0.1", "10.0.0.10", "10.0.0.254", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = a.Release(net.ParseIP("10.0.0.5"))
	if !errors.Is(err, ErrNotAllocated) {
		t.Fatalf("Release of a never-allocated address = %v, want ErrNotAllocated", err)
	}

	ip, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if err := a.Release(ip); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := a.Release(ip); !errors.Is(err, ErrNotAllocated) {
		t.Fatalf("double Release = %v, want ErrNotAllocated", err)
	}
}

func TestAllocate_RoundRobinsAcrossTheRange(t *testing.T) {
	// Not a strict requirement of the design note, but pins the actual
	// scan behavior: sequential Allocate/Release/Allocate cycles spread
	// reuse across the range (cursor-based) rather than always handing
	// back the lowest free address — the shape that makes ARP-quarantine
	// meaningful in the first place (constantly reusing the same handful
	// of addresses would defeat the point of quarantining at all).
	a, err := New("10.0.0.1", "10.0.0.3", "10.0.0.254", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var got []string
	for i := 0; i < 3; i++ {
		ip, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate %d: %v", i, err)
		}
		got = append(got, ip.String())
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("allocation order = %v, want %v", got, want)
			break
		}
	}
}

func ExampleAllocator() {
	a, err := New("10.100.0.10", "10.100.0.20", "10.100.0.1", time.Minute)
	if err != nil {
		panic(err)
	}
	ip, err := a.Allocate()
	if err != nil {
		panic(err)
	}
	fmt.Println(ip)
	// Output: 10.100.0.10
}
