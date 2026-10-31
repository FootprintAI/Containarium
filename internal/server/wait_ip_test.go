package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A container that was just started has no DHCP lease for a moment, so an
// adopt that reads the address once fails even though the container is fine.
func TestWaitForContainerIP_WaitsForTheLease(t *testing.T) {
	calls := 0
	get := func() (string, error) {
		calls++
		if calls < 4 {
			return "", nil // running, no lease yet
		}
		return "10.0.3.42", nil
	}

	ip, err := waitForContainerIP(context.Background(), get, 5*time.Second, time.Millisecond)
	if err != nil {
		t.Fatalf("waitForContainerIP: %v", err)
	}
	if ip != "10.0.3.42" {
		t.Errorf("ip = %q, want 10.0.3.42", ip)
	}
	if calls != 4 {
		t.Errorf("polled %d times, want 4", calls)
	}
}

func TestWaitForContainerIP_ReturnsAtOnceWhenTheIPIsThere(t *testing.T) {
	calls := 0
	ip, err := waitForContainerIP(context.Background(), func() (string, error) {
		calls++
		return "10.0.3.7", nil
	}, time.Second, time.Hour)
	if err != nil || ip != "10.0.3.7" || calls != 1 {
		t.Errorf("got ip=%q err=%v after %d calls, want 10.0.3.7 after 1", ip, err, calls)
	}
}

func TestWaitForContainerIP_GivesUpAtTheDeadline(t *testing.T) {
	start := time.Now()
	_, err := waitForContainerIP(context.Background(), func() (string, error) { return "", nil }, 50*time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error when no address ever appears")
	}
	if !strings.Contains(err.Error(), "no IP address") {
		t.Errorf("error %q should say there is no IP address", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %v; it must stop near the 50ms deadline", time.Since(start))
	}
}

func TestWaitForContainerIP_ReportsALookupErrorAtOnce(t *testing.T) {
	boom := errors.New("substrate unreachable")
	calls := 0
	_, err := waitForContainerIP(context.Background(), func() (string, error) {
		calls++
		return "", boom
	}, time.Second, time.Millisecond)
	if !errors.Is(err, boom) || calls != 1 {
		t.Errorf("got err=%v after %d calls, want the lookup error after 1", err, calls)
	}
}

func TestWaitForContainerIP_StopsWhenTheCallerGivesUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := waitForContainerIP(ctx, func() (string, error) { return "", nil }, time.Hour, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
