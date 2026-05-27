package container

import (
	"sync"
	"testing"
)

// TestHostClassDetection covers the gating contract for the
// jump-server's GCP-specific code paths (issue #351). The actual
// useradd/systemctl calls in retryUseraddWithLockWait need root and
// a real host, so we test what we CAN cheaply test: that isGCPHost
// returns the detector's verdict and that the detector is replaceable
// for callers that want deterministic behavior in tests.
func TestHostClassDetection(t *testing.T) {
	t.Run("isGCPHost returns true when detector reports GCP", func(t *testing.T) {
		withStubDetector(t, func() hostClass { return hostClassGCP })
		if !isGCPHost() {
			t.Errorf("isGCPHost() = false, want true (detector returned hostClassGCP)")
		}
	})

	t.Run("isGCPHost returns false when detector reports unknown", func(t *testing.T) {
		withStubDetector(t, func() hostClass { return hostClassUnknown })
		if isGCPHost() {
			t.Errorf("isGCPHost() = true, want false (detector returned hostClassUnknown)")
		}
	})

	t.Run("detector is invoked exactly once per process", func(t *testing.T) {
		calls := 0
		withStubDetector(t, func() hostClass {
			calls++
			return hostClassGCP
		})

		// Hammer it from a few goroutines too — sync.Once should
		// still let exactly one detector call through.
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = isGCPHost()
			}()
		}
		wg.Wait()
		_ = isGCPHost()

		if calls != 1 {
			t.Errorf("detector called %d times, want 1 (sync.Once should cache)", calls)
		}
	})
}

// withStubDetector swaps the package-level hostClassDetector for the
// duration of a sub-test and clears the sync.Once / cached result so
// the next isGCPHost() call re-invokes the stub. On cleanup the
// detector is restored to its real implementation and the Once is
// reset again — any subsequent caller in the same process will
// re-detect against the real host. Note: sync.Once contains a
// noCopy field so it isn't safe to value-copy; we reset to a fresh
// zero-value instead of saving/restoring the previous Once.
func withStubDetector(t *testing.T, stub func() hostClass) {
	t.Helper()
	prevDetector := hostClassDetector

	hostClassDetector = stub
	hostClassOnce = sync.Once{}
	hostClassResult = hostClassUnknown

	t.Cleanup(func() {
		hostClassDetector = prevDetector
		hostClassOnce = sync.Once{}
		hostClassResult = hostClassUnknown
	})
}
