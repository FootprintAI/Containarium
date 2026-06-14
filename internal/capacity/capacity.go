// Package capacity turns a backend's implicit spare resources into an
// explicit, policy-bounded scheduling-headroom signal that the control plane
// can read through the backend surface (ListBackends).
//
// Today a backend's capacity is implicit — the control plane infers it from
// SystemInfo. A box that the auto-sleep loop would scale down can instead
// publish its freed headroom here so the control plane can direct work at it.
// The advertisement is bounded by a local Policy (a time window, excluded
// workload classes, and a safety reservation), so a host running protected
// work never offers it as free. Withdrawing is idempotent. See #680.
package capacity

import (
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// WorkloadClassLabel is the container label that tags a workload's class. A
// container whose class appears in Policy.ExcludedWorkloadClasses is excluded
// from the idle/spare computation, so protected work is never advertised as
// freed headroom.
const WorkloadClassLabel = "user.containarium.workload_class"

// Policy bounds what a backend is willing to advertise. The zero value is a
// valid "always open, no exclusions, offer everything available" policy.
type Policy struct {
	// WindowStartHour / WindowEndHour describe the local-clock hour window
	// during which the advertisement offers non-zero spare. Equal values mean
	// the window is always open. A start greater than the end expresses an
	// overnight window (e.g. 22..6).
	WindowStartHour int32
	WindowEndHour   int32

	// ExcludedWorkloadClasses are workload classes that must not be displaced
	// or co-scheduled. Running containers carrying any of these classes are
	// excluded from the idle/spare computation.
	ExcludedWorkloadClasses []string

	// ReserveFraction is the share of host resources to hold back as a safety
	// reservation, in [0,1). Spare = available * (1 - ReserveFraction).
	ReserveFraction float64
}

// WindowOpen reports whether the policy's advertisement window includes the
// given local time. An always-open window (start == end) is always true.
func (p Policy) WindowOpen(now time.Time) bool {
	if p.WindowStartHour == p.WindowEndHour {
		return true
	}
	h := int32(now.Hour())
	if p.WindowStartHour < p.WindowEndHour {
		return h >= p.WindowStartHour && h < p.WindowEndHour
	}
	// Overnight window wraps midnight, e.g. 22..6.
	return h >= p.WindowStartHour || h < p.WindowEndHour
}

// excludes reports whether the policy excludes the given workload class.
func (p Policy) excludes(class string) bool {
	if class == "" {
		return false
	}
	for _, c := range p.ExcludedWorkloadClasses {
		if c == class {
			return true
		}
	}
	return false
}

// HostState is the snapshot the headroom computation consumes. The caller
// (the daemon) gathers it from SystemInfo (the AvailableMemoryBytes /
// AvailableDiskBytes already fetched in peer.go) plus the container list.
type HostState struct {
	// AvailableCPUs / AvailableMemoryBytes / AvailableDiskBytes mirror the
	// host-level figures from SystemInfo. AvailableCPUs is derived from total
	// cores minus the 1-minute load average (clamped at zero).
	AvailableCPUs        int32
	AvailableMemoryBytes int64
	AvailableDiskBytes   int64

	// Containers is the host's full container list. Used to derive the
	// host-level idle fraction (a host aggregate over the per-container idle
	// signal) and to honor workload-class exclusions.
	Containers []incus.ContainerInfo

	// Now is injected so callers/tests can pin the clock for the window check
	// and the per-container idle threshold.
	Now time.Time
}

// Headroom is the computed advertisement. It mirrors pb.CapacityHeadroom but
// stays free of any proto dependency so the computation is unit-testable in
// isolation; the server maps it onto the wire type.
type Headroom struct {
	Advertised       bool
	SpareCPUs        int32
	SpareMemoryBytes int64
	SpareDiskBytes   int64
	IdleFraction     float64
	AdvertisedAt     time.Time
	Policy           Policy
}

// Compute derives the policy-bounded headroom from a HostState. When the
// policy window is closed the spare figures are all zero (the host advertises
// "available, but nothing free right now"); advertised stays whatever the
// caller passes in via the Store. Compute itself is pure: it computes the
// figures and leaves the advertised flag to the Store.
func Compute(p Policy, st HostState) Headroom {
	h := Headroom{Policy: p}

	idleN, userN := hostIdle(p, st)
	if userN > 0 {
		h.IdleFraction = float64(idleN) / float64(userN)
	}

	// Outside the window we surface zero spare — the host keeps its capacity
	// to itself until the window reopens.
	if !p.WindowOpen(st.Now) {
		return h
	}

	keep := 1 - p.ReserveFraction
	if keep < 0 {
		keep = 0
	}
	if keep > 1 {
		keep = 1
	}

	if st.AvailableCPUs > 0 {
		h.SpareCPUs = int32(float64(st.AvailableCPUs) * keep)
	}
	if st.AvailableMemoryBytes > 0 {
		h.SpareMemoryBytes = int64(float64(st.AvailableMemoryBytes) * keep)
	}
	if st.AvailableDiskBytes > 0 {
		h.SpareDiskBytes = int64(float64(st.AvailableDiskBytes) * keep)
	}
	return h
}

// hostIdle returns (idle user containers, total considered user containers).
// A container is "considered" when it is a running, non-core user container
// whose workload class is not excluded by policy. A considered container
// counts as idle when it has gone quiet longer than its idle threshold — the
// same scale-down signal the auto-sleep loop uses, aggregated to a host level.
func hostIdle(p Policy, st HostState) (idle, considered int) {
	for _, c := range st.Containers {
		if c.Role.IsCoreRole() {
			continue
		}
		if c.State != "Running" {
			continue
		}
		if p.excludes(c.Labels[WorkloadClassLabel]) {
			continue
		}
		considered++

		threshold := time.Duration(c.IdleThresholdMinutes) * time.Minute
		if threshold <= 0 {
			threshold = 15 * time.Minute
		}
		// Reuse the auto-sleep "since last start" idle proxy: a container that
		// has been up longer than its idle threshold and shows no recent start
		// activity is treated as idle for the host aggregate. The per-container
		// network signal lives in the auto-sleep loop; here we only need a
		// host-level fraction, so the start-stamp proxy is sufficient and needs
		// no traffic store.
		if c.LastStartedAt.IsZero() {
			continue
		}
		if st.Now.Sub(c.LastStartedAt) >= threshold {
			idle++
		}
	}
	return idle, considered
}

// Store holds the per-daemon advertise/withdraw state and the active policy.
// One per daemon. All methods are safe for concurrent use. The store does not
// itself gather HostState — the caller passes a fresh snapshot on each call so
// the figures are always current.
type Store struct {
	mu           sync.RWMutex
	advertised   bool
	policy       Policy
	advertisedAt time.Time
}

// NewStore returns an empty store: nothing advertised, default policy.
func NewStore() *Store {
	return &Store{}
}

// Advertise publishes (or republishes) the backend's headroom under the given
// policy and returns the freshly computed advertisement. Republishing with a
// new policy replaces the old one and re-stamps advertisedAt.
func (s *Store) Advertise(p Policy, st HostState) Headroom {
	s.mu.Lock()
	s.advertised = true
	s.policy = p
	s.advertisedAt = st.Now
	s.mu.Unlock()

	h := Compute(p, st)
	h.Advertised = true
	h.AdvertisedAt = st.Now
	return h
}

// Withdraw removes any active advertisement. Idempotent: withdrawing when
// nothing is advertised succeeds and returns a withdrawn snapshot. The policy
// is retained so a subsequent bare Advertise can reuse it, but the spare
// figures are zeroed because nothing is offered while withdrawn.
func (s *Store) Withdraw() Headroom {
	s.mu.Lock()
	s.advertised = false
	s.advertisedAt = time.Time{}
	p := s.policy
	s.mu.Unlock()

	return Headroom{Advertised: false, Policy: p}
}

// Current returns the present advertisement state with spare figures
// recomputed against the supplied HostState. When nothing is advertised the
// figures are zeroed (advertised=false); the policy is still surfaced.
func (s *Store) Current(st HostState) Headroom {
	s.mu.RLock()
	advertised := s.advertised
	p := s.policy
	at := s.advertisedAt
	s.mu.RUnlock()

	if !advertised {
		return Headroom{Advertised: false, Policy: p}
	}
	h := Compute(p, st)
	h.Advertised = true
	h.AdvertisedAt = at
	return h
}

// Policy returns the store's current policy (the one a bare Advertise reuses).
func (s *Store) Policy() Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}
