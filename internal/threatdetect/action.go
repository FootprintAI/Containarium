package threatdetect

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Who released a SecurityAction (security_actions.released_by).
const (
	ReleasedByOperator = "operator"
	ReleasedByTTL      = "ttl"
	// ReleasedByError marks a row whose apply failed: recorded for the audit
	// trail with released_at = applied_at, so it never holds the container's
	// open slot (the rule's next sweep re-fires the finding, which is the
	// retry).
	ReleasedByError = "error"
)

// ErrNoOpenAction reports that a container has no action in effect.
var ErrNoOpenAction = errors.New("no open process action for container")

// ErrActionOpen reports that Insert would open a second action on a
// container that already has one — the security_actions_open_per_container
// partial unique index, surfaced as a sentinel by both stores.
var ErrActionOpen = errors.New("a process action is already open for container")

// SecurityAction is one applied process action (#2636): what was done to
// which container because of which finding, what it replaced, and when it
// was undone. Mirrors the security_actions table.
type SecurityAction struct {
	ID        int64
	FindingID int64
	Container string
	TenantID  string
	Action    pb.ProcessAction
	// PrevCPUCount and PrevCPUAllowance are the box's limits.cpu and
	// limits.cpu.allowance before a THROTTLE, restored verbatim on release.
	PrevCPUCount     string
	PrevCPUAllowance string
	// Error is the Incus failure text when the apply did not take effect.
	Error     string
	AppliedAt time.Time
	ExpiresAt time.Time
	// ReleasedAt is zero while the action is in effect.
	ReleasedAt time.Time
	ReleasedBy string
}

// Open reports whether the action is still in effect.
func (a *SecurityAction) Open() bool { return a.ReleasedAt.IsZero() }

// ActionStore persists SecurityActions. *PGActionStore (Postgres) and
// *MemActionStore (degraded, no Postgres) both satisfy it.
type ActionStore interface {
	// Insert records a; it assigns a.ID. ErrActionOpen when a is open and
	// the container already has an open action.
	Insert(ctx context.Context, a *SecurityAction) error
	// Open returns the container's open action, or ErrNoOpenAction.
	Open(ctx context.Context, container string) (*SecurityAction, error)
	// Release closes the open action id; ErrNoOpenAction if it is not open.
	Release(ctx context.Context, id int64, releasedBy string, at time.Time) error
	// ListExpired returns the open actions whose expires_at is at or before
	// now, oldest first.
	ListExpired(ctx context.Context, now time.Time) ([]*SecurityAction, error)
}

// memActionRingCap bounds the degraded-mode store like memFindingRingCap.
const memActionRingCap = 1000

// MemActionStore is the DEGRADED-mode ActionStore: same contract as the
// Postgres store, bounded in-memory ring, lost on restart. The responder
// never applies THROTTLE or FREEZE on a degraded backend (a previous-limit
// row that can vanish is worse than an alert), so in production this only
// ever holds the rows unit tests and the ALERT-only path produce.
type MemActionStore struct {
	mu     sync.Mutex
	nextID int64
	rows   []*SecurityAction
}

// NewMemActionStore builds an empty degraded-mode store.
func NewMemActionStore() *MemActionStore { return &MemActionStore{} }

func (s *MemActionStore) Insert(_ context.Context, a *SecurityAction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.Open() {
		for _, r := range s.rows {
			if r.Container == a.Container && r.Open() {
				return fmt.Errorf("threatdetect: %s: %w", a.Container, ErrActionOpen)
			}
		}
	}
	s.nextID++
	a.ID = s.nextID
	cp := *a
	s.rows = append(s.rows, &cp)
	if len(s.rows) > memActionRingCap {
		s.rows = s.rows[1:]
	}
	return nil
}

func (s *MemActionStore) Open(_ context.Context, container string) (*SecurityAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.Container == container && r.Open() {
			cp := *r
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("threatdetect: %s: %w", container, ErrNoOpenAction)
}

func (s *MemActionStore) Release(_ context.Context, id int64, releasedBy string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.ID == id && r.Open() {
			r.ReleasedAt, r.ReleasedBy = at, releasedBy
			return nil
		}
	}
	return fmt.Errorf("threatdetect: action %d: %w", id, ErrNoOpenAction)
}

func (s *MemActionStore) ListExpired(_ context.Context, now time.Time) ([]*SecurityAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*SecurityAction
	for _, r := range s.rows {
		if r.Open() && !r.ExpiresAt.After(now) {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out, nil
}
