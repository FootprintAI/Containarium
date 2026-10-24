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
	// ReleasedByOrphanSweep marks a row that stayed PENDING (inserted, never
	// confirmed applied — the daemon died mid-apply) and was undone by the
	// sweep.
	ReleasedByOrphanSweep = "orphan-sweep"
	// ReleasedByContainerDeleted marks an action closed because its box no
	// longer exists (#2835): the box was deleted through the daemon, or a
	// sweep found it gone. There is nothing to restore on a deleted box.
	ReleasedByContainerDeleted = "container-deleted"
)

// PendingOrphanAfter is how long a PENDING row may wait for its actuator
// call to be confirmed before the sweep treats it as orphaned.
const PendingOrphanAfter = 5 * time.Minute

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
	// KilledPID is the host pid the responder SIGKILLed for the same finding
	// (kill_process on a miner-signature finding, #2638); 0 when none.
	KilledPID uint32
	// Error is the Incus failure text when the apply did not take effect.
	Error string
	// Pending is true between the row's insert and the actuator call being
	// confirmed (MarkApplied) or failed (Fail). The row is written first so
	// a crash mid-apply leaves a record the sweep can undo.
	Pending   bool
	AppliedAt time.Time
	ExpiresAt time.Time
	// InstanceID is the Incus instance id (volatile.uuid) of the box the
	// action was applied to (#2835): a box re-created under the same name is
	// another instance, and an undo must never write this row's saved limits
	// onto it. "" on rows recorded before it existed, or when it could not
	// be read.
	InstanceID string
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
	// MarkApplied confirms pending action id took effect.
	MarkApplied(ctx context.Context, id int64) error
	// Fail closes pending action id as failed with cause: released at `at`
	// by ReleasedByError, so it stops holding the open slot.
	Fail(ctx context.Context, id int64, cause string, at time.Time) error
	// Latest returns the container's most recent action, open or not, or
	// ErrNoOpenAction when it has none.
	Latest(ctx context.Context, container string) (*SecurityAction, error)
	// ListOrphaned returns the open actions still PENDING that were applied
	// (inserted) at or before cutoff.
	ListOrphaned(ctx context.Context, cutoff time.Time) ([]*SecurityAction, error)
	// ListByFinding returns every action recorded for finding id, open or
	// not, on any container, newest first; empty when none. A finding shared
	// by several boxes of one tenant (#2766) has one row per box that acted
	// on it, so this is how the responder tells whether another box still
	// holds the finding open, and which of a box's rows belong to it.
	ListByFinding(ctx context.Context, findingID int64) ([]*SecurityAction, error)
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
		if r.Open() && !r.Pending && !r.ExpiresAt.After(now) {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *MemActionStore) MarkApplied(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.ID == id && r.Open() && r.Pending {
			r.Pending = false
			return nil
		}
	}
	return fmt.Errorf("threatdetect: action %d: %w", id, ErrNoOpenAction)
}

func (s *MemActionStore) Fail(_ context.Context, id int64, cause string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.ID == id && r.Open() {
			r.Pending, r.Error, r.ReleasedAt, r.ReleasedBy = false, cause, at, ReleasedByError
			return nil
		}
	}
	return fmt.Errorf("threatdetect: action %d: %w", id, ErrNoOpenAction)
}

func (s *MemActionStore) Latest(_ context.Context, container string) (*SecurityAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.rows) - 1; i >= 0; i-- {
		if s.rows[i].Container == container {
			cp := *s.rows[i]
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("threatdetect: %s: %w", container, ErrNoOpenAction)
}

func (s *MemActionStore) ListOrphaned(_ context.Context, cutoff time.Time) ([]*SecurityAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*SecurityAction
	for _, r := range s.rows {
		if r.Open() && r.Pending && !r.AppliedAt.After(cutoff) {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *MemActionStore) ListByFinding(_ context.Context, findingID int64) ([]*SecurityAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*SecurityAction
	for i := len(s.rows) - 1; i >= 0; i-- {
		if s.rows[i].FindingID == findingID {
			cp := *s.rows[i]
			out = append(out, &cp)
		}
	}
	return out, nil
}
