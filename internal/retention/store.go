// Package retention stores the per-class retention policy and the per-org
// legal holds (#2576, slice A #2875; docs/security/DATA-FLOW-AND-RETENTION.md).
// It deletes nothing: the sweeper in this package only counts (#2876); the
// enforcing slices come later.
package retention

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var (
	// ErrInvalid wraps every rejected input (bad class, days < 1, empty org).
	ErrInvalid      = errors.New("invalid retention request")
	ErrHoldExists   = errors.New("org is already on legal hold")
	ErrHoldNotFound = errors.New("org has no legal hold")
)

// defaultDays are the windows of a class no admin has set (Q6 on #2727).
var defaultDays = map[pb.RetentionClass]int32{
	pb.RetentionClass_RETENTION_CLASS_PROMPTS:             30,
	pb.RetentionClass_RETENTION_CLASS_RESPONSES:           30,
	pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS:        90,
	pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS: 90,
	pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES:    365,
}

// Classes returns every class, in enum order.
func Classes() []pb.RetentionClass {
	out := make([]pb.RetentionClass, 0, len(defaultDays))
	for c := range defaultDays {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// PolicySetResult is what one SetPolicy replaced and stored.
type PolicySetResult struct {
	Previous, Current *pb.RetentionPolicy
}

// Store keeps the policy and the holds. Each write takes a beforeCommit hook
// (nil = none) that runs with the pending change before it is committed; its
// error discards the change and is returned, so a caller can make a change
// conditional on its audit entry being written.
type Store interface {
	// GetPolicy returns a window for every class, set or default.
	GetPolicy(ctx context.Context) (*pb.RetentionPolicy, error)
	// SetPolicy changes the listed classes only; revision = previous + 1.
	SetPolicy(ctx context.Context, windows []*pb.RetentionWindow, updatedBy string, beforeCommit func(*PolicySetResult) error) (*PolicySetResult, error)
	// ListHolds returns the active holds ordered by org id.
	ListHolds(ctx context.Context) ([]*pb.LegalHold, error)
	// SetHold places a hold; an org already on hold is ErrHoldExists.
	SetHold(ctx context.Context, orgID, reason, setBy string, beforeCommit func(*pb.LegalHold) error) (*pb.LegalHold, error)
	// ReleaseHold removes a hold and returns it; no hold is ErrHoldNotFound.
	ReleaseHold(ctx context.Context, orgID, releasedBy string, beforeCommit func(*pb.LegalHold) error) (*pb.LegalHold, error)
}

// ValidateWindows checks a SetPolicy request and returns it as class -> days.
func ValidateWindows(ws []*pb.RetentionWindow) (map[pb.RetentionClass]int32, error) {
	if len(ws) == 0 {
		return nil, fmt.Errorf("%w: no class to set", ErrInvalid)
	}
	out := make(map[pb.RetentionClass]int32, len(ws))
	for _, w := range ws {
		if _, known := defaultDays[w.GetClass()]; !known {
			return nil, fmt.Errorf("%w: unknown class %v", ErrInvalid, w.GetClass())
		}
		if _, dup := out[w.GetClass()]; dup {
			return nil, fmt.Errorf("%w: class %v listed twice", ErrInvalid, w.GetClass())
		}
		if w.GetDays() < 1 || w.GetDays() > MaxDays {
			return nil, fmt.Errorf("%w: %v days must be between 1 and %d, got %d", ErrInvalid, w.GetClass(), MaxDays, w.GetDays())
		}
		out[w.GetClass()] = w.GetDays()
	}
	return out, nil
}

// MaxDays is the longest window (100 years). It keeps days*24h far below
// time.Duration's limit (about 106,751 days), so a sweeper computing a
// cutoff can never wrap around and treat every record as expired. The
// Postgres store enforces it with a CHECK too.
const MaxDays int32 = 36500

// NormalizeHold checks the org id (and the reason, unless it is a release)
// and returns the org id trimmed, so " org-a" and "org-a" are one org.
func NormalizeHold(orgID, reason string, needReason bool) (string, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return "", fmt.Errorf("%w: org id is required", ErrInvalid)
	}
	// The REST routes carry the org in one path segment, where a slash
	// cannot travel; such a hold could never be released over REST.
	if strings.Contains(orgID, "/") {
		return "", fmt.Errorf("%w: org id %q contains a slash", ErrInvalid, orgID)
	}
	if needReason && strings.TrimSpace(reason) == "" {
		return "", fmt.Errorf("%w: a reason is required", ErrInvalid)
	}
	return orgID, nil
}

// BuildPolicy renders the stored windows (set) as a full policy. Exported
// for the Postgres store.
func BuildPolicy(set map[pb.RetentionClass]int32, revision int64, updatedAt *time.Time, updatedBy string) *pb.RetentionPolicy {
	p := &pb.RetentionPolicy{Revision: revision, UpdatedBy: updatedBy}
	if updatedAt != nil {
		p.UpdatedAt = timestamppb.New(*updatedAt)
	}
	for _, c := range Classes() {
		d, ok := set[c]
		if !ok {
			d = defaultDays[c]
		}
		p.Windows = append(p.Windows, &pb.RetentionWindow{Class: c, Days: d, IsDefault: !ok})
	}
	return p
}

// Now is the store clock, truncated to what Postgres keeps.
func Now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// MemoryStore is the in-process store for a daemon without a database and
// for tests. It does not survive a restart.
type MemoryStore struct {
	mu        sync.Mutex
	set       map[pb.RetentionClass]int32
	revision  int64
	updatedAt *time.Time
	updatedBy string
	holds     map[string]*pb.LegalHold
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{set: map[pb.RetentionClass]int32{}, holds: map[string]*pb.LegalHold{}}
}

func (m *MemoryStore) GetPolicy(context.Context) (*pb.RetentionPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return BuildPolicy(m.set, m.revision, m.updatedAt, m.updatedBy), nil
}

func (m *MemoryStore) SetPolicy(_ context.Context, ws []*pb.RetentionWindow, updatedBy string, beforeCommit func(*PolicySetResult) error) (*PolicySetResult, error) {
	changes, err := ValidateWindows(ws)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	next := make(map[pb.RetentionClass]int32, len(m.set)+len(changes))
	for c, d := range m.set {
		next[c] = d
	}
	for c, d := range changes {
		next[c] = d
	}
	now := Now()
	res := &PolicySetResult{
		Previous: BuildPolicy(m.set, m.revision, m.updatedAt, m.updatedBy),
		Current:  BuildPolicy(next, m.revision+1, &now, updatedBy),
	}
	if beforeCommit != nil {
		if err := beforeCommit(res); err != nil {
			return nil, err
		}
	}
	m.set, m.revision, m.updatedAt, m.updatedBy = next, m.revision+1, &now, updatedBy
	return res, nil
}

func (m *MemoryStore) ListHolds(context.Context) ([]*pb.LegalHold, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*pb.LegalHold, 0, len(m.holds))
	for _, h := range m.holds {
		out = append(out, proto.Clone(h).(*pb.LegalHold))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetOrgId() < out[j].GetOrgId() })
	return out, nil
}

func (m *MemoryStore) SetHold(_ context.Context, orgID, reason, setBy string, beforeCommit func(*pb.LegalHold) error) (*pb.LegalHold, error) {
	orgID, err := NormalizeHold(orgID, reason, true)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.holds[orgID]; ok {
		return nil, ErrHoldExists
	}
	h := &pb.LegalHold{OrgId: orgID, Reason: reason, SetBy: setBy, SetAt: timestamppb.New(Now())}
	if beforeCommit != nil {
		if err := beforeCommit(h); err != nil {
			return nil, err
		}
	}
	m.holds[orgID] = h
	return proto.Clone(h).(*pb.LegalHold), nil
}

func (m *MemoryStore) ReleaseHold(_ context.Context, orgID, _ string, beforeCommit func(*pb.LegalHold) error) (*pb.LegalHold, error) {
	orgID, err := NormalizeHold(orgID, "", false)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.holds[orgID]
	if !ok {
		return nil, ErrHoldNotFound
	}
	if beforeCommit != nil {
		if err := beforeCommit(h); err != nil {
			return nil, err
		}
	}
	delete(m.holds, orgID)
	return proto.Clone(h).(*pb.LegalHold), nil
}
