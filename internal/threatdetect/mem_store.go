package threatdetect

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// memFindingRingCap bounds the degraded-mode store so a sustained attack
// with Postgres down can't grow it without limit — a bounded in-memory ring,
// per the design doc.
const memFindingRingCap = 1000

// dedupeKey mirrors the security_findings_open_dedupe partial unique index:
// an open finding is keyed by (rule, tenant, subject).
type dedupeKey struct {
	rule    string
	tenant  string
	subject string
}

// MemFindingStore is the DEGRADED-mode FindingSink used when Postgres isn't
// available: findings still flow to the event bus and the audit hash chain
// (the same emitter/audit dependencies FindingStore uses), backed by a
// bounded in-memory ring instead of persisted rows. Findings here do NOT
// survive a daemon restart — GetSentryStatus reports DEGRADED so an operator
// knows detection is running without persistence, rather than silently
// looking identical to the healthy path.
type MemFindingStore struct {
	emitter  *events.Emitter
	audit    *audit.Store
	notifier Notifier // nil = no webhook delivery

	mu     sync.Mutex
	nextID int64
	byKey  map[dedupeKey]*Finding // open findings only
	ring   []*Finding             // insertion order, capped at memFindingRingCap
}

// SetNotifier wires webhook delivery (#1643) — see FindingStore.SetNotifier.
func (s *MemFindingStore) SetNotifier(notifier Notifier) {
	s.notifier = notifier
}

// NewMemFindingStore builds a degraded-mode store. Both dependencies are
// required, matching NewFindingStore — a degraded store that could silently
// skip the event or the audit entry would defeat the point of falling back
// to it instead of refusing to run.
func NewMemFindingStore(emitter *events.Emitter, auditStore *audit.Store) (*MemFindingStore, error) {
	if emitter == nil {
		return nil, fmt.Errorf("threatdetect: emitter is required")
	}
	if auditStore == nil {
		return nil, fmt.Errorf("threatdetect: auditStore is required")
	}
	return &MemFindingStore{emitter: emitter, audit: auditStore, byKey: make(map[dedupeKey]*Finding)}, nil
}

// Upsert dedupes an open (rule, tenant_id, subject) finding exactly like
// FindingStore.Upsert, without Postgres.
func (s *MemFindingStore) Upsert(ctx context.Context, f *Finding) (*Finding, error) {
	now := time.Now()
	key := dedupeKey{rule: f.Rule.String(), tenant: f.TenantID, subject: f.Subject}

	s.mu.Lock()
	existing, ok := s.byKey[key]
	var out *Finding
	var rollback func()
	if ok && existing.State == FindingStateOpen {
		prevCount, prevLastSeen, prevEvidence := existing.Count, existing.LastSeen, existing.Evidence
		existing.Count++
		existing.LastSeen = now
		existing.Evidence = Evidence{
			Flows:  append(append([]FlowEvidence(nil), existing.Evidence.Flows...), f.Evidence.Flows...),
			Denies: append(append([]DenyEvidence(nil), existing.Evidence.Denies...), f.Evidence.Denies...),
		}.Capped()
		out = existing
		rollback = func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			existing.Count, existing.LastSeen, existing.Evidence = prevCount, prevLastSeen, prevEvidence
		}
	} else {
		s.nextID++
		f.ID = s.nextID
		f.FirstSeen, f.LastSeen = now, now
		f.State = FindingStateOpen
		f.Count = 1
		f.Evidence = f.Evidence.Capped()
		s.byKey[key] = f
		s.ring = append(s.ring, f)
		if len(s.ring) > memFindingRingCap {
			evicted := s.ring[0]
			s.ring = s.ring[1:]
			evictedKey := dedupeKey{rule: evicted.Rule.String(), tenant: evicted.TenantID, subject: evicted.Subject}
			if s.byKey[evictedKey] == evicted {
				delete(s.byKey, evictedKey)
			}
		}
		out = f
		rollback = func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.byKey[key] == f {
				delete(s.byKey, key)
			}
			// The ring entry is left in place: it's never read by key, so an
			// orphaned entry there is harmless, and removing it would shift
			// every later index for no benefit.
		}
	}
	s.mu.Unlock()

	detail := fmt.Sprintf("rule=%s severity=%s tenant=%s subject=%s count=%d", out.Rule, out.Severity, out.TenantID, out.Subject, out.Count)
	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Action:       "create",
		ResourceType: auditResourceType,
		ResourceID:   fmt.Sprintf("%d", out.ID),
		Detail:       detail,
	}); err != nil {
		rollback()
		return nil, fmt.Errorf("threatdetect: audit log finding (degraded mode): %w", err)
	}
	s.emitter.EmitSecurityFinding(out.ToProto())
	if s.notifier != nil {
		s.notifier.Notify(out)
	}
	return out, nil
}

// Get returns the finding with the given id (mirrors FindingStore.Get).
func (s *MemFindingStore) Get(ctx context.Context, id int64) (*Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.ring {
		if f.ID == id {
			return f, nil
		}
	}
	return nil, fmt.Errorf("threatdetect: finding %d: %w", id, ErrFindingNotFound)
}

// List returns findings matching filter, ordered most-recently-seen first
// (mirrors FindingStore.List — same ListFilter, same zero-value semantics).
func (s *MemFindingStore) List(ctx context.Context, filter ListFilter) ([]*Finding, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	matches := make([]*Finding, 0, len(s.ring))
	for _, f := range s.ring {
		if filter.Severity != pb.ThreatSeverity_THREAT_SEVERITY_UNSPECIFIED && f.Severity != filter.Severity {
			continue
		}
		if filter.TenantID != "" && f.TenantID != filter.TenantID {
			continue
		}
		if !filter.Since.IsZero() && f.LastSeen.Before(filter.Since) {
			continue
		}
		if filter.State != "" && f.State != filter.State {
			continue
		}
		matches = append(matches, f)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].LastSeen.After(matches[j].LastSeen) })
	if len(matches) > limit {
		matches = matches[:limit]
	}
	return matches, nil
}

// Resolve transitions a finding to FindingStateResolved (mirrors
// FindingStore.Resolve, including the ErrFindingNotOpen distinction between
// "no such finding" and "already resolved").
func (s *MemFindingStore) Resolve(ctx context.Context, id int64) (*Finding, error) {
	s.mu.Lock()
	var f *Finding
	for _, cand := range s.ring {
		if cand.ID == id {
			f = cand
			break
		}
	}
	if f == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("threatdetect: finding %d: %w", id, ErrFindingNotFound)
	}
	if f.State != FindingStateOpen {
		s.mu.Unlock()
		return nil, fmt.Errorf("threatdetect: finding %d is not open (state=%s): %w", id, f.State, ErrFindingNotOpen)
	}
	f.State = FindingStateResolved
	key := dedupeKey{rule: f.Rule.String(), tenant: f.TenantID, subject: f.Subject}
	if s.byKey[key] == f {
		delete(s.byKey, key)
	}
	s.mu.Unlock()

	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Action:       "resolve",
		ResourceType: auditResourceType,
		ResourceID:   fmt.Sprintf("%d", f.ID),
		Detail:       fmt.Sprintf("rule=%s tenant=%s subject=%s", f.Rule, f.TenantID, f.Subject),
	}); err != nil {
		log.Printf("threatdetect: audit log resolve for finding %d (degraded mode): %v", f.ID, err)
	}
	s.emitter.EmitSecurityFinding(f.ToProto())
	return f, nil
}
