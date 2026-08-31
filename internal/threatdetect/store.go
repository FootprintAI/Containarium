package threatdetect

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// auditResourceType is the audit_logs.resource_type value every finding is
// logged under, per the design doc's "category security.finding".
const auditResourceType = "security.finding"

// FindingStore persists security findings to Postgres. Every insert also (a)
// emits EVENT_TYPE_SECURITY_FINDING on the event bus and (b) writes an entry
// into the tamper-evident audit hash chain — findings ride the existing
// chain rather than growing new chain code.
type FindingStore struct {
	pool    *pgxpool.Pool
	emitter *events.Emitter
	audit   *audit.Store
}

// NewFindingStore creates a finding store sharing the given pool, emitting
// through emitter and logging through auditStore.
func NewFindingStore(ctx context.Context, pool *pgxpool.Pool, emitter *events.Emitter, auditStore *audit.Store) (*FindingStore, error) {
	s := &FindingStore{pool: pool, emitter: emitter, audit: auditStore}
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("threatdetect: init schema: %w", err)
	}
	return s, nil
}

func (s *FindingStore) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS security_findings (
			id           BIGSERIAL PRIMARY KEY,
			rule         TEXT        NOT NULL,
			severity     TEXT        NOT NULL,
			tenant_id    TEXT        NOT NULL,
			container    TEXT        NOT NULL DEFAULT '',
			backend_id   TEXT        NOT NULL DEFAULT '',
			subject      TEXT        NOT NULL,
			state        TEXT        NOT NULL DEFAULT 'open',
			count        BIGINT      NOT NULL DEFAULT 1,
			evidence     JSONB       NOT NULL,
			first_seen   TIMESTAMPTZ NOT NULL,
			last_seen    TIMESTAMPTZ NOT NULL
		);
		CREATE UNIQUE INDEX IF NOT EXISTS security_findings_open_dedupe
			ON security_findings (rule, tenant_id, subject) WHERE state = 'open';
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Insert writes a new finding row, then emits it on the event bus and logs
// it into the audit hash chain. It assigns ID, FirstSeen, and LastSeen (a
// caller-supplied FirstSeen/LastSeen is honored if already set) and caps
// evidence to EvidenceCap entries per kind.
//
// Insert always creates a new row. The dedupe/upsert path that increments an
// existing open finding's count instead of inserting a duplicate is the
// detection engine's job (#1640) — the unique index above exists for that
// upsert's ON CONFLICT clause.
func (s *FindingStore) Insert(ctx context.Context, f *Finding) (*Finding, error) {
	now := time.Now()
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = f.FirstSeen
	}
	if f.State == "" {
		f.State = FindingStateOpen
	}
	if f.Count == 0 {
		f.Count = 1
	}
	f.Evidence = f.Evidence.Capped()

	evidenceJSON, err := json.Marshal(f.Evidence)
	if err != nil {
		return nil, fmt.Errorf("threatdetect: marshal evidence: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO security_findings
			(rule, severity, tenant_id, container, backend_id, subject, state, count, evidence, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`,
		f.Rule.String(), f.Severity.String(), f.TenantID, f.Container, f.BackendID,
		f.Subject, string(f.State), f.Count, evidenceJSON, f.FirstSeen, f.LastSeen,
	)
	if err := row.Scan(&f.ID); err != nil {
		return nil, fmt.Errorf("threatdetect: insert finding: %w", err)
	}

	if s.emitter != nil {
		s.emitter.EmitSecurityFinding(f.ToProto())
	}
	if s.audit != nil {
		detail, _ := json.Marshal(f.Evidence)
		if err := s.audit.Log(ctx, &audit.AuditEntry{
			Action:       "create",
			ResourceType: auditResourceType,
			ResourceID:   fmt.Sprintf("%d", f.ID),
			Detail:       fmt.Sprintf("rule=%s severity=%s tenant=%s subject=%s evidence=%s", f.Rule, f.Severity, f.TenantID, f.Subject, detail),
		}); err != nil {
			return nil, fmt.Errorf("threatdetect: audit log finding: %w", err)
		}
	}

	return f, nil
}

// Get returns the finding with the given id.
func (s *FindingStore) Get(ctx context.Context, id int64) (*Finding, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, rule, severity, tenant_id, container, backend_id, subject,
		       state, count, evidence, first_seen, last_seen
		FROM security_findings WHERE id = $1
	`, id)
	return scanFinding(row)
}

// List returns findings ordered by most recently seen first, up to limit
// (default/cap 200).
func (s *FindingStore) List(ctx context.Context, limit int) ([]*Finding, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, rule, severity, tenant_id, container, backend_id, subject,
		       state, count, evidence, first_seen, last_seen
		FROM security_findings
		ORDER BY last_seen DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("threatdetect: list findings: %w", err)
	}
	defer rows.Close()

	var out []*Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("threatdetect: iterate findings: %w", err)
	}
	return out, nil
}

// rowScanner is the subset of pgx.Row / pgx.Rows that scanFinding needs.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanFinding(row rowScanner) (*Finding, error) {
	var f Finding
	var rule, severity, state string
	var evidenceJSON []byte
	err := row.Scan(&f.ID, &rule, &severity, &f.TenantID, &f.Container, &f.BackendID,
		&f.Subject, &state, &f.Count, &evidenceJSON, &f.FirstSeen, &f.LastSeen)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("threatdetect: scan finding: %w", err)
	}
	f.Rule = pb.ThreatRuleId(pb.ThreatRuleId_value[rule])
	f.Severity = pb.ThreatSeverity(pb.ThreatSeverity_value[severity])
	f.State = FindingState(state)
	if err := json.Unmarshal(evidenceJSON, &f.Evidence); err != nil {
		return nil, fmt.Errorf("threatdetect: unmarshal evidence: %w", err)
	}
	return &f, nil
}
