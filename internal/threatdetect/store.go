package threatdetect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// pgUniqueViolation is Postgres' SQLSTATE for a unique-constraint conflict —
// what Upsert's INSERT branch hits if two callers race to create the first
// open finding for the same (rule, tenant_id, subject) key at once (the
// FOR UPDATE lock below only serializes callers once a row exists).
const pgUniqueViolation = "23505"

// auditResourceType is the audit_logs.resource_type value every finding is
// logged under, per the design doc's "category security.finding".
const auditResourceType = "security.finding"

// FindingStore persists security findings to Postgres. Every insert also (a)
// emits EVENT_TYPE_SECURITY_FINDING on the event bus and (b) writes an entry
// into the tamper-evident audit hash chain — findings ride the existing
// chain rather than growing new chain code.
type FindingStore struct {
	pool     *pgxpool.Pool
	emitter  *events.Emitter
	audit    *audit.Store
	notifier Notifier // nil = no webhook delivery (e.g. #1639/#1640 tests)
}

// SetNotifier wires webhook delivery (#1643): every finding this store
// writes from here on is handed to notifier.Notify after the event/audit
// write succeeds. nil is valid (no delivery) and is the zero-value default.
func (s *FindingStore) SetNotifier(notifier Notifier) {
	s.notifier = notifier
}

// NewFindingStore creates a finding store sharing the given pool, emitting
// through emitter and logging through auditStore. Both dependencies are
// required: a store that could silently skip the event or the audit entry
// would violate the #1639 acceptance criteria (findings are queryable,
// streamable, and tamper-evident — not log lines) for every finding it
// wrote, not just some.
func NewFindingStore(ctx context.Context, pool *pgxpool.Pool, emitter *events.Emitter, auditStore *audit.Store) (*FindingStore, error) {
	if emitter == nil {
		return nil, fmt.Errorf("threatdetect: emitter is required")
	}
	if auditStore == nil {
		return nil, fmt.Errorf("threatdetect: auditStore is required")
	}
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
		ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS response JSONB;
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

	// Audit before emit, and roll back the row on an audit failure: a
	// finding that reached subscribers but never made the tamper-evident
	// chain — or that sits in security_findings with no audit trail at
	// all — is exactly the "log line nobody watches" gap #1639 exists to
	// close. audit.Store.Log manages its own transaction against its own
	// pool checkout, so this can't be one shared DB transaction without
	// changing that package's API (out of scope — "use it as-is" per the
	// design doc); a compensating delete gives the same guarantee an
	// operator cares about: no finding is ever visible without an audit
	// entry backing it.
	detail, err := json.Marshal(f.Evidence)
	if err != nil {
		s.deleteOrphan(ctx, f.ID)
		return nil, fmt.Errorf("threatdetect: marshal audit detail: %w", err)
	}
	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Action:       "create",
		ResourceType: auditResourceType,
		ResourceID:   fmt.Sprintf("%d", f.ID),
		Detail:       fmt.Sprintf("rule=%s severity=%s tenant=%s subject=%s evidence=%s", f.Rule, f.Severity, f.TenantID, f.Subject, detail),
	}); err != nil {
		s.deleteOrphan(ctx, f.ID)
		return nil, fmt.Errorf("threatdetect: audit log finding: %w", err)
	}

	s.emitter.EmitSecurityFinding(f.ToProto())
	if s.notifier != nil {
		s.notifier.Notify(f)
	}

	return f, nil
}

// deleteOrphan removes a finding row whose audit entry failed to write, so a
// finding is never left visible without an audit trail backing it. Best
// effort: if the delete itself fails there is nothing further to compensate
// with, so it only logs.
func (s *FindingStore) deleteOrphan(ctx context.Context, id int64) {
	if _, err := s.pool.Exec(ctx, `DELETE FROM security_findings WHERE id = $1`, id); err != nil {
		log.Printf("threatdetect: failed to roll back orphaned finding %d after an audit-log failure: %v", id, err)
	}
}

// Upsert dedupes an open (rule, tenant_id, subject) finding: a repeat
// increments count and bumps last_seen (merging evidence, capped) instead of
// creating a new row. This is the detection engine's entry point (#1640) —
// Insert always creates a new row (#1639's job) and is unaffected.
//
// On the caller-supplied f: Rule, Severity, TenantID, Container, BackendID,
// Subject, and Evidence are read; ID/State/Count/FirstSeen/LastSeen are
// ignored (set by this method) except that a caller-supplied Evidence is
// merged into (not replacing) an existing open finding's evidence.
func (s *FindingStore) Upsert(ctx context.Context, f *Finding) (*Finding, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		out, retry, err := s.tryUpsert(ctx, f)
		if !retry {
			return out, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("threatdetect: upsert finding: exhausted retries after a concurrent insert race: %w", lastErr)
}

// tryUpsert is one attempt at Upsert. retry is true only when a concurrent
// caller won the race to insert the first row for this key between our
// SELECT and our INSERT — Upsert retries that case (it becomes a plain
// update on the next attempt) rather than surfacing a transient conflict as
// a permanent error.
func (s *FindingStore) tryUpsert(ctx context.Context, f *Finding) (out *Finding, retry bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("threatdetect: begin upsert: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	now := time.Now()
	row := tx.QueryRow(ctx, `
		SELECT id, count, evidence, severity, response
		FROM security_findings
		WHERE rule = $1 AND tenant_id = $2 AND subject = $3 AND state = 'open'
		FOR UPDATE
	`, f.Rule.String(), f.TenantID, f.Subject)

	var id, count int64
	var evidenceJSON, responseJSON []byte
	var storedSeverity string
	selErr := row.Scan(&id, &count, &evidenceJSON, &storedSeverity, &responseJSON)

	switch {
	case selErr == nil:
		var existing Evidence
		if uerr := json.Unmarshal(evidenceJSON, &existing); uerr != nil {
			return nil, false, fmt.Errorf("threatdetect: unmarshal existing evidence: %w", uerr)
		}
		merged := existing.merged(f.Evidence).Capped()
		mergedJSON, merr := json.Marshal(merged)
		if merr != nil {
			return nil, false, fmt.Errorf("threatdetect: marshal merged evidence: %w", merr)
		}
		newCount := count + 1
		severity := maxSeverity(pb.ThreatSeverity(pb.ThreatSeverity_value[storedSeverity]), f.Severity)
		if _, uerr := tx.Exec(ctx, `
			UPDATE security_findings SET count = $1, last_seen = $2, evidence = $3, severity = $4 WHERE id = $5
		`, newCount, now, mergedJSON, severity.String(), id); uerr != nil {
			return nil, false, fmt.Errorf("threatdetect: update finding: %w", uerr)
		}
		out = &Finding{
			ID: id, Rule: f.Rule, Severity: severity, TenantID: f.TenantID,
			Container: f.Container, BackendID: f.BackendID, Subject: f.Subject,
			State: FindingStateOpen, Count: newCount, Evidence: merged, LastSeen: now,
		}
		// Carry the stored response back so the process responder's
		// dedupe sees what it already did about this finding (#2636).
		if out.Response, err = unmarshalResponse(responseJSON); err != nil {
			return nil, false, err
		}
	case errors.Is(selErr, pgx.ErrNoRows):
		f.FirstSeen, f.LastSeen = now, now
		f.State = FindingStateOpen
		f.Count = 1
		f.Evidence = f.Evidence.Capped()
		evJSON, merr := json.Marshal(f.Evidence)
		if merr != nil {
			return nil, false, fmt.Errorf("threatdetect: marshal evidence: %w", merr)
		}
		insertRow := tx.QueryRow(ctx, `
			INSERT INTO security_findings
				(rule, severity, tenant_id, container, backend_id, subject, state, count, evidence, first_seen, last_seen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			RETURNING id
		`, f.Rule.String(), f.Severity.String(), f.TenantID, f.Container, f.BackendID,
			f.Subject, string(f.State), f.Count, evJSON, f.FirstSeen, f.LastSeen)
		if serr := insertRow.Scan(&f.ID); serr != nil {
			var pgErr *pgconn.PgError
			if errors.As(serr, &pgErr) && pgErr.Code == pgUniqueViolation {
				return nil, true, serr // lost the race — caller retries as an update
			}
			return nil, false, fmt.Errorf("threatdetect: insert finding: %w", serr)
		}
		out = f
	default:
		return nil, false, fmt.Errorf("threatdetect: select existing finding: %w", selErr)
	}

	if cerr := tx.Commit(ctx); cerr != nil {
		return nil, false, fmt.Errorf("threatdetect: commit upsert: %w", cerr)
	}
	committed = true

	// Audit + emit after commit, mirroring Insert's ordering and compensation:
	// a finding must never be visible to a subscriber or missing from the
	// audit chain relative to each other. Unlike Insert, an update-path
	// failure here can't be compensated by deleting the row (it predates this
	// call and already carries an audit trail from its creation) — best
	// effort is logging; the row's count/evidence still correctly reflect
	// what happened, only missing one audit entry for THIS repeat.
	detail, merr := json.Marshal(out.Evidence)
	if merr != nil {
		log.Printf("threatdetect: marshal audit detail for finding %d: %v", out.ID, merr)
		return out, false, nil
	}
	auditErr := s.audit.Log(ctx, &audit.AuditEntry{
		Action:       "create",
		ResourceType: auditResourceType,
		ResourceID:   fmt.Sprintf("%d", out.ID),
		Detail:       fmt.Sprintf("rule=%s severity=%s tenant=%s subject=%s count=%d evidence=%s", out.Rule, out.Severity, out.TenantID, out.Subject, out.Count, detail),
	})
	if auditErr != nil {
		if out.Count == 1 {
			// First-seen row: same guarantee Insert gives — no finding is ever
			// left visible without an audit trail backing it.
			s.deleteOrphan(ctx, out.ID)
		}
		return nil, false, fmt.Errorf("threatdetect: audit log finding: %w", auditErr)
	}
	s.emitter.EmitSecurityFinding(out.ToProto())
	if s.notifier != nil {
		s.notifier.Notify(out)
	}
	return out, false, nil
}

// Get returns the finding with the given id.
func (s *FindingStore) Get(ctx context.Context, id int64) (*Finding, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, rule, severity, tenant_id, container, backend_id, subject,
		       state, count, evidence, first_seen, last_seen, response
		FROM security_findings WHERE id = $1
	`, id)
	return scanFinding(row)
}

// List returns findings matching filter, ordered by most recently seen
// first. See ListFilter for the zero-value ("no filter") semantics of each
// field.
func (s *FindingStore) List(ctx context.Context, filter ListFilter) ([]*Finding, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `
		SELECT id, rule, severity, tenant_id, container, backend_id, subject,
		       state, count, evidence, first_seen, last_seen, response
		FROM security_findings
		WHERE 1 = 1
	`
	var args []any
	if filter.Severity != pb.ThreatSeverity_THREAT_SEVERITY_UNSPECIFIED {
		args = append(args, filter.Severity.String())
		query += fmt.Sprintf(" AND severity = $%d", len(args))
	}
	if filter.TenantID != "" {
		args = append(args, filter.TenantID)
		query += fmt.Sprintf(" AND tenant_id = $%d", len(args))
	}
	if !filter.Since.IsZero() {
		args = append(args, filter.Since)
		query += fmt.Sprintf(" AND last_seen >= $%d", len(args))
	}
	if filter.State != "" {
		args = append(args, string(filter.State))
		query += fmt.Sprintf(" AND state = $%d", len(args))
	}
	if filter.Rule != pb.ThreatRuleId_THREAT_RULE_ID_UNSPECIFIED {
		args = append(args, filter.Rule.String())
		query += fmt.Sprintf(" AND rule = $%d", len(args))
	}
	if filter.BackendID != "" {
		args = append(args, filter.BackendID)
		query += fmt.Sprintf(" AND backend_id = $%d", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY last_seen DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
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

// Resolve transitions a finding to FindingStateResolved. Also emits an
// updated event and an audit entry (action "resolve") — a resolution is
// itself an auditable operator action, same as create.
func (s *FindingStore) Resolve(ctx context.Context, id int64) (*Finding, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE security_findings SET state = 'resolved' WHERE id = $1 AND state = 'open'`, id)
	if err != nil {
		return nil, fmt.Errorf("threatdetect: resolve finding %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		// Distinguish "no such finding" from "already resolved" for the
		// caller (server maps the two to NotFound vs FailedPrecondition).
		existing, gerr := s.Get(ctx, id)
		if gerr != nil {
			return nil, gerr
		}
		return nil, fmt.Errorf("threatdetect: finding %d is not open (state=%s): %w", id, existing.State, ErrFindingNotOpen)
	}
	f, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	s.resolved(ctx, f, f)
	return f, nil
}

// resolved audits, emits and delivers a resolve: delivery is the finding
// the webhook gets (once: the resolution, #2643).
func (s *FindingStore) resolved(ctx context.Context, f, delivery *Finding) {
	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Action:       "resolve",
		ResourceType: auditResourceType,
		ResourceID:   fmt.Sprintf("%d", f.ID),
		Detail:       fmt.Sprintf("rule=%s tenant=%s subject=%s", f.Rule, f.TenantID, f.Subject),
	}); err != nil {
		log.Printf("threatdetect: audit log resolve for finding %d: %v", f.ID, err)
	}
	s.emitter.EmitSecurityFinding(f.ToProto())
	if s.notifier != nil {
		s.notifier.Notify(delivery)
	}
}

// stickyResponseSQL is the response column's new value for a write of $1
// (#2766): $1 as given, except that a kill on record survives a write that
// carries none, or carries an older one with a lower kill count (#2816: a
// stale fallback never rolls the count back). The kill on record is kept
// whole (process_killed, the latest pid, the count and the skip reason, or
// the lack of one), exactly as FindingResponse.KeepKillOf does for the
// in-memory store. One expression, so two writers cannot lose it; every
// response write uses it.
const stickyResponseSQL = `CASE
			WHEN COALESCE((response->>'process_killed')::boolean, FALSE)
				AND (NOT COALESCE(($1::jsonb->>'process_killed')::boolean, FALSE)
					OR COALESCE(($1::jsonb->>'kills')::bigint, 0) < COALESCE((response->>'kills')::bigint, 0))
				THEN ($1::jsonb - 'killed_pid' - 'kills' - 'kill_skip_reason') || jsonb_strip_nulls(jsonb_build_object(
					'process_killed', TRUE,
					'killed_pid', response->'killed_pid',
					'kills', response->'kills',
					'kill_skip_reason', response->'kill_skip_reason'))
			ELSE $1::jsonb
		END`

// SetResponse records what the process responder did about finding id
// (#2636) and emits the updated finding. The audit entry for the action
// itself is the responder's (category security.action); this only updates
// the finding row. The kill facts are sticky: once a kill is on record for
// the finding, every later response that carries no newer kill keeps it
// whole (see stickyResponseSQL), whichever path (release, expiry, a later
// box's action on a shared finding) rewrites the rest. That happens in the
// UPDATE itself, so two writers cannot lose it.
func (s *FindingStore) SetResponse(ctx context.Context, id int64, r FindingResponse) (*Finding, error) {
	return s.setResponse(ctx, id, r, r)
}

// SetResponseHeld stores standing as the finding's response and delivers
// box (#2820): a box released, expired or failed while another box of the
// shared finding still holds an applied action.
func (s *FindingStore) SetResponseHeld(ctx context.Context, id int64, box, standing FindingResponse) (*Finding, error) {
	return s.setResponse(ctx, id, standing, box)
}

func (s *FindingStore) setResponse(ctx context.Context, id int64, stored, box FindingResponse) (*Finding, error) {
	raw, err := json.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("threatdetect: marshal finding response: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE security_findings SET response = `+stickyResponseSQL+` WHERE id = $2`, string(raw), id)
	if err != nil {
		return nil, fmt.Errorf("threatdetect: set response on finding %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("threatdetect: finding %d: %w", id, ErrFindingNotFound)
	}
	f, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	s.emitter.EmitSecurityFinding(f.ToProto())
	if s.notifier != nil {
		s.notifier.Notify(ResponseDelivery(f, box)) // a response transition is delivered (#2718), naming its box (#2820)
	}
	return f, nil
}

// ResolveWithResponse records r and resolves the finding in one UPDATE
// (#2820), audited and emitted like Resolve and delivered once, as the
// resolve carrying r. A finding that is no longer open still gets r
// (through SetResponse, delivered) and the error wraps ErrFindingNotOpen.
func (s *FindingStore) ResolveWithResponse(ctx context.Context, id int64, r FindingResponse) (*Finding, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("threatdetect: marshal finding response: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE security_findings SET response = `+stickyResponseSQL+`, state = 'resolved'
		WHERE id = $2 AND state = 'open'`, string(raw), id)
	if err != nil {
		return nil, fmt.Errorf("threatdetect: resolve finding %d with its response: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		f, serr := s.SetResponse(ctx, id, r)
		if serr != nil {
			return nil, serr
		}
		return f, fmt.Errorf("threatdetect: finding %d is not open (state=%s): %w", id, f.State, ErrFindingNotOpen)
	}
	f, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	s.resolved(ctx, f, ResponseDelivery(f, r))
	return f, nil
}

// unmarshalResponse decodes the nullable response column.
func unmarshalResponse(raw []byte) (*FindingResponse, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var r FindingResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("threatdetect: unmarshal finding response: %w", err)
	}
	return &r, nil
}

// rowScanner is the subset of pgx.Row / pgx.Rows that scanFinding needs.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanFinding(row rowScanner) (*Finding, error) {
	var f Finding
	var rule, severity, state string
	var evidenceJSON, responseJSON []byte
	err := row.Scan(&f.ID, &rule, &severity, &f.TenantID, &f.Container, &f.BackendID,
		&f.Subject, &state, &f.Count, &evidenceJSON, &f.FirstSeen, &f.LastSeen, &responseJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, fmt.Errorf("threatdetect: scan finding: %w", err)
	}
	f.Rule = pb.ThreatRuleId(pb.ThreatRuleId_value[rule])
	f.Severity = pb.ThreatSeverity(pb.ThreatSeverity_value[severity])
	f.State = FindingState(state)
	if err := json.Unmarshal(evidenceJSON, &f.Evidence); err != nil {
		return nil, fmt.Errorf("threatdetect: unmarshal evidence: %w", err)
	}
	if f.Response, err = unmarshalResponse(responseJSON); err != nil {
		return nil, err
	}
	return &f, nil
}
