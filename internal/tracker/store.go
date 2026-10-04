package tracker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
)

// Connection is the storage-layer view of a TrackerConnection. Provider is
// the typed enum, not the DB's TEXT column — the string<->enum conversion
// happens at this store boundary (providerToString / providerFromString),
// per the "protobuf enums over magic strings" convention: every caller
// above this package sees pb.TrackerProvider, never a raw string.
type Connection struct {
	Username         string
	Name             string
	Provider         pb.TrackerProvider
	BaseURL          string
	Project          string
	CredentialSecret string
	// CredentialExpiresAt is surfaced, not enforced — populated
	// best-effort from the provider's own introspection of the
	// credential (DescribeCredential) at connect time and refreshed by
	// GetTrackerStatus. Zero means "unknown or no expiry", not "never
	// expires".
	CredentialExpiresAt time.Time
	// Policy is the connection's guardrails for agent-filed follow-ups
	// (#2024), stored as protojson in a JSONB column and read back
	// through the generated decoder. nil when the operator never set
	// one — callers apply the documented defaults via PolicyFromProto,
	// which treats nil and zero-valued identically.
	Policy    *pb.TrackerPolicy
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ErrNotFound is returned by Get / Delete when the (username, name) tuple
// has no row.
var ErrNotFound = errors.New("tracker: connection not found")

// Store handles per-tenant tracker-connection persistence. Holds no
// credential material itself — CredentialSecret only names a secret that
// lives in internal/secrets, in SECRET_DELIVERY_BROKER_ONLY mode; that
// cross-package validation happens in internal/server (this package has
// no dependency on internal/secrets).
type Store struct {
	pool *pgxpool.Pool
	// runGates serializes RecordChild's reservation step per run inside
	// this process, BEFORE a pool connection is taken, so same-run
	// creates queue without holding connections (#2044).
	runGates runGates
}

// NewStore opens the tracker-connections store, creating the table on
// first run. Idempotent on every subsequent call, same idiom as
// internal/secrets.NewStore. Safe to call from several processes at once
// (#2061): see initSchema.
func NewStore(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("tracker: pool is nil")
	}
	s := &Store{pool: pool}
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return s, nil
}

// schemaLockKey is the advisory-lock key concurrent initSchema calls
// serialize on — one constant for the whole tracker schema, hashed the
// same way as reserveChild's per-run key. It is only ever taken inside
// initSchema's transaction, so it costs nothing after startup.
const schemaLockKey = "tracker/schema"

// initSchema creates or upgrades the tracker tables, in one transaction
// under a transaction-scoped advisory lock (#2061).
//
// CREATE TABLE IF NOT EXISTS is not safe to race: it checks pg_class and
// then inserts the table's row type into pg_type, so two sessions that
// both passed the check collide on pg_type_typname_nsp_index (SQLSTATE
// 23505) and the loser's whole batch rolls back. Nothing in the first-run
// path serialized the sessions before that point: the upgrade path only
// looked safe because ALTER TABLE ... ADD COLUMN takes an ACCESS EXCLUSIVE
// lock on tracker_connections and holds it to the end of ITS implicit
// transaction, which covered the CREATE after it in the same batch — and
// nothing in the two batches that follow.
//
// So the lock has to cover every CREATE in every batch, not just the
// first-run one. Taking it once around the whole init does that: the
// winner creates everything, each later holder sees the tables committed
// and every statement becomes the no-op its IF NOT EXISTS promises. It
// is transaction-scoped, same as the lineage lock in reserveChild, so it
// releases at commit or rollback and never touches a query afterward;
// on an already-initialized database it adds one lock round trip to a
// path that runs once per process start.
func (s *Store) initSchema(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin schema transaction: %w", err)
	}
	// No-op after a successful Commit. Detached so a cancelled context
	// still releases the transaction (and with it the lock) cleanly.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, schemaLockKey); err != nil {
		return fmt.Errorf("lock schema: %w", err)
	}
	if err := applySchema(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit schema: %w", err)
	}
	return nil
}

// applySchema runs the three schema batches, in dependency order, on tx.
func applySchema(ctx context.Context, tx pgx.Tx) error {
	const schema = `
		CREATE TABLE IF NOT EXISTS tracker_connections (
			username          TEXT NOT NULL,
			name              TEXT NOT NULL,
			provider          TEXT NOT NULL CHECK (provider IN ('github', 'gitlab')),
			base_url          TEXT NOT NULL DEFAULT '',
			project           TEXT NOT NULL,
			credential_secret TEXT NOT NULL,
			created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (username, name)
		);

		-- #1921 step 3: added after initial release — idempotent
		-- ALTER, same idiom as internal/secrets.Store.initSchema.
		ALTER TABLE tracker_connections ADD COLUMN IF NOT EXISTS credential_expires_at TIMESTAMPTZ;

		-- #2024: connection policy (protojson of TrackerPolicy; NULL =
		-- never set = defaults).
		ALTER TABLE tracker_connections ADD COLUMN IF NOT EXISTS policy JSONB;

		-- #2024: which run filed which follow-up under which parent, and
		-- how deep. A human-created issue has no row (depth 0).
		CREATE TABLE IF NOT EXISTS tracker_issue_lineage (
			username       TEXT   NOT NULL,
			connection     TEXT   NOT NULL,
			child_number   BIGINT NOT NULL,
			parent_number  BIGINT NOT NULL,
			created_by_run TEXT   NOT NULL,
			depth          INT    NOT NULL,
			PRIMARY KEY (username, connection, child_number)
		);

		-- #2044: a fan-out slot claimed by an in-flight RecordChild whose
		-- upstream create has not finished yet. Counted with the lineage
		-- rows by the fan-out guard, so the upstream call can run with no
		-- transaction (and no pool connection) held. Deleted when the
		-- create fails or its lineage row is recorded.
		CREATE TABLE IF NOT EXISTS tracker_lineage_reservations (
			id             BIGSERIAL   PRIMARY KEY,
			username       TEXT        NOT NULL,
			connection     TEXT        NOT NULL,
			created_by_run TEXT        NOT NULL,
			created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS tracker_lineage_reservations_run
			ON tracker_lineage_reservations (username, connection, created_by_run);
	`
	if _, err := tx.Exec(ctx, schema); err != nil {
		return err
	}
	// #2021: scope routes hang off a connection by foreign key, so they
	// are created after tracker_connections.
	if _, err := tx.Exec(ctx, routeSchema); err != nil {
		return err
	}
	// #2022: dispatch rows and unrouted-scope warnings, also keyed off a
	// connection.
	_, err := tx.Exec(ctx, dispatchSchema)
	return err
}

// providerToString converts the typed enum to the DB's stored string.
// Rejects UNSPECIFIED (and anything else unrecognized) — provider is
// never inferred or defaulted, per the design note.
func providerToString(p pb.TrackerProvider) (string, error) {
	switch p {
	case pb.TrackerProvider_TRACKER_PROVIDER_GITHUB:
		return "github", nil
	case pb.TrackerProvider_TRACKER_PROVIDER_GITLAB:
		return "gitlab", nil
	default:
		return "", fmt.Errorf("tracker: provider must be GITHUB or GITLAB, got %v", p)
	}
}

// providerFromString is providerToString's inverse, used when reading a
// row back. An unrecognized string (should be unreachable given the CHECK
// constraint and providerToString gating every write) maps to
// UNSPECIFIED rather than guessing.
func providerFromString(s string) pb.TrackerProvider {
	switch s {
	case "github":
		return pb.TrackerProvider_TRACKER_PROVIDER_GITHUB
	case "gitlab":
		return pb.TrackerProvider_TRACKER_PROVIDER_GITLAB
	default:
		return pb.TrackerProvider_TRACKER_PROVIDER_UNSPECIFIED
	}
}

// Set creates or updates a tracker connection. Idempotent — repeated
// calls with the same (username, name) replace every field.
func (s *Store) Set(ctx context.Context, c Connection) (*Connection, error) {
	if c.Username == "" {
		return nil, errors.New("tracker: username is required")
	}
	if c.Name == "" {
		return nil, errors.New("tracker: name is required")
	}
	if c.Project == "" {
		return nil, errors.New("tracker: project is required")
	}
	if c.CredentialSecret == "" {
		return nil, errors.New("tracker: credential_secret is required")
	}
	providerStr, err := providerToString(c.Provider)
	if err != nil {
		return nil, err
	}

	policyJSON, err := policyToJSON(c.Policy)
	if err != nil {
		return nil, err
	}

	const q = `
		INSERT INTO tracker_connections (username, name, provider, base_url, project, credential_secret, policy)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (username, name) DO UPDATE SET
			provider          = EXCLUDED.provider,
			base_url          = EXCLUDED.base_url,
			project           = EXCLUDED.project,
			credential_secret = EXCLUDED.credential_secret,
			policy            = EXCLUDED.policy,
			updated_at        = NOW()
		RETURNING created_at, updated_at;
	`
	var createdAt, updatedAt time.Time
	if err := s.pool.QueryRow(ctx, q, c.Username, c.Name, providerStr, c.BaseURL, c.Project, c.CredentialSecret, policyJSON).
		Scan(&createdAt, &updatedAt); err != nil {
		return nil, fmt.Errorf("upsert tracker connection: %w", err)
	}
	out := c
	out.CreatedAt = createdAt
	out.UpdatedAt = updatedAt
	return &out, nil
}

// SetCredentialExpiry updates only credential_expires_at, leaving every
// other field untouched. Separate from Set because expiry is never
// client-supplied — the server calls this after a successful
// DescribeCredential, best-effort, so a describe failure (or the
// tracker being briefly unreachable) never blocks SetTrackerConnection
// itself. A zero expiresAt clears the column (NULL) rather than storing
// the zero time, matching "unknown" rather than a specific past instant.
func (s *Store) SetCredentialExpiry(ctx context.Context, username, name string, expiresAt time.Time) error {
	if username == "" {
		return errors.New("tracker: username is required")
	}
	var arg *time.Time
	if !expiresAt.IsZero() {
		arg = &expiresAt
	}
	const q = `UPDATE tracker_connections SET credential_expires_at = $1 WHERE username = $2 AND name = $3`
	tag, err := s.pool.Exec(ctx, q, arg, username, name)
	if err != nil {
		return fmt.Errorf("update credential expiry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Get returns a single named connection. ErrNotFound if it doesn't exist
// for this tenant — a connection named by another tenant never matches,
// since the lookup is always scoped by username.
func (s *Store) Get(ctx context.Context, username, name string) (*Connection, error) {
	if username == "" {
		return nil, errors.New("tracker: username is required")
	}
	const q = `
		SELECT provider, base_url, project, credential_secret, credential_expires_at, policy, created_at, updated_at
		FROM tracker_connections
		WHERE username = $1 AND name = $2
	`
	var providerStr, baseURL, project, credSecret string
	var credentialExpiresAt *time.Time
	var policyJSON []byte
	var createdAt, updatedAt time.Time
	if err := s.pool.QueryRow(ctx, q, username, name).
		Scan(&providerStr, &baseURL, &project, &credSecret, &credentialExpiresAt, &policyJSON, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("select tracker connection: %w", err)
	}
	c := &Connection{
		Username:         username,
		Name:             name,
		Provider:         providerFromString(providerStr),
		BaseURL:          baseURL,
		Project:          project,
		CredentialSecret: credSecret,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
	}
	if credentialExpiresAt != nil {
		c.CredentialExpiresAt = *credentialExpiresAt
	}
	policy, err := policyFromJSON(policyJSON)
	if err != nil {
		return nil, err
	}
	c.Policy = policy
	return c, nil
}

// policyToJSON encodes a policy as protojson for the JSONB column; nil
// stores NULL rather than "{}" so "never set" stays distinguishable
// from "set to defaults" in the row (both behave the same).
func policyToJSON(p *pb.TrackerPolicy) (*string, error) {
	if p == nil {
		return nil, nil
	}
	b, err := protojson.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("tracker: encode policy: %w", err)
	}
	s := string(b)
	return &s, nil
}

// policyFromJSON is policyToJSON's inverse, through the generated
// decoder — never map[string]interface{}. Unknown fields are discarded
// so a row written by a newer daemon still reads on an older one.
func policyFromJSON(raw []byte) (*pb.TrackerPolicy, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	p := &pb.TrackerPolicy{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, p); err != nil {
		return nil, fmt.Errorf("tracker: decode policy: %w", err)
	}
	return p, nil
}

// List returns every connection owned by the tenant, ordered by name.
func (s *Store) List(ctx context.Context, username string) ([]Connection, error) {
	if username == "" {
		return nil, errors.New("tracker: username is required")
	}
	const q = `
		SELECT name, provider, base_url, project, credential_secret, credential_expires_at, policy, created_at, updated_at
		FROM tracker_connections
		WHERE username = $1
		ORDER BY name
	`
	rows, err := s.pool.Query(ctx, q, username)
	if err != nil {
		return nil, fmt.Errorf("list tracker connections: %w", err)
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		var c Connection
		var providerStr string
		var credentialExpiresAt *time.Time
		var policyJSON []byte
		c.Username = username
		if err := rows.Scan(&c.Name, &providerStr, &c.BaseURL, &c.Project, &c.CredentialSecret, &credentialExpiresAt, &policyJSON, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan tracker connection row: %w", err)
		}
		c.Provider = providerFromString(providerStr)
		if credentialExpiresAt != nil {
			c.CredentialExpiresAt = *credentialExpiresAt
		}
		if c.Policy, err = policyFromJSON(policyJSON); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tracker connection rows: %w", err)
	}
	return out, nil
}

// Delete removes a single connection. Does not touch the credential
// secret it referenced. Returns ErrNotFound if no such row existed.
func (s *Store) Delete(ctx context.Context, username, name string) error {
	if username == "" {
		return errors.New("tracker: username is required")
	}
	const q = `DELETE FROM tracker_connections WHERE username = $1 AND name = $2`
	tag, err := s.pool.Exec(ctx, q, username, name)
	if err != nil {
		return fmt.Errorf("delete tracker connection: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- issue lineage (#2024) -------------------------------------------
//
// tracker_issue_lineage records which run filed which follow-up under
// which parent, and at what depth. A human-created issue has no row and
// is depth 0 by definition. The dispatcher (#2022/#2025) reads depth
// before starting a run; CreateTrackerIssue writes rows through
// RecordChild, which enforces the depth and per-run fan-out caps in the
// same transaction as the insert.

// Lineage is one tracker_issue_lineage row.
type Lineage struct {
	Username     string
	Connection   string
	ChildNumber  int64
	ParentNumber int64
	CreatedByRun string
	Depth        int32
}

var (
	// ErrDepthExceeded: the child would sit deeper than max_depth.
	ErrDepthExceeded = errors.New("tracker: follow-up chain depth exceeded")
	// ErrFanoutExceeded: the run has already filed max_children_per_run
	// follow-ups.
	ErrFanoutExceeded = errors.New("tracker: run has reached its max_children_per_run")
)

// IssueDepth returns the recorded depth of an issue — 0 when it has no
// lineage row (a human-created issue).
func (s *Store) IssueDepth(ctx context.Context, username, connection string, number int64) (int32, error) {
	return issueDepth(ctx, s.pool, username, connection, number)
}

// ChildrenCount returns how many follow-ups runID has filed on this
// connection.
func (s *Store) ChildrenCount(ctx context.Context, username, connection, runID string) (int32, error) {
	return childrenCount(ctx, s.pool, username, connection, runID)
}

// IssueInRunLineage reports whether issue number is within runID's own
// lineage on this connection (#2060): the issue the dispatcher started
// runID for (a tracker_dispatches row with that run_id, in any state), or
// a follow-up runID filed itself (a tracker_issue_lineage row with
// created_by_run = runID). An empty runID is in no lineage — dispatch
// rows default run_id to the empty string. A child whose lineage row
// failed to record (LineageRecordError) is outside it: fail closed.
func (s *Store) IssueInRunLineage(ctx context.Context, username, connection, runID string, number int64) (bool, error) {
	if runID == "" {
		return false, nil
	}
	const sql = `
		SELECT
			EXISTS (SELECT 1 FROM tracker_dispatches
				WHERE username = $1 AND connection = $2 AND run_id = $3 AND issue_number = $4)
			OR
			EXISTS (SELECT 1 FROM tracker_issue_lineage
				WHERE username = $1 AND connection = $2 AND created_by_run = $3 AND child_number = $4)
	`
	var in bool
	if err := s.pool.QueryRow(ctx, sql, username, connection, runID, number).Scan(&in); err != nil {
		return false, fmt.Errorf("select run lineage: %w", err)
	}
	return in, nil
}

// lineageQuerier is the subset of pgxpool.Pool / pgx.Tx the two reads
// above need, so they run identically inside and outside RecordChild's
// transaction.
type lineageQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func issueDepth(ctx context.Context, q lineageQuerier, username, connection string, number int64) (int32, error) {
	const sql = `
		SELECT COALESCE(
			(SELECT depth FROM tracker_issue_lineage WHERE username = $1 AND connection = $2 AND child_number = $3),
			0)
	`
	var depth int32
	if err := q.QueryRow(ctx, sql, username, connection, number).Scan(&depth); err != nil {
		return 0, fmt.Errorf("select issue depth: %w", err)
	}
	return depth, nil
}

// runDispatchDepth returns the depth the dispatcher recorded on runID's
// own tracker_dispatches row when it started the run — the depth of the
// issue the run was dispatched for, read from the lineage table at that
// moment (#2073). 0 for a run the dispatcher did not start (no row: a
// run a human started by hand), or an empty runID. Written only by the
// dispatcher's own code path, never from anything a run sends, so it is
// the floor a run's follow-ups cannot dip below. MAX fails closed should
// a run id ever carry more than one row.
func runDispatchDepth(ctx context.Context, q lineageQuerier, username, connection, runID string) (int32, error) {
	if runID == "" {
		return 0, nil
	}
	const sql = `
		SELECT COALESCE(MAX(depth), 0) FROM tracker_dispatches
		WHERE username = $1 AND connection = $2 AND run_id = $3
	`
	var depth int32
	if err := q.QueryRow(ctx, sql, username, connection, runID).Scan(&depth); err != nil {
		return 0, fmt.Errorf("select run dispatch depth: %w", err)
	}
	return depth, nil
}

// claimedCount counts runID's fan-out slots: its recorded children plus
// its reservations (in-flight or abandoned creates with no lineage row
// yet). Both counts MUST come from one statement: under READ COMMITTED
// each statement takes its own snapshot, and RecordChild's final step
// inserts the lineage row and deletes the reservation in one commit — two
// separate COUNTs straddling that commit would see neither and let the
// cap be raced past.
func claimedCount(ctx context.Context, q lineageQuerier, username, connection, runID string) (recorded, reserved int32, err error) {
	const sql = `
		SELECT
			(SELECT COUNT(*) FROM tracker_issue_lineage        WHERE username = $1 AND connection = $2 AND created_by_run = $3),
			(SELECT COUNT(*) FROM tracker_lineage_reservations WHERE username = $1 AND connection = $2 AND created_by_run = $3)
	`
	if err := q.QueryRow(ctx, sql, username, connection, runID).Scan(&recorded, &reserved); err != nil {
		return 0, 0, fmt.Errorf("count run fan-out: %w", err)
	}
	return recorded, reserved, nil
}

func childrenCount(ctx context.Context, q lineageQuerier, username, connection, runID string) (int32, error) {
	const sql = `SELECT COUNT(*) FROM tracker_issue_lineage WHERE username = $1 AND connection = $2 AND created_by_run = $3`
	var n int32
	if err := q.QueryRow(ctx, sql, username, connection, runID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count run children: %w", err)
	}
	return n, nil
}

// RecordChild files one follow-up under l.ParentNumber for l.CreatedByRun,
// enforcing the chain guards and recording the lineage row exactly once:
//
//  1. reserve: take the run's in-process gate (no pool connection held
//     while queued), then in one short transaction take a per-run
//     advisory lock (the cross-process guard), derive the child's depth
//     as max(parent's row, the run's own dispatch row) + 1 (#2073: the
//     caller-chosen parent cannot lower it) and reject with
//     ErrDepthExceeded if it would exceed maxDepth, count the run's
//     recorded children PLUS its
//     outstanding reservations and reject with ErrFanoutExceeded if that
//     already reaches maxChildren, then insert a reservation row and
//     commit — releasing the connection;
//  2. call create — the caller's upstream call, which returns the new
//     issue's number — with NO transaction or pool connection held;
//  3. record: insert the lineage row and delete the reservation in one
//     transaction; or, if create failed, delete the reservation — unless
//     the failure leaves the outcome unknown (IsAmbiguousUpstreamError),
//     in which case the reservation stays and the error wraps
//     ErrUpstreamOutcomeUnknown, with the returned Lineage carrying the
//     depth the child would have had (#2045).
//
// The guards therefore run BEFORE any upstream call, and a reservation
// is counted exactly like a recorded child, so a cap cannot be raced past
// even though concurrent creates now overlap upstream. Holding nothing
// across the upstream call is what keeps one run token from starving the
// tracker store's small pool (#2044). A maxDepth or maxChildren of 0 (or
// less) means unlimited.
//
// A reservation that is never cleared (the process died mid-create, or
// the cleanup itself failed) keeps counting against the run's fan-out.
// That is deliberate: the create may have succeeded upstream, so
// over-counting is the fail-closed side. Such reservations are visible
// through ListLineageReservations, and are swept by
// ReleaseRunReservations when the run's lease ends (#2062).
func (s *Store) RecordChild(ctx context.Context, l Lineage, maxDepth, maxChildren int32, create func(ctx context.Context) (int64, error)) (Lineage, error) {
	if l.Username == "" || l.Connection == "" {
		return Lineage{}, errors.New("tracker: username and connection are required")
	}
	if l.ParentNumber <= 0 {
		return Lineage{}, errors.New("tracker: parent_number is required")
	}
	if l.CreatedByRun == "" {
		return Lineage{}, errors.New("tracker: created_by_run is required")
	}
	if create == nil {
		return Lineage{}, errors.New("tracker: create callback is required")
	}

	reservationID, err := s.reserveChild(ctx, &l, maxDepth, maxChildren)
	if err != nil {
		return Lineage{}, err
	}

	// Every check has passed and the slot is claimed: the create is now
	// committed-to. Run it detached from the caller's cancellation
	// (bounded by a timeout) so it either completes and is recorded below,
	// or fails for a real upstream reason — never because the caller
	// disconnected after the forge accepted the POST, which would leave an
	// unrecorded issue (re-review of #2034).
	createCtx, cancelCreate := context.WithTimeout(context.WithoutCancel(ctx), UpstreamCreateTimeout)
	defer cancelCreate()
	child, err := create(createCtx)

	// From here on the bookkeeping must not depend on the caller still
	// being around (review of #2034): detach from cancellation, bounded by
	// a short timeout.
	recCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lineageRecordTimeout)
	defer cancel()

	if err != nil && IsAmbiguousUpstreamError(err) {
		// The request was sent but no answer came back in time: the issue
		// may exist upstream (#2045). Keep the slot claimed so a retry is
		// counted against the cap — the fail-closed side, like any other
		// stale reservation, released when the run's lease ends.
		return l, fmt.Errorf("%w: %w", ErrUpstreamOutcomeUnknown, err)
	}
	if err != nil {
		// Nothing was created: free the slot. If even that fails the stale
		// reservation over-counts, which is the fail-closed side.
		if _, relErr := s.pool.Exec(recCtx, `DELETE FROM tracker_lineage_reservations WHERE id = $1`, reservationID); relErr != nil {
			return Lineage{}, errors.Join(err, fmt.Errorf("release lineage reservation: %w", relErr))
		}
		return Lineage{}, err
	}
	l.ChildNumber = child

	// The issue EXISTS upstream. If recording fails, the reservation stays
	// (the child keeps counting toward fan-out) and the typed error names
	// the child so the caller reports it instead of retrying blind.
	if err := s.recordReservedChild(recCtx, l, reservationID); err != nil {
		return l, &LineageRecordError{ChildNumber: l.ChildNumber, Depth: l.Depth, Err: err}
	}
	return l, nil
}

// reserveChild is RecordChild's step 1: it runs the depth and fan-out
// guards and claims a fan-out slot, setting l.Depth. The run's in-process
// gate is held only for this short transaction, and is taken before a
// pool connection, so same-run creates queue without holding one.
func (s *Store) reserveChild(ctx context.Context, l *Lineage, maxDepth, maxChildren int32) (int64, error) {
	lockKey := l.Username + "/" + l.Connection + "/" + l.CreatedByRun
	release, err := s.runGates.acquire(ctx, lockKey)
	if err != nil {
		return 0, fmt.Errorf("wait for run lineage gate: %w", err)
	}
	defer release()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin lineage transaction: %w", err)
	}
	// No-op after a successful Commit. Detached so a cancelled request
	// context still releases the transaction cleanly.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// Cross-process guard (another daemon on the same database); within
	// this process the gate above already serializes the run.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return 0, fmt.Errorf("lock run lineage: %w", err)
	}

	// The child's depth is one below the DEEPER of the named parent and
	// the run's own dispatched issue (#2073). parent_number is chosen by
	// the run, so on its own it could name any human-created issue and
	// reset the chain to depth 1; the run's dispatch depth was written by
	// the dispatcher from this table and is not the run's to choose. So
	// depth never decreases along a dispatch chain, whatever parent each
	// hop claims, and max_depth bounds the chain end to end.
	parentDepth, err := issueDepth(ctx, tx, l.Username, l.Connection, l.ParentNumber)
	if err != nil {
		return 0, err
	}
	runDepth, err := runDispatchDepth(ctx, tx, l.Username, l.Connection, l.CreatedByRun)
	if err != nil {
		return 0, err
	}
	l.Depth = max(parentDepth, runDepth) + 1
	if maxDepth > 0 && l.Depth > maxDepth {
		return 0, fmt.Errorf("%w: child of #%d by a run at depth %d would be depth %d, max %d", ErrDepthExceeded, l.ParentNumber, runDepth, l.Depth, maxDepth)
	}

	recorded, reserved, err := claimedCount(ctx, tx, l.Username, l.Connection, l.CreatedByRun)
	if err != nil {
		return 0, err
	}
	if maxChildren > 0 && recorded+reserved >= maxChildren {
		return 0, fmt.Errorf("%w: run %s already filed %d (%d in flight), max %d", ErrFanoutExceeded, l.CreatedByRun, recorded+reserved, reserved, maxChildren)
	}

	var id int64
	const reserve = `
		INSERT INTO tracker_lineage_reservations (username, connection, created_by_run)
		VALUES ($1, $2, $3)
		RETURNING id
	`
	if err := tx.QueryRow(ctx, reserve, l.Username, l.Connection, l.CreatedByRun).Scan(&id); err != nil {
		return 0, fmt.Errorf("reserve lineage slot: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit lineage reservation: %w", err)
	}
	return id, nil
}

// recordReservedChild is RecordChild's step 3: it turns the reservation
// into the lineage row atomically.
func (s *Store) recordReservedChild(ctx context.Context, l Lineage, reservationID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin lineage record: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	const insert = `
		INSERT INTO tracker_issue_lineage (username, connection, child_number, parent_number, created_by_run, depth)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	if _, err := tx.Exec(ctx, insert, l.Username, l.Connection, l.ChildNumber, l.ParentNumber, l.CreatedByRun, l.Depth); err != nil {
		return fmt.Errorf("insert issue lineage: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tracker_lineage_reservations WHERE id = $1`, reservationID); err != nil {
		return fmt.Errorf("clear lineage reservation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit issue lineage: %w", err)
	}
	return nil
}

// LineageReservation is one tracker_lineage_reservations row: a fan-out
// slot RecordChild claimed and has not yet recorded or released.
type LineageReservation struct {
	ID           int64
	Username     string
	Connection   string
	CreatedByRun string
	CreatedAt    time.Time
}

// ListLineageReservations returns a connection's outstanding fan-out
// reservations, oldest first (#2062). Each one counts against its run's
// max_children_per_run exactly like a recorded child: a create still in
// flight, or one RecordChild could not clear (the daemon died mid-create,
// the release failed, or the lineage row did not record). Read-only; it
// is how an operator sees why a run's fan-out looks exhausted.
func (s *Store) ListLineageReservations(ctx context.Context, username, connection string) ([]LineageReservation, error) {
	if username == "" {
		return nil, errors.New("tracker: username is required")
	}
	const q = `
		SELECT id, created_by_run, created_at FROM tracker_lineage_reservations
		WHERE username = $1 AND connection = $2
		ORDER BY created_at, id
	`
	rows, err := s.pool.Query(ctx, q, username, connection)
	if err != nil {
		return nil, fmt.Errorf("list lineage reservations: %w", err)
	}
	defer rows.Close()
	var out []LineageReservation
	for rows.Next() {
		r := LineageReservation{Username: username, Connection: connection}
		if err := rows.Scan(&r.ID, &r.CreatedByRun, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan lineage reservation row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate lineage reservation rows: %w", err)
	}
	return out, nil
}

// ReleaseRunReservations deletes every reservation runID still holds for
// username, on any connection, and returns how many it removed (#2062).
// Called when the run's lease ends: its credentials are revoked by then,
// so it cannot start another create, and the fail-closed reason for
// keeping a stale reservation (the create may have succeeded upstream and
// must keep counting) no longer has a cap to protect. A create already
// past its reservation step finishes normally — recording its lineage
// row, or releasing a reservation that is already gone.
//
// Scoped to (username, runID), never runID alone: a run id can be
// caller-chosen, so the same string may name another tenant's run.
// Idempotent.
func (s *Store) ReleaseRunReservations(ctx context.Context, username, runID string) (int64, error) {
	if username == "" || runID == "" {
		return 0, errors.New("tracker: username and run id are required")
	}
	const q = `DELETE FROM tracker_lineage_reservations WHERE username = $1 AND created_by_run = $2`
	tag, err := s.pool.Exec(ctx, q, username, runID)
	if err != nil {
		return 0, fmt.Errorf("release run lineage reservations: %w", err)
	}
	return tag.RowsAffected(), nil
}

// runGates is a set of per-key, context-aware mutexes. A key's entry
// lives only while someone holds or waits on it, so the map does not
// grow with the number of runs ever seen. The zero value is ready to use.
type runGates struct {
	mu    sync.Mutex
	gates map[string]*runGate
}

type runGate struct {
	token chan struct{} // capacity 1: holding the token = holding the gate
	refs  int           // holders + waiters; guarded by runGates.mu
}

// acquire blocks until key's gate is held or ctx is done. The returned
// release must be called exactly once.
func (g *runGates) acquire(ctx context.Context, key string) (release func(), err error) {
	g.mu.Lock()
	if g.gates == nil {
		g.gates = make(map[string]*runGate)
	}
	gate, ok := g.gates[key]
	if !ok {
		gate = &runGate{token: make(chan struct{}, 1)}
		g.gates[key] = gate
	}
	gate.refs++
	g.mu.Unlock()

	unref := func() {
		g.mu.Lock()
		gate.refs--
		if gate.refs == 0 {
			delete(g.gates, key)
		}
		g.mu.Unlock()
	}

	select {
	case gate.token <- struct{}{}:
		return func() {
			<-gate.token
			unref()
		}, nil
	case <-ctx.Done():
		unref()
		return nil, ctx.Err()
	}
}

// lineageRecordTimeout bounds the detached insert+commit that follows a
// successful upstream create.
const lineageRecordTimeout = 10 * time.Second

// UpstreamCreateTimeout bounds an upstream issue create that has been
// detached from the caller's cancellation — RecordChild's create callback
// and CreateTrackerIssue's operator path both use it.
//
// It is the budget for an upstream create request: the GitHub and GitLab
// adapters run CreateIssue under it, not under their general client
// timeout (#2045). Whichever fires, the result is the same ambiguous
// timeout (IsAmbiguousUpstreamError).
const UpstreamCreateTimeout = 30 * time.Second

// DefaultHTTPTimeout is the timeout of the HTTP client the GitHub and
// GitLab adapters build when none is passed in, for every call except
// issue creates (which use UpstreamCreateTimeout).
const DefaultHTTPTimeout = 10 * time.Second

// ErrUpstreamOutcomeUnknown marks an upstream create whose request was
// sent but whose answer never arrived in time (#2045): the issue may or
// may not exist on the tracker, and the daemon does not know its number.
// RecordChild keeps the run's fan-out slot claimed for it (fail-closed:
// it is released with the run's other reservations when the lease ends),
// and CreateTrackerIssue audits it and tells the caller not to retry
// blindly. The cause stays in the chain.
var ErrUpstreamOutcomeUnknown = errors.New("tracker: upstream create outcome unknown")

// IsAmbiguousUpstreamError reports whether err from an upstream create
// leaves its outcome unknown: a timeout — the detached context's deadline,
// or the HTTP client's own timeout (net/http's timeout errors match
// context.DeadlineExceeded) — rather than an answer from the forge. A
// timeout while still connecting is reported the same way: the adapters
// cannot tell it apart from one after the request was sent, and treating
// it as ambiguous is the fail-closed side (it costs a fan-out slot, never
// a duplicate). A refused connection or any HTTP status is a definite
// failure: nothing was created.
func IsAmbiguousUpstreamError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

// LineageRecordError is returned by RecordChild when the upstream create
// SUCCEEDED but its lineage row could not be recorded. The issue exists on
// the tracker as ChildNumber: callers must report it as created (and audit
// it), never treat the call as failed — a retry would file a duplicate.
type LineageRecordError struct {
	ChildNumber int64
	Depth       int32
	Err         error
}

func (e *LineageRecordError) Error() string {
	return fmt.Sprintf("tracker: issue #%d was created upstream but its lineage was not recorded: %v", e.ChildNumber, e.Err)
}

func (e *LineageRecordError) Unwrap() error { return e.Err }
