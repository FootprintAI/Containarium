package tracker

import (
	"context"
	"errors"
	"fmt"
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
}

// NewStore opens the tracker-connections store, creating the table on
// first run. Idempotent on every subsequent call, same idiom as
// internal/secrets.NewStore.
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

func (s *Store) initSchema(ctx context.Context) error {
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
	`
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return err
	}
	// #2021: scope routes hang off a connection by foreign key, so they
	// are created after tracker_connections.
	_, err := s.pool.Exec(ctx, routeSchema)
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

func childrenCount(ctx context.Context, q lineageQuerier, username, connection, runID string) (int32, error) {
	const sql = `SELECT COUNT(*) FROM tracker_issue_lineage WHERE username = $1 AND connection = $2 AND created_by_run = $3`
	var n int32
	if err := q.QueryRow(ctx, sql, username, connection, runID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count run children: %w", err)
	}
	return n, nil
}

// RecordChild files one follow-up under l.ParentNumber for l.CreatedByRun,
// enforcing the chain guards and recording the lineage row atomically:
//
//  1. begin a transaction and take a per-run advisory lock, so two
//     concurrent creates from the same run serialize here;
//  2. derive the child's depth from the parent's row (+1) and reject
//     with ErrDepthExceeded if it would exceed maxDepth;
//  3. count the run's existing children and reject with
//     ErrFanoutExceeded if it already has maxChildren;
//  4. only then call create — the caller's upstream call, which returns
//     the new issue's number — and insert the row; commit.
//
// The guards therefore run BEFORE any upstream call, and the fan-out
// count and the insert are in the same transaction, so a cap cannot be
// raced past. If create fails, nothing is recorded. A maxDepth or
// maxChildren of 0 (or less) means unlimited. The transaction — and its
// pool connection — is held for the duration of the upstream call; at
// the design's stated scale (a handful of runs per tenant per day)
// that is a non-issue, and it is what makes the count authoritative.
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

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Lineage{}, fmt.Errorf("begin lineage transaction: %w", err)
	}
	// No-op after a successful Commit. Detached so a cancelled request
	// context still releases the transaction cleanly.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	lockKey := l.Username + "/" + l.Connection + "/" + l.CreatedByRun
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return Lineage{}, fmt.Errorf("lock run lineage: %w", err)
	}

	parentDepth, err := issueDepth(ctx, tx, l.Username, l.Connection, l.ParentNumber)
	if err != nil {
		return Lineage{}, err
	}
	l.Depth = parentDepth + 1
	if maxDepth > 0 && l.Depth > maxDepth {
		return Lineage{}, fmt.Errorf("%w: child of #%d would be depth %d, max %d", ErrDepthExceeded, l.ParentNumber, l.Depth, maxDepth)
	}

	existing, err := childrenCount(ctx, tx, l.Username, l.Connection, l.CreatedByRun)
	if err != nil {
		return Lineage{}, err
	}
	if maxChildren > 0 && existing >= maxChildren {
		return Lineage{}, fmt.Errorf("%w: run %s already filed %d, max %d", ErrFanoutExceeded, l.CreatedByRun, existing, maxChildren)
	}

	// Every check has passed: the create is now committed-to. Run it
	// detached from the caller's cancellation (bounded by a timeout) so it
	// either completes and is recorded below, or fails for a real upstream
	// reason — never because the caller disconnected after the forge
	// accepted the POST, which would leave an unrecorded, uncounted issue
	// and let a run slip past max_children_per_run (re-review of #2034).
	createCtx, cancelCreate := context.WithTimeout(context.WithoutCancel(ctx), UpstreamCreateTimeout)
	defer cancelCreate()
	child, err := create(createCtx)
	if err != nil {
		return Lineage{}, err
	}
	l.ChildNumber = child

	// From here the issue EXISTS upstream. Recording it must not depend on
	// the caller still being around (review of #2034): a cancelled request
	// context would otherwise leave an uncounted, depth-0 child and invite
	// a duplicate on retry. Detach from cancellation, bounded by a short
	// timeout; if recording still fails, the typed error names the child.
	recCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lineageRecordTimeout)
	defer cancel()
	const insert = `
		INSERT INTO tracker_issue_lineage (username, connection, child_number, parent_number, created_by_run, depth)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	if _, err := tx.Exec(recCtx, insert, l.Username, l.Connection, l.ChildNumber, l.ParentNumber, l.CreatedByRun, l.Depth); err != nil {
		return l, &LineageRecordError{ChildNumber: l.ChildNumber, Depth: l.Depth, Err: fmt.Errorf("insert issue lineage: %w", err)}
	}
	if err := tx.Commit(recCtx); err != nil {
		return l, &LineageRecordError{ChildNumber: l.ChildNumber, Depth: l.Depth, Err: fmt.Errorf("commit issue lineage: %w", err)}
	}
	return l, nil
}

// lineageRecordTimeout bounds the detached insert+commit that follows a
// successful upstream create.
const lineageRecordTimeout = 10 * time.Second

// UpstreamCreateTimeout bounds an upstream issue create that has been
// detached from the caller's cancellation — RecordChild's create callback
// and CreateTrackerIssue's operator path both use it.
const UpstreamCreateTimeout = 30 * time.Second

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
