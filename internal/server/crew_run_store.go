package server

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// CrewRunStore records crew executions, keyed by run id. Two impls, selected
// the same way NetworkPolicyStore is: PostgresCrewRunStore when the daemon has
// a DB pool, MemCrewRunStore for --standalone daemons and tests.
//
// Durability is the point (#1182). A daemon restart used to lose every
// in-flight run: the run simply never completed, and nothing recorded that it
// had existed. GetCrewRun returned NotFound for work that really did happen.
//
// Entries are cloned on the way in and on the way out. Handing out the same
// pointer the caller keeps mutating would let a reader observe a run
// mid-write — a proto message is several fields and nothing makes updating
// them atomic. That property predates this interface and is preserved by both
// impls; the Postgres one gets it for free by serializing.
type CrewRunStore interface {
	// Put records a run, overwriting any previous state for the same id.
	Put(ctx context.Context, r *pb.CrewRun) error
	// Get returns the run and whether it was found.
	Get(ctx context.Context, id string) (*pb.CrewRun, bool, error)
}

// --- in-memory ------------------------------------------------------

// MemCrewRunStore is a goroutine-safe in-memory store. Runs do not survive a
// daemon restart — used on --standalone daemons (no Postgres) and in tests.
type MemCrewRunStore struct {
	mu   sync.RWMutex
	runs map[string]*pb.CrewRun
}

func NewMemCrewRunStore() *MemCrewRunStore {
	return &MemCrewRunStore{runs: make(map[string]*pb.CrewRun)}
}

func (s *MemCrewRunStore) Put(_ context.Context, r *pb.CrewRun) error {
	if r == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[r.GetId()] = proto.Clone(r).(*pb.CrewRun)
	return nil
}

func (s *MemCrewRunStore) Get(_ context.Context, id string) (*pb.CrewRun, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.runs[id]
	if !ok {
		return nil, false, nil
	}
	return proto.Clone(r).(*pb.CrewRun), true, nil
}

// --- postgres -------------------------------------------------------

// PostgresCrewRunStore persists runs so they survive a daemon restart.
type PostgresCrewRunStore struct {
	pool *pgxpool.Pool
}

// NewPostgresCrewRunStore creates the table if it does not exist.
//
// The run body is stored as protojson rather than a column per field. The
// CrewRun message is a small bag of strings today, but the columns that
// matter for querying — id and state — are lifted out and indexed, so adding
// a proto field later needs no migration. That is the shape google/ax uses
// for its event log (conversation_id, step, payload) and it holds up well:
// the payload evolves with the proto, the queryable keys are explicit.
func NewPostgresCrewRunStore(ctx context.Context, pool *pgxpool.Pool) (*PostgresCrewRunStore, error) {
	const schema = `
		CREATE TABLE IF NOT EXISTS crew_runs (
			id TEXT PRIMARY KEY,
			crew_id TEXT NOT NULL DEFAULT '',
			state INTEGER NOT NULL DEFAULT 0,
			run JSONB NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS crew_runs_state_idx ON crew_runs (state);
	`
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("init crew_runs schema: %w", err)
	}
	return &PostgresCrewRunStore{pool: pool}, nil
}

func (s *PostgresCrewRunStore) Put(ctx context.Context, r *pb.CrewRun) error {
	if r == nil {
		return nil
	}
	if r.GetId() == "" {
		// A run with no id would collide with every other id-less run on the
		// primary key, silently overwriting them. The in-memory store had the
		// same hazard under an empty map key; surface it instead.
		return errors.New("crew run has no id")
	}
	body, err := protojson.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal crew run %s: %w", r.GetId(), err)
	}
	const q = `
		INSERT INTO crew_runs (id, crew_id, state, run, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (id) DO UPDATE SET
			crew_id = EXCLUDED.crew_id,
			state = EXCLUDED.state,
			run = EXCLUDED.run,
			updated_at = NOW()
	`
	if _, err := s.pool.Exec(ctx, q, r.GetId(), r.GetCrewId(), int32(r.GetState()), body); err != nil {
		return fmt.Errorf("put crew run %s: %w", r.GetId(), err)
	}
	return nil
}

func (s *PostgresCrewRunStore) Get(ctx context.Context, id string) (*pb.CrewRun, bool, error) {
	const q = `SELECT run FROM crew_runs WHERE id = $1`
	var body []byte
	switch err := s.pool.QueryRow(ctx, q, id).Scan(&body); {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("get crew run %s: %w", id, err)
	}
	var r pb.CrewRun
	// DiscardUnknown so a daemon rolled back to an older build can still read
	// runs written by a newer one, rather than failing every Get.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &r); err != nil {
		return nil, false, fmt.Errorf("unmarshal crew run %s: %w", id, err)
	}
	return &r, true, nil
}
