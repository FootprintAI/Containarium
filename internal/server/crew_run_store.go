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
	// FailStranded marks every run still RUNNING as FAILED with the given
	// reason, returning how many it changed.
	//
	// Called once at daemon start. RunCrew records a run as RUNNING before it
	// drives it, so a daemon that dies mid-run leaves that state behind — and
	// with a durable store it survives, so GetCrewRun answers RUNNING forever
	// for a run that can never finish (#1182 AC4). Nothing else reconciles
	// them: driveCrew has no resumption point, so the honest outcome is a
	// terminal failure that says why, not a run that claims to be working.
	FailStranded(ctx context.Context, reason string) (int, error)
}

// StrandedByRestart is the reason recorded for a run the daemon was driving
// when it stopped. Named so an operator reading a failed run can tell this
// apart from a crew that genuinely failed.
const StrandedByRestart = "daemon restarted while this run was in flight; the run was not resumed"

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

func (s *MemCrewRunStore) FailStranded(_ context.Context, reason string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, r := range s.runs {
		if r.GetState() != pb.CrewRunState_CREW_RUN_STATE_RUNNING {
			continue
		}
		updated := proto.Clone(r).(*pb.CrewRun)
		updated.State = pb.CrewRunState_CREW_RUN_STATE_FAILED
		updated.Error = reason
		s.runs[id] = updated
		n++
	}
	return n, nil
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

// SetRunStore swaps the crew-run store, used at daemon start to upgrade from
// the in-memory default to Postgres once the connection string is resolved.
// Called before grpcServer.Serve, so it races with no live RPCs — the same
// point and the same reasoning as NetworkPolicyServer.SetStore.
// FailStranded marks rows still RUNNING as FAILED in one statement.
//
// The state column and the marshalled proto both carry the state, so both are
// updated — a row whose column said FAILED while its body still said RUNNING
// would report differently depending on which one a reader trusted. jsonb_set
// keeps the rest of the run intact.
//
// Not covered by a test that runs: nothing in this repo can execute Postgres
// SQL today (#1300). The memory implementation's behaviour is tested, and the
// orchestration is guarded, but this statement itself is reviewed rather than
// exercised.
func (s *PostgresCrewRunStore) FailStranded(ctx context.Context, reason string) (int, error) {
	const q = `
		UPDATE crew_runs
		SET state = $1,
		    run = jsonb_set(
		            jsonb_set(run::jsonb, '{state}', to_jsonb($2::text), true),
		            '{error}', to_jsonb($3::text), true)::text::json,
		    updated_at = NOW()
		WHERE state = $4
	`
	tag, err := s.pool.Exec(ctx, q,
		int32(pb.CrewRunState_CREW_RUN_STATE_FAILED),
		pb.CrewRunState_CREW_RUN_STATE_FAILED.String(),
		reason,
		int32(pb.CrewRunState_CREW_RUN_STATE_RUNNING),
	)
	if err != nil {
		return 0, fmt.Errorf("fail stranded crew runs: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *CrewServer) SetRunStore(store CrewRunStore) {
	if store != nil {
		s.runs = store
	}
}
