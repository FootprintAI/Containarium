//go:build integration

// Integration coverage for the Postgres store implementations (#1300, #1322).
//
// Everything else in this package exercises the in-memory impls, which is the
// half that cannot fail for the reasons the Postgres half exists. These cases
// run the SAME assertions against both, so the contract is stated once rather
// than restated per backend — and so a divergence between them is a failure
// rather than a discovery.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/server/
//
// The DSN is required rather than defaulted: a test that silently skips is
// indistinguishable from one that passed, which is the failure this file
// exists to stop being possible.
package server

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. This build tag exists to run against a real " +
			"database; failing rather than skipping, so a lane that loses its service container " +
			"reports it instead of going quietly green.")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// freshSchema drops and recreates the tables so each test starts clean and
// the migrations in the constructors are exercised every run.
func freshSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`DROP TABLE IF EXISTS agent_task_results`,
		`DROP TABLE IF EXISTS agent_tasks`,
		`DROP TABLE IF EXISTS crew_runs`,
		`DROP SEQUENCE IF EXISTS agent_lease_token_seq`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("reset schema (%s): %v", q, err)
		}
	}
}

// --- crew run store, both implementations ----------------------------

func crewStores(t *testing.T) map[string]CrewRunStore {
	t.Helper()
	pool := testPool(t)
	freshSchema(t, pool)
	pg, err := NewPostgresCrewRunStore(context.Background(), pool)
	if err != nil {
		t.Fatalf("NewPostgresCrewRunStore: %v", err)
	}
	return map[string]CrewRunStore{"mem": NewMemCrewRunStore(), "postgres": pg}
}

func TestCrewRunStore_ContractHoldsForBothImpls(t *testing.T) {
	ctx := context.Background()
	for name, s := range crewStores(t) {
		t.Run(name, func(t *testing.T) {
			run := &pb.CrewRun{Id: "r1", CrewId: "crew-1", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING}
			if err := s.Put(ctx, run); err != nil {
				t.Fatalf("put: %v", err)
			}

			got, ok, err := s.Get(ctx, "r1")
			if err != nil || !ok {
				t.Fatalf("get: ok=%v err=%v", ok, err)
			}
			if got.State != pb.CrewRunState_CREW_RUN_STATE_RUNNING || got.CrewId != "crew-1" {
				t.Errorf("round trip lost fields: %+v", got)
			}

			// Mutating what you put must not change what is stored.
			run.State = pb.CrewRunState_CREW_RUN_STATE_FAILED
			again, _, _ := s.Get(ctx, "r1")
			if again.State != pb.CrewRunState_CREW_RUN_STATE_RUNNING {
				t.Error("the caller's later writes reached the store")
			}

			if _, ok, _ := s.Get(ctx, "missing"); ok {
				t.Error("a missing run reported found")
			}
		})
	}
}

// #1182 AC4 against a real database: the sweep has to update both the state
// column and the state inside the marshalled proto. A row disagreeing with
// itself reports differently depending on which one a reader trusts, and only
// Postgres can show that.
func TestCrewRunStore_FailStrandedForBothImpls(t *testing.T) {
	ctx := context.Background()
	for name, s := range crewStores(t) {
		t.Run(name, func(t *testing.T) {
			mustPutI(t, s, &pb.CrewRun{Id: "stuck", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING})
			mustPutI(t, s, &pb.CrewRun{Id: "done", State: pb.CrewRunState_CREW_RUN_STATE_COMPLETED, ArtifactJson: "{}"})

			n, err := s.FailStranded(ctx, StrandedByRestart)
			if err != nil {
				t.Fatalf("FailStranded: %v", err)
			}
			if n != 1 {
				t.Errorf("reconciled %d, want 1", n)
			}

			stuck, _, _ := s.Get(ctx, "stuck")
			if stuck.State != pb.CrewRunState_CREW_RUN_STATE_FAILED {
				t.Errorf("state = %v, want FAILED", stuck.State)
			}
			if stuck.Error != StrandedByRestart {
				t.Errorf("error = %q, want the restart reason — this is the field that comes back "+
					"from the marshalled proto, so it proves both copies were updated", stuck.Error)
			}

			done, _, _ := s.Get(ctx, "done")
			if done.State != pb.CrewRunState_CREW_RUN_STATE_COMPLETED || done.ArtifactJson != "{}" {
				t.Errorf("a completed run was altered: %+v", done)
			}

			if again, _ := s.FailStranded(ctx, StrandedByRestart); again != 0 {
				t.Errorf("second sweep reconciled %d, want 0 (idempotent)", again)
			}
		})
	}
}

func mustPutI(t *testing.T, s CrewRunStore, r *pb.CrewRun) {
	t.Helper()
	if err := s.Put(context.Background(), r); err != nil {
		t.Fatalf("put %s: %v", r.GetId(), err)
	}
}

// --- task queue, both implementations --------------------------------

func taskQueues(t *testing.T) map[string]AgentTaskQueue {
	t.Helper()
	pool := testPool(t)
	freshSchema(t, pool)
	pg, err := NewPostgresAgentTaskQueue(context.Background(), pool)
	if err != nil {
		t.Fatalf("NewPostgresAgentTaskQueue: %v", err)
	}
	return map[string]AgentTaskQueue{"mem": NewMemAgentTaskQueue(), "postgres": pg}
}

func TestAgentTaskQueue_ContractHoldsForBothImpls(t *testing.T) {
	ctx := context.Background()
	for name, q := range taskQueues(t) {
		t.Run(name, func(t *testing.T) {
			id, err := q.Enqueue(ctx, "skill-1", `{"in":1}`)
			if err != nil {
				t.Fatalf("enqueue: %v", err)
			}

			task, ok, err := q.Lease(ctx, "", time.Minute)
			if err != nil || !ok {
				t.Fatalf("lease: ok=%v err=%v", ok, err)
			}
			if task.ID != id {
				t.Errorf("leased %q, enqueued %q", task.ID, id)
			}

			// A leased task is hidden until its lease expires.
			if _, ok, _ := q.Lease(ctx, "", time.Minute); ok {
				t.Error("a leased task was handed out twice — two workers would run it")
			}

			if ok, err := q.Complete(ctx, id, task.LeaseToken, `{"out":1}`, ""); err != nil || !ok {
				t.Fatalf("complete: ok=%v err=%v", ok, err)
			}
			res, ok, err := q.Result(ctx, id)
			if err != nil || !ok || res.artifactJSON != `{"out":1}` {
				t.Errorf("result: ok=%v err=%v res=%+v", ok, err, res)
			}
		})
	}
}

// The property that motivated a sequence for lease tokens rather than a
// counter: a token issued before a restart must not be accepted afterwards.
// An in-memory counter restarts at zero, so this is where the two impls are
// expected to differ — and the Postgres one is the one that has to hold.
func TestAgentTaskQueue_StaleLeaseTokenRejectedAcrossReconnect(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	freshSchema(t, pool)

	q1, err := NewPostgresAgentTaskQueue(ctx, pool)
	if err != nil {
		t.Fatalf("queue: %v", err)
	}
	id, err := q1.Enqueue(ctx, "skill-1", "{}")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	first, ok, err := q1.Lease(ctx, "", 50*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("first lease: ok=%v err=%v", ok, err)
	}

	// The lease expires while "the daemon is down".
	time.Sleep(300 * time.Millisecond)

	// A new process, new pool, same database.
	pool2, err := pgxpool.New(ctx, os.Getenv("CONTAINARIUM_TEST_DSN"))
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer pool2.Close()
	q2, err := NewPostgresAgentTaskQueue(ctx, pool2)
	if err != nil {
		t.Fatalf("queue after reconnect: %v", err)
	}

	second, ok, err := q2.Lease(ctx, "", time.Minute)
	if err != nil || !ok {
		t.Fatalf("redelivery after the lease expired: ok=%v err=%v", ok, err)
	}
	if second.ID != id {
		t.Fatalf("redelivered %q, want %q", second.ID, id)
	}
	if second.LeaseToken == first.LeaseToken {
		t.Fatal("redelivery reused the pre-restart lease token — the old holder would still be " +
			"accepted as the current owner")
	}

	// The pre-restart holder must not be able to complete it.
	if ok, _ := q2.Complete(ctx, id, first.LeaseToken, "{}", ""); ok {
		t.Error("a pre-restart lease token completed a task that had been redelivered — the " +
			"result of a run nobody is waiting on would overwrite the live one")
	}
	if ok, err := q2.Complete(ctx, id, second.LeaseToken, "{}", ""); err != nil || !ok {
		t.Errorf("the current holder could not complete: ok=%v err=%v", ok, err)
	}
}

// Row locking on the lease claim is what stops two concurrent workers being
// handed the same task. Nothing in the memory impl can show this.
//
// Measured, because the obvious claim is wrong: removing the locking entirely
// fails this test (the same task is leased three times), but removing only
// SKIP LOCKED does NOT — plain FOR UPDATE serializes the claimants instead of
// duplicating the row, so distinctness still holds. SKIP LOCKED is a
// throughput choice, not the thing keeping this correct. Worth stating so the
// next person does not read a passing run as proof of it.
func TestAgentTaskQueue_ConcurrentLeasesAreDistinct(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	freshSchema(t, pool)

	q, err := NewPostgresAgentTaskQueue(ctx, pool)
	if err != nil {
		t.Fatalf("queue: %v", err)
	}

	const tasks = 12
	for i := 0; i < tasks; i++ {
		if _, err := q.Enqueue(ctx, "skill-1", fmt.Sprintf(`{"n":%d}`, i)); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	var mu sync.Mutex
	seen := map[string]int{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < tasks; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			task, ok, err := q.Lease(ctx, "", time.Minute)
			if err != nil || !ok {
				return
			}
			mu.Lock()
			seen[task.ID]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	for id, n := range seen {
		if n > 1 {
			t.Errorf("task %s was leased %d times — two workers would run it concurrently", id, n)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no worker leased anything; the test proved nothing")
	}
}
