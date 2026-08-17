package security

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres coverage for the ClamAV scan store (#1300).
//
// Two things live here: the antivirus report history, and the job queue the
// scan workers claim from. The queue carries a retry policy — a failed job goes
// back to pending until it has burned its retries, then gives up — and that
// policy is real logic with two bad directions. Retry too eagerly and a
// permanently-failing job cycles forever, occupying a worker and never
// clearing. Retry too little and a transient failure loses a container's scan
// silently.
//
// The package's existing test covers ClamAV output parsing; nothing covered the
// store.

func securityTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := NewStore(context.Background(), pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Container names namespace this test's rows; every query filters on them.
	container := fmt.Sprintf("t%d-%s", os.Getpid(), t.Name())
	if len(container) > 60 {
		container = container[:60]
	}
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(),
			"DELETE FROM clamav_reports WHERE container_name = $1", container)
		_, _ = store.pool.Exec(context.Background(),
			"DELETE FROM scan_jobs WHERE container_name = $1", container)
	})
	return store, container
}

func aReport(container, status string, count int, when time.Time) *Report {
	return &Report{
		ContainerName: container,
		Username:      "alice",
		Status:        status,
		FindingsCount: count,
		Findings:      "Eicar-Test-Signature",
		ScannedAt:     when,
		ScanDuration:  "3s",
	}
}

func TestSecurityStore_ReportRoundTrips(t *testing.T) {
	ctx := context.Background()
	store, container := securityTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := store.SaveReport(ctx, aReport(container, "infected", 2, now)); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}

	reports, total, err := store.ListReports(ctx, ListParams{ContainerName: container, Limit: 10})
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if total != 1 || len(reports) != 1 {
		t.Fatalf("got %d report(s) (total %d), want 1", len(reports), total)
	}
	r := reports[0]
	if r.GetStatus() != "infected" || r.GetFindingsCount() != 2 {
		t.Errorf("status=%q count=%d, want infected/2 — this is the record that says a container "+
			"has malware on it", r.GetStatus(), r.GetFindingsCount())
	}
	if r.GetFindings() == "" {
		t.Error("the findings text is empty — an operator told a container is infected and not " +
			"what was found cannot act on it")
	}
}

// Re-saving the same scan must not duplicate it. Unlike the traffic store's
// absent constraint (#1394), clamav_reports really does carry
// UNIQUE(container_name, scanned_at), so ON CONFLICT DO NOTHING can fire —
// asserted rather than assumed, because that is exactly the difference #1394
// turned on.
func TestSecurityStore_SaveReportIsIdempotentForOneScan(t *testing.T) {
	ctx := context.Background()
	store, container := securityTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	for i := 0; i < 2; i++ {
		if err := store.SaveReport(ctx, aReport(container, "clean", 0, now)); err != nil {
			t.Fatalf("SaveReport #%d: %v", i+1, err)
		}
	}

	_, total, err := store.ListReports(ctx, ListParams{ContainerName: container, Limit: 10})
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if total != 1 {
		t.Errorf("one scan stored %d times — a retried write would inflate the history and any "+
			"count of how often a container was found infected", total)
	}
}

// The status filter is what an operator uses to find infected containers, so
// an over-broad filter buries the finding among clean scans.
func TestSecurityStore_ListFiltersByStatus(t *testing.T) {
	ctx := context.Background()
	store, container := securityTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := store.SaveReport(ctx, aReport(container, "clean", 0, now)); err != nil {
		t.Fatalf("SaveReport(clean): %v", err)
	}
	if err := store.SaveReport(ctx, aReport(container, "infected", 1, now.Add(time.Minute))); err != nil {
		t.Fatalf("SaveReport(infected): %v", err)
	}

	got, _, err := store.ListReports(ctx, ListParams{
		ContainerName: container, Status: "infected", Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListReports(infected): %v", err)
	}
	if len(got) != 1 || got[0].GetStatus() != "infected" {
		t.Fatalf("status filter returned %d row(s) %v, want only the infected one",
			len(got), got)
	}
}

// --- the job queue and its retry policy ----------------------------------

// A failed job returns to pending until its retries are spent, then fails for
// good. Both directions matter: forever-pending is a poisoned job cycling
// through a worker indefinitely; failing on the first error silently loses a
// container's scan to a transient problem.
func TestSecurityStore_FailedJobRetriesThenGivesUp(t *testing.T) {
	ctx := context.Background()
	store, container := securityTestStore(t)

	id, err := store.EnqueueScanJob(ctx, container, "alice")
	if err != nil {
		t.Fatalf("EnqueueScanJob: %v", err)
	}

	max := securityJobField(t, store, id).MaxRetries
	if max < 1 {
		t.Fatalf("max_retries is %d, so there is no retry policy to test", max)
	}

	// Each failure short of the limit must return the job to the queue.
	for attempt := 1; attempt <= max-1; attempt++ {
		if err := store.FailJob(ctx, id, "clamd unreachable"); err != nil {
			t.Fatalf("FailJob(attempt %d): %v", attempt, err)
		}
		job := securityJobField(t, store, id)
		if job.Status != "pending" {
			t.Fatalf("after failure %d of %d the job is %q, want pending — a transient error "+
				"would lose this container's scan entirely", attempt, max, job.Status)
		}
		if job.RetryCount != attempt {
			t.Errorf("retry_count = %d after %d failure(s)", job.RetryCount, attempt)
		}
		if job.StartedAt != nil {
			t.Error("started_at survived a re-queue — the job would look like it is already " +
				"running and never be claimed again")
		}
	}

	// The failure that exhausts the budget must stick.
	if err := store.FailJob(ctx, id, "clamd unreachable"); err != nil {
		t.Fatalf("FailJob(final): %v", err)
	}
	job := securityJobField(t, store, id)
	if job.Status != "failed" {
		t.Errorf("after exhausting %d retries the job is %q, want failed — a permanently broken "+
			"job would cycle through a worker forever", max, job.Status)
	}
	if job.CompletedAt == nil {
		t.Error("a finally-failed job has no completed_at, so nothing records when it gave up")
	}
}

// securityJobField reads one job back by id.
func securityJobField(t *testing.T, store *Store, id int64) ScanJob {
	t.Helper()
	var j ScanJob
	if err := store.pool.QueryRow(context.Background(),
		`SELECT id, container_name, status, retry_count, max_retries, started_at, completed_at
		 FROM scan_jobs WHERE id = $1`, id,
	).Scan(&j.ID, &j.ContainerName, &j.Status, &j.RetryCount, &j.MaxRetries,
		&j.StartedAt, &j.CompletedAt); err != nil {
		t.Fatalf("read job %d: %v", id, err)
	}
	return j
}

// A re-queued job must be claimable again, or the retry is theatre: the row
// says pending and no worker ever picks it up.
func TestSecurityStore_ARequeuedJobCanBeClaimedAgain(t *testing.T) {
	ctx := context.Background()
	store, container := securityTestStore(t)

	id, err := store.EnqueueScanJob(ctx, container, "alice")
	if err != nil {
		t.Fatalf("EnqueueScanJob: %v", err)
	}
	if err := store.FailJob(ctx, id, "transient"); err != nil {
		t.Fatalf("FailJob: %v", err)
	}
	if got := securityJobField(t, store, id).Status; got != "pending" {
		t.Fatalf("precondition: job is %q after one failure, want pending", got)
	}

	// Drain until this job comes back round — other tests' jobs may be ahead
	// of it in the queue.
	for i := 0; i < 200; i++ {
		job, err := store.ClaimNextJob(ctx)
		if err != nil {
			t.Fatalf("ClaimNextJob: %v", err)
		}
		if job == nil {
			break
		}
		if job.ID == id {
			return // claimed again, which is the property under test
		}
	}
	t.Error("a re-queued job was never claimed — the retry sets status back to pending but no " +
		"worker picks it up, so the scan is lost while the row claims it is waiting")
}

// Two workers claiming at once must not get the same job. Nothing about this
// is observable single-threaded: a sequential test passes just as happily
// without whatever exclusion the query relies on, while in production one
// container is scanned twice and another not at all.
func TestSecurityStore_ConcurrentClaimsGetDistinctJobs(t *testing.T) {
	ctx := context.Background()
	store, container := securityTestStore(t)

	const jobs = 6
	for i := 0; i < jobs; i++ {
		if _, err := store.EnqueueScanJob(ctx, fmt.Sprintf("%s-%d", container, i), "alice"); err != nil {
			t.Fatalf("EnqueueScanJob(%d): %v", i, err)
		}
	}
	t.Cleanup(func() {
		for i := 0; i < jobs; i++ {
			_, _ = store.pool.Exec(context.Background(),
				"DELETE FROM scan_jobs WHERE container_name = $1", fmt.Sprintf("%s-%d", container, i))
		}
	})

	var mu sync.Mutex
	claimed := map[int64]int{}
	var wg sync.WaitGroup
	for w := 0; w < jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, err := store.ClaimNextJob(context.Background())
			if err != nil || job == nil {
				return
			}
			mu.Lock()
			claimed[job.ID]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(claimed) == 0 {
		t.Fatal("no jobs were claimed at all, so this proves nothing about exclusivity")
	}
	for id, n := range claimed {
		if n > 1 {
			t.Errorf("job %d was claimed %d times — two workers scan one container while another "+
				"is never scanned", id, n)
		}
	}
}

func TestSecurityStore_ClaimOnAnEmptyQueueIsNotAnError(t *testing.T) {
	ctx := context.Background()
	store, _ := securityTestStore(t)

	for i := 0; i < 200; i++ {
		job, err := store.ClaimNextJob(ctx)
		if err != nil {
			t.Fatalf("draining: %v", err)
		}
		if job == nil {
			break
		}
	}

	job, err := store.ClaimNextJob(ctx)
	if err != nil {
		t.Fatalf("claiming from an empty queue returned %v, want nil — the worker loop would log "+
			"an error on every idle poll", err)
	}
	if job != nil {
		t.Errorf("got job %+v from a queue that should be empty", job)
	}
}

func TestSecurityStore_SchemaInitIsRepeatable(t *testing.T) {
	ctx := context.Background()
	store, container := securityTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := store.SaveReport(ctx, aReport(container, "infected", 1, now)); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}
	if _, err := NewStore(ctx, store.pool); err != nil {
		t.Fatalf("re-initialising the schema failed: %v — the daemon would not start twice", err)
	}

	_, total, err := store.ListReports(ctx, ListParams{ContainerName: container, Limit: 10})
	if err != nil {
		t.Fatalf("ListReports after re-init: %v", err)
	}
	if total != 1 {
		t.Errorf("the report did not survive a schema re-init — a restart would erase the "+
			"malware-scan history (%d rows)", total)
	}
}
