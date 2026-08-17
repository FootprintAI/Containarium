package zap

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres coverage for the ZAP alert store (#1300).
//
// This store holds web-vulnerability findings and their lifecycle: open,
// suppressed, resolved. "Resolved" here does not mean a human checked
// anything — it means a later scan did not report the finding again, which the
// UI and any alerting on top read as "fixed".
//
// So the load-bearing property is *which* alerts a finishing scan is allowed
// to resolve. Resolving too few is noise; resolving too many silently closes
// live vulnerabilities and is the failure nobody sees, because a closed alert
// stops being displayed.
//
// The store had no test of any kind.

func zapTestStore(t *testing.T) (*Store, string) {
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

	// Fingerprints are globally UNIQUE, so every test needs its own namespace
	// or concurrent runs collide on the upsert.
	tag := fmt.Sprintf("t%d-%s", os.Getpid(), t.Name())
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(),
			"DELETE FROM zap_alerts WHERE fingerprint LIKE $1", tag+"%")
	})
	return store, tag
}

func anAlert(fingerprint, risk, url string) Alert {
	return Alert{
		Fingerprint: fingerprint,
		PluginID:    "10038",
		AlertName:   "Content Security Policy Header Not Set",
		Risk:        risk,
		Confidence:  "High",
		Description: "no CSP header",
		URL:         url,
		Method:      "GET",
	}
}

// A finding seen again must keep its first-seen date and gain a new last-seen.
// "How long has this been open" is the question an operator asks of a
// vulnerability, and an upsert that rewrote first_seen_at would answer it with
// "since the last scan" forever.
func TestZapStore_ReSeenAlertKeepsItsFirstSeenDate(t *testing.T) {
	ctx := context.Background()
	store, tag := zapTestStore(t)

	run1, err := store.CreateScanRun(ctx, "manual", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	fp := tag + "-recurring"
	if err := store.SaveAlerts(ctx, run1, []Alert{anAlert(fp, "High", "https://a.example.com/")}); err != nil {
		t.Fatalf("SaveAlerts: %v", err)
	}

	var firstSeen, lastSeen string
	if err := store.pool.QueryRow(ctx,
		"SELECT first_seen_at::text, last_seen_at::text FROM zap_alerts WHERE fingerprint = $1", fp,
	).Scan(&firstSeen, &lastSeen); err != nil {
		t.Fatalf("read timestamps: %v", err)
	}

	// A second scan reports the same finding.
	run2, err := store.CreateScanRun(ctx, "scheduled", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun(2): %v", err)
	}
	if err := store.SaveAlerts(ctx, run2, []Alert{anAlert(fp, "High", "https://a.example.com/")}); err != nil {
		t.Fatalf("SaveAlerts(2): %v", err)
	}

	var firstSeen2, lastSeen2 string
	if err := store.pool.QueryRow(ctx,
		"SELECT first_seen_at::text, last_seen_at::text FROM zap_alerts WHERE fingerprint = $1", fp,
	).Scan(&firstSeen2, &lastSeen2); err != nil {
		t.Fatalf("read timestamps after re-save: %v", err)
	}
	if firstSeen2 != firstSeen {
		t.Errorf("first_seen_at moved from %s to %s — an alert open for months would report as "+
			"newly discovered on every scan", firstSeen, firstSeen2)
	}
	if lastSeen2 == lastSeen {
		t.Errorf("last_seen_at did not move (%s) — a still-present finding would look stale and "+
			"could be mistaken for one nobody has re-checked", lastSeen)
	}
}

// A suppressed finding that reappears must stay suppressed. Otherwise every
// scan resurfaces something an operator has already dismissed, and the
// suppression feature is decorative.
func TestZapStore_SuppressionSurvivesTheAlertBeingSeenAgain(t *testing.T) {
	ctx := context.Background()
	store, tag := zapTestStore(t)

	run, err := store.CreateScanRun(ctx, "manual", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	fp := tag + "-suppressed"
	if err := store.SaveAlerts(ctx, run, []Alert{anAlert(fp, "Low", "https://a.example.com/")}); err != nil {
		t.Fatalf("SaveAlerts: %v", err)
	}

	var id int64
	if err := store.pool.QueryRow(ctx,
		"SELECT id FROM zap_alerts WHERE fingerprint = $1", fp).Scan(&id); err != nil {
		t.Fatalf("read id: %v", err)
	}
	if err := store.SuppressAlert(ctx, id, "accepted risk"); err != nil {
		t.Fatalf("SuppressAlert: %v", err)
	}

	// The next scan reports it again.
	run2, err := store.CreateScanRun(ctx, "scheduled", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun(2): %v", err)
	}
	if err := store.SaveAlerts(ctx, run2, []Alert{anAlert(fp, "Low", "https://a.example.com/")}); err != nil {
		t.Fatalf("SaveAlerts(2): %v", err)
	}

	var status string
	var suppressed bool
	if err := store.pool.QueryRow(ctx,
		"SELECT status, suppressed FROM zap_alerts WHERE fingerprint = $1", fp,
	).Scan(&status, &suppressed); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !suppressed || status != "suppressed" {
		t.Errorf("status=%q suppressed=%v after being seen again, want suppressed — a dismissed "+
			"finding reappearing on every scan makes the suppression feature useless", status, suppressed)
	}
}

// The core of the lifecycle: seen in this scan → still open; not seen →
// resolved.
func TestZapStore_MarkResolvedClosesOnlyWhatThisScanDidNotSee(t *testing.T) {
	ctx := context.Background()
	store, tag := zapTestStore(t)

	run, err := store.CreateScanRun(ctx, "manual", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	stillThere, gone := tag+"-still", tag+"-gone"
	if err := store.SaveAlerts(ctx, run, []Alert{
		anAlert(stillThere, "High", "https://a.example.com/"),
		anAlert(gone, "Medium", "https://a.example.com/old"),
	}); err != nil {
		t.Fatalf("SaveAlerts: %v", err)
	}

	// A later scan of the same target reports only one of them.
	run2, err := store.CreateScanRun(ctx, "scheduled", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun(2): %v", err)
	}
	if err := store.SaveAlerts(ctx, run2, []Alert{anAlert(stillThere, "High", "https://a.example.com/")}); err != nil {
		t.Fatalf("SaveAlerts(2): %v", err)
	}
	if err := store.MarkResolved(ctx, run2, []string{stillThere}); err != nil {
		t.Fatalf("MarkResolved: %v", err)
	}

	if got := zapStatusOf(t, store, stillThere); got != "open" {
		t.Errorf("a finding reported by this scan is %q, want open — resolving it tells the "+
			"operator a live vulnerability is fixed", got)
	}
	if got := zapStatusOf(t, store, gone); got != "resolved" {
		t.Errorf("a finding this scan no longer reports is %q, want resolved", got)
	}
}

func zapStatusOf(t *testing.T, store *Store, fingerprint string) string {
	t.Helper()
	var status string
	if err := store.pool.QueryRow(context.Background(),
		"SELECT status FROM zap_alerts WHERE fingerprint = $1", fingerprint).Scan(&status); err != nil {
		t.Fatalf("read status of %s: %v", fingerprint, err)
	}
	return status
}

// CHARACTERIZATION (#1398): MarkResolved ignores its scanRunID.
//
// The parameter is accepted and never used. The UPDATE matches every open
// alert whose fingerprint is not in the seen list — across every scan run,
// every container and every target.
//
// Scan runs ARE per-container (`CreateScanRun(ctx, trigger, containerName)`,
// and `zap_scan_runs.container_name`), so a scan of one container marks every
// other container's open findings resolved. The operator is told those
// vulnerabilities are fixed; nothing scanned them.
func TestZapStore_MarkResolvedClosesOtherContainersFindings(t *testing.T) {
	ctx := context.Background()
	store, tag := zapTestStore(t)

	// Alice's container is scanned and has an open finding.
	aliceRun, err := store.CreateScanRun(ctx, "manual", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun(alice): %v", err)
	}
	aliceFP := tag + "-alice"
	if err := store.SaveAlerts(ctx, aliceRun, []Alert{anAlert(aliceFP, "High", "https://alice.example.com/")}); err != nil {
		t.Fatalf("SaveAlerts(alice): %v", err)
	}

	// A completely separate scan of BOB's container finds its own thing.
	bobRun, err := store.CreateScanRun(ctx, "manual", "bob-container")
	if err != nil {
		t.Fatalf("CreateScanRun(bob): %v", err)
	}
	bobFP := tag + "-bob"
	if err := store.SaveAlerts(ctx, bobRun, []Alert{anAlert(bobFP, "High", "https://bob.example.com/")}); err != nil {
		t.Fatalf("SaveAlerts(bob): %v", err)
	}

	// Bob's scan finishes, reporting only what it saw — Bob's finding.
	if err := store.MarkResolved(ctx, bobRun, []string{bobFP}); err != nil {
		t.Fatalf("MarkResolved(bob): %v", err)
	}

	got := zapStatusOf(t, store, aliceFP)
	if got == "open" {
		t.Fatalf("#1398 no longer reproduces: alice's finding is still open after bob's scan.\n\n" +
			"If you scoped MarkResolved to its scan run, this test has done its job — replace it " +
			"with the positive assertion that a scan resolves only findings within its own scope.")
	}
	if got != "resolved" {
		t.Fatalf("alice's finding is %q, expected the defect to leave it resolved", got)
	}
	t.Logf("REPRODUCED #1398: bob's scan marked alice's untouched High-risk finding %q. "+
		"MarkResolved accepts a scanRunID and never uses it, so any finishing scan closes every "+
		"open alert it did not itself report.", got)
}

// CHARACTERIZATION (#1398, the severe half): an empty seen-list resolves
// EVERYTHING.
//
// MarkResolved special-cases the empty slice into an unfiltered
// `UPDATE ... WHERE status = 'open'`. Two ordinary paths reach it: a scan that
// legitimately finds nothing, and — worse — `GetFingerprintsForScanRun`
// failing, which manager.go logs and then continues past, passing the nil
// slice straight in. So a transient database error while collecting
// fingerprints closes the entire open-alert backlog.
func TestZapStore_MarkResolvedWithNoFingerprintsClosesEverything(t *testing.T) {
	ctx := context.Background()
	store, tag := zapTestStore(t)

	run, err := store.CreateScanRun(ctx, "manual", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	fp := tag + "-untouched"
	if err := store.SaveAlerts(ctx, run, []Alert{anAlert(fp, "High", "https://alice.example.com/")}); err != nil {
		t.Fatalf("SaveAlerts: %v", err)
	}

	// What manager.go passes when GetFingerprintsForScanRun errors: nil.
	emptyRun, err := store.CreateScanRun(ctx, "scheduled", "bob-container")
	if err != nil {
		t.Fatalf("CreateScanRun(empty): %v", err)
	}
	if err := store.MarkResolved(ctx, emptyRun, nil); err != nil {
		t.Fatalf("MarkResolved(nil): %v", err)
	}

	got := zapStatusOf(t, store, fp)
	if got == "open" {
		t.Fatalf("#1398's empty case no longer reproduces: the finding survived an empty " +
			"seen-list.\n\nIf you fixed this, replace this test with the positive assertion — " +
			"an empty result must not be treated as 'everything is fixed', because the most " +
			"likely cause is that the scan or the fingerprint query failed.")
	}
	t.Logf("REPRODUCED #1398 (empty case): a High-risk finding from an unrelated container is "+
		"%q after MarkResolved(nil). manager.go reaches this when GetFingerprintsForScanRun "+
		"errors — it logs and continues — so a transient database error silently closes the "+
		"entire open-alert backlog.", got)
}

// The summary is what a dashboard renders, so suppressed and resolved findings
// must not be counted as live.
func TestZapStore_AlertSummaryExcludesSuppressedAndResolved(t *testing.T) {
	ctx := context.Background()
	store, tag := zapTestStore(t)

	run, err := store.CreateScanRun(ctx, "manual", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	open, supp := tag+"-open", tag+"-supp"
	if err := store.SaveAlerts(ctx, run, []Alert{
		anAlert(open, "High", "https://a.example.com/1"),
		anAlert(supp, "High", "https://a.example.com/2"),
	}); err != nil {
		t.Fatalf("SaveAlerts: %v", err)
	}

	before, err := store.GetAlertSummary(ctx)
	if err != nil {
		t.Fatalf("GetAlertSummary: %v", err)
	}

	var id int64
	if err := store.pool.QueryRow(ctx,
		"SELECT id FROM zap_alerts WHERE fingerprint = $1", supp).Scan(&id); err != nil {
		t.Fatalf("read id: %v", err)
	}
	if err := store.SuppressAlert(ctx, id, "accepted"); err != nil {
		t.Fatalf("SuppressAlert: %v", err)
	}

	after, err := store.GetAlertSummary(ctx)
	if err != nil {
		t.Fatalf("GetAlertSummary after suppression: %v", err)
	}
	if after.HighCount >= before.HighCount {
		t.Errorf("high count went %d -> %d after suppressing one, want a decrease — a "+
			"dashboard would keep alarming on a finding the operator has dismissed",
			before.HighCount, after.HighCount)
	}
}

// The risk breakdown must actually count findings (#1400).
//
// ZAP emits capitalised risks ("High"), stored verbatim; both consumers
// matched lowercase, so every risk count was permanently zero while the alerts
// themselves stored and listed correctly. Asserted through CountAlertsByRisk
// too, because that one is read as byRisk["high"] by manager.go to write the
// scan run's own counts — a separate path with the same mismatch.
func TestZapStore_RiskCountsAreCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	store, tag := zapTestStore(t)

	run, err := store.CreateScanRun(ctx, "manual", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	// Exactly as ZAP emits them.
	if err := store.SaveAlerts(ctx, run, []Alert{
		anAlert(tag+"-h1", "High", "https://a.example.com/1"),
		anAlert(tag+"-h2", "High", "https://a.example.com/2"),
		anAlert(tag+"-m1", "Medium", "https://a.example.com/3"),
	}); err != nil {
		t.Fatalf("SaveAlerts: %v", err)
	}

	byRisk, err := store.CountAlertsByRisk(ctx, run)
	if err != nil {
		t.Fatalf("CountAlertsByRisk: %v", err)
	}
	if byRisk["high"] != 2 || byRisk["medium"] != 1 {
		t.Errorf("byRisk = %v, want high=2 medium=1 — manager.go reads these keys to write the "+
			"scan run's counts, so a miss records every completed scan as having found nothing",
			byRisk)
	}

	summary, err := store.GetAlertSummary(ctx)
	if err != nil {
		t.Fatalf("GetAlertSummary: %v", err)
	}
	if summary.HighCount < 2 {
		t.Errorf("summary HighCount = %d, want at least the 2 just saved — this is what the "+
			"dashboard renders, and zero reads as 'no vulnerabilities'", summary.HighCount)
	}
}

func TestZapStore_SchemaInitIsRepeatable(t *testing.T) {
	ctx := context.Background()
	store, tag := zapTestStore(t)

	run, err := store.CreateScanRun(ctx, "manual", "alice-container")
	if err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	fp := tag + "-survivor"
	if err := store.SaveAlerts(ctx, run, []Alert{anAlert(fp, "High", "https://a.example.com/")}); err != nil {
		t.Fatalf("SaveAlerts: %v", err)
	}

	if _, err := NewStore(ctx, store.pool); err != nil {
		t.Fatalf("re-initialising the schema failed: %v — the daemon would not start twice", err)
	}

	if got := zapStatusOf(t, store, fp); got != "open" {
		t.Errorf("the alert did not survive a schema re-init (status %q) — a restart would erase "+
			"the vulnerability backlog", got)
	}
}
