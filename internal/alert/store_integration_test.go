//go:build integration

// Integration coverage for the alert rule and webhook delivery stores (#1300).
//
// An alert rule that does not survive its round trip, or is dropped from the
// enabled set, is an alert that never fires — and the observable outcome of a
// rule that never fires is silence, which is also the observable outcome of
// nothing being wrong. That pair is why this store is worth exercising rather
// than assuming: you find out during an incident.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/alert/
package alert

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func alertPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping, so a lane that " +
			"loses its database reports it instead of going quietly green.")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	for _, q := range []string{`DROP TABLE IF EXISTS alert_rules`, `DROP TABLE IF EXISTS webhook_deliveries`} {
		if _, err := pool.Exec(context.Background(), q); err != nil {
			t.Fatalf("reset (%s): %v", q, err)
		}
	}
	return pool
}

func alertStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(context.Background(), alertPool(t))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// A rule must come back as it went in. Severity in particular is written into
// the generated Prometheus rule as a routing label (#1305) — a value mangled
// on the round trip routes the alert nowhere.
func TestAlertStore_RuleRoundTrips(t *testing.T) {
	ctx := context.Background()
	s := alertStore(t)

	created, err := s.Create(ctx, &AlertRule{
		Name:        "HighCPU",
		Expr:        `rate(cpu_seconds[5m]) > 0.9`,
		Duration:    "5m",
		Severity:    SeverityCritical,
		Description: "CPU is pinned",
		Labels:      map[string]string{"team": "platform"},
		Annotations: map[string]string{"runbook_url": "https://example.com/rb"},
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q — this value becomes the routing label, so a mangled "+
			"one sends the alert nowhere", got.Severity, SeverityCritical)
	}
	if got.Expr != `rate(cpu_seconds[5m]) > 0.9` {
		t.Errorf("expr = %q, want the original — a rewritten expression fires on something else",
			got.Expr)
	}
	// Labels and annotations are JSON columns, the most likely thing to be
	// lost silently in a round trip.
	if got.Labels["team"] != "platform" {
		t.Errorf("labels did not survive: %v", got.Labels)
	}
	if got.Annotations["runbook_url"] != "https://example.com/rb" {
		t.Errorf("annotations did not survive: %v", got.Annotations)
	}
}

// ListEnabled is what the rule generator reads. A disabled rule appearing
// fires alerts an operator switched off; an enabled one missing means the
// alert silently never fires.
func TestAlertStore_ListEnabledReturnsExactlyTheEnabledRules(t *testing.T) {
	ctx := context.Background()
	s := alertStore(t)

	on, err := s.Create(ctx, &AlertRule{Name: "on", Expr: "up == 0", Duration: "5m", Severity: SeverityWarning, Enabled: true})
	if err != nil {
		t.Fatalf("create enabled: %v", err)
	}
	if _, err := s.Create(ctx, &AlertRule{Name: "off", Expr: "up == 0", Duration: "5m", Severity: SeverityWarning, Enabled: false}); err != nil {
		t.Fatalf("create disabled: %v", err)
	}

	enabled, err := s.ListEnabled(ctx)
	if err != nil {
		t.Fatalf("ListEnabled: %v", err)
	}
	if len(enabled) != 1 {
		t.Fatalf("ListEnabled returned %d rules, want 1", len(enabled))
	}
	if enabled[0].ID != on.ID {
		t.Errorf("ListEnabled returned the wrong rule: %+v", enabled[0])
	}
	if !enabled[0].Enabled {
		t.Error("a disabled rule came back from ListEnabled — an operator who switched an alert " +
			"off would keep receiving it")
	}
}

// Deleting a rule has to stop it firing. A delete that does not take leaves
// an alert an operator believes is gone.
func TestAlertStore_DeleteStopsTheRuleBeingServed(t *testing.T) {
	ctx := context.Background()
	s := alertStore(t)

	r, err := s.Create(ctx, &AlertRule{Name: "temp", Expr: "up == 0", Duration: "5m", Severity: SeverityInfo, Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Delete(ctx, r.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := s.Get(ctx, r.ID); err == nil {
		t.Error("a deleted rule is still readable")
	}
	enabled, _ := s.ListEnabled(ctx)
	for _, e := range enabled {
		if e.ID == r.ID {
			t.Error("a deleted rule is still served to the generator — it keeps firing after an " +
				"operator removed it")
		}
	}
}

// --- webhook delivery ------------------------------------------------

// The delivery record is the only evidence an alert reached its webhook. A
// failed delivery recorded as successful is the worst case: the operator sees
// a delivery that never landed.
func TestAlertDeliveryStore_RecordsOutcomeFaithfully(t *testing.T) {
	ctx := context.Background()
	pool := alertPool(t)
	s, err := NewDeliveryStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewDeliveryStore: %v", err)
	}

	if err := s.Record(ctx, &WebhookDelivery{
		AlertName: "HighCPU", Source: "relay", WebhookURL: "https://hooks.example.com/xxx",
		Success: false, HTTPStatus: 503, ErrorMessage: "upstream unavailable",
		PayloadSize: 128, DurationMs: 42,
	}); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	if err := s.Record(ctx, &WebhookDelivery{
		AlertName: "HighCPU", Source: "relay", WebhookURL: "https://hooks.example.com/xxx",
		Success: true, HTTPStatus: 200, PayloadSize: 128, DurationMs: 12,
	}); err != nil {
		t.Fatalf("record success: %v", err)
	}

	rows, total, err := s.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("total=%d rows=%d, want 2 and 2", total, len(rows))
	}

	var failures, successes int
	for _, r := range rows {
		if r.Success {
			successes++
			continue
		}
		failures++
		if r.HTTPStatus != 503 || r.ErrorMessage != "upstream unavailable" {
			t.Errorf("the failure lost its detail: status=%d err=%q", r.HTTPStatus, r.ErrorMessage)
		}
	}
	if failures != 1 || successes != 1 {
		t.Errorf("recorded %d failures and %d successes, want one of each — a failed delivery "+
			"stored as successful shows the operator a webhook that never landed",
			failures, successes)
	}
}
