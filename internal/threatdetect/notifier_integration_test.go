//go:build integration

// Integration coverage for WebhookNotifier's alert.DeliveryStore recording
// (#1643): the design doc's Notifier test-strategy row explicitly calls for
// "httptest server asserting payload + DeliveryStore row recorded" — the
// notifier_test.go unit tests all pass a nil DeliveryStore (delivery
// recording is optional there), so this is the one place that actually
// proves a delivery attempt lands in the real store an operator queries.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/threatdetect/
package threatdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/alert"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func deliveryPool(t *testing.T) *pgxpool.Pool {
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
	// webhook_deliveries is internal/alert's own table; other packages'
	// integration tests run concurrently against this same database in CI,
	// so only reset the rows this test writes, not the table itself.
	if _, err := pool.Exec(context.Background(), `DELETE FROM webhook_deliveries WHERE source = 'threatdetect'`); err != nil {
		t.Fatalf("reset (webhook_deliveries): %v", err)
	}
	return pool
}

// The #1643 acceptance test: a successful delivery is recorded in the real
// DeliveryStore an operator queries via the existing alert-delivery surface
// — not just logged.
func TestWebhookNotifier_RecordsSuccessfulDeliveryInRealDeliveryStore(t *testing.T) {
	ctx := context.Background()
	pool := deliveryPool(t)
	deliveryStore, err := alert.NewDeliveryStore(ctx, pool)
	if err != nil {
		t.Fatalf("alert.NewDeliveryStore: %v", err)
	}

	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := newFakeConfigSource(srv.URL, "")
	n := NewWebhookNotifier(cfg, deliveryStore)
	notifyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	n.Start(notifyCtx)

	f := testFinding(pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	n.Notify(f)

	waitFor(t, 2*time.Second, func() bool {
		deliveries, _, err := deliveryStore.List(ctx, 10, 0)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for _, d := range deliveries {
			if d.Source == "threatdetect" {
				return true
			}
		}
		return false
	})

	deliveries, _, err := deliveryStore.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found *alert.WebhookDelivery
	for i := range deliveries {
		if deliveries[i].Source == "threatdetect" {
			found = &deliveries[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no webhook_deliveries row with source=threatdetect")
	}
	if !found.Success {
		t.Errorf("Success = false, want true (HTTPStatus=%d ErrorMessage=%q)", found.HTTPStatus, found.ErrorMessage)
	}
	if found.HTTPStatus != http.StatusOK {
		t.Errorf("HTTPStatus = %d, want %d", found.HTTPStatus, http.StatusOK)
	}
	if found.AlertName != f.Rule.String() {
		t.Errorf("AlertName = %q, want %q", found.AlertName, f.Rule.String())
	}
	if found.PayloadSize != len(gotBody) {
		t.Errorf("PayloadSize = %d, want %d (actual payload received)", found.PayloadSize, len(gotBody))
	}
}

// A failed delivery (dead webhook) is also recorded — an operator triaging
// "why didn't I get alerted" needs the failure visible, not silently
// dropped once retries are exhausted.
func TestWebhookNotifier_RecordsFailedDeliveryInRealDeliveryStore(t *testing.T) {
	ctx := context.Background()
	pool := deliveryPool(t)
	deliveryStore, err := alert.NewDeliveryStore(ctx, pool)
	if err != nil {
		t.Fatalf("alert.NewDeliveryStore: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := newFakeConfigSource(srv.URL, "")
	n := NewWebhookNotifier(cfg, deliveryStore)
	notifyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	n.Start(notifyCtx)

	n.Notify(testFinding(pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL))

	waitFor(t, 3*time.Second, func() bool {
		deliveries, _, err := deliveryStore.List(ctx, 10, 0)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for _, d := range deliveries {
			if d.Source == "threatdetect" && !d.Success {
				return true
			}
		}
		return false
	})
}
