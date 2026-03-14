package alert

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WebhookDelivery represents a single webhook delivery attempt
type WebhookDelivery struct {
	ID           int64
	Timestamp    time.Time
	AlertName    string
	Source       string // "relay" or "test"
	WebhookURL   string // masked
	Success      bool
	HTTPStatus   int
	ErrorMessage string
	PayloadSize  int
	DurationMs   int
}

// DeliveryStore handles persistent storage of webhook delivery attempts
type DeliveryStore struct {
	pool *pgxpool.Pool

	// Debounce cleanup: only run once per interval
	cleanupMu   sync.Mutex
	lastCleanup time.Time
}

// NewDeliveryStore creates a new delivery store sharing the given pool
func NewDeliveryStore(ctx context.Context, pool *pgxpool.Pool) (*DeliveryStore, error) {
	store := &DeliveryStore{pool: pool}
	if err := store.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize delivery schema: %w", err)
	}
	return store, nil
}

func (s *DeliveryStore) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS webhook_deliveries (
			id BIGSERIAL PRIMARY KEY,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			alert_name TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT '',
			webhook_url TEXT NOT NULL DEFAULT '',
			success BOOLEAN NOT NULL DEFAULT false,
			http_status INTEGER NOT NULL DEFAULT 0,
			error_message TEXT NOT NULL DEFAULT '',
			payload_size INTEGER NOT NULL DEFAULT 0,
			duration_ms INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_timestamp
			ON webhook_deliveries(timestamp DESC);
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Record inserts a new delivery attempt and triggers debounced cleanup
func (s *DeliveryStore) Record(ctx context.Context, d *WebhookDelivery) error {
	query := `
		INSERT INTO webhook_deliveries
			(alert_name, source, webhook_url, success, http_status, error_message, payload_size, duration_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.pool.Exec(ctx, query,
		d.AlertName, d.Source, d.WebhookURL, d.Success,
		d.HTTPStatus, d.ErrorMessage, d.PayloadSize, d.DurationMs,
	)
	if err != nil {
		return fmt.Errorf("failed to record delivery: %w", err)
	}

	// Best-effort cleanup (debounced)
	go s.Cleanup(context.Background())
	return nil
}

// List retrieves delivery history with pagination, returning deliveries and total count
func (s *DeliveryStore) List(ctx context.Context, limit, offset int) ([]WebhookDelivery, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var total int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM webhook_deliveries").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count deliveries: %w", err)
	}

	query := `
		SELECT id, timestamp, alert_name, source, webhook_url, success,
			http_status, error_message, payload_size, duration_ms
		FROM webhook_deliveries
		ORDER BY timestamp DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := s.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list deliveries: %w", err)
	}
	defer rows.Close()

	var deliveries []WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(
			&d.ID, &d.Timestamp, &d.AlertName, &d.Source, &d.WebhookURL,
			&d.Success, &d.HTTPStatus, &d.ErrorMessage, &d.PayloadSize, &d.DurationMs,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan delivery: %w", err)
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating deliveries: %w", err)
	}

	return deliveries, total, nil
}

// Cleanup removes old rows, keeping the last 1000 or rows newer than 30 days.
// Debounced: runs at most once per 10 minutes.
func (s *DeliveryStore) Cleanup(ctx context.Context) {
	s.cleanupMu.Lock()
	if time.Since(s.lastCleanup) < 10*time.Minute {
		s.cleanupMu.Unlock()
		return
	}
	s.lastCleanup = time.Now()
	s.cleanupMu.Unlock()

	// Keep last 1000 rows OR rows newer than 30 days
	query := `
		DELETE FROM webhook_deliveries
		WHERE id NOT IN (
			SELECT id FROM webhook_deliveries ORDER BY timestamp DESC LIMIT 1000
		)
		AND timestamp < NOW() - INTERVAL '30 days'
	`
	s.pool.Exec(ctx, query)
}
