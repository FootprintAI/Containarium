package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertRule represents a custom alert rule persisted in PostgreSQL
type AlertRule struct {
	ID          string
	Name        string
	Expr        string
	Duration    string
	Severity    string
	Description string
	Labels      map[string]string
	Annotations map[string]string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Store handles persistent storage of alert rules
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new alert store connected to PostgreSQL
func NewStore(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	store := &Store{pool: pool}

	if err := store.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize alert schema: %w", err)
	}

	return store, nil
}

// initSchema creates the database schema if it doesn't exist
func (s *Store) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS alert_rules (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL,
			expr TEXT NOT NULL,
			duration TEXT NOT NULL DEFAULT '5m',
			severity TEXT NOT NULL DEFAULT 'warning',
			description TEXT NOT NULL DEFAULT '',
			labels JSONB NOT NULL DEFAULT '{}',
			annotations JSONB NOT NULL DEFAULT '{}',
			enabled BOOLEAN NOT NULL DEFAULT true,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled
			ON alert_rules(enabled);
		CREATE INDEX IF NOT EXISTS idx_alert_rules_severity
			ON alert_rules(severity);
	`

	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Create inserts a new alert rule and returns it with the generated ID
func (s *Store) Create(ctx context.Context, rule *AlertRule) (*AlertRule, error) {
	labelsJSON, err := json.Marshal(rule.Labels)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal labels: %w", err)
	}
	annotationsJSON, err := json.Marshal(rule.Annotations)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal annotations: %w", err)
	}

	query := `
		INSERT INTO alert_rules (name, expr, duration, severity, description, labels, annotations, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at
	`

	var id string
	var createdAt, updatedAt time.Time
	err = s.pool.QueryRow(ctx, query,
		rule.Name, rule.Expr, rule.Duration, rule.Severity,
		rule.Description, labelsJSON, annotationsJSON, rule.Enabled,
	).Scan(&id, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert alert rule: %w", err)
	}

	rule.ID = id
	rule.CreatedAt = createdAt
	rule.UpdatedAt = updatedAt
	return rule, nil
}

// Get retrieves a single alert rule by ID
func (s *Store) Get(ctx context.Context, id string) (*AlertRule, error) {
	query := `
		SELECT id, name, expr, duration, severity, description,
			labels, annotations, enabled, created_at, updated_at
		FROM alert_rules WHERE id = $1
	`

	rule := &AlertRule{}
	var labelsJSON, annotationsJSON []byte
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&rule.ID, &rule.Name, &rule.Expr, &rule.Duration, &rule.Severity,
		&rule.Description, &labelsJSON, &annotationsJSON,
		&rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("alert rule not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get alert rule: %w", err)
	}

	if err := json.Unmarshal(labelsJSON, &rule.Labels); err != nil {
		return nil, fmt.Errorf("failed to unmarshal labels: %w", err)
	}
	if err := json.Unmarshal(annotationsJSON, &rule.Annotations); err != nil {
		return nil, fmt.Errorf("failed to unmarshal annotations: %w", err)
	}

	return rule, nil
}

// List retrieves all alert rules
func (s *Store) List(ctx context.Context) ([]*AlertRule, error) {
	query := `
		SELECT id, name, expr, duration, severity, description,
			labels, annotations, enabled, created_at, updated_at
		FROM alert_rules ORDER BY created_at DESC
	`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list alert rules: %w", err)
	}
	defer rows.Close()

	var rules []*AlertRule
	for rows.Next() {
		rule := &AlertRule{}
		var labelsJSON, annotationsJSON []byte
		if err := rows.Scan(
			&rule.ID, &rule.Name, &rule.Expr, &rule.Duration, &rule.Severity,
			&rule.Description, &labelsJSON, &annotationsJSON,
			&rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan alert rule: %w", err)
		}

		if err := json.Unmarshal(labelsJSON, &rule.Labels); err != nil {
			return nil, fmt.Errorf("failed to unmarshal labels: %w", err)
		}
		if err := json.Unmarshal(annotationsJSON, &rule.Annotations); err != nil {
			return nil, fmt.Errorf("failed to unmarshal annotations: %w", err)
		}

		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alert rules: %w", err)
	}

	return rules, nil
}

// ListEnabled retrieves only enabled alert rules
func (s *Store) ListEnabled(ctx context.Context) ([]*AlertRule, error) {
	query := `
		SELECT id, name, expr, duration, severity, description,
			labels, annotations, enabled, created_at, updated_at
		FROM alert_rules WHERE enabled = true ORDER BY created_at DESC
	`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list enabled alert rules: %w", err)
	}
	defer rows.Close()

	var rules []*AlertRule
	for rows.Next() {
		rule := &AlertRule{}
		var labelsJSON, annotationsJSON []byte
		if err := rows.Scan(
			&rule.ID, &rule.Name, &rule.Expr, &rule.Duration, &rule.Severity,
			&rule.Description, &labelsJSON, &annotationsJSON,
			&rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan alert rule: %w", err)
		}

		if err := json.Unmarshal(labelsJSON, &rule.Labels); err != nil {
			return nil, fmt.Errorf("failed to unmarshal labels: %w", err)
		}
		if err := json.Unmarshal(annotationsJSON, &rule.Annotations); err != nil {
			return nil, fmt.Errorf("failed to unmarshal annotations: %w", err)
		}

		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alert rules: %w", err)
	}

	return rules, nil
}

// Update updates an existing alert rule
func (s *Store) Update(ctx context.Context, rule *AlertRule) (*AlertRule, error) {
	labelsJSON, err := json.Marshal(rule.Labels)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal labels: %w", err)
	}
	annotationsJSON, err := json.Marshal(rule.Annotations)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal annotations: %w", err)
	}

	query := `
		UPDATE alert_rules SET
			name = $2, expr = $3, duration = $4, severity = $5,
			description = $6, labels = $7, annotations = $8,
			enabled = $9, updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at
	`

	var updatedAt time.Time
	err = s.pool.QueryRow(ctx, query,
		rule.ID, rule.Name, rule.Expr, rule.Duration, rule.Severity,
		rule.Description, labelsJSON, annotationsJSON, rule.Enabled,
	).Scan(&updatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("alert rule not found: %s", rule.ID)
		}
		return nil, fmt.Errorf("failed to update alert rule: %w", err)
	}

	rule.UpdatedAt = updatedAt
	return rule, nil
}

// Delete removes an alert rule by ID
func (s *Store) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM alert_rules WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete alert rule: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("alert rule not found: %s", id)
	}
	return nil
}

// Close closes the underlying connection pool
func (s *Store) Close() {
	s.pool.Close()
}
