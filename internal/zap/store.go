package zap

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store handles persistent storage of ZAP scan runs and alerts
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new ZAP store connected to PostgreSQL
func NewStore(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	store := &Store{pool: pool}
	if err := store.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize zap schema: %w", err)
	}
	return store, nil
}

func (s *Store) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS zap_scan_runs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			trigger TEXT NOT NULL DEFAULT 'manual',
			status TEXT NOT NULL DEFAULT 'running',
			targets_count INTEGER NOT NULL DEFAULT 0,
			high_count INTEGER NOT NULL DEFAULT 0,
			medium_count INTEGER NOT NULL DEFAULT 0,
			low_count INTEGER NOT NULL DEFAULT 0,
			info_count INTEGER NOT NULL DEFAULT 0,
			error_message TEXT NOT NULL DEFAULT '',
			started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			completed_at TIMESTAMP WITH TIME ZONE
		);
		CREATE INDEX IF NOT EXISTS idx_zap_scan_runs_started
			ON zap_scan_runs(started_at DESC);
		CREATE INDEX IF NOT EXISTS idx_zap_scan_runs_status
			ON zap_scan_runs(status);

		CREATE TABLE IF NOT EXISTS zap_alerts (
			id BIGSERIAL PRIMARY KEY,
			fingerprint TEXT NOT NULL UNIQUE,
			plugin_id TEXT NOT NULL DEFAULT '',
			alert_name TEXT NOT NULL,
			risk TEXT NOT NULL,
			confidence TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			url TEXT NOT NULL,
			method TEXT NOT NULL DEFAULT '',
			evidence TEXT NOT NULL DEFAULT '',
			solution TEXT NOT NULL DEFAULT '',
			cwe_ids TEXT NOT NULL DEFAULT '',
			"references" TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'open',
			first_scan_run_id UUID REFERENCES zap_scan_runs(id) ON DELETE SET NULL,
			last_scan_run_id UUID REFERENCES zap_scan_runs(id) ON DELETE SET NULL,
			first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			resolved_at TIMESTAMP WITH TIME ZONE,
			suppressed BOOLEAN NOT NULL DEFAULT false,
			suppressed_reason TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_zap_alerts_risk
			ON zap_alerts(risk);
		CREATE INDEX IF NOT EXISTS idx_zap_alerts_status
			ON zap_alerts(status);
		CREATE INDEX IF NOT EXISTS idx_zap_alerts_fingerprint
			ON zap_alerts(fingerprint);

		CREATE TABLE IF NOT EXISTS zap_scan_jobs (
			id BIGSERIAL PRIMARY KEY,
			scan_run_id UUID REFERENCES zap_scan_runs(id) ON DELETE CASCADE,
			target_url TEXT NOT NULL,
			container_name TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			retry_count INTEGER NOT NULL DEFAULT 0,
			max_retries INTEGER NOT NULL DEFAULT 2,
			error_message TEXT,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			started_at TIMESTAMP WITH TIME ZONE,
			completed_at TIMESTAMP WITH TIME ZONE
		);
		CREATE INDEX IF NOT EXISTS idx_zap_scan_jobs_status
			ON zap_scan_jobs(status);
		CREATE INDEX IF NOT EXISTS idx_zap_scan_jobs_scan_run_id
			ON zap_scan_jobs(scan_run_id);
		CREATE INDEX IF NOT EXISTS idx_zap_scan_jobs_created_at
			ON zap_scan_jobs(created_at DESC);
	`
	_, err := s.pool.Exec(ctx, schema)
	if err != nil {
		return err
	}

	// Migration: add report columns
	_, err = s.pool.Exec(ctx, `
		ALTER TABLE zap_scan_runs ADD COLUMN IF NOT EXISTS report_html TEXT NOT NULL DEFAULT '';
		ALTER TABLE zap_scan_runs ADD COLUMN IF NOT EXISTS report_json TEXT NOT NULL DEFAULT '';
	`)
	if err != nil {
		return err
	}

	// Migration: container_name column on zap_scan_runs to record which
	// container an operator scoped an on-demand scan to. Empty for
	// every existing row (cluster-wide scans), which is the historical
	// default and remains the behavior when the field is unset.
	_, err = s.pool.Exec(ctx,
		`ALTER TABLE zap_scan_runs ADD COLUMN IF NOT EXISTS container_name TEXT NOT NULL DEFAULT ''`)
	return err
}

// ScanRun represents a ZAP scan execution
type ScanRun struct {
	ID           string
	Trigger      string
	Status       string
	TargetsCount int
	HighCount    int
	MediumCount  int
	LowCount     int
	InfoCount    int
	ErrorMessage string
	StartedAt    time.Time
	CompletedAt  *time.Time
	// ContainerName is set for operator-triggered scans scoped to one
	// container; empty for cluster-wide scheduled scans.
	ContainerName string
}

// AlertRecord represents a stored ZAP alert
type AlertRecord struct {
	ID               int64
	Fingerprint      string
	PluginID         string
	AlertName        string
	Risk             string
	Confidence       string
	Description      string
	URL              string
	Method           string
	Evidence         string
	Solution         string
	CWEIDs           string
	References       string
	Status           string
	FirstScanRunID   *string
	LastScanRunID    *string
	FirstSeenAt      time.Time
	LastSeenAt       time.Time
	ResolvedAt       *time.Time
	Suppressed       bool
	SuppressedReason string
}

// Alert represents a ZAP alert to be saved
type Alert struct {
	Fingerprint string
	PluginID    string
	AlertName   string
	Risk        string
	Confidence  string
	Description string
	URL         string
	Method      string
	Evidence    string
	Solution    string
	CWEIDs      string
	References  string
}

// ScanJob represents a queued ZAP scan job for a single target URL
type ScanJob struct {
	ID            int64
	ScanRunID     string
	TargetURL     string
	ContainerName string
	Status        string // pending | running | completed | failed
	RetryCount    int
	MaxRetries    int
	ErrorMessage  string
	CreatedAt     time.Time
	StartedAt     *time.Time
	CompletedAt   *time.Time
}

// CreateScanRun inserts a new scan run and returns its UUID.
// containerName is empty for cluster-wide scans (the historical default)
// and set when an operator scopes a scan to a specific container.
func (s *Store) CreateScanRun(ctx context.Context, trigger, containerName string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO zap_scan_runs (trigger, container_name) VALUES ($1, $2) RETURNING id`,
		trigger, containerName,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to create zap scan run: %w", err)
	}
	return id, nil
}

// UpdateScanRun updates a scan run's status and counts
func (s *Store) UpdateScanRun(ctx context.Context, run *ScanRun) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE zap_scan_runs
		SET status = $2, targets_count = $3,
			high_count = $4, medium_count = $5, low_count = $6,
			info_count = $7, error_message = $8, completed_at = $9
		WHERE id = $1
	`, run.ID, run.Status, run.TargetsCount,
		run.HighCount, run.MediumCount, run.LowCount,
		run.InfoCount, run.ErrorMessage, run.CompletedAt)
	return err
}

// SaveReport stores generated HTML and JSON reports for a scan run
func (s *Store) SaveReport(ctx context.Context, scanRunID, htmlReport, jsonReport string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE zap_scan_runs SET report_html = $2, report_json = $3 WHERE id = $1
	`, scanRunID, htmlReport, jsonReport)
	return err
}

// GetReport retrieves stored reports for a scan run
func (s *Store) GetReport(ctx context.Context, scanRunID string) (htmlReport, jsonReport string, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT report_html, report_json FROM zap_scan_runs WHERE id = $1
	`, scanRunID).Scan(&htmlReport, &jsonReport)
	return
}

// ListScanRuns returns recent scan runs. If containerName is non-empty,
// only runs scoped to that container are returned.
func (s *Store) ListScanRuns(ctx context.Context, limit, offset int, containerName string) ([]ScanRun, int32, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	// Same pattern as the pentest store — one predicate handles both
	// unfiltered and scoped cases to avoid duplicate SQL strings.
	whereClause := ""
	args := []interface{}{}
	if containerName != "" {
		whereClause = "WHERE container_name = $1"
		args = append(args, containerName)
	}

	var totalCount int32
	err := s.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM zap_scan_runs "+whereClause, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count zap scan runs: %w", err)
	}

	args = append(args, limit, offset)
	limitOffset := fmt.Sprintf("LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := s.pool.Query(ctx, `
		SELECT id, trigger, status, targets_count,
			high_count, medium_count, low_count, info_count,
			error_message, started_at, completed_at, container_name
		FROM zap_scan_runs
		`+whereClause+`
		ORDER BY started_at DESC
		`+limitOffset, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list zap scan runs: %w", err)
	}
	defer rows.Close()

	var runs []ScanRun
	for rows.Next() {
		var run ScanRun
		if err := rows.Scan(
			&run.ID, &run.Trigger, &run.Status, &run.TargetsCount,
			&run.HighCount, &run.MediumCount, &run.LowCount, &run.InfoCount,
			&run.ErrorMessage, &run.StartedAt, &run.CompletedAt, &run.ContainerName,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan zap run row: %w", err)
		}
		runs = append(runs, run)
	}
	return runs, totalCount, rows.Err()
}

// GetScanRun returns a specific scan run by ID
func (s *Store) GetScanRun(ctx context.Context, id string) (*ScanRun, error) {
	run := &ScanRun{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, trigger, status, targets_count,
			high_count, medium_count, low_count, info_count,
			error_message, started_at, completed_at, container_name
		FROM zap_scan_runs
		WHERE id = $1
	`, id).Scan(
		&run.ID, &run.Trigger, &run.Status, &run.TargetsCount,
		&run.HighCount, &run.MediumCount, &run.LowCount, &run.InfoCount,
		&run.ErrorMessage, &run.StartedAt, &run.CompletedAt, &run.ContainerName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get zap scan run: %w", err)
	}
	return run, nil
}

// SaveAlerts batch-upserts alerts by fingerprint
func (s *Store) SaveAlerts(ctx context.Context, scanRunID string, alerts []Alert) error {
	for _, a := range alerts {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO zap_alerts (
				fingerprint, plugin_id, alert_name, risk, confidence,
				description, url, method, evidence, solution,
				cwe_ids, "references", status,
				first_scan_run_id, last_scan_run_id,
				first_seen_at, last_seen_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'open', $13, $13, NOW(), NOW())
			ON CONFLICT (fingerprint) DO UPDATE SET
				last_scan_run_id = $13,
				last_seen_at = NOW(),
				risk = EXCLUDED.risk,
				confidence = EXCLUDED.confidence,
				description = EXCLUDED.description,
				evidence = EXCLUDED.evidence,
				solution = EXCLUDED.solution,
				cwe_ids = EXCLUDED.cwe_ids,
				"references" = EXCLUDED."references",
				status = CASE
					WHEN zap_alerts.suppressed = true THEN 'suppressed'
					ELSE 'open'
				END
		`, a.Fingerprint, a.PluginID, a.AlertName, a.Risk, a.Confidence,
			a.Description, a.URL, a.Method, a.Evidence, a.Solution,
			a.CWEIDs, a.References, scanRunID)
		if err != nil {
			return fmt.Errorf("failed to save zap alert %s: %w", a.Fingerprint, err)
		}
	}
	return nil
}

// AlertListParams holds filter parameters for listing alerts
type AlertListParams struct {
	Risk   string
	Status string
	// Domain filters to alerts whose url contains this host — substring
	// matched (ILIKE) against the stored url column rather than a
	// dedicated host column, since url is the only place the target is
	// recorded today (#zap-domain-filter).
	Domain string
	Limit  int
	Offset int
}

// ListAlerts returns alerts with optional filters
func (s *Store) ListAlerts(ctx context.Context, params AlertListParams) ([]AlertRecord, int32, error) {
	if params.Limit <= 0 {
		params.Limit = 50
	}
	if params.Limit > 1000 {
		params.Limit = 1000
	}

	baseQuery := `SELECT id, fingerprint, plugin_id, alert_name, risk, confidence,
		description, url, method, evidence, solution, cwe_ids, "references", status,
		first_scan_run_id, last_scan_run_id,
		first_seen_at, last_seen_at, resolved_at, suppressed, suppressed_reason
		FROM zap_alerts WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM zap_alerts WHERE 1=1`

	var args []interface{}
	argIdx := 1

	if params.Risk != "" {
		baseQuery += fmt.Sprintf(" AND risk = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND risk = $%d", argIdx)
		args = append(args, params.Risk)
		argIdx++
	}
	if params.Status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, params.Status)
		argIdx++
	}
	if params.Domain != "" {
		baseQuery += fmt.Sprintf(" AND url ILIKE $%d", argIdx)
		countQuery += fmt.Sprintf(" AND url ILIKE $%d", argIdx)
		args = append(args, "%"+params.Domain+"%")
		argIdx++
	}

	var totalCount int32
	err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count zap alerts: %w", err)
	}

	baseQuery += fmt.Sprintf(" ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, params.Limit, params.Offset)

	rows, err := s.pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list zap alerts: %w", err)
	}
	defer rows.Close()

	var alerts []AlertRecord
	for rows.Next() {
		var a AlertRecord
		if err := rows.Scan(
			&a.ID, &a.Fingerprint, &a.PluginID, &a.AlertName, &a.Risk, &a.Confidence,
			&a.Description, &a.URL, &a.Method, &a.Evidence, &a.Solution, &a.CWEIDs, &a.References, &a.Status,
			&a.FirstScanRunID, &a.LastScanRunID,
			&a.FirstSeenAt, &a.LastSeenAt, &a.ResolvedAt, &a.Suppressed, &a.SuppressedReason,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan zap alert row: %w", err)
		}
		alerts = append(alerts, a)
	}
	return alerts, totalCount, rows.Err()
}

// AlertSummary holds aggregate alert statistics
type AlertSummary struct {
	TotalAlerts      int32
	OpenAlerts       int32
	ResolvedAlerts   int32
	SuppressedAlerts int32
	HighCount        int32
	MediumCount      int32
	LowCount         int32
	InfoCount        int32
}

// GetAlertSummary returns aggregate alert statistics
func (s *Store) GetAlertSummary(ctx context.Context) (*AlertSummary, error) {
	summary := &AlertSummary{}

	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'open'),
			COUNT(*) FILTER (WHERE status = 'resolved'),
			COUNT(*) FILTER (WHERE suppressed = true)
		FROM zap_alerts
	`).Scan(&summary.TotalAlerts, &summary.OpenAlerts, &summary.ResolvedAlerts, &summary.SuppressedAlerts)
	if err != nil {
		return nil, fmt.Errorf("failed to get zap alert summary: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT risk, COUNT(*)
		FROM zap_alerts
		WHERE status = 'open'
		GROUP BY risk
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to get zap risk counts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var risk string
		var count int32
		if err := rows.Scan(&risk, &count); err != nil {
			return nil, err
		}
		switch risk {
		case "high":
			summary.HighCount = count
		case "medium":
			summary.MediumCount = count
		case "low":
			summary.LowCount = count
		case "informational":
			summary.InfoCount = count
		}
	}

	return summary, rows.Err()
}

// SuppressAlert marks an alert as suppressed
func (s *Store) SuppressAlert(ctx context.Context, alertID int64, reason string) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE zap_alerts
		SET suppressed = true, suppressed_reason = $2, status = 'suppressed'
		WHERE id = $1
	`, alertID, reason)
	if err != nil {
		return fmt.Errorf("failed to suppress zap alert: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("zap alert %d not found", alertID)
	}
	return nil
}

// MarkResolved marks alerts as resolved if they were not seen in the given scan run
func (s *Store) MarkResolved(ctx context.Context, scanRunID string, seenFingerprints []string) error {
	if len(seenFingerprints) == 0 {
		_, err := s.pool.Exec(ctx, `
			UPDATE zap_alerts
			SET status = 'resolved', resolved_at = NOW()
			WHERE status = 'open'
		`)
		return err
	}

	query := `
		UPDATE zap_alerts
		SET status = 'resolved', resolved_at = NOW()
		WHERE status = 'open' AND fingerprint NOT IN (`
	args := make([]interface{}, len(seenFingerprints))
	for i, fp := range seenFingerprints {
		if i > 0 {
			query += ", "
		}
		query += fmt.Sprintf("$%d", i+1)
		args[i] = fp
	}
	query += ")"

	_, err := s.pool.Exec(ctx, query, args...)
	return err
}

// CountAlertsByRisk returns a map of risk -> count for alerts in a scan run
func (s *Store) CountAlertsByRisk(ctx context.Context, scanRunID string) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT risk, COUNT(*)
		FROM zap_alerts
		WHERE last_scan_run_id = $1
		GROUP BY risk
	`, scanRunID)
	if err != nil {
		return nil, fmt.Errorf("failed to count zap alerts by risk: %w", err)
	}
	defer rows.Close()

	counts := map[string]int{"high": 0, "medium": 0, "low": 0, "informational": 0}
	for rows.Next() {
		var risk string
		var count int
		if err := rows.Scan(&risk, &count); err != nil {
			return nil, err
		}
		counts[risk] = count
	}
	return counts, rows.Err()
}

// GetFingerprintsForScanRun returns all fingerprints of alerts associated with a scan run
func (s *Store) GetFingerprintsForScanRun(ctx context.Context, scanRunID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT fingerprint
		FROM zap_alerts
		WHERE last_scan_run_id = $1
	`, scanRunID)
	if err != nil {
		return nil, fmt.Errorf("failed to get zap fingerprints for scan run: %w", err)
	}
	defer rows.Close()

	var fingerprints []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		fingerprints = append(fingerprints, fp)
	}
	return fingerprints, rows.Err()
}

// EnqueueScanJob inserts a new pending scan job for a target URL
func (s *Store) EnqueueScanJob(ctx context.Context, scanRunID, targetURL, containerName string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO zap_scan_jobs (scan_run_id, target_url, container_name)
		 VALUES ($1, $2, $3) RETURNING id`,
		scanRunID, targetURL, containerName,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("failed to enqueue zap scan job: %w", err)
	}
	return id, nil
}

// ClaimNextJob atomically claims the oldest pending ZAP job for processing
func (s *Store) ClaimNextJob(ctx context.Context) (*ScanJob, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE zap_scan_jobs
		SET status = 'running', started_at = NOW()
		WHERE id = (
			SELECT id FROM zap_scan_jobs
			WHERE status = 'pending'
			ORDER BY created_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, scan_run_id, target_url, container_name,
			status, retry_count, max_retries,
			COALESCE(error_message, ''), created_at, started_at, completed_at
	`)

	job := &ScanJob{}
	err := row.Scan(
		&job.ID, &job.ScanRunID, &job.TargetURL, &job.ContainerName,
		&job.Status, &job.RetryCount, &job.MaxRetries,
		&job.ErrorMessage, &job.CreatedAt, &job.StartedAt, &job.CompletedAt,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to claim zap scan job: %w", err)
	}
	return job, nil
}

// CompleteJob marks a ZAP scan job as completed
func (s *Store) CompleteJob(ctx context.Context, jobID int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE zap_scan_jobs SET status = 'completed', completed_at = NOW() WHERE id = $1`,
		jobID,
	)
	return err
}

// FailJob increments retry_count. If retries remain, re-queues as pending; otherwise marks as failed.
func (s *Store) FailJob(ctx context.Context, jobID int64, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE zap_scan_jobs
		SET retry_count = retry_count + 1,
			error_message = $2,
			status = CASE WHEN retry_count + 1 < max_retries THEN 'pending' ELSE 'failed' END,
			started_at = CASE WHEN retry_count + 1 < max_retries THEN NULL ELSE started_at END,
			completed_at = CASE WHEN retry_count + 1 >= max_retries THEN NOW() ELSE NULL END
		WHERE id = $1
	`, jobID, errMsg)
	return err
}

// CountPendingJobs returns the number of pending or running jobs for a scan run
func (s *Store) CountPendingJobs(ctx context.Context, scanRunID string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM zap_scan_jobs WHERE scan_run_id = $1 AND status IN ('pending', 'running')`,
		scanRunID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count pending zap jobs: %w", err)
	}
	return count, nil
}

// CountFinishedJobs returns the number of completed or failed jobs for a scan run
func (s *Store) CountFinishedJobs(ctx context.Context, scanRunID string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM zap_scan_jobs WHERE scan_run_id = $1 AND status IN ('completed', 'failed')`,
		scanRunID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count finished zap jobs: %w", err)
	}
	return count, nil
}

// Cleanup removes old scan runs and resolved alerts beyond the retention period
func (s *Store) Cleanup(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	_, err := s.pool.Exec(ctx, `DELETE FROM zap_scan_runs WHERE started_at < $1`, cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup zap scan runs: %w", err)
	}

	_, err = s.pool.Exec(ctx, `DELETE FROM zap_alerts WHERE status = 'resolved' AND resolved_at < $1`, cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup zap alerts: %w", err)
	}

	return nil
}

// CleanupOldJobs deletes completed/failed ZAP jobs older than retentionDays
func (s *Store) CleanupOldJobs(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	_, err := s.pool.Exec(ctx,
		`DELETE FROM zap_scan_jobs WHERE status IN ('completed', 'failed') AND created_at < $1`,
		cutoff,
	)
	return err
}

// Close closes the underlying connection pool
func (s *Store) Close() {
	s.pool.Close()
}
