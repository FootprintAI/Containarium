package security

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Store handles persistent storage of ClamAV scan reports
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new security store connected to PostgreSQL
func NewStore(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	store := &Store{pool: pool}

	if err := store.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize security schema: %w", err)
	}

	return store, nil
}

// initSchema creates the database schema if it doesn't exist
func (s *Store) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS clamav_reports (
			id BIGSERIAL PRIMARY KEY,
			container_name TEXT NOT NULL,
			username TEXT NOT NULL,
			status TEXT NOT NULL,
			findings_count INTEGER NOT NULL DEFAULT 0,
			findings TEXT NOT NULL DEFAULT '',
			scanned_at TIMESTAMP WITH TIME ZONE NOT NULL,
			scan_duration TEXT,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			UNIQUE(container_name, scanned_at)
		);

		CREATE INDEX IF NOT EXISTS idx_clamav_container_time
			ON clamav_reports(container_name, scanned_at DESC);
		CREATE INDEX IF NOT EXISTS idx_clamav_status
			ON clamav_reports(status);
		CREATE INDEX IF NOT EXISTS idx_clamav_scanned_at
			ON clamav_reports(scanned_at DESC);

		CREATE TABLE IF NOT EXISTS scan_jobs (
			id BIGSERIAL PRIMARY KEY,
			container_name TEXT NOT NULL,
			username TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			retry_count INTEGER NOT NULL DEFAULT 0,
			max_retries INTEGER NOT NULL DEFAULT 2,
			error_message TEXT,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			started_at TIMESTAMP WITH TIME ZONE,
			completed_at TIMESTAMP WITH TIME ZONE
		);
		CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
		CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at DESC);
	`

	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Report represents a ClamAV scan result
type Report struct {
	ContainerName string
	Username      string
	Status        string // "clean" or "infected"
	FindingsCount int
	Findings      string
	ScannedAt     time.Time
	ScanDuration  string
}

// SaveReport saves a scan report to the database
func (s *Store) SaveReport(ctx context.Context, report *Report) error {
	query := `
		INSERT INTO clamav_reports (
			container_name, username, status, findings_count, findings,
			scanned_at, scan_duration
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (container_name, scanned_at) DO NOTHING
	`

	_, err := s.pool.Exec(ctx, query,
		report.ContainerName,
		report.Username,
		report.Status,
		report.FindingsCount,
		report.Findings,
		report.ScannedAt,
		report.ScanDuration,
	)
	if err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	return nil
}

// ListParams holds parameters for listing reports
type ListParams struct {
	ContainerName string
	Status        string
	From          string // ISO date
	To            string // ISO date
	Limit         int
	Offset        int
}

// ListReports retrieves scan reports with optional filtering
func (s *Store) ListReports(ctx context.Context, params ListParams) ([]*pb.ClamavReport, int32, error) {
	baseQuery := `SELECT id, container_name, username, status, findings_count, findings,
		scanned_at, scan_duration, created_at FROM clamav_reports WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM clamav_reports WHERE 1=1`

	var args []interface{}
	argIdx := 1

	if params.ContainerName != "" {
		baseQuery += fmt.Sprintf(" AND container_name = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND container_name = $%d", argIdx)
		args = append(args, params.ContainerName)
		argIdx++
	}

	if params.Status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, params.Status)
		argIdx++
	}

	if params.From != "" {
		baseQuery += fmt.Sprintf(" AND scanned_at >= $%d", argIdx)
		countQuery += fmt.Sprintf(" AND scanned_at >= $%d", argIdx)
		args = append(args, params.From)
		argIdx++
	}

	if params.To != "" {
		baseQuery += fmt.Sprintf(" AND scanned_at <= $%d", argIdx)
		countQuery += fmt.Sprintf(" AND scanned_at <= $%d", argIdx)
		args = append(args, params.To)
		argIdx++
	}

	// Get total count
	var totalCount int32
	err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count reports: %w", err)
	}

	// Apply pagination
	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	baseQuery += fmt.Sprintf(" ORDER BY scanned_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, params.Offset)

	rows, err := s.pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query reports: %w", err)
	}
	defer rows.Close()

	var reports []*pb.ClamavReport
	for rows.Next() {
		var (
			id            int64
			containerName string
			username      string
			status        string
			findingsCount int32
			findings      string
			scannedAt     time.Time
			scanDuration  *string
			createdAt     time.Time
		)

		if err := rows.Scan(&id, &containerName, &username, &status, &findingsCount,
			&findings, &scannedAt, &scanDuration, &createdAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan row: %w", err)
		}

		report := &pb.ClamavReport{
			Id:            id,
			ContainerName: containerName,
			Username:      username,
			Status:        status,
			FindingsCount: findingsCount,
			Findings:      findings,
			ScannedAt:     scannedAt.Format(time.RFC3339),
			CreatedAt:     createdAt.Format(time.RFC3339),
		}
		if scanDuration != nil {
			report.ScanDuration = *scanDuration
		}

		reports = append(reports, report)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating rows: %w", err)
	}

	return reports, totalCount, nil
}

// ListReportsForExport returns all matching rows (no pagination) for CSV export
func (s *Store) ListReportsForExport(ctx context.Context, from, to, containerName, status string) ([]*pb.ClamavReport, error) {
	query := `SELECT id, container_name, username, status, findings_count, findings,
		scanned_at, scan_duration, created_at FROM clamav_reports WHERE scanned_at >= $1 AND scanned_at <= $2`

	args := []interface{}{from, to}
	argIdx := 3

	if containerName != "" {
		query += fmt.Sprintf(" AND container_name = $%d", argIdx)
		args = append(args, containerName)
		argIdx++
	}

	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
	}

	query += " ORDER BY scanned_at DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query reports for export: %w", err)
	}
	defer rows.Close()

	var reports []*pb.ClamavReport
	for rows.Next() {
		var (
			id            int64
			cname         string
			username      string
			st            string
			findingsCount int32
			findings      string
			scannedAt     time.Time
			scanDuration  *string
			createdAt     time.Time
		)

		if err := rows.Scan(&id, &cname, &username, &st, &findingsCount,
			&findings, &scannedAt, &scanDuration, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		report := &pb.ClamavReport{
			Id:            id,
			ContainerName: cname,
			Username:      username,
			Status:        st,
			FindingsCount: findingsCount,
			Findings:      findings,
			ScannedAt:     scannedAt.Format(time.RFC3339),
			CreatedAt:     createdAt.Format(time.RFC3339),
		}
		if scanDuration != nil {
			report.ScanDuration = *scanDuration
		}

		reports = append(reports, report)
	}

	return reports, rows.Err()
}

// GetContainerSummaries returns the latest scan status per container
func (s *Store) GetContainerSummaries(ctx context.Context) ([]*pb.ClamavContainerSummary, error) {
	query := `
		SELECT DISTINCT ON (container_name)
			container_name, username, scanned_at, status, findings_count,
			(SELECT COUNT(*) FROM clamav_reports r2 WHERE r2.container_name = r1.container_name) as total_scans,
			(SELECT COUNT(*) FROM clamav_reports r2 WHERE r2.container_name = r1.container_name AND r2.status = 'infected') as infected_scans
		FROM clamav_reports r1
		ORDER BY container_name, scanned_at DESC
	`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query summaries: %w", err)
	}
	defer rows.Close()

	var summaries []*pb.ClamavContainerSummary
	for rows.Next() {
		var (
			containerName string
			username      string
			scannedAt     time.Time
			status        string
			findingsCount int32
			totalScans    int32
			infectedScans int32
		)

		if err := rows.Scan(&containerName, &username, &scannedAt, &status,
			&findingsCount, &totalScans, &infectedScans); err != nil {
			return nil, fmt.Errorf("failed to scan summary row: %w", err)
		}

		summaries = append(summaries, &pb.ClamavContainerSummary{
			ContainerName:     containerName,
			Username:          username,
			LastScanAt:        scannedAt.Format(time.RFC3339),
			LastStatus:        status,
			LastFindingsCount: findingsCount,
			TotalScans:        totalScans,
			InfectedScans:     infectedScans,
		})
	}

	return summaries, rows.Err()
}

// Cleanup removes old reports beyond the retention period
func (s *Store) Cleanup(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	query := "DELETE FROM clamav_reports WHERE created_at < $1"
	_, err := s.pool.Exec(ctx, query, cutoff)
	return err
}

// ScanJob represents a queued ClamAV scan job
type ScanJob struct {
	ID            int64
	ContainerName string
	Username      string
	Status        string // pending | running | completed | failed
	RetryCount    int
	MaxRetries    int
	ErrorMessage  string
	CreatedAt     time.Time
	StartedAt     *time.Time
	CompletedAt   *time.Time
}

// EnqueueScanJob inserts a new pending scan job and returns its ID
func (s *Store) EnqueueScanJob(ctx context.Context, containerName, username string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO scan_jobs (container_name, username) VALUES ($1, $2) RETURNING id`,
		containerName, username,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("failed to enqueue scan job: %w", err)
	}
	return id, nil
}

// ClaimNextJob atomically claims the oldest pending job for processing.
// Returns nil if no jobs are available.
func (s *Store) ClaimNextJob(ctx context.Context) (*ScanJob, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE scan_jobs
		SET status = 'running', started_at = NOW()
		WHERE id = (
			SELECT id FROM scan_jobs
			WHERE status = 'pending'
			ORDER BY created_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, container_name, username, status, retry_count, max_retries,
			COALESCE(error_message, ''), created_at, started_at, completed_at
	`)

	job := &ScanJob{}
	err := row.Scan(
		&job.ID, &job.ContainerName, &job.Username, &job.Status,
		&job.RetryCount, &job.MaxRetries, &job.ErrorMessage,
		&job.CreatedAt, &job.StartedAt, &job.CompletedAt,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to claim scan job: %w", err)
	}
	return job, nil
}

// CompleteJob marks a job as completed
func (s *Store) CompleteJob(ctx context.Context, jobID int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scan_jobs SET status = 'completed', completed_at = NOW() WHERE id = $1`,
		jobID,
	)
	return err
}

// FailJob increments retry_count. If retries remain, re-queues as pending; otherwise marks as failed.
func (s *Store) FailJob(ctx context.Context, jobID int64, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_jobs
		SET retry_count = retry_count + 1,
			error_message = $2,
			status = CASE WHEN retry_count + 1 < max_retries THEN 'pending' ELSE 'failed' END,
			started_at = CASE WHEN retry_count + 1 < max_retries THEN NULL ELSE started_at END,
			completed_at = CASE WHEN retry_count + 1 >= max_retries THEN NOW() ELSE NULL END
		WHERE id = $1
	`, jobID, errMsg)
	return err
}

// ListScanJobs returns recent scan jobs, optionally filtered by status.
// Returns up to limit jobs ordered by created_at DESC.
func (s *Store) ListScanJobs(ctx context.Context, status string, limit int) ([]ScanJob, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `SELECT id, container_name, username, status, retry_count, max_retries,
		COALESCE(error_message, ''), created_at, started_at, completed_at
		FROM scan_jobs WHERE 1=1`
	var args []interface{}
	argIdx := 1

	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list scan jobs: %w", err)
	}
	defer rows.Close()

	var jobs []ScanJob
	for rows.Next() {
		var job ScanJob
		if err := rows.Scan(
			&job.ID, &job.ContainerName, &job.Username, &job.Status,
			&job.RetryCount, &job.MaxRetries, &job.ErrorMessage,
			&job.CreatedAt, &job.StartedAt, &job.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan job row: %w", err)
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// CleanupOldJobs deletes completed/failed jobs older than retentionDays
func (s *Store) CleanupOldJobs(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	_, err := s.pool.Exec(ctx,
		`DELETE FROM scan_jobs WHERE status IN ('completed', 'failed') AND created_at < $1`,
		cutoff,
	)
	return err
}

// ParseClamScanOutput parses clamscan output and returns status, findings count, and findings text
func ParseClamScanOutput(output string) (status string, findingsCount int, findings string) {
	lines := strings.Split(output, "\n")
	var foundLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "FOUND") {
			foundLines = append(foundLines, line)
		}
	}

	if len(foundLines) > 0 {
		return "infected", len(foundLines), strings.Join(foundLines, "\n")
	}
	return "clean", 0, ""
}
