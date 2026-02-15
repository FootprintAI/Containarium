package traffic

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Store handles persistent storage of traffic data using PostgreSQL
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new traffic store connected to PostgreSQL
// connectionString format: postgres://user:password@host:port/database?sslmode=disable
func NewStore(ctx context.Context, connectionString string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test the connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &Store{pool: pool}

	// Initialize schema
	if err := store.initSchema(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return store, nil
}

// Close closes the database connection pool
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// initSchema creates the database schema if it doesn't exist
func (s *Store) initSchema(ctx context.Context) error {
	schema := `
		-- Connection history table for long-term storage
		CREATE TABLE IF NOT EXISTS traffic_connections (
			id BIGSERIAL PRIMARY KEY,
			container_name TEXT NOT NULL,
			protocol SMALLINT NOT NULL,
			source_ip INET NOT NULL,
			source_port INTEGER,
			dest_ip INET NOT NULL,
			dest_port INTEGER,
			direction SMALLINT NOT NULL,
			bytes_sent BIGINT NOT NULL DEFAULT 0,
			bytes_received BIGINT NOT NULL DEFAULT 0,
			packets_sent BIGINT NOT NULL DEFAULT 0,
			packets_received BIGINT NOT NULL DEFAULT 0,
			started_at TIMESTAMP WITH TIME ZONE NOT NULL,
			ended_at TIMESTAMP WITH TIME ZONE,
			duration_seconds INTEGER,
			conntrack_id TEXT,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		-- Indexes for common query patterns
		CREATE INDEX IF NOT EXISTS idx_traffic_container_time
			ON traffic_connections(container_name, started_at DESC);
		CREATE INDEX IF NOT EXISTS idx_traffic_dest_ip
			ON traffic_connections(dest_ip);
		CREATE INDEX IF NOT EXISTS idx_traffic_dest_port
			ON traffic_connections(dest_port);
		CREATE INDEX IF NOT EXISTS idx_traffic_started_at
			ON traffic_connections(started_at DESC);
		CREATE INDEX IF NOT EXISTS idx_traffic_conntrack_id
			ON traffic_connections(conntrack_id);

		-- Aggregated traffic stats table (for faster time-series queries)
		CREATE TABLE IF NOT EXISTS traffic_aggregates (
			id BIGSERIAL PRIMARY KEY,
			container_name TEXT NOT NULL,
			dest_ip INET,
			dest_port INTEGER,
			interval_start TIMESTAMP WITH TIME ZONE NOT NULL,
			interval_end TIMESTAMP WITH TIME ZONE NOT NULL,
			bytes_sent BIGINT NOT NULL DEFAULT 0,
			bytes_received BIGINT NOT NULL DEFAULT 0,
			connection_count INTEGER NOT NULL DEFAULT 0,
			UNIQUE(container_name, dest_ip, dest_port, interval_start)
		);

		CREATE INDEX IF NOT EXISTS idx_traffic_agg_container_time
			ON traffic_aggregates(container_name, interval_start DESC);
	`

	_, err := s.pool.Exec(ctx, schema)
	return err
}

// SaveConnection saves a completed connection to the database
func (s *Store) SaveConnection(ctx context.Context, conn *pb.Connection) error {
	query := `
		INSERT INTO traffic_connections (
			container_name, protocol, source_ip, source_port, dest_ip, dest_port,
			direction, bytes_sent, bytes_received, packets_sent, packets_received,
			started_at, ended_at, duration_seconds, conntrack_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT DO NOTHING
	`

	startedAt := conn.FirstSeen.AsTime()
	var endedAt *time.Time
	var durationSeconds *int64
	if conn.LastSeen != nil {
		t := conn.LastSeen.AsTime()
		endedAt = &t
		d := int64(t.Sub(startedAt).Seconds())
		durationSeconds = &d
	}

	_, err := s.pool.Exec(ctx, query,
		conn.ContainerName,
		int16(conn.Protocol),
		conn.SourceIp,
		conn.SourcePort,
		conn.DestIp,
		conn.DestPort,
		int16(conn.Direction),
		conn.BytesSent,
		conn.BytesReceived,
		conn.PacketsSent,
		conn.PacketsReceived,
		startedAt,
		endedAt,
		durationSeconds,
		conn.Id,
	)

	if err != nil {
		return fmt.Errorf("failed to save connection: %w", err)
	}

	return nil
}

// QueryParams holds parameters for querying traffic history
type QueryParams struct {
	ContainerName string
	StartTime     time.Time
	EndTime       time.Time
	DestIP        string
	DestPort      int
	Offset        int
	Limit         int
}

// QueryConnections retrieves historical connections matching the criteria
func (s *Store) QueryConnections(ctx context.Context, params QueryParams) ([]*pb.HistoricalConnection, int32, error) {
	// Build query dynamically based on filters
	baseQuery := `
		SELECT id, container_name, protocol, source_ip, source_port, dest_ip, dest_port,
		       direction, bytes_sent, bytes_received, started_at, ended_at, duration_seconds
		FROM traffic_connections
		WHERE container_name = $1 AND started_at >= $2 AND started_at <= $3
	`
	countQuery := `
		SELECT COUNT(*) FROM traffic_connections
		WHERE container_name = $1 AND started_at >= $2 AND started_at <= $3
	`

	args := []interface{}{params.ContainerName, params.StartTime, params.EndTime}
	argIndex := 4

	if params.DestIP != "" {
		baseQuery += fmt.Sprintf(" AND dest_ip = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND dest_ip = $%d", argIndex)
		args = append(args, params.DestIP)
		argIndex++
	}

	if params.DestPort > 0 {
		baseQuery += fmt.Sprintf(" AND dest_port = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND dest_port = $%d", argIndex)
		args = append(args, params.DestPort)
		argIndex++
	}

	// Get total count
	var totalCount int32
	err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count connections: %w", err)
	}

	// Apply pagination
	limit := params.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	baseQuery += fmt.Sprintf(" ORDER BY started_at DESC LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, limit, params.Offset)

	rows, err := s.pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query connections: %w", err)
	}
	defer rows.Close()

	var connections []*pb.HistoricalConnection
	for rows.Next() {
		var (
			id              int64
			containerName   string
			protocol        int16
			sourceIP        string
			sourcePort      *int32
			destIP          string
			destPort        *int32
			direction       int16
			bytesSent       int64
			bytesReceived   int64
			startedAt       time.Time
			endedAt         *time.Time
			durationSeconds *int64
		)

		err := rows.Scan(
			&id, &containerName, &protocol, &sourceIP, &sourcePort,
			&destIP, &destPort, &direction, &bytesSent, &bytesReceived,
			&startedAt, &endedAt, &durationSeconds,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan row: %w", err)
		}

		conn := &pb.HistoricalConnection{
			Id:            id,
			ContainerName: containerName,
			Protocol:      pb.Protocol(protocol),
			SourceIp:      sourceIP,
			DestIp:        destIP,
			Direction:     pb.TrafficDirection(direction),
			BytesSent:     bytesSent,
			BytesReceived: bytesReceived,
			StartedAt:     timestamppb.New(startedAt),
		}

		if sourcePort != nil {
			conn.SourcePort = uint32(*sourcePort)
		}
		if destPort != nil {
			conn.DestPort = uint32(*destPort)
		}
		if endedAt != nil {
			conn.EndedAt = timestamppb.New(*endedAt)
		}
		if durationSeconds != nil {
			conn.DurationSeconds = *durationSeconds
		}

		connections = append(connections, conn)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating rows: %w", err)
	}

	return connections, totalCount, nil
}

// AggregateParams holds parameters for querying traffic aggregates
type AggregateParams struct {
	ContainerName   string
	StartTime       time.Time
	EndTime         time.Time
	Interval        string
	GroupByDestIP   bool
	GroupByDestPort bool
}

// GetAggregates retrieves time-series traffic aggregates
func (s *Store) GetAggregates(ctx context.Context, params AggregateParams) ([]*pb.TrafficAggregate, error) {
	// Parse interval
	intervalDuration, err := parseInterval(params.Interval)
	if err != nil {
		return nil, fmt.Errorf("invalid interval: %w", err)
	}

	// Build the aggregation query
	selectCols := "date_trunc('hour', started_at) as bucket"
	groupCols := "date_trunc('hour', started_at)"

	if params.GroupByDestIP {
		selectCols += ", dest_ip"
		groupCols += ", dest_ip"
	}
	if params.GroupByDestPort {
		selectCols += ", dest_port"
		groupCols += ", dest_port"
	}

	query := fmt.Sprintf(`
		SELECT %s,
		       COALESCE(SUM(bytes_sent), 0) as bytes_sent,
		       COALESCE(SUM(bytes_received), 0) as bytes_received,
		       COUNT(*) as connection_count
		FROM traffic_connections
		WHERE container_name = $1 AND started_at >= $2 AND started_at <= $3
		GROUP BY %s
		ORDER BY bucket DESC
	`, selectCols, groupCols)

	rows, err := s.pool.Query(ctx, query, params.ContainerName, params.StartTime, params.EndTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query aggregates: %w", err)
	}
	defer rows.Close()

	var aggregates []*pb.TrafficAggregate
	for rows.Next() {
		agg := &pb.TrafficAggregate{}

		var bucket time.Time
		var destIP *string
		var destPort *int32
		var bytesSent, bytesReceived int64
		var connCount int32

		// Scan based on grouping
		if params.GroupByDestIP && params.GroupByDestPort {
			err = rows.Scan(&bucket, &destIP, &destPort, &bytesSent, &bytesReceived, &connCount)
		} else if params.GroupByDestIP {
			err = rows.Scan(&bucket, &destIP, &bytesSent, &bytesReceived, &connCount)
		} else if params.GroupByDestPort {
			err = rows.Scan(&bucket, &destPort, &bytesSent, &bytesReceived, &connCount)
		} else {
			err = rows.Scan(&bucket, &bytesSent, &bytesReceived, &connCount)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to scan aggregate row: %w", err)
		}

		agg.Timestamp = timestamppb.New(bucket)
		agg.BytesSent = bytesSent
		agg.BytesReceived = bytesReceived
		agg.ConnectionCount = connCount

		if destIP != nil {
			agg.DestIp = *destIP
		}
		if destPort != nil {
			agg.DestPort = uint32(*destPort)
		}

		aggregates = append(aggregates, agg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating aggregate rows: %w", err)
	}

	// Re-aggregate to the requested interval if needed
	if intervalDuration > time.Hour {
		aggregates = reAggregate(aggregates, intervalDuration)
	}

	return aggregates, nil
}

// Cleanup removes old traffic data beyond the retention period
func (s *Store) Cleanup(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	query := "DELETE FROM traffic_connections WHERE created_at < $1"
	result, err := s.pool.Exec(ctx, query, cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup old connections: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected > 0 {
		// Log cleanup
		fmt.Printf("Cleaned up %d old traffic records\n", rowsAffected)
	}

	return nil
}

// parseInterval parses interval strings like "1m", "5m", "1h", "1d"
func parseInterval(interval string) (time.Duration, error) {
	if interval == "" {
		return time.Hour, nil // default to 1 hour
	}

	switch interval {
	case "1m":
		return time.Minute, nil
	case "5m":
		return 5 * time.Minute, nil
	case "15m":
		return 15 * time.Minute, nil
	case "30m":
		return 30 * time.Minute, nil
	case "1h":
		return time.Hour, nil
	case "6h":
		return 6 * time.Hour, nil
	case "12h":
		return 12 * time.Hour, nil
	case "1d":
		return 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unsupported interval: %s", interval)
	}
}

// reAggregate re-aggregates hourly data to a larger interval
func reAggregate(aggregates []*pb.TrafficAggregate, interval time.Duration) []*pb.TrafficAggregate {
	if len(aggregates) == 0 {
		return aggregates
	}

	// Group by truncated timestamp
	buckets := make(map[int64]*pb.TrafficAggregate)

	for _, agg := range aggregates {
		ts := agg.Timestamp.AsTime()
		bucketTime := ts.Truncate(interval)
		bucketKey := bucketTime.Unix()

		if existing, ok := buckets[bucketKey]; ok {
			existing.BytesSent += agg.BytesSent
			existing.BytesReceived += agg.BytesReceived
			existing.ConnectionCount += agg.ConnectionCount
		} else {
			buckets[bucketKey] = &pb.TrafficAggregate{
				Timestamp:       timestamppb.New(bucketTime),
				DestIp:          agg.DestIp,
				DestPort:        agg.DestPort,
				BytesSent:       agg.BytesSent,
				BytesReceived:   agg.BytesReceived,
				ConnectionCount: agg.ConnectionCount,
			}
		}
	}

	// Convert back to slice
	result := make([]*pb.TrafficAggregate, 0, len(buckets))
	for _, agg := range buckets {
		result = append(result, agg)
	}

	return result
}

// SaveAggregate saves a pre-computed aggregate (for periodic aggregation jobs)
func (s *Store) SaveAggregate(ctx context.Context, agg *pb.TrafficAggregate, containerName string, intervalEnd time.Time) error {
	query := `
		INSERT INTO traffic_aggregates (
			container_name, dest_ip, dest_port, interval_start, interval_end,
			bytes_sent, bytes_received, connection_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (container_name, dest_ip, dest_port, interval_start) DO UPDATE SET
			bytes_sent = traffic_aggregates.bytes_sent + EXCLUDED.bytes_sent,
			bytes_received = traffic_aggregates.bytes_received + EXCLUDED.bytes_received,
			connection_count = traffic_aggregates.connection_count + EXCLUDED.connection_count
	`

	var destIP *string
	var destPort *int32
	if agg.DestIp != "" {
		destIP = &agg.DestIp
	}
	if agg.DestPort > 0 {
		port := int32(agg.DestPort)
		destPort = &port
	}

	_, err := s.pool.Exec(ctx, query,
		containerName,
		destIP,
		destPort,
		agg.Timestamp.AsTime(),
		intervalEnd,
		agg.BytesSent,
		agg.BytesReceived,
		agg.ConnectionCount,
	)

	if err != nil {
		return fmt.Errorf("failed to save aggregate: %w", err)
	}

	return nil
}

// GetConnectionByConntrackID checks if a connection with the given conntrack ID exists
func (s *Store) GetConnectionByConntrackID(ctx context.Context, conntrackID string) (bool, error) {
	query := "SELECT 1 FROM traffic_connections WHERE conntrack_id = $1 LIMIT 1"
	var exists int
	err := s.pool.QueryRow(ctx, query, conntrackID).Scan(&exists)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
