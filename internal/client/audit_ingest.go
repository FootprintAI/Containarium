package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2415 — typed client for AuditService.IngestSSHSessionRecords, on both
// transports. Request and response are the generated messages; the REST
// path speaks protojson, exactly what grpc-gateway expects and emits.

// IngestHTTPError is returned by the REST transport for a non-2xx
// response. It carries the status so the sentinel's shipper can tell a
// rejected batch (4xx: a contract bug, never retried) from an unavailable
// backend (5xx / transport error: retried).
type IngestHTTPError struct {
	StatusCode int
	Body       string
}

func (e *IngestHTTPError) Error() string {
	return fmt.Sprintf("ingest ssh session records: HTTP %d: %s", e.StatusCode, e.Body)
}

// IngestSSHSessionRecords appends a batch of sentinel SSH session records to
// the backend's audit chain over REST.
func (c *HTTPClient) IngestSSHSessionRecords(ctx context.Context, req *pb.IngestSSHSessionRecordsRequest) (*pb.IngestSSHSessionRecordsResponse, error) {
	body, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/audit/ssh-sessions/ingest", body)
	if err != nil {
		return nil, fmt.Errorf("ingest ssh session records: %w", err)
	}
	defer drainClose(resp)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ingest ssh session records: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &IngestHTTPError{StatusCode: resp.StatusCode, Body: string(b)}
	}
	var out pb.IngestSSHSessionRecordsResponse
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("ingest ssh session records: decode response: %w", err)
	}
	return &out, nil
}

// IngestSSHSessionRecords is the gRPC transport's counterpart.
func (c *GRPCClient) IngestSSHSessionRecords(ctx context.Context, req *pb.IngestSSHSessionRecordsRequest) (*pb.IngestSSHSessionRecordsResponse, error) {
	resp, err := c.auditClient.IngestSSHSessionRecords(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("ingest ssh session records: %w", err)
	}
	return resp, nil
}

// IsIngestRejected reports whether err means the backend refused the batch
// as invalid or unauthorized (HTTP 400/401/403 or gRPC InvalidArgument /
// Unauthenticated / PermissionDenied). Those are not retryable: resending
// the same batch fails the same way.
func IsIngestRejected(err error) bool {
	if err == nil {
		return false
	}
	var he *IngestHTTPError
	if errors.As(err, &he) {
		return he.StatusCode == http.StatusBadRequest ||
			he.StatusCode == http.StatusUnauthorized ||
			he.StatusCode == http.StatusForbidden
	}
	// status.FromError unwraps %w-wrapped statuses.
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.InvalidArgument, codes.Unauthenticated, codes.PermissionDenied:
			return true
		}
	}
	return false
}
