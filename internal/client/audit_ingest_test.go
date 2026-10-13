package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2415 — typed client for AuditService.IngestSSHSessionRecords.

func ingestReq() *pb.IngestSSHSessionRecordsRequest {
	return &pb.IngestSSHSessionRecordsRequest{
		SentinelId: "s1",
		Records: []*pb.SSHSessionRecord{{
			SessionId: "sess-1",
			Phase:     pb.SSHSessionPhase_SSH_SESSION_PHASE_OPEN,
			Login:     "alice",
		}},
	}
}

func TestHTTPClient_IngestSSHSessionRecords(t *testing.T) {
	var gotPath, gotAuth, gotMethod string
	var gotReq pb.IngestSSHSessionRecordsRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotMethod = r.URL.Path, r.Header.Get("Authorization"), r.Method
		b, _ := io.ReadAll(r.Body)
		if err := protojson.Unmarshal(b, &gotReq); err != nil {
			t.Errorf("body is not protojson of the request: %v (%s)", err, b)
		}
		out, _ := protojson.Marshal(&pb.IngestSSHSessionRecordsResponse{
			Outcomes:   []pb.IngestOutcome{pb.IngestOutcome_INGEST_OUTCOME_DUPLICATE},
			Duplicates: 1,
		})
		_, _ = w.Write(out)
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok-123")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.IngestSSHSessionRecords(context.Background(), ingestReq())
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/audit/ssh-sessions/ingest" || gotAuth != "Bearer tok-123" {
		t.Fatalf("request = %s %s auth=%q", gotMethod, gotPath, gotAuth)
	}
	if gotReq.SentinelId != "s1" || len(gotReq.Records) != 1 || gotReq.Records[0].SessionId != "sess-1" ||
		gotReq.Records[0].Phase != pb.SSHSessionPhase_SSH_SESSION_PHASE_OPEN {
		t.Fatalf("server decoded %+v", &gotReq)
	}
	if resp.Duplicates != 1 || len(resp.Outcomes) != 1 || resp.Outcomes[0] != pb.IngestOutcome_INGEST_OUTCOME_DUPLICATE {
		t.Fatalf("response = %+v", resp)
	}
}

func TestHTTPClient_IngestSSHSessionRecords_ErrorStatusIsAnError(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusServiceUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"code":3,"message":"records[1]: invalid phase"}`))
		}))
		c, _ := NewHTTPClient(srv.URL, "t")
		_, err := c.IngestSSHSessionRecords(context.Background(), ingestReq())
		srv.Close()
		if err == nil {
			t.Fatalf("status %d must surface as an error", code)
		}
		var he *IngestHTTPError
		if !errors.As(err, &he) || he.StatusCode != code {
			t.Fatalf("status %d: error %v must carry the status code", code, err)
		}
	}
}

func TestIsIngestRejected(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("ctx: %w", err) }
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"http 400", &IngestHTTPError{StatusCode: 400}, true},
		{"http 401 wrapped", wrap(&IngestHTTPError{StatusCode: 401}), true},
		{"http 403", &IngestHTTPError{StatusCode: 403}, true},
		{"http 503", &IngestHTTPError{StatusCode: 503}, false},
		{"http 500", &IngestHTTPError{StatusCode: 500}, false},
		{"grpc invalid argument", wrap(status.Error(codes.InvalidArgument, "x")), true},
		{"grpc permission denied", status.Error(codes.PermissionDenied, "x"), true},
		{"grpc unavailable", status.Error(codes.Unavailable, "x"), false},
		{"transport error", errors.New("connection refused"), false},
	}
	for _, tc := range tests {
		if got := IsIngestRejected(tc.err); got != tc.want {
			t.Errorf("%s: IsIngestRejected = %v, want %v", tc.name, got, tc.want)
		}
	}
}
