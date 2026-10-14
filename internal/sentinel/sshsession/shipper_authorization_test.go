package sshsession

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/proto"
)

type authorizationCaptureClient struct{ records []*pb.SSHSessionRecord }

func (c *authorizationCaptureClient) IngestSSHSessionRecords(_ context.Context, req *pb.IngestSSHSessionRecordsRequest) (*pb.IngestSSHSessionRecordsResponse, error) {
	resp := &pb.IngestSSHSessionRecordsResponse{}
	for _, record := range req.Records {
		c.records = append(c.records, proto.Clone(record).(*pb.SSHSessionRecord))
		resp.Outcomes = append(resp.Outcomes, pb.IngestOutcome_INGEST_OUTCOME_INSERTED)
		resp.Inserted++
	}
	return resp, nil
}

type authorizationTestTokens struct{}

func (authorizationTestTokens) TokenFor(string) (string, bool, error) { return "test-token", true, nil }
func (authorizationTestTokens) Backends() ([]string, error)           { return []string{"test-backend"}, nil }

func TestShipOnce_AuthorizationAndLegacyJSONL(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  *pb.SSHSessionRecord
	}{
		{"legacy", `{"session_id":"legacy","phase":"open","occurred_at":"2026-10-13T00:00:00Z","login":"test-login"}`, &pb.SSHSessionRecord{
			SessionId: "legacy", Phase: pb.SSHSessionPhase_SSH_SESSION_PHASE_OPEN,
		}},
		{"audit-only open", `{"session_id":"audit","phase":"open","occurred_at":"2026-10-13T00:00:00Z","login":"test-login","user_id":"user-test","authz_decision":2,"deny_reason":1,"enforced":false}`, &pb.SSHSessionRecord{
			SessionId: "audit", Phase: pb.SSHSessionPhase_SSH_SESSION_PHASE_OPEN, UserId: "user-test",
			AuthzDecision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY,
		}},
		{"enforced denied", `{"session_id":"denied","phase":"denied","occurred_at":"2026-10-13T00:00:00Z","login":"test-login","user_id":"user-test","authz_decision":2,"deny_reason":2,"enforced":true}`, &pb.SSHSessionRecord{
			SessionId: "denied", Phase: pb.SSHSessionPhase_SSH_SESSION_PHASE_DENIED, UserId: "user-test", Enforced: true,
			AuthzDecision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_USER_INACTIVE,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "sessions.jsonl")
			if err := os.WriteFile(path, []byte(tc.input+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			capture := &authorizationCaptureClient{}
			cfg := ShipConfig{RecordsFile: path, CheckpointFile: filepath.Join(dir, "checkpoint.json"),
				DefaultBackend: "test-backend", Tokens: authorizationTestTokens{},
				NewClient: func(string, string) (IngestClient, error) { return capture, nil },
			}
			stats, err := ShipOnce(context.Background(), cfg)
			if err != nil || stats.Shipped != 1 || stats.SkippedMalformed != 0 || len(capture.records) != 1 {
				t.Fatalf("stats=%+v captured=%d err=%v", stats, len(capture.records), err)
			}
			var input Record
			if err := json.Unmarshal([]byte(tc.input), &input); err != nil {
				t.Fatal(err)
			}
			tc.want.OccurredAt = ToProto(input).OccurredAt
			tc.want.Login = "test-login"
			if !proto.Equal(capture.records[0], tc.want) {
				t.Fatalf("shipped record changed: got %v want %v", capture.records[0], tc.want)
			}
			stats, err = ShipOnce(context.Background(), cfg)
			if err != nil || stats.Shipped != 0 || len(capture.records) != 1 {
				t.Fatalf("checkpoint replay: stats=%+v captured=%d err=%v", stats, len(capture.records), err)
			}
		})
	}
}
