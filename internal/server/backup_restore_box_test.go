package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RestoreBoxBackup is a contract-only stub until #3357: it applies the same
// scope and tenant gates as RestoreBackup, then reports Unimplemented, so a
// client can reach it over both transports without anything being restored.
func TestRestoreBoxBackup_StubGatesThenUnimplemented(t *testing.T) {
	writer := auth.ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"},
		[]string{auth.ScopeBackupsWrite})
	for _, tc := range []struct {
		name string
		req  *pb.RestoreBoxBackupRequest
		want codes.Code
	}{
		{"missing id", &pb.RestoreBoxBackupRequest{}, codes.InvalidArgument},
		{"unknown backup", &pb.RestoreBoxBackupRequest{Id: "alice-app-20991231T000000Z"}, codes.NotFound},
		{"another tenant's backup", &pb.RestoreBoxBackupRequest{Id: bobBackupID}, codes.PermissionDenied},
		{"own backup", &pb.RestoreBoxBackupRequest{Id: "alice-app-20261003T010000Z", TargetBox: "alice-copy", Force: true}, codes.Unimplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, bs := verifierServer(t)
			_, err := bs.RestoreBoxBackup(writer, tc.req)
			if got := status.Code(err); got != tc.want {
				t.Fatalf("RestoreBoxBackup code = %v (%v), want %v", got, err, tc.want)
			}
		})
	}
}
