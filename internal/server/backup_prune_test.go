package server

import (
	"context"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// pruneTestCtx authenticates as the tenant the request names, with the
// scope PruneBackups requires — isolates the keep/username validation this
// file locks down from the auth layer, which authcoverage_test.go and
// friends already cover generically.
func pruneTestCtx(username string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), username, []string{"user"}, []string{auth.ScopeBackupsWrite})
}

// PruneBackups is not covered by a full-RPC test here (same posture as the
// rest of this file: no fixture builds a real ContainerServer + Postgres-
// backed backup.Manager for a unit test — that's the "stores against a
// real Postgres" CI lane's job). This locks down the one piece that is
// pure and easy to get wrong silently: a caller-supplied keep <= 0 must
// be rejected with InvalidArgument, not accepted and misread as "delete
// everything" or "keep everything" by whatever's on the other end of the
// RPC (#1839).
func TestPruneBackups_RejectsNonPositiveKeepBeforeUsernameCheck(t *testing.T) {
	s := &BackupServer{}
	for _, req := range []*pb.PruneBackupsRequest{
		{Username: "alice", Keep: 0},
		{Username: "alice", Keep: -1},
	} {
		_, err := s.PruneBackups(pruneTestCtx(req.Username), req)
		if err == nil {
			t.Fatalf("PruneBackups(keep=%d) = nil error, want a rejection", req.Keep)
		}
		if !strings.Contains(err.Error(), "keep must be at least 1") {
			t.Errorf("PruneBackups(keep=%d) error = %v, want it to name the keep requirement", req.Keep, err)
		}
	}
}

func TestPruneBackups_RequiresUsername(t *testing.T) {
	s := &BackupServer{}
	_, err := s.PruneBackups(pruneTestCtx("someone"), &pb.PruneBackupsRequest{Keep: 1})
	if err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("PruneBackups with no username = %v, want a username-required error", err)
	}
}
