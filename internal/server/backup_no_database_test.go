package server

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3600: a database backup with no database and no hook named discovers the
// container's databases. When there is nothing to back up because of the
// container (no Postgres answered, or no database), the caller gets
// FAILED_PRECONDITION with what to do, not a generic INTERNAL; a genuine
// fault stays INTERNAL.

// listingOps answers the database listing with stdout, stderr and err, the
// way the container exec does.
type listingOps struct {
	restoreTargetOps
	stdout, stderr string
	err            error
}

func (o *listingOps) ExecWithOutput(string, []string) (string, string, error) {
	return o.stdout, o.stderr, o.err
}

func newListingServer(t *testing.T, ops *listingOps) *BackupServer {
	t.Helper()
	backend := newFakeSandboxBackend()
	if err := backend.CreateContainer(incus.ContainerConfig{Name: "alice-container"}); err != nil {
		t.Fatal(err)
	}
	ops.touched = map[string]int{}
	return &BackupServer{
		containers: &ContainerServer{manager: container.NewWithBackend(backend)},
		mgr:        backup.NewManager(ops, nil, t.TempDir()),
	}
}

func TestCreateBackup_NothingToBackUpIsAPrecondition(t *testing.T) {
	exitErr := errors.New("command exited with code 2")
	for _, tc := range []struct {
		name     string
		ops      *listingOps
		wantCode codes.Code
		wantMsg  string
		// notInMsg is the cause's detail, which stays in the daemon log.
		notInMsg string
	}{
		{
			name:     "no Postgres answered",
			ops:      &listingOps{stderr: "psql: error: connection to server failed: Connection refused\nCBK_PSQL_EXIT=2\n", err: exitErr},
			wantCode: codes.FailedPrecondition,
			wantMsg:  "no Postgres answered",
			notInMsg: "Connection refused",
		},
		{
			name:     "no psql in the container",
			ops:      &listingOps{stderr: "bash: line 1: psql: command not found\nCBK_PSQL_EXIT=127\n", err: errors.New("command exited with code 127")},
			wantCode: codes.FailedPrecondition,
			wantMsg:  "no Postgres answered",
			notInMsg: "command not found",
		},
		{
			name:     "Postgres has no database",
			ops:      &listingOps{},
			wantCode: codes.FailedPrecondition,
			wantMsg:  "no database to back up",
		},
		{
			name:     "the exec itself failed",
			ops:      &listingOps{err: errors.New("failed to execute command: instance is not running")},
			wantCode: codes.Internal,
			wantMsg:  "backup failed",
		},
		{
			name:     "psql failed for another reason",
			ops:      &listingOps{stderr: "psql: error: out of memory\nCBK_PSQL_EXIT=1\n", err: errors.New("command exited with code 1")},
			wantCode: codes.Internal,
			wantMsg:  "backup failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newListingServer(t, tc.ops)
			_, err := s.CreateBackup(restoreCtx("ops", true), &pb.CreateBackupRequest{Username: "alice", Destination: pb.BackupDestination_BACKUP_DESTINATION_LOCAL})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("err = %v, want code %v", err, tc.wantCode)
			}
			msg := status.Convert(err).Message()
			if !strings.Contains(msg, tc.wantMsg) {
				t.Errorf("message %q, want it to say %q", msg, tc.wantMsg)
			}
			if tc.wantCode == codes.FailedPrecondition && (!strings.Contains(msg, `"alice"`) || !strings.Contains(msg, "hook")) {
				t.Errorf("message %q, want it to name the box and what to do", msg)
			}
			if tc.notInMsg != "" && strings.Contains(msg, tc.notInMsg) {
				t.Errorf("message %q carries the cause's detail %q", msg, tc.notInMsg)
			}
		})
	}
}

func TestBackupAllRefusal(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want codes.Code
	}{
		{fmt.Errorf("list databases: %w", backup.ErrDatabaseUnavailable), codes.FailedPrecondition},
		{backup.ErrNoDatabaseFound, codes.FailedPrecondition},
		{errors.New("database \"app\": pg_dump failed"), codes.OK},
	} {
		got := backupAllRefusal("alice", tc.err)
		if tc.want == codes.OK {
			if got != nil {
				t.Errorf("backupAllRefusal(%v) = %v, want nil (stays Internal)", tc.err, got)
			}
			continue
		}
		if status.Code(got) != tc.want {
			t.Errorf("backupAllRefusal(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
