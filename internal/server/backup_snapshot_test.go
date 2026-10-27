package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/backup"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serverSnapshots struct{ creates, restores, deletes int }

func (s *serverSnapshots) CreateVolumeSnapshot(_ context.Context, tenant, name string) (*backup.SnapshotReference, error) {
	s.creates++
	return &backup.SnapshotReference{Namespace: "tenant-" + tenant, Name: name, UID: "uid", Size: "1Gi", StorageClass: "csi"}, nil
}
func (s *serverSnapshots) RestoreVolumeSnapshot(context.Context, string, backup.SnapshotReference) error {
	s.restores++
	return nil
}
func (s *serverSnapshots) DeleteVolumeSnapshot(context.Context, string, backup.SnapshotReference) error {
	s.deletes++
	return nil
}

func TestSnapshotBackupRPC(t *testing.T) {
	ops := &serverSnapshots{}
	dir := t.TempDir()
	bs := &BackupServer{mgr: backup.NewManager(nil, nil, dir, backup.WithSnapshots(ops))}
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "example", []string{"user"}, []string{auth.ScopeBackupsRead, auth.ScopeBackupsWrite})
	create := func(user string) *pb.CreateBackupRequest {
		return &pb.CreateBackupRequest{Username: user, Scope: pb.BackupScope_BACKUP_SCOPE_BOX, Destination: pb.BackupDestination_BACKUP_DESTINATION_SNAPSHOT}
	}
	if _, err := bs.CreateBackup(ctx, create("other")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross tenant: %v", err)
	}
	for _, mutate := range []func(*pb.CreateBackupRequest){func(r *pb.CreateBackupRequest) { r.Scope = pb.BackupScope_BACKUP_SCOPE_DATABASE }, func(r *pb.CreateBackupRequest) { r.Connection = &pb.PgConnection{} }, func(r *pb.CreateBackupRequest) { r.KeyMode = pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED }, func(r *pb.CreateBackupRequest) { r.Hook = "/backup" }, func(r *pb.CreateBackupRequest) { r.AgeRecipient = "age1..." }} {
		req := create("example")
		mutate(req)
		if _, err := bs.CreateBackup(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid request: %v", err)
		}
	}
	if ops.creates != 0 {
		t.Fatal("invalid requests reached storage")
	}
	resp, err := bs.CreateBackup(ctx, create("example"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Record.Destination != pb.BackupDestination_BACKUP_DESTINATION_SNAPSHOT || resp.Record.Scope != pb.BackupScope_BACKUP_SCOPE_BOX || resp.Record.Encrypted {
		t.Fatalf("record %+v", resp.Record)
	}
	// Restart the index: snapshot references must survive daemon restarts.
	bs.mgr = backup.NewManager(nil, nil, dir, backup.WithSnapshots(ops))
	list, err := bs.ListBackups(ctx, &pb.ListBackupsRequest{})
	if err != nil || len(list.Records) != 1 {
		t.Fatalf("list %+v %v", list, err)
	}
	for _, req := range []*pb.RestoreBackupRequest{{Id: resp.Record.Id, Connection: &pb.PgConnection{}}, {Id: resp.Record.Id, TargetContainer: "other-container"}, {Id: resp.Record.Id, Clean: true}} {
		if _, err := bs.RestoreBackup(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid restore: %v", err)
		}
	}
	if ops.restores != 0 {
		t.Fatal("invalid restore reached storage")
	}
	if _, err = bs.RestoreBackup(ctx, &pb.RestoreBackupRequest{Id: resp.Record.Id}); err != nil {
		t.Fatal(err)
	}
	if ops.restores != 1 {
		t.Fatal("restore did not reach storage")
	}
	if _, err = bs.DeleteBackup(ctx, &pb.DeleteBackupRequest{Id: resp.Record.Id}); err != nil {
		t.Fatal(err)
	}
	if ops.deletes != 1 {
		t.Fatal("delete did not reach storage")
	}
}

func TestSnapshotUnsupportedBackend(t *testing.T) {
	bs := &BackupServer{mgr: backup.NewManager(nil, nil, t.TempDir())}
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "example", []string{"user"}, []string{auth.ScopeBackupsWrite})
	_, err := bs.CreateBackup(ctx, &pb.CreateBackupRequest{Username: "example", Scope: pb.BackupScope_BACKUP_SCOPE_BOX, Destination: pb.BackupDestination_BACKUP_DESTINATION_SNAPSHOT})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatal(err)
	}
}
