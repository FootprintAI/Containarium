package server

import (
	"context"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *BackupServer) createSnapshotBackup(ctx context.Context, req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	if req.Connection != nil || req.Hook != "" || req.HookFormat != pb.HookFormat_HOOK_FORMAT_UNSPECIFIED || req.Label != "" || req.GcsBucket != "" || req.AgeRecipient != "" || req.KeyMode != pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "snapshot backups accept no database, hook, label, GCS or age key options; encryption is provided by CSI storage")
	}
	rec, err := s.mgr.CreateSnapshot(ctx, req.Username)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "snapshot backup failed: %v", err)
	}
	result := recordToProto(rec)
	return &pb.CreateBackupResponse{Message: "snapshot backup created: " + rec.ID, Record: result, Records: []*pb.BackupRecord{result}}, nil
}
