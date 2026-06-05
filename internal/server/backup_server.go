package server

import (
	"context"
	"log"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/backup"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// defaultBackupDir is where dumps (for LOCAL) and the JSON index (for all
// destinations) live on the daemon host. Overridable via the
// CONTAINARIUM_BACKUP_DIR env var. Kept off the container data disks so a
// backup never shares a failure domain with the database it describes.
const defaultBackupDir = "/var/lib/containarium/backups"

// BackupServer implements the gRPC BackupService. It is orchestration over
// the existing ContainerServer: CreateBackup runs pg_dump inside the
// tenant's container (via the container manager's Exec/ReadFile), then
// stores the dump off-host. Lives in package server to reuse the wired
// container manager.
type BackupServer struct {
	pb.UnimplementedBackupServiceServer
	containers *ContainerServer
	mgr        *backup.Manager
}

// NewBackupServer wires the backup service to the container manager. A GCS
// uploader is constructed best-effort: if `gcloud` is absent the daemon
// still serves LOCAL backups and rejects GCS requests with a clear error,
// rather than failing to start.
func NewBackupServer(containers *ContainerServer) *BackupServer {
	dir := os.Getenv("CONTAINARIUM_BACKUP_DIR")
	if dir == "" {
		dir = defaultBackupDir
	}

	var uploader backup.Uploader
	if u, err := backup.NewGcloudUploader(); err != nil {
		log.Printf("[backup] GCS uploader unavailable (%v); LOCAL backups only", err)
	} else {
		uploader = u
	}

	return &BackupServer{
		containers: containers,
		mgr:        backup.NewManager(containers.manager, uploader, dir),
	}
}

// CreateBackup dumps a tenant's database and stores it off-host.
func (s *BackupServer) CreateBackup(ctx context.Context, req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeBackupsWrite); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	dest, err := destFromProto(req.Destination)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	info, err := s.containers.manager.Get(req.Username)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "container for user %s not found: %v", req.Username, err)
	}

	rec, err := s.mgr.Create(backup.CreateOptions{
		Username:      req.Username,
		ContainerName: info.Name,
		Conn:          connFromProto(req.Connection),
		Destination:   dest,
		GCSBucket:     req.GcsBucket,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "backup failed: %v", err)
	}
	log.Printf("[backup] created id=%s user=%s db=%s dest=%s size=%d", rec.ID, rec.Username, rec.Database, rec.Destination, rec.SizeBytes)
	return &pb.CreateBackupResponse{
		Message: "backup created: " + rec.ID,
		Record:  recordToProto(rec),
	}, nil
}

// ListBackups returns stored records. Admins see all tenants; a non-admin
// is scoped to their own backups regardless of the requested filter.
func (s *BackupServer) ListBackups(ctx context.Context, req *pb.ListBackupsRequest) (*pb.ListBackupsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeBackupsRead); err != nil {
		return nil, err
	}
	username := req.Username
	if subject, roles, ok := auth.SubjectFromGRPCContext(ctx); ok && !auth.HasRole(roles, auth.RoleAdmin) {
		// Non-admins only ever see their own backups.
		username = subject
	}
	if username != "" {
		if err := auth.AuthorizeTenant(ctx, username); err != nil {
			return nil, err
		}
	}

	records, err := s.mgr.List(username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list backups: %v", err)
	}
	resp := &pb.ListBackupsResponse{Records: make([]*pb.BackupRecord, 0, len(records))}
	for _, r := range records {
		resp.Records = append(resp.Records, recordToProto(r))
	}
	return resp, nil
}

// GetBackup returns a single record by ID.
func (s *BackupServer) GetBackup(ctx context.Context, req *pb.GetBackupRequest) (*pb.GetBackupResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeBackupsRead); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	rec, err := s.mgr.Get(req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := auth.AuthorizeTenant(ctx, rec.Username); err != nil {
		return nil, err
	}
	return &pb.GetBackupResponse{Record: recordToProto(rec)}, nil
}

// RestoreBackup loads a stored dump back into the owning tenant's
// container database.
func (s *BackupServer) RestoreBackup(ctx context.Context, req *pb.RestoreBackupRequest) (*pb.RestoreBackupResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeBackupsWrite); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	rec, err := s.mgr.Get(req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := auth.AuthorizeTenant(ctx, rec.Username); err != nil {
		return nil, err
	}
	info, err := s.containers.manager.Get(rec.Username)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "container for user %s not found: %v", rec.Username, err)
	}

	if err := s.mgr.Restore(backup.RestoreOptions{
		ID:            req.Id,
		ContainerName: info.Name,
		Conn:          connFromProto(req.Connection),
		Clean:         req.Clean,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "restore failed: %v", err)
	}
	log.Printf("[backup] restored id=%s user=%s db=%s clean=%t", rec.ID, rec.Username, rec.Database, req.Clean)
	return &pb.RestoreBackupResponse{Message: "restore complete: " + rec.ID}, nil
}

// DeleteBackup removes a stored dump and its index entry.
func (s *BackupServer) DeleteBackup(ctx context.Context, req *pb.DeleteBackupRequest) (*pb.DeleteBackupResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeBackupsWrite); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	rec, err := s.mgr.Get(req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := auth.AuthorizeTenant(ctx, rec.Username); err != nil {
		return nil, err
	}
	if err := s.mgr.Delete(req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete backup: %v", err)
	}
	log.Printf("[backup] deleted id=%s user=%s", rec.ID, rec.Username)
	return &pb.DeleteBackupResponse{Message: "backup deleted: " + rec.ID}, nil
}

// --- proto <-> core mapping ---

func destFromProto(d pb.BackupDestination) (backup.Destination, error) {
	switch d {
	case pb.BackupDestination_BACKUP_DESTINATION_LOCAL:
		return backup.DestLocal, nil
	case pb.BackupDestination_BACKUP_DESTINATION_GCS:
		return backup.DestGCS, nil
	default:
		return "", status.Error(codes.InvalidArgument, "destination is required (local or gcs)")
	}
}

func destToProto(d backup.Destination) pb.BackupDestination {
	switch d {
	case backup.DestLocal:
		return pb.BackupDestination_BACKUP_DESTINATION_LOCAL
	case backup.DestGCS:
		return pb.BackupDestination_BACKUP_DESTINATION_GCS
	default:
		return pb.BackupDestination_BACKUP_DESTINATION_UNSPECIFIED
	}
}

func connFromProto(c *pb.PgConnection) backup.PgConn {
	if c == nil {
		return backup.PgConn{}
	}
	return backup.PgConn{
		Database: c.Database,
		User:     c.User,
		Password: c.Password,
		Host:     c.Host,
		Port:     int(c.Port),
	}
}

func recordToProto(r *backup.Record) *pb.BackupRecord {
	return &pb.BackupRecord{
		Id:          r.ID,
		Username:    r.Username,
		Database:    r.Database,
		CreatedAt:   r.CreatedAt.UTC().Format(time.RFC3339),
		SizeBytes:   r.SizeBytes,
		Sha256:      r.SHA256,
		Destination: destToProto(r.Destination),
		Location:    r.Location,
		Engine:      r.Engine,
	}
}
