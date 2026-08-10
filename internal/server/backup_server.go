package server

import (
	"context"
	"fmt"
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

	opts := backup.CreateOptions{
		Username:      req.Username,
		ContainerName: info.Name,
		Conn:          connFromProto(req.Connection),
		Destination:   dest,
		GCSBucket:     req.GcsBucket,
	}

	// Empty database → back up every non-template database found (#954),
	// the default, no-guessing path. An explicit database keeps today's
	// single-database behavior and response shape exactly as before.
	if opts.Conn.Database == "" {
		records, errs := s.mgr.CreateAll(opts)
		if len(records) == 0 {
			msg := "no databases were backed up"
			if len(errs) > 0 {
				msg = errs[0].Error()
			}
			return nil, status.Errorf(codes.Internal, "backup failed: %s", msg)
		}
		resp := &pb.CreateBackupResponse{
			Records: make([]*pb.BackupRecord, 0, len(records)),
		}
		for _, r := range records {
			resp.Records = append(resp.Records, recordToProto(r))
			log.Printf("[backup] created id=%s user=%s db=%s dest=%s size=%d", r.ID, r.Username, r.Database, r.Destination, r.SizeBytes)
		}
		for _, e := range errs {
			resp.Failures = append(resp.Failures, e.Error())
			log.Printf("[backup] partial failure user=%s: %v", req.Username, e)
		}
		resp.Message = fmt.Sprintf("backed up %d database(s)", len(records))
		if len(errs) > 0 {
			resp.Message += fmt.Sprintf(", %d failed", len(errs))
		}
		return resp, nil
	}

	rec, err := s.mgr.Create(opts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "backup failed: %v", err)
	}
	log.Printf("[backup] created id=%s user=%s db=%s dest=%s size=%d", rec.ID, rec.Username, rec.Database, rec.Destination, rec.SizeBytes)
	return &pb.CreateBackupResponse{
		Message: "backup created: " + rec.ID,
		Record:  recordToProto(rec),
		Records: []*pb.BackupRecord{recordToProto(rec)},
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

// VerifyBackup restore-tests a stored dump against a throwaway database
// inside a *target* tenant's container, never the source container.
//
// A dump that fails to restore is a successful RPC reporting a failed
// verification — the failure is the answer, not an error. Only a test
// that could not be run at all (unknown backup, missing target
// container) returns a gRPC error.
func (s *BackupServer) VerifyBackup(ctx context.Context, req *pb.VerifyBackupRequest) (*pb.VerifyBackupResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeBackupsWrite); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if req.TargetUsername == "" {
		return nil, status.Error(codes.InvalidArgument, "target_username is required: a restore test needs a throwaway container to load into")
	}

	rec, err := s.mgr.Get(req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := auth.AuthorizeTenant(ctx, rec.Username); err != nil {
		return nil, err
	}
	// The caller must also own the container being written to — the
	// restore test creates and drops a database inside it.
	if err := auth.AuthorizeTenant(ctx, req.TargetUsername); err != nil {
		return nil, err
	}

	target, err := s.containers.manager.Get(req.TargetUsername)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "target container for user %s not found: %v", req.TargetUsername, err)
	}

	// Resolve the source container so the core can refuse to restore
	// over it. A source container that no longer exists is not a
	// blocker — verifying a backup after its container is gone is a
	// legitimate (and important) case — so an unresolvable source just
	// leaves nothing to collide with.
	sourceName := ""
	if src, err := s.containers.manager.Get(rec.Username); err == nil {
		sourceName = src.Name
	}

	subject, _, _ := auth.SubjectFromGRPCContext(ctx)
	v, err := s.mgr.Verify(backup.VerifyOptions{
		ID:              req.Id,
		TargetContainer: target.Name,
		SourceContainer: sourceName,
		Conn:            connFromProto(req.Connection),
		VerifiedBy:      subject,
	})
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "verification could not run: %v", err)
	}

	updated, err := s.mgr.Get(req.Id)
	if err != nil {
		updated = rec
	}
	log.Printf("[backup] verified id=%s user=%s db=%s target=%s result=%s duration_ms=%d",
		rec.ID, rec.Username, rec.Database, v.TargetContainer, v.Result, v.DurationMS)

	msg := "verification passed: " + rec.ID
	if v.Result != backup.VerificationPassed {
		msg = "verification FAILED: " + rec.ID + ": " + v.Error
	}
	return &pb.VerifyBackupResponse{
		Message:      msg,
		Verification: verificationToProto(v),
		Record:       recordToProto(updated),
	}, nil
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

// engineToProto maps a stored record's engine to the wire enum.
//
// The manifest keeps engine as a string, so records written before the enum
// existed — and any record whose engine this daemon does not recognise — map
// to UNSPECIFIED rather than to Postgres. Defaulting an unknown engine to
// Postgres would present a dump as restorable by pg_restore on the strength
// of a guess, which is the failure the enum exists to make impossible.
func engineToProto(engine string) pb.BackupEngine {
	switch engine {
	case backup.EnginePostgres:
		return pb.BackupEngine_BACKUP_ENGINE_POSTGRES
	default:
		return pb.BackupEngine_BACKUP_ENGINE_UNSPECIFIED
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

func verificationResultToProto(r backup.VerificationResult) pb.VerificationResult {
	switch r {
	case backup.VerificationPassed:
		return pb.VerificationResult_VERIFICATION_RESULT_PASSED
	case backup.VerificationFailed:
		return pb.VerificationResult_VERIFICATION_RESULT_FAILED
	default:
		return pb.VerificationResult_VERIFICATION_RESULT_UNSPECIFIED
	}
}

func verificationToProto(v *backup.Verification) *pb.BackupVerification {
	if v == nil {
		return nil
	}
	out := &pb.BackupVerification{
		VerifiedAt:      v.VerifiedAt.UTC().Format(time.RFC3339),
		Result:          verificationResultToProto(v.Result),
		Error:           v.Error,
		TargetContainer: v.TargetContainer,
		ScratchDatabase: v.ScratchDatabase,
		DurationMs:      v.DurationMS,
		VerifiedBy:      v.VerifiedBy,
	}
	for _, c := range v.Checks {
		out.Checks = append(out.Checks, &pb.VerificationCheck{
			Name:   c.Name,
			Passed: c.Passed,
			Detail: c.Detail,
		})
	}
	return out
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
		Engine:      engineToProto(r.Engine),

		LastVerification: verificationToProto(r.LastVerification),
		RelationCount:    r.RelationCount,
	}
}
