package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	appconfig "github.com/footprintai/containarium/internal/config"
	secretsstore "github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/pkg/core/backup"
	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
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
	verifierMu sync.Mutex
	verifiers  map[string]bool
}

// acquireVerifier reserves one managed verifier per tenant. The release must
// run after container cleanup, including when provisioning or verification fails.
func (s *BackupServer) acquireVerifier(tenant string) (release func(), ok bool) {
	s.verifierMu.Lock()
	defer s.verifierMu.Unlock()
	if s.verifiers[tenant] {
		return nil, false
	}
	if s.verifiers == nil {
		s.verifiers = make(map[string]bool)
	}
	s.verifiers[tenant] = true
	return func() {
		s.verifierMu.Lock()
		defer s.verifierMu.Unlock()
		delete(s.verifiers, tenant)
	}, true
}

// Manager exposes the backup core for wiring into other subsystems that
// need read access to the durable backup index — currently the metrics
// export collector's backup-health series (#2294), via
// ContainerServer.SetBackupManager. Nothing else should need this: it is
// a seam for cross-cutting observability, not a general escape hatch
// around BackupServer's own RPC surface.
func (s *BackupServer) Manager() *backup.Manager {
	return s.mgr
}

// envBackupKMSKeyName names the KMS key the daemon wraps per-backup
// identities under (#2402): a full CryptoKey resource name, reached via
// the daemon's existing CONTAINARIUM_KMS_BACKEND=gcp configuration. Empty
// means no wrapper — the #1831 / #1836 behaviour, byte for byte.
const envBackupKMSKeyName = "CONTAINARIUM_BACKUP_KMS_KEY_NAME"

// NewBackupServer wires the backup service to the container manager. A GCS
// uploader is constructed best-effort: if `gcloud` is absent the daemon
// still serves LOCAL backups and rejects GCS requests with a clear error,
// rather than failing to start.
//
// The managed-backup key wrapper (#2402) is NOT best-effort: when
// CONTAINARIUM_BACKUP_KMS_KEY_NAME is set but no wrapper can be built —
// the KMS backend is not gcp, the credentials are missing, the name is
// not a CryptoKey — the daemon fails to start. An operator who configured
// managed backups and silently got legacy ones would learn about it at
// restore time, which is the one moment that must not hold surprises.
func NewBackupServer(containers *ContainerServer) (*BackupServer, error) {
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

	wrapper, err := loadBackupWrapper()
	if err != nil {
		return nil, err
	}
	opts, err := boxBackupOptionsFromEnv(containers.manager)
	if err != nil {
		return nil, err
	}
	if wrapper != nil {
		opts = append(opts, backup.WithWrapper(wrapper))
		log.Printf("[backup] managed key mode enabled (wrapping per-backup identities under %s)", os.Getenv(envBackupKMSKeyName))
	}

	mgr := backup.NewManager(containers.manager, uploader, dir, opts...)
	// A daemon killed mid whole-box backup leaves its spill file behind.
	if n, err := mgr.SweepStaleBoxSpills(); err != nil {
		log.Printf("[backup] sweeping stale whole-box spill files: %v", err)
	} else if n > 0 {
		log.Printf("[backup] removed %d stale whole-box spill file(s) at start", n)
	}
	return &BackupServer{
		containers: containers,
		mgr:        mgr,
	}, nil
}

// Whole-box backup settings (#2801).
const (
	// envBackupBoxMaxBytes overrides the 256 GiB cap on a stored BOX
	// backup, in bytes.
	envBackupBoxMaxBytes = "CONTAINARIUM_BACKUP_BOX_MAX_BYTES"
	// envIncusBackupsDir is where Incus stages an export before streaming
	// it (Incus 6.0 LTS has no direct_backup). The free-space pre-flight
	// counts a copy of the box there.
	envIncusBackupsDir = "CONTAINARIUM_INCUS_BACKUPS_DIR"
	// defaultIncusBackupsDir is that directory on a default Incus install.
	defaultIncusBackupsDir = "/var/lib/incus/backups"
)

// boxBackupOptionsFromEnv wires whole-box backup into the backup core: the
// container manager as the export, the Incus staging dir for the
// pre-flight, and the cap. A cap that does not parse fails startup, like a
// bad KMS key name: an operator who set one and silently got the default
// would find out when a backup is refused, or when the disk fills.
func boxBackupOptionsFromEnv(box backup.BoxOps) ([]backup.Option, error) {
	var opts []backup.Option
	if box != nil {
		opts = append(opts, backup.WithBoxOps(box))
	}
	dir := strings.TrimSpace(os.Getenv(envIncusBackupsDir))
	if dir == "" {
		dir = defaultIncusBackupsDir
	}
	opts = append(opts, backup.WithBoxStagingDirs(dir))
	if raw := strings.TrimSpace(os.Getenv(envBackupBoxMaxBytes)); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("%s=%q: want a positive number of bytes", envBackupBoxMaxBytes, raw)
		}
		opts = append(opts, backup.WithMaxBoxBytes(n))
	}
	return opts, nil
}

// loadBackupWrapper builds the key wrapper from CONTAINARIUM_BACKUP_KMS_
// KEY_NAME through the same resource-name keyed factory the secrets
// store uses for per-tenant KEKs, so the backup key rides the daemon's
// existing KMS auth (token / token file / endpoint). Returns (nil, nil)
// when the variable is empty.
func loadBackupWrapper() (corecrypto.KMSClient, error) {
	keyName := strings.TrimSpace(os.Getenv(envBackupKMSKeyName))
	if keyName == "" {
		return nil, nil
	}
	factory, err := secretsstore.LoadTenantKMSFactory()
	if err != nil {
		return nil, fmt.Errorf("%s is set but the KMS backend could not be loaded: %w", envBackupKMSKeyName, err)
	}
	if factory == nil {
		return nil, fmt.Errorf("%s is set but CONTAINARIUM_KMS_BACKEND is not \"gcp\" (got %q): managed backups need a resource-name keyed KMS backend",
			envBackupKMSKeyName, os.Getenv(appconfig.EnvKMSBackend))
	}
	wrapper, err := factory(keyName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envBackupKMSKeyName, err)
	}
	return wrapper, nil
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

	scope, err := scopeFromProto(req.Scope)
	if err != nil {
		return nil, err
	}
	if scope == pb.BackupScope_BACKUP_SCOPE_BOX {
		return s.createBoxBackup(ctx, req)
	}

	dest, err := destFromProto(req.Destination)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// #1836: an explicit request recipient always wins; otherwise fall
	// back to the tenant's own self-registered CONTAINARIUM_BACKUP_AGE_RECIPIENT
	// secret, so a scheduled backup with no operator present still
	// encrypts. Neither a standalone daemon (no secrets store) nor a
	// tenant who never registered one is an error — both mean plaintext,
	// today's unchanged default (or, on a daemon with a key wrapper,
	// MANAGED instead of BOTH — #2402).
	ageRecipient, err := resolveAgeRecipient(ctx, backupSecretsReader(s.containers), req.Username, req.AgeRecipient)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	// #2402: a key mode this daemon cannot satisfy is refused here, with
	// a code that says why, before any container is touched. The core
	// re-checks the same rules; this is where they become gRPC codes.
	keyMode, err := keyModeFromProto(req.KeyMode, s.mgr.HasWrapper(), ageRecipient != "")
	if err != nil {
		return nil, err
	}

	// #3169: with require_encryption, a dump that would be stored with no
	// key at all is refused here, before any container is touched, so no
	// plaintext object is ever written.
	if err := refusePlaintext(req.RequireEncryption, req.Username, keyMode, ageRecipient, s.mgr.HasWrapper()); err != nil {
		log.Printf("[backup] REFUSED user=%s: %v", req.Username, err)
		return nil, err
	}

	hookFormat, err := hookFormatFromProto(req.HookFormat)
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
		Hook:          req.Hook,
		Label:         req.Label,
		HookFormat:    hookFormat,
		AgeRecipient:  ageRecipient,
		KeyMode:       keyMode,
	}

	// Empty database → back up every non-template database found (#954),
	// the default, no-guessing path. An explicit database keeps today's
	// single-database behavior and response shape exactly as before. A
	// hook backup (#1831) names no database and runs exactly once.
	if backupAllRequested(req) {
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
			if backupStoredPlaintext(r) {
				log.Printf("[backup] WARNING UNENCRYPTED user=%s id=%s: stored without encryption (no age recipient registered or given)", r.Username, r.ID)
			}
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
	if backupStoredPlaintext(rec) {
		log.Printf("[backup] WARNING UNENCRYPTED user=%s id=%s: stored without encryption (no age recipient registered or given)", rec.Username, rec.ID)
	}
	return &pb.CreateBackupResponse{
		Message: "backup created: " + rec.ID,
		Record:  recordToProto(rec),
		Records: []*pb.BackupRecord{recordToProto(rec)},
	}, nil
}

// createBoxBackup takes a BOX-scope backup (#2800 contract, #2801 data
// path). The caller has already passed the scope and tenant checks; the box
// is the tenant's own container, addressed by username as everywhere else.
//
// Every refusal precedes the export. No command runs inside the box: the
// export goes through Incus, which reads a point-in-time snapshot on ZFS.
func (s *BackupServer) createBoxBackup(ctx context.Context, req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	// A BOX request names a box, not a database. A connection — even an
	// empty one — or a hook means the caller built a database request and
	// set the wrong scope; guessing which they meant is not our call.
	if req.Connection != nil {
		return nil, status.Error(codes.InvalidArgument, "a BOX backup takes no database connection: unset connection, or use scope DATABASE")
	}
	if req.Hook != "" || req.HookFormat != pb.HookFormat_HOOK_FORMAT_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "a BOX backup takes no hook or hook_format: unset them, or use scope DATABASE")
	}
	if _, err := destFromProto(req.Destination); err != nil {
		return nil, err
	}

	// Plaintext is forbidden for BOX (decision of 2026-10-25 on #2800). The
	// database default can resolve to plaintext, so BOX does not take a
	// default at all: the caller names MANAGED, AGE_RECIPIENT or BOTH, and
	// keyModeFromProto then checks this daemon can honour it.
	if req.KeyMode == pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "a BOX backup must be encrypted: set key_mode to MANAGED, AGE_RECIPIENT or BOTH")
	}
	ageRecipient, err := resolveAgeRecipient(ctx, backupSecretsReader(s.containers), req.Username, req.AgeRecipient)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	keyMode, err := keyModeFromProto(req.KeyMode, s.mgr.HasWrapper(), ageRecipient != "")
	if err != nil {
		return nil, err
	}
	dest, err := destFromProto(req.Destination)
	if err != nil {
		return nil, err
	}

	info, err := s.containers.manager.Get(req.Username)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "box for user %s not found: %v", req.Username, err)
	}
	rec, err := s.mgr.CreateBox(backup.BoxCreateOptions{
		Username:      req.Username,
		ContainerName: info.Name,
		Destination:   dest,
		GCSBucket:     req.GcsBucket,
		AgeRecipient:  ageRecipient,
		KeyMode:       keyMode,
	})
	if err != nil {
		return nil, boxCreateStatus(err)
	}
	log.Printf("[backup] created id=%s user=%s box=%s dest=%s size=%d", rec.ID, rec.Username, rec.Database, rec.Destination, rec.SizeBytes)
	return &pb.CreateBackupResponse{
		Message: "box backup created: " + rec.ID,
		Record:  recordToProto(rec),
		Records: []*pb.BackupRecord{recordToProto(rec)},
	}, nil
}

// boxCreateStatus maps a whole-box create failure to a gRPC code: no room
// (the free-space pre-flight, or the cap) is ResourceExhausted, a daemon
// that cannot export is FailedPrecondition, a second backup of a box that is
// already being backed up is Aborted (retry when the first finishes, the
// same code a profile operation already in progress returns), and anything
// else is Internal.
func boxCreateStatus(err error) error {
	switch {
	case errors.Is(err, backup.ErrInsufficientSpace), errors.Is(err, backup.ErrDumpTooLarge):
		return status.Errorf(codes.ResourceExhausted, "box backup failed: %v", err)
	case errors.Is(err, backup.ErrBoxBackupInProgress):
		return status.Errorf(codes.Aborted, "box backup failed: %v", err)
	case errors.Is(err, backup.ErrBoxUnavailable):
		return status.Errorf(codes.FailedPrecondition, "box backup failed: %v", err)
	default:
		return status.Errorf(codes.Internal, "box backup failed: %v", err)
	}
}

// ListBackups returns stored records. Admins see all tenants; a non-admin
// defaults to their own backups and cannot request another tenant's records.
func (s *BackupServer) ListBackups(ctx context.Context, req *pb.ListBackupsRequest) (*pb.ListBackupsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeBackupsRead); err != nil {
		return nil, err
	}
	username := req.Username
	if subject, roles, ok := auth.SubjectFromGRPCContext(ctx); ok && !auth.HasRole(roles, auth.RoleAdmin) {
		if username != "" {
			if err := auth.AuthorizeTenant(ctx, username); err != nil {
				return nil, err
			}
		}
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
	target, err := s.resolveRestoreTarget(ctx, req.TargetContainer)
	if err != nil {
		return nil, err
	}

	if err := s.mgr.Restore(backup.RestoreOptions{
		ID:              req.Id,
		ContainerName:   info.Name,
		TargetContainer: target,
		Conn:            connFromProto(req.Connection),
		Clean:           req.Clean,
		AgeIdentity:     req.AgeIdentity, // per-call; never logged or stored (#1831)
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "restore failed: %v", err)
	}
	if target == "" {
		target = info.Name
	}
	log.Printf("[backup] restored id=%s user=%s db=%s target=%s clean=%t", rec.ID, rec.Username, rec.Database, target, req.Clean)
	return &pb.RestoreBackupResponse{Message: "restore complete: " + rec.ID}, nil
}

// resolveRestoreTarget checks a RestoreBackupRequest.target_container
// (#2403). Empty stays empty: the core then restores in place. Otherwise
// the name must be a tenant container ("<username>-container"), the
// caller must be authorized for that tenant (the restore writes into it),
// and it must exist. Every refusal precedes any container command.
func (s *BackupServer) resolveRestoreTarget(ctx context.Context, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	owner, ok := strings.CutSuffix(name, "-container")
	if !ok || owner == "" {
		return "", status.Errorf(codes.InvalidArgument, "target_container %q is not a tenant container (expected <username>-container)", name)
	}
	if err := auth.AuthorizeTenant(ctx, owner); err != nil {
		return "", err
	}
	info, err := s.containers.manager.Get(owner)
	if err != nil {
		return "", status.Errorf(codes.NotFound, "target container %s not found: %v", name, err)
	}
	return info.Name, nil
}

// VerifyBackup restore-tests a stored dump against a throwaway database
// inside a *target* tenant's container, never the source container.
//
// A dump that fails to restore is a successful RPC reporting a failed
// verification — the failure is the answer, not an error. Only a test
// that could not be run at all (unknown backup, missing target
// container) returns a gRPC error.
func (s *BackupServer) VerifyBackup(ctx context.Context, req *pb.VerifyBackupRequest) (*pb.VerifyBackupResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeBackupsVerify); err != nil {
		if status.Code(err) == codes.PermissionDenied {
			return nil, status.Errorf(codes.PermissionDenied,
				"%s; re-mint the verifier token with containarium token generate --username <tenant> --roles user --scopes %s,%s --expiry 720h --secret-file <jwt-secret-file> --raw",
				status.Convert(err).Message(), auth.ScopeBackupsRead, auth.ScopeBackupsVerify)
		}
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

	var targetName string
	conn := connFromProto(req.Connection)
	if req.TargetUsername == rec.Username {
		release, ok := s.acquireVerifier(rec.Username)
		if !ok {
			return nil, status.Error(codes.ResourceExhausted, "a managed backup verification is already running for this tenant")
		}
		defer release()
		// A tenant's own username selects a daemon-owned throwaway target,
		// never its live container. Authorization above still binds BOTH
		// the backup and target to the caller's tenant.
		name, password, cleanup, err := s.containers.manager.CreateBackupVerifier(rec.Username)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "create isolated backup verifier: %v", err)
		}
		targetName = name
		conn = backup.PgConn{Host: "127.0.0.1", Port: 5432, User: "postgres", Password: password}
		defer func() {
			if err := cleanup(); err != nil {
				log.Printf("[backup] verifier cleanup failed target=%s: %v", name, err)
			}
		}()
	} else {
		target, err := s.containers.manager.Get(req.TargetUsername)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "target container for user %s not found: %v", req.TargetUsername, err)
		}
		targetName = target.Name
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
		TargetContainer: targetName,
		SourceContainer: sourceName,
		Conn:            conn,
		VerifiedBy:      subject,
		AgeIdentity:     req.AgeIdentity, // per-call; never logged or stored (#1831, #2295)
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

// PruneBackups deletes older backups for a tenant, keeping only the newest
// N per database (#1839). A partial failure — one record's delete fails —
// is reported in the response, never as a gRPC error: the sweep still ran
// and still deleted what it could, mirroring CreateBackup's per-database
// partial-failure posture (#954).
func (s *BackupServer) PruneBackups(ctx context.Context, req *pb.PruneBackupsRequest) (*pb.PruneBackupsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeBackupsWrite); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}
	if req.Keep < 1 {
		return nil, status.Errorf(codes.InvalidArgument, "keep must be at least 1 (got %d); use DeleteBackup to remove a specific backup by id", req.Keep)
	}

	res, err := s.mgr.Prune(backup.PruneOptions{
		Username: req.Username,
		Database: req.Database,
		Keep:     int(req.Keep),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "prune failed: %v", err)
	}
	for _, id := range res.Deleted {
		log.Printf("[backup] pruned id=%s user=%s", id, req.Username)
	}
	for _, f := range res.Failures {
		log.Printf("[backup] prune failure user=%s: %s", req.Username, f)
	}
	msg := fmt.Sprintf("pruned %d backup(s)", len(res.Deleted))
	if len(res.Failures) > 0 {
		msg += fmt.Sprintf(", %d failed", len(res.Failures))
	}
	return &pb.PruneBackupsResponse{
		Message:    msg,
		DeletedIds: res.Deleted,
		Failures:   res.Failures,
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

// backupAllRequested reports whether a create should fan out over every
// database in the container (#954). That is the pg_dump path's default when
// no database is named; a hook backup (#1831) has no database concept and
// always runs exactly once.
func backupAllRequested(req *pb.CreateBackupRequest) bool {
	if req.Hook != "" {
		return false
	}
	return req.Connection == nil || req.Connection.Database == ""
}

// --- proto <-> core mapping ---

// scopeFromProto normalises a create request's scope (#2800). UNSPECIFIED
// is DATABASE, so a client that predates the field behaves exactly as
// before; a value this daemon does not know is refused, never read as
// either scope.
func scopeFromProto(s pb.BackupScope) (pb.BackupScope, error) {
	switch s {
	case pb.BackupScope_BACKUP_SCOPE_UNSPECIFIED, pb.BackupScope_BACKUP_SCOPE_DATABASE:
		return pb.BackupScope_BACKUP_SCOPE_DATABASE, nil
	case pb.BackupScope_BACKUP_SCOPE_BOX:
		return pb.BackupScope_BACKUP_SCOPE_BOX, nil
	default:
		return pb.BackupScope_BACKUP_SCOPE_UNSPECIFIED, status.Errorf(codes.InvalidArgument, "unknown scope %d", s)
	}
}

// scopeToProto reports what a stored record captured. A BOX record is
// recognised by its engine (#2801); every other record is a database backup
// (pg_dump or hook), including every record written before the field
// existed.
func scopeToProto(r *backup.Record) pb.BackupScope {
	if r.Engine == backup.EngineBox {
		return pb.BackupScope_BACKUP_SCOPE_BOX
	}
	return pb.BackupScope_BACKUP_SCOPE_DATABASE
}

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
	case backup.EngineHook:
		return pb.BackupEngine_BACKUP_ENGINE_HOOK
	case backup.EngineBox:
		return pb.BackupEngine_BACKUP_ENGINE_BOX
	default:
		return pb.BackupEngine_BACKUP_ENGINE_UNSPECIFIED
	}
}

// keyModeFromProto maps a request's key mode to the core's (#2402).
// UNSPECIFIED is "" — the core applies the daemon default. An explicit
// mode is checked against what this daemon can do: a managed mode on a
// daemon with no wrapper is FAILED_PRECONDITION (the daemon is not set
// up for it); a recipient mode with no recipient is INVALID_ARGUMENT
// (the request is incomplete). Neither is ever downgraded silently.
func keyModeFromProto(m pb.BackupKeyMode, hasWrapper, hasRecipient bool) (backup.KeyMode, error) {
	switch m {
	case pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED:
		return "", nil
	case pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT:
		if !hasRecipient {
			return "", status.Error(codes.InvalidArgument, "key_mode AGE_RECIPIENT needs an age recipient: pass age_recipient or register CONTAINARIUM_BACKUP_AGE_RECIPIENT")
		}
		return backup.KeyModeAgeRecipient, nil
	case pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED:
		if !hasWrapper {
			return "", status.Error(codes.FailedPrecondition, "key_mode MANAGED requested but this daemon has no backup key wrapper configured (CONTAINARIUM_BACKUP_KMS_KEY_NAME)")
		}
		return backup.KeyModeManaged, nil
	case pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH:
		if !hasWrapper {
			return "", status.Error(codes.FailedPrecondition, "key_mode BOTH requested but this daemon has no backup key wrapper configured (CONTAINARIUM_BACKUP_KMS_KEY_NAME)")
		}
		if !hasRecipient {
			return "", status.Error(codes.InvalidArgument, "key_mode BOTH needs an age recipient alongside the managed key: pass age_recipient or register CONTAINARIUM_BACKUP_AGE_RECIPIENT")
		}
		return backup.KeyModeBoth, nil
	default:
		return "", status.Errorf(codes.InvalidArgument, "unknown key_mode %d", m)
	}
}

// backupStoredPlaintext reports whether a stored record has no key protecting
// it at all (#3169): not age-encrypted and not managed/both key mode.
func backupStoredPlaintext(r *backup.Record) bool {
	return !r.Encrypted && keyModeToProto(r) == pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED
}

// refusePlaintext enforces require_encryption (#3169). It refuses exactly
// the case Manager.resolveKeyMode would store in plaintext: no explicit key
// mode, no recipient (given or registered), and no managed key wrapper on
// this daemon. Without require it never refuses, so today's default stands.
func refusePlaintext(require bool, username string, mode backup.KeyMode, recipient string, hasWrapper bool) error {
	if !require || mode != "" || strings.TrimSpace(recipient) != "" || hasWrapper {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"refusing to store tenant %s's backup unencrypted (require_encryption): no age recipient was given or registered (%s) and this daemon has no managed backup key; register one with `containarium secrets set %s %s age1...` on this daemon",
		username, backupAgeRecipientSecretName, username, backupAgeRecipientSecretName)
}

// keyModeToProto maps a stored record's key mode to the wire enum. The
// sidecar carries key_mode only for managed records; for anything else
// Record.EffectiveKeyMode derives AGE_RECIPIENT from encrypted +
// age_recipient, so records written before the field existed read the
// same as records written after. An unknown stored value maps to
// UNSPECIFIED rather than to a guess, as engineToProto does.
func keyModeToProto(r *backup.Record) pb.BackupKeyMode {
	switch r.EffectiveKeyMode() {
	case backup.KeyModeAgeRecipient:
		return pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT
	case backup.KeyModeManaged:
		return pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED
	case backup.KeyModeBoth:
		return pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH
	default:
		return pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED
	}
}

// hookFormatFromProto maps a create request's declared hook format to the
// core (#2405). UNSPECIFIED stays empty, which the core treats as opaque.
func hookFormatFromProto(f pb.HookFormat) (backup.HookFormat, error) {
	switch f {
	case pb.HookFormat_HOOK_FORMAT_UNSPECIFIED:
		return "", nil
	case pb.HookFormat_HOOK_FORMAT_OPAQUE:
		return backup.HookFormatOpaque, nil
	case pb.HookFormat_HOOK_FORMAT_PG_CUSTOM:
		return backup.HookFormatPGCustom, nil
	default:
		return "", fmt.Errorf("unknown hook_format %v", f)
	}
}

func hookFormatToProto(f backup.HookFormat) pb.HookFormat {
	switch f {
	case backup.HookFormatOpaque:
		return pb.HookFormat_HOOK_FORMAT_OPAQUE
	case backup.HookFormatPGCustom:
		return pb.HookFormat_HOOK_FORMAT_PG_CUSTOM
	default:
		return pb.HookFormat_HOOK_FORMAT_UNSPECIFIED
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

		Encrypted:    r.Encrypted,
		AgeRecipient: r.AgeRecipient,
		Hook:         r.Hook,

		WrappedKey: r.WrappedKey,
		KekId:      r.KEKID,
		KeyMode:    keyModeToProto(r),
		HookFormat: hookFormatToProto(r.HookFormat),
		Scope:      scopeToProto(r),
	}
}
