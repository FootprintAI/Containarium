// Package backup implements logical (pg_dump) database backups for the
// databases running inside Containarium containers, stored off the
// database host.
//
// Design (see docs/DB-BACKUP-OPERATIONS.md for the operator runbook and
// the ISO 27001 A.8.13 control mapping):
//
//   - The dump is produced by running pg_dump *inside* the tenant's
//     container (reaching the container's own Postgres over loopback),
//     writing a compressed custom-format archive to the container's /tmp.
//   - The archive is pulled to the daemon host (ReadFile), checksummed,
//     and either kept in the host backup directory (LOCAL) or shipped to
//     an object store and removed from local staging (GCS).
//   - Metadata is persisted as a small JSON sidecar per backup in the
//     host backup directory, so ListBackups works even when the database
//     being backed up is down — the index never shares a failure domain
//     with the data it describes.
//
// The package deliberately does not import the protobuf types; the
// server layer translates between these core types and pb.
package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// EnginePostgres is the only database engine supported in v1.
const EnginePostgres = "postgres"

// Destination is where a dump is stored off-host. Kept as a string in the
// core so the package stays free of the pb dependency; the server maps it
// to/from pb.BackupDestination.
type Destination string

const (
	DestLocal Destination = "local"
	DestGCS   Destination = "gcs"
)

// ContainerOps is the slice of *container.Manager the backup manager
// needs. Declared as an interface so tests can supply a fake without an
// Incus backend.
type ContainerOps interface {
	// Exec runs a command inside the container, discarding output.
	Exec(containerName string, command []string) error
	// ExecWithOutput runs a command inside the container and returns
	// stdout/stderr (pg_dump/pg_restore report errors on stderr).
	ExecWithOutput(containerName string, command []string) (string, string, error)
	// ReadFile pulls a file from inside the container into host memory.
	ReadFile(containerName, path string) ([]byte, error)
	// WriteFile pushes content to a path inside the container.
	WriteFile(containerName, path string, content []byte, mode string) error
}

// Uploader ships a staged local file to and from an off-host object
// store. The GCS implementation shells out to the host's `gcloud`; tests
// supply a fake.
type Uploader interface {
	Upload(localPath, destURI string) error
	Download(destURI, localPath string) error
	Delete(destURI string) error
}

// Record is the metadata index entry for one stored dump. Persisted as
// JSON in the host backup directory.
type Record struct {
	ID          string      `json:"id"`
	Username    string      `json:"username"`
	Database    string      `json:"database"`
	CreatedAt   time.Time   `json:"created_at"`
	SizeBytes   int64       `json:"size_bytes"`
	SHA256      string      `json:"sha256"`
	Destination Destination `json:"destination"`
	Location    string      `json:"location"`
	Engine      string      `json:"engine"`
}

// PgConn carries the connection parameters pg_dump / pg_restore use
// *inside the container*. Password is passed to the child via the
// PGPASSWORD environment variable, never on argv.
type PgConn struct {
	Database string
	User     string
	Password string
	Host     string
	Port     int
}

func (c PgConn) withDefaults() PgConn {
	if c.User == "" {
		c.User = "postgres"
	}
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Port == 0 {
		c.Port = 5432
	}
	return c
}

// Manager orchestrates backups. One per daemon.
type Manager struct {
	ops      ContainerOps
	uploader Uploader // may be nil → GCS destinations are rejected
	dir      string   // host backup directory (dumps for LOCAL + sidecar index for all)
	clock    func() time.Time
}

// NewManager constructs a backup manager. dir is the host directory where
// dumps (for LOCAL) and the JSON index (for all destinations) are kept.
// uploader may be nil when no object store is configured; GCS backups
// then return a clear error.
func NewManager(ops ContainerOps, uploader Uploader, dir string) *Manager {
	return &Manager{ops: ops, uploader: uploader, dir: dir, clock: time.Now}
}

// CreateOptions parameterizes a backup.
type CreateOptions struct {
	Username      string
	ContainerName string
	Conn          PgConn
	Destination   Destination
	GCSBucket     string // e.g. "gs://my-backups/pg" — required for DestGCS
}

// RestoreOptions parameterizes a restore.
type RestoreOptions struct {
	ID            string
	ContainerName string
	Conn          PgConn // Database empty → restore into the record's database
	Clean         bool   // pass --clean --if-exists to pg_restore
}

func (m *Manager) now() time.Time {
	if m.clock != nil {
		return m.clock()
	}
	return time.Now()
}

// Create dumps the container's database and stores it at the chosen
// destination, returning the committed record.
func (m *Manager) Create(opts CreateOptions) (*Record, error) {
	conn := opts.Conn.withDefaults()
	if conn.Database == "" {
		return nil, fmt.Errorf("database is required")
	}
	if opts.ContainerName == "" {
		return nil, fmt.Errorf("container name is required")
	}
	switch opts.Destination {
	case DestLocal:
		// ok
	case DestGCS:
		if m.uploader == nil {
			return nil, fmt.Errorf("gcs destination requested but no object-store uploader is configured on this daemon")
		}
		if !strings.HasPrefix(opts.GCSBucket, "gs://") {
			return nil, fmt.Errorf("gcs_bucket must be a gs:// URI, got %q", opts.GCSBucket)
		}
	default:
		return nil, fmt.Errorf("unknown or unspecified destination %q", opts.Destination)
	}

	id := fmt.Sprintf("%s-%s-%s", opts.Username, conn.Database, m.now().UTC().Format("20060102T150405Z"))
	// The id becomes a path component (sidecar, temp files). A
	// username or database carrying a separator would let it
	// escape m.dir — reject rather than silently mangle.
	if err := validateBackupID(id); err != nil {
		return nil, fmt.Errorf("cannot derive a safe backup id: %w", err)
	}
	inContainerPath := "/tmp/containarium-backup-" + id + ".dump"

	// 1. Dump inside the container (custom format = compressed + selective
	//    restore). Password travels via PGPASSWORD, not argv.
	dumpScript := fmt.Sprintf(
		"pg_dump -h %s -p %d -U %s -d %s -Fc -f %s",
		shellQuote(conn.Host), conn.Port, shellQuote(conn.User),
		shellQuote(conn.Database), shellQuote(inContainerPath),
	)
	if _, stderr, err := m.ops.ExecWithOutput(opts.ContainerName, wrapPg(conn.Password, dumpScript)); err != nil {
		return nil, fmt.Errorf("pg_dump failed: %w: %s", err, strings.TrimSpace(stderr))
	}

	// 2. Pull the archive to the host, then clean up the in-container copy.
	data, err := m.ops.ReadFile(opts.ContainerName, inContainerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dump from container: %w", err)
	}
	_ = m.ops.Exec(opts.ContainerName, []string{"rm", "-f", inContainerPath})
	if len(data) == 0 {
		return nil, fmt.Errorf("pg_dump produced an empty archive (check database name and credentials)")
	}

	sum := sha256.Sum256(data)
	record := &Record{
		ID:          id,
		Username:    opts.Username,
		Database:    conn.Database,
		CreatedAt:   m.now().UTC(),
		SizeBytes:   int64(len(data)),
		SHA256:      hex.EncodeToString(sum[:]),
		Destination: opts.Destination,
		Engine:      EnginePostgres,
	}

	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}
	localDump := filepath.Join(m.dir, id+".dump")
	if err := os.WriteFile(localDump, data, 0o600); err != nil {
		return nil, fmt.Errorf("failed to stage dump: %w", err)
	}

	// 3. For off-host destinations, ship the staged dump and drop the
	//    local copy (the sidecar index stays local).
	switch opts.Destination {
	case DestLocal:
		record.Location = localDump
	case DestGCS:
		destURI := strings.TrimRight(opts.GCSBucket, "/") + "/" + id + ".dump"
		if err := m.uploader.Upload(localDump, destURI); err != nil {
			_ = os.Remove(localDump)
			return nil, fmt.Errorf("failed to upload dump to %s: %w", destURI, err)
		}
		_ = os.Remove(localDump)
		record.Location = destURI
	}

	if err := m.writeSidecar(record); err != nil {
		return nil, err
	}
	return record, nil
}

// List returns stored records, newest first, optionally filtered by
// tenant.
func (m *Manager) List(username string) ([]*Record, error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}
	var out []*Record
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".meta.json") {
			continue
		}
		r, err := m.readSidecar(filepath.Join(m.dir, e.Name()))
		if err != nil {
			continue // a corrupt sidecar shouldn't hide the rest
		}
		if username != "" && r.Username != username {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Get returns a single record by ID.
func (m *Manager) Get(id string) (*Record, error) {
	if err := validateBackupID(id); err != nil {
		return nil, err
	}
	return m.readSidecar(m.sidecarPath(id))
}

// validateBackupID rejects ids that could escape the backup
// directory once joined into a path. Ids are generated as
// "<username>-<database>-<timestamp>" (see Create), but on the
// Get / Delete / Restore paths the id arrives from the API
// caller, so we re-check it before it ever reaches
// filepath.Join. The filepath.Base equality check catches any
// separator or "." / ".." component on every platform.
func validateBackupID(id string) error {
	if id == "" {
		return fmt.Errorf("id is required")
	}
	if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") || id != filepath.Base(id) {
		return fmt.Errorf("invalid backup id %q", id)
	}
	return nil
}

// Delete removes a stored dump and its index entry.
func (m *Manager) Delete(id string) error {
	r, err := m.Get(id)
	if err != nil {
		return err
	}
	switch r.Destination {
	case DestGCS:
		if m.uploader == nil {
			return fmt.Errorf("cannot delete GCS object: no object-store uploader configured")
		}
		if err := m.uploader.Delete(r.Location); err != nil {
			return fmt.Errorf("failed to delete %s: %w", r.Location, err)
		}
	default:
		if err := os.Remove(r.Location); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete dump %s: %w", r.Location, err)
		}
	}
	if err := os.Remove(m.sidecarPath(id)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete index entry: %w", err)
	}
	return nil
}

// Restore streams a stored dump back into a container's database.
func (m *Manager) Restore(opts RestoreOptions) error {
	if opts.ContainerName == "" {
		return fmt.Errorf("container name is required")
	}
	r, err := m.Get(opts.ID)
	if err != nil {
		return err
	}

	// Fetch the dump bytes to the host.
	var data []byte
	switch r.Destination {
	case DestGCS:
		if m.uploader == nil {
			return fmt.Errorf("cannot restore GCS backup: no object-store uploader configured")
		}
		tmp := filepath.Join(m.dir, "."+r.ID+".restore.tmp")
		if err := m.uploader.Download(r.Location, tmp); err != nil {
			return fmt.Errorf("failed to download %s: %w", r.Location, err)
		}
		data, err = os.ReadFile(tmp) // #nosec G304 -- tmp is filepath.Join(m.dir, ...) with a validated record id
		_ = os.Remove(tmp)
		if err != nil {
			return fmt.Errorf("failed to read downloaded dump: %w", err)
		}
	default:
		data, err = os.ReadFile(r.Location)
		if err != nil {
			return fmt.Errorf("failed to read dump %s: %w", r.Location, err)
		}
	}

	// Integrity check before we overwrite a live database.
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != r.SHA256 {
		return fmt.Errorf("dump integrity check failed: sha256 %s != recorded %s (corruption or tampering)", got, r.SHA256)
	}

	conn := opts.Conn.withDefaults()
	if conn.Database == "" {
		conn.Database = r.Database
	}

	inContainerPath := "/tmp/containarium-restore-" + r.ID + ".dump"
	if err := m.ops.WriteFile(opts.ContainerName, inContainerPath, data, "0600"); err != nil {
		return fmt.Errorf("failed to push dump into container: %w", err)
	}
	defer func() { _ = m.ops.Exec(opts.ContainerName, []string{"rm", "-f", inContainerPath}) }()

	cleanFlag := ""
	if opts.Clean {
		cleanFlag = "--clean --if-exists "
	}
	restoreScript := fmt.Sprintf(
		"pg_restore -h %s -p %d -U %s -d %s %s%s",
		shellQuote(conn.Host), conn.Port, shellQuote(conn.User),
		shellQuote(conn.Database), cleanFlag, shellQuote(inContainerPath),
	)
	if _, stderr, err := m.ops.ExecWithOutput(opts.ContainerName, wrapPg(conn.Password, restoreScript)); err != nil {
		return fmt.Errorf("pg_restore failed: %w: %s", err, strings.TrimSpace(stderr))
	}
	return nil
}

func (m *Manager) sidecarPath(id string) string { return filepath.Join(m.dir, id+".meta.json") }

func (m *Manager) writeSidecar(r *Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode backup metadata: %w", err)
	}
	if err := os.WriteFile(m.sidecarPath(r.ID), b, 0o600); err != nil {
		return fmt.Errorf("failed to write backup metadata: %w", err)
	}
	return nil
}

func (m *Manager) readSidecar(path string) (*Record, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is m.sidecarPath(id); id validated in Get/Create via validateBackupID
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("backup not found")
		}
		return nil, fmt.Errorf("failed to read backup metadata: %w", err)
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("corrupt backup metadata at %s: %w", path, err)
	}
	return &r, nil
}

// wrapPg builds the bash invocation that exports PGPASSWORD (when set)
// and runs the given pg command under strict mode. Returns the argv for
// ExecWithOutput.
func wrapPg(password, pgCmd string) []string {
	var b strings.Builder
	b.WriteString("set -euo pipefail; ")
	if password != "" {
		fmt.Fprintf(&b, "export PGPASSWORD=%s; ", shellQuote(password))
	}
	b.WriteString(pgCmd)
	return []string{"bash", "-c", b.String()}
}

// shellQuote single-quotes s for safe interpolation into a bash command,
// escaping embedded single quotes the POSIX way ('\” closes, escapes,
// reopens).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
