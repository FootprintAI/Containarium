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
	"log"
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

	// LastVerification is the outcome of the most recent restore test,
	// nil until the backup has been verified. SHA256 proves the bytes
	// are intact; only this proves the dump is restorable (#1159).
	LastVerification *Verification `json:"last_verification,omitempty"`

	// RelationCount is the number of user relations in the source
	// database at dump time — the manifest a restore test compares the
	// restored schema against. Nil when no manifest was captured (a
	// backup taken before verification existed, or a source that could
	// not be queried).
	RelationCount *int64 `json:"relation_count,omitempty"`

	// Encrypted is true when the stored bytes are an age ciphertext (#1831).
	// SizeBytes and SHA256 describe the ciphertext — what is actually stored
	// — so the integrity gate in fetchDump is unchanged. AgeRecipient is the
	// public recipient the dump was encrypted to; it is a public key, safe to
	// record, and tells an operator which identity can restore it.
	Encrypted    bool   `json:"encrypted,omitempty"`
	AgeRecipient string `json:"age_recipient,omitempty"`
	// Hook is the in-tenant command that produced a hook backup (#1831);
	// empty for pg_dump backups.
	Hook string `json:"hook,omitempty"`
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

	// Hook, when set, is an absolute path to an executable INSIDE the
	// container whose stdout is the dump (#1831). The pg_dump path and Conn
	// are bypassed entirely: the hook reaches its database over localhost
	// under the container's own auth, so no credential crosses to the
	// platform. Label fills the record's "database" slot (defaults to the
	// hook's basename).
	Hook  string
	Label string
	// AgeRecipient, when set, encrypts the dump to this age recipient
	// ("age1…") in-process before it is staged or uploaded (#1831). The
	// platform and the storage backend then hold ciphertext only.
	AgeRecipient string
}

// RestoreOptions parameterizes a restore.
type RestoreOptions struct {
	ID            string
	ContainerName string
	Conn          PgConn // Database empty → restore into the record's database
	Clean         bool   // pass --clean --if-exists to pg_restore
	// AgeIdentity ("AGE-SECRET-KEY-1…") decrypts an Encrypted record for
	// this one call. The platform holds no decryption key; the caller
	// supplies it and it is never stored or logged (#1831).
	AgeIdentity string
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
	if opts.ContainerName == "" {
		return nil, fmt.Errorf("container name is required")
	}
	// Hook mode (#1831): the tenant's own program produces the dump, so no
	// database name or credential is required — or used.
	hookMode := strings.TrimSpace(opts.Hook) != ""
	conn := opts.Conn.withDefaults()
	var dbLabel string
	if hookMode {
		if err := validateHook(opts.Hook); err != nil {
			return nil, err
		}
		dbLabel = strings.TrimSpace(opts.Label)
		if dbLabel == "" {
			dbLabel = hookLabel(opts.Hook)
		}
	} else {
		if conn.Database == "" {
			return nil, fmt.Errorf("database is required")
		}
		dbLabel = conn.Database
	}
	if opts.AgeRecipient != "" {
		if _, err := parseRecipient(opts.AgeRecipient); err != nil {
			return nil, err
		}
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

	id := fmt.Sprintf("%s-%s-%s", opts.Username, dbLabel, m.now().UTC().Format("20060102T150405Z"))
	// The id becomes a path component (sidecar, temp files). A
	// username or database carrying a separator would let it
	// escape m.dir — reject rather than silently mangle.
	if err := validateBackupID(id); err != nil {
		return nil, fmt.Errorf("cannot derive a safe backup id: %w", err)
	}
	inContainerPath := "/tmp/containarium-backup-" + id + ".dump"

	// 1. Produce the dump inside the container, writing to the same staging
	//    path either way so step 2 (pull + clean up) is shared.
	if hookMode {
		// The hook's stdout is the dump. `set -euo pipefail` (from wrapPg)
		// means a failing hook fails the backup instead of staging an empty
		// or truncated file. The path is single-quoted; it is a program to
		// run, never a shell fragment.
		hookScript := shellQuote(strings.TrimSpace(opts.Hook)) + " > " + shellQuote(inContainerPath)
		if _, stderr, err := m.ops.ExecWithOutput(opts.ContainerName, wrapPg("", hookScript)); err != nil {
			return nil, fmt.Errorf("backup hook %s failed: %w: %s", opts.Hook, err, strings.TrimSpace(stderr))
		}
	} else {
		// pg_dump (custom format = compressed + selective restore). Password
		// travels via PGPASSWORD, not argv.
		dumpScript := fmt.Sprintf(
			"pg_dump -h %s -p %d -U %s -d %s -Fc -f %s",
			shellQuote(conn.Host), conn.Port, shellQuote(conn.User),
			shellQuote(conn.Database), shellQuote(inContainerPath),
		)
		if _, stderr, err := m.ops.ExecWithOutput(opts.ContainerName, wrapPg(conn.Password, dumpScript)); err != nil {
			return nil, fmt.Errorf("pg_dump failed: %w: %s", err, strings.TrimSpace(stderr))
		}
	}

	// 2. Pull the archive to the host, then clean up the in-container copy.
	data, err := m.ops.ReadFile(opts.ContainerName, inContainerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dump from container: %w", err)
	}
	_ = m.ops.Exec(opts.ContainerName, []string{"rm", "-f", inContainerPath})
	if len(data) == 0 {
		if hookMode {
			return nil, fmt.Errorf("backup hook %s produced no output", opts.Hook)
		}
		return nil, fmt.Errorf("pg_dump produced an empty archive (check database name and credentials)")
	}

	// Record the source's user-relation count as a manifest for later
	// restore tests to compare against. Best-effort: a source that
	// cannot be queried still produced a valid dump, so a failure here
	// leaves the manifest unset rather than failing the backup.
	var relationCount *int64
	engine := EnginePostgres
	if hookMode {
		// An opaque hook stream has no Postgres catalog to read a manifest from.
		engine = EngineHook
	} else if n, err := m.countUserRelations(opts.ContainerName, conn, conn.Database); err != nil {
		log.Printf("[backup] could not record relation manifest for %s/%s: %v (verification will have nothing to compare against)",
			opts.Username, conn.Database, err)
	} else {
		relationCount = &n
	}

	// 2b. Encrypt in-process BEFORE anything is staged or shipped (#1831).
	//     From here on `data` is the ciphertext: it is what gets checksummed,
	//     sized, staged and stored, so plaintext never touches the daemon's
	//     disk or the object store, and fetchDump's integrity gate applies
	//     to the stored bytes unchanged.
	encrypted := false
	if opts.AgeRecipient != "" {
		ct, err := encryptWithRecipient(data, opts.AgeRecipient)
		if err != nil {
			return nil, fmt.Errorf("encrypt dump: %w", err)
		}
		data = ct
		encrypted = true
	}
	ext := ".dump"
	if encrypted {
		ext = ".dump.age"
	}

	sum := sha256.Sum256(data)
	record := &Record{
		ID:            id,
		Username:      opts.Username,
		Database:      dbLabel,
		CreatedAt:     m.now().UTC(),
		SizeBytes:     int64(len(data)),
		SHA256:        hex.EncodeToString(sum[:]),
		Destination:   opts.Destination,
		Engine:        engine,
		RelationCount: relationCount,
		Encrypted:     encrypted,
	}
	if encrypted {
		record.AgeRecipient = strings.TrimSpace(opts.AgeRecipient)
	}
	if hookMode {
		record.Hook = strings.TrimSpace(opts.Hook)
	}

	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}
	localDump := filepath.Join(m.dir, id+ext)
	if err := os.WriteFile(localDump, data, 0o600); err != nil {
		return nil, fmt.Errorf("failed to stage dump: %w", err)
	}

	// 3. For off-host destinations, ship the staged dump and drop the
	//    local copy (the sidecar index stays local).
	switch opts.Destination {
	case DestLocal:
		record.Location = localDump
	case DestGCS:
		destURI := strings.TrimRight(opts.GCSBucket, "/") + "/" + id + ext
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

// ListDatabases enumerates the non-template databases visible inside the
// container's Postgres — the same connection info used for pg_dump/
// pg_restore, just pointed at the always-present "postgres" maintenance
// database to run a catalog query instead of a dump. Used by CreateAll so
// a backup never requires the caller to already know a database name (#954).
func (m *Manager) ListDatabases(containerName string, conn PgConn) ([]string, error) {
	conn = conn.withDefaults()
	if containerName == "" {
		return nil, fmt.Errorf("container name is required")
	}
	const query = "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname;"
	script := fmt.Sprintf(
		"psql -h %s -p %d -U %s -d postgres -Atc %s",
		shellQuote(conn.Host), conn.Port, shellQuote(conn.User), shellQuote(query),
	)
	stdout, stderr, err := m.ops.ExecWithOutput(containerName, wrapPg(conn.Password, script))
	if err != nil {
		return nil, fmt.Errorf("list databases: %w: %s", err, strings.TrimSpace(stderr))
	}
	var dbs []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			dbs = append(dbs, line)
		}
	}
	return dbs, nil
}

// CreateAll backs up every non-template database in the container — the
// default, no-guessing path (#954): the caller doesn't need to already
// know a database name, and a scheduled backup can't fail because of a
// typo'd one, since no name is ever supplied. opts.Conn.Database is
// ignored (overwritten per database); every other CreateOptions field
// (container, destination, credentials) applies to each dump the same way
// a single Create call would.
//
// Reuses Create as-is per database rather than duplicating its dump/stage/
// upload logic, so the two paths can never drift. One failing database
// doesn't abort the others — errs collects a per-database failure
// alongside the record for every database that DID succeed, so a caller
// can surface "7 of 8 databases backed up, orders_db failed: <reason>"
// instead of an all-or-nothing result.
func (m *Manager) CreateAll(opts CreateOptions) ([]*Record, []error) {
	dbs, err := m.ListDatabases(opts.ContainerName, opts.Conn)
	if err != nil {
		return nil, []error{fmt.Errorf("list databases: %w", err)}
	}
	if len(dbs) == 0 {
		return nil, []error{fmt.Errorf("no databases found to back up")}
	}

	var records []*Record
	var errs []error
	for _, db := range dbs {
		o := opts
		o.Conn.Database = db
		r, err := m.Create(o)
		if err != nil {
			errs = append(errs, fmt.Errorf("database %q: %w", db, err))
			continue
		}
		records = append(records, r)
	}
	return records, errs
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

	// A hook backup is an opaque stream the platform never understood; it
	// cannot be pg_restore'd. Refuse before touching the target (#1831).
	if r.Engine == EngineHook {
		return fmt.Errorf("backup %s was produced by tenant hook %s and is an opaque stream: fetch it and apply it with the tenant's own tooling (automatic restore is only supported for %s dumps)",
			r.ID, r.Hook, EnginePostgres)
	}

	// Fetch the dump bytes to the host and integrity-check them before
	// we overwrite a live database. For an encrypted record the checksum
	// covers the ciphertext, so integrity is verified BEFORE decryption.
	data, err := m.fetchDump(r)
	if err != nil {
		return err
	}
	if r.Encrypted {
		if strings.TrimSpace(opts.AgeIdentity) == "" {
			return fmt.Errorf("backup %s is encrypted to %s: supply the matching age identity to restore (the platform holds no decryption key)", r.ID, r.AgeRecipient)
		}
		pt, err := decryptWithIdentity(data, opts.AgeIdentity)
		if err != nil {
			return fmt.Errorf("decrypt backup %s: %w", r.ID, err)
		}
		data = pt
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

// fetchDump pulls a record's dump bytes to the host (downloading from the
// object store for off-host destinations) and verifies them against the
// recorded SHA-256. Shared by Restore and Verify so the integrity gate
// cannot drift between the two paths.
func (m *Manager) fetchDump(r *Record) ([]byte, error) {
	var data []byte
	var err error
	switch r.Destination {
	case DestGCS:
		if m.uploader == nil {
			return nil, fmt.Errorf("cannot read GCS backup: no object-store uploader configured")
		}
		tmp := filepath.Join(m.dir, "."+r.ID+".restore.tmp")
		if err := m.uploader.Download(r.Location, tmp); err != nil {
			return nil, fmt.Errorf("failed to download %s: %w", r.Location, err)
		}
		data, err = os.ReadFile(tmp) // #nosec G304 -- tmp is filepath.Join(m.dir, ...) with a validated record id
		_ = os.Remove(tmp)
		if err != nil {
			return nil, fmt.Errorf("failed to read downloaded dump: %w", err)
		}
	default:
		data, err = os.ReadFile(r.Location)
		if err != nil {
			return nil, fmt.Errorf("failed to read dump %s: %w", r.Location, err)
		}
	}

	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != r.SHA256 {
		return nil, fmt.Errorf("dump integrity check failed: sha256 %s != recorded %s (corruption or tampering)", got, r.SHA256)
	}
	return data, nil
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
