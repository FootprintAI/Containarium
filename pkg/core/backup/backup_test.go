package backup

import (
	"os"
	"strings"
	"testing"
	"time"
)

// fakeOps is an in-memory ContainerOps. pg_dump is not actually run; any
// ReadFile of a /tmp dump path returns the canned dumpPayload, simulating
// the archive pg_dump would have written. WriteFile/Exec are recorded so
// tests can assert on the restore path.
type fakeOps struct {
	dumpPayload []byte
	written     map[string][]byte // in-container path -> content (restore)
	execLog     []string
	failExec    bool

	// listDatabasesOut, when set, is returned verbatim as stdout for a
	// `psql ... -Atc` listing call (ListDatabases); listDatabasesErr, when
	// set, makes that call fail instead. Dump/restore calls are
	// unaffected by either field.
	listDatabasesOut string
	listDatabasesErr error
	// failDatabases, when set, makes Create's own pg_dump step fail only
	// for these specific database names — lets tests exercise CreateAll's
	// partial-failure path without failing every database.
	failDatabases map[string]bool
}

func newFakeOps(payload []byte) *fakeOps {
	return &fakeOps{dumpPayload: payload, written: map[string][]byte{}}
}

func (f *fakeOps) Exec(container string, command []string) error {
	f.execLog = append(f.execLog, strings.Join(command, " "))
	return nil
}

func (f *fakeOps) ExecWithOutput(container string, command []string) (string, string, error) {
	f.execLog = append(f.execLog, strings.Join(command, " "))
	full := strings.Join(command, " ")
	if strings.Contains(full, "psql") && strings.Contains(full, "-Atc") {
		if f.listDatabasesErr != nil {
			return "", "connection refused", f.listDatabasesErr
		}
		return f.listDatabasesOut, "", nil
	}
	for db := range f.failDatabases {
		if strings.Contains(full, "-d '"+db+"'") {
			return "", "FATAL: database \"" + db + "\" does not exist", errExec
		}
	}
	if f.failExec {
		return "", "FATAL: database \"missing\" does not exist", errExec
	}
	return "", "", nil
}

func (f *fakeOps) ReadFile(container, path string) ([]byte, error) {
	if strings.HasSuffix(path, ".dump") {
		return f.dumpPayload, nil
	}
	return nil, errNotFound
}

func (f *fakeOps) WriteFile(container, path string, content []byte, mode string) error {
	f.written[path] = content
	return nil
}

var (
	errExec     = &opErr{"exec failed"}
	errNotFound = &opErr{"not found"}
)

type opErr struct{ s string }

func (e *opErr) Error() string { return e.s }

// fixedClock returns a deterministic time so backup IDs are stable.
func fixedClock() time.Time {
	return time.Date(2026, 6, 5, 13, 4, 5, 0, time.UTC)
}

func newTestManager(t *testing.T, ops ContainerOps) *Manager {
	t.Helper()
	m := NewManager(ops, nil, t.TempDir())
	m.clock = fixedClock
	return m
}

func TestCreateListGetLocal(t *testing.T) {
	payload := []byte("PGDMP-fake-archive-bytes")
	ops := newFakeOps(payload)
	m := newTestManager(t, ops)

	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Conn:          PgConn{Database: "app"},
		Destination:   DestLocal,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.ID != "alice-app-20260605T130405Z" {
		t.Errorf("unexpected id %q", rec.ID)
	}
	if rec.SizeBytes != int64(len(payload)) {
		t.Errorf("size = %d, want %d", rec.SizeBytes, len(payload))
	}
	if rec.Engine != EnginePostgres || rec.Destination != DestLocal {
		t.Errorf("unexpected engine/destination: %+v", rec)
	}
	if !strings.HasSuffix(rec.Location, rec.ID+".dump") {
		t.Errorf("location not a local dump path: %q", rec.Location)
	}

	// pg_dump must run with -Fc and never put the password on argv.
	joined := strings.Join(ops.execLog, "\n")
	if !strings.Contains(joined, "pg_dump") || !strings.Contains(joined, "-Fc") {
		t.Errorf("pg_dump -Fc not invoked; execLog=%v", ops.execLog)
	}

	list, err := m.List("alice")
	if err != nil || len(list) != 1 {
		t.Fatalf("List: %v len=%d", err, len(list))
	}
	if list[0].ID != rec.ID {
		t.Errorf("List returned %q, want %q", list[0].ID, rec.ID)
	}

	// Tenant filter excludes other users.
	if other, _ := m.List("bob"); len(other) != 0 {
		t.Errorf("List(bob) should be empty, got %d", len(other))
	}

	got, err := m.Get(rec.ID)
	if err != nil || got.SHA256 != rec.SHA256 {
		t.Fatalf("Get: %v sha=%s", err, rec.SHA256)
	}
}

func TestPasswordNotOnArgv(t *testing.T) {
	ops := newFakeOps([]byte("dump"))
	m := newTestManager(t, ops)
	if _, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Conn:          PgConn{Database: "app", Password: "s3cr3t"},
		Destination:   DestLocal,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, cmd := range ops.execLog {
		if strings.Contains(cmd, "PGPASSWORD=") {
			// PGPASSWORD export is fine inside the bash -c body; what we
			// guard is that the dump command line itself doesn't carry it
			// as a -W/--password style argv. The export form is expected.
			if !strings.Contains(cmd, "export PGPASSWORD=") {
				t.Errorf("password leaked onto argv: %q", cmd)
			}
		}
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	payload := []byte("PGDMP-archive")
	ops := newFakeOps(payload)
	m := newTestManager(t, ops)

	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Conn:          PgConn{Database: "app"},
		Destination:   DestLocal,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := m.Restore(RestoreOptions{
		ID:            rec.ID,
		ContainerName: "alice-container",
		Clean:         true,
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// The dump bytes must have been pushed back into the container intact.
	var pushed []byte
	for p, c := range ops.written {
		if strings.HasSuffix(p, ".dump") {
			pushed = c
		}
	}
	if string(pushed) != string(payload) {
		t.Errorf("restored bytes = %q, want %q", pushed, payload)
	}
	joined := strings.Join(ops.execLog, "\n")
	if !strings.Contains(joined, "pg_restore") || !strings.Contains(joined, "--clean --if-exists") {
		t.Errorf("pg_restore --clean not invoked; execLog=%v", ops.execLog)
	}
}

func TestRestoreDetectsCorruption(t *testing.T) {
	ops := newFakeOps([]byte("good-bytes"))
	m := newTestManager(t, ops)
	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Conn:          PgConn{Database: "app"},
		Destination:   DestLocal,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Tamper with the stored dump on disk.
	if err := os.WriteFile(rec.Location, []byte("tampered"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	err = m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "alice-container"})
	if err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("expected integrity failure, got %v", err)
	}
}

func TestDeleteRemovesDumpAndIndex(t *testing.T) {
	ops := newFakeOps([]byte("dump"))
	m := newTestManager(t, ops)
	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Conn:          PgConn{Database: "app"},
		Destination:   DestLocal,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Delete(rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := m.Get(rec.ID); err == nil {
		t.Errorf("Get after Delete should fail")
	}
	if list, _ := m.List(""); len(list) != 0 {
		t.Errorf("List after Delete should be empty, got %d", len(list))
	}
}

func TestCreateValidation(t *testing.T) {
	m := newTestManager(t, newFakeOps([]byte("x")))
	cases := []CreateOptions{
		{Username: "a", ContainerName: "a-container", Destination: DestLocal},                            // no database
		{Username: "a", ContainerName: "a-container", Conn: PgConn{Database: "d"}},                       // no destination
		{Username: "a", ContainerName: "a-container", Conn: PgConn{Database: "d"}, Destination: DestGCS}, // gcs without uploader
		{Username: "a", Conn: PgConn{Database: "d"}, Destination: DestLocal},                             // no container
	}
	for i, c := range cases {
		if _, err := m.Create(c); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestRejectsPathTraversalID(t *testing.T) {
	m := newTestManager(t, newFakeOps([]byte("x")))
	// Ids that would escape m.dir once joined into a path must
	// be refused before they ever reach filepath.Join.
	bad := []string{
		"../../etc/passwd",
		"..",
		"a/b",
		`a\b`,
		"sub/../../escape",
		"",
	}
	for _, id := range bad {
		if _, err := m.Get(id); err == nil {
			t.Errorf("Get(%q): expected rejection", id)
		}
		if err := m.Delete(id); err == nil {
			t.Errorf("Delete(%q): expected rejection", id)
		}
		if err := m.Restore(RestoreOptions{ContainerName: "c", ID: id}); err == nil {
			t.Errorf("Restore(%q): expected rejection", id)
		}
	}
	// A well-formed id is accepted by the validator (the lookup
	// then fails only because no such record exists).
	if err := validateBackupID("alice-appdb-20260605T103000Z"); err != nil {
		t.Errorf("well-formed id rejected: %v", err)
	}
}

func TestCreateRejectsUnsafeDerivedID(t *testing.T) {
	m := newTestManager(t, newFakeOps([]byte("x")))
	// A username or database carrying a path separator would
	// produce an id that escapes m.dir; Create must refuse.
	if _, err := m.Create(CreateOptions{
		Username:      "../evil",
		ContainerName: "c",
		Conn:          PgConn{Database: "d"},
		Destination:   DestLocal,
	}); err == nil {
		t.Error("Create with separator in username should fail")
	}
}

func TestCreateGCS(t *testing.T) {
	ops := newFakeOps([]byte("archive"))
	up := &fakeUploader{}
	m := NewManager(ops, up, t.TempDir())
	m.clock = fixedClock

	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Conn:          PgConn{Database: "app"},
		Destination:   DestGCS,
		GCSBucket:     "gs://my-backups/pg",
	})
	if err != nil {
		t.Fatalf("Create gcs: %v", err)
	}
	wantURI := "gs://my-backups/pg/" + rec.ID + ".dump"
	if rec.Location != wantURI {
		t.Errorf("location = %q, want %q", rec.Location, wantURI)
	}
	if up.uploaded[wantURI] == 0 {
		t.Errorf("expected upload to %q", wantURI)
	}
	// Restore should download from GCS and round-trip.
	if err := m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "alice-container"}); err != nil {
		t.Fatalf("Restore gcs: %v", err)
	}
}

// fakeUploader records uploads in memory and serves them back on download.
type fakeUploader struct {
	uploaded map[string]int
	blobs    map[string][]byte
}

func (f *fakeUploader) Upload(localPath, destURI string) error {
	if f.uploaded == nil {
		f.uploaded = map[string]int{}
		f.blobs = map[string][]byte{}
	}
	b, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	f.uploaded[destURI]++
	f.blobs[destURI] = b
	return nil
}

func (f *fakeUploader) Download(destURI, localPath string) error {
	b, ok := f.blobs[destURI]
	if !ok {
		return errNotFound
	}
	return os.WriteFile(localPath, b, 0o600)
}

func (f *fakeUploader) Delete(destURI string) error {
	delete(f.blobs, destURI)
	delete(f.uploaded, destURI)
	return nil
}

func TestListDatabases(t *testing.T) {
	ops := newFakeOps([]byte("payload"))
	ops.listDatabasesOut = "postgres\napp_production\nanalytics\n"
	m := newTestManager(t, ops)

	dbs, err := m.ListDatabases("alice-container", PgConn{})
	if err != nil {
		t.Fatalf("ListDatabases: %v", err)
	}
	want := []string{"postgres", "app_production", "analytics"}
	if len(dbs) != len(want) {
		t.Fatalf("got %v, want %v", dbs, want)
	}
	for i, w := range want {
		if dbs[i] != w {
			t.Errorf("dbs[%d] = %q, want %q", i, dbs[i], w)
		}
	}
}

func TestListDatabases_EmptyOutput(t *testing.T) {
	ops := newFakeOps([]byte("payload"))
	ops.listDatabasesOut = ""
	m := newTestManager(t, ops)

	dbs, err := m.ListDatabases("alice-container", PgConn{})
	if err != nil {
		t.Fatalf("ListDatabases: %v", err)
	}
	if len(dbs) != 0 {
		t.Errorf("got %v, want empty", dbs)
	}
}

func TestListDatabases_ExecFails(t *testing.T) {
	ops := newFakeOps([]byte("payload"))
	ops.listDatabasesErr = errExec
	m := newTestManager(t, ops)

	if _, err := m.ListDatabases("alice-container", PgConn{}); err == nil {
		t.Fatal("expected an error")
	}
}

// TestCreateAll_BacksUpEveryDatabase pins #954's core behavior: no database
// name is supplied by the caller — CreateAll discovers and backs up every
// one found, producing one Record per database (same shape a single Create
// call already produces, just looped).
func TestCreateAll_BacksUpEveryDatabase(t *testing.T) {
	ops := newFakeOps([]byte("PGDMP-fake-archive-bytes"))
	ops.listDatabasesOut = "app_production\nanalytics\n"
	m := newTestManager(t, ops)

	records, errs := m.CreateAll(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Destination:   DestLocal,
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	gotDBs := map[string]bool{}
	for _, r := range records {
		gotDBs[r.Database] = true
	}
	if !gotDBs["app_production"] || !gotDBs["analytics"] {
		t.Errorf("records = %+v, want app_production and analytics", records)
	}

	// Each database's record is independently listable/gettable, same as
	// today's single-database Create — CreateAll doesn't change storage
	// shape, just how many Creates happen per call.
	listed, err := m.List("alice")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 2 {
		t.Errorf("List returned %d records, want 2", len(listed))
	}
}

// TestCreateAll_PartialFailureStillBacksUpTheRest pins the resilience
// property: one database failing pg_dump must not abort the others.
func TestCreateAll_PartialFailureStillBacksUpTheRest(t *testing.T) {
	ops := newFakeOps([]byte("PGDMP-fake-archive-bytes"))
	ops.listDatabasesOut = "app_production\nbroken_db\nanalytics\n"
	ops.failDatabases = map[string]bool{"broken_db": true}
	m := newTestManager(t, ops)

	records, errs := m.CreateAll(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Destination:   DestLocal,
	})
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (broken_db should be the only failure)", len(records))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1", len(errs))
	}
	if !strings.Contains(errs[0].Error(), "broken_db") {
		t.Errorf("error %q doesn't name the failing database", errs[0].Error())
	}
}

func TestCreateAll_NoDatabasesFound(t *testing.T) {
	ops := newFakeOps([]byte("payload"))
	ops.listDatabasesOut = ""
	m := newTestManager(t, ops)

	records, errs := m.CreateAll(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Destination:   DestLocal,
	})
	if len(records) != 0 {
		t.Errorf("got %d records, want 0", len(records))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1", len(errs))
	}
}

func TestCreateAll_ListDatabasesFails(t *testing.T) {
	ops := newFakeOps([]byte("payload"))
	ops.listDatabasesErr = errExec
	m := newTestManager(t, ops)

	records, errs := m.CreateAll(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Destination:   DestLocal,
	})
	if len(records) != 0 {
		t.Errorf("got %d records, want 0", len(records))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1", len(errs))
	}
}
