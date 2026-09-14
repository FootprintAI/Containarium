package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

func newLocalManager(t *testing.T, ops *fakeOps) *Manager {
	t.Helper()
	return NewManager(ops, nil, t.TempDir())
}

func execLogHas(ops *fakeOps, needle string) bool {
	for _, e := range ops.execLog {
		if strings.Contains(e, needle) {
			return true
		}
	}
	return false
}

// --- hook mode (#1831 part A: credential-less in-tenant dump) ---

func TestCreate_HookMode_RunsHookNotPgDump(t *testing.T) {
	payload := []byte("opaque-dump-bytes")
	ops := newFakeOps(payload)
	m := newLocalManager(t, ops)

	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Hook:          "/opt/backup/db-dump.sh",
		Destination:   DestLocal,
	})
	if err != nil {
		t.Fatalf("Create (hook): %v", err)
	}

	if rec.Engine != EngineHook {
		t.Errorf("engine = %q, want %q", rec.Engine, EngineHook)
	}
	if rec.Hook != "/opt/backup/db-dump.sh" {
		t.Errorf("record.Hook = %q", rec.Hook)
	}
	if rec.Database != "db-dump" {
		t.Errorf("database label = %q, want hook basename db-dump", rec.Database)
	}
	if rec.RelationCount != nil {
		t.Error("hook backup must not record a Postgres relation manifest")
	}
	// The hook ran (single-quoted, stdout redirected to the staging path)…
	if !execLogHas(ops, "'/opt/backup/db-dump.sh' > '/tmp/containarium-backup-") {
		t.Errorf("hook was not invoked with stdout redirected; exec log: %v", ops.execLog)
	}
	// …and pg_dump / the catalog manifest query never did — no credential path.
	if execLogHas(ops, "pg_dump") || execLogHas(ops, "pg_class") {
		t.Errorf("hook mode must not run pg_dump or the manifest query; exec log: %v", ops.execLog)
	}
	// The stored bytes are the hook's stdout, verbatim.
	got, err := os.ReadFile(rec.Location)
	if err != nil {
		t.Fatalf("read stored dump: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("stored bytes differ from hook output")
	}
}

func TestCreate_HookMode_RejectsBadHooks(t *testing.T) {
	m := newLocalManager(t, newFakeOps([]byte("x")))
	for _, bad := range []string{"relative/path.sh", "/opt/dump.sh --all", "  "} {
		_, err := m.Create(CreateOptions{Username: "alice", ContainerName: "c", Hook: bad, Destination: DestLocal})
		if err == nil {
			t.Errorf("hook %q should be refused", bad)
		}
	}
}

func TestCreate_HookMode_EmptyOutputIsAnError(t *testing.T) {
	m := newLocalManager(t, newFakeOps(nil))
	_, err := m.Create(CreateOptions{Username: "alice", ContainerName: "c", Hook: "/opt/dump.sh", Destination: DestLocal})
	if err == nil || !strings.Contains(err.Error(), "produced no output") {
		t.Errorf("expected empty-output error, got %v", err)
	}
}

func TestHookLabel(t *testing.T) {
	cases := map[string]string{
		"/opt/backup/db-dump.sh":   "db-dump",
		"/usr/local/bin/pgdump":    "pgdump",
		"/opt/x/weird name!.py":    "weird-name-",
		"/opt/.hidden":             "hook",
		"/opt/backup/a.b.c.tar.gz": "a",
	}
	for in, want := range cases {
		if got := hookLabel(in); got != want {
			t.Errorf("hookLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- encryption (#1831 part B: user-held key, ciphertext-only at rest) ---

func TestCreate_Encrypt_StoresCiphertextOnly(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("PGDMP\x00plaintext-archive-bytes")
	m := newLocalManager(t, newFakeOps(payload))

	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Conn:          PgConn{Database: "app"},
		Destination:   DestLocal,
		AgeRecipient:  id.Recipient().String(),
	})
	if err != nil {
		t.Fatalf("Create (encrypted): %v", err)
	}
	if !rec.Encrypted {
		t.Fatal("record.Encrypted should be true")
	}
	if rec.AgeRecipient != id.Recipient().String() {
		t.Errorf("record.AgeRecipient = %q", rec.AgeRecipient)
	}
	if !strings.HasSuffix(rec.Location, ".dump.age") {
		t.Errorf("location should end in .dump.age, got %s", rec.Location)
	}

	stored, err := os.ReadFile(rec.Location)
	if err != nil {
		t.Fatalf("read stored: %v", err)
	}
	// The store never sees plaintext.
	if bytes.Contains(stored, []byte("plaintext-archive-bytes")) {
		t.Fatal("plaintext leaked into the stored object")
	}
	if !bytes.HasPrefix(stored, []byte("age-encryption.org/")) {
		t.Errorf("stored object is not an age ciphertext (prefix %q)", stored[:min(20, len(stored))])
	}
	// Size + checksum describe the ciphertext, so the integrity gate applies to what is stored.
	if rec.SizeBytes != int64(len(stored)) {
		t.Errorf("SizeBytes = %d, want ciphertext len %d", rec.SizeBytes, len(stored))
	}
	sum := sha256.Sum256(stored)
	if rec.SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("SHA256 must be over the stored ciphertext")
	}
	// Only the identity holder can get the plaintext back.
	pt, err := decryptWithIdentity(stored, id.String())
	if err != nil {
		t.Fatalf("decrypt with the right identity: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Error("decrypted bytes differ from the original dump")
	}
}

func TestCreate_InvalidRecipientRefused(t *testing.T) {
	m := newLocalManager(t, newFakeOps([]byte("x")))
	_, err := m.Create(CreateOptions{
		Username: "alice", ContainerName: "c", Conn: PgConn{Database: "app"},
		Destination: DestLocal, AgeRecipient: "not-an-age-key",
	})
	if err == nil || !strings.Contains(err.Error(), "age recipient") {
		t.Errorf("expected invalid-recipient error, got %v", err)
	}
	// Refused before any dump ran.
	if execLogHas(m.ops.(*fakeOps), "pg_dump") {
		t.Error("an invalid recipient must be rejected before running pg_dump")
	}
}

func TestRestore_Encrypted_RequiresIdentityThenDecrypts(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	payload := []byte("PGDMP\x00archive")
	ops := newFakeOps(payload)
	m := newLocalManager(t, ops)

	rec, err := m.Create(CreateOptions{
		Username: "alice", ContainerName: "alice-container",
		Conn: PgConn{Database: "app"}, Destination: DestLocal,
		AgeRecipient: id.Recipient().String(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Without the identity the platform cannot proceed — it holds no key.
	err = m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "alice-container"})
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("expected encrypted/identity-required error, got %v", err)
	}
	if execLogHas(ops, "pg_restore") {
		t.Fatal("pg_restore must not run without a decryption identity")
	}

	// With it, the PLAINTEXT is what gets pushed into the container and restored.
	if err := m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "alice-container", AgeIdentity: id.String()}); err != nil {
		t.Fatalf("Restore with identity: %v", err)
	}
	var pushed []byte
	for p, b := range ops.written {
		if strings.Contains(p, "containarium-restore-") {
			pushed = b
		}
	}
	if !bytes.Equal(pushed, payload) {
		t.Errorf("container received %q, want the decrypted plaintext", pushed)
	}
	if !execLogHas(ops, "pg_restore") {
		t.Error("pg_restore should have run after decryption")
	}
}

func TestRestore_Encrypted_WrongIdentityFails(t *testing.T) {
	right, _ := age.GenerateX25519Identity()
	wrong, _ := age.GenerateX25519Identity()
	ops := newFakeOps([]byte("PGDMP\x00archive"))
	m := newLocalManager(t, ops)
	rec, err := m.Create(CreateOptions{
		Username: "alice", ContainerName: "c", Conn: PgConn{Database: "app"},
		Destination: DestLocal, AgeRecipient: right.Recipient().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "c", AgeIdentity: wrong.String()})
	if err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("expected decrypt failure with the wrong identity, got %v", err)
	}
	if execLogHas(ops, "pg_restore") {
		t.Error("pg_restore must not run when decryption fails")
	}
}

func TestRestore_HookRecordIsRefused(t *testing.T) {
	ops := newFakeOps([]byte("opaque"))
	m := newLocalManager(t, ops)
	rec, err := m.Create(CreateOptions{Username: "alice", ContainerName: "c", Hook: "/opt/dump.sh", Destination: DestLocal})
	if err != nil {
		t.Fatal(err)
	}
	err = m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "c"})
	if err == nil || !strings.Contains(err.Error(), "opaque") {
		t.Errorf("hook backup restore should be refused with an explanatory error, got %v", err)
	}
	if execLogHas(ops, "pg_restore") {
		t.Error("pg_restore must never run for a hook backup")
	}
}

// Both features compose: a hook-produced stream, encrypted to a user key.
func TestCreate_HookAndEncrypt_Compose(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	payload := []byte("mysqldump-or-anything")
	m := newLocalManager(t, newFakeOps(payload))
	rec, err := m.Create(CreateOptions{
		Username: "alice", ContainerName: "c", Hook: "/opt/dump.sh",
		Destination: DestLocal, AgeRecipient: id.Recipient().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Engine != EngineHook || !rec.Encrypted {
		t.Fatalf("want hook+encrypted record, got engine=%q encrypted=%v", rec.Engine, rec.Encrypted)
	}
	stored, _ := os.ReadFile(rec.Location)
	pt, err := decryptWithIdentity(stored, id.String())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, payload) {
		t.Error("hook+encrypt round-trip mismatch")
	}
}

// Plaintext backups are byte-for-byte unchanged by this feature (no regression).
func TestCreate_PlaintextUnchanged(t *testing.T) {
	payload := []byte("PGDMP\x00archive")
	m := newLocalManager(t, newFakeOps(payload))
	rec, err := m.Create(CreateOptions{Username: "alice", ContainerName: "c", Conn: PgConn{Database: "app"}, Destination: DestLocal})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Encrypted || rec.AgeRecipient != "" || rec.Hook != "" || rec.Engine != EnginePostgres {
		t.Errorf("plaintext pg_dump record changed shape: %+v", rec)
	}
	if !strings.HasSuffix(rec.Location, ".dump") || strings.HasSuffix(rec.Location, ".dump.age") {
		t.Errorf("plaintext location should end in .dump, got %s", rec.Location)
	}
	got, _ := os.ReadFile(rec.Location)
	if !bytes.Equal(got, payload) {
		t.Error("plaintext stored bytes changed")
	}
}

// Verify (restore-test) only understands pg_dump archives it can read. A
// hook dump is opaque and an encrypted dump is ciphertext the platform
// cannot open, so both must be refused up front — before a scratch
// database is created in the target — rather than recorded as a FAILED
// verification that looks like a corrupt backup.
func TestVerify_RefusesHookAndEncryptedRecords(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	for _, tc := range []struct {
		name string
		opts CreateOptions
		want string
	}{
		{"hook record", CreateOptions{Hook: "/opt/dump.sh"}, "opaque"},
		{"encrypted record", CreateOptions{Conn: PgConn{Database: "app"}, AgeRecipient: id.Recipient().String()}, "encrypted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := newFakeOps([]byte("PGDMP\x00archive"))
			m := newLocalManager(t, ops)
			o := tc.opts
			o.Username, o.ContainerName, o.Destination = "alice", "alice-container", DestLocal
			rec, err := m.Create(o)
			if err != nil {
				t.Fatal(err)
			}
			_, err = m.Verify(VerifyOptions{ID: rec.ID, TargetContainer: "scratch", SourceContainer: "alice-container"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected verify to refuse with %q, got %v", tc.want, err)
			}
			if execLogHas(ops, "CREATE DATABASE") || execLogHas(ops, "pg_restore") {
				t.Errorf("verify must refuse before touching the target; exec log: %v", ops.execLog)
			}
			got, _ := m.Get(rec.ID)
			if got.LastVerification != nil {
				t.Error("a refused verification must not be recorded as an outcome on the backup")
			}
		})
	}
}
