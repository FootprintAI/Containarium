package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/backup"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #1831: a hook dump is an opaque stream. It gets its own enum value so a
// reader can tell it from Postgres (never pg_restore it) and from a record
// this build does not understand.
func TestEngineToProto_Hook(t *testing.T) {
	if got := engineToProto(backup.EngineHook); got != pb.BackupEngine_BACKUP_ENGINE_HOOK {
		t.Errorf("engineToProto(%q) = %v, want BACKUP_ENGINE_HOOK", backup.EngineHook, got)
	}
}

// The wire record must carry the #1831 facts a caller needs: that the
// stored bytes are ciphertext (and to which public recipient), and which
// in-tenant hook produced an opaque dump.
func TestRecordToProto_CarriesHookAndEncryptionFields(t *testing.T) {
	r := &backup.Record{
		ID: "alice-db-dump-20260913T000000Z", Username: "alice", Database: "db-dump",
		Engine: backup.EngineHook, Hook: "/opt/backup/db-dump.sh",
		Encrypted: true, AgeRecipient: "age1examplerecipient",
	}
	got := recordToProto(r)
	if got.Engine != pb.BackupEngine_BACKUP_ENGINE_HOOK {
		t.Errorf("engine = %v, want HOOK", got.Engine)
	}
	if got.Hook != r.Hook {
		t.Errorf("hook = %q, want %q", got.Hook, r.Hook)
	}
	if !got.Encrypted || got.AgeRecipient != r.AgeRecipient {
		t.Errorf("encrypted/recipient = %v/%q, want true/%q", got.Encrypted, got.AgeRecipient, r.AgeRecipient)
	}
	plain := recordToProto(&backup.Record{ID: "x", Engine: backup.EnginePostgres})
	if plain.Encrypted || plain.AgeRecipient != "" || plain.Hook != "" {
		t.Errorf("plaintext pg_dump record grew #1831 fields: %+v", plain)
	}
}

// An empty database means "back up every database" (#954) — but only on
// the pg_dump path. A hook backup names no database at all, and must run
// exactly once, not once per database the daemon happens to find.
func TestBackupAllRequested(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *pb.CreateBackupRequest
		want bool
	}{
		{"no database, no hook → all", &pb.CreateBackupRequest{Connection: &pb.PgConnection{}}, true},
		{"nil connection, no hook → all", &pb.CreateBackupRequest{}, true},
		{"explicit database → single", &pb.CreateBackupRequest{Connection: &pb.PgConnection{Database: "app"}}, false},
		{"hook, no database → single", &pb.CreateBackupRequest{Hook: "/opt/dump.sh"}, false},
		{"hook and database → single (hook wins)", &pb.CreateBackupRequest{Hook: "/opt/dump.sh", Connection: &pb.PgConnection{Database: "app"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := backupAllRequested(tc.req); got != tc.want {
				t.Errorf("backupAllRequested = %v, want %v", got, tc.want)
			}
		})
	}
}
