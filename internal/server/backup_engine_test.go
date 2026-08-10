package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/backup"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #1157: engine was a string on the wire, so "postgres", "postgress" and ""
// were all equally valid values of the contract and only a driver lookup at
// dump time could tell them apart. The manifest still stores a string, so
// this boundary is where an unrecognised one has to be caught.
func TestEngineToProto(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stored string
		want   pb.BackupEngine
	}{
		{"the engine we support", backup.EnginePostgres, pb.BackupEngine_BACKUP_ENGINE_POSTGRES},
		{"a record predating the enum", "", pb.BackupEngine_BACKUP_ENGINE_UNSPECIFIED},
		{"an engine this build does not know", "mongodb", pb.BackupEngine_BACKUP_ENGINE_UNSPECIFIED},
		{"a near miss", "postgress", pb.BackupEngine_BACKUP_ENGINE_UNSPECIFIED},
		{"differing case is not the same value", "Postgres", pb.BackupEngine_BACKUP_ENGINE_UNSPECIFIED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := engineToProto(tc.stored); got != tc.want {
				t.Errorf("engineToProto(%q) = %v, want %v", tc.stored, got, tc.want)
			}
		})
	}
}

// The failure the enum exists to make impossible: an engine nobody recognises
// must never present itself as Postgres. A caller reading POSTGRES will hand
// the dump to pg_restore.
func TestEngineToProto_NeverGuessesPostgres(t *testing.T) {
	for _, stored := range []string{"", "mongodb", "mysql", "unknown", "POSTGRES", " postgres"} {
		if got := engineToProto(stored); got == pb.BackupEngine_BACKUP_ENGINE_POSTGRES {
			t.Errorf("engineToProto(%q) reported POSTGRES — a caller would hand this dump to "+
				"pg_restore on the strength of a guess", stored)
		}
	}
}

// The constant the manifest writes and the case this maps must not drift
// apart: if EnginePostgres changed, every existing record would start
// reading as UNSPECIFIED and nothing else would notice.
func TestEngineToProto_MatchesWhatTheManifestWrites(t *testing.T) {
	if engineToProto(backup.EnginePostgres) != pb.BackupEngine_BACKUP_ENGINE_POSTGRES {
		t.Fatalf("the mapping does not recognise backup.EnginePostgres (%q) — every record "+
			"written by this daemon would read as UNSPECIFIED", backup.EnginePostgres)
	}
}
