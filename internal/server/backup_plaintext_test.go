package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/backup"
)

// #3169: only a record with no key at all counts as stored in plaintext.
func TestBackupStoredPlaintext(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  backup.Record
		want bool
	}{
		{"no key", backup.Record{}, true},
		{"age", backup.Record{Encrypted: true, AgeRecipient: "age1x"}, false},
		{"managed", backup.Record{KeyMode: backup.KeyModeManaged}, false},
		{"both", backup.Record{Encrypted: true, KeyMode: backup.KeyModeBoth}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := backupStoredPlaintext(&tc.rec); got != tc.want {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}
}
