package cmd

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2405: --hook-format is a thin wrapper that lands the typed enum on the
// request; the daemon decides what it means.
func TestBackupCreate_HookFormatFlagReachesRequest(t *testing.T) {
	for _, tc := range []struct {
		flag string
		want pb.HookFormat
	}{
		{"", pb.HookFormat_HOOK_FORMAT_UNSPECIFIED},
		{"opaque", pb.HookFormat_HOOK_FORMAT_OPAQUE},
		{"pg_custom", pb.HookFormat_HOOK_FORMAT_PG_CUSTOM},
	} {
		t.Run("flag="+tc.flag, func(t *testing.T) {
			f := withRecordingBackupClient(t)
			resetBackupCreateFlags(t)
			backupCreateHook = "/opt/backup/db-dump.sh"
			backupCreateHookFormat = tc.flag

			if err := runBackupCreate(backupCreateCmd, []string{"alice"}); err != nil {
				t.Fatalf("runBackupCreate: %v", err)
			}
			if f.gotCreate == nil {
				t.Fatal("CreateBackup was not called")
			}
			if f.gotCreate.HookFormat != tc.want {
				t.Errorf("HookFormat = %v, want %v", f.gotCreate.HookFormat, tc.want)
			}
		})
	}
}

func TestBackupCreate_InvalidHookFormatIsAnErrorBeforeAnyCall(t *testing.T) {
	f := withRecordingBackupClient(t)
	resetBackupCreateFlags(t)
	backupCreateHook = "/opt/backup/db-dump.sh"
	backupCreateHookFormat = "plain_sql"

	err := runBackupCreate(backupCreateCmd, []string{"alice"})
	if err == nil || !strings.Contains(err.Error(), "--hook-format") {
		t.Fatalf("err = %v, want one naming --hook-format", err)
	}
	if f.gotCreate != nil {
		t.Error("create must not be attempted with an invalid --hook-format")
	}
}
