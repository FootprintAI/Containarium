package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/backup"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2405: the wire enum and the core's typed format map one-to-one, and an
// unset request format means opaque (today's behaviour), never pg_custom.
func TestHookFormatFromProto(t *testing.T) {
	for _, tc := range []struct {
		in      pb.HookFormat
		want    backup.HookFormat
		wantErr bool
	}{
		{pb.HookFormat_HOOK_FORMAT_UNSPECIFIED, "", false},
		{pb.HookFormat_HOOK_FORMAT_OPAQUE, backup.HookFormatOpaque, false},
		{pb.HookFormat_HOOK_FORMAT_PG_CUSTOM, backup.HookFormatPGCustom, false},
		{pb.HookFormat(99), "", true},
	} {
		t.Run(tc.in.String(), func(t *testing.T) {
			got, err := hookFormatFromProto(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("hookFormatFromProto(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRecordToProto_CarriesHookFormat(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  *backup.Record
		want pb.HookFormat
	}{
		{"pg_custom hook", &backup.Record{Engine: backup.EngineHook, HookFormat: backup.HookFormatPGCustom}, pb.HookFormat_HOOK_FORMAT_PG_CUSTOM},
		{"opaque hook", &backup.Record{Engine: backup.EngineHook, HookFormat: backup.HookFormatOpaque}, pb.HookFormat_HOOK_FORMAT_OPAQUE},
		{"pg_dump record", &backup.Record{Engine: backup.EnginePostgres}, pb.HookFormat_HOOK_FORMAT_UNSPECIFIED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := recordToProto(tc.rec).HookFormat; got != tc.want {
				t.Errorf("HookFormat = %v, want %v", got, tc.want)
			}
		})
	}
}
