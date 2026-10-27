package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/footprintai/containarium/pkg/core/backup"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- #2800: the whole-box scope at the server boundary ---

// testBoxRecipient is a syntactically ordinary age recipient. The BOX
// path refuses before any encryption happens, so it is never parsed.
const testBoxRecipient = "age1boxscopetestrecipient"

// boxRequest is a BOX request that passes every #2800 check: a tenant with
// an existing box, a destination, an explicit key mode and no database
// connection. Each test case breaks exactly one thing.
func boxRequest() *pb.CreateBackupRequest {
	return &pb.CreateBackupRequest{
		Username:     "alice",
		Scope:        pb.BackupScope_BACKUP_SCOPE_BOX,
		Destination:  pb.BackupDestination_BACKUP_DESTINATION_LOCAL,
		AgeRecipient: testBoxRecipient,
		KeyMode:      pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT,
	}
}

// A BOX request is refused before any container is touched when it
// carries database-backup fields, or when it names no encryption mode:
// plaintext is forbidden for BOX scope (decision of 2026-10-25 on #2800).
func TestCreateBackup_BoxScopeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*pb.CreateBackupRequest)
		code    codes.Code
		wantMsg string
	}{
		{
			name:    "a database connection is refused",
			mutate:  func(r *pb.CreateBackupRequest) { r.Connection = &pb.PgConnection{Database: "app"} },
			code:    codes.InvalidArgument,
			wantMsg: "connection",
		},
		{
			name:    "an empty database connection is still a connection",
			mutate:  func(r *pb.CreateBackupRequest) { r.Connection = &pb.PgConnection{} },
			code:    codes.InvalidArgument,
			wantMsg: "connection",
		},
		{
			name:    "a hook is refused",
			mutate:  func(r *pb.CreateBackupRequest) { r.Hook = "/usr/local/bin/dump" },
			code:    codes.InvalidArgument,
			wantMsg: "hook",
		},
		{
			name:    "a hook format is refused",
			mutate:  func(r *pb.CreateBackupRequest) { r.HookFormat = pb.HookFormat_HOOK_FORMAT_PG_CUSTOM },
			code:    codes.InvalidArgument,
			wantMsg: "hook",
		},
		{
			name: "no encryption mode is refused (plaintext is forbidden)",
			mutate: func(r *pb.CreateBackupRequest) {
				r.KeyMode = pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED
				r.AgeRecipient = ""
			},
			code:    codes.InvalidArgument,
			wantMsg: "key_mode",
		},
		{
			// A resolvable recipient would make the database default
			// AGE_RECIPIENT; BOX still wants the mode named, not inferred.
			name:    "no encryption mode is refused even with a recipient",
			mutate:  func(r *pb.CreateBackupRequest) { r.KeyMode = pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED },
			code:    codes.InvalidArgument,
			wantMsg: "key_mode",
		},
		{
			name:   "an explicit recipient mode without a recipient is refused",
			mutate: func(r *pb.CreateBackupRequest) { r.AgeRecipient = "" },
			code:   codes.InvalidArgument,
		},
		{
			name:   "managed mode on a daemon with no key wrapper is refused",
			mutate: func(r *pb.CreateBackupRequest) { r.KeyMode = pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED },
			code:   codes.FailedPrecondition,
		},
		{
			name:   "no destination is refused",
			mutate: func(r *pb.CreateBackupRequest) { r.Destination = pb.BackupDestination_BACKUP_DESTINATION_UNSPECIFIED },
			code:   codes.InvalidArgument,
		},
		{
			name:   "an unknown scope value is refused",
			mutate: func(r *pb.CreateBackupRequest) { r.Scope = pb.BackupScope(99) },
			code:   codes.InvalidArgument,
		},
		{
			name:   "a box that does not exist is not found",
			mutate: func(r *pb.CreateBackupRequest) { r.Username = "ghost" },
			code:   codes.NotFound,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearBackupKMSEnv(t)
			s, ops, _ := newRestoreTargetServer(t)
			req := boxRequest()
			tc.mutate(req)
			_, err := s.CreateBackup(restoreCtx("ops", true), req)
			if status.Code(err) != tc.code {
				t.Fatalf("err = %v, want code %v", err, tc.code)
			}
			if tc.wantMsg != "" && !strings.Contains(status.Convert(err).Message(), tc.wantMsg) {
				t.Errorf("message %q does not name %q", status.Convert(err).Message(), tc.wantMsg)
			}
			if len(ops.touched) != 0 {
				t.Errorf("containers touched before the refusal: %v", ops.touched)
			}
		})
	}
}

// A well-formed BOX request clears validation and runs the whole-box data
// path (#2801): the record says BOX, and no command runs inside the box (the
// export goes through Incus, not through exec). Every encryption mode the
// daemon can honour is accepted.
func TestCreateBackup_BoxScopeCreatesARecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*pb.CreateBackupRequest)
	}{
		{"age recipient", func(*pb.CreateBackupRequest) {}},
		{"gcs destination", func(r *pb.CreateBackupRequest) {
			r.Destination = pb.BackupDestination_BACKUP_DESTINATION_GCS
			r.GcsBucket = "gs://example-bucket/boxes"
		}},
		// A label is ignored without a hook, as for a database backup.
		{"label is ignored", func(r *pb.CreateBackupRequest) { r.Label = "nightly" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearBackupKMSEnv(t)
			s, ops, box := newBoxServer(t)
			req := boxRequest()
			req.AgeRecipient = testBoxRealRecipient(t)
			tc.mutate(req)
			resp, err := s.CreateBackup(restoreCtx("ops", true), req)
			if err != nil {
				t.Fatalf("CreateBackup: %v", err)
			}
			if len(resp.Records) != 1 || resp.Record == nil || resp.Record.Id != resp.Records[0].Id {
				t.Fatalf("response = %+v, want one record in both shapes", resp)
			}
			r := resp.Record
			if r.Scope != pb.BackupScope_BACKUP_SCOPE_BOX || r.Engine != pb.BackupEngine_BACKUP_ENGINE_BOX {
				t.Errorf("record scope %v engine %v, want BOX/BOX", r.Scope, r.Engine)
			}
			if !r.Encrypted || r.KeyMode != pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT || r.Database != "alice-container" {
				t.Errorf("record = %+v", r)
			}
			if !strings.Contains(resp.Message, r.Id) {
				t.Errorf("message %q does not name the backup", resp.Message)
			}
			if strings.Join(box.exported, ",") != "alice-container" {
				t.Errorf("exported %v, want alice-container", box.exported)
			}
			if len(ops.touched) != 0 {
				t.Errorf("BOX create ran container commands: %v", ops.touched)
			}
		})
	}
}

// A daemon whose backup core has no Incus export cannot take a BOX backup,
// and says so as a precondition, not an internal error.
func TestCreateBackup_BoxScopeWithoutExportIsFailedPrecondition(t *testing.T) {
	clearBackupKMSEnv(t)
	s, _, _ := newRestoreTargetServer(t)
	req := boxRequest()
	req.AgeRecipient = testBoxRealRecipient(t)
	_, err := s.CreateBackup(restoreCtx("ops", true), req)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

func TestBoxCreateStatus(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want codes.Code
	}{
		{fmt.Errorf("wrapped: %w", backup.ErrInsufficientSpace), codes.ResourceExhausted},
		{fmt.Errorf("wrapped: %w", backup.ErrDumpTooLarge), codes.ResourceExhausted},
		{fmt.Errorf("wrapped: %w", backup.ErrBoxUnavailable), codes.FailedPrecondition},
		{errors.New("export alice-container: connection reset"), codes.Internal},
	} {
		if got := status.Code(boxCreateStatus(tc.err)); got != tc.want {
			t.Errorf("boxCreateStatus(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// The BOX cap and the Incus staging dir come from the daemon's environment;
// a cap that does not parse stops the daemon rather than being ignored.
func TestBoxBackupOptionsFromEnv(t *testing.T) {
	for _, tc := range []struct {
		maxBytes, incusDir string
		wantErr            bool
	}{
		{"", "", false},
		{"1073741824", "/srv/incus/backups", false},
		{"lots", "", true},
		{"0", "", true},
		{"-5", "", true},
	} {
		t.Setenv(envBackupBoxMaxBytes, tc.maxBytes)
		t.Setenv(envIncusBackupsDir, tc.incusDir)
		_, err := boxBackupOptionsFromEnv(nil)
		if (err != nil) != tc.wantErr {
			t.Errorf("max=%q dir=%q: err = %v, wantErr %v", tc.maxBytes, tc.incusDir, err, tc.wantErr)
		}
	}
}

// The tenant check keys on username for BOX exactly as for a database
// backup: a tenant cannot back up another tenant's box.
func TestCreateBackup_BoxScopeAuthorizesTenant(t *testing.T) {
	clearBackupKMSEnv(t)
	s, ops, _ := newRestoreTargetServer(t)
	req := boxRequest()
	req.Username = "scratch"
	_, err := s.CreateBackup(restoreCtx("alice", false), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if len(ops.touched) != 0 {
		t.Errorf("containers touched: %v", ops.touched)
	}
}

// An unset scope is a database backup: the same request with scope
// UNSPECIFIED and with scope DATABASE gets the same answer, and neither
// is held to BOX's rules (a connection and plaintext are both allowed).
func TestCreateBackup_UnsetScopeIsDatabase(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  func() *pb.CreateBackupRequest
	}{
		{"plaintext, all databases", func() *pb.CreateBackupRequest {
			return &pb.CreateBackupRequest{Username: "alice", Destination: pb.BackupDestination_BACKUP_DESTINATION_LOCAL}
		}},
		{"plaintext, one named database", func() *pb.CreateBackupRequest {
			return &pb.CreateBackupRequest{Username: "alice", Destination: pb.BackupDestination_BACKUP_DESTINATION_LOCAL,
				Connection: &pb.PgConnection{Database: "app"}}
		}},
		{"hook", func() *pb.CreateBackupRequest {
			return &pb.CreateBackupRequest{Username: "alice", Destination: pb.BackupDestination_BACKUP_DESTINATION_LOCAL,
				Hook: "/usr/local/bin/dump"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outcome := func(scope pb.BackupScope) (codes.Code, string, map[string]int) {
				clearBackupKMSEnv(t)
				s, ops, _ := newRestoreTargetServer(t)
				req := tc.req()
				req.Scope = scope
				_, err := s.CreateBackup(restoreCtx("ops", true), req)
				return status.Code(err), status.Convert(err).Message(), ops.touched
			}
			unsetCode, unsetMsg, unsetTouched := outcome(pb.BackupScope_BACKUP_SCOPE_UNSPECIFIED)
			dbCode, dbMsg, dbTouched := outcome(pb.BackupScope_BACKUP_SCOPE_DATABASE)
			if unsetCode != dbCode {
				t.Fatalf("unset scope: %v, DATABASE: %v — must be identical", unsetCode, dbCode)
			}
			// Both runs fail the same way against the fake container
			// (it produces no pg_dump output), so the text must match.
			if unsetMsg != dbMsg {
				t.Errorf("unset scope message %q, DATABASE message %q", unsetMsg, dbMsg)
			}
			for _, c := range []codes.Code{codes.InvalidArgument, codes.Unimplemented} {
				if unsetCode == c {
					t.Errorf("a database backup was held to BOX rules: %v %q", unsetCode, unsetMsg)
				}
			}
			if unsetTouched["alice-container"] == 0 || dbTouched["alice-container"] == 0 {
				t.Errorf("the database path never reached the container: unset=%v database=%v", unsetTouched, dbTouched)
			}
		})
	}
}

// Every record the daemon returns says what it captured. A database
// record — including one written before the field existed — reads DATABASE.
func TestRecordToProto_BoxRecordIsBox(t *testing.T) {
	got := recordToProto(&backup.Record{ID: "alice-box-1", Engine: backup.EngineBox})
	if got.Scope != pb.BackupScope_BACKUP_SCOPE_BOX || got.Engine != pb.BackupEngine_BACKUP_ENGINE_BOX {
		t.Errorf("box record maps to scope %v engine %v", got.Scope, got.Engine)
	}
}

func TestRecordToProto_ScopeIsDatabase(t *testing.T) {
	for _, r := range []backup.Record{
		{ID: "pg", Engine: backup.EnginePostgres},
		{ID: "hook", Engine: backup.EngineHook, Hook: "/usr/local/bin/dump"},
		{ID: "legacy"},
	} {
		if got := recordToProto(&r).GetScope(); got != pb.BackupScope_BACKUP_SCOPE_DATABASE {
			t.Errorf("record %s: scope = %v, want DATABASE", r.ID, got)
		}
	}
}

// --- #2800: the contract change is additive ---

// fieldNumbers lists a message's fields as name -> number.
func fieldNumbers(md protoreflect.MessageDescriptor) map[string]protoreflect.FieldNumber {
	out := map[string]protoreflect.FieldNumber{}
	for i := 0; i < md.Fields().Len(); i++ {
		f := md.Fields().Get(i)
		out[string(f.Name())] = f.Number()
	}
	return out
}

// Golden field numbers. Every field that existed before #2800 keeps its
// name and number, and the new fields take fresh numbers. A renumbering
// or rename is a wire break for every stored record and old client.
func TestBackupScope_FieldNumbersAreAdditive(t *testing.T) {
	for _, tc := range []struct {
		msg  proto.Message
		want map[string]protoreflect.FieldNumber
	}{
		{&pb.CreateBackupRequest{}, map[string]protoreflect.FieldNumber{
			"username": 1, "connection": 2, "destination": 3, "gcs_bucket": 4,
			"hook": 5, "label": 6, "age_recipient": 7, "key_mode": 8, "hook_format": 9,
			"scope": 10, // #2800
		}},
		{&pb.BackupRecord{}, map[string]protoreflect.FieldNumber{
			"id": 1, "username": 2, "database": 3, "created_at": 4, "size_bytes": 5,
			"sha256": 6, "destination": 7, "location": 8, "engine": 9,
			"last_verification": 10, "relation_count": 11, "encrypted": 12,
			"age_recipient": 13, "hook": 14, "wrapped_key": 15, "kek_id": 16,
			"key_mode": 17, "hook_format": 18,
			"scope": 19, // #2800
		}},
	} {
		md := tc.msg.ProtoReflect().Descriptor()
		got := fieldNumbers(md)
		for name, num := range tc.want {
			if got[name] != num {
				t.Errorf("%s.%s = %d, want %d", md.Name(), name, got[name], num)
			}
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s has %d fields, golden lists %d: update the golden deliberately", md.Name(), len(got), len(tc.want))
		}
	}

	ed := pb.BackupScope(0).Descriptor()
	for name, num := range map[string]protoreflect.EnumNumber{
		"BACKUP_SCOPE_UNSPECIFIED": 0, "BACKUP_SCOPE_DATABASE": 1, "BACKUP_SCOPE_BOX": 2,
	} {
		v := ed.Values().ByName(protoreflect.Name(name))
		if v == nil || v.Number() != num {
			t.Errorf("enum value %s missing or renumbered: %v", name, v)
		}
	}
}

// A request encoded by a client that predates #2800 (bytes frozen here)
// decodes with every field intact and scope UNSPECIFIED, i.e. DATABASE.
func TestBackupScope_PreScopeWireBytesDecodeAsDatabase(t *testing.T) {
	// username="alice", connection{database="app"}, destination=LOCAL,
	// key_mode=MANAGED, hook_format=PG_CUSTOM — encoded before field 10
	// existed.
	const golden = "0a05616c69636512050a0361707018014002" + "4802"
	raw, err := hex.DecodeString(golden)
	if err != nil {
		t.Fatal(err)
	}
	var req pb.CreateBackupRequest
	if err := proto.Unmarshal(raw, &req); err != nil {
		t.Fatalf("unmarshal pre-scope bytes: %v", err)
	}
	if req.GetUsername() != "alice" || req.GetConnection().GetDatabase() != "app" ||
		req.GetDestination() != pb.BackupDestination_BACKUP_DESTINATION_LOCAL ||
		req.GetKeyMode() != pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED ||
		req.GetHookFormat() != pb.HookFormat_HOOK_FORMAT_PG_CUSTOM {
		t.Errorf("pre-scope fields lost: %v", &req)
	}
	if req.GetScope() != pb.BackupScope_BACKUP_SCOPE_UNSPECIFIED {
		t.Errorf("scope = %v, want UNSPECIFIED", req.GetScope())
	}
	if len(req.ProtoReflect().GetUnknown()) != 0 {
		t.Errorf("pre-scope bytes left unknown fields: a field number moved")
	}

	// And the new field round-trips on its own number, not on top of an
	// old one.
	b, err := proto.Marshal(&pb.CreateBackupRequest{Scope: pb.BackupScope_BACKUP_SCOPE_BOX})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != "5002" {
		t.Errorf("scope=BOX encodes as %s, want 5002 (field 10, varint 2)", got)
	}
}
