package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// Tests for #2405: a hook may declare the format of what it emits. A hook
// that declares HookFormatPGCustom promises a `pg_dump -Fc` archive, so the
// daemon can restore-test it and restore it into a scratch target exactly
// like a database-mode dump. An undeclared (or OPAQUE) hook keeps every
// refusal it had before.

// sampleTOC is what `pg_restore --list` prints for a small custom-format
// archive: three user tables (one of them partitioned, plus one partition),
// their data entries, and objects that must NOT be counted as relations.
const sampleTOC = `;
; Archive created at 2026-10-09 02:00:01 UTC
;     dbname: app
;     TOC Entries: 12
;     Format: CUSTOM
;
; Selected TOC Entries:
;
215; 1259 16386 TABLE public accounts app
216; 1259 16390 TABLE public events app
217; 1259 16394 TABLE public events_2026 app
3329; 0 0 TABLE ATTACH public events_2026 app
218; 1259 16398 SEQUENCE public accounts_id_seq app
219; 1259 16400 VIEW public active_accounts app
220; 1259 16402 FOREIGN TABLE public remote_things app
3328; 0 16386 TABLE DATA public accounts app
3330; 0 16394 TABLE DATA public events_2026 app
3200; 2606 16405 CONSTRAINT public accounts accounts_pkey app
3201; 1259 16406 INDEX public events_idx app
`

// hookFormatOps layers `pg_restore --list` on top of the restore-test fake
// so Create's manifest step for a PG_CUSTOM hook has a TOC to read.
type hookFormatOps struct {
	*verifyOps
	tocListing string
	failList   bool
}

func newHookFormatOps(payload []byte) *hookFormatOps {
	o := &hookFormatOps{verifyOps: newVerifyOps(payload), tocListing: sampleTOC}
	// The scratch database restored from sampleTOC holds the same three
	// user relations the archive declares.
	o.restoredRelations = "3"
	return o
}

func (h *hookFormatOps) ExecWithOutput(container string, command []string) (string, string, error) {
	full := strings.Join(command, " ")
	if strings.Contains(full, "pg_restore --list") {
		h.record(container, command)
		if h.failList {
			return "", "bash: line 1: pg_restore: command not found", errExec
		}
		return h.tocListing, "", nil
	}
	return h.verifyOps.ExecWithOutput(container, command)
}

func (h *hookFormatOps) ran(container, needle string) bool {
	for _, c := range h.execByContainer[container] {
		if strings.Contains(c, needle) {
			return true
		}
	}
	return false
}

const testHook = "/opt/backup/db-dump.sh"

func createHookBackup(t *testing.T, m *Manager, format HookFormat, recipient string) *Record {
	t.Helper()
	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Destination:   DestLocal,
		Hook:          testHook,
		HookFormat:    format,
		AgeRecipient:  recipient,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return rec
}

func TestCreate_HookPGCustomRecordsRelationCount(t *testing.T) {
	ops := newHookFormatOps([]byte("PGDMP-custom-archive"))
	m := newTestManager(t, ops)
	rec := createHookBackup(t, m, HookFormatPGCustom, "")

	if rec.Engine != EngineHook {
		t.Fatalf("engine = %q, want %q", rec.Engine, EngineHook)
	}
	if rec.HookFormat != HookFormatPGCustom {
		t.Errorf("HookFormat = %q, want %q", rec.HookFormat, HookFormatPGCustom)
	}
	if rec.RelationCount == nil || *rec.RelationCount != 3 {
		t.Fatalf("RelationCount = %v, want 3 (tables in the archive's TOC)", rec.RelationCount)
	}

	// The TOC is read from the staged dump inside the source container,
	// before the staged copy is removed.
	cmds := ops.execByContainer["alice-container"]
	listAt, rmAt := -1, -1
	for i, c := range cmds {
		if strings.Contains(c, "pg_restore --list") && strings.Contains(c, "/tmp/containarium-backup-"+rec.ID+".dump") {
			listAt = i
		}
		if strings.HasPrefix(c, "rm -f /tmp/containarium-backup-"+rec.ID) {
			rmAt = i
		}
	}
	if listAt < 0 {
		t.Fatalf("pg_restore --list never ran on the staged dump; commands: %v", cmds)
	}
	if rmAt >= 0 && rmAt < listAt {
		t.Errorf("staged dump removed (cmd %d) before its TOC was read (cmd %d)", rmAt, listAt)
	}

	// Persisted, not just returned.
	got, err := m.Get(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.HookFormat != HookFormatPGCustom || got.RelationCount == nil || *got.RelationCount != 3 {
		t.Errorf("sidecar = format %q count %v, want pg_custom / 3", got.HookFormat, got.RelationCount)
	}
}

// pg_restore may not exist where the hook ran (that Postgres can be nested
// out of the daemon's reach). The dump is still good; the manifest is just
// absent, and Verify records "nothing to compare against".
func TestCreate_HookPGCustomWithoutPgRestoreLeavesManifestAbsent(t *testing.T) {
	ops := newHookFormatOps([]byte("PGDMP-custom-archive"))
	ops.failList = true
	m := newTestManager(t, ops)
	rec := createHookBackup(t, m, HookFormatPGCustom, "")
	if rec.RelationCount != nil {
		t.Errorf("RelationCount = %d, want nil when the TOC could not be read", *rec.RelationCount)
	}
	if rec.HookFormat != HookFormatPGCustom {
		t.Errorf("HookFormat = %q, want pg_custom", rec.HookFormat)
	}
}

func TestCreate_HookOpaqueReadsNoManifest(t *testing.T) {
	for _, format := range []HookFormat{"", HookFormatOpaque} {
		t.Run(fmt.Sprintf("format=%q", format), func(t *testing.T) {
			ops := newHookFormatOps([]byte("anything"))
			m := newTestManager(t, ops)
			rec := createHookBackup(t, m, format, "")
			if rec.HookFormat != HookFormatOpaque {
				t.Errorf("HookFormat = %q, want %q (unspecified means opaque)", rec.HookFormat, HookFormatOpaque)
			}
			if rec.RelationCount != nil {
				t.Errorf("RelationCount = %d, want nil for an opaque hook", *rec.RelationCount)
			}
			if ops.ran("alice-container", "pg_restore") {
				t.Error("pg_restore must not run against an opaque hook stream")
			}
		})
	}
}

func TestCreate_HookFormatValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts CreateOptions
		want string
	}{
		{"format without hook", CreateOptions{Conn: PgConn{Database: "app"}, HookFormat: HookFormatPGCustom}, "hook format"},
		{"unknown format", CreateOptions{Hook: testHook, HookFormat: HookFormat("plain_sql")}, "hook format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t, newFakeOps([]byte("x")))
			o := tc.opts
			o.Username, o.ContainerName, o.Destination = "alice", "alice-container", DestLocal
			_, err := m.Create(o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

func TestVerify_HookPGCustomIsRestoreTested(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		recipient  string
		identity   string
		wantChecks []string
	}{
		{"plaintext", "", "", []string{"integrity", "scratch_database", "restore", "relation_count"}},
		{"encrypted", id.Recipient().String(), id.String(), []string{"integrity", "decrypt", "scratch_database", "restore", "relation_count"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := newHookFormatOps([]byte("PGDMP-custom-archive"))
			m := newTestManager(t, ops)
			rec := createHookBackup(t, m, HookFormatPGCustom, tc.recipient)
			ops.execByContainer = map[string][]string{}

			v, err := m.Verify(VerifyOptions{
				ID:              rec.ID,
				TargetContainer: "scratch-container",
				SourceContainer: "alice-container",
				AgeIdentity:     tc.identity,
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if v.Result != VerificationPassed {
				t.Fatalf("result = %q (error %q), want passed", v.Result, v.Error)
			}
			var names []string
			for _, c := range v.Checks {
				names = append(names, c.Name)
				if !c.Passed {
					t.Errorf("check %s failed: %s", c.Name, c.Detail)
				}
			}
			if strings.Join(names, ",") != strings.Join(tc.wantChecks, ",") {
				t.Errorf("checks = %v, want %v", names, tc.wantChecks)
			}
			last := v.Checks[len(v.Checks)-1]
			if !strings.Contains(last.Detail, "matching the source") {
				t.Errorf("relation_count detail = %q, want a comparison against the create-time manifest", last.Detail)
			}
			if cmds, touched := ops.execByContainer["alice-container"]; touched {
				t.Errorf("source container touched during verification: %v", cmds)
			}
			got, _ := m.Get(rec.ID)
			if got.LastVerification == nil || got.LastVerification.Result != VerificationPassed {
				t.Error("PASSED verification was not recorded on the backup")
			}
		})
	}
}

func TestVerify_HookOpaqueStillRefused(t *testing.T) {
	for _, format := range []HookFormat{"", HookFormatOpaque} {
		t.Run(fmt.Sprintf("format=%q", format), func(t *testing.T) {
			ops := newHookFormatOps([]byte("anything"))
			m := newTestManager(t, ops)
			rec := createHookBackup(t, m, format, "")
			ops.execByContainer = map[string][]string{}

			_, err := m.Verify(VerifyOptions{ID: rec.ID, TargetContainer: "scratch-container", SourceContainer: "alice-container"})
			want := fmt.Sprintf("backup %s was produced by tenant hook %s and is an opaque stream: the platform cannot restore-test it", rec.ID, testHook)
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v, want exactly %q", err, want)
			}
			if len(ops.execByContainer) != 0 {
				t.Errorf("refusal must precede any container command: %v", ops.execByContainer)
			}
		})
	}
}

func TestRestore_HookPGCustomIntoScratchTarget(t *testing.T) {
	ops := newHookFormatOps([]byte("PGDMP-custom-archive"))
	m := newTestManager(t, ops)
	rec := createHookBackup(t, m, HookFormatPGCustom, "")
	ops.execByContainer = map[string][]string{}

	err := m.Restore(RestoreOptions{
		ID:              rec.ID,
		ContainerName:   "alice-container",
		TargetContainer: "scratch-container",
		Conn:            PgConn{Database: "restored"},
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !ops.ran("scratch-container", "pg_restore") || !ops.ran("scratch-container", "-d 'restored'") {
		t.Errorf("pg_restore did not run into the target; commands: %v", ops.execByContainer["scratch-container"])
	}
	if cmds, touched := ops.execByContainer["alice-container"]; touched {
		t.Errorf("source container touched by a scratch restore: %v", cmds)
	}
	if _, ok := ops.written["/tmp/containarium-restore-"+rec.ID+".dump"]; !ok {
		t.Error("dump was never pushed to the target")
	}
}

func TestRestore_HookPGCustomInPlaceRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
	}{
		{"no target named", ""},
		{"target is the source", "alice-container"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := newHookFormatOps([]byte("PGDMP-custom-archive"))
			m := newTestManager(t, ops)
			rec := createHookBackup(t, m, HookFormatPGCustom, "")
			ops.execByContainer = map[string][]string{}
			ops.written = map[string][]byte{}

			err := m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "alice-container", TargetContainer: tc.target})
			if err == nil || !strings.Contains(err.Error(), "target container") {
				t.Fatalf("err = %v, want an in-place refusal naming the target-container requirement", err)
			}
			if len(ops.execByContainer) != 0 || len(ops.written) != 0 {
				t.Errorf("refusal must precede any container command: exec %v, written %v", ops.execByContainer, ops.written)
			}
		})
	}
}

// An opaque hook stays refused with today's message even into a named
// scratch target: the bytes are unknown wherever they would be loaded.
func TestRestore_HookOpaqueRefusedEvenIntoTarget(t *testing.T) {
	for _, target := range []string{"", "scratch-container"} {
		t.Run("target="+target, func(t *testing.T) {
			ops := newHookFormatOps([]byte("anything"))
			m := newTestManager(t, ops)
			rec := createHookBackup(t, m, HookFormatOpaque, "")
			ops.execByContainer = map[string][]string{}

			err := m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "alice-container", TargetContainer: target})
			want := fmt.Sprintf("backup %s was produced by tenant hook %s and is an opaque stream: fetch it and apply it with the tenant's own tooling (automatic restore is only supported for %s dumps)", rec.ID, testHook, EnginePostgres)
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v, want exactly %q", err, want)
			}
			if len(ops.execByContainer) != 0 {
				t.Errorf("refusal must precede any container command: %v", ops.execByContainer)
			}
		})
	}
}

// Sidecars written before #2405 carry no hook_format. A hook record among
// them loads as OPAQUE (today's behaviour); a pg_dump record has no hook
// format at all.
func TestReadSidecar_OldRecordsWithoutHookFormat(t *testing.T) {
	for _, tc := range []struct {
		name   string
		engine string
		want   HookFormat
	}{
		{"old hook record", EngineHook, HookFormatOpaque},
		{"pg_dump record", EnginePostgres, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t, newFakeOps(nil))
			if err := os.MkdirAll(m.dir, 0o700); err != nil {
				t.Fatal(err)
			}
			id := "alice-app-20260101T000000Z"
			old := fmt.Sprintf(`{"id":%q,"username":"alice","database":"app","created_at":"2026-01-01T00:00:00Z","size_bytes":1,"sha256":"x","destination":"local","location":"/nowhere","engine":%q,"hook":"/opt/dump.sh"}`, id, tc.engine)
			if err := os.WriteFile(filepath.Join(m.dir, id+".meta.json"), []byte(old), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := m.Get(id)
			if err != nil {
				t.Fatal(err)
			}
			if got.HookFormat != tc.want {
				t.Errorf("HookFormat = %q, want %q", got.HookFormat, tc.want)
			}
		})
	}
}

func TestCountTOCTables(t *testing.T) {
	for _, tc := range []struct {
		name string
		toc  string
		want int64
	}{
		{"sample archive", sampleTOC, 3},
		{"header only", ";\n; Archive created at x\n;\n", 0},
		{"empty", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := countTOCTables(tc.toc); got != tc.want {
				t.Errorf("countTOCTables = %d, want %d", got, tc.want)
			}
		})
	}
}
