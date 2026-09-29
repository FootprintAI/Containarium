package agentbox

import (
	"testing"
	"time"
)

// The exported decode helpers (#2123) are the same rules listRunRecords and
// readRunRecord apply, so the daemon's box-run reader cannot drift from what
// process_list reports.
func TestDecodeRunRecord(t *testing.T) {
	cases := []struct {
		name    string
		data    string
		wantErr bool
		want    string
	}{
		{name: "current version", data: `{"version":2,"name":"task","pid":7}`, want: "task"},
		{name: "v1 still readable", data: `{"version":1,"name":"old"}`, want: "old"},
		{name: "future version rejected", data: `{"version":99,"name":"x"}`, wantErr: true},
		{name: "zero version rejected", data: `{"name":"x"}`, wantErr: true},
		{name: "malformed", data: `{`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := DecodeRunRecord([]byte(tc.data))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && r.Name != tc.want {
				t.Errorf("name = %q, want %q", r.Name, tc.want)
			}
		})
	}
}

func TestFoldExitSidecar(t *testing.T) {
	seven := 7
	cases := []struct {
		name     string
		record   RunRecord
		sidecar  string
		wantCode *int
		wantAt   time.Time
	}{
		{name: "no sidecar leaves it open", record: RunRecord{Name: "a"}},
		{name: "sidecar supplies code and time", record: RunRecord{Name: "a"}, sidecar: "3 1790000000", wantCode: intPtr(3), wantAt: time.Unix(1790000000, 0).UTC()},
		{name: "corrupt sidecar ignored", record: RunRecord{Name: "a"}, sidecar: "x"},
		{name: "record's own code wins", record: RunRecord{Name: "a", ExitCode: &seven}, sidecar: "0 1790000000", wantCode: intPtr(7)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FoldExitSidecar(tc.record, []byte(tc.sidecar))
			switch {
			case tc.wantCode == nil && got.ExitCode != nil:
				t.Fatalf("exit code = %d, want none", *got.ExitCode)
			case tc.wantCode != nil && (got.ExitCode == nil || *got.ExitCode != *tc.wantCode):
				t.Fatalf("exit code = %v, want %d", got.ExitCode, *tc.wantCode)
			}
			if !tc.wantAt.IsZero() && (got.FinishedAt == nil || !got.FinishedAt.Equal(tc.wantAt)) {
				t.Errorf("finished_at = %v, want %v", got.FinishedAt, tc.wantAt)
			}
		})
	}
}

func TestIsCurrentRecordFile(t *testing.T) {
	for name, want := range map[string]bool{
		"task.json":            true,
		"my-run_2.json":        true,
		"task.1790000000.json": false, // rotated aside
		"task.log":             false,
		"task.exit":            false,
		".agent-box.1.tmp":     false,
	} {
		if got := IsCurrentRecordFile(name); got != want {
			t.Errorf("IsCurrentRecordFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func intPtr(v int) *int { return &v }
