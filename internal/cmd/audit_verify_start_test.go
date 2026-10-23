package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/audit"
)

func TestVerifyStartID(t *testing.T) {
	base := audit.ChainBase{ID: 510, RowsPurged: 509, PurgedAt: time.Date(2026, 10, 23, 11, 0, 0, 0, time.UTC)}
	tests := []struct {
		name     string
		from     int64
		purged   bool
		want     int64
		wantNote string
	}{
		{"never purged starts where asked", 0, false, 0, ""},
		{"never purged keeps a from-id", 700, false, 700, ""},
		{"from genesis starts at the base", 0, true, 510, "verifying from the stored chain base"},
		{"a from-id inside the purged range starts at the base", 300, true, 510, "id=510"},
		{"a from-id at the base is the base", 510, true, 510, "id=510"},
		{"a from-id past the base is honoured", 700, true, 700, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, note := verifyStartID(tc.from, base, tc.purged)
			if got != tc.want || (tc.wantNote == "") != (note == "") || !strings.Contains(note, tc.wantNote) {
				t.Fatalf("verifyStartID(%d, purged=%v) = %d %q, want %d containing %q", tc.from, tc.purged, got, note, tc.want, tc.wantNote)
			}
		})
	}
}
