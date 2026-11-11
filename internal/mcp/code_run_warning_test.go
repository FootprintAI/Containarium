package mcp

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun"
)

// #3529: code_run's reply carries a note from the start (a stale skill-set
// apply marker was cleared) as its first line, and nothing extra without one.
func TestCodeRunReply_SurfacesTheWarning(t *testing.T) {
	with := codeRunReply(&coderun.ProcessStartResult{Name: "r", PID: 7, LogPath: "/l", Warning: "cleared a stale skill-set apply marker"}, "alice", "out", 3)
	if !strings.HasPrefix(with, "warning: cleared a stale skill-set apply marker\n✓ started \"r\" (pid 7) on alice") {
		t.Fatalf("reply = %q", with)
	}
	without := codeRunReply(&coderun.ProcessStartResult{Name: "r", PID: 7, LogPath: "/l"}, "alice", "out", 3)
	if strings.Contains(without, "warning:") || !strings.HasPrefix(without, "✓ started") || !strings.Contains(without, "next_offset: 3") {
		t.Fatalf("reply without a warning = %q", without)
	}
}
