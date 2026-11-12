// Package boxlogs reads one window of a box's logs (#3643): the systemd
// journal and the logs of the containers running inside the box, collected
// by one fixed script the daemon execs in the box and merged in the daemon.
//
// Everything the box prints is untrusted: a box's root user can replace
// journalctl, docker, head or sed. Parse is a strict frame parser with hard
// size limits; anything it cannot read is skipped and counted, never trusted.
// The pieces here are pure functions (script text, parser, merge, cursor) so
// each is unit-tested on its own with hostile inputs.
package boxlogs

import (
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	// MaxLinesDefault and MaxLinesLimit bound the lines in one window.
	MaxLinesDefault = 200
	MaxLinesLimit   = 1000
	// TailDefault is the tail used when a read has neither cursor nor since.
	TailDefault = 100
	// TextCap caps one line's text, in bytes of valid UTF-8.
	TextCap = 8 << 10
	// WindowTextBudget caps the text bytes in one window, so a window of
	// MaxLinesLimit long lines still fits a gRPC message.
	WindowTextBudget = 1 << 20
	// OutputCap is the most the script prints; the parser reads no further.
	OutputCap = 8 << 20
	// MaxFrameLine is the longest frame the parser accepts. The script cuts
	// honest frames well below it (journalFrameCut, dockerFrameCut).
	MaxFrameLine = 64 << 10
	// MaxContainers is the most containers one read lists and reads.
	MaxContainers = 32
	// MaxFilterNames bounds each of the units and containers filters.
	MaxFilterNames = 16
	// MaxCursorLen bounds the opaque cursor a caller passes back.
	MaxCursorLen = 8 << 10
	// ScriptBudgetSeconds is how long the script lets its readers run.
	ScriptBudgetSeconds = 5
	// Settle holds back lines this close to the box's clock, so a line a
	// slower source has not delivered yet is not skipped by the merge.
	Settle = time.Second

	// journalFrameCut and dockerFrameCut are where the script cuts one
	// output line. journalctl prints a field over 4096 bytes as null, so an
	// honest journal frame stays far below journalFrameCut; a docker line is
	// its timestamp plus text, and one longer than dockerFrameCut is
	// reported truncated.
	journalFrameCut = 32 << 10
	dockerFrameCut  = TextCap + 64
)

// Line is one log line as read from the box.
type Line struct {
	Time   time.Time
	Kind   pb.BoxLogSourceKind
	Source string // unit, syslog identifier, or container name
	Text   string
	// Truncated is set when the text is only the start of a longer line.
	Truncated bool

	// journalCursor is the journal entry's cursor (journal lines only).
	journalCursor string
	// containerID is the container's full id (container lines only).
	containerID string
}

// Proto renders the line for the API.
func (l Line) Proto() *pb.BoxLogLine {
	return lineProto(l)
}
