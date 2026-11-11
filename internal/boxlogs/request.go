package boxlogs

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// ArgError is a request the caller must fix: the server answers it with
// InvalidArgument.
type ArgError struct{ Msg string }

func (e *ArgError) Error() string { return e.Msg }

func argErrorf(format string, a ...any) error { return &ArgError{Msg: fmt.Sprintf(format, a...)} }

// Request is a TailBoxLogs request, decoded from the proto.
type Request struct {
	Cursor     string
	Since      time.Time // zero: none
	Tail       int
	Units      []string
	Containers []string
	MaxLines   int
}

// Plan is a validated request: what to read and how to cut the window.
type Plan struct {
	Cursor Cursor
	// Tail is set only on a first read that starts with the last lines.
	Tail       int
	MaxLines   int
	Units      []string // normalized unit names
	Containers []string
	// Root and Budget are passed through to the script (test seams).
	Root   string
	Budget int
}

// unitSuffixes are the unit types; a name without one means a service, as
// systemctl and journalctl read it.
var unitSuffixes = []string{".service", ".socket", ".timer", ".scope", ".slice", ".mount", ".automount", ".swap", ".path", ".target", ".device"}

// NormalizeUnit checks a unit filter name and adds ".service" when the name
// has no unit type.
func NormalizeUnit(u string) (string, bool) {
	if !unitPattern.MatchString(u) {
		return "", false
	}
	for _, s := range unitSuffixes {
		if strings.HasSuffix(u, s) && len(u) > len(s) {
			return u, true
		}
	}
	u += ".service"
	return u, unitPattern.MatchString(u)
}

// Prepare validates a request into a Plan. Every value that can reach the
// box is checked here, before any exec.
func Prepare(r Request) (*Plan, error) {
	p := &Plan{MaxLines: r.MaxLines, Budget: ScriptBudgetSeconds}
	switch {
	case r.MaxLines < 0:
		return nil, argErrorf("max_lines must be >= 0")
	case r.MaxLines == 0:
		p.MaxLines = MaxLinesDefault
	case r.MaxLines > MaxLinesLimit:
		p.MaxLines = MaxLinesLimit
	}
	if r.Tail < 0 || r.Tail > MaxLinesLimit {
		return nil, argErrorf("tail must be 0..%d", MaxLinesLimit)
	}
	if len(r.Units) > MaxFilterNames || len(r.Containers) > MaxFilterNames {
		return nil, argErrorf("at most %d units and %d containers", MaxFilterNames, MaxFilterNames)
	}
	for _, u := range r.Units {
		n, ok := NormalizeUnit(u)
		if !ok {
			return nil, argErrorf("unit %q must match %s", u, unitPattern.String())
		}
		if !slices.Contains(p.Units, n) {
			p.Units = append(p.Units, n)
		}
	}
	for _, c := range r.Containers {
		if !containerNamePattern.MatchString(c) {
			return nil, argErrorf("container %q must match %s", c, containerNamePattern.String())
		}
		if !slices.Contains(p.Containers, c) {
			p.Containers = append(p.Containers, c)
		}
	}
	if r.Cursor != "" {
		if !r.Since.IsZero() || r.Tail != 0 {
			return nil, argErrorf("cursor cannot be combined with since or tail")
		}
		c, err := DecodeCursor(r.Cursor)
		if err != nil {
			return nil, argErrorf("cursor: %v", err)
		}
		p.Cursor = c
		return p, nil
	}
	p.Cursor = Cursor{V: cursorVersion}
	if !r.Since.IsZero() {
		if r.Since.UnixNano() <= 0 {
			return nil, argErrorf("since must be after 1970")
		}
		p.Cursor.Horizon = r.Since.UnixNano() - 1
	}
	p.Tail = r.Tail
	if p.Tail == 0 && r.Since.IsZero() {
		p.Tail = TailDefault
	}
	return p, nil
}

// Next is the plan for the window after one that returned c.
func (p *Plan) Next(c Cursor) *Plan {
	n := *p
	n.Cursor, n.Tail = c, 0
	return &n
}

func (p *Plan) readJournal() bool    { return len(p.Units) > 0 || len(p.Containers) == 0 }
func (p *Plan) readContainers() bool { return len(p.Containers) > 0 || len(p.Units) == 0 }

// Params is the plan's collection script parameters.
func (p *Plan) Params() ScriptParams {
	sp := ScriptParams{
		Root: p.Root, Budget: p.Budget, Tail: p.Tail, Units: p.Units,
		ReadJournal: p.readJournal(), ReadContainers: p.readContainers(),
		JournalCursor: p.Cursor.Journal, JournalInclusive: p.Cursor.JournalAt,
		Lines: p.MaxLines + 1,
	}
	if p.Tail > 0 {
		sp.Lines = p.Tail
	}
	if sp.JournalCursor == "" && p.Cursor.Horizon > 0 {
		sp.JournalSince = p.Cursor.Horizon / 1e9
	}
	// One --since (inclusive) serves every container: the earliest point
	// any of them resumes from. A position that consumed every line at its
	// time resumes a nanosecond later; one that consumed only the first N
	// re-reads those N, so the cap grows by the largest N and they cannot
	// fill it. A container further ahead re-reads lines it consumed; it
	// catches up over windows as the others reach its position.
	start := func(pos Pos) int64 {
		if pos.All {
			return pos.T + 1
		}
		return pos.T
	}
	// A horizon of 0 means a container with no position of its own reads
	// from its first line, so there is no --since at all.
	since, sameTime := start(Pos{T: p.Cursor.Horizon, All: true}), 0
	for _, pos := range p.Cursor.Containers {
		since = min(since, start(pos))
		if !pos.All {
			sameTime = max(sameTime, pos.N)
		}
	}
	if p.Cursor.Horizon <= 0 {
		since = 0
	}
	sp.ContainerSince = since
	if p.Tail == 0 {
		sp.Lines += sameTime
	}
	return sp
}

// Script is the collection script for this plan.
func (p *Plan) Script() string { return Script(p.Params()) }

// CheckFilter checks the unit and container filters against what the box
// has, listing the valid names when one is unknown.
func (p *Plan) CheckFilter(c *Collection) error {
	for _, u := range p.Units {
		if !slices.Contains(c.Units, u) {
			return argErrorf("unknown unit %q; valid units: %s", u, nameList(c.Units))
		}
	}
	var names []string
	for _, ct := range c.Containers {
		names = append(names, ct.Name)
	}
	for _, n := range p.Containers {
		if !slices.Contains(names, n) {
			return argErrorf("unknown container %q; valid containers: %s", n, nameList(names))
		}
	}
	return nil
}

func nameList(names []string) string {
	if len(names) == 0 {
		return "(none)"
	}
	s := slices.Clone(names)
	slices.Sort(s)
	s = slices.Compact(s)
	const show = 50
	if len(s) > show {
		return strings.Join(s[:show], ", ") + fmt.Sprintf(", and %d more", len(s)-show)
	}
	return strings.Join(s, ", ")
}
