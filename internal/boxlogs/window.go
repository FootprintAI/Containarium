package boxlogs

import (
	"maps"
	"slices"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Window is one window of merged lines and the cursor after it.
type Window struct {
	Lines  []Line
	Cursor Cursor
	// More is set when lines were ready past this window, or a source was
	// cut at its line cap: the caller should read again at once.
	More bool
}

// source is one reader's lines as the merge sees them.
type source struct {
	journal bool
	id      string // container id
	read    []Line // every line read, in the reader's order
	kAt     []int  // per read line: earlier read lines stamped the same time
	fresh   []int  // indexes into read of lines not consumed by the cursor
	cand    int    // fresh[:cand] are stamped at or before the horizon
	used    int    // fresh[:used] are consumed by this window
	// limit, when capped, is the time past which this source may hold
	// unread lines; nothing later is emitted from any source.
	capped      bool
	countCapped bool
	limit       int64
}

func newSource(read []Line) *source {
	s := &source{read: read, kAt: make([]int, len(read))}
	for i := range read {
		for j := i - 1; j >= 0 && read[j].Time.Equal(read[i].Time); j-- {
			s.kAt[i]++
		}
	}
	return s
}

// Window merges the collection into one window (#3643). Each source's fresh
// lines (those the cursor has not consumed) are merged k-way by receipt
// time up to a horizon: the box's clock less the settle margin, and no later
// than the last line read from a source cut off at its line cap or budget,
// since that source may still hold earlier lines. Lines past the horizon
// stay unconsumed for the next window. The cursor then records, per source,
// the exact point consumption reached, so the next window repeats and skips
// nothing.
func (p *Plan) Window(c *Collection, settle time.Duration) Window {
	cur := p.Cursor
	cur.V = cursorVersion
	cur.Containers = maps.Clone(cur.Containers)
	horizon := c.Now.Add(-settle).UnixNano()

	var srcs []*source
	if p.readJournal() {
		s := newSource(c.Journal.Lines)
		s.journal = true
		for i, l := range s.read {
			if cur.Journal != "" || l.Time.UnixNano() > cur.Horizon {
				s.fresh = append(s.fresh, i)
			}
		}
		s.setCapped(&c.Journal, c.JournalLimit, p.Tail, cur.Horizon)
		srcs = append(srcs, s)
	}
	if p.readContainers() && c.Runtime == pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER {
		for _, ct := range c.Containers {
			if len(p.Containers) > 0 && !slices.Contains(p.Containers, ct.Name) {
				continue
			}
			r := c.ContainerReads[ct.Index]
			if r == nil {
				r = &SourceRead{} // listed, never read: not complete
			}
			s := newSource(r.Lines)
			s.id = ct.ID
			pos := cur.pos(ct.ID)
			for i, l := range s.read {
				if !pos.covers(l.Time.UnixNano(), s.kAt[i]) {
					s.fresh = append(s.fresh, i)
				}
			}
			s.setCapped(r, c.ContainerLimit, p.Tail, pos.T)
			srcs = append(srcs, s)
		}
	}
	more := false
	for _, s := range srcs {
		if s.capped {
			horizon = min(horizon, s.limit)
		}
		more = more || s.countCapped
	}
	for _, s := range srcs {
		for s.cand < len(s.fresh) && s.read[s.fresh[s.cand]].Time.UnixNano() <= horizon {
			s.cand++
		}
	}

	merged := mergeSources(srcs)
	// A first read with tail consumes the older lines without emitting them.
	skip := 0
	if p.Tail > 0 && len(merged) > p.Tail {
		skip = len(merged) - p.Tail
	}
	for _, s := range merged[:skip] {
		s.used++
	}
	var w Window
	size := 0
	for _, s := range merged[skip:] {
		l := s.read[s.fresh[s.used]]
		if len(w.Lines) == p.MaxLines || (len(w.Lines) > 0 && size+len(l.Text) > WindowTextBudget) {
			more = true
			break
		}
		w.Lines = append(w.Lines, l)
		size += len(l.Text)
		s.used++
	}

	allUsed := true
	for _, s := range srcs {
		allUsed = allUsed && s.used == s.cand
		s.advance(&cur, horizon)
	}
	if allUsed && horizon > cur.Horizon {
		cur.Horizon = horizon
	}
	if c.Runtime == pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER {
		listed := map[string]bool{}
		for _, ct := range c.Containers {
			listed[ct.ID] = true
		}
		maps.DeleteFunc(cur.Containers, func(id string, _ Pos) bool { return !listed[id] })
	}
	if len(cur.Containers) == 0 {
		cur.Containers = nil
	}
	w.Cursor, w.More = cur, more
	return w
}

// setCapped decides whether more lines may follow this read: the reader was
// cut off (budget, output cap), or stopped at its line cap. A tail read is
// cut by its line cap only when the script lowered the cap below the tail.
func (s *source) setCapped(r *SourceRead, limit, tail int, from int64) {
	byCount := limit <= 0 || (len(s.read) >= limit && (tail == 0 || limit < tail))
	s.countCapped = r.complete() && byCount
	s.capped = !r.complete() || byCount
	// Unread lines come after the last one read, and any before `from` (the
	// source's own position) were consumed already.
	s.limit = from
	if n := len(s.read); n > 0 {
		s.limit = max(from, s.read[n-1].Time.UnixNano())
	}
}

// advance records in cur how far this window consumed the source.
func (s *source) advance(cur *Cursor, horizon int64) {
	if s.journal {
		switch {
		case s.used < len(s.fresh):
			// Resume at the first unconsumed entry: everything before it
			// in read order is consumed.
			if u := s.fresh[s.used]; u > 0 {
				cur.Journal, cur.JournalAt = s.read[u-1].journalCursor, false
			} else {
				cur.Journal, cur.JournalAt = s.read[u].journalCursor, true
			}
		case s.used > 0:
			cur.Journal, cur.JournalAt = s.read[len(s.read)-1].journalCursor, false
		}
		// Nothing consumed: the old cursor (or the horizon) stands.
		return
	}
	pos, set := cur.pos(s.id), false
	switch {
	case s.used < s.cand:
		// Resume at the first unconsumed line at or before the horizon.
		// (Not at one past it: a line stamped between the horizon and that
		// one may still arrive.)
		u := s.fresh[s.used]
		pos, set = Pos{T: s.read[u].Time.UnixNano(), N: s.kAt[u]}, true
	case s.used > 0:
		last := s.fresh[s.used-1]
		pos, set = Pos{T: s.read[last].Time.UnixNano(), N: s.kAt[last] + 1}, true
	}
	// A source with every line up to the horizon consumed, and none left
	// unread at or before it (it read to its end, or its unread lines come
	// after the horizon), moves up to the horizon, so it does not hold back
	// the shared --since.
	if s.used == s.cand && (!s.capped || s.limit > horizon) {
		if floor := (Pos{T: horizon, All: true}); posBefore(pos, floor) {
			pos, set = floor, true
		}
	}
	if !set {
		return
	}
	if cur.Containers == nil {
		cur.Containers = map[string]Pos{}
	}
	cur.Containers[s.id] = pos
}

// posBefore reports whether a consumes strictly less than b.
func posBefore(a, b Pos) bool {
	if a.T != b.T {
		return a.T < b.T
	}
	return !a.All && (b.All || a.N < b.N)
}

// mergeSources merges the sources' candidate lines k-way by time, the
// earlier source winning a tie, and returns the source of each merged line
// in order.
func mergeSources(srcs []*source) []*source {
	heads := make([]int, len(srcs))
	var out []*source
	for {
		best := -1
		var bestT int64
		for i, s := range srcs {
			if heads[i] >= s.cand {
				continue
			}
			t := s.read[s.fresh[heads[i]]].Time.UnixNano()
			if best < 0 || t < bestT {
				best, bestT = i, t
			}
		}
		if best < 0 {
			return out
		}
		out = append(out, srcs[best])
		heads[best]++
	}
}
