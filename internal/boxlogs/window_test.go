package boxlogs

import (
	"errors"
	"fmt"
	"math/rand"

	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// simEntry is one log line in the simulated box: it carries the time its
// source stamped on it, and becomes visible to a reader only at arrive (a
// slower source delivers a line a little after its timestamp).
type simEntry struct {
	t      time.Time
	arrive time.Time
	text   string
	unit   string // journal entries
	seq    int    // journal entries: the journal's own order
}

type simContainer struct {
	id, name string
	entries  []simEntry // in the runtime's order (by t)
}

// simBox stands in for a box: it answers a plan's script parameters the way
// journalctl and docker logs do (after-cursor, inclusive since, tail, the
// per-source line cap), so the merge and cursor are exercised against the
// same semantics the real script relies on.
type simBox struct {
	now        time.Time
	journal    []simEntry // in seq order
	containers []simContainer
	units      []string
}

// Each source is an append-only log: a reader sees its lines in the order
// they were appended, so a line delayed in delivery also delays every line
// after it in the same source. Lateness is across sources: a line can be
// delivered after another source's later-stamped line.
func arrival(entries []simEntry, t time.Time, delay time.Duration) time.Time {
	a := t.Add(delay)
	if n := len(entries); n > 0 && entries[n-1].arrive.After(a) {
		a = entries[n-1].arrive
	}
	return a
}

func (b *simBox) addJournal(t time.Time, delay time.Duration, unit, text string) {
	b.journal = append(b.journal, simEntry{t: t, arrive: arrival(b.journal, t, delay), unit: unit, text: text, seq: len(b.journal) + 1})
}

func (b *simBox) addDocker(i int, t time.Time, delay time.Duration, text string) {
	c := &b.containers[i]
	c.entries = append(c.entries, simEntry{t: t, arrive: arrival(c.entries, t, delay), text: text})
}

func (b *simBox) collect(p ScriptParams) *Collection {
	if p.Lines <= 0 {
		panic("plan with no per-source line cap")
	}
	c := &Collection{Now: b.now, Runtime: pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER, Units: b.units,
		JournalLimit: p.Lines, ContainerLimit: p.Lines, ContainerReads: map[int]*SourceRead{}}
	cap := func(lines []Line, limit int) ([]Line, int) {
		if limit > 0 && len(lines) > limit {
			return lines[:limit], 141
		}
		return lines, 0
	}
	if p.ReadJournal {
		var lines []Line
		after := -1
		if p.JournalCursor != "" {
			for _, e := range b.journal {
				if jcur(e.seq) == p.JournalCursor {
					after = e.seq
				}
			}
			if after < 0 {
				panic("cursor not found: " + p.JournalCursor)
			}
			if p.JournalInclusive {
				after-- // --cursor: start at the entry itself
			}
		}
		units := map[string]bool{}
		for _, u := range p.Units {
			units[u] = true
		}
		for _, e := range b.journal {
			if e.arrive.After(b.now) || (after >= 0 && e.seq <= after) || (len(units) > 0 && !units[e.unit]) {
				continue
			}
			if after < 0 && p.JournalSince > 0 && e.t.Unix() < p.JournalSince {
				continue
			}
			lines = append(lines, Line{Time: e.t, Kind: pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_JOURNAL, Source: e.unit, Text: e.text, journalCursor: jcur(e.seq)})
		}
		if p.Tail > 0 && len(lines) > p.Tail {
			lines = lines[len(lines)-p.Tail:]
		}
		lines, rc := cap(lines, p.Lines)
		c.Journal = SourceRead{Lines: lines, Ended: true, RC: rc}
	}
	for i, ct := range b.containers {
		c.Containers = append(c.Containers, Container{Index: i, ID: ct.id, Name: ct.name, State: "running"})
		if !p.ReadContainers {
			continue
		}
		var lines []Line
		for _, e := range ct.entries {
			if e.arrive.After(b.now) || (p.ContainerSince > 0 && e.t.UnixNano() < p.ContainerSince) {
				continue
			}
			lines = append(lines, Line{Time: e.t, Kind: pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_CONTAINER, Source: ct.name, Text: e.text, containerID: ct.id})
		}
		if p.Tail > 0 && len(lines) > p.Tail {
			lines = lines[len(lines)-p.Tail:]
		}
		lines, rc := cap(lines, p.Lines)
		c.ContainerReads[i] = &SourceRead{Lines: lines, Ended: true, RC: rc}
	}
	return c
}

func newSim() *simBox {
	return &simBox{
		now:        t0,
		units:      []string{"nginx.service", "cron.service"},
		containers: []simContainer{{id: testID0, name: "web"}, {id: testID1, name: "worker"}},
	}
}

func render(lines []Line) []string {
	var out []string
	for _, l := range lines {
		out = append(out, fmt.Sprintf("%s %s %s", l.Time.Sub(t0), l.Source, l.Text))
	}
	return out
}

func mustPrepare(t *testing.T, r Request) *Plan {
	t.Helper()
	p, err := Prepare(r)
	if err != nil {
		t.Fatalf("Prepare(%+v): %v", r, err)
	}
	return p
}

// Criterion 1: a box running one unit and one container returns lines from
// both, labelled and in time order.
func TestWindow_MergesUnitAndContainer(t *testing.T) {
	b := newSim()
	b.containers = b.containers[:1]
	b.addJournal(t0.Add(1*time.Millisecond), 0, "nginx.service", "j1")
	b.addDocker(0, t0.Add(2*time.Millisecond), 0, "d1")
	b.addJournal(t0.Add(3*time.Millisecond), 0, "nginx.service", "j2")
	b.addDocker(0, t0.Add(3*time.Millisecond), 0, "d2")
	b.addDocker(0, t0.Add(4*time.Millisecond), 0, "d3")
	b.now = t0.Add(5 * time.Second)

	p := mustPrepare(t, Request{})
	w := p.Window(b.collect(p.Params()), Settle)
	want := []string{"1ms nginx.service j1", "2ms web d1", "3ms nginx.service j2", "3ms web d2", "4ms web d3"}
	if got := render(w.Lines); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("lines =\n%v\nwant\n%v", got, want)
	}
	for _, l := range w.Lines {
		wantKind := pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_CONTAINER
		if strings.HasPrefix(l.Text, "j") {
			wantKind = pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_JOURNAL
		}
		if l.Kind != wantKind {
			t.Errorf("%s: kind %v, want %v", l.Text, l.Kind, wantKind)
		}
	}
	pl := w.Lines[1].Proto()
	if pl.GetSourceKind() != pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_CONTAINER || pl.GetSource() != "web" || pl.GetText() != "d1" || !pl.GetTime().AsTime().Equal(t0.Add(2*time.Millisecond)) {
		t.Errorf("proto = %v", pl)
	}
}

// Criterion 2: following the cursor window after window returns every line
// exactly once — with lines arriving between windows, equal timestamps
// within and across sources, late arrivals inside the settle margin, and
// windows far smaller than the backlog.
func TestWindow_CursorResumesWithoutDuplicateOrLoss(t *testing.T) {
	for seed := int64(1); seed <= 60; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			b := newSim()
			var all []string
			at := t0
			add := func() {
				// A line is stamped no earlier than the box's clock (it is
				// being written now) and delivered within the settle margin.
				if at.Before(b.now) {
					at = b.now
				}
				at = at.Add(time.Duration(rng.Intn(3)) * 100 * time.Millisecond) // 0 gives equal timestamps
				delay := time.Duration(rng.Intn(9)) * 100 * time.Millisecond     // < Settle
				text := fmt.Sprintf("l%d", len(all))
				switch rng.Intn(3) {
				case 0:
					b.addJournal(at, delay, []string{"nginx.service", "cron.service"}[rng.Intn(2)], text)
				default:
					b.addDocker(rng.Intn(2), at, delay, text)
				}
				all = append(all, text)
			}
			for i := 0; i < 40; i++ {
				add()
			}
			b.now = at.Add(-300 * time.Millisecond) // some lines not yet arrived

			seen := map[string]int{}
			var order []Line
			plan := mustPrepare(t, Request{Since: t0, MaxLines: 1 + rng.Intn(7)})
			for round := 0; round < 500; round++ {
				w := plan.Window(b.collect(plan.Params()), Settle)
				if len(w.Lines) > plan.MaxLines {
					t.Fatalf("window of %d lines, max %d", len(w.Lines), plan.MaxLines)
				}
				for _, l := range w.Lines {
					seen[l.Text]++
					order = append(order, l)
				}
				// Cursor goes over the wire between windows.
				c, err := DecodeCursor(EncodeCursor(w.Cursor))
				if err != nil {
					t.Fatalf("cursor does not round-trip: %v", err)
				}
				plan = plan.Next(c)
				if round < 20 && rng.Intn(2) == 0 {
					add()
				}
				b.now = b.now.Add(time.Duration(rng.Intn(4)) * 200 * time.Millisecond)
				if round > 30 {
					b.now = at.Add(10 * time.Second)
				}
			}
			for _, text := range all {
				if seen[text] != 1 {
					t.Errorf("line %s seen %d times", text, seen[text])
				}
			}
			for i := 1; i < len(order); i++ {
				if order[i].Time.Before(order[i-1].Time) {
					t.Errorf("out of order: %s at %v after %s at %v", order[i].Text, order[i].Time.Sub(t0), order[i-1].Text, order[i-1].Time.Sub(t0))
				}
			}
		})
	}
}

// Criterion 3: --tail starts with the last N lines across all sources.
func TestWindow_Tail(t *testing.T) {
	b := newSim()
	for i := 0; i < 10; i++ {
		b.addJournal(t0.Add(time.Duration(2*i)*time.Millisecond), 0, "nginx.service", fmt.Sprintf("j%d", i))
		b.addDocker(0, t0.Add(time.Duration(2*i+1)*time.Millisecond), 0, fmt.Sprintf("d%d", i))
	}
	b.now = t0.Add(time.Minute)
	p := mustPrepare(t, Request{Tail: 3})
	w := p.Window(b.collect(p.Params()), Settle)
	want := []string{"17ms web d8", "18ms nginx.service j9", "19ms web d9"}
	if got := render(w.Lines); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("tail 3 =\n%v\nwant\n%v", got, want)
	}
	// And the cursor carries on after the tail, not before it.
	b.addJournal(t0.Add(20*time.Millisecond), 0, "nginx.service", "j10")
	p = p.Next(w.Cursor)
	w = p.Window(b.collect(p.Params()), Settle)
	if got := render(w.Lines); fmt.Sprint(got) != "[20ms nginx.service j10]" {
		t.Errorf("after the tail = %v", got)
	}
}

// With neither cursor nor since, a read starts with the last TailDefault lines.
func TestWindow_DefaultTail(t *testing.T) {
	b := newSim()
	for i := 0; i < TailDefault+20; i++ {
		b.addDocker(0, t0.Add(time.Duration(i)*time.Millisecond), 0, fmt.Sprintf("d%d", i))
	}
	b.now = t0.Add(time.Minute)
	p := mustPrepare(t, Request{MaxLines: MaxLinesLimit})
	w := p.Window(b.collect(p.Params()), Settle)
	if len(w.Lines) != TailDefault || w.Lines[0].Text != "d20" {
		t.Errorf("got %d lines from %v, want the last %d", len(w.Lines), render(w.Lines[:1]), TailDefault)
	}
}

// Criterion 3: --since drops older lines, including the sub-second part the
// journal's whole-second --since cannot express.
func TestWindow_Since(t *testing.T) {
	b := newSim()
	b.addJournal(t0.Add(100*time.Millisecond), 0, "nginx.service", "old-j")
	b.addDocker(0, t0.Add(200*time.Millisecond), 0, "old-d")
	b.addJournal(t0.Add(500*time.Millisecond), 0, "nginx.service", "new-j")
	b.addDocker(0, t0.Add(600*time.Millisecond), 0, "new-d")
	b.now = t0.Add(time.Minute)
	p := mustPrepare(t, Request{Since: t0.Add(500 * time.Millisecond)})
	if sp := p.Params(); sp.JournalSince != t0.Unix() || sp.ContainerSince > t0.Add(500*time.Millisecond).UnixNano() {
		t.Errorf("script since = %d / %d", sp.JournalSince, sp.ContainerSince)
	}
	w := p.Window(b.collect(p.Params()), Settle)
	if got := render(w.Lines); fmt.Sprint(got) != "[500ms nginx.service new-j 600ms web new-d]" {
		t.Errorf("since = %v", got)
	}
}

// Criterion 3: unit and container filters select sources; the journal is
// filtered in the box (journalctl -u), containers by name in the daemon.
func TestWindow_Filters(t *testing.T) {
	b := newSim()
	b.addJournal(t0.Add(1*time.Millisecond), 0, "nginx.service", "nginx")
	b.addJournal(t0.Add(2*time.Millisecond), 0, "cron.service", "cron")
	b.addDocker(0, t0.Add(3*time.Millisecond), 0, "web")
	b.addDocker(1, t0.Add(4*time.Millisecond), 0, "worker")
	b.now = t0.Add(time.Minute)
	cases := []struct {
		name       string
		units, cts []string
		want       string
		wantJ      bool
	}{
		{"none", nil, nil, "[nginx cron web worker]", true},
		{"unit", []string{"nginx"}, nil, "[nginx]", true},
		{"unit with suffix", []string{"cron.service"}, nil, "[cron]", true},
		{"container", nil, []string{"worker"}, "[worker]", false},
		{"both", []string{"nginx"}, []string{"web"}, "[nginx web]", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustPrepare(t, Request{Since: t0, Units: tc.units, Containers: tc.cts})
			sp := p.Params()
			if sp.ReadJournal != tc.wantJ {
				t.Errorf("ReadJournal = %v, want %v", sp.ReadJournal, tc.wantJ)
			}
			c := b.collect(sp)
			if err := p.CheckFilter(c); err != nil {
				t.Fatalf("CheckFilter: %v", err)
			}
			w := p.Window(c, Settle)
			var got []string
			for _, l := range w.Lines {
				got = append(got, l.Text)
			}
			if fmt.Sprint(got) != tc.want {
				t.Errorf("lines = %v, want %s", got, tc.want)
			}
		})
	}
}

// Criterion 3: a filter naming no unit or container in the box is an
// argument error that lists the valid names.
func TestCheckFilter_UnknownNameListsValid(t *testing.T) {
	b := newSim()
	cases := []struct {
		name       string
		units, cts []string
		wantInMsg  []string
	}{
		{"unknown unit", []string{"postgres"}, nil, []string{`"postgres.service"`, "cron.service", "nginx.service"}},
		{"unknown container", nil, []string{"db"}, []string{`"db"`, "web", "worker"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustPrepare(t, Request{Units: tc.units, Containers: tc.cts})
			err := p.CheckFilter(b.collect(p.Params()))
			var ae *ArgError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %v, want *ArgError", err)
			}
			for _, s := range tc.wantInMsg {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("error %q does not mention %s", err, s)
				}
			}
		})
	}
}

// Request validation: anything that would reach the script is checked, and
// bounds are enforced, before any exec.
func TestPrepare_Validation(t *testing.T) {
	good := EncodeCursor(Cursor{V: 1, Horizon: 1})
	cases := []struct {
		name string
		r    Request
	}{
		{"unit with a quote", Request{Units: []string{"a'b"}}},
		{"unit with a space", Request{Units: []string{"a b"}}},
		{"unit glob", Request{Units: []string{"ngin*"}}},
		{"unit option", Request{Units: []string{"--merge"}}},
		{"unit empty", Request{Units: []string{""}}},
		{"unit too long", Request{Units: []string{strings.Repeat("a", 200)}}},
		{"too many units", Request{Units: strings.Split(strings.Repeat("a,", MaxFilterNames+1), ",")[:MaxFilterNames+1]}},
		{"container name hostile", Request{Containers: []string{"$(reboot)"}}},
		{"too many containers", Request{Containers: strings.Split(strings.Repeat("a,", MaxFilterNames+1), ",")[:MaxFilterNames+1]}},
		{"negative tail", Request{Tail: -1}},
		{"tail too big", Request{Tail: MaxLinesLimit + 1}},
		{"negative max_lines", Request{MaxLines: -1}},
		{"cursor and since", Request{Cursor: good, Since: t0}},
		{"cursor and tail", Request{Cursor: good, Tail: 5}},
		{"bad cursor", Request{Cursor: "garbage!"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Prepare(tc.r)
			var ae *ArgError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %v, want *ArgError", err)
			}
		})
	}
	p := mustPrepare(t, Request{MaxLines: 5000})
	if p.MaxLines != MaxLinesLimit {
		t.Errorf("max_lines clamps to %d, got %d", MaxLinesLimit, p.MaxLines)
	}
	if p = mustPrepare(t, Request{}); p.MaxLines != MaxLinesDefault {
		t.Errorf("default max_lines = %d", p.MaxLines)
	}
}

// Criterion 5: a window never exceeds its caps, however long the lines.
func TestWindow_Caps(t *testing.T) {
	b := newSim()
	long := strings.Repeat("x", TextCap)
	for i := 0; i < MaxLinesLimit; i++ {
		b.addDocker(0, t0.Add(time.Duration(i)*time.Millisecond), 0, long)
	}
	b.now = t0.Add(time.Hour)
	p := mustPrepare(t, Request{Since: t0, MaxLines: MaxLinesLimit})
	total, windows := 0, 0
	for windows < 50 {
		w := p.Window(b.collect(p.Params()), Settle)
		size := 0
		for _, l := range w.Lines {
			size += len(l.Text)
		}
		if size > WindowTextBudget || len(w.Lines) > MaxLinesLimit {
			t.Fatalf("window of %d lines / %d bytes over the caps", len(w.Lines), size)
		}
		total += len(w.Lines)
		windows++
		if len(w.Lines) == 0 {
			break
		}
		if !w.More && total < MaxLinesLimit {
			t.Errorf("window %d stopped at the byte budget without More", windows)
		}
		p = p.Next(w.Cursor)
	}
	if total != MaxLinesLimit {
		t.Errorf("read %d lines over %d windows, want %d", total, windows, MaxLinesLimit)
	}
}

// Lines inside the settle margin are held back until a slower source has
// had time to deliver, not emitted ahead of an earlier line.
func TestWindow_SettleHoldsBackRecentLines(t *testing.T) {
	b := newSim()
	b.addDocker(0, t0.Add(100*time.Millisecond), 0, "early")
	b.addJournal(t0.Add(900*time.Millisecond), 0, "nginx.service", "recent")
	b.now = t0.Add(1200 * time.Millisecond)
	p := mustPrepare(t, Request{Since: t0})
	w := p.Window(b.collect(p.Params()), Settle)
	if got := render(w.Lines); fmt.Sprint(got) != "[100ms web early]" {
		t.Errorf("first window = %v", got)
	}
	// A late container line stamped before the held-back journal line.
	b.addDocker(1, t0.Add(800*time.Millisecond), 300*time.Millisecond, "late")
	b.now = t0.Add(3 * time.Second)
	p = p.Next(w.Cursor)
	w = p.Window(b.collect(p.Params()), Settle)
	if got := render(w.Lines); fmt.Sprint(got) != "[800ms worker late 900ms nginx.service recent]" {
		t.Errorf("second window = %v", got)
	}
}
