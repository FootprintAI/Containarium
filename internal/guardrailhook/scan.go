package guardrailhook

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// markerRE matches a placeholder, [[EMAIL:1a2b3c4d5e6f]]: the form the
// dataset flow writes (internal/guardrail/redact.go).
var markerRE = regexp.MustCompile(`\[\[([A-Z0-9_]+):[0-9a-f]{12}\]\]`)

// scanKinds is what every scan asks for. Never empty: by contract an empty
// list means "whatever the engine has enabled", and an engine that cannot
// cover one of these must refuse, not scan the rest.
var scanKinds = []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII, pb.GuardrailKind_GUARDRAIL_KIND_SECRET}

// excerptContext is how many code points of redacted text an excerpt keeps
// on each side of the marker.
const excerptContext = 24

type span struct {
	start, end int
	kind       pb.GuardrailKind
	typ        string
	conf       float64
}

// hit is one span that was (or, for an event that cannot rewrite, would
// be) replaced by a marker.
type hit struct {
	kind    pb.GuardrailKind
	typ     string
	excerpt string
}

// scanned is the outcome of scanning one value.
type scanned struct {
	hits []hit
	// partial says why the text got the pattern pass only; "" for a full
	// scan.
	partial       string
	skippedBinary int64
}

// scanMode says what a scan may do.
type scanMode struct {
	// strict fails when the engine does. Without it the scan falls back to
	// the in-process pattern pass and says so: right when the text reaches
	// the model whatever the handler does, wrong when the handler can still
	// stop it.
	strict bool
	// rewrite writes markers into the units and remembers them.
	rewrite bool
}

// ready reports whether the engine answers and covers the kinds, waiting up
// to EngineWait for it.
func (h *Handler) ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, h.cfg.EngineWait)
	defer cancel()
	_, err := h.cfg.Engine.Scan(ctx, &pb.GuardrailScanRequest{
		Units: []*pb.GuardrailTextUnit{{UnitId: "ready"}},
		Kinds: scanKinds,
	})
	return err
}

// scanUnits finds and marks what is sensitive in units.
func (c *call) scanUnits(ctx context.Context, units []*unit, mode scanMode) (*scanned, error) {
	res := &scanned{}
	if len(units) == 0 {
		return res, nil
	}
	req := &pb.GuardrailScanRequest{Kinds: scanKinds}
	total := 0
	for i, u := range units {
		text := u.text()
		total += len(text)
		req.Units = append(req.Units, &pb.GuardrailTextUnit{UnitId: strconv.Itoa(i), Text: text})
	}

	var byUnit map[int][]span
	var err error
	if total > c.h.cfg.FullScanMaxBytes {
		res.partial = fmt.Sprintf("%d bytes is over the %d byte full-scan limit", total, c.h.cfg.FullScanMaxBytes)
	} else {
		sctx, cancel := context.WithTimeout(ctx, c.h.cfg.ScanTimeout)
		byUnit, err = findSpans(sctx, c.h.cfg.Engine, req)
		cancel()
		if err != nil {
			if mode.strict {
				return nil, fmt.Errorf("guardrail engine: %w", err)
			}
			res.partial = "the engine did not return a usable scan"
		}
	}
	if res.partial != "" {
		if byUnit, err = findSpans(ctx, c.h.fast, req); err != nil {
			return nil, fmt.Errorf("guardrail pattern pass: %w", err)
		}
	}
	for i, u := range units {
		res.hits = append(res.hits, c.mark(u, byUnit[i], mode.rewrite)...)
	}
	return res, nil
}

// findSpans runs one scan and returns merged, validated spans per unit
// index. A gap is an error: "no findings" from an engine that did not look
// is not "clean".
func findSpans(ctx context.Context, engine guardrail.Engine, req *pb.GuardrailScanRequest) (map[int][]span, error) {
	resp, err := engine.Scan(ctx, req)
	if err != nil {
		return nil, err
	}
	if n := len(resp.GetGaps()); n > 0 {
		return nil, fmt.Errorf("%d unit(s) could not be scanned", n)
	}
	out := map[int][]span{}
	for _, f := range resp.GetFindings() {
		i, err := strconv.Atoi(f.GetUnitId())
		if err != nil || i < 0 || i >= len(req.GetUnits()) {
			return nil, fmt.Errorf("finding names unknown unit %q", f.GetUnitId())
		}
		s := span{int(f.GetStart()), int(f.GetEnd()), f.GetKind(), f.GetType(), f.GetConfidence()}
		if s.start < 0 || s.start >= s.end || s.end > utf8.RuneCountInString(req.GetUnits()[i].GetText()) {
			return nil, errors.New("finding is out of range for its unit")
		}
		out[i] = append(out[i], s)
	}
	for i, spans := range out {
		out[i] = mergeSpans(dropInsideMarkers(req.GetUnits()[i].GetText(), spans))
	}
	return out, nil
}

// dropInsideMarkers removes findings that lie inside a marker: a detector
// reading its own placeholder is not a finding (the dataset gate does the
// same).
func dropInsideMarkers(text string, spans []span) []span {
	locs := markerRE.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return spans
	}
	kept := spans[:0]
	for _, s := range spans {
		inside := false
		for _, l := range locs {
			if s.start >= utf8.RuneCountInString(text[:l[0]]) && s.end <= utf8.RuneCountInString(text[:l[1]]) {
				inside = true
				break
			}
		}
		if !inside {
			kept = append(kept, s)
		}
	}
	return kept
}

// mergeSpans collapses overlapping or touching spans; the survivor takes
// the higher-confidence member's kind and type.
func mergeSpans(in []span) []span {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].start != in[j].start {
			return in[i].start < in[j].start
		}
		return in[i].end > in[j].end
	})
	out := []span{in[0]}
	for _, s := range in[1:] {
		last := &out[len(out)-1]
		if s.start > last.end {
			out = append(out, s)
			continue
		}
		last.end = max(last.end, s.end)
		if s.conf > last.conf {
			last.kind, last.typ, last.conf = s.kind, s.typ, s.conf
		}
	}
	return out
}

// mark replaces each span of u with its marker. Offsets are code points
// into the unit's lines joined with "\n". A span that covers several lines
// puts the same marker in place of its part of each line, so an array of
// lines keeps its length.
func (c *call) mark(u *unit, spans []span, rewrite bool) []hit {
	if len(spans) == 0 {
		return nil
	}
	joined := []rune(u.text())
	tokens := make([]string, len(spans))
	for i, s := range spans {
		value := string(joined[s.start:s.end])
		tokens[i] = guardrail.Token(c.state.key, s.kind, s.typ, value)
		if rewrite {
			// Only personal data gets its value recorded. Anything else is
			// redacted and never stored.
			e := guardrail.VaultEntry{Kind: s.kind, Type: s.typ}
			if s.kind == pb.GuardrailKind_GUARDRAIL_KIND_PII {
				e.Value = value
			}
			c.state.remember(tokens[i], e)
		}
	}
	marked := make([]string, len(u.lines))
	lo := 0
	for li, line := range u.lines {
		hi := lo + utf8.RuneCountInString(line)
		var b strings.Builder
		pos := lo
		for i, s := range spans {
			from, to := max(s.start, lo), min(s.end, hi)
			if from >= to {
				continue
			}
			b.WriteString(string(joined[pos:from]))
			b.WriteString(tokens[i])
			pos = to
		}
		b.WriteString(string(joined[pos:hi]))
		marked[li] = b.String()
		if rewrite && marked[li] != line {
			u.set(li, marked[li])
			for _, d := range u.dirty {
				*d = true
			}
		}
		lo = hi + 1 // the "\n" that joined this line to the next
	}
	after := strings.Join(marked, "\n")
	hits := make([]hit, len(spans))
	for i, s := range spans {
		hits[i] = hit{kind: s.kind, typ: s.typ, excerpt: excerpt(after, tokens[i])}
	}
	return hits
}

// excerpt is a short window of already-redacted text around token.
func excerpt(redacted, token string) string {
	at := strings.Index(redacted, token)
	if at < 0 {
		return token
	}
	before, after := []rune(redacted[:at]), []rune(redacted[at+len(token):])
	before = before[max(0, len(before)-excerptContext):]
	after = after[:min(len(after), excerptContext)]
	return strings.Join(strings.Fields(string(before)+token+string(after)), " ")
}

// scanValue walks one JSON value from tool (a result, or a prompt as a JSON
// string) and scans every unit in it. With mode.rewrite it returns the
// redacted value when anything changed, nil otherwise.
func (c *call) scanValue(ctx context.Context, tool string, raw []byte, mode scanMode) ([]byte, *scanned, error) {
	tree, err := decodeTree(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("hook input holds an invalid JSON value: %w", err)
	}
	w := &walker{tool: tool}
	rootChanged := new(bool)
	w.walk(tree, "", func(nv any) { tree = nv }, []*bool{rootChanged})
	res, err := c.scanUnits(ctx, w.units, mode)
	if err != nil {
		return nil, nil, err
	}
	res.skippedBinary = w.skippedBinary
	if !*rootChanged {
		return nil, res, nil
	}
	for _, fin := range w.finalizers {
		if err := fin(); err != nil {
			return nil, nil, err
		}
	}
	out, err := marshalJSON(tree)
	return out, res, err
}

// recordScan writes one row per hit, plus the coverage rows.
func (c *call) recordScan(tool string, source pb.GuardrailHookSource, outcome pb.GuardrailHookOutcome, res *scanned) {
	for _, h := range res.hits {
		c.record(&pb.GuardrailHookRecord{ToolName: tool, Source: source, Outcome: outcome, Kind: h.kind, Type: h.typ, Excerpt: h.excerpt})
	}
	if res.partial != "" {
		c.record(&pb.GuardrailHookRecord{ToolName: tool, Source: source,
			Outcome: pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_PARTIALLY_SCANNED, Detail: res.partial})
	}
	if res.skippedBinary > 0 {
		c.record(&pb.GuardrailHookRecord{ToolName: tool, Source: source,
			Outcome: pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_SKIPPED_BINARY, Count: res.skippedBinary})
	}
}

// hitTypes lists the distinct finding types, for a reason shown to a
// person. Types only: a reason never carries a value.
func hitTypes(hits []hit) string {
	seen := map[string]bool{}
	var types []string
	for _, h := range hits {
		if !seen[h.typ] {
			seen[h.typ] = true
			types = append(types, h.typ)
		}
	}
	return strings.Join(sortedStrings(types), ", ")
}
