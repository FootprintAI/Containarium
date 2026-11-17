package guardrailhook

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A tool result has no schema the handler can rely on: every tool has its
// own shape and a new tool can appear in any agent release. So the result is
// decoded once into Go's generic JSON tree and wrapped straight away by the
// walker below, which is the only code that touches the untyped values. It
// hands the rest of the package typed units of text.

// unit is one piece of text to scan: a single string leaf, or an array of
// strings (a file held as lines) scanned joined with "\n" so a value that
// spans lines is seen whole.
type unit struct {
	lines []string
	// set writes line i back into the tree.
	set func(i int, s string)
	// dirty flags every embedded JSON document this unit sits inside, so
	// each one is re-encoded if, and only if, something in it changed.
	dirty []*bool
	// fixed is non-empty for text that is scanned but must not be replaced,
	// and says what it is. A marker is a string: putting one in place of a
	// number, or renaming an object key, changes the shape of a tool's
	// result, and the agent then rejects the whole replacement. See walk.
	fixed string
}

func (u *unit) text() string { return strings.Join(u.lines, "\n") }

// structuralFields is the per-tool allowlist of string fields that cannot
// carry outside content: enum-like discriminators. It is an optimisation,
// never a requirement, and it only ever applies to the tool it is listed
// under. Paths and file names are content and must not appear here: a tool
// echoes the real path back after a marker in it was restored.
var structuralFields = map[string]map[string]bool{
	"Read":  {"type": true},
	"Write": {"type": true},
}

// verbatimTextTools return a file's or a command's text as it is. A string
// from one of them that happens to be JSON is scanned as text, so a redacted
// copy differs from the original only at the redacted spans and a follow-up
// edit still matches the file. Every other tool's JSON-in-a-string is
// decoded first (see leaf).
var verbatimTextTools = map[string]bool{
	"Read": true, "Edit": true, "Write": true, "NotebookEdit": true, "Bash": true, "PowerShell": true,
}

// binaryMinLen is the length from which a string made only of base64
// characters is taken to be encoded binary, not text.
const binaryMinLen = 256

type walker struct {
	tool          string
	units         []*unit
	skippedBinary int64
	// finalizers re-encode embedded JSON documents, innermost first.
	finalizers []func() error
}

// decodeTree decodes one JSON value, keeping numbers exactly as written.
func decodeTree(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, io.ErrUnexpectedEOF
	}
	return v, nil
}

// walk collects the units under v. key is the object field v sits in ("" at
// the root); set replaces v in its parent.
//
// Redaction never changes a JSON type or an object's keys in the result's
// own structure: only string values are replaced there, by strings. A
// finding in a number or in a key of that structure is recorded and left.
// Inside an embedded JSON document (a string that holds JSON) both are
// rewritten, because the container stays the string it was.
func (w *walker) walk(v any, key string, set func(any), dirty []*bool) {
	// Every embedded document adds one flag; the first is the root's.
	embedded := len(dirty) > 1
	switch t := v.(type) {
	case string:
		w.leaf(t, key, set, dirty)
	case []any:
		if lines, ok := stringLines(t); ok && !w.structural(key) {
			w.units = append(w.units, &unit{lines: lines, set: func(i int, s string) { t[i] = s }, dirty: dirty})
			return
		}
		for i := range t {
			w.walk(t[i], key, func(nv any) { t[i] = nv }, dirty)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		for _, k := range sortedStrings(keys) {
			// A key is text the model reads too (an email keying a map, say).
			// It is renamed when redacted, so the value's setter follows the
			// key's current name.
			name := k
			if k != "" && !isBinary(k) {
				w.units = append(w.units, &unit{lines: []string{k}, fixed: fixedUnless(embedded, "an object key"), set: func(_ int, nk string) {
					v := t[name]
					delete(t, name)
					name = freeKey(t, nk)
					t[name] = v
				}, dirty: dirty})
			}
			w.walk(t[k], k, func(nv any) { t[name] = nv }, dirty)
		}
	case json.Number:
		// A card or phone number can be a JSON number. Inside an embedded
		// document it becomes a marker string when redacted.
		w.units = append(w.units, &unit{lines: []string{t.String()}, fixed: fixedUnless(embedded, "a number"), set: func(_ int, ns string) { set(ns) }, dirty: dirty})
	}
	// Booleans and null carry no text.
}

func fixedUnless(embedded bool, what string) string {
	if embedded {
		return ""
	}
	return what
}

// freeKey returns k, or k with a numeric suffix when t already has k: two
// keys that redact to the same marker keep both values.
func freeKey(t map[string]any, k string) string {
	for n, c := 2, k; ; n, c = n+1, k+"#"+strconv.Itoa(n) {
		if _, taken := t[c]; !taken {
			return c
		}
	}
}

func (w *walker) leaf(s, key string, set func(any), dirty []*bool) {
	if s == "" || w.structural(key) {
		return
	}
	if isBinary(s) {
		w.skippedBinary++
		return
	}
	if !verbatimTextTools[w.tool] {
		// Some tools hand their whole result over as one JSON string. Scanned
		// as text, a multi-line value inside it is broken up by escapes and
		// separators, so decode it and walk it like any other result.
		if sub, ok := embeddedJSON(s); ok {
			changed := new(bool)
			inner := append(append([]*bool{}, dirty...), changed)
			w.walk(sub, "", func(nv any) { sub = nv }, inner)
			w.finalizers = append(w.finalizers, func() error {
				if !*changed {
					return nil
				}
				b, err := marshalJSON(sub)
				if err == nil {
					set(string(b))
				}
				return err
			})
			return
		}
	}
	w.units = append(w.units, &unit{lines: []string{s}, set: func(_ int, ns string) { set(ns) }, dirty: dirty})
}

func (w *walker) structural(key string) bool { return structuralFields[w.tool][key] }

// stringLines reports whether arr is two or more strings and nothing else.
func stringLines(arr []any) ([]string, bool) {
	if len(arr) < 2 {
		return nil, false
	}
	lines := make([]string, len(arr))
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		lines[i] = s
	}
	return lines, true
}

// embeddedJSON decodes s if it is a JSON object or array.
func embeddedJSON(s string) (any, bool) {
	t := strings.TrimSpace(s)
	if t == "" || (t[0] != '{' && t[0] != '[') {
		return nil, false
	}
	v, err := decodeTree([]byte(t))
	if err != nil {
		return nil, false
	}
	return v, true
}

// isBinary reports whether s is binary or encoded binary: not text an
// engine can judge. Such a leaf is skipped and counted, never passed off as
// scanned.
func isBinary(s string) bool {
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return true
	}
	if strings.HasPrefix(s, "data:") && strings.Contains(s[:min(len(s), 128)], ";base64,") {
		return true
	}
	if len(s) < binaryMinLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=', c == '-', c == '_', c == '\n', c == '\r':
		default:
			return false
		}
	}
	return true
}

func sortedStrings(s []string) []string {
	sort.Strings(s)
	return s
}
