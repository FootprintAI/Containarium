package boxlogs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// journalCursorPattern is the cursor journald prints: s= seqnum id, i=
// seqnum, b= boot id, m= monotonic, t= realtime, x= xor hash. Nothing else
// is ever passed to journalctl --after-cursor.
var journalCursorPattern = regexp.MustCompile(`^s=[0-9a-f]{32};i=[0-9a-f]{1,16};b=[0-9a-f]{32};m=[0-9a-f]{1,16};t=[0-9a-f]{1,16};x=[0-9a-f]{1,16}$`)

// ValidJournalCursor reports whether s is a journald cursor.
func ValidJournalCursor(s string) bool { return journalCursorPattern.MatchString(s) }

// cursorVersion is the cursor format this package reads and writes.
const cursorVersion = 1

// Pos is how far a container's log has been consumed: every line stamped
// before T, and the first N lines stamped exactly T (all of them when All).
type Pos struct {
	T   int64 `json:"t"`
	N   int   `json:"n,omitempty"`
	All bool  `json:"a,omitempty"`
}

// covers reports whether a line at time t, the k-th (from 0) at that time in
// read order, was consumed.
func (p Pos) covers(t int64, k int) bool {
	return t < p.T || (t == p.T && (p.All || k < p.N))
}

// Cursor is the resume point a window hands back, opaque to callers.
type Cursor struct {
	V int `json:"v"`
	// Horizon: every line stamped at or before it was consumed, from every
	// source without its own position below.
	Horizon int64 `json:"h"`
	// Journal is the cursor of the last consumed journal entry; the next
	// read starts after it. Empty: the journal is consumed up to Horizon.
	Journal string `json:"j,omitempty"`
	// JournalAt resumes at the Journal entry itself rather than after it:
	// set when a window consumed nothing before that entry.
	JournalAt bool `json:"ja,omitempty"`
	// Containers holds the positions of containers consumed past, or short
	// of, Horizon, by full container id.
	Containers map[string]Pos `json:"c,omitempty"`
}

// pos is the consumption point of container id.
func (c Cursor) pos(id string) Pos {
	if p, ok := c.Containers[id]; ok {
		return p
	}
	return Pos{T: c.Horizon, All: true}
}

// EncodeCursor renders c as an opaque URL-safe string.
func EncodeCursor(c Cursor) string {
	c.V = cursorVersion
	data, err := json.Marshal(c)
	if err != nil { // a struct of ints, strings and a map: cannot fail
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeCursor parses a cursor a caller passed back. It is caller input, so
// every field is checked: only a well-formed journal cursor and hex
// container ids survive.
func DecodeCursor(s string) (Cursor, error) {
	var c Cursor
	if len(s) > MaxCursorLen {
		return c, errors.New("cursor too long")
	}
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return c, errors.New("cursor is not one a previous response returned")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Cursor{}, errors.New("cursor is not one a previous response returned")
	}
	switch {
	case c.V != cursorVersion:
		return Cursor{}, fmt.Errorf("cursor version %d is not supported", c.V)
	case c.Horizon < 0:
		return Cursor{}, errors.New("cursor horizon is negative")
	case c.Journal != "" && !ValidJournalCursor(c.Journal):
		return Cursor{}, errors.New("cursor holds an invalid journal cursor")
	case c.JournalAt && c.Journal == "":
		return Cursor{}, errors.New("cursor resumes at no journal entry")
	case len(c.Containers) > MaxContainers:
		return Cursor{}, errors.New("cursor holds too many containers")
	}
	for id, p := range c.Containers {
		if !containerIDPattern.MatchString(id) || p.T < 0 || p.N < 0 {
			return Cursor{}, errors.New("cursor holds an invalid container position")
		}
	}
	return c, nil
}
