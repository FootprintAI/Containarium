package boxlogs

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCursor_RoundTrip(t *testing.T) {
	c := Cursor{V: 1, Horizon: 1762862400000000000, Journal: jcur(42),
		Containers: map[string]Pos{testID0: {T: 1762862400000000001, N: 2}, testID1: {T: 5, All: true}}}
	s := EncodeCursor(c)
	if s == "" || strings.ContainsAny(s, "+/= ") {
		t.Fatalf("cursor %q is not URL-safe", s)
	}
	got, err := DecodeCursor(s)
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}
	if got.Horizon != c.Horizon || got.Journal != c.Journal || got.Containers[testID0] != c.Containers[testID0] || got.Containers[testID1] != c.Containers[testID1] {
		t.Errorf("round trip = %+v, want %+v", got, c)
	}
}

// The cursor comes back from the caller: everything in it is checked before
// any of it reaches the script.
func TestCursor_RejectsHostile(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	many := `{"v":1,"h":1,"c":{`
	for i := 0; i < MaxContainers*2+1; i++ {
		if i > 0 {
			many += ","
		}
		many += `"` + strings.Repeat(string("0123456789abcdef"[i%16]), 63) + string("0123456789abcdef"[i/16]) + `":{"t":1}`
	}
	many += "}}"
	cases := map[string]string{
		"not base64":           "!!!",
		"not JSON":             enc("{"),
		"wrong version":        enc(`{"v":2,"h":1}`),
		"no version":           enc(`{"h":1}`),
		"negative horizon":     enc(`{"v":1,"h":-1}`),
		"journal cursor shell": enc(`{"v":1,"h":1,"j":"s=x';reboot;'"}`),
		"journal cursor space": enc(`{"v":1,"h":1,"j":"` + jcur(1) + ` --merge"}`),
		"container id not hex": enc(`{"v":1,"h":1,"c":{"../etc":{"t":1}}}`),
		"container id short":   enc(`{"v":1,"h":1,"c":{"abc":{"t":1}}}`),
		"negative position":    enc(`{"v":1,"h":1,"c":{"` + testID0 + `":{"t":-1}}}`),
		"negative count":       enc(`{"v":1,"h":1,"c":{"` + testID0 + `":{"t":1,"n":-1}}}`),
		"unknown field":        enc(`{"v":1,"h":1,"x":"y"}`),
		"too many containers":  enc(many),
		"too long":             strings.Repeat("A", MaxCursorLen+1),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCursor(s); err == nil {
				t.Fatalf("DecodeCursor(%.40q) accepted a hostile cursor", s)
			}
		})
	}
}

func TestValidJournalCursor(t *testing.T) {
	for _, s := range []string{jcur(1), jcur(1 << 40)} {
		if !ValidJournalCursor(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "s=1", jcur(1) + ";", jcur(1) + "\n", "-s=" + jcur(1), strings.ToUpper(jcur(1))} {
		if ValidJournalCursor(s) {
			t.Errorf("%q accepted", s)
		}
	}
}
