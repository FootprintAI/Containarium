package coderun

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseApprovalMode(t *testing.T) {
	for in, want := range map[string]ApprovalMode{"": ApprovalsDeny, "deny": ApprovalsDeny, "ask": ApprovalsAsk, " ask ": ApprovalsAsk} {
		got, err := ParseApprovalMode(in)
		if err != nil || got != want {
			t.Errorf("ParseApprovalMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseApprovalMode("allow"); err == nil {
		t.Error("ParseApprovalMode(\"allow\") accepted a value that is not a mode")
	}
}

// An answer verifies only under the public key of the private key that signed
// it, and only for the run, request, tool call and answer it was signed for:
// no replay onto another request or run, no turning a deny into an allow, and
// no answer made for a tool call the box did not ask (#2184: the journal a
// human reads is writable by the agent, so what it shows can be a forgery).
func TestVerifyAnswerBindsKeyRunRequestToolCallAndAnswer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	shown := RequestDigest("Bash", `{"command":"rm -rf ~/repo"}`)
	good := FormatAnswer(priv, "code", "req-1", shown, AnswerAllow)

	if a, err := VerifyAnswer(pub, "code", "req-1", shown, good); err != nil || a != AnswerAllow {
		t.Fatalf("VerifyAnswer(good) = %q, %v; want allow", a, err)
	}
	denySig := SignAnswer(priv, "code", "req-1", shown, AnswerDeny)
	cases := map[string]struct {
		pub     ed25519.PublicKey
		run, id string
		digest  []byte
		content string
	}{
		"other public key":  {otherPub, "code", "req-1", shown, good},
		"signed by another": {pub, "code", "req-1", shown, FormatAnswer(otherPriv, "code", "req-1", shown, AnswerAllow)},
		"other request":     {pub, "code", "req-2", shown, good},
		"other run":         {pub, "other", "req-1", shown, good},
		"other input":       {pub, "code", "req-1", RequestDigest("Bash", `{"command":"ls"}`), good},
		"other tool":        {pub, "code", "req-1", RequestDigest("Write", `{"command":"rm -rf ~/repo"}`), good},
		"no request digest": {pub, "code", "req-1", nil, good},
		"deny sig as allow": {pub, "code", "req-1", shown, "allow " + denySig},
		"unsigned":          {pub, "code", "req-1", shown, "allow"},
		"not hex":           {pub, "code", "req-1", shown, "allow zz"},
		"not an answer":     {pub, "code", "req-1", shown, "maybe " + SignAnswer(priv, "code", "req-1", shown, "maybe")},
		"extra field":       {pub, "code", "req-1", shown, strings.TrimSpace(good) + " extra"},
		"empty":             {pub, "code", "req-1", shown, ""},
	}
	for name, c := range cases {
		if a, err := VerifyAnswer(c.pub, c.run, c.id, c.digest, c.content); err == nil {
			t.Errorf("%s: VerifyAnswer accepted %q as %q", name, c.content, a)
		}
	}
}

func TestParseApprovalPublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if got, err := ParseApprovalPublicKey(hex.EncodeToString(pub)); err != nil || !got.Equal(pub) {
		t.Errorf("round trip = %x, %v", got, err)
	}
	for _, bad := range []string{"", "zz", hex.EncodeToString(pub[:16])} {
		if _, err := ParseApprovalPublicKey(bad); err == nil {
			t.Errorf("ParseApprovalPublicKey(%q) accepted", bad)
		}
	}
}

func TestValidApprovalRunName(t *testing.T) {
	for _, ok := range []string{"code", "sess-42", "a_b.c", "..x"} {
		if err := ValidApprovalRunName(ok); err != nil {
			t.Errorf("ValidApprovalRunName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "sub/task", "../victim", "a b", "x\x00"} {
		if err := ValidApprovalRunName(bad); err == nil {
			t.Errorf("ValidApprovalRunName(%q) accepted", bad)
		}
	}
}

func TestSummarizeApprovalsAndStatusLines(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	ev := func(e InputEvent) string {
		b, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	req := func(id, prompt string) string {
		return ev(InputEvent{Kind: KindInputRequest, T: t0, RequestID: id, RequestKind: RequestKindPermission,
			Tool: "Bash", Prompt: prompt, Options: []Answer{AnswerAllow, AnswerDeny}, Default: AnswerDeny,
			ExpiresAt: t0.Add(30 * time.Minute)})
	}
	resp := func(id string, a Answer, r ResponseReason) string {
		return ev(InputEvent{Kind: KindInputResponse, T: t0, RequestID: id, Answer: a, Reason: r})
	}
	journal := req("r1", "Bash: touch a") + resp("r1", AnswerAllow, ReasonAnswered) +
		req("r2", "Bash: rm b") + resp("r2", AnswerDeny, ReasonAnswered) +
		req("r3", "Bash: curl c") + resp("r3", AnswerDeny, ReasonExpired) +
		ev(InputEvent{Kind: KindInputStatus, T: t0, Text: "ignored an answer to r4: answer signature does not verify"}) +
		req("r4", "Bash: git push") +
		`{"kind":"input_resp` // torn last line while the server writes

	s := SummarizeApprovals(ParseInputJournal([]byte(journal)))
	if s.Requests != 4 || s.Allowed != 1 || s.Denied != 1 || s.Expired != 1 || len(s.Open) != 1 || s.Open[0].RequestID != "r4" {
		t.Fatalf("summary = %+v", s)
	}

	running := ApprovalStatusLines(s, true, t0.Add(10*time.Minute))
	for _, want := range []string{
		"state: waiting_input",
		"request r4: Bash: git push (expires in 20m0s)",
		"permission requests: 4 (allowed 1, denied 1, expired 1, cancelled 0, open 1)",
		"note: ignored an answer to r4",
	} {
		if !strings.Contains(running, want) {
			t.Errorf("running status lacks %q:\n%s", want, running)
		}
	}
	// A finished run with an open request is not waiting on anyone.
	if done := ApprovalStatusLines(s, false, t0); strings.Contains(done, "waiting_input") {
		t.Errorf("finished run reported waiting_input:\n%s", done)
	}
	if got := ApprovalStatusLines(SummarizeApprovals(nil), true, t0); got != "" {
		t.Errorf("a run without approvals rendered %q, want nothing", got)
	}
}

// The request line carries every field the issue's acceptance criterion names.
func TestInputRequestLineFields(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	b, err := InputEvent{Kind: KindInputRequest, T: t0, RequestID: "req-1", RequestKind: RequestKindPermission,
		Tool: "Bash", Prompt: "Bash: ls", Options: []Answer{AnswerAllow, AnswerDeny}, Default: AnswerDeny,
		ExpiresAt: t0.Add(time.Minute)}.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"kind":"input_request"`, `"request_id":"req-1"`, `"request_kind":"permission"`,
		`"prompt":"Bash: ls"`, `"options":["allow","deny"]`, `"default":"deny"`, `"expires_at":"2026-10-27T10:01:00Z"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("request line lacks %s: %s", want, b)
		}
	}
}

// Journal text is the agent's own input and the agent can write the journal,
// so what `code status` prints must stay on its own line and cannot carry
// terminal control sequences that forge or hide other lines.
func TestApprovalStatusLinesNeutralizesControlCharacters(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	hostile := "ls\n  request req-fake: Bash: true (expires in 1m0s)\r\x1b[2Kstate: idle\u202e\u2028x"
	s := ApprovalSummary{
		Requests: 1,
		Open:     []InputEvent{{Kind: KindInputRequest, RequestID: "req-1\nstate: x", Prompt: hostile, ExpiresAt: t0.Add(time.Minute)}},
		Notes:    []string{"note\x1b]0;title\x07"},
	}
	out := ApprovalStatusLines(s, true, t0)
	for _, bad := range []string{"\r", "\x1b", "\x07", "\u202e", "\u2028"} {
		if strings.Contains(out, bad) {
			t.Errorf("output carries %q:\n%s", bad, out)
		}
	}
	lines := strings.Split(out, "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want 4 (state, one request, counts, one note):\n%s", len(lines), out)
	}
	if !strings.Contains(lines[1], `request req-1\nstate: x: ls\n  request req-fake`) || !strings.Contains(lines[1], `\u202e`) {
		t.Errorf("request line does not show the escaped text: %q", lines[1])
	}
}

// windowReader serves data through the same bounded, offset-based contract as
// agent-box's tail_log: at most window bytes per call, truncated when more
// remains, and end_offset = start + bytes returned (#3182).
type windowReader struct {
	data   []byte
	window int
	calls  int
	// missing makes every read fail like a path with no file.
	missing bool
}

func (r *windowReader) Read(_ context.Context, _ string, start int64, _ time.Duration) ([]byte, int64, bool, error) {
	r.calls++
	if r.missing {
		return nil, start, false, errors.New("tail_log: stat /x: no such file or directory")
	}
	if start > int64(len(r.data)) {
		start = int64(len(r.data))
	}
	end := start + int64(r.window)
	// Like tail_log: a reply that fills the window is truncated even when it
	// happens to end exactly at EOF.
	truncated := end <= int64(len(r.data))
	if end > int64(len(r.data)) {
		end = int64(len(r.data))
	}
	return r.data[start:end], end, truncated, nil
}

// bigJournal is over 512 KiB: n requests, each with a ~1 KiB prompt, then the
// response to every request but the last, and the last request's response as
// the very last line (so it lies past every earlier window).
func bigJournal(t *testing.T, n int) []byte {
	t.Helper()
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	add := func(e InputEvent) {
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
	}
	pad := strings.Repeat("é", 512) // multi-byte, so a window can split a rune
	for i := 0; i < n; i++ {
		add(InputEvent{Kind: KindInputRequest, T: t0, RequestID: fmt.Sprintf("r%d", i), Tool: "Bash",
			Prompt: "Bash: " + pad, ExpiresAt: t0.Add(time.Hour)})
	}
	for i := 0; i < n; i++ {
		add(InputEvent{Kind: KindInputResponse, T: t0, RequestID: fmt.Sprintf("r%d", i), Answer: AnswerAllow, Reason: ReasonAnswered})
	}
	if b.Len() <= 512*1024 {
		t.Fatalf("journal is %d bytes, want over 512 KiB", b.Len())
	}
	return b.Bytes()
}

func TestReadApprovalJournalWholeJournal(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	data := bigJournal(t, 420)
	want := ApprovalStatusLines(SummarizeApprovals(ParseInputJournal(data)), true, t0)
	if !strings.Contains(want, "permission requests: 420 (allowed 420, denied 0, expired 0, cancelled 0, open 0)") || strings.Contains(want, "waiting_input") {
		t.Fatalf("reference summary is wrong:\n%s", want)
	}

	// 256 KiB is tail_log's real cap; 100001 splits lines and runes mid-way.
	for _, window := range []int{256 * 1024, 100001} {
		r := &windowReader{data: data, window: window}
		got, err := readApprovalJournal(context.Background(), r, "/x/run.input.jsonl")
		if err != nil {
			t.Fatalf("window %d: %v", window, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("window %d: read %d bytes, want %d", window, len(got), len(data))
		}
		if r.calls < 2 {
			t.Errorf("window %d: %d reads for a %d-byte journal, want several", window, r.calls, len(data))
		}
		out := ApprovalStatusLines(SummarizeApprovals(ParseInputJournal(got)), true, t0)
		if out != want {
			t.Errorf("window %d: windowed summary differs from the full one:\n%s\nvs\n%s", window, out, want)
		}
	}
}

func TestReadApprovalJournalBounds(t *testing.T) {
	// A journal over the cap is cut at it, said so, and the loop ends.
	r := &windowReader{data: bytes.Repeat([]byte("x"), maxApprovalJournalBytes+300*1024), window: 256 * 1024}
	got, err := readApprovalJournal(context.Background(), r, "/x")
	if !errors.Is(err, ErrJournalTooLarge) {
		t.Fatalf("err = %v, want ErrJournalTooLarge", err)
	}
	if len(got) < maxApprovalJournalBytes || len(got) > maxApprovalJournalBytes+256*1024 {
		t.Errorf("kept %d bytes, want about the %d cap", len(got), maxApprovalJournalBytes)
	}

	// A reader that never advances cannot loop forever.
	stuck := stuckReader{}
	if _, err := readApprovalJournal(context.Background(), stuck, "/x"); err == nil {
		t.Error("a reader that makes no progress while truncated must be an error")
	}

	// A missing file is not an error for the caller's "never used approvals".
	_, err = readApprovalJournal(context.Background(), &windowReader{missing: true}, "/x")
	if !errors.Is(err, ErrFileNotFound) {
		t.Errorf("err = %v, want ErrFileNotFound", err)
	}
}

type stuckReader struct{}

func (stuckReader) Read(_ context.Context, _ string, start int64, _ time.Duration) ([]byte, int64, bool, error) {
	return nil, start, true, nil
}

// journalOfSize builds a journal of exactly size bytes: a request, one status
// line of padding, and that request's response as the very last line, so a
// read cut anywhere before the end sees the request as open.
func journalOfSize(t *testing.T, size int) []byte {
	t.Helper()
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	line := func(e InputEvent) []byte {
		b, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	req := line(InputEvent{Kind: KindInputRequest, T: t0, RequestID: "r0", Tool: "Bash", Prompt: "Bash: ls", ExpiresAt: t0.Add(time.Hour)})
	resp := line(InputEvent{Kind: KindInputResponse, T: t0, RequestID: "r0", Answer: AnswerAllow, Reason: ReasonAnswered})
	pad := size - len(req) - len(resp)
	// status lines (notes) are the filler: one note, padded to fit exactly.
	note := line(InputEvent{Kind: KindInputStatus, T: t0, Text: ""})
	if pad < len(note) {
		t.Fatal("size too small")
	}
	note = line(InputEvent{Kind: KindInputStatus, T: t0, Text: strings.Repeat("n", pad-len(note)-len(`,"text":""`))})
	out := append(append(append([]byte{}, req...), note...), resp...)
	if len(out) != size {
		t.Fatalf("built %d bytes, want %d", len(out), size)
	}
	return out
}

func TestApprovalStatusOverLimitIsPartialAndClaimsNothingOpen(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	r := &windowReader{data: journalOfSize(t, maxApprovalJournalBytes+1024*1024), window: 256 * 1024}
	out, err := approvalStatus(context.Background(), r, "run", true, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "note: the journal is over 8 MiB and was read only in part") {
		t.Errorf("partial note must come first:\n%.200s", out)
	}
	for _, bad := range []string{"waiting_input", "open 1", "open 0", "request r0"} {
		if strings.Contains(out, bad) {
			t.Errorf("partial output claims %q:\n%.300s", bad, out)
		}
	}
	if !strings.Contains(out, "open requests unknown") || !strings.Contains(out, "at least 1 so far") {
		t.Errorf("partial output does not say counts are partial:\n%.300s", out)
	}
}

func TestApprovalStatusJournalOfExactlyTheLimitIsComplete(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	// A window size that divides the limit, so the last full window ends
	// exactly at the cap with truncated=true.
	r := &windowReader{data: journalOfSize(t, maxApprovalJournalBytes), window: 256 * 1024}
	out, err := approvalStatus(context.Background(), r, "run", true, t0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "read only in part") || strings.Contains(out, "unknown") {
		t.Errorf("a journal of exactly the limit was reported partial:\n%.300s", out)
	}
	if !strings.Contains(out, "permission requests: 1 (allowed 1,") {
		t.Errorf("summary wrong:\n%.300s", out)
	}
}
