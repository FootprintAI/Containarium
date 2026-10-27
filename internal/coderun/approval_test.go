package coderun

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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
// it, and only for the run, request and answer it was signed for: no replay
// onto another request or run, no turning a deny into an allow.
func TestVerifyAnswerBindsKeyRunRequestAndAnswer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	good := FormatAnswer(priv, "code", "req-1", AnswerAllow)

	if a, err := VerifyAnswer(pub, "code", "req-1", good); err != nil || a != AnswerAllow {
		t.Fatalf("VerifyAnswer(good) = %q, %v; want allow", a, err)
	}
	denySig := SignAnswer(priv, "code", "req-1", AnswerDeny)
	cases := map[string]struct {
		pub     ed25519.PublicKey
		run, id string
		content string
	}{
		"other public key":  {otherPub, "code", "req-1", good},
		"signed by another": {pub, "code", "req-1", FormatAnswer(otherPriv, "code", "req-1", AnswerAllow)},
		"other request":     {pub, "code", "req-2", good},
		"other run":         {pub, "other", "req-1", good},
		"deny sig as allow": {pub, "code", "req-1", "allow " + denySig},
		"unsigned":          {pub, "code", "req-1", "allow"},
		"not hex":           {pub, "code", "req-1", "allow zz"},
		"not an answer":     {pub, "code", "req-1", "maybe " + SignAnswer(priv, "code", "req-1", "maybe")},
		"extra field":       {pub, "code", "req-1", strings.TrimSpace(good) + " extra"},
		"empty":             {pub, "code", "req-1", ""},
	}
	for name, c := range cases {
		if a, err := VerifyAnswer(c.pub, c.run, c.id, c.content); err == nil {
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
