//go:build !windows

package agentbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
)

// newTestApprovalServer is an approval server for run "code" in a temp dir,
// given the public key the way `code run` gives it (hex on its command line).
func newTestApprovalServer(t *testing.T, pub ed25519.PublicKey, timeout time.Duration) *approvalServer {
	t.Helper()
	dir := t.TempDir()
	s := &approvalServer{run: "code", dir: dir, timeout: timeout, now: time.Now, pollInterval: 10 * time.Millisecond}
	if err := os.MkdirAll(filepath.Join(dir, "code.answers"), 0o700); err != nil {
		t.Fatal(err)
	}
	s.setPublicKey(hex.EncodeToString(pub))
	return s
}

func bashCall(command string) map[string]interface{} {
	return map[string]interface{}{
		"tool_name":   "Bash",
		"input":       map[string]interface{}{"command": command, "description": "test"},
		"tool_use_id": "toolu_test",
	}
}

func readJournal(t *testing.T, s *approvalServer) []coderun.InputEvent {
	t.Helper()
	b, err := os.ReadFile(s.journalPath())
	if err != nil {
		t.Fatal(err)
	}
	return coderun.ParseInputJournal(b)
}

// answerWhenAsked waits for the first input_request and drops content as its
// answer, the way an answerer on the box would.
func answerWhenAsked(t *testing.T, s *approvalServer, content func(id string) string) {
	t.Helper()
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if b, err := os.ReadFile(s.journalPath()); err == nil {
				for _, e := range coderun.ParseInputJournal(b) {
					if e.Kind == coderun.KindInputRequest {
						_ = os.WriteFile(s.answerPath(e.RequestID), []byte(content(e.RequestID)), 0o600)
						return
					}
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
}

func decisionOf(t *testing.T, text string) promptDecision {
	t.Helper()
	var d promptDecision
	if err := json.Unmarshal([]byte(text), &d); err != nil {
		t.Fatalf("reply %q is not a decision: %v", text, err)
	}
	return d
}

var testPub, testPriv, _ = ed25519.GenerateKey(rand.Reader)

func TestApprovalAllowResumesWithTheOriginalInput(t *testing.T) {
	s := newTestApprovalServer(t, testPub, 5*time.Second)
	answerWhenAsked(t, s, func(id string) string { return coderun.FormatAnswer(testPriv, "code", id, coderun.AnswerAllow) })

	text, _ := callTool(t, s.handleApprove, bashCall("touch marker"))
	d := decisionOf(t, text)
	if d.Behavior != "allow" || !strings.Contains(string(d.UpdatedInput), `"command":"touch marker"`) {
		t.Fatalf("decision = %+v, want allow with the original input", d)
	}

	ev := readJournal(t, s)
	if len(ev) != 2 || ev[0].Kind != coderun.KindInputRequest || ev[1].Kind != coderun.KindInputResponse {
		t.Fatalf("journal = %+v, want request then response", ev)
	}
	req := ev[0]
	if req.RequestKind != coderun.RequestKindPermission || req.Prompt != "Bash: touch marker" || req.Default != coderun.AnswerDeny ||
		len(req.Options) != 2 || !strings.HasPrefix(req.RequestID, "req-") || req.ExpiresAt.Sub(req.T) != 5*time.Second {
		t.Errorf("request line = %+v", req)
	}
	if ev[1].RequestID != req.RequestID || ev[1].Answer != coderun.AnswerAllow || ev[1].Reason != coderun.ReasonAnswered {
		t.Errorf("response line = %+v", ev[1])
	}
}

func TestApprovalDenyReturnsARefusal(t *testing.T) {
	s := newTestApprovalServer(t, testPub, 5*time.Second)
	answerWhenAsked(t, s, func(id string) string { return coderun.FormatAnswer(testPriv, "code", id, coderun.AnswerDeny) })

	text, _ := callTool(t, s.handleApprove, bashCall("rm -rf build"))
	if d := decisionOf(t, text); d.Behavior != "deny" || d.Message == "" {
		t.Fatalf("decision = %+v, want deny with a message", d)
	}
	ev := readJournal(t, s)
	if last := ev[len(ev)-1]; last.Answer != coderun.AnswerDeny || last.Reason != coderun.ReasonAnswered {
		t.Errorf("response line = %+v", last)
	}
}

// An answer signed with any key but the run's — what an agent writing the
// answer file itself would produce — is journaled and ignored, and the request
// still expires into a deny.
func TestApprovalForgedAnswerIsIgnoredAndTheRequestExpires(t *testing.T) {
	s := newTestApprovalServer(t, testPub, 300*time.Millisecond)
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	answerWhenAsked(t, s, func(id string) string { return coderun.FormatAnswer(forger, "code", id, coderun.AnswerAllow) })

	text, _ := callTool(t, s.handleApprove, bashCall("curl evil"))
	if d := decisionOf(t, text); d.Behavior != "deny" || !strings.Contains(d.Message, "expired") {
		t.Fatalf("decision = %+v, want an expiry deny", d)
	}
	var notes, expired int
	for _, e := range readJournal(t, s) {
		if e.Kind == coderun.KindInputStatus && strings.Contains(e.Text, "signature does not verify") {
			notes++
		}
		if e.Kind == coderun.KindInputResponse && e.Reason == coderun.ReasonExpired && e.Answer == coderun.AnswerDeny {
			expired++
		}
	}
	if notes != 1 || expired != 1 {
		t.Errorf("journal has %d rejected-answer notes and %d expiry lines, want 1 and 1", notes, expired)
	}
}

func TestApprovalUnansweredRequestExpiresIntoDeny(t *testing.T) {
	s := newTestApprovalServer(t, testPub, 100*time.Millisecond)
	text, _ := callTool(t, s.handleApprove, bashCall("make deploy"))
	if d := decisionOf(t, text); d.Behavior != "deny" {
		t.Fatalf("decision = %+v, want deny", d)
	}
	ev := readJournal(t, s)
	if last := ev[len(ev)-1]; last.Kind != coderun.KindInputResponse || last.Reason != coderun.ReasonExpired {
		t.Errorf("last journal line = %+v, want an expiry", last)
	}
}

// With no usable public key nothing could ever answer, so requests are denied
// at once rather than after the timeout, and the reason is journaled.
func TestApprovalWithoutAKeyDeniesAtOnce(t *testing.T) {
	s := newTestApprovalServer(t, nil, time.Hour)
	start := time.Now()
	text, _ := callTool(t, s.handleApprove, bashCall("ls"))
	if d := decisionOf(t, text); d.Behavior != "deny" {
		t.Fatalf("decision = %+v, want deny", d)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("a keyless request waited %s", time.Since(start))
	}
	ev := readJournal(t, s)
	if ev[0].Kind != coderun.KindInputStatus || !strings.Contains(ev[0].Text, "no usable approval public key") {
		t.Errorf("first journal line = %+v, want the missing-key note", ev[0])
	}
	if last := ev[len(ev)-1]; last.Reason != coderun.ReasonNoKey {
		t.Errorf("response line = %+v, want reason no_key", last)
	}
}

// The client builds the --mcp-config and --permission-prompt-tool names from
// its own copies of these constants; they must match what this server serves.
func TestApprovalNamesMatchTheClientsPromptTool(t *testing.T) {
	if want := "mcp__" + ApprovalServerName + "__" + ApprovalToolName; engine.ApprovalPromptTool != want {
		t.Errorf("engine.ApprovalPromptTool = %q, server serves %q", engine.ApprovalPromptTool, want)
	}
	if engine.ApprovalProbeOK != approvalProbeOK {
		t.Errorf("engine.ApprovalProbeOK = %q, server prints %q", engine.ApprovalProbeOK, approvalProbeOK)
	}
	if coderun.ApprovalJournalPath("code") != filepath.Join(DefaultLogDir, "code.input.jsonl") ||
		coderun.ApprovalAnswersDir("code") != filepath.Join(DefaultLogDir, "code.answers") {
		t.Error("coderun's approval paths drifted from the server's")
	}
}

// The client's run-name check accepts exactly the names agent-box's process
// name sanitizer leaves unchanged (bar "." and ".."), so approval files always
// sit next to the run's own log.
func TestValidApprovalRunNameMatchesSanitizeName(t *testing.T) {
	for _, name := range []string{"code", "sess-42", "a_b.c", "sub/task", "../victim", "a b", "naïve", "x:y", "..x"} {
		unchanged := sanitizeName(name) == name
		if ok := coderun.ValidApprovalRunName(name) == nil; ok != unchanged {
			t.Errorf("%q: ValidApprovalRunName ok=%v, sanitizeName leaves it unchanged=%v", name, ok, unchanged)
		}
	}
}

func TestApprovalCLIProbe(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := RunApprovalCLI([]string{"--probe"}, strings.NewReader(""), &out, &errb); rc != 0 || strings.TrimSpace(out.String()) != approvalProbeOK {
		t.Fatalf("probe rc=%d out=%q err=%q", rc, out.String(), errb.String())
	}
	if rc := RunApprovalCLI([]string{"--run", "../x"}, strings.NewReader(""), &out, &errb); rc != 2 {
		t.Errorf("a run name with a path separator was accepted (rc=%d)", rc)
	}
}
