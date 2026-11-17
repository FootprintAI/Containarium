package guardrailhook

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Every value below is synthetic: the cloud provider's documented example
// key id, a made-up key body and example.com addresses.
const (
	synthKey   = "AKIAIOSFODNN7EXAMPLE"
	synthEmail = "ann@example.com"
	pemBegin   = "-----BEGIN PRIVATE KEY-----"
	pemBody    = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7synthetic"
	pemEnd     = "-----END PRIVATE KEY-----"
)

const (
	evSession = pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_SESSION_START
	evPre     = pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_PRE_TOOL_USE
	evPost    = pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_POST_TOOL_USE
	evBatch   = pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_POST_TOOL_BATCH
	evPrompt  = pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_USER_PROMPT_SUBMIT
	evInstr   = pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_INSTRUCTIONS_LOADED
)

func newHandler(t *testing.T, mut func(*Config)) (*Handler, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	cfg := Config{StateDir: dir, Engine: guardrail.RulesEngine{}}
	if mut != nil {
		mut(&cfg)
	}
	return New(cfg), dir
}

// fire runs one event and decodes what the handler printed. An empty stdout
// (the handler has nothing to say) decodes to the zero output.
func fire(t *testing.T, h *Handler, ev pb.GuardrailHookEvent, input string) hookOutput {
	t.Helper()
	raw, err := h.Handle(context.Background(), ev, []byte(input))
	if err != nil {
		t.Fatalf("%v: %v", ev, err)
	}
	var out hookOutput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%v printed invalid JSON %q: %v", ev, raw, err)
		}
	}
	return out
}

func spoolRows(t *testing.T, dir string) []*pb.GuardrailHookRecord {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, spoolFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var rows []*pb.GuardrailHookRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		r := &pb.GuardrailHookRecord{}
		if err := protojson.Unmarshal(sc.Bytes(), r); err != nil {
			t.Fatalf("spool row %q: %v", sc.Text(), err)
		}
		rows = append(rows, r)
	}
	return rows
}

func hasRow(rows []*pb.GuardrailHookRecord, outcome pb.GuardrailHookOutcome, typ string) bool {
	for _, r := range rows {
		if r.GetOutcome() == outcome && (typ == "" || r.GetType() == typ) {
			return true
		}
	}
	return false
}

// stateContains reports whether any file under the state directory holds s.
func stateContains(t *testing.T, dir, s string) bool {
	t.Helper()
	found := false
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(s)) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func marker(t *testing.T, s string) string {
	t.Helper()
	m := markerRE.FindString(s)
	if m == "" {
		t.Fatalf("no marker in %q", s)
	}
	return m
}

func q(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// readResult is a PostToolUse input for a file read, in the shape the file
// read tool reports.
func readResult(path, content string) string {
	return `{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{"file_path":` + q(path) +
		`},"tool_response":{"type":"text","file":{"filePath":` + q(path) + `,"content":` + q(content) + `,"numLines":2,"startLine":1,"totalLines":2}}}`
}

type readOut struct {
	Type string `json:"type"`
	File struct {
		FilePath string      `json:"filePath"`
		Content  string      `json:"content"`
		NumLines json.Number `json:"numLines"`
	} `json:"file"`
}

func decodeRead(t *testing.T, out hookOutput) readOut {
	t.Helper()
	if out.HookSpecificOutput == nil || len(out.HookSpecificOutput.UpdatedToolOutput) == 0 {
		t.Fatalf("no updatedToolOutput in %+v", out)
	}
	var r readOut
	if err := json.Unmarshal(out.HookSpecificOutput.UpdatedToolOutput, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// Criterion: a synthetic secret in a file the agent reads reaches the model
// as a marker.
func TestPostToolUse_FileContentIsRedactedInPlace(t *testing.T) {
	h, dir := newHandler(t, nil)
	out := fire(t, h, evPost, readResult("/w/.env", "AWS="+synthKey+"\nowner "+synthEmail))
	r := decodeRead(t, out)
	if strings.Contains(r.File.Content, synthKey) || strings.Contains(r.File.Content, synthEmail) {
		t.Fatalf("value reached the model: %q", r.File.Content)
	}
	if !strings.Contains(r.File.Content, "[[AWS_ACCESS_KEY_ID:") || !strings.Contains(r.File.Content, "[[EMAIL:") {
		t.Fatalf("want both markers, got %q", r.File.Content)
	}
	if r.Type != "text" || r.File.FilePath != "/w/.env" || r.File.NumLines != "2" {
		t.Errorf("structure changed: %+v", r)
	}
	if out.HookSpecificOutput.PermissionDecision != "" || out.Decision != "" {
		t.Errorf("a redaction carries no decision: %+v", out)
	}
	rows := spoolRows(t, dir)
	redacted := pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_REDACTED
	if !hasRow(rows, redacted, "AWS_ACCESS_KEY_ID") || !hasRow(rows, redacted, "EMAIL") {
		t.Errorf("want a REDACTED row per finding, got %v", rows)
	}
	for _, row := range rows {
		if row.GetSessionId() != "s1" || row.GetToolName() != "Read" {
			t.Errorf("row lost its session or tool: %v", row)
		}
		if strings.Contains(row.GetExcerpt(), synthKey) || strings.Contains(row.GetExcerpt(), synthEmail) {
			t.Errorf("excerpt carries a value: %q", row.GetExcerpt())
		}
	}
	if stateContains(t, dir, synthKey) {
		t.Error("a secret was persisted in the state directory")
	}
	if !stateContains(t, dir, synthEmail) {
		t.Error("the PII value must be in the marker map, or it can never be restored")
	}
	if fire(t, h, evPost, readResult("/w/a.txt", "nothing here")).HookSpecificOutput != nil {
		t.Error("a clean result must be left alone")
	}
}

// seedMarkers runs one redaction and returns the PII and the secret marker.
func seedMarkers(t *testing.T, h *Handler) (pii, secret string) {
	t.Helper()
	r := decodeRead(t, fire(t, h, evPost, readResult("/w/.env", synthEmail+"\n"+synthKey)))
	lines := strings.Split(r.File.Content, "\n")
	return marker(t, lines[0]), marker(t, lines[1])
}

func preInput(tool, toolInput string) string {
	return `{"session_id":"s1","cwd":"/w","hook_event_name":"PreToolUse","tool_name":` + q(tool) + `,"tool_input":` + toolInput + `}`
}

// Criterion: an Edit using a PII marker writes the real value; one using a
// secret marker is denied; a marker with no map entry is denied and never
// written literally.
func TestPreToolUse_RehydratesPIIOnlyInEditContent(t *testing.T) {
	h, dir := newHandler(t, nil)
	pii, secret := seedMarkers(t, h)
	const unknown = "[[EMAIL:000000000000]]"

	t.Run("pii marker is restored with no permission decision", func(t *testing.T) {
		for _, tc := range []struct{ tool, input, field string }{
			{"Edit", `{"file_path":"/w/a.txt","old_string":"contact: x","new_string":` + q("contact: "+pii) + `,"replace_all":false}`, "new_string"},
			{"Write", `{"file_path":"/w/a.txt","content":` + q("to "+pii) + `}`, "content"},
			{"NotebookEdit", `{"notebook_path":"/w/n.ipynb","cell_id":"c1","new_source":` + q("# "+pii) + `}`, "new_source"},
		} {
			out := fire(t, h, evPre, preInput(tc.tool, tc.input))
			hs := out.HookSpecificOutput
			if hs == nil || hs.UpdatedInput == nil {
				t.Fatalf("%s: no updatedInput: %+v", tc.tool, out)
			}
			if hs.PermissionDecision != "" {
				t.Errorf("%s: the user's own permission rules must decide, got %q", tc.tool, hs.PermissionDecision)
			}
			var got string
			if err := json.Unmarshal(hs.UpdatedInput[tc.field], &got); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(got, synthEmail) || strings.Contains(got, pii) {
				t.Errorf("%s %s = %q, want the real value", tc.tool, tc.field, got)
			}
			var orig map[string]json.RawMessage
			_ = json.Unmarshal([]byte(tc.input), &orig)
			if len(hs.UpdatedInput) != len(orig) {
				t.Errorf("%s: updatedInput replaces the whole input and must keep every field", tc.tool)
			}
		}
	})

	t.Run("a marker in the text an edit replaces is left as it is", func(t *testing.T) {
		out := fire(t, h, evPre, preInput("Edit", `{"file_path":"/w/a.txt","old_string":`+q(pii)+`,"new_string":"x"}`))
		if out.HookSpecificOutput != nil {
			t.Errorf("old_string must never be rehydrated: %+v", out)
		}
	})

	t.Run("secret and unknown markers deny the call", func(t *testing.T) {
		for name, m := range map[string]string{"secret": secret, "unknown": unknown} {
			for _, in := range []string{
				preInput("Edit", `{"file_path":"/w/a.txt","old_string":"k","new_string":`+q("key="+m)+`}`),
				preInput("Write", `{"file_path":"/w/a.txt","content":`+q("key="+m)+`}`),
				preInput("Read", `{"file_path":`+q("/w/"+m+".txt")+`}`),
			} {
				out := fire(t, h, evPre, in)
				hs := out.HookSpecificOutput
				if hs == nil || hs.PermissionDecision != "deny" || hs.PermissionDecisionReason == "" {
					t.Fatalf("%s marker must deny with a reason: %+v", name, out)
				}
				if hs.UpdatedInput != nil {
					t.Errorf("%s: a denied call carries no updatedInput", name)
				}
				if strings.Contains(hs.PermissionDecisionReason, synthKey) {
					t.Errorf("reason carries the value: %q", hs.PermissionDecisionReason)
				}
			}
		}
		if !hasRow(spoolRows(t, dir), pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_DENIED, "") {
			t.Error("a denial is recorded")
		}
	})
}

// Criterion: a marker in a Bash command, WebSearch query or MCP call is not
// rehydrated. WebFetch is denied outright: the page reaches the model inside
// the tool, before any hook.
func TestPreToolUse_NeverRehydratesOtherTools(t *testing.T) {
	h, _ := newHandler(t, nil)
	pii, _ := seedMarkers(t, h)
	for _, tc := range []struct{ tool, input string }{
		{"Bash", `{"command":` + q("echo "+pii) + `}`},
		{"WebSearch", `{"query":` + q(pii) + `}`},
		{"mcp__crm__lookup", `{"email":` + q(pii) + `,"file_path":` + q(pii) + `}`},
		{"FutureTool", `{"content":` + q(pii) + `}`},
	} {
		if out := fire(t, h, evPre, preInput(tc.tool, tc.input)); out.HookSpecificOutput != nil {
			t.Errorf("%s: must pass through untouched, got %+v", tc.tool, out)
		}
	}
	out := fire(t, h, evPre, preInput("WebFetch", `{"url":`+q("https://example.com/?u="+pii)+`,"prompt":"summarise"}`))
	if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("WebFetch must be denied while the guardrail is on: %+v", out)
	}
}

// Criterion: a file path containing an email works for a follow-up Read or
// Edit; the echoed path reaches the model as the marker.
func TestPathWithEmail_RoundTrips(t *testing.T) {
	h, _ := newHandler(t, nil)
	real := "/w/exports/" + synthEmail + ".csv"
	r := decodeRead(t, fire(t, h, evPost, readResult(real, "id,name")))
	if strings.Contains(r.File.FilePath, synthEmail) {
		t.Fatalf("echoed path reached the model unredacted: %q", r.File.FilePath)
	}
	redactedPath := r.File.FilePath
	for _, tc := range []struct{ tool, field, input string }{
		{"Read", "file_path", `{"file_path":` + q(redactedPath) + `}`},
		{"Edit", "file_path", `{"file_path":` + q(redactedPath) + `,"old_string":"a","new_string":"b"}`},
		{"Glob", "pattern", `{"pattern":` + q("/w/exports/"+marker(t, redactedPath)+"*") + `}`},
		{"Grep", "path", `{"pattern":"id","path":` + q(redactedPath) + `}`},
	} {
		out := fire(t, h, evPre, preInput(tc.tool, tc.input))
		if out.HookSpecificOutput == nil || out.HookSpecificOutput.UpdatedInput == nil {
			t.Fatalf("%s: path was not rehydrated: %+v", tc.tool, out)
		}
		var got string
		_ = json.Unmarshal(out.HookSpecificOutput.UpdatedInput[tc.field], &got)
		if !strings.Contains(got, synthEmail) {
			t.Errorf("%s %s = %q, want the real path", tc.tool, tc.field, got)
		}
	}
	// A Grep search pattern is content, not a path: it stays as typed.
	out := fire(t, h, evPre, preInput("Grep", `{"pattern":`+q(marker(t, redactedPath))+`}`))
	if out.HookSpecificOutput != nil {
		t.Errorf("a search pattern must not be rehydrated: %+v", out)
	}
}

func postInput(tool, toolInput, toolResponse string) string {
	return `{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":` + q(tool) + `,"tool_input":` + toolInput + `,"tool_response":` + toolResponse + `}`
}

// Criterion: a multi-line private key held as an array of lines is caught;
// array length is unchanged. Also covers an unknown tool, and a result that
// arrives as one JSON string (how MCP results reach the hook).
func TestPostToolUse_LineArraysAndEmbeddedJSON(t *testing.T) {
	h, dir := newHandler(t, nil)
	lines := []string{"# 設定 header", pemBegin, pemBody, pemBody, pemEnd, "owner " + synthEmail}
	object := `{"lines":` + q(lines) + `,"count":6,"ok":true}`

	check := func(t *testing.T, raw json.RawMessage) {
		t.Helper()
		var got struct {
			Lines []string    `json:"lines"`
			Count json.Number `json:"count"`
			OK    bool        `json:"ok"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if len(got.Lines) != len(lines) {
			t.Fatalf("array length changed: %d -> %d", len(lines), len(got.Lines))
		}
		if got.Lines[0] != lines[0] {
			t.Errorf("clean line changed: %q", got.Lines[0])
		}
		m := marker(t, got.Lines[1])
		for i := 1; i <= 4; i++ {
			if got.Lines[i] != m {
				t.Errorf("line %d = %q, want the one marker %q for every line the key covers", i, got.Lines[i], m)
			}
		}
		if !strings.HasPrefix(m, "[[PRIVATE_KEY:") {
			t.Errorf("marker %q", m)
		}
		if want := "owner " + marker(t, got.Lines[5]); got.Lines[5] != want || strings.Contains(got.Lines[5], synthEmail) {
			t.Errorf("offsets after a multi-byte line are off: %q", got.Lines[5])
		}
		if got.Count != "6" || !got.OK {
			t.Errorf("non-string leaves changed: %+v", got)
		}
	}

	t.Run("object from an unknown tool", func(t *testing.T) {
		out := fire(t, h, evPost, postInput("FutureTool", `{}`, object))
		check(t, out.HookSpecificOutput.UpdatedToolOutput)
	})
	t.Run("one JSON string", func(t *testing.T) {
		out := fire(t, h, evPost, postInput("mcp__db__dump", `{}`, q(object)))
		var inner string
		if err := json.Unmarshal(out.HookSpecificOutput.UpdatedToolOutput, &inner); err != nil {
			t.Fatalf("the result must stay a string: %s", out.HookSpecificOutput.UpdatedToolOutput)
		}
		check(t, json.RawMessage(inner))
	})
	if stateContains(t, dir, pemBody) {
		t.Error("key material was persisted")
	}
}

// Criterion: an unknown tool's string output is scanned. A failed command
// also reports as a bare string.
func TestPostToolUse_BareStringFromUnknownTool(t *testing.T) {
	h, _ := newHandler(t, nil)
	out := fire(t, h, evPost, postInput("FutureTool", `{}`, q("Error: Exit code 1\nmail "+synthEmail)))
	var got string
	if err := json.Unmarshal(out.HookSpecificOutput.UpdatedToolOutput, &got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, synthEmail) || !strings.HasPrefix(got, "Error: Exit code 1\nmail [[EMAIL:") {
		t.Errorf("got %q", got)
	}
}

func TestPostToolUse_BinaryIsSkippedAndCounted(t *testing.T) {
	h, dir := newHandler(t, nil)
	blob := strings.Repeat("QUJDREVGR0g=", 40)
	out := fire(t, h, evPost, postInput("Read", `{}`, `{"type":"image","file":{"base64":`+q(blob)+`},"note":"\u0000raw"}`))
	if out.HookSpecificOutput != nil {
		t.Errorf("nothing to redact: %+v", out)
	}
	var skipped *pb.GuardrailHookRecord
	for _, r := range spoolRows(t, dir) {
		if r.GetOutcome() == pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_SKIPPED_BINARY {
			skipped = r
		}
	}
	if skipped == nil || skipped.GetCount() != 2 {
		t.Errorf("want one SKIPPED_BINARY row counting 2 leaves, got %v", skipped)
	}
}

// countingEngine is the reference engine with a call counter, for the tests
// that need to know which path scanned.
type countingEngine struct {
	guardrail.RulesEngine
	calls int
}

func (e *countingEngine) Scan(ctx context.Context, req *pb.GuardrailScanRequest) (*pb.GuardrailScanResponse, error) {
	e.calls++
	return e.RulesEngine.Scan(ctx, req)
}

// downEngine stands in for an engine process that is not running.
type downEngine struct{}

func (downEngine) Scan(context.Context, *pb.GuardrailScanRequest) (*pb.GuardrailScanResponse, error) {
	return nil, errors.New("connection refused")
}

func TestPostToolUse_OverTheSizeLimitGetsThePatternPass(t *testing.T) {
	eng := &countingEngine{}
	h, dir := newHandler(t, func(c *Config) { c.Engine = eng; c.FullScanMaxBytes = 64 })
	big := strings.Repeat("filler line\n", 20) + "key " + synthKey
	r := decodeRead(t, fire(t, h, evPost, readResult("/w/big.log", big)))
	if strings.Contains(r.File.Content, synthKey) {
		t.Fatal("an oversize result must still get the pattern pass")
	}
	if eng.calls != 0 {
		t.Errorf("engine called %d times for an oversize result", eng.calls)
	}
	if !hasRow(spoolRows(t, dir), pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_PARTIALLY_SCANNED, "") {
		t.Error("an oversize result is recorded as partially scanned")
	}
	fire(t, h, evPost, readResult("/w/small", "x"))
	if eng.calls != 1 {
		t.Errorf("a small result goes to the engine, calls=%d", eng.calls)
	}
}

func TestPostToolUse_EngineFailureAfterTheToolRanFallsBackAndRecords(t *testing.T) {
	h, dir := newHandler(t, func(c *Config) { c.Engine = downEngine{} })
	r := decodeRead(t, fire(t, h, evPost, readResult("/w/.env", "k="+synthKey)))
	if strings.Contains(r.File.Content, synthKey) {
		t.Fatal("the tool already ran: the result must not go out unscanned")
	}
	if !hasRow(spoolRows(t, dir), pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_PARTIALLY_SCANNED, "") {
		t.Error("the fallback is recorded")
	}
}

// Another hook's input rewrite can replace ours; the marker is then still in
// the input when the tool has run.
func TestPostToolUse_MarkerLeftInToolInputIsRecorded(t *testing.T) {
	h, dir := newHandler(t, nil)
	pii, _ := seedMarkers(t, h)
	fire(t, h, evPost, postInput("Write", `{"file_path":"/w/a.txt","content":`+q("to "+pii)+`}`, `{"type":"create","filePath":"/w/a.txt"}`))
	if !hasRow(spoolRows(t, dir), pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_MARKER_IN_TOOL_INPUT, "EMAIL") {
		t.Errorf("want a MARKER_IN_TOOL_INPUT row, got %v", spoolRows(t, dir))
	}
}

// Criterion: engine stopped -> PreToolUse denies.
func TestPreToolUse_DeniesWhenTheEngineIsNotReady(t *testing.T) {
	h, _ := newHandler(t, func(c *Config) { c.Engine = downEngine{} })
	out := fire(t, h, evPre, preInput("Bash", `{"command":"ls"}`))
	hs := out.HookSpecificOutput
	if hs == nil || hs.PermissionDecision != "deny" || !strings.Contains(hs.PermissionDecisionReason, "not ready") {
		t.Fatalf("want a deny naming the engine, got %+v", out)
	}
}

func TestPreToolUse_DeniesReadsOfTheStateDirectory(t *testing.T) {
	h, dir := newHandler(t, nil)
	for _, in := range []string{
		preInput("Read", `{"file_path":`+q(filepath.Join(dir, markersFile))+`}`),
		preInput("Grep", `{"pattern":"x","path":`+q(dir)+`}`),
		preInput("Bash", `{"command":`+q("cat "+dir+"/"+keyFile)+`}`),
	} {
		out := fire(t, h, evPre, in)
		if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != "deny" {
			t.Errorf("must deny %s: %+v", in, out)
		}
	}
	if out := fire(t, h, evPre, preInput("Read", `{"file_path":"/w/README.md"}`)); out.HookSpecificOutput != nil {
		t.Errorf("an ordinary read passes: %+v", out)
	}
}

// Criterion: a prompt with a secret is blocked, type named, original not
// echoed.
func TestUserPromptSubmit_BlocksOnAFinding(t *testing.T) {
	h, dir := newHandler(t, nil)
	in := func(prompt string) string {
		return `{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":` + q(prompt) + `}`
	}
	out := fire(t, h, evPrompt, in("deploy with "+synthKey+" please"))
	if out.Decision != "block" || !strings.Contains(out.Reason, "AWS_ACCESS_KEY_ID") {
		t.Fatalf("want a block naming the type: %+v", out)
	}
	if strings.Contains(out.Reason, synthKey) {
		t.Errorf("reason echoes the value: %q", out.Reason)
	}
	if out.HookSpecificOutput == nil || !out.HookSpecificOutput.SuppressOriginalPrompt {
		t.Error("suppressOriginalPrompt must be set")
	}
	if out := fire(t, h, evPrompt, in("what does main.go do?")); out.Decision != "" {
		t.Errorf("a clean prompt passes: %+v", out)
	}

	// A background event arrives as a prompt; it is its own source.
	out = fire(t, h, evPrompt, in("<task-notification><event>TOKEN "+synthKey+"</event></task-notification>"))
	if out.Decision != "block" {
		t.Fatalf("a notification with a finding is dropped whole: %+v", out)
	}
	sources := map[pb.GuardrailHookSource]bool{}
	for _, r := range spoolRows(t, dir) {
		if r.GetOutcome() == pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_BLOCKED {
			sources[r.GetSource()] = true
		}
	}
	if !sources[pb.GuardrailHookSource_GUARDRAIL_HOOK_SOURCE_PROMPT] || !sources[pb.GuardrailHookSource_GUARDRAIL_HOOK_SOURCE_TASK_NOTIFICATION] {
		t.Errorf("want one BLOCKED row per source, got %v", sources)
	}
	if stateContains(t, dir, synthKey) {
		t.Error("a blocked prompt's value was persisted")
	}
}

func TestUserPromptSubmit_EngineFailureIsAnError(t *testing.T) {
	h, _ := newHandler(t, func(c *Config) { c.Engine = downEngine{} })
	_, err := h.Handle(context.Background(), evPrompt, []byte(`{"session_id":"s1","prompt":"hello"}`))
	if err == nil {
		t.Fatal("a prompt that could not be scanned must not pass as clean")
	}
}

func batchInput(response string) string {
	return `{"session_id":"s1","hook_event_name":"PostToolBatch","tool_calls":[{"tool_name":"Read","tool_input":{"file_path":"/w/.env"},"tool_use_id":"t1","tool_response":` + response + `}]}`
}

func TestPostToolBatch_RescanRecordsWhatIsStillUnredacted(t *testing.T) {
	h, dir := newHandler(t, nil)
	_, secret := seedMarkers(t, h)
	before := len(spoolRows(t, dir))
	if out := fire(t, h, evBatch, batchInput(q("1\tAWS="+secret))); out.Decision != "" {
		t.Errorf("a redacted batch passes: %+v", out)
	}
	if got := len(spoolRows(t, dir)); got != before {
		t.Errorf("a marker is not a finding: %d new rows", got-before)
	}
	out := fire(t, h, evBatch, batchInput(`[{"type":"text","text":`+q("1\tAWS="+synthKey)+`}]`))
	if out.Decision != "" {
		t.Errorf("blocking at the batch is off by default: %+v", out)
	}
	if !hasRow(spoolRows(t, dir), pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_UNREDACTED_AT_BATCH, "AWS_ACCESS_KEY_ID") {
		t.Errorf("want an UNREDACTED_AT_BATCH row, got %v", spoolRows(t, dir))
	}
}

// A block at the batch stops the turn but does not remove the result, so
// with the flag on the session refuses later prompts until it is cleared.
func TestPostToolBatch_BlockRefusesLaterPromptsUntilClear(t *testing.T) {
	h, _ := newHandler(t, func(c *Config) { c.BlockOnBatchFinding = true })
	prompt := `{"session_id":"s1","prompt":"what next"}`
	if out := fire(t, h, evPrompt, prompt); out.Decision != "" {
		t.Fatalf("before the batch: %+v", out)
	}
	if out := fire(t, h, evBatch, batchInput(q(synthKey))); out.Decision != "block" {
		t.Fatalf("want a block: %+v", out)
	}
	if out := fire(t, h, evPrompt, prompt); out.Decision != "block" || !strings.Contains(out.Reason, "/clear") {
		t.Fatalf("later prompts in the session are refused: %+v", out)
	}
	if out := fire(t, h, evPrompt, `{"session_id":"s2","prompt":"hi"}`); out.Decision != "" {
		t.Errorf("another session is unaffected: %+v", out)
	}
	fire(t, h, evSession, `{"session_id":"s1","source":"clear"}`)
	if out := fire(t, h, evPrompt, prompt); out.Decision != "" {
		t.Errorf("after /clear: %+v", out)
	}
}

// Criterion: no code path opens the agent's credentials file.
func TestInstructionsLoaded_RecordsAndNeverOpensCredentials(t *testing.T) {
	var opened []string
	h, dir := newHandler(t, func(c *Config) {
		c.ReadFile = func(p string) ([]byte, error) {
			opened = append(opened, p)
			return []byte("deploy key " + synthKey), nil
		}
	})
	in := func(p string) string {
		return `{"session_id":"s1","hook_event_name":"InstructionsLoaded","file_path":` + q(p) + `,"memory_type":"Project","load_reason":"session_start"}`
	}
	raw, err := h.Handle(context.Background(), evInstr, []byte(in("/home/dev/.claude/.credentials.json")))
	if err != nil || len(raw) != 0 {
		t.Fatalf("out=%q err=%v", raw, err)
	}
	if len(opened) != 0 {
		t.Fatalf("the credentials file was opened: %v", opened)
	}
	raw, err = h.Handle(context.Background(), evInstr, []byte(in("/w/CLAUDE.md")))
	if err != nil || len(raw) != 0 {
		t.Fatalf("the event's output is discarded, print nothing: out=%q err=%v", raw, err)
	}
	if len(opened) != 1 {
		t.Fatalf("opened %v", opened)
	}
	var row *pb.GuardrailHookRecord
	for _, r := range spoolRows(t, dir) {
		if r.GetOutcome() == pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_RECORDED {
			row = r
		}
	}
	if row == nil || row.GetSource() != pb.GuardrailHookSource_GUARDRAIL_HOOK_SOURCE_INSTRUCTIONS || row.GetType() != "AWS_ACCESS_KEY_ID" {
		t.Errorf("want a RECORDED instructions row, got %v", row)
	}
}

func TestSessionStart_AddsFactualContext(t *testing.T) {
	h, _ := newHandler(t, func(c *Config) { c.Engine = downEngine{} })
	out := fire(t, h, evSession, `{"session_id":"s1","source":"startup"}`)
	if out.HookSpecificOutput == nil {
		t.Fatal("no context")
	}
	ctx := out.HookSpecificOutput.AdditionalContext
	for _, want := range []string{"[[TYPE:", "secret", "old_string", "WebFetch"} {
		if !strings.Contains(ctx, want) {
			t.Errorf("context does not mention %q: %s", want, ctx)
		}
	}
}

// An internal error must never look like a clean pass: Handle returns an
// error and prints nothing, and the command turns that into exit status 2.
func TestHandle_InternalErrorsAreErrors(t *testing.T) {
	h, _ := newHandler(t, nil)
	for name, tc := range map[string]struct {
		ev pb.GuardrailHookEvent
		in string
	}{
		"invalid json":      {evPre, `{"tool_name":`},
		"unknown event":     {pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_UNSPECIFIED, `{}`},
		"input not object":  {evPre, `{"tool_name":"Edit","tool_input":"x"}`},
		"missing tool name": {evPost, `{"tool_response":"x"}`},
	} {
		raw, err := h.Handle(context.Background(), tc.ev, []byte(tc.in))
		if err == nil || len(raw) != 0 {
			t.Errorf("%s: out=%q err=%v, want an error and no output", name, raw, err)
		}
	}
}

func TestState_KeyIsPrivateAndStable(t *testing.T) {
	h, dir := newHandler(t, nil)
	a, _ := seedMarkers(t, h)
	b, _ := seedMarkers(t, New(Config{StateDir: dir, Engine: guardrail.RulesEngine{}}))
	if a != b {
		t.Errorf("the same value must get the same marker across invocations: %s vs %s", a, b)
	}
	for _, name := range []string{keyFile, markersFile, spoolFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v, want 0600", name, info.Mode().Perm())
		}
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("state dir is %v, want 0700", info.Mode().Perm())
	}
}

func TestSpool_IsBoundedAndNeverBlocks(t *testing.T) {
	// Room for a few rows, not for the 20 the loop writes.
	const bound = 2048
	h, dir := newHandler(t, func(c *Config) { c.SpoolMaxBytes = bound })
	for i := 0; i < 20; i++ {
		decodeRead(t, fire(t, h, evPost, readResult("/w/.env", "k="+synthKey)))
	}
	info, err := os.Stat(filepath.Join(dir, spoolFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > bound {
		t.Errorf("spool grew to %d bytes past its %d byte bound", info.Size(), bound)
	}
	if n := len(spoolRows(t, dir)); n < 1 || n >= 20 {
		t.Errorf("spool holds %d rows: want at least one, and fewer than the 20 written", n)
	}
}

func TestAllowlist_NeverNamesAPath(t *testing.T) {
	for tool, fields := range structuralFields {
		for f := range fields {
			l := strings.ToLower(f)
			if strings.Contains(l, "path") || strings.Contains(l, "file") || strings.Contains(l, "dir") {
				t.Errorf("%s.%s: paths are content and must be scanned", tool, f)
			}
		}
	}
	// An allowlisted field is skipped only for its own tool.
	h, _ := newHandler(t, nil)
	out := fire(t, h, evPost, postInput("FutureTool", `{}`, `{"type":`+q(synthEmail)+`}`))
	if out.HookSpecificOutput == nil {
		t.Error("an unknown tool's `type` field is content")
	}
}

type fakeProc map[int]struct {
	comm   string
	parent int
}

func (f fakeProc) Comm(pid int) (string, error) {
	p, ok := f[pid]
	if !ok {
		return "", os.ErrNotExist
	}
	return p.comm, nil
}

func (f fakeProc) Parent(pid int) (int, error) {
	p, ok := f[pid]
	if !ok {
		return 0, os.ErrNotExist
	}
	return p.parent, nil
}

func TestStamp_IsKeyedByTheAgentProcess(t *testing.T) {
	for name, tc := range map[string]struct {
		proc fakeProc
		want int
	}{
		"exec form: the parent is the agent": {fakeProc{50: {"claude", 1}}, 50},
		"shell form: walk up to the agent":   {fakeProc{50: {"sh", 40}, 40: {"claude", 1}}, 40},
		"no agent ancestor: the parent":      {fakeProc{50: {"sh", 40}, 40: {"bash", 1}, 1: {"init", 0}}, 50},
		"process table unreadable":           {fakeProc{}, 50},
	} {
		if got := stampPID(50, tc.proc); got != tc.want {
			t.Errorf("%s: got %d want %d", name, got, tc.want)
		}
	}
	h, dir := newHandler(t, func(c *Config) { c.ParentPID = 50; c.Proc = fakeProc{50: {"claude", 1}} })
	fire(t, h, evSession, `{"session_id":"s1","source":"startup"}`)
	if _, err := os.Stat(filepath.Join(dir, stampsDir, "50")); err != nil {
		t.Errorf("every invocation touches the stamp: %v", err)
	}
}

// A Glob whose search root is an ancestor of the state directory, with a
// pattern that can reach into it, would list the directory's file names.
func TestPreToolUse_DeniesGlobsThatReachTheStateDirectory(t *testing.T) {
	h, dir := newHandler(t, nil)
	parent := filepath.Dir(filepath.Dir(dir))
	for _, in := range []string{
		preInput("Glob", `{"pattern":"**/*","path":`+q(parent)+`}`),
		preInput("Glob", `{"pattern":"**/marker.key","path":`+q(parent)+`}`),
		preInput("Glob", `{"pattern":"*/state/*","path":`+q(parent)+`}`),
		preInput("Glob", `{"pattern":`+q(parent+"/**/*.jsonl")+`}`),
		`{"session_id":"s1","cwd":` + q(parent) + `,"hook_event_name":"PreToolUse","tool_name":"Glob","tool_input":{"pattern":"**/*.key"}}`,
	} {
		out := fire(t, h, evPre, in)
		if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != "deny" {
			t.Errorf("must deny %s: %+v", in, out)
		}
	}
	for _, in := range []string{
		preInput("Glob", `{"pattern":"**/*.go","path":"/w"}`),
		preInput("Glob", `{"pattern":"src/*","path":`+q(parent)+`}`),
		preInput("Glob", `{"pattern":"*","path":`+q(parent)+`}`),
	} {
		if out := fire(t, h, evPre, in); out.HookSpecificOutput != nil {
			t.Errorf("a glob that cannot reach the state directory passes: %s: %+v", in, out)
		}
	}
}

// The pattern pass is a fallback for text that reaches the model anyway. A
// prompt can still be stopped, so an oversized one goes to the engine too.
func TestUserPromptSubmit_OversizedPromptStillGetsTheEngine(t *testing.T) {
	h, _ := newHandler(t, func(c *Config) { c.Engine = wordEngine{}; c.FullScanMaxBytes = 64 })
	prompt := strings.Repeat("filler words ", 20) + "codename BLUEHERON"
	out := fire(t, h, evPrompt, `{"session_id":"s1","prompt":`+q(prompt)+`}`)
	if out.Decision != "block" || !strings.Contains(out.Reason, "CODENAME") {
		t.Fatalf("a finding only the engine makes must still block an oversized prompt: %+v", out)
	}
}

// wordEngine is the reference engine plus one finding the pattern pass
// does not make: the word BLUEHERON, as a secret.
type wordEngine struct{ guardrail.RulesEngine }

func (e wordEngine) Scan(ctx context.Context, req *pb.GuardrailScanRequest) (*pb.GuardrailScanResponse, error) {
	resp, err := e.RulesEngine.Scan(ctx, req)
	if err != nil {
		return nil, err
	}
	for _, u := range req.GetUnits() {
		if at := strings.Index(u.GetText(), "BLUEHERON"); at >= 0 {
			start := int32(utf8.RuneCountInString(u.GetText()[:at]))
			resp.Findings = append(resp.Findings, &pb.GuardrailFinding{UnitId: u.GetUnitId(), Start: start, End: start + 9,
				Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Type: "CODENAME", Confidence: 1})
		}
	}
	return resp, nil
}

// A secret that touches or overlaps personal data keeps the merged span a
// secret, so its value is never written to the marker map.
func TestMergeSpans_SecretDecidesTheKind(t *testing.T) {
	pii, secret := pb.GuardrailKind_GUARDRAIL_KIND_PII, pb.GuardrailKind_GUARDRAIL_KIND_SECRET
	for name, in := range map[string][]span{
		"touching, equal confidence":  {{0, 11, pii, "SSN", 1}, {11, 40, secret, "PRIVATE_KEY", 1}},
		"overlap, pii more confident": {{0, 20, pii, "EMAIL", 0.9}, {5, 15, secret, "TOKEN", 0.5}},
	} {
		got := mergeSpans(in)
		if len(got) != 1 || got[0].kind != secret {
			t.Errorf("%s: %+v, want one SECRET span", name, got)
		}
	}
	h, dir := newHandler(t, nil)
	fire(t, h, evPost, readResult("/w/k", "123-45-6789"+pemBegin+"\n"+pemBody+"\n"+pemEnd))
	if stateContains(t, dir, pemBody) {
		t.Error("key material was persisted through a merged personal-data span")
	}
}

// A block marker that cannot be read is treated as set: the session stays
// held rather than released by an error.
func TestUserPromptSubmit_UnreadableBlockMarkerHoldsTheSession(t *testing.T) {
	h, dir := newHandler(t, func(c *Config) { c.BlockOnBatchFinding = true })
	fire(t, h, evSession, `{"session_id":"s1","source":"startup"}`)
	// A file where the directory should be: every lookup under it fails
	// with something other than "does not exist".
	if err := os.WriteFile(filepath.Join(dir, blockedDir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if out := fire(t, h, evPrompt, `{"session_id":"s1","prompt":"what next"}`); out.Decision != "block" {
		t.Fatalf("an unreadable block marker must hold the session: %+v", out)
	}
}

// Each excerpt is the window around its own marker, however far into a
// large unit the span is.
func TestPostToolUse_ExcerptIsTheWindowAroundEachMarker(t *testing.T) {
	h, dir := newHandler(t, nil)
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString(strings.Repeat("filler ", 10) + "row" + string(rune('a'+i%26)) + " " + synthEmail + "\n")
	}
	fire(t, h, evPost, postInput("FutureTool", `{}`, q(b.String())))
	n := 0
	for _, r := range spoolRows(t, dir) {
		if r.GetOutcome() != pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_REDACTED {
			continue
		}
		n++
		ex := r.GetExcerpt()
		if !strings.Contains(ex, "row") || !strings.Contains(ex, "[[EMAIL:") || strings.Contains(ex, synthEmail) || utf8.RuneCountInString(ex) > 2*excerptContext+len("[[EMAIL:0123456789ab]]") {
			t.Errorf("excerpt %q", ex)
		}
	}
	if n != 200 {
		t.Errorf("%d REDACTED rows, want 200", n)
	}
	if got := excerpt("ab [[X:1]] cd", 3, "[[X:1]]"); got != "ab [[X:1]] cd" {
		t.Errorf("excerpt = %q", got)
	}
	if got := excerpt("ab", -1, "[[X:1]]"); got != "[[X:1]]" {
		t.Errorf("a token not in the text is its own excerpt: %q", got)
	}
}

// Object keys and numbers are text the model reads too.
func TestPostToolUse_KeysAndNumbersAreScanned(t *testing.T) {
	h, dir := newHandler(t, nil)
	const card = "4111111111111111" // the card network's documented test number
	out := fire(t, h, evPost, postInput("FutureTool", `{}`, `{"users":{`+q(synthEmail)+`:{"id":1}},"card":`+card+`,"count":6}`))
	if out.HookSpecificOutput == nil {
		t.Fatal("a result with a personal-data key must be redacted")
	}
	raw := string(out.HookSpecificOutput.UpdatedToolOutput)
	if strings.Contains(raw, synthEmail) || strings.Contains(raw, card) {
		t.Fatalf("value reached the model: %s", raw)
	}
	var got struct {
		Users map[string]struct {
			ID json.Number `json:"id"`
		} `json:"users"`
		Card  string      `json:"card"`
		Count json.Number `json:"count"`
	}
	if err := json.Unmarshal(out.HookSpecificOutput.UpdatedToolOutput, &got); err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	if len(got.Users) != 1 {
		t.Fatalf("users = %v", got.Users)
	}
	for k, v := range got.Users {
		if !strings.HasPrefix(k, "[[EMAIL:") || v.ID != "1" {
			t.Errorf("key %q -> %+v, want an EMAIL marker keeping its value", k, v)
		}
	}
	if !strings.HasPrefix(got.Card, "[[CREDIT_CARD:") || got.Count != "6" {
		t.Errorf("card %q count %q", got.Card, got.Count)
	}
	if !stateContains(t, dir, synthEmail) {
		t.Error("the PII key must be in the marker map, or it can never be restored")
	}

	// A redacted key that lands on a key already present keeps both values.
	pii, _ := seedMarkers(t, h)
	out = fire(t, h, evPost, postInput("FutureTool", `{}`, `{`+q(synthEmail)+`:1,`+q(pii)+`:2}`))
	if out.HookSpecificOutput == nil {
		t.Fatal("a result with a personal-data key must be redacted")
	}
	var both map[string]int
	if err := json.Unmarshal(out.HookSpecificOutput.UpdatedToolOutput, &both); err != nil {
		t.Fatal(err)
	}
	sum := 0
	for k, v := range both {
		if strings.Contains(k, synthEmail) {
			t.Errorf("key reached the model: %q", k)
		}
		sum += v
	}
	if len(both) != 2 || sum != 3 {
		t.Errorf("a key collision lost a value: %v", both)
	}
}
