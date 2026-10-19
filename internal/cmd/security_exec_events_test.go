package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestRunSecurityExecEvents_RequiresServer(t *testing.T) {
	oldServer := serverAddr
	serverAddr = ""
	defer func() { serverAddr = oldServer }()
	if err := runSecurityExecEvents(testCmd(), nil); err == nil {
		t.Fatal("expected an error when --server is unset")
	}
}

func TestRunSecurityExecEvents_RejectsBadSince(t *testing.T) {
	oldServer, oldSince := serverAddr, execEventsSince
	serverAddr, execEventsSince = "http://127.0.0.1:1", "soon"
	defer func() { serverAddr, execEventsSince = oldServer, oldSince }()
	err := runSecurityExecEvents(testCmd(), nil)
	if err == nil || !strings.Contains(err.Error(), "invalid --since") {
		t.Fatalf("err = %v, want an invalid --since error", err)
	}
}

func execEventJSON(t *testing.T, container string, pid uint32, argv string, truncated bool) string {
	t.Helper()
	ev := &pb.ExecEvent{
		Container: container, TenantId: "t-" + container,
		At:   timestamppb.New(mustTime(t, "2026-10-19T05:07:18Z")),
		Exec: &pb.ExecEvidence{Pid: pid, Ppid: 4100, Uid: 1000, Comm: "xmrig", Filename: "/tmp/.x/xmrig", Argv: argv, ArgvTruncated: truncated},
	}
	b, err := protojson.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The flag→request mapping (#2637): --container, --since and --follow land
// as the StreamExecEvents query parameters on the exact gateway path; each
// `{"result": …}` line renders as one formatted line.
func TestRunSecurityExecEvents_HitsExpectedPathAndRendersLines(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":{"event":` + execEventJSON(t, "box-a", 4242, "./xmrig -o pool:3333", false) + "}}\n"))
		w.Write([]byte("\n")) // keep-alive blank line is ignored
		w.Write([]byte(`{"result":{"event":` + execEventJSON(t, "box-a", 4243, "node --url=stratum+tcp://poo", true) + "}}\n"))
	}))
	defer srv.Close()

	oldServer, oldC, oldS, oldF := serverAddr, execEventsContainer, execEventsSince, execEventsFollow
	serverAddr, execEventsContainer, execEventsSince, execEventsFollow = srv.URL, "box-a", "90s", true
	defer func() {
		serverAddr, execEventsContainer, execEventsSince, execEventsFollow = oldServer, oldC, oldS, oldF
	}()

	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := runSecurityExecEvents(cmd, nil); err != nil {
		t.Fatalf("runSecurityExecEvents: %v", err)
	}
	if gotPath != "/v1/security/exec-events" {
		t.Fatalf("path = %q", gotPath)
	}
	for _, want := range []string{"container=box-a", "since=90s", "follow=true"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q missing %q", gotQuery, want)
		}
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("output lines = %d, want 2:\n%s", len(lines), buf.String())
	}
	if lines[0] != "2026-10-19T05:07:18Z  box-a  pid=4242 ppid=4100 uid=1000  /tmp/.x/xmrig  ./xmrig -o pool:3333" {
		t.Errorf("line 1 = %q", lines[0])
	}
	if !strings.HasSuffix(lines[1], "node --url=stratum+tcp://poo  [argv truncated]") {
		t.Errorf("line 2 = %q, want the truncation marker", lines[1])
	}
}

// Tenant-controlled argv/filename cannot drive the operator's terminal: ESC,
// CR, LF and other controls are escaped in the formatted line; printable
// non-ASCII stays; --json is untouched (TestStreamExecEvents_JSONPassthrough).
func TestFormatExecEvent_EscapesControlCharacters(t *testing.T) {
	ev := &pb.ExecEvent{Container: "box-a", At: timestamppb.New(mustTime(t, "2026-10-19T05:07:18Z")),
		Exec: &pb.ExecEvidence{Pid: 1, Filename: "/tmp/\x1b[2Kfake", Argv: "sh -c \x1b[1;31mALERT\r\nroot-ok café\ttab"}}
	got := formatExecEvent(ev)
	for _, raw := range []string{"\x1b", "\r", "\n", "\t"} {
		if strings.Contains(got, raw) {
			t.Errorf("formatted line still carries a raw control byte %q:\n%q", raw, got)
		}
	}
	for _, want := range []string{`/tmp/\x1b[2Kfake`, `\x1b[1;31mALERT\r\nroot-ok café\ttab`} {
		if !strings.Contains(got, want) {
			t.Errorf("formatted line missing escaped %q:\n%q", want, got)
		}
	}
	if escapeControl("plain ./xmrig -o pool:3333") != "plain ./xmrig -o pool:3333" {
		t.Error("escapeControl altered a clean string")
	}
}

// --since 0 sends no replay window and no follow by default.
func TestRunSecurityExecEvents_ZeroSinceOmitsWindow(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	oldServer, oldS := serverAddr, execEventsSince
	serverAddr, execEventsSince = srv.URL, "0"
	defer func() { serverAddr, execEventsSince = oldServer, oldS }()
	if err := runSecurityExecEvents(testCmd(), nil); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "" {
		t.Fatalf("query = %q, want none", gotQuery)
	}
}

// --json passes each event's JSON through untouched, one per line.
func TestStreamExecEvents_JSONPassthrough(t *testing.T) {
	raw := execEventJSON(t, "box-b", 7, "sh -c true", false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":{"event":` + raw + "}}\n"))
	}))
	defer srv.Close()
	var buf bytes.Buffer
	if err := streamExecEvents(context.Background(), srv.URL, &buf, true); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != raw {
		t.Fatalf("json output = %q, want %q", buf.String(), raw)
	}
}

// A mid-stream gateway error (e.g. RESOURCE_EXHAUSTED for a dropped
// subscriber) surfaces as the command's error with its message; events
// before it are still printed.
func TestStreamExecEvents_MidStreamErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":{"event":` + execEventJSON(t, "box-a", 1, "sh", false) + "}}\n"))
		w.Write([]byte(`{"error":{"code":8,"message":"exec-events subscriber fell behind and was dropped"}}` + "\n"))
	}))
	defer srv.Close()
	var buf bytes.Buffer
	err := streamExecEvents(context.Background(), srv.URL, &buf, false)
	if err == nil || !strings.Contains(err.Error(), "fell behind") {
		t.Fatalf("err = %v, want the gateway error message", err)
	}
	if !strings.Contains(buf.String(), "pid=1 ") {
		t.Fatalf("event before the error not printed:\n%s", buf.String())
	}
}

// A non-200 (exec telemetry unavailable → 503 from the gateway) reports the
// daemon's reason, the same one `sentry status` prints.
func TestStreamExecEvents_UnavailableReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"code":14,"message":"exec telemetry unavailable (netbpf: execwatch: load collection: BTF not found)"}`))
	}))
	defer srv.Close()
	err := streamExecEvents(context.Background(), srv.URL, &bytes.Buffer{}, false)
	if err == nil || !strings.Contains(err.Error(), "status 503") || !strings.Contains(err.Error(), "BTF not found") {
		t.Fatalf("err = %v", err)
	}
}

// Ctrl-C under --follow (ctx cancelled while the stream is open) is a clean
// exit, not an error.
func TestStreamExecEvents_CancelIsClean(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		cancel()
		<-r.Context().Done()
	}))
	defer srv.Close()
	if err := streamExecEvents(ctx, srv.URL, &bytes.Buffer{}, false); err != nil {
		t.Fatalf("cancelled follow returned %v, want nil", err)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}
