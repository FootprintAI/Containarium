package coderun

import (
	"strconv"
	"testing"
)

// These fixtures are agent-box's own output formats (internal/agentbox's
// handleProcessStart/handleTailLog/handleProcessKill Sprintf bodies) —
// kept in sync by hand since coderun deliberately doesn't import agentbox
// (a CLI-side package pulling in agent-box's exec/syscall internals for a
// string format would be the wrong coupling; the wire contract is text,
// not a shared Go type).

func TestParseKV_ProcessStartBody(t *testing.T) {
	body := "name: my-run\npid: 12345\ncommand: sleep 5\nlog_path: /tmp/agent-box/my-run.log\nstarted_at: 2026-09-02T12:00:00Z\n"
	kv, rest := parseKV(body, "")
	if rest != "" {
		t.Errorf("rest = %q, want empty (no content marker in this body)", rest)
	}
	want := map[string]string{
		"name": "my-run", "pid": "12345", "command": "sleep 5",
		"log_path": "/tmp/agent-box/my-run.log", "started_at": "2026-09-02T12:00:00Z",
	}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("kv[%q] = %q, want %q", k, kv[k], v)
		}
	}
}

func TestParseKV_TailLogBody_SeparatesHeaderFromContent(t *testing.T) {
	body := "path: /tmp/x.log\nstart_offset: 0\nend_offset: 11\nbytes_returned: 11\ntruncated: false\nfollow_seconds: 10\n--- content ---\nhello: not-a-header\nworld"
	kv, content := parseKV(body, tailLogContentMarker)
	if kv["end_offset"] != "11" {
		t.Errorf(`kv["end_offset"] = %q, want "11"`, kv["end_offset"])
	}
	if kv["truncated"] != "false" {
		t.Errorf(`kv["truncated"] = %q, want "false"`, kv["truncated"])
	}
	// "hello: not-a-header" must NOT be parsed as a kv pair — it's file
	// content that happens to look like one.
	if _, present := kv["hello"]; present {
		t.Error(`content line "hello: not-a-header" was parsed as a header key — content marker split failed`)
	}
	if content != "hello: not-a-header\nworld" {
		t.Errorf("content = %q, want the raw text after the marker verbatim", content)
	}
}

func TestParseKV_TailLogBody_EmptyContent(t *testing.T) {
	body := "path: /tmp/x.log\nstart_offset: 5\nend_offset: 5\nbytes_returned: 0\ntruncated: false\nfollow_seconds: 10\n--- content ---\n"
	kv, content := parseKV(body, tailLogContentMarker)
	if kv["start_offset"] != "5" || kv["end_offset"] != "5" {
		t.Errorf("kv = %+v", kv)
	}
	if content != "" {
		t.Errorf("content = %q, want empty", content)
	}
}

func TestParseKV_ProcessKillBody(t *testing.T) {
	body := "name: kill-me\npid: 999\nsignal: SIGTERM\nexited: true\nlog_path: /tmp/agent-box/kill-me.log\n"
	kv, _ := parseKV(body, "")
	if kv["signal"] != "SIGTERM" {
		t.Errorf(`kv["signal"] = %q, want "SIGTERM"`, kv["signal"])
	}
	if kv["exited"] != "true" {
		t.Errorf(`kv["exited"] = %q, want "true"`, kv["exited"])
	}
	pid, err := strconv.Atoi(kv["pid"])
	if err != nil || pid != 999 {
		t.Errorf("pid = %q (err=%v), want 999", kv["pid"], err)
	}
}

func TestParseKV_MarkerAbsentReturnsWholeBodyAsHead(t *testing.T) {
	body := "name: x\npid: 1\n"
	kv, rest := parseKV(body, tailLogContentMarker) // marker not actually present
	if rest != "" {
		t.Errorf("rest = %q, want empty when the marker never appears", rest)
	}
	if kv["name"] != "x" || kv["pid"] != "1" {
		t.Errorf("kv = %+v", kv)
	}
}
