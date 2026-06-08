package connectcore

import (
	"errors"
	"strings"
	"testing"
)

func TestNewMarker_UniqueAndHex(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		m, err := NewMarker()
		if err != nil {
			t.Fatalf("NewMarker: %v", err)
		}
		if len(m) != 16 {
			t.Fatalf("marker %q len = %d, want 16 hex chars", m, len(m))
		}
		for _, r := range m {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				t.Fatalf("marker %q has non-hex char %q", m, r)
			}
		}
		if seen[m] {
			t.Fatalf("duplicate marker %q", m)
		}
		seen[m] = true
	}
}

func TestEncodeCommand_RoundTripSafe(t *testing.T) {
	// The encoding must be free of characters that need shell quoting, so it
	// survives ssh + remote shell + tmux unquoted.
	for _, cmd := range []string{`echo "hi"`, `cd /a/b && ls -la | grep x`, "a'b\"c$d`e", "weird\nnewline"} {
		enc := EncodeCommand(cmd)
		for _, r := range enc {
			switch {
			case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/', r == '=':
				continue
			default:
				t.Fatalf("EncodeCommand(%q) produced shell-unsafe char %q in %q", cmd, r, enc)
			}
		}
	}
}

func TestValidateSessionName(t *testing.T) {
	ok := []string{"work", "build-1", "a_b", "S"}
	for _, n := range ok {
		if err := ValidateSessionName(n); err != nil {
			t.Errorf("ValidateSessionName(%q) = %v, want nil", n, err)
		}
	}
	bad := []string{"", "has space", "dot.name", "colon:name", strings.Repeat("x", 65)}
	for _, n := range bad {
		if err := ValidateSessionName(n); err == nil {
			t.Errorf("ValidateSessionName(%q) = nil, want error", n)
		}
	}
}

func TestBuildSessionExecArgs(t *testing.T) {
	target := Target{User: "cld-x", Host: "h.example.com", Port: 22}
	args := BuildSessionExecArgs(target, "/k/id", "work", "deadbeef", "Y21k", 60)
	joined := strings.Join(args, " ")
	for _, want := range []string{"cld-x@h.example.com", "bash -s -- work deadbeef Y21k 60", "-i /k/id", "accept-new"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
	// The remote command tail must come after the destination.
	if !strings.Contains(joined, "cld-x@h.example.com bash -s --") {
		t.Errorf("bash -s should follow the destination: %q", joined)
	}
}

func TestBuildAttachArgs(t *testing.T) {
	args := BuildAttachArgs(Target{User: "alice", Host: "10.0.0.5", Port: 2222}, "/k/id", "work")
	joined := strings.Join(args, " ")
	for _, want := range []string{"-t", "-p 2222", "alice@10.0.0.5", "tmux new-session -A -s work"} {
		if !strings.Contains(joined, want) {
			t.Errorf("attach args %q missing %q", joined, want)
		}
	}
	if args[0] != "-t" {
		t.Errorf("first arg = %q, want -t (force PTY)", args[0])
	}
}

func TestParseSessionResult_Success(t *testing.T) {
	m := "deadbeef"
	raw := "CNTR_RC_" + m + "=0\nCNTR_OUT_BEGIN_" + m + "\n/app\n\nCNTR_OUT_END_" + m + "\n"
	out, code, err := ParseSessionResult(raw, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if out != "/app\n" {
		t.Errorf("out = %q, want %q", out, "/app\n")
	}
}

func TestParseSessionResult_NonZeroExit(t *testing.T) {
	m := "cafe1234"
	raw := "CNTR_RC_" + m + "=2\nCNTR_OUT_BEGIN_" + m + "\nboom\n\nCNTR_OUT_END_" + m + "\n"
	out, code, err := ParseSessionResult(raw, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(out, "boom") {
		t.Errorf("out = %q, want it to contain boom", out)
	}
}

func TestParseSessionResult_NoTmux(t *testing.T) {
	m := "aaaa1111"
	if _, _, err := ParseSessionResult("CNTR_NO_TMUX_"+m+"\n", m); !errors.Is(err, ErrNoTmux) {
		t.Fatalf("err = %v, want ErrNoTmux", err)
	}
}

func TestParseSessionResult_Timeout(t *testing.T) {
	m := "bbbb2222"
	raw := "CNTR_RC_" + m + "=timeout\nCNTR_OUT_BEGIN_" + m + "\npartial\nCNTR_OUT_END_" + m + "\n"
	out, _, err := ParseSessionResult(raw, m)
	if !errors.Is(err, ErrSessionTimeout) {
		t.Fatalf("err = %v, want ErrSessionTimeout", err)
	}
	if !strings.Contains(out, "partial") {
		t.Errorf("timeout should still return partial output, got %q", out)
	}
}

// Command output that happens to contain a delimiter-looking string must
// not break parsing, because the real delimiters carry the random marker.
func TestParseSessionResult_OutputCannotSpoofDelimiter(t *testing.T) {
	m := "9f9f9f9f"
	raw := "CNTR_RC_" + m + "=0\nCNTR_OUT_BEGIN_" + m + "\nfake CNTR_OUT_END_other line\n\nCNTR_OUT_END_" + m + "\n"
	out, code, err := ParseSessionResult(raw, m)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(out, "fake CNTR_OUT_END_other") {
		t.Errorf("output with a non-matching delimiter should survive: %q", out)
	}
}
