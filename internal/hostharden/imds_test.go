package hostharden

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type call struct {
	name string
	args []string
}

func fakeRunner(t *testing.T, calls *[]call, responses map[string]result) runner {
	t.Helper()
	return func(name string, args ...string) ([]byte, error) {
		*calls = append(*calls, call{name, args})
		key := name + " " + strings.Join(args, " ")
		for pattern, r := range responses {
			if strings.HasPrefix(key, pattern) {
				return []byte(r.out), r.err
			}
		}
		t.Fatalf("unexpected command: %s", key)
		return nil, nil
	}
}

type result struct {
	out string
	err error
}

func TestBridgeSubnet(t *testing.T) {
	t.Run("resolves the configured address", func(t *testing.T) {
		var calls []call
		run := fakeRunner(t, &calls, map[string]result{
			"incus network get incusbr0 ipv4.address": {out: "10.0.3.1/24\n"},
		})
		got, err := bridgeSubnet(run, "incusbr0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "10.0.3.1/24" {
			t.Errorf("got %q, want 10.0.3.1/24", got)
		}
	})

	t.Run("errors when incus fails", func(t *testing.T) {
		var calls []call
		run := fakeRunner(t, &calls, map[string]result{
			"incus network get incusbr0 ipv4.address": {out: "not found", err: errors.New("exit 1")},
		})
		if _, err := bridgeSubnet(run, "incusbr0"); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("errors when the bridge has no address (none)", func(t *testing.T) {
		var calls []call
		run := fakeRunner(t, &calls, map[string]result{
			"incus network get incusbr0 ipv4.address": {out: "none\n"},
		})
		if _, err := bridgeSubnet(run, "incusbr0"); err == nil {
			t.Fatal("expected an error for an unconfigured bridge")
		}
	})
}

func TestBlockMetadataFromBridge(t *testing.T) {
	t.Run("inserts the rule when absent", func(t *testing.T) {
		var calls []call
		run := fakeRunner(t, &calls, map[string]result{
			"incus network get incusbr0 ipv4.address":                       {out: "10.0.3.1/24\n"},
			"iptables -C FORWARD -s 10.0.3.1/24 -d 169.254.169.254 -j DROP": {err: errors.New("exit 1: no such rule")},
			"iptables -I FORWARD -s 10.0.3.1/24 -d 169.254.169.254 -j DROP": {},
		})
		applied, detail, err := blockMetadataFromBridge(run, "incusbr0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !applied {
			t.Errorf("expected applied=true, detail=%q", detail)
		}
		if len(calls) != 3 {
			t.Fatalf("expected 3 commands (resolve, check, insert), got %d: %+v", len(calls), calls)
		}
	})

	t.Run("is idempotent when the rule already exists", func(t *testing.T) {
		var calls []call
		run := fakeRunner(t, &calls, map[string]result{
			"incus network get incusbr0 ipv4.address":                       {out: "10.0.3.1/24\n"},
			"iptables -C FORWARD -s 10.0.3.1/24 -d 169.254.169.254 -j DROP": {}, // -C succeeds: rule present
		})
		applied, detail, err := blockMetadataFromBridge(run, "incusbr0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if applied {
			t.Errorf("expected applied=false (already present), detail=%q", detail)
		}
		if len(calls) != 2 {
			t.Fatalf("expected 2 commands (resolve, check — no insert), got %d: %+v", len(calls), calls)
		}
	})

	t.Run("propagates a bridge-resolution failure without touching iptables", func(t *testing.T) {
		var calls []call
		run := fakeRunner(t, &calls, map[string]result{
			"incus network get incusbr0 ipv4.address": {err: errors.New("no such network")},
		})
		if _, _, err := blockMetadataFromBridge(run, "incusbr0"); err == nil {
			t.Fatal("expected an error")
		}
		if len(calls) != 1 {
			t.Fatalf("expected exactly 1 command (resolve only), got %d: %+v", len(calls), calls)
		}
	})

	t.Run("checks and inserts the same rule MetadataBlockPresent looks for", func(t *testing.T) {
		var calls []call
		run := fakeRunner(t, &calls, map[string]result{
			"incus network get incusbr0 ipv4.address": {out: "10.0.3.1/24\n"},
			"iptables -C": {err: errors.New("no such rule")},
			"iptables -I": {},
		})
		if _, _, err := blockMetadataFromBridge(run, "incusbr0"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := strings.Join(metadataRule("10.0.3.1/24"), " ")
		for _, c := range calls[1:] {
			if got := strings.Join(c.args[1:], " "); got != want {
				t.Errorf("iptables %s used rule %q, want %q", c.args[0], got, want)
			}
		}
	})

	t.Run("surfaces an iptables insert failure", func(t *testing.T) {
		var calls []call
		run := fakeRunner(t, &calls, map[string]result{
			"incus network get incusbr0 ipv4.address":                       {out: "10.0.3.1/24\n"},
			"iptables -C FORWARD -s 10.0.3.1/24 -d 169.254.169.254 -j DROP": {err: errors.New("no such rule")},
			"iptables -I FORWARD -s 10.0.3.1/24 -d 169.254.169.254 -j DROP": {out: "iptables: command not found", err: errors.New("exit 127")},
		})
		if _, _, err := blockMetadataFromBridge(run, "incusbr0"); err == nil {
			t.Fatal("expected an error")
		}
	})
}

// exitErr stands in for *exec.ExitError: an error that carries the process's
// exit status.
type exitErr int

func (e exitErr) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitErr) ExitCode() int { return int(e) }

// metadataBlockPresent reads the exit status through this method set; the
// real runner's error must have it too.
var _ interface{ ExitCode() int } = (*exec.ExitError)(nil)

// TestTimeoutRunner runs real processes: the bound only matters against a
// command that actually hangs.
func TestTimeoutRunner(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on this host")
	}

	t.Run("a command that finishes keeps its output and exit status", func(t *testing.T) {
		out, err := timeoutRunner(5*time.Second)("sh", "-c", "echo no such rule; exit 1")
		var exit interface{ ExitCode() int }
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Fatalf("err = %v, want exit status 1 (metadataBlockPresent's \"absent\")", err)
		}
		if strings.TrimSpace(string(out)) != "no such rule" {
			t.Errorf("out = %q", out)
		}
	})

	t.Run("a hung command is cut off, even if a child holds its output open", func(t *testing.T) {
		start := time.Now()
		// The backgrounded sleep inherits stdout, so killing sh alone would
		// leave CombinedOutput waiting for it.
		_, err := timeoutRunner(100*time.Millisecond)("sh", "-c", "sleep 30 & sleep 30")
		elapsed := time.Since(start)
		if err == nil || !strings.Contains(err.Error(), "did not finish within") {
			t.Fatalf("err = %v, want a timeout error", err)
		}
		var exit interface{ ExitCode() int }
		if errors.As(err, &exit) {
			t.Errorf("timeout error carries exit code %d; it must read as unknown, not as a verdict", exit.ExitCode())
		}
		if elapsed > 5*time.Second {
			t.Errorf("returned after %v; the timeout plus probeWaitDelay should bound it to about 1s", elapsed)
		}
	})
}

func TestMetadataBlockPresent(t *testing.T) {
	const check = "iptables -C FORWARD -s 10.0.3.1/24 -d 169.254.169.254 -j DROP"
	cases := []struct {
		name        string
		responses   map[string]result
		wantPresent bool
		wantErr     bool
		wantCalls   int
	}{
		{
			name: "rule present",
			responses: map[string]result{
				"incus network get incusbr0 ipv4.address": {out: "10.0.3.1/24\n"},
				check: {},
			},
			wantPresent: true, wantCalls: 2,
		},
		{
			name: "rule absent (iptables -C exits 1)",
			responses: map[string]result{
				"incus network get incusbr0 ipv4.address": {out: "10.0.3.1/24\n"},
				check: {out: "iptables: Bad rule (does a matching rule exist in that chain?).", err: exitErr(1)},
			},
			wantCalls: 2,
		},
		{
			name: "permission denied is unknown, not absent",
			responses: map[string]result{
				"incus network get incusbr0 ipv4.address": {out: "10.0.3.1/24\n"},
				check: {out: "iptables: Permission denied (you must be root).", err: exitErr(4)},
			},
			wantErr: true, wantCalls: 2,
		},
		{
			name: "missing iptables binary is unknown, not absent",
			responses: map[string]result{
				"incus network get incusbr0 ipv4.address": {out: "10.0.3.1/24\n"},
				check: {err: exec.ErrNotFound},
			},
			wantErr: true, wantCalls: 2,
		},
		{
			name: "unresolvable bridge is unknown and never reaches iptables",
			responses: map[string]result{
				"incus network get incusbr0 ipv4.address": {out: "none\n"},
			},
			wantErr: true, wantCalls: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []call
			present, detail, err := metadataBlockPresent(fakeRunner(t, &calls, tc.responses), "incusbr0")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if present != tc.wantPresent {
				t.Errorf("present = %v, want %v (detail %q)", present, tc.wantPresent, detail)
			}
			if len(calls) != tc.wantCalls {
				t.Errorf("ran %d commands, want %d: %+v", len(calls), tc.wantCalls, calls)
			}
			for _, c := range calls {
				if c.name == "iptables" && c.args[0] != "-C" {
					t.Errorf("ran iptables %s; the probe must only check, never change", c.args[0])
				}
			}
		})
	}
}
