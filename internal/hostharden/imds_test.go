package hostharden

import (
	"errors"
	"strings"
	"testing"
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
