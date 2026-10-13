//go:build !windows && !containarium_client

package cmd

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/sentinel"
)

// captureLog redirects the standard logger for the duration of a test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestConfigureTunnelTransport_FirstStartGeneratesThenRestartReuses(t *testing.T) {
	logs := captureLog(t)
	path := filepath.Join(t.TempDir(), "conf", "sentinel-tunnel-identity.pem")

	ts1 := sentinel.NewTunnelServer("", sentinel.NewTokenPolicy(), sentinel.NewTunnelRegistry(), 0)
	pin1, err := configureTunnelTransport(ts1, path)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("identity file not created: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("identity file mode = %o, want 600", mode)
	}
	if !strings.Contains(logs.String(), string(pin1)) {
		t.Errorf("startup log does not contain the pin %s:\n%s", pin1, logs.String())
	}
	if !strings.Contains(logs.String(), "generated") {
		t.Errorf("first start should log that the identity was generated:\n%s", logs.String())
	}

	logs.Reset()
	ts2 := sentinel.NewTunnelServer("", sentinel.NewTokenPolicy(), sentinel.NewTunnelRegistry(), 0)
	pin2, err := configureTunnelTransport(ts2, path)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if pin2 != pin1 {
		t.Errorf("restart pin = %s, want reused %s", pin2, pin1)
	}
	if strings.Contains(logs.String(), "generated") {
		t.Errorf("restart must reuse, not regenerate:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), string(pin1)) {
		t.Errorf("restart log does not contain the pin:\n%s", logs.String())
	}
}

func TestConfigureTunnelTransport_UnreadableIdentityIsErrorAndKept(t *testing.T) {
	captureLog(t)
	path := filepath.Join(t.TempDir(), "id.pem")
	garbage := []byte("not a pem file\n")
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	ts := sentinel.NewTunnelServer("", sentinel.NewTokenPolicy(), sentinel.NewTunnelRegistry(), 0)
	if _, err := configureTunnelTransport(ts, path); err == nil {
		t.Fatal("want error for an unreadable identity file")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, garbage) {
		t.Error("unreadable identity file was overwritten")
	}
}

func TestPrintTunnelIdentityPin_AcceptedByClientVerifier(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.pem")
	id, err := sentinel.GenerateTunnelIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(path); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := printTunnelIdentityPin(&out, path); err != nil {
		t.Fatalf("printTunnelIdentityPin: %v", err)
	}
	pins, err := sentinel.ParsePins(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatalf("output %q is not a pin: %v", out.String(), err)
	}
	if len(pins) != 1 || pins[0] != id.Pin() {
		t.Fatalf("printed pins %v, want [%s]", pins, id.Pin())
	}
	cert := id.TLSCertificate()
	if err := sentinel.VerifyPinned(pins)(cert.Certificate, nil); err != nil {
		t.Errorf("client verifier rejected the printed pin: %v", err)
	}

	other, err := sentinel.GenerateTunnelIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := sentinel.VerifyPinned(pins)(other.TLSCertificate().Certificate, nil); err == nil {
		t.Error("printed pin must not accept a different identity")
	}
}

func TestPrintTunnelIdentityPin_MissingFileIsErrorAndNotCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.pem")
	var out bytes.Buffer
	err := printTunnelIdentityPin(&out, path)
	if err == nil {
		t.Fatal("want error for a missing identity file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error %v should wrap os.ErrNotExist", err)
	}
	if out.Len() != 0 {
		t.Errorf("nothing should be printed on error, got %q", out.String())
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("tunnel-identity must not create the identity file")
	}
}

func TestSentinelTunnelFlagsDefaults(t *testing.T) {
	cleartext := sentinelCmd.Flags().Lookup("tunnel-allow-cleartext")
	if cleartext == nil {
		t.Fatal("sentinel has no --tunnel-allow-cleartext flag")
	}
	if cleartext.DefValue != "false" {
		t.Errorf("--tunnel-allow-cleartext default = %s, want false", cleartext.DefValue)
	}
	identity := sentinelCmd.Flags().Lookup("tunnel-tls-identity")
	if identity == nil {
		t.Fatal("sentinel has no --tunnel-tls-identity flag")
	}
	if identity.DefValue != sentinel.DefaultTunnelIdentityPath {
		t.Errorf("--tunnel-tls-identity default = %s, want %s", identity.DefValue, sentinel.DefaultTunnelIdentityPath)
	}

	sub, _, err := sentinelCmd.Find([]string{"tunnel-identity"})
	if err != nil || sub == nil || sub.Name() != "tunnel-identity" {
		t.Fatalf("sentinel tunnel-identity subcommand not registered: %v", err)
	}
	subFlag := sub.Flags().Lookup("tunnel-tls-identity")
	if subFlag == nil || subFlag.DefValue != sentinel.DefaultTunnelIdentityPath {
		t.Errorf("tunnel-identity --tunnel-tls-identity flag missing or default wrong: %+v", subFlag)
	}
}

// TestSentinelTunnelAllowCleartextDeprecated: the removed flag still parses
// so existing service units start. false is a no-op; true is refused with an
// error that says cleartext tunnels are no longer supported.
func TestSentinelTunnelAllowCleartextDeprecated(t *testing.T) {
	flag := sentinelCmd.Flags().Lookup("tunnel-allow-cleartext")
	if flag == nil {
		t.Fatal("sentinel has no --tunnel-allow-cleartext flag")
	}
	if flag.Deprecated == "" {
		t.Error("--tunnel-allow-cleartext is not marked deprecated")
	}
	t.Cleanup(func() {
		_ = flag.Value.Set(flag.DefValue)
		flag.Changed = false
	})

	if err := sentinelCmd.ParseFlags([]string{"--tunnel-allow-cleartext=false"}); err != nil {
		t.Fatalf("parse false: %v", err)
	}
	if err := checkDeprecatedCleartextFlag(sentinelTunnelAllowCleartext); err != nil {
		t.Errorf("--tunnel-allow-cleartext=false must be a no-op, got %v", err)
	}

	if err := sentinelCmd.ParseFlags([]string{"--tunnel-allow-cleartext=true"}); err != nil {
		t.Fatalf("parse true: %v", err)
	}
	err := checkDeprecatedCleartextFlag(sentinelTunnelAllowCleartext)
	if err == nil || !strings.Contains(err.Error(), "no longer supported") {
		t.Errorf("--tunnel-allow-cleartext=true error = %v, want 'no longer supported'", err)
	}
}
