package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetGuardrailFlags clears the package-level flag vars between runs;
// cobra keeps them across Execute calls in one process.
func resetGuardrailFlags() {
	guardrailEngineAddr, guardrailKinds, guardrailJSON = "", nil, false
	guardrailOut, guardrailPolicyFile, guardrailVaultFile = "", "", ""
	guardrailRedactKey, guardrailSignKey, guardrailAttestFile = "", "", ""
	guardrailPublicKey, guardrailKeygenPrefix = "", ""
	guardrailRequireKinds = nil
}

func runGuardrail(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetGuardrailFlags()
	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs(append([]string{"guardrail"}, args...))
	defer rootCmd.SetArgs(nil)
	err := rootCmd.Execute()
	return out.String() + errb.String(), err
}

// The whole flow on the reference engine: keygen -> apply -> verify, then
// the two ways verify must refuse (tampered bytes, wrong key).
func TestGuardrail_ApplyThenVerify(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "raw")
	if err := os.MkdirAll(filepath.Join(in, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(filepath.Join(in, "note.txt"), []byte("Contact ann@example.com or 555-010-7788. SSN 123-45-6789.\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(in, "sub", "clean.txt"), []byte("release notes 4.12.1, nothing personal\n"), 0o644))
	out := filepath.Join(work, "clean")
	keys := filepath.Join(work, "tenant")

	if o, err := runGuardrail(t, "keygen", "--out", keys); err != nil {
		t.Fatalf("keygen: %v\n%s", err, o)
	}
	o, err := runGuardrail(t, "apply", in, "--out", out, "--sign-key", keys+".key")
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, o)
	}
	if !strings.Contains(o, "verdict: PASS") {
		t.Errorf("apply output:\n%s", o)
	}
	wiped, _ := os.ReadFile(filepath.Join(out, "note.txt"))
	for _, leaked := range []string{"ann@example.com", "555-010-7788", "123-45-6789"} {
		if strings.Contains(string(wiped), leaked) {
			t.Errorf("%q survived in the wiped output: %s", leaked, wiped)
		}
	}
	if clean, _ := os.ReadFile(filepath.Join(out, "sub", "clean.txt")); !strings.Contains(string(clean), "nothing personal") {
		t.Errorf("clean file not mirrored: %q", clean)
	}
	for _, side := range []string{out + ".vault.json", out + ".redaction.key", out + ".attestation.json"} {
		if _, err := os.Stat(side); err != nil {
			t.Errorf("expected %s beside --out: %v", side, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "..", "clean", "clean.vault.json")); err == nil {
		t.Error("vault must never land inside --out (it would be hashed into the subject)")
	}

	if o, err := runGuardrail(t, "verify", out, "--attestation", out+".attestation.json", "--public-key", keys+".pub"); err != nil {
		t.Fatalf("verify: %v\n%s", err, o)
	}

	// A consumer that received altered bytes must be refused.
	must(t, os.WriteFile(filepath.Join(out, "note.txt"), []byte("edited after attestation\n"), 0o600))
	if _, err := runGuardrail(t, "verify", out, "--attestation", out+".attestation.json", "--public-key", keys+".pub"); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("verify after tamper: want digest error, got %v", err)
	}
	// And one holding somebody else's public key must be refused by name.
	other := filepath.Join(work, "other")
	if _, err := runGuardrail(t, "keygen", "--out", other); err != nil {
		t.Fatal(err)
	}
	if _, err := runGuardrail(t, "verify", out, "--attestation", out+".attestation.json", "--public-key", other+".pub"); err == nil || !strings.Contains(err.Error(), "signed by key") {
		t.Errorf("verify with wrong key: got %v", err)
	}
}

// A file the loader cannot decode is a gap, and a gap fails the gate —
// the attestation is still written, saying FAIL.
func TestGuardrail_ApplyFailsOnGap(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "raw")
	must(t, os.MkdirAll(in, 0o755))
	must(t, os.WriteFile(filepath.Join(in, "ok.txt"), []byte("fine\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(in, "blob.bin"), []byte{0xff, 0xfe, 0x00}, 0o644))
	out := filepath.Join(work, "clean")
	o, err := runGuardrail(t, "apply", in, "--out", out)
	if err == nil || !strings.Contains(err.Error(), "gap") {
		t.Fatalf("want gate failure naming the gap, got err=%v\n%s", err, o)
	}
	att, rerr := os.ReadFile(out + ".attestation.json")
	if rerr != nil || !strings.Contains(string(att), "GUARDRAIL_VERDICT_FAIL") {
		t.Errorf("attestation must record the FAIL: %v %s", rerr, att)
	}
}

func TestGuardrail_ScanJSONNeverPrintsText(t *testing.T) {
	in := t.TempDir()
	must(t, os.WriteFile(filepath.Join(in, "a.txt"), []byte("mail bob@example.org\n"), 0o644))
	o, err := runGuardrail(t, "scan", in, "--json", "--kind", "pii")
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, o)
	}
	if !strings.Contains(o, `"EMAIL"`) || strings.Contains(o, "bob@example.org") {
		t.Errorf("scan --json must name the type and never the text:\n%s", o)
	}
	if _, err := runGuardrail(t, "scan", in, "--kind", "bogus"); err == nil {
		t.Error("unknown --kind must be rejected")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
