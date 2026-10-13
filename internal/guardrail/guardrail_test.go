package guardrail

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func pii(typ string, start, end int32) *pb.GuardrailFinding {
	return &pb.GuardrailFinding{UnitId: "u", Start: start, End: end, Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Type: typ, Confidence: 1}
}

// The reference engine reports CODE POINT offsets. A multi-byte prefix
// before the match is the case a byte-offset bug would get wrong.
func TestRulesEngine_OffsetsAreCodePoints(t *testing.T) {
	text := "客戶來電：mail is ann@example.com, ssn 123-45-6789."
	resp, err := RulesEngine{}.Scan(context.Background(), &pb.GuardrailScanRequest{
		Units: []*pb.GuardrailTextUnit{{UnitId: "u", Text: text}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runes := []rune(text)
	got := map[string]string{}
	for _, f := range resp.Findings {
		got[f.Type] = string(runes[f.Start:f.End])
	}
	if got["EMAIL"] != "ann@example.com" {
		t.Errorf("EMAIL slice = %q", got["EMAIL"])
	}
	if got["SSN"] != "123-45-6789" {
		t.Errorf("SSN slice = %q", got["SSN"])
	}
	if resp.EngineId != RulesEngineID || !strings.HasPrefix(resp.EngineVersion, "rules@") {
		t.Errorf("engine identity = %q %q", resp.EngineId, resp.EngineVersion)
	}
}

func TestRulesEngine_KindFilterAndLuhn(t *testing.T) {
	text := "card 4111 1111 1111 1111 and not-a-card 1234 5678 9012 3456; key AKIAIOSFODNN7EXAMPLE"
	resp, err := RulesEngine{}.Scan(context.Background(), &pb.GuardrailScanRequest{
		Units: []*pb.GuardrailTextUnit{{UnitId: "u", Text: text}},
		Kinds: []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII},
	})
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, f := range resp.Findings {
		types = append(types, f.Type)
	}
	if strings.Join(types, ",") != "CREDIT_CARD" {
		t.Errorf("PII-only scan found %v; want exactly the Luhn-valid card, no secret", types)
	}
	if _, err := (RulesEngine{}).Scan(context.Background(), &pb.GuardrailScanRequest{Kinds: []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_UNSPECIFIED}}); err == nil {
		t.Error("UNSPECIFIED kind must be rejected, not treated as 'all'")
	}
}

func TestRedact_StableTokensAndVault(t *testing.T) {
	units := []*pb.GuardrailTextUnit{
		{UnitId: "u", Text: "a@x.io wrote to a@x.io; key -----BEGIN PRIVATE KEY-----"},
		{UnitId: "clean", Text: "nothing here"},
	}
	findings := []*pb.GuardrailFinding{
		pii("EMAIL", 0, 6), pii("EMAIL", 16, 22),
		{UnitId: "u", Start: 28, End: 55, Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Type: "PRIVATE_KEY", Confidence: 1},
	}
	res, err := Redact(units, findings, DefaultPolicy(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	tok := Token(testKey, pb.GuardrailKind_GUARDRAIL_KIND_PII, "EMAIL", "a@x.io")
	if want := tok + " wrote to " + tok + "; key " + Token(testKey, pb.GuardrailKind_GUARDRAIL_KIND_SECRET, "PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----"); res.Wiped["u"] != want {
		t.Errorf("wiped = %q\nwant    %q", res.Wiped["u"], want)
	}
	if res.Wiped["clean"] != "nothing here" {
		t.Errorf("unit without findings must be copied verbatim, got %q", res.Wiped["clean"])
	}
	if len(res.Vault) != 1 || res.Vault[tok].Value != "a@x.io" {
		t.Errorf("vault = %+v; want exactly the one PII token (same value => one entry) and NO secret", res.Vault)
	}
	if res.Found[pb.GuardrailKind_GUARDRAIL_KIND_PII] != 2 || res.Found[pb.GuardrailKind_GUARDRAIL_KIND_SECRET] != 1 {
		t.Errorf("found = %v", res.Found)
	}
	if !placeholderRE.MatchString(tok) {
		t.Errorf("token %q is not recognised by placeholderRE — the gate would count it as residual", tok)
	}
}

func TestRedact_OverlapMergeBlockAndRangeCheck(t *testing.T) {
	units := []*pb.GuardrailTextUnit{{UnitId: "u", Text: "John Smith <j@x.io>"}}
	findings := []*pb.GuardrailFinding{
		pii("PERSON_NAME", 0, 10),
		{UnitId: "u", Start: 5, End: 10, Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Type: "SURNAME", Confidence: 0.4},
		pii("EMAIL", 12, 18),
	}
	res, err := Redact(units, findings, DefaultPolicy(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(res.Wiped["u"], "[[") != 2 {
		t.Errorf("overlapping spans must merge into one token: %q", res.Wiped["u"])
	}
	if !strings.Contains(res.Wiped["u"], "[[PERSON_NAME:") {
		t.Errorf("merged span should keep the higher-confidence type: %q", res.Wiped["u"])
	}

	block := &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK}}}
	res, err = Redact(units, findings, block, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if res.Blocked[pb.GuardrailKind_GUARDRAIL_KIND_PII] != 3 || res.Wiped["u"] != "John Smith <j@x.io>" {
		t.Errorf("BLOCK must count, not rewrite: blocked=%v wiped=%q", res.Blocked, res.Wiped["u"])
	}

	if _, err := Redact(units, []*pb.GuardrailFinding{pii("X", 5, 99)}, DefaultPolicy(), testKey); err == nil {
		t.Error("out-of-range finding must be an error, never a silent partial redaction")
	}
	if _, err := Redact(units, nil, DefaultPolicy(), nil); err == nil {
		t.Error("empty key must be refused")
	}
}

func TestGate(t *testing.T) {
	tok := Token(testKey, pb.GuardrailKind_GUARDRAIL_KIND_PII, "PERSON_NAME", "Ann")
	wiped := map[string]string{"u": "hello " + tok + " and bob@x.io"}
	// "[[PERSON_NAME:" + 12 hex + "]]" is 28 code points; pin it so the
	// literal offsets below cannot silently drift from the token format.
	if n := len([]rune(tok)); n != 28 {
		t.Fatalf("token %q is %d code points, test offsets assume 28", tok, n)
	}
	const tokStart, tokEnd int32 = 6, 34

	inside := &pb.GuardrailScanResponse{Findings: []*pb.GuardrailFinding{pii("PERSON", tokStart+2, tokStart+8)}}
	if g := Gate(inside, wiped, DefaultPolicy(), nil); g.Verdict != pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS || g.InPlaceholder != 1 {
		t.Errorf("finding inside a placeholder must be ignored: %+v", g)
	}

	real := &pb.GuardrailScanResponse{Findings: []*pb.GuardrailFinding{pii("EMAIL", tokEnd+5, tokEnd+13)}}
	if g := Gate(real, wiped, DefaultPolicy(), nil); g.Verdict != pb.GuardrailVerdict_GUARDRAIL_VERDICT_FAIL || len(g.Reasons) != 1 {
		t.Errorf("real residual must fail with one reason: %+v", g)
	}
	tolerant := &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT, MaxResidual: 1}}}
	if g := Gate(real, wiped, tolerant, nil); g.Verdict != pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS {
		t.Errorf("max_residual=1 must tolerate one: %+v", g)
	}

	gap := &pb.GuardrailScanResponse{Gaps: []*pb.GuardrailScanGap{{UnitId: "u", Detail: "x"}}}
	if g := Gate(gap, wiped, DefaultPolicy(), nil); g.Verdict != pb.GuardrailVerdict_GUARDRAIL_VERDICT_FAIL {
		t.Errorf("a coverage gap must fail: %+v", g)
	}
	if g := Gate(&pb.GuardrailScanResponse{}, wiped, DefaultPolicy(), map[pb.GuardrailKind]int64{pb.GuardrailKind_GUARDRAIL_KIND_SECRET: 1}); g.Verdict != pb.GuardrailVerdict_GUARDRAIL_VERDICT_FAIL {
		t.Errorf("a BLOCK count must fail even with a clean re-scan: %+v", g)
	}
}

func TestAttestation_SignVerifyAndSubject(t *testing.T) {
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bee"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "sub", "a.txt"), []byte("ay"), 0o644))
	digest, err := SubjectDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Same content under a different parent path, written in another order: same digest.
	dir2 := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir2, "sub"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir2, "sub", "a.txt"), []byte("ay"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir2, "b.txt"), []byte("bee"), 0o600))
	if d2, _ := SubjectDigest(dir2); d2 != digest {
		t.Errorf("digest depends on something other than paths+content: %s vs %s", digest, d2)
	}

	prefix := filepath.Join(t.TempDir(), "k")
	pub, err := GenerateKeyFiles(prefix)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := LoadSigningKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(prefix + ".key"); st.Mode().Perm() != 0o600 {
		t.Errorf("private key file mode = %o, want 0600", st.Mode().Perm())
	}
	policyHash, _ := PolicyHash(DefaultPolicy())
	att := &pb.GuardrailAttestation{
		SubjectSha256: digest, EngineId: RulesEngineID, EngineVersion: "rules@x", PolicyHash: policyHash,
		Verdict: pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS,
	}
	must(t, Sign(att, priv))
	if att.KeyId != KeyID(pub) {
		t.Errorf("key_id = %s, want %s", att.KeyId, KeyID(pub))
	}
	must(t, VerifySubject(att, pub, dir))

	// Tamper with the subject after signing.
	must(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bee!"), 0o644))
	if err := VerifySubject(att, pub, dir); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("changed bytes must fail on the digest, got %v", err)
	}
	// Tamper with the record.
	att.Verdict = pb.GuardrailVerdict_GUARDRAIL_VERDICT_FAIL
	if err := Verify(att, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("edited attestation must fail the signature, got %v", err)
	}
	// Wrong key.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	att.Verdict = pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS
	if err := Verify(att, otherPub); err == nil || !strings.Contains(err.Error(), "signed by key") {
		t.Errorf("wrong public key must be named, got %v", err)
	}
}

func TestLoadUnits_InvalidUTF8IsAGap(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("fine"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "bad.bin"), []byte{0xff, 0xfe, 'x'}, 0o644))
	units, gaps, err := LoadUnits(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 1 || units[0].UnitId != "ok.txt" {
		t.Errorf("units = %v", units)
	}
	if len(gaps) != 1 || gaps[0].UnitId != "bad.bin" {
		t.Errorf("undecodable file must be a gap, got %v", gaps)
	}
	out := t.TempDir()
	must(t, WriteUnits(out, map[string]string{"sub/x.txt": "y"}))
	if b, _ := os.ReadFile(filepath.Join(out, "sub", "x.txt")); string(b) != "y" {
		t.Errorf("WriteUnits did not mirror the unit id as a path")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
