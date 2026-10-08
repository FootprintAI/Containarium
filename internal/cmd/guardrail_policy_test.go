package cmd

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeGuardrailPolicyAPI records what the CLI sends and serves from an
// in-memory store, the same one the daemon uses without a database.
type fakeGuardrailPolicyAPI struct {
	store  *guardrailpolicy.MemoryStore
	sets   []*pb.SetGuardrailPolicyRequest
	getErr error // when set, Get fails the way an unreachable daemon does
}

func (f *fakeGuardrailPolicyAPI) GetGuardrailPolicy() (*pb.GetGuardrailPolicyResponse, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	p, err := f.store.Get(context.Background())
	if errors.Is(err, guardrailpolicy.ErrNotConfigured) {
		return &pb.GetGuardrailPolicyResponse{}, nil
	}
	if err != nil {
		return nil, err
	}
	h, _ := guardrailpolicy.Hash(p)
	return &pb.GetGuardrailPolicyResponse{Configured: true, Policy: p, PolicyHash: h}, nil
}

func (f *fakeGuardrailPolicyAPI) SetGuardrailPolicy(req *pb.SetGuardrailPolicyRequest) (*pb.SetGuardrailPolicyResponse, error) {
	f.sets = append(f.sets, proto.Clone(req).(*pb.SetGuardrailPolicyRequest))
	res, err := f.store.Set(context.Background(), req.GetPolicy(), req.GetTrustedSigners(), "ops")
	if err != nil {
		return nil, err
	}
	h, _ := guardrailpolicy.Hash(res.Current)
	return &pb.SetGuardrailPolicyResponse{Policy: res.Current, PolicyHash: h}, nil
}

func withFakeGuardrailPolicyAPI(t *testing.T) *fakeGuardrailPolicyAPI {
	t.Helper()
	fake := &fakeGuardrailPolicyAPI{store: guardrailpolicy.NewMemoryStore()}
	prev := newGuardrailPolicyAPI
	newGuardrailPolicyAPI = func() (guardrailPolicyAPI, func(), error) { return fake, func() {}, nil }
	t.Cleanup(func() { newGuardrailPolicyAPI = prev })
	return fake
}

func runGuardrailPolicy(t *testing.T, args ...string) (string, error) {
	t.Helper()
	guardrailPolicyJSON, guardrailPolicySetFile = false, ""
	return runGuardrail(t, append([]string{"policy"}, args...)...)
}

func writePolicyFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGuardrailPolicyCLI_GetSet(t *testing.T) {
	fake := withFakeGuardrailPolicyAPI(t)

	out, err := runGuardrailPolicy(t, "get")
	if err != nil || !strings.Contains(out, "not configured") {
		t.Fatalf("get before set = (%q, %v), want a not-configured report", out, err)
	}

	pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	keyID := guardrail.KeyID(pub)
	file := writePolicyFile(t, `{"policy":{"rules":[`+
		`{"kind":"GUARDRAIL_KIND_PII","action":"GUARDRAIL_ACTION_REDACT","maxResidual":1},`+
		`{"kind":"GUARDRAIL_KIND_SECRET","action":"GUARDRAIL_ACTION_BLOCK"}]},`+
		`"trustedSigners":[{"keyId":"`+keyID+`","publicKey":"`+base64.StdEncoding.EncodeToString(pub)+`","label":"release key"}]}`)
	out, err = runGuardrailPolicy(t, "set", "--file", file)
	if err != nil {
		t.Fatalf("set: %v (%s)", err, out)
	}
	if len(fake.sets) != 1 || fake.sets[0].GetPolicy().GetRules()[1].GetAction() != pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK {
		t.Fatalf("set sent %v, want the file's two rules", fake.sets)
	}
	wantHash, _ := guardrail.PolicyHash(fake.sets[0].GetPolicy())
	if !strings.Contains(out, "revision 1") || !strings.Contains(out, wantHash) {
		t.Fatalf("set output %q, want revision 1 and the policy hash", out)
	}

	out, err = runGuardrailPolicy(t, "get")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	for _, want := range []string{"Revision:", "1", wantHash, "PII", "REDACT", "SECRET", "BLOCK", keyID, "release key"} {
		if !strings.Contains(out, want) {
			t.Fatalf("get output missing %q:\n%s", want, out)
		}
	}
	for enc, key := range map[string]string{
		"base64":     base64.StdEncoding.EncodeToString(pub),
		"base64 raw": base64.RawStdEncoding.EncodeToString(pub),
		"base64 url": base64.RawURLEncoding.EncodeToString(pub),
		"hex":        hex.EncodeToString(pub),
	} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(key)) {
			t.Fatalf("text output prints the raw public key (%s):\n%s", enc, out)
		}
	}

	out, err = runGuardrailPolicy(t, "get", "--json")
	if err != nil {
		t.Fatalf("get --json: %v", err)
	}
	var decoded pb.GetGuardrailPolicyResponse
	if err := protojson.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("get --json is not the response's protojson: %v\n%s", err, out)
	}
	if !decoded.GetConfigured() || decoded.GetPolicyHash() != wantHash {
		t.Fatalf("get --json = %v, want configured with hash %s", &decoded, wantHash)
	}
}

// TestGuardrailPolicyCLI_GetErrorIsAnError: a failed Get (daemon down, or
// the store unavailable) is a command error, never a "not configured"
// report, in both the text and --json forms.
func TestGuardrailPolicyCLI_GetErrorIsAnError(t *testing.T) {
	fake := withFakeGuardrailPolicyAPI(t)
	fake.getErr = errors.New("rpc error: code = Internal desc = read guardrail policy failed")
	for _, args := range [][]string{{"get"}, {"get", "--json"}} {
		out, err := runGuardrailPolicy(t, args...)
		if err == nil {
			t.Fatalf("%v with a failing daemon = nil error (output %q), want the error", args, out)
		}
		if strings.Contains(out, "configured") {
			t.Fatalf("%v with a failing daemon printed %q, want no policy report", args, out)
		}
	}
}

// TestGuardrailPolicyCLI_SetRefusesBadFileLocally: a malformed or invalid
// file never reaches the daemon.
func TestGuardrailPolicyCLI_SetRefusesBadFileLocally(t *testing.T) {
	fake := withFakeGuardrailPolicyAPI(t)
	for name, body := range map[string]string{
		"unknown field":  `{"policy":{"rules":[]},"policyy":{}}`,
		"duplicate kind": `{"policy":{"rules":[{"kind":"GUARDRAIL_KIND_PII","action":"GUARDRAIL_ACTION_REDACT"},{"kind":"GUARDRAIL_KIND_PII","action":"GUARDRAIL_ACTION_BLOCK"}]}}`,
		"no policy":      `{}`,
	} {
		if _, err := runGuardrailPolicy(t, "set", "--file", writePolicyFile(t, body)); err == nil {
			t.Errorf("set with %s = nil, want an error", name)
		}
	}
	if _, err := runGuardrailPolicy(t, "set"); err == nil {
		t.Errorf("set without --file = nil, want an error")
	}
	if len(fake.sets) != 0 {
		t.Fatalf("invalid files reached the daemon: %v", fake.sets)
	}
}
