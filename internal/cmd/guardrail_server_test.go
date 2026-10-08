package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// piiOnlyPolicy differs from guardrail.DefaultPolicy (it ALLOWs secrets), so
// an attestation made under the default policy has a different policy_hash.
func piiOnlyPolicy() *pb.GuardrailPolicy {
	return &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT},
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_ALLOW},
	}}
}

// guardrailWork is a raw dataset and a signing key pair in a temp dir.
type guardrailWork struct {
	in, out, keys string
}

func newGuardrailWork(t *testing.T) guardrailWork {
	t.Helper()
	work := t.TempDir()
	w := guardrailWork{in: filepath.Join(work, "raw"), out: filepath.Join(work, "clean"), keys: filepath.Join(work, "tenant")}
	must(t, os.MkdirAll(w.in, 0o755))
	must(t, os.WriteFile(filepath.Join(w.in, "note.txt"), []byte("Contact ann@example.com please.\n"), 0o644))
	if o, err := runGuardrail(t, "keygen", "--out", w.keys); err != nil {
		t.Fatalf("keygen: %v\n%s", err, o)
	}
	return w
}

func (w guardrailWork) attestationFile() string { return w.out + ".attestation.json" }

func (w guardrailWork) readAttestation(t *testing.T) *pb.GuardrailAttestation {
	t.Helper()
	b, err := os.ReadFile(w.attestationFile())
	if err != nil {
		t.Fatal(err)
	}
	att := &pb.GuardrailAttestation{}
	must(t, protojson.Unmarshal(b, att))
	return att
}

// setServerPolicy stores policy on the fake daemon, trusting the key pairs
// under the given prefixes.
func setServerPolicy(t *testing.T, fake *fakeGuardrailPolicyAPI, policy *pb.GuardrailPolicy, signerPrefixes ...string) string {
	t.Helper()
	var signers []*pb.GuardrailTrustedSigner
	for _, p := range signerPrefixes {
		pub, err := guardrail.LoadPublicKey(p + ".pub")
		must(t, err)
		signers = append(signers, &pb.GuardrailTrustedSigner{KeyId: guardrail.KeyID(pub), PublicKey: pub, Label: filepath.Base(p)})
	}
	if _, err := fake.store.Set(context.Background(), policy, signers, "ops"); err != nil {
		t.Fatal(err)
	}
	h, err := guardrail.PolicyHash(policy)
	must(t, err)
	return h
}

func writeGuardrailPolicyJSON(t *testing.T, policy *pb.GuardrailPolicy) string {
	t.Helper()
	b, err := protojson.Marshal(policy)
	must(t, err)
	return writePolicyFile(t, string(b))
}

// TestGuardrailApply_ServerPolicy: with a reachable daemon that holds a
// policy, apply runs under the server's policy; --policy is accepted only
// when it hashes to the server's.
func TestGuardrailApply_ServerPolicy(t *testing.T) {
	t.Run("no --policy uses the server's", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		want := setServerPolicy(t, fake, piiOnlyPolicy(), w.keys)
		o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key")
		if err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		att := w.readAttestation(t)
		if att.GetPolicyHash() != want {
			t.Fatalf("policy_hash = %s, want the server's %s", att.GetPolicyHash(), want)
		}
		if got := kindNames(att.GetKindsScanned()); got != "pii" {
			t.Errorf("kinds_scanned = %s, want the server policy's (pii)", got)
		}
		if !strings.Contains(o, "server policy revision 1") || strings.Contains(o, "NOT server-attested") {
			t.Errorf("apply output does not say it ran under the server policy:\n%s", o)
		}
	})
	t.Run("--policy equal to the server's is accepted", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		want := setServerPolicy(t, fake, piiOnlyPolicy(), w.keys)
		o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--policy", writeGuardrailPolicyJSON(t, piiOnlyPolicy()))
		if err != nil {
			t.Fatalf("apply --policy <server's>: %v\n%s", err, o)
		}
		if got := w.readAttestation(t).GetPolicyHash(); got != want {
			t.Fatalf("policy_hash = %s, want %s", got, want)
		}
	})
	t.Run("--policy that differs is refused before anything is written", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		setServerPolicy(t, fake, piiOnlyPolicy(), w.keys)
		o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--policy", writeGuardrailPolicyJSON(t, guardrail.DefaultPolicy()))
		if err == nil || !strings.Contains(err.Error(), "does not match the server") {
			t.Fatalf("apply --policy <weaker> = %v, want refused\n%s", err, o)
		}
		for _, p := range []string{w.out, w.attestationFile()} {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Errorf("%s exists after a refused apply", p)
			}
		}
	})
}

// TestGuardrailApply_LocalModes: no daemon, an unreachable daemon, and a
// daemon with no policy keep the old local behaviour and say on stderr the
// result is NOT server-attested. A daemon that answers with an error is an
// error, never a silent fallback.
func TestGuardrailApply_LocalModes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		getErr error
	}{
		{name: "daemon unreachable", getErr: status.Error(codes.Unavailable, "connection refused")},
		{name: "no server policy configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := withFakeGuardrailPolicyAPI(t)
			fake.getErr = tc.getErr
			w := newGuardrailWork(t)
			o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--policy", writeGuardrailPolicyJSON(t, piiOnlyPolicy()))
			if err != nil {
				t.Fatalf("apply: %v\n%s", err, o)
			}
			if !strings.Contains(o, "NOT server-attested") {
				t.Errorf("local apply does not say it is not server-attested:\n%s", o)
			}
			want, _ := guardrail.PolicyHash(piiOnlyPolicy())
			if got := w.readAttestation(t).GetPolicyHash(); got != want {
				t.Errorf("local apply ignored --policy: hash %s, want %s", got, want)
			}
		})
	}
	t.Run("no --server at all", func(t *testing.T) {
		resetGuardrailFlags()
		prev := serverAddr
		serverAddr = ""
		t.Cleanup(func() { serverAddr = prev })
		w := newGuardrailWork(t)
		o, err := runGuardrail(t, "apply", w.in, "--out", w.out)
		if err != nil || !strings.Contains(o, "NOT server-attested") {
			t.Fatalf("apply with no daemon = %v, want local mode\n%s", err, o)
		}
	})
	t.Run("daemon read error is an error", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		fake.getErr = status.Error(codes.Internal, "read guardrail policy failed")
		w := newGuardrailWork(t)
		o, err := runGuardrail(t, "apply", w.in, "--out", w.out)
		if err == nil {
			t.Fatalf("apply with a failing policy read = nil error, want refused\n%s", o)
		}
		if _, statErr := os.Stat(w.attestationFile()); !os.IsNotExist(statErr) {
			t.Errorf("attestation written despite the policy read error")
		}
	})
}

// TestGuardrailVerify_ServerTrust: with a server policy, verify needs the
// attestation's policy_hash to be the server's and its signer to be a
// trusted one; --public-key is not needed. Offline, --public-key still works
// and the result is labelled not server-trusted.
func TestGuardrailVerify_ServerTrust(t *testing.T) {
	t.Run("trusted signer under the server policy passes", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		setServerPolicy(t, fake, piiOnlyPolicy(), w.keys)
		if o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		o, err := runGuardrail(t, "verify", w.out, "--attestation", w.attestationFile())
		if err != nil {
			t.Fatalf("verify: %v\n%s", err, o)
		}
		if !strings.Contains(o, "server-trusted") || strings.Contains(o, "NOT server-trusted") {
			t.Errorf("verify output does not say server-trusted:\n%s", o)
		}
	})
	t.Run("untrusted signer is refused", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		other := filepath.Join(t.TempDir(), "other")
		if o, err := runGuardrail(t, "keygen", "--out", other); err != nil {
			t.Fatalf("keygen: %v\n%s", err, o)
		}
		setServerPolicy(t, fake, piiOnlyPolicy(), other)
		if o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		// Even with the signer's own --public-key, the server check decides.
		o, err := runGuardrail(t, "verify", w.out, "--attestation", w.attestationFile(), "--public-key", w.keys+".pub")
		if err == nil || !strings.Contains(err.Error(), "trusted signer") {
			t.Fatalf("verify by an untrusted signer = %v, want refused\n%s", err, o)
		}
	})
	t.Run("attestation under a different policy is refused", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		fake.getErr = status.Error(codes.Unavailable, "offline")
		w := newGuardrailWork(t)
		// Made offline under the default policy...
		if o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		// ...then checked against a server whose policy differs.
		fake.getErr = nil
		setServerPolicy(t, fake, piiOnlyPolicy(), w.keys)
		o, err := runGuardrail(t, "verify", w.out, "--attestation", w.attestationFile())
		if err == nil || !strings.Contains(err.Error(), "different policy") {
			t.Fatalf("verify under a different policy = %v, want refused\n%s", err, o)
		}
	})
	t.Run("offline with --public-key works and is not server-trusted", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		fake.getErr = status.Error(codes.Unavailable, "offline")
		w := newGuardrailWork(t)
		if o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		o, err := runGuardrail(t, "verify", w.out, "--attestation", w.attestationFile(), "--public-key", w.keys+".pub")
		if err != nil {
			t.Fatalf("offline verify: %v\n%s", err, o)
		}
		if !strings.Contains(o, "NOT server-trusted") {
			t.Errorf("offline verify does not say it is not server-trusted:\n%s", o)
		}
		if _, err := runGuardrail(t, "verify", w.out, "--attestation", w.attestationFile()); err == nil || !strings.Contains(err.Error(), "--public-key") {
			t.Errorf("offline verify without --public-key = %v, want it to ask for one", err)
		}
	})
	t.Run("server policy with no trusted signer is refused", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		setServerPolicy(t, fake, piiOnlyPolicy())
		if o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		_, err := runGuardrail(t, "verify", w.out, "--attestation", w.attestationFile(), "--public-key", w.keys+".pub")
		if err == nil || !strings.Contains(err.Error(), guardrailpolicy.ErrNoTrustedSigner.Error()) {
			t.Fatalf("verify with no trusted signer = %v, want refused", err)
		}
	})
}
