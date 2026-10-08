package cmd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/mtls"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeServerFlag names a server explicitly, the only way apply/verify are
// allowed to contact one (#2368). The fake API never dials it.
var fakeServerFlag = []string{"--server", "fake.invalid:50051"}

// runGuardrailAt runs a guardrail verb with an explicitly named server.
func runGuardrailAt(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return runGuardrail(t, append(args, fakeServerFlag...)...)
}

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

// written lists every file apply may write; a refused apply writes none.
func (w guardrailWork) written() []string {
	return []string{w.out, w.attestationFile(), w.out + ".vault.json", w.out + ".redaction.key"}
}

func (w guardrailWork) assertNothingWritten(t *testing.T) {
	t.Helper()
	for _, p := range w.written() {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s exists after a refused apply", p)
		}
	}
}

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

// TestGuardrailApply_ServerPolicy: with an explicitly named server that
// holds a policy, apply runs under the server's policy; --policy is
// accepted only when it hashes to the server's.
func TestGuardrailApply_ServerPolicy(t *testing.T) {
	t.Run("no --policy uses the server's", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		want := setServerPolicy(t, fake, piiOnlyPolicy(), w.keys)
		o, err := runGuardrailAt(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key")
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
		if strings.Contains(o, "--sign-key") {
			t.Errorf("a trusted --sign-key got a signer hint:\n%s", o)
		}
	})
	t.Run("--policy equal to the server's is accepted", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		want := setServerPolicy(t, fake, piiOnlyPolicy(), w.keys)
		o, err := runGuardrailAt(t, "apply", w.in, "--out", w.out, "--policy", writeGuardrailPolicyJSON(t, piiOnlyPolicy()))
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
		o, err := runGuardrailAt(t, "apply", w.in, "--out", w.out, "--policy", writeGuardrailPolicyJSON(t, guardrail.DefaultPolicy()))
		if err == nil || !strings.Contains(err.Error(), "does not match the server") {
			t.Fatalf("apply --policy <weaker> = %v, want refused\n%s", err, o)
		}
		w.assertNothingWritten(t)
	})
}

// TestGuardrailApply_SignerHints: under a server policy, apply says on
// stderr when the attestation will not be server-trusted because it is
// unsigned or signed by a key the server does not trust (key id prefixes
// only, never key bytes).
func TestGuardrailApply_SignerHints(t *testing.T) {
	t.Run("no --sign-key", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		setServerPolicy(t, fake, piiOnlyPolicy(), w.keys)
		o, err := runGuardrailAt(t, "apply", w.in, "--out", w.out)
		if err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		if !strings.Contains(o, "no --sign-key") {
			t.Fatalf("no hint for an unsigned attestation under a server policy:\n%s", o)
		}
	})
	t.Run("--sign-key not trusted", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		trusted := filepath.Join(t.TempDir(), "release")
		if o, err := runGuardrail(t, "keygen", "--out", trusted); err != nil {
			t.Fatalf("keygen: %v\n%s", err, o)
		}
		setServerPolicy(t, fake, piiOnlyPolicy(), trusted)
		o, err := runGuardrailAt(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key")
		if err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		pub, _ := guardrail.LoadPublicKey(w.keys + ".pub")
		trustedPub, _ := guardrail.LoadPublicKey(trusted + ".pub")
		if !strings.Contains(o, "not one of the server's trusted signers") || !strings.Contains(o, guardrail.KeyID(pub)[:12]) || !strings.Contains(o, guardrail.KeyID(trustedPub)[:12]) {
			t.Fatalf("no hint naming the untrusted key and the trusted one:\n%s", o)
		}
		if strings.Contains(o, guardrail.KeyID(pub)) {
			t.Fatalf("hint prints a full key id, want a prefix only:\n%s", o)
		}
	})
}

// TestGuardrailApply_LocalModes: local mode (the old behaviour, labelled
// NOT server-attested) happens only with no explicitly named server, or
// when the named server answers that it has no policy.
func TestGuardrailApply_LocalModes(t *testing.T) {
	t.Run("named server has no policy configured", func(t *testing.T) {
		withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		o, err := runGuardrailAt(t, "apply", w.in, "--out", w.out, "--policy", writeGuardrailPolicyJSON(t, piiOnlyPolicy()))
		if err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		if !strings.Contains(o, "no guardrail policy configured") || !strings.Contains(o, "NOT server-attested") {
			t.Errorf("output does not say the server has no policy and the result is not server-attested:\n%s", o)
		}
		want, _ := guardrail.PolicyHash(piiOnlyPolicy())
		if got := w.readAttestation(t).GetPolicyHash(); got != want {
			t.Errorf("local apply ignored --policy: hash %s, want %s", got, want)
		}
	})
	t.Run("no --server at all", func(t *testing.T) {
		forbidGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		o, err := runGuardrail(t, "apply", w.in, "--out", w.out)
		if err != nil || !strings.Contains(o, "NOT server-attested") {
			t.Fatalf("apply with no server = %v, want local mode\n%s", err, o)
		}
	})
	t.Run("a login's default_server does not count", func(t *testing.T) {
		forbidGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		writeLoginDefaultServer(t)
		o, err := runGuardrail(t, "apply", w.in, "--out", w.out)
		if err != nil || !strings.Contains(o, "NOT server-attested") {
			t.Fatalf("apply with only a login default_server = %v, want local mode\n%s", err, o)
		}
		if o, err := runGuardrail(t, "verify", w.out, "--attestation", w.attestationFile()); err == nil || !strings.Contains(err.Error(), "--public-key") {
			t.Fatalf("verify with only a login default_server = %v, want offline mode asking for --public-key\n%s", err, o)
		}
	})
}

// forbidGuardrailPolicyAPI fails the test if apply/verify build a policy
// client at all: no server may be contacted.
func forbidGuardrailPolicyAPI(t *testing.T) {
	t.Helper()
	prev := newGuardrailPolicyAPI
	newGuardrailPolicyAPI = func() (guardrailPolicyAPI, func(), error) {
		t.Errorf("a policy client was built (server %q) without an explicitly named server", serverAddr)
		return nil, nil, errors.New("forbidden in this test")
	}
	t.Cleanup(func() { newGuardrailPolicyAPI = prev })
}

// writeLoginDefaultServer puts a credentials.json with a default_server in
// the (test-private) HOME, as `containarium login` would. In the client
// build PersistentPreRunE resolves serverAddr from it.
func writeLoginDefaultServer(t *testing.T) {
	t.Helper()
	dir := filepath.Join(os.Getenv("HOME"), ".containarium")
	must(t, os.MkdirAll(dir, 0o700))
	must(t, os.WriteFile(filepath.Join(dir, "credentials.json"), []byte(
		`{"default_server":"127.0.0.1:1","servers":{"127.0.0.1:1":{"token":"t","user_email":"x@example.com","org_id":"o","issued_at":"2026-01-01T00:00:00Z","expires_at":null}}}`), 0o600))
}

// fixedPolicyAPI answers Get with a fixed response.
type fixedPolicyAPI struct {
	resp *pb.GetGuardrailPolicyResponse
}

func (f fixedPolicyAPI) GetGuardrailPolicy() (*pb.GetGuardrailPolicyResponse, error) {
	return f.resp, nil
}
func (fixedPolicyAPI) SetGuardrailPolicy(*pb.SetGuardrailPolicyRequest) (*pb.SetGuardrailPolicyResponse, error) {
	return nil, errors.New("not used")
}

// TestGuardrail_ExplicitServerFailuresAreErrors: with a server named
// explicitly, every failure to get an authenticated answer is an error with
// a non-zero exit, for apply and verify alike, and nothing falls back to
// local mode. Real clients over real transports where it matters (TLS,
// connection refused, HTTP 500, mTLS handshake), injected statuses for the
// rest.
func TestGuardrail_ExplicitServerFailuresAreErrors(t *testing.T) {
	type row struct {
		name  string
		setup func(t *testing.T) []string // returns the server flags
	}
	injected := func(err error) func(t *testing.T) []string {
		return func(t *testing.T) []string {
			withFakeGuardrailPolicyAPI(t).getErr = err
			return fakeServerFlag
		}
	}
	rows := []row{
		{"gRPC UNAVAILABLE", injected(status.Error(codes.Unavailable, "connection refused"))},
		{"gRPC DEADLINE_EXCEEDED", injected(status.Error(codes.DeadlineExceeded, "timeout"))},
		{"gRPC UNAUTHENTICATED", injected(status.Error(codes.Unauthenticated, "no subject"))},
		{"store read error", injected(status.Error(codes.Internal, "read guardrail policy failed"))},
		{"reported hash is not the policy's hash", func(t *testing.T) []string {
			prev := newGuardrailPolicyAPI
			newGuardrailPolicyAPI = func() (guardrailPolicyAPI, func(), error) {
				return fixedPolicyAPI{&pb.GetGuardrailPolicyResponse{Configured: true, Policy: &pb.ServerGuardrailPolicy{Policy: piiOnlyPolicy()}, PolicyHash: "deadbeef"}}, func() {}, nil
			}
			t.Cleanup(func() { newGuardrailPolicyAPI = prev })
			return fakeServerFlag
		}},
		{"HTTP TLS certificate not trusted", func(t *testing.T) []string {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"configured":false}`))
			}))
			t.Cleanup(srv.Close)
			return []string{"--server", srv.URL, "--http"}
		}},
		{"HTTP connection refused", func(t *testing.T) []string {
			return []string{"--server", "http://" + closedPort(t), "--http"}
		}},
		{"HTTP 500", func(t *testing.T) []string {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
			}))
			t.Cleanup(srv.Close)
			return []string{"--server", srv.URL, "--http"}
		}},
		{"gRPC client cannot be built (no mTLS certs)", func(t *testing.T) []string {
			return []string{"--server", closedPort(t)} // HOME is private: no certs there
		}},
		{"gRPC connection refused", func(t *testing.T) []string {
			return []string{"--server", closedPort(t), "--insecure"}
		}},
		{"gRPC mTLS handshake failure", func(t *testing.T) []string {
			addr := mtlsServerWithForeignCA(t)
			clientCerts := t.TempDir()
			must(t, mtls.Generate(mtls.GenerateOptions{Organization: "client side", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"}, Duration: 1e12, OutputDir: clientCerts}))
			return []string{"--server", addr, "--certs-dir", clientCerts}
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			// An attestation made offline, so verify has something to check.
			w := newGuardrailWork(t)
			if o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
				t.Fatalf("offline apply: %v\n%s", err, o)
			}
			flags := r.setup(t)

			o, err := runGuardrail(t, append([]string{"verify", w.out, "--attestation", w.attestationFile(), "--public-key", w.keys + ".pub"}, flags...)...)
			if err == nil || strings.Contains(o, "verified:") {
				t.Fatalf("verify with a failing named server = %v, want an error (no local fallback)\n%s", err, o)
			}

			w2 := newGuardrailWork(t)
			o, err = runGuardrail(t, append([]string{"apply", w2.in, "--out", w2.out}, flags...)...)
			if err == nil || strings.Contains(o, "NOT server-attested") {
				t.Fatalf("apply with a failing named server = %v, want an error (no local fallback)\n%s", err, o)
			}
			w2.assertNothingWritten(t)
		})
	}
}

// closedPort returns a 127.0.0.1 address nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	addr := l.Addr().String()
	must(t, l.Close())
	return addr
}

// mtlsServerWithForeignCA serves gRPC over mTLS with certificates from a CA
// the client does not have, so every handshake fails.
func mtlsServerWithForeignCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must(t, mtls.Generate(mtls.GenerateOptions{Organization: "server side", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"}, Duration: 1e12, OutputDir: dir}))
	creds, err := mtls.LoadServerCredentials(mtls.CertPathsFromDir(dir))
	must(t, err)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	gs := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterGuardrailPolicyServiceServer(gs, pb.UnimplementedGuardrailPolicyServiceServer{})
	go func() { _ = gs.Serve(l) }()
	t.Cleanup(gs.Stop)
	return l.Addr().String()
}

// TestGuardrailVerify_ServerTrust: with a server policy, verify needs the
// attestation's policy_hash to be the server's and its signer to be a
// trusted one; --public-key is not needed. With no named server,
// --public-key still works and the result is labelled not server-trusted.
func TestGuardrailVerify_ServerTrust(t *testing.T) {
	t.Run("trusted signer under the server policy passes", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		setServerPolicy(t, fake, piiOnlyPolicy(), w.keys)
		if o, err := runGuardrailAt(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		o, err := runGuardrailAt(t, "verify", w.out, "--attestation", w.attestationFile())
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
		if o, err := runGuardrailAt(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		// Even with the signer's own --public-key, the server check decides.
		o, err := runGuardrailAt(t, "verify", w.out, "--attestation", w.attestationFile(), "--public-key", w.keys+".pub")
		if err == nil || !strings.Contains(err.Error(), "trusted signer") {
			t.Fatalf("verify by an untrusted signer = %v, want refused\n%s", err, o)
		}
	})
	t.Run("attestation under a different policy is refused", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		w := newGuardrailWork(t)
		// Made with no server, under the default policy...
		if o, err := runGuardrail(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		// ...then checked against a server whose policy differs.
		setServerPolicy(t, fake, piiOnlyPolicy(), w.keys)
		o, err := runGuardrailAt(t, "verify", w.out, "--attestation", w.attestationFile())
		if err == nil || !strings.Contains(err.Error(), "different policy") {
			t.Fatalf("verify under a different policy = %v, want refused\n%s", err, o)
		}
	})
	t.Run("no named server: --public-key works and is not server-trusted", func(t *testing.T) {
		forbidGuardrailPolicyAPI(t)
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
		if o, err := runGuardrailAt(t, "apply", w.in, "--out", w.out, "--sign-key", w.keys+".key"); err != nil {
			t.Fatalf("apply: %v\n%s", err, o)
		}
		_, err := runGuardrailAt(t, "verify", w.out, "--attestation", w.attestationFile(), "--public-key", w.keys+".pub")
		if err == nil || !strings.Contains(err.Error(), guardrailpolicy.ErrNoTrustedSigner.Error()) {
			t.Fatalf("verify with no trusted signer = %v, want refused", err)
		}
	})
}
