package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeRecipeBoxes is the fake container backend: it records every box it
// is asked to create, every file written into a box and every command run,
// in order, and creates nothing real.
type fakeRecipeBoxes struct {
	mu       sync.Mutex
	created  []string
	files    map[string][]byte // path in the box -> bytes
	events   []string          // "create", "write <path>", "exec <argv0>"
	onCreate func()            // runs inside CreateContainer (between verify and copy)
}

func (f *fakeRecipeBoxes) CreateContainer(_ context.Context, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	f.mu.Lock()
	f.created = append(f.created, req.GetUsername())
	f.events = append(f.events, "create")
	hook := f.onCreate
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return &pb.CreateContainerResponse{}, nil
}

func (f *fakeRecipeBoxes) Exec(_ string, command []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ev := "exec " + command[0]
	if command[0] == "bash" {
		ev = "exec post_start"
	}
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeRecipeBoxes) WriteFile(_ string, path string, content []byte, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.files == nil {
		f.files = map[string][]byte{}
	}
	f.files[path] = append([]byte(nil), content...)
	f.events = append(f.events, "write "+path)
	return nil
}

func (f *fakeRecipeBoxes) Get(string) (*incus.ContainerInfo, error) { return nil, errors.New("fake") }

// fakePolicyProvider serves a fixed policy or error.
type fakePolicyProvider struct {
	policy *pb.ServerGuardrailPolicy
	err    error
}

func (p fakePolicyProvider) Get(context.Context) (*pb.ServerGuardrailPolicy, error) {
	if p.err != nil {
		return nil, p.err
	}
	return proto.Clone(p.policy).(*pb.ServerGuardrailPolicy), nil
}

const gatedRecipeYAML = `recipes:
  - id: gated
    image: x
    guardrail_gate:
      dataset_path: /data/train
      require_kinds: [pii]
    post_start:
      - echo up
`

// gateFixture is a gated recipe, a staged dataset for tenant alice, a
// server policy trusting one signer, and a request with a valid
// attestation: everything the gate accepts. Each case breaks one part.
type gateFixture struct {
	srv     *RecipeServer
	boxes   *fakeRecipeBoxes
	policy  *pb.ServerGuardrailPolicy
	priv    ed25519.PrivateKey
	staged  string // the staged dataset directory
	files   map[string]string
	req     *pb.DeployRecipeRequest
	perr    error // policy read error
	noStore bool  // daemon has no policy provider
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	catalog := recipes.New()
	if err := catalog.LoadFromBytes([]byte(gatedRecipeYAML)); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	f := &gateFixture{
		boxes:  &fakeRecipeBoxes{},
		staged: filepath.Join(root, "alice", "ds1"),
		files:  map[string]string{"a.txt": "clean row one\n", "sub/b.txt": "clean row two\n"},
	}
	for rel, body := range f.files {
		p := filepath.Join(f.staged, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.priv = priv
	f.policy = &pb.ServerGuardrailPolicy{
		Policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
			{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT},
			{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT},
		}},
		TrustedSigners: []*pb.GuardrailTrustedSigner{{KeyId: guardrail.KeyID(pub), PublicKey: pub, Label: "release"}},
		Revision:       1,
	}
	f.srv = &RecipeServer{catalog: catalog, boxes: f.boxes, guardrailStagingRoot: root}
	f.req = &pb.DeployRecipeRequest{
		RecipeId: "gated",
		Name:     "alice",
		GuardrailInput: &pb.GuardrailGateInput{
			StagingRef:  "ds1",
			Attestation: f.attest(t, f.policy.GetPolicy(), pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS, priv),
		},
	}
	return f
}

func (f *gateFixture) attest(t *testing.T, policy *pb.GuardrailPolicy, verdict pb.GuardrailVerdict, priv ed25519.PrivateKey) *pb.GuardrailAttestation {
	t.Helper()
	digest, err := guardrail.SubjectDigest(f.staged)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := guardrail.PolicyHash(policy)
	if err != nil {
		t.Fatal(err)
	}
	att := &pb.GuardrailAttestation{SubjectSha256: digest, PolicyHash: hash, Verdict: verdict, KindsScanned: guardrail.KindsFor(policy)}
	if err := guardrail.Sign(att, priv); err != nil {
		t.Fatal(err)
	}
	return att
}

func (f *gateFixture) deploy(t *testing.T) (*pb.DeployRecipeResponse, error) {
	t.Helper()
	switch {
	case f.noStore:
		f.srv.guardrailPolicy = nil
	case f.perr != nil:
		f.srv.guardrailPolicy = fakePolicyProvider{err: f.perr}
	case f.policy == nil:
		f.srv.guardrailPolicy = fakePolicyProvider{err: guardrailpolicy.ErrNotConfigured}
	default:
		f.srv.guardrailPolicy = fakePolicyProvider{policy: f.policy}
	}
	return f.srv.DeployRecipe(tenantWithScopes("alice", auth.ScopeContainersWrite), f.req)
}

// TestDeployGate: every way a gated deploy is refused, and in EVERY refusal
// no container is created (asserted on the fake backend).
func TestDeployGate(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(t *testing.T, f *gateFixture)
		wantCode codes.Code
		wantMsg  string
	}{
		{"async refused", func(_ *testing.T, f *gateFixture) { f.req.Async = true }, codes.FailedPrecondition, "async"},
		{"no policy store on the daemon", func(_ *testing.T, f *gateFixture) { f.noStore = true }, codes.FailedPrecondition, "no server guardrail policy"},
		{"no server policy", func(_ *testing.T, f *gateFixture) { f.policy = nil }, codes.FailedPrecondition, "no server guardrail policy"},
		{"policy read error is an error, not 'no policy'", func(_ *testing.T, f *gateFixture) { f.perr = errors.New("database down") }, codes.Unavailable, "cannot read the server guardrail policy"},
		{"no trusted signer", func(_ *testing.T, f *gateFixture) { f.policy.TrustedSigners = nil }, codes.FailedPrecondition, "no trusted signer"},
		{"missing guardrail_input", func(_ *testing.T, f *gateFixture) { f.req.GuardrailInput = nil }, codes.FailedPrecondition, "guardrail_input"},
		{"missing attestation", func(_ *testing.T, f *gateFixture) { f.req.GuardrailInput.Attestation = nil }, codes.FailedPrecondition, "guardrail_input"},
		{"no staging root configured", func(_ *testing.T, f *gateFixture) { f.srv.guardrailStagingRoot = "" }, codes.FailedPrecondition, "staging root"},
		{"staging_ref escapes", func(_ *testing.T, f *gateFixture) { f.req.GuardrailInput.StagingRef = "../alice/ds1" }, codes.FailedPrecondition, "staging_ref"},
		{"wrong policy_hash", func(t *testing.T, f *gateFixture) {
			f.req.GuardrailInput.Attestation = f.attest(t, guardrail.DefaultPolicy(), pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS, f.priv)
			f.policy.Policy.Rules[1].MaxResidual = 1 // server policy now differs from the default
		}, codes.FailedPrecondition, "different policy"},
		{"untrusted signer", func(t *testing.T, f *gateFixture) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			f.req.GuardrailInput.Attestation = f.attest(t, f.policy.GetPolicy(), pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS, other)
		}, codes.FailedPrecondition, "trusted signer"},
		{"FAIL verdict", func(t *testing.T, f *gateFixture) {
			f.req.GuardrailInput.Attestation = f.attest(t, f.policy.GetPolicy(), pb.GuardrailVerdict_GUARDRAIL_VERDICT_FAIL, f.priv)
		}, codes.FailedPrecondition, "not PASS"},
		{"uncovered kind", func(t *testing.T, f *gateFixture) {
			att := f.req.GuardrailInput.Attestation
			att.KindsScanned = []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_SECRET} // no PII, which require_kinds and the policy need
			if err := guardrail.Sign(att, f.priv); err != nil {
				t.Fatal(err)
			}
		}, codes.FailedPrecondition, "cover"},
		{"tampered byte: digest mismatch", func(t *testing.T, f *gateFixture) {
			if err := os.WriteFile(filepath.Join(f.staged, "a.txt"), []byte("clean row onE\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, codes.FailedPrecondition, "digest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGateFixture(t)
			tc.mutate(t, f)
			_, err := f.deploy(t)
			if status.Code(err) != tc.wantCode || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("deploy = %v, want %v containing %q", err, tc.wantCode, tc.wantMsg)
			}
			if len(f.boxes.created) != 0 || len(f.boxes.events) != 0 {
				t.Fatalf("a refused deploy touched the backend: created %v, events %v", f.boxes.created, f.boxes.events)
			}
		})
	}
}

// TestDeployGate_Pass: the bytes in the box are the verified bytes, at
// dataset_path, and post_start runs only after every file is written.
func TestDeployGate_Pass(t *testing.T) {
	f := newGateFixture(t)
	if _, err := f.deploy(t); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(f.boxes.created) != 1 {
		t.Fatalf("created %v, want one box", f.boxes.created)
	}
	assertDelivered(t, f.boxes, f.files)
	last := f.boxes.events[len(f.boxes.events)-1]
	if last != "exec post_start" {
		t.Fatalf("events %v: post_start must run last, after the dataset is in the box", f.boxes.events)
	}
	if f.boxes.events[0] != "create" {
		t.Fatalf("events %v: want create first", f.boxes.events)
	}
}

// TestDeployGate_StagingChangesAfterVerifyAreNotDelivered: the staged files
// are rewritten, added to and deleted between verification and the copy
// (inside CreateContainer). What reaches the box is still exactly the
// verified bytes, because the copy is from the verification snapshot.
func TestDeployGate_StagingChangesAfterVerifyAreNotDelivered(t *testing.T) {
	f := newGateFixture(t)
	f.boxes.onCreate = func() {
		_ = os.WriteFile(filepath.Join(f.staged, "a.txt"), []byte("SSN 123-45-6789 swapped in after verify\n"), 0o600)
		_ = os.WriteFile(filepath.Join(f.staged, "added.txt"), []byte("added after verify\n"), 0o600)
		_ = os.Remove(filepath.Join(f.staged, "sub", "b.txt"))
	}
	if _, err := f.deploy(t); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	assertDelivered(t, f.boxes, f.files)
}

func assertDelivered(t *testing.T, boxes *fakeRecipeBoxes, want map[string]string) {
	t.Helper()
	if len(boxes.files) != len(want) {
		t.Fatalf("delivered %d files %v, want %d", len(boxes.files), keys(boxes.files), len(want))
	}
	for rel, body := range want {
		got, ok := boxes.files["/data/train/"+rel]
		if !ok || string(got) != body {
			t.Fatalf("/data/train/%s = %q (present %v), want %q", rel, got, ok, body)
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// An ungated recipe ignores guardrail_input entirely and never reads the
// policy: the gate is the recipe's decision.
func TestDeployGate_UngatedRecipeUnaffected(t *testing.T) {
	f := newGateFixture(t)
	if err := f.srv.catalog.LoadFromBytes([]byte("recipes:\n  - id: gated\n    image: x\n")); err != nil {
		t.Fatal(err)
	}
	f.perr = errors.New("database down") // would refuse a gated deploy
	if _, err := f.deploy(t); err != nil {
		t.Fatalf("ungated deploy: %v", err)
	}
	if len(f.boxes.files) != 0 {
		t.Fatalf("ungated deploy wrote %v", keys(f.boxes.files))
	}
}
