package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/guardrailstage"
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
	modes    map[string]string // path in the box -> mode it was written with
	events   []string          // "create", "write <path>", "exec <argv0>"
	onCreate func()            // runs inside CreateContainer (between verify and copy)
	// failWrite, when set, fails every file written into the box with an
	// error that names a daemon-side path (which must not reach the caller).
	failWrite error
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

func (f *fakeRecipeBoxes) PushFile(_ string, path string, content io.ReadSeeker, mode string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrite != nil {
		f.events = append(f.events, "write-failed "+path)
		return f.failWrite
	}
	b, err := io.ReadAll(content)
	if err != nil {
		return err
	}
	if f.files == nil {
		f.files, f.modes = map[string][]byte{}, map[string]string{}
	}
	f.files[path], f.modes[path] = b, mode
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
	// snapParent is where the gate makes its snapshots; every test asserts
	// it is empty afterwards (a leaked snapshot is a full dataset copy).
	snapParent string
}

func (f *gateFixture) assertNoSnapshotLeft(t *testing.T) {
	t.Helper()
	if entries, _ := os.ReadDir(f.snapParent); len(entries) != 0 {
		t.Errorf("%d snapshot(s) left in the snapshot dir after the deploy", len(entries))
	}
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
	f.snapParent = t.TempDir()
	f.srv = &RecipeServer{catalog: catalog, boxes: f.boxes, guardrailStagingRoot: root, guardrailSnapshotParent: f.snapParent}
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
		{"require_kinds alone demands a kind the attestation lacks", func(t *testing.T, f *gateFixture) {
			// The server policy ALLOWs PII, so the policy alone does not
			// need it scanned; only the recipe's require_kinds [pii] does.
			f.policy.Policy.Rules[0].Action = pb.GuardrailAction_GUARDRAIL_ACTION_ALLOW
			f.req.GuardrailInput.Attestation = f.attest(t, f.policy.GetPolicy(), pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS, f.priv)
			if got := f.req.GuardrailInput.Attestation.GetKindsScanned(); len(got) != 1 || got[0] != pb.GuardrailKind_GUARDRAIL_KIND_SECRET {
				t.Fatalf("fixture: kinds_scanned = %v, want [SECRET] only", got)
			}
		}, codes.FailedPrecondition, "PII"},
		{"snapshot dir inside the staging root", func(_ *testing.T, f *gateFixture) {
			f.srv.guardrailSnapshotParent = filepath.Join(f.srv.guardrailStagingRoot, "alice")
		}, codes.FailedPrecondition, "snapshot dir is misconfigured"},
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
			f.assertNoSnapshotLeft(t)
			for _, p := range []string{f.srv.guardrailStagingRoot, f.snapParent} {
				if p != "" && strings.Contains(err.Error(), p) {
					t.Errorf("error %q echoes the daemon-side path %s", err, p)
				}
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
	f.assertNoSnapshotLeft(t)
}

// TestDeployGate_DeliveryFailureKeepsTheBox is the accepted Q13 behaviour:
// when copying the verified bytes INTO the new box fails, the deploy errors,
// post_start does not run, the box is kept (as a post_start failure keeps
// it), the snapshot is removed, and no daemon-side path is echoed.
func TestDeployGate_DeliveryFailureKeepsTheBox(t *testing.T) {
	f := newGateFixture(t)
	f.boxes.failWrite = fmt.Errorf("push %s/guardrail-snapshot-9/a.txt: %w", f.snapParent, syscall.EIO)
	_, err := f.deploy(t)
	if err == nil {
		t.Fatal("deploy with a failing copy into the box = nil error")
	}
	if len(f.boxes.created) != 1 {
		t.Fatalf("created %v, want the one box, kept", f.boxes.created)
	}
	for _, ev := range f.boxes.events {
		if ev == "exec post_start" {
			t.Fatalf("post_start ran on a box without its dataset: events %v", f.boxes.events)
		}
	}
	if strings.Contains(err.Error(), f.snapParent) || strings.Contains(err.Error(), f.srv.guardrailStagingRoot) {
		t.Fatalf("error %q echoes a daemon-side path", err)
	}
	f.assertNoSnapshotLeft(t)
}

// TestDeployGate_BadAttestationIsRefusedBeforeAnyCopy: the attestation-only
// checks run before the dataset is copied, so a garbage or untrusted
// attestation never costs a snapshot.
func TestDeployGate_BadAttestationIsRefusedBeforeAnyCopy(t *testing.T) {
	f := newGateFixture(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	f.req.GuardrailInput.Attestation = f.attest(t, f.policy.GetPolicy(), pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS, other)
	snapshots := 0
	f.srv.guardrailSnapshot = func(a *guardrailstage.Area, ref, parent string) (*guardrailstage.Snapshot, error) {
		snapshots++
		return a.Snapshot(ref, parent)
	}
	if _, err := f.deploy(t); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("deploy = %v, want FAILED_PRECONDITION", err)
	}
	if snapshots != 0 {
		t.Fatalf("an untrusted attestation cost %d snapshot(s), want 0", snapshots)
	}
}

// TestSetGuardrailGate_SnapshotDirIsUsed: the daemon's
// --guardrail-snapshot-dir reaches the gate, and snapshots land there.
func TestSetGuardrailGate_SnapshotDirIsUsed(t *testing.T) {
	f := newGateFixture(t)
	dir := t.TempDir()
	f.srv.SetGuardrailGate(nil, f.srv.guardrailStagingRoot, dir)
	var parents []string
	f.srv.guardrailSnapshot = func(a *guardrailstage.Area, ref, parent string) (*guardrailstage.Snapshot, error) {
		parents = append(parents, parent)
		return a.Snapshot(ref, parent)
	}
	if _, err := f.deploy(t); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(parents) != 1 || parents[0] != dir {
		t.Fatalf("snapshots made under %v, want [%s]", parents, dir)
	}
}

// TestGuardrailStagingRef: the deploy name scopes the ref and must be a
// single path component (an admin may pass any name).
func TestGuardrailStagingRef(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/b", `a\b`, "../bob", "bob/.."} {
		if _, err := guardrailStagingRef(name, "ds1"); !errors.Is(err, guardrailstage.ErrBadRef) {
			t.Errorf("guardrailStagingRef(%q) = %v, want ErrBadRef", name, err)
		}
	}
	if got, err := guardrailStagingRef("alice", "ds1"); err != nil || got != "alice/ds1" {
		t.Errorf("guardrailStagingRef(alice, ds1) = (%q, %v), want alice/ds1", got, err)
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
		if mode := boxes.modes["/data/train/"+rel]; mode != "0644" {
			t.Fatalf("/data/train/%s written with mode %q, want 0644 (Q13)", rel, mode)
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

// TestDeployGate_InternalErrorsDoNotEchoHostPaths: a staging root that is
// configured but gone refuses the deploy, creates nothing, and the error the
// caller sees names no daemon-side path.
func TestDeployGate_InternalErrorsDoNotEchoHostPaths(t *testing.T) {
	f := newGateFixture(t)
	root := f.srv.guardrailStagingRoot
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	_, err := f.deploy(t)
	if err == nil {
		t.Fatal("deploy with a vanished staging root = nil error")
	}
	if strings.Contains(err.Error(), root) || strings.Contains(err.Error(), os.TempDir()) {
		t.Fatalf("error %q echoes a daemon-side path", err)
	}
	if len(f.boxes.created) != 0 {
		t.Fatalf("created %v", f.boxes.created)
	}
}

// TestDeployGate_SnapshotCopyFailureDegradesCleanly: provisioned storage is
// the only capacity control on staged datasets, so a snapshot copy that
// fails (a full disk, an unreadable staged file) must refuse the deploy with
// a typed status, name no daemon-side path, leave no partial snapshot, and
// create no box.
func TestDeployGate_SnapshotCopyFailureDegradesCleanly(t *testing.T) {
	t.Run("out of disk space", func(t *testing.T) {
		f := newGateFixture(t)
		parent := t.TempDir()
		f.srv.guardrailSnapshotParent = parent
		f.srv.guardrailSnapshot = func(_ *guardrailstage.Area, ref, p string) (*guardrailstage.Snapshot, error) {
			return nil, fmt.Errorf("snapshot %q: write %s/guardrail-snapshot-1/a.txt: %w", ref, p, syscall.ENOSPC)
		}
		_, err := f.deploy(t)
		if status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("deploy on a full disk = %v, want RESOURCE_EXHAUSTED", err)
		}
		assertCleanRefusal(t, f, err, parent)
	})
	t.Run("staged file unreadable mid-copy", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a 0000 file; this row needs a non-root user")
		}
		f := newGateFixture(t)
		parent := t.TempDir()
		f.srv.guardrailSnapshotParent = parent
		unreadable := filepath.Join(f.staged, "sub", "b.txt")
		if err := os.Chmod(unreadable, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })
		_, err := f.deploy(t)
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("deploy with an unreadable staged file = %v, want FAILED_PRECONDITION", err)
		}
		assertCleanRefusal(t, f, err, parent)
	})
}

func assertCleanRefusal(t *testing.T, f *gateFixture, err error, parent string) {
	t.Helper()
	for _, p := range []string{parent, f.srv.guardrailStagingRoot, os.TempDir()} {
		if strings.Contains(err.Error(), p) {
			t.Errorf("error %q echoes the daemon-side path %s", err, p)
		}
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 0 {
		t.Errorf("a failed snapshot left %d entries in the snapshot parent", len(entries))
	}
	if len(f.boxes.created) != 0 || len(f.boxes.events) != 0 {
		t.Errorf("a refused deploy touched the backend: %v %v", f.boxes.created, f.boxes.events)
	}
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
