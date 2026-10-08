package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"strings"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/guardrailstage"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The DeployRecipe guardrail gate (#2368;
// docs/architecture/guardrail-inbound-and-server-policy.md, "The gate").
// For a recipe with guardrail_gate set, deploy runs, in this order:
//
//  1. refuse async, before anything is created;
//  2. refuse when there is no server policy or no trusted signer (a policy
//     READ ERROR is its own refusal, never "no policy");
//  3. refuse when guardrail_input is absent: the recipe, not the caller,
//     decides whether a gate applies;
//  4. snapshot the staged dataset and verify the snapshot in process
//     (guardrailpolicy.VerifyAttestation: trusted signer, policy hash,
//     PASS, kinds, digest). Any failure: FAILED_PRECONDITION, no box;
//  5. (in deploy) create the box and copy the snapshot, the verified
//     bytes and nothing else, to dataset_path;
//  6. (in deploy) run post_start.

// SetGuardrailGate wires the gate: the server policy provider, the daemon's
// guardrail staging root, and where verification snapshots are made.
// Startup only, after the policy store's startup swap. "" root leaves gated
// recipes refused. "" snapshotDir is the OS temp dir; a snapshotDir must be
// daemon-private and outside the staging root, or every gated deploy is
// refused (the stager's ErrBadParent rule, checked on every snapshot).
func (s *RecipeServer) SetGuardrailGate(provider guardrailpolicy.PolicyProvider, stagingRoot, snapshotDir string) {
	s.guardrailPolicy = provider
	s.guardrailStagingRoot = stagingRoot
	s.guardrailSnapshotParent = snapshotDir
}

// guardrailStagingRef scopes a request's staging_ref to the deploying
// tenant: <staging root>/<name>/<staging_ref>. name is the tenant DeployRecipe
// already authorised, so a ref can only reach that tenant's own staged
// data; an attestation proves data is clean, not that the caller may have
// it. The ref is joined WITHOUT cleaning, so a "../" in it stays visible to
// the staging area's clean-path check and is refused there.
func guardrailStagingRef(name, ref string) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return "", fmt.Errorf("%w: deploy name %q cannot scope a staging directory", guardrailstage.ErrBadRef, name)
	}
	return name + "/" + ref, nil
}

func gateRefusal(format string, args ...any) error {
	return status.Errorf(codes.FailedPrecondition, "guardrail gate: "+format, args...)
}

// checkGuardrailGate runs steps 1-4. On success it returns the verified
// snapshot, which the caller delivers and then removes.
func (s *RecipeServer) checkGuardrailGate(ctx context.Context, recipe *pb.Recipe, req *pb.DeployRecipeRequest) (*guardrailstage.Snapshot, error) {
	if req.GetAsync() {
		return nil, gateRefusal("recipe %q is guardrail-gated and cannot be deployed async; deploy synchronously", recipe.GetId())
	}
	if s.guardrailPolicy == nil {
		return nil, gateRefusal("no server guardrail policy: this daemon has no policy store wired")
	}
	policy, err := s.guardrailPolicy.Get(ctx)
	if errors.Is(err, guardrailpolicy.ErrNotConfigured) {
		return nil, gateRefusal("no server guardrail policy is configured; an admin sets one with 'containarium guardrail policy set'")
	}
	if err != nil {
		// Never "no policy": the policy is unknown, so the deploy is refused.
		log.Printf("[recipe] guardrail gate: read policy: %v", err)
		return nil, status.Error(codes.Unavailable, "guardrail gate: cannot read the server guardrail policy; refusing the gated deploy")
	}
	if len(policy.GetTrustedSigners()) == 0 {
		return nil, gateRefusal("the server guardrail policy has no trusted signer")
	}
	in := req.GetGuardrailInput()
	if in == nil || in.GetAttestation() == nil || in.GetStagingRef() == "" {
		return nil, gateRefusal("recipe %q is guardrail-gated: guardrail_input with staging_ref and attestation is required", recipe.GetId())
	}
	// Errors below that are not one of the typed refusals may carry
	// daemon-side paths: they are logged, and the caller gets a generic
	// message (guardrailstage's error contract).
	area, err := guardrailstage.New(s.guardrailStagingRoot)
	if errors.Is(err, guardrailstage.ErrNoStagingRoot) {
		return nil, gateRefusal("this daemon has no guardrail staging root configured")
	}
	if err != nil {
		log.Printf("[recipe] guardrail gate: staging root: %v", err)
		return nil, gateRefusal("the guardrail staging root is unavailable")
	}
	ref, err := guardrailStagingRef(req.GetName(), in.GetStagingRef())
	if err != nil {
		return nil, gateRefusal("staging_ref: %v", err)
	}
	// Cheap checks first (signer, signature, policy hash, verdict, kinds):
	// a bad attestation is refused before any dataset is copied. The full
	// VerifyAttestation over the snapshot below is still what accepts.
	if _, err := guardrailpolicy.VerifyClaims(in.GetAttestation(), policy, recipe.GetGuardrailGate().GetRequireKinds()); err != nil {
		return nil, verifyFailure(err)
	}
	snapshot := (*guardrailstage.Area).Snapshot
	if s.guardrailSnapshot != nil {
		snapshot = s.guardrailSnapshot
	}
	snap, err := snapshot(area, ref, s.guardrailSnapshotParent)
	if errors.Is(err, guardrailstage.ErrBadRef) {
		return nil, gateRefusal("staging_ref %q: %v", in.GetStagingRef(), err)
	}
	if errors.Is(err, guardrailstage.ErrStagingRootUnavailable) {
		return nil, gateRefusal("the guardrail staging root is unavailable")
	}
	if errors.Is(err, guardrailstage.ErrBadParent) {
		log.Printf("[recipe] guardrail gate: snapshot dir %q: %v", s.guardrailSnapshotParent, err)
		return nil, gateRefusal("the daemon's guardrail snapshot dir is misconfigured (it must be daemon-private and outside the staging root)")
	}
	if err != nil {
		log.Printf("[recipe] guardrail gate: snapshot %q: %v", ref, err)
		// Provisioned storage is the only capacity control on staged
		// datasets, so a full disk is an expected, typed refusal. The
		// stager has already removed its partial snapshot.
		if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
			return nil, status.Error(codes.ResourceExhausted, "guardrail gate: the daemon's storage is full; could not make a private copy of the staged dataset")
		}
		return nil, gateRefusal("could not make a private copy of the staged dataset (unreadable or changing while copied)")
	}
	if _, err := guardrailpolicy.VerifyAttestation(in.GetAttestation(), policy, snap.Dir, recipe.GetGuardrailGate().GetRequireKinds()); err != nil {
		if rmErr := snap.Remove(); rmErr != nil {
			log.Printf("[recipe] remove guardrail snapshot %s: %v", snap.Dir, rmErr)
		}
		return nil, verifyFailure(err)
	}
	return snap, nil
}

// verifyFailure maps a VerifyClaims/VerifyAttestation error to the caller's
// status: the typed refusals keep their message (hashes and key ids only),
// anything else is logged and answered generically.
func verifyFailure(err error) error {
	if isVerifyRefusal(err) {
		return gateRefusal("%v", err)
	}
	log.Printf("[recipe] guardrail gate: verify: %v", err)
	return status.Error(codes.Internal, "guardrail gate: could not verify the staged dataset")
}

// isVerifyRefusal is true for the typed reasons VerifyAttestation refuses
// (their messages carry hashes and key ids only); anything else, such as an
// I/O error while digesting the snapshot, is internal.
func isVerifyRefusal(err error) bool {
	for _, target := range []error{
		guardrailpolicy.ErrNoServerPolicy, guardrailpolicy.ErrNoTrustedSigner, guardrailpolicy.ErrUntrustedSigner,
		guardrailpolicy.ErrPolicyMismatch, guardrailpolicy.ErrVerdictNotPass, guardrailpolicy.ErrKindNotCovered,
		guardrailpolicy.ErrDigestMismatch, guardrail.ErrBadSignature,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// deliverGuardrailDataset copies every regular file under dir (the verified
// snapshot) to datasetPath in the box: directories first via mkdir -p, then
// each file, root-owned 0644. The snapshot holds only directories and
// regular files. Each file is streamed from the snapshot, never read whole
// into daemon memory (datasets have no size limit by decision).
func deliverGuardrailDataset(boxes recipeBoxes, containerName, datasetPath, dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := boxes.Exec(containerName, []string{"mkdir", "-p", datasetPath}); err != nil {
		return err
	}
	return fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil || rel == "." {
			return err
		}
		dst := path.Join(datasetPath, rel)
		if d.IsDir() {
			return boxes.Exec(containerName, []string{"mkdir", "-p", dst})
		}
		if !d.Type().IsRegular() {
			return nil
		}
		f, err := root.Open(rel)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		return boxes.PushFile(containerName, dst, f, "0644")
	})
}
