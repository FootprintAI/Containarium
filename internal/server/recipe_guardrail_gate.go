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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

// SetGuardrailGate wires the gate: the server policy provider and the
// daemon's guardrail staging root. Startup only, after the policy store's
// startup swap. "" root leaves gated recipes refused.
func (s *RecipeServer) SetGuardrailGate(provider guardrailpolicy.PolicyProvider, stagingRoot string) {
	s.guardrailPolicy = provider
	s.guardrailStagingRoot = stagingRoot
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
	area, err := guardrailstage.New(s.guardrailStagingRoot)
	if err != nil {
		return nil, gateRefusal("guardrail staging root: %v", err)
	}
	ref, err := guardrailStagingRef(req.GetName(), in.GetStagingRef())
	if err != nil {
		return nil, gateRefusal("staging_ref: %v", err)
	}
	snap, err := area.Snapshot(ref, "")
	if errors.Is(err, guardrailstage.ErrBadRef) {
		return nil, gateRefusal("staging_ref %q: %v", in.GetStagingRef(), err)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "guardrail gate: snapshot staging_ref %q: %v", in.GetStagingRef(), err)
	}
	if _, err := guardrailpolicy.VerifyAttestation(in.GetAttestation(), policy, snap.Dir, recipe.GetGuardrailGate().GetRequireKinds()); err != nil {
		if rmErr := snap.Remove(); rmErr != nil {
			log.Printf("[recipe] remove guardrail snapshot %s: %v", snap.Dir, rmErr)
		}
		return nil, gateRefusal("%v", err)
	}
	return snap, nil
}

// deliverGuardrailDataset copies every regular file under dir (the verified
// snapshot) to datasetPath in the box: directories first via mkdir -p, then
// each file, root-owned 0644. The snapshot holds only directories and
// regular files.
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
		b, err := fs.ReadFile(root.FS(), rel)
		if err != nil {
			return err
		}
		return boxes.WriteFile(containerName, dst, b, "0644")
	})
}
