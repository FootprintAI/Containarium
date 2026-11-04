package server

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Re-applying a box's SDLC skill sets (#3374). `code install --skill-sets`
// installs the pinned role skills when a box is set up; ApplyBoxSkillSets
// changes that selection on a box that already exists, through the same
// installer (scripts/install-sdlc-skills.sh at a release) and the same lock
// (pkg/core/sdlcskills/sdlc-skills.lock), and keeps a per-box manifest of
// which skill directories each set installed so a removal deletes exactly
// those. This file holds the contract: the capability name, the typed
// refusals, and the request validation that runs before the box is touched.

// DaemonCapBoxSkillSets: the ApplyBoxSkillSets RPC (#3374). Advertised in
// SystemInfo.capabilities once the install itself is served.
const DaemonCapBoxSkillSets = "box_skill_sets"

// boxSkillSetsField is the request field a BadRequest refusal names.
const boxSkillSetsField = "skill_sets"

// skillSetIDPattern is the charset of a set id, the same the lock and the
// installer enforce: nothing in it can carry shell syntax.
var skillSetIDPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// boxSkillSetsRefusal is the typed refusal of ApplyBoxSkillSets: the human
// message for people, and reason for callers, spelled as the enum value's
// name so a control plane switches on it rather than on message text. An
// UNKNOWN_SKILL_SET is the caller's mistake, so it is INVALID_ARGUMENT with a
// google.rpc.BadRequest field violation on skill_sets (subject is the id,
// carried in the description); every other reason is the box's state, so it
// is FAILED_PRECONDITION with a google.rpc.PreconditionFailure violation
// whose subject is the box or the set.
func boxSkillSetsRefusal(reason pb.BoxSkillSetsRefusal, subject, msg string) error {
	if reason == pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET {
		st := status.New(codes.InvalidArgument, msg)
		if detailed, err := st.WithDetails(&errdetails.BadRequest{
			FieldViolations: []*errdetails.BadRequest_FieldViolation{{Field: boxSkillSetsField, Description: msg, Reason: reason.String()}},
		}); err == nil {
			st = detailed
		}
		return st.Err()
	}
	st := status.New(codes.FailedPrecondition, msg)
	if detailed, err := st.WithDetails(&errdetails.PreconditionFailure{
		Violations: []*errdetails.PreconditionFailure_Violation{{Type: reason.String(), Subject: subject, Description: msg}},
	}); err == nil {
		st = detailed
	}
	return st.Err()
}

// knownSkillSets is the set id -> namespaces map of the lock this daemon was
// built with: what ApplyBoxSkillSets accepts and attributes skills by.
func knownSkillSets() (map[string][]string, error) {
	lock, err := sdlcskills.Embedded()
	if err != nil {
		return nil, err
	}
	return lock.Sets, nil
}

// sortedSkillSetIDs lists known's ids in order, for messages and responses.
func sortedSkillSetIDs(known map[string][]string) []string {
	ids := make([]string, 0, len(known))
	for id := range known {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// validateSkillSetIDs checks a request's target list against the known sets
// and returns it sorted and without duplicates. An id the lock does not define
// — including the installer's "all" and "none" literals, an empty id, or
// anything outside [a-z0-9-] — is the typed UNKNOWN_SKILL_SET refusal naming
// the known ids. Nothing else in the request is looked at, so this runs before
// the box is touched.
func validateSkillSetIDs(ids []string, known map[string][]string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if _, ok := known[id]; !ok || !skillSetIDPattern.MatchString(id) {
			return nil, boxSkillSetsRefusal(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET, id,
				fmt.Sprintf("unknown skill set %q; known skill sets: %s", id, strings.Join(sortedSkillSetIDs(known), ", ")))
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ApplyBoxSkillSets re-applies a box's SDLC skill sets (#3374). This slice
// lands the contract: the request is validated and authorized exactly as the
// served call will be, and a well-formed call is Unimplemented until the
// install lands.
func (s *ContainerServer) ApplyBoxSkillSets(ctx context.Context, req *pb.ApplyBoxSkillSetsRequest) (*pb.ApplyBoxSkillSetsResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	known, err := knownSkillSets()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the embedded skill-set lock: %v", err)
	}
	if _, err := validateSkillSetIDs(req.GetSkillSets(), known); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unimplemented, "ApplyBoxSkillSets is not served by this daemon yet")
}
