package client

import (
	"fmt"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The shared half of re-applying a box's SDLC skill sets (#3374, #3511):
// `containarium code skill-sets` and the platform MCP tool apply_box_skill_sets
// both call ApplySkillSets and print with RenderSkillSetsApply, so a box is
// validated, refused and reported the same way on either surface.

// BoxSkillSetApplier is what ApplySkillSets needs from a daemon client; both
// GRPCClient and HTTPClient satisfy it.
type BoxSkillSetApplier interface {
	ApplyBoxSkillSets(req *pb.ApplyBoxSkillSetsRequest) (*pb.ApplyBoxSkillSetsResponse, error)
}

// SkillSetsRefusedError is a typed refusal of ApplyBoxSkillSets: the reason
// the daemon gave (RUN_IN_PROGRESS, SET_PREDATES_MANIFEST, UNKNOWN_SKILL_SET)
// next to its message, so a caller switches on Reason, not on message text.
type SkillSetsRefusedError struct {
	Box     string
	Reason  pb.BoxSkillSetsRefusal
	Message string
}

// ReasonName is the reason without the enum prefix, e.g. "RUN_IN_PROGRESS".
func (e *SkillSetsRefusedError) ReasonName() string {
	return strings.TrimPrefix(e.Reason.String(), "BOX_SKILL_SETS_REFUSAL_")
}

func (e *SkillSetsRefusedError) Error() string {
	return fmt.Sprintf("apply skill sets on %s: refused (%s): %s", e.Box, e.ReasonName(), e.Message)
}

// ValidateBoxName is the box-name shape: lowercase letters, digits, '-' and
// '_' up to 32 characters, tighter than a key name (no '@' or '.') because box
// names go into Linux usernames upstream. Keep in sync with
// internal/server/create_bounds.go if it changes there.
func ValidateBoxName(name string) error {
	n := strings.TrimSpace(name)
	if n == "" {
		return fmt.Errorf("box name is empty")
	}
	if len(n) > 32 {
		return fmt.Errorf("box name %q exceeds 32 characters", n)
	}
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
			continue
		default:
			return fmt.Errorf("box name %q contains disallowed character %q (allowed: lowercase, digits, '-', '_')", n, r)
		}
	}
	return nil
}

// SkillSetsApply is one request to re-apply a box's skill sets.
type SkillSetsApply struct {
	// Box is the box owner's username.
	Box string
	// Target is the complete list of set ids the box should have; empty
	// removes every set.
	Target []string
	// Release is the Containarium release whose installer to use; empty is
	// the daemon's own.
	Release string
	// SkillsVersion moves the box to a signed skills release: a version
	// name or "latest". Empty keeps the box on the release it has.
	SkillsVersion string
}

// ApplySkillSets makes box's installed skill sets exactly target (an empty
// target removes every set), leaving the box on the skills release it has.
// It is ApplySkillSetsWith without a skills version.
func ApplySkillSets(c BoxSkillSetApplier, box string, target []string, release string) (*pb.ApplyBoxSkillSetsResponse, error) {
	return ApplySkillSetsWith(c, SkillSetsApply{Box: box, Target: target, Release: release})
}

// ApplySkillSetsWith makes a box's installed skill sets exactly a.Target and,
// when a.SkillsVersion is set, moves the box to that skills release. The
// release tag and the skills version are validated here, before any request.
// A typed refusal comes back as *SkillSetsRefusedError; an Unimplemented
// status (a daemon without the RPC) is returned as is, so the caller can add
// its own hint.
func ApplySkillSetsWith(c BoxSkillSetApplier, a SkillSetsApply) (*pb.ApplyBoxSkillSetsResponse, error) {
	box := a.Box
	release := strings.TrimSpace(a.Release)
	if release != "" && !sdlcskills.ValidReleaseTag(release) {
		return nil, fmt.Errorf("--release %q is not a release tag (expected something like v0.89.0)", release)
	}
	version := strings.TrimSpace(a.SkillsVersion)
	if version != "" && version != sdlcskills.LatestVersion && !sdlcskills.ValidSkillsVersion(version) {
		return nil, fmt.Errorf("--skills-version %q is not a skills release version (letters, digits and ._-, or %q)", version, sdlcskills.LatestVersion)
	}
	resp, err := c.ApplyBoxSkillSets(&pb.ApplyBoxSkillSetsRequest{Username: box, SkillSets: a.Target, Release: release, SkillsVersion: version})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return nil, err
		}
		if reason := SkillSetsRefusalOf(err); reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNSPECIFIED {
			return nil, &SkillSetsRefusedError{Box: box, Reason: reason, Message: status.Convert(err).Message()}
		}
		return nil, fmt.Errorf("apply skill sets on %s: %w", box, err)
	}
	// A daemon that predates skills_version ignores the field and answers
	// without one. Reporting success would say the box moved when it did not.
	if version != "" && resp.GetSkillsVersion() == "" && len(a.Target) > 0 {
		return nil, fmt.Errorf("apply skill sets on %s: the daemon did not report a skills release after being asked for %q; it predates per-box skills versions (upgrade it) and the box was left on its release's bundle", box, version)
	}
	return resp, nil
}

// SkillSetsRefusalOf returns the typed reason a refusal carries in its status
// details (a PreconditionFailure violation type or a BadRequest field
// violation reason spelled as a BoxSkillSetsRefusal name), or UNSPECIFIED.
// Both transports carry the details: gRPC natively, the HTTP client by
// decoding the gateway's error body.
func SkillSetsRefusalOf(err error) pb.BoxSkillSetsRefusal {
	st, ok := status.FromError(err)
	if !ok {
		return pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNSPECIFIED
	}
	for _, d := range st.Details() {
		switch p := d.(type) {
		case *errdetails.PreconditionFailure:
			for _, v := range p.GetViolations() {
				if r, ok := pb.BoxSkillSetsRefusal_value[v.GetType()]; ok {
					return pb.BoxSkillSetsRefusal(r)
				}
			}
		case *errdetails.BadRequest:
			for _, v := range p.GetFieldViolations() {
				if r, ok := pb.BoxSkillSetsRefusal_value[v.GetReason()]; ok {
					return pb.BoxSkillSetsRefusal(r)
				}
			}
		}
	}
	return pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNSPECIFIED
}

// RenderSkillSetsApply prints the sets the box now has and what this call
// installed and removed, or that nothing changed.
func RenderSkillSetsApply(box string, resp *pb.ApplyBoxSkillSetsResponse) string {
	sets := "none"
	if len(resp.GetSkillSets()) > 0 {
		sets = strings.Join(resp.GetSkillSets(), ", ")
	}
	var b strings.Builder
	// The signed skills release the box is on now, when it is on one.
	from := resp.GetRelease()
	if v := resp.GetSkillsVersion(); v != "" {
		from += ", skills release " + v
	}
	if resp.GetUnchanged() {
		fmt.Fprintf(&b, "%s: skill sets unchanged (%s); nothing installed or removed, files refreshed from %s\n", box, sets, from)
		return b.String()
	}
	fmt.Fprintf(&b, "%s: skill sets now %s (from %s)\n", box, sets, from)
	for _, c := range resp.GetInstalled() {
		fmt.Fprintf(&b, "  installed %s: %s\n", c.GetSkillSet(), strings.Join(c.GetSkills(), ", "))
	}
	for _, c := range resp.GetRemoved() {
		set := c.GetSkillSet()
		if set == "" {
			set = "(no set in this release's lock)"
		}
		fmt.Fprintf(&b, "  removed %s: %s\n", set, strings.Join(c.GetSkills(), ", "))
	}
	return b.String()
}
