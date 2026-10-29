package server

import (
	"context"
	"strings"

	"github.com/footprintai/containarium/internal/coderun/engine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// boxRunUserExistsScript is run as root and prints one word. It never touches
// the run user's files.
func boxRunUserExistsScript() string {
	return `if id -u ` + boxRunUnprivilegedUser + ` >/dev/null 2>&1; then echo yes; else echo no; fi` + "\n"
}

// GetBoxRunUserStatus reports, read-only, what StartBoxRun would conclude about
// the run user's sign-in on a box (#3274): the same level lookup and the same
// credential-status probe, with nothing queued, rotated or provisioned. A box
// with no recorded level is reported as such (platform runs use the owner's
// identity there). On a recorded box whose run user does not exist yet the state
// is NONE, which is what the first run would refuse on once it created the user.
// Names the credential source only, never a value.
func (s *ContainerServer) GetBoxRunUserStatus(ctx context.Context, req *pb.GetBoxRunUserStatusRequest) (*pb.GetBoxRunUserStatusResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	listExec := s.boxRunExecFn()
	startExec := s.boxRunStartExecFn()
	if listExec == nil || startExec == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to check the run user on")
	}

	level, err := s.boxRunRecordedToolAccess(ctx, req.GetUsername())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the tool-access level of %q: %v", req.GetUsername(), err)
	}
	resp := &pb.GetBoxRunUserStatusResponse{RunUser: boxRunUnprivilegedUser, ToolAccessRecorded: level != ""}
	if level == "" {
		return resp, nil
	}
	// The same refusal StartBoxRun gives for a level it cannot enforce, so a
	// pre-check never reports "fine" for a box the run would refuse.
	if _, err := boxRunPolicyFor(level); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%q: %v", req.GetUsername(), err)
	}

	box := req.GetUsername() + "-container"
	out, err := listExec(box, boxRunUserExistsScript())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "check for the run user on %q: %v", req.GetUsername(), err)
	}
	switch strings.TrimSpace(out) {
	case "yes":
		resp.RunUserExists = true
	case "no":
		resp.State = codeCredentialSourcePB(engine.CredentialStatusNone)
		return resp, nil
	default:
		return nil, status.Errorf(codes.Unavailable, "check for the run user on %q: unexpected output %q", req.GetUsername(), strings.TrimSpace(out))
	}

	state, err := boxRunSignInState(startExec, box)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "check the run user's sign-in on %q: %v", req.GetUsername(), err)
	}
	resp.State = codeCredentialSourcePB(state)
	return resp, nil
}
