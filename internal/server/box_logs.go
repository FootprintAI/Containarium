package server

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/boxlogs"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TailBoxLogs returns one window of a box's journal and container logs
// (#3643). The collection is one fixed script (boxlogs.Script) exec'd in
// the box through the same seam as TailBoxRunLog; its output is parsed as
// untrusted (boxlogs.Parse) and merged here (Plan.Window). Same access rule
// as TailBoxRunLog, and like it, follow_seconds long-polls rather than
// streaming.
func (s *ContainerServer) TailBoxLogs(ctx context.Context, req *pb.TailBoxLogsRequest) (*pb.TailBoxLogsResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	r := boxlogs.Request{
		Cursor:     req.GetCursor(),
		Tail:       int(req.GetTail()),
		Units:      req.GetUnits(),
		Containers: req.GetContainers(),
		MaxLines:   int(req.GetMaxLines()),
	}
	if since := req.GetSince(); since != nil {
		if err := since.CheckValid(); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "since: %v", err)
		}
		r.Since = since.AsTime()
	}
	plan, err := boxlogs.Prepare(r)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}

	// A stopped box is reported as stopped: never started, never read.
	state := s.boxLogsStateFn()
	exec := s.boxRunExecFn()
	if state == nil || exec == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to read the box's logs from")
	}
	running, err := state(req.GetUsername())
	switch {
	case incus.IsNotFound(err):
		return nil, status.Errorf(codes.NotFound, "no box for %q", req.GetUsername())
	case err != nil:
		return nil, status.Errorf(codes.Unavailable, "read the state of %q's box: %v", req.GetUsername(), err)
	case !running:
		return &pb.TailBoxLogsResponse{
			Status: pb.BoxLogsStatus_BOX_LOGS_STATUS_BOX_STOPPED,
			Reason: "the box is not running; start it to read its logs",
			Cursor: req.GetCursor(),
		}, nil
	}

	plan.Root = s.boxLogsRoot
	poll := s.boxRunPoll
	if poll <= 0 {
		poll = tailRunLogPoll
	}
	follow := time.Duration(min(max(req.GetFollowSeconds(), 0), tailRunLogMaxFollow)) * time.Second
	deadline := time.Now().Add(follow)
	box := req.GetUsername() + "-container"
	dropped := 0
	for {
		out, err := exec(box, plan.Script())
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "read logs on %s: %v", box, err)
		}
		coll, err := boxlogs.Parse(out)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "read logs on %s: %v", box, err)
		}
		dropped += coll.Dropped
		switch coll.Runtime {
		case pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_PODMAN, pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER_ROOTLESS:
			return &pb.TailBoxLogsResponse{
				Status:  pb.BoxLogsStatus_BOX_LOGS_STATUS_RUNTIME_UNSUPPORTED,
				Reason:  "the box runs its containers on " + runtimeWord(coll.Runtime) + "; box logs read docker-backed boxes only",
				Runtime: coll.Runtime,
				Cursor:  req.GetCursor(),
			}, nil
		}
		if err := plan.CheckFilter(coll); err != nil {
			var ae *boxlogs.ArgError
			if errors.As(err, &ae) {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			return nil, status.Errorf(codes.Internal, "check filters: %v", err)
		}
		w := plan.Window(coll, boxlogs.Settle)
		if len(w.Lines) > 0 || w.More || !time.Now().Add(poll).Before(deadline) {
			resp := &pb.TailBoxLogsResponse{
				Status:        pb.BoxLogsStatus_BOX_LOGS_STATUS_OK,
				Runtime:       coll.Runtime,
				Cursor:        boxlogs.EncodeCursor(w.Cursor),
				More:          w.More,
				DroppedFrames: int32(min(dropped, 1<<30)), // #nosec G115 -- clamped
			}
			for _, l := range w.Lines {
				resp.Lines = append(resp.Lines, l.Proto())
			}
			return resp, nil
		}
		plan = plan.Next(w.Cursor)
		select {
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-time.After(poll):
		}
	}
}

func runtimeWord(rt pb.BoxContainerRuntime) string {
	if rt == pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER_ROOTLESS {
		return "rootless docker"
	}
	return "podman"
}

// boxLogsStateFn returns the running-state seam: the injected fake, else the
// container manager's view of the box (which never starts it).
func (s *ContainerServer) boxLogsStateFn() func(string) (bool, error) {
	if s.boxLogsState != nil {
		return s.boxLogsState
	}
	if s.manager == nil {
		return nil
	}
	mgr := s.manager
	return func(username string) (bool, error) {
		info, err := mgr.Get(username)
		if err != nil {
			return false, err
		}
		return info.State == "Running", nil
	}
}
