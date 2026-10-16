package server

import (
	"context"
	"fmt"
	"log"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/pkg/core/container"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// collaboratorAccess lists the boxes a user reaches as a collaborator.
// *container.CollaboratorManager satisfies it.
type collaboratorAccess interface {
	ListByCollaborator(ctx context.Context, collaboratorUsername string) ([]*collaborator.Collaborator, error)
}

// TerminateUserSessions ends every live SSH session username holds on this
// backend (#2522; component 5 of docs/architecture/ssh-live-authorization.md).
//
// Authorization (decided on #2522): the caller needs ssh:write; the admin
// role — which the daemon's service tokens carry — may name any user, any
// other caller only themselves (PermissionDenied otherwise).
func (s *ContainerServer) TerminateUserSessions(ctx context.Context, req *pb.TerminateUserSessionsRequest) (*pb.TerminateUserSessionsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSSHWrite); err != nil {
		return nil, err
	}
	if err := auth.AuthorizeTenant(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	return s.EndUserSessions(ctx, req.GetUsername())
}

// EndUserSessions is the unauthenticated core of TerminateUserSessions, shared
// with the cloud assignment handler (kind TERMINATE_USER_SESSIONS). It walks
// the user's owner box "<user>-container" (box account "<user>", host jump
// account "<user>") and every box they collaborate on (box and host account
// "<owner>-container-<user>"). For each box that exists it kills the account's
// processes in the box (when running) and on the host. Nothing is deleted;
// accounts, homes, sudoers and authorized_keys are untouched, so the user can
// connect again.
//
// A failed collaborator lookup does not stop the owner box from being
// handled; the error is returned afterwards so the caller retries.
func (s *ContainerServer) EndUserSessions(ctx context.Context, username string) (*pb.TerminateUserSessionsResponse, error) {
	if !container.IsValidAccountName(username) || strings.Contains(username, "-container-") {
		return nil, status.Errorf(codes.InvalidArgument, "invalid username %q", username)
	}
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "no local box manager on this backend")
	}

	type target struct{ box, account string }
	targets := []target{{box: username + "-container", account: username}}

	var listErr error
	if access := s.collaboratorAccessor(); access != nil {
		rows, err := access.ListByCollaborator(ctx, username)
		if err != nil {
			listErr = fmt.Errorf("list collaborator boxes for %s: %w", username, err)
		}
		for _, r := range rows {
			targets = append(targets, target{box: r.ContainerName, account: r.AccountName})
		}
	}

	hostKill := s.hostSessionKill
	if hostKill == nil {
		hostKill = container.TerminateJumpAccountSessions
	}

	resp := &pb.TerminateUserSessionsResponse{}
	for _, t := range targets {
		info, err := s.manager.GetInfo(t.box)
		if err != nil || info == nil {
			continue // no such box on this backend
		}
		resp.BoxesTouched++
		if info.State == "Running" && s.manager.TerminateAccountSessions(t.box, t.account) {
			resp.TerminatedSessions++
		}
		if hostKill(t.account) {
			resp.TerminatedSessions++
		}
	}
	log.Printf("[ssh-sessions] terminated sessions for %s: %d account(s) with live processes across %d box(es)",
		username, resp.TerminatedSessions, resp.BoxesTouched)
	if listErr != nil {
		return resp, status.Error(codes.Unavailable, listErr.Error())
	}
	return resp, nil
}

func (s *ContainerServer) collaboratorAccessor() collaboratorAccess {
	if s.collabAccess != nil {
		return s.collabAccess
	}
	if s.collaboratorManager != nil {
		return s.collaboratorManager
	}
	return nil
}

// cloudSessionTerminator hands cloud TERMINATE_USER_SESSIONS assignments to
// EndUserSessions. The assignment's user_id is the self-host user id, which
// is the username (sshauthz.UserIDForLogin).
type cloudSessionTerminator struct{ s *ContainerServer }

func (t cloudSessionTerminator) TerminateUserSessions(ctx context.Context, userID string) error {
	_, err := t.s.EndUserSessions(ctx, userID)
	return err
}
