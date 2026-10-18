package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/cloud"
	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/sshauthz"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
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
	return s.EndUserSessions(ctx, req.GetUsername(), "")
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
// orgID, when non-empty, limits the walk to boxes whose owning tenant
// (incus.ResolveTenant: tenant label, then cloud_org_id, then the name
// convention) is that org (#2546); other orgs' boxes are left alone. Empty
// walks every box, as before. A box whose tenant cannot be resolved to orgID
// is skipped, never guessed.
//
// A failed collaborator lookup does not stop the owner box from being
// handled; the error is returned afterwards so the caller retries.
func (s *ContainerServer) EndUserSessions(ctx context.Context, username, orgID string) (*pb.TerminateUserSessionsResponse, error) {
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
		if orgID != "" && boxTenant(info) != orgID {
			continue // another org's box on a shared host
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

// boxTenant is the org/tenant that owns a box, by the precedence every
// tenant-scoped control shares.
func boxTenant(info *incus.ContainerInfo) string {
	return incus.ResolveTenant(info.Tenant, info.Labels[incus.CloudOrgIDLabel], info.Name)
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
// EndUserSessions. In managed mode the assignment's user_id is the control
// plane's user id (#2602): it is resolved to the local logins recorded on
// earlier managed AuthorizeSSH ALLOWs, each walked as its self-host user
// (sshauthz.UserIDForLogin). An id with no record falls back to the
// self-host rule when it is itself a known local user (a walk that finds
// one of its boxes); otherwise it is cloud.ErrUserNotMapped.
type cloudSessionTerminator struct {
	s   *ContainerServer
	ids *sshauthz.ManagedIdentities
}

func (t cloudSessionTerminator) TerminateUserSessions(ctx context.Context, userID, orgID string) error {
	logins := t.ids.Logins(userID)
	if len(logins) == 0 {
		if !container.IsValidAccountName(userID) || strings.Contains(userID, "-container-") {
			return fmt.Errorf("%w: %q", cloud.ErrUserNotMapped, userID)
		}
		resp, err := t.s.EndUserSessions(ctx, userID, orgID)
		if err == nil && resp.GetBoxesTouched() == 0 {
			return fmt.Errorf("%w: %q", cloud.ErrUserNotMapped, userID)
		}
		return err
	}
	var errs []error
	walked := map[string]bool{}
	for _, login := range logins {
		local := sshauthz.UserIDForLogin(login)
		if walked[local] {
			continue
		}
		walked[local] = true
		if _, err := t.s.EndUserSessions(ctx, local, orgID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
