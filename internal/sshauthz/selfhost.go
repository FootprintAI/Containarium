package sshauthz

// SelfHostDecider answers SSHAuthzService.Authorize from the daemon's own
// state when no cloud is enrolled (#2517; component 4 of
// docs/architecture/ssh-live-authorization.md). The managed-mode forwarder
// is a separate decider (#2525); both expose the same
// Decide(ctx, req) (resp, error) method the server dispatches to.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/footprintai/containarium/pkg/core/container"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SelfHostCacheTTL is the positive cache lifetime returned with every
// self-host ALLOW (decided on #2517).
const SelfHostCacheTTL = 30 * time.Second

// BoxLister returns the set of live box (container) names.
// *container.Manager satisfies it.
type BoxLister interface {
	ExistingContainerNames() (map[string]bool, error)
}

// CollaboratorChecker reports whether a collaborator row grants
// collaboratorUsername access to containerName.
type CollaboratorChecker interface {
	CollaboratorExists(ctx context.Context, containerName, collaboratorUsername string) (bool, error)
}

// SelfHostDecider is the self-host decision engine.
type SelfHostDecider struct {
	// HomeRoot holds the jump accounts' home directories ("/home" when empty).
	HomeRoot string
	// Boxes lists live boxes. Required.
	Boxes BoxLister
	// Collaborators checks collaborator rows. Nil refuses every
	// collaborator login.
	Collaborators CollaboratorChecker
	// Keys is the ssh_keys registry. Required.
	Keys KeyLookup
	// MaxKeyAge refuses keys registered at least this long ago with
	// KEY_EXPIRED. Zero means no limit (--ssh-authz-max-key-age).
	MaxKeyAge time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Decide applies, in order: local facts (→ NO_ACCESS), the registry
// (→ UNKNOWN_KEY, also for a revoked key), and local policy (→ KEY_EXPIRED).
// Security-key (SK_*) types pass like any other registered key; device
// approval is not offered in self-host mode. A registry that cannot be read
// (or is not configured) fails closed: DENY with UPSTREAM_UNAVAILABLE, the
// local registry being the decision source in self-host mode (#2550). The
// underlying error is never copied into the response.
func (d *SelfHostDecider) Decide(ctx context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	login := req.GetLogin()
	userID, ok := d.localFacts(ctx, login)
	if !ok {
		return denyResponse(pb.SSHDenyReason_SSH_DENY_REASON_NO_ACCESS, ""), nil
	}

	fp := req.GetCredential().GetPublicKey().GetFingerprintSha256()
	if fp == "" {
		// Certificates and empty credentials have no registry entry.
		return denyResponse(pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY, userID), nil
	}
	if d.Keys == nil {
		return denyResponse(pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, userID), nil
	}
	rec, err := d.Keys.Lookup(ctx, fp)
	if errors.Is(err, ErrKeyNotFound) {
		return denyResponse(pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY, userID), nil
	}
	if err != nil {
		return denyResponse(pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, userID), nil
	}
	if !rec.RevokedAt.IsZero() {
		return denyResponse(pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY, userID), nil
	}
	if d.MaxKeyAge > 0 && d.now().Sub(rec.CreatedAt) >= d.MaxKeyAge {
		return denyResponse(pb.SSHDenyReason_SSH_DENY_REASON_KEY_EXPIRED, userID), nil
	}
	return &pb.AuthorizeSSHResponse{
		Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW,
		UserId:   userID,
		CacheTtl: durationpb.New(SelfHostCacheTTL),
	}, nil
}

func (d *SelfHostDecider) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// localFacts checks that login is a live jump account: its box exists (the
// /authorized-keys orphan filter's rule: owner "<o>" → "<o>-container",
// collaborator "<o>-container-<c>" → "<o>-container"), a collaborator login
// has its collaborator row, and the account has a non-empty authorized_keys
// file. Any error fails closed. It returns the self-host user id.
func (d *SelfHostDecider) localFacts(ctx context.Context, login string) (string, bool) {
	if login == "" || login == "." || login == ".." || strings.ContainsAny(login, "/\\\x00") {
		return "", false
	}
	if d.Boxes == nil {
		return "", false
	}
	names, err := d.Boxes.ExistingContainerNames()
	if err != nil {
		return "", false
	}
	switch {
	case names[login+"-container"]:
		// owner account
	default:
		box, isCollab := container.CollaboratorJumpAccountContainer(login)
		if !isCollab || !names[box] || d.Collaborators == nil {
			return "", false
		}
		exists, err := d.Collaborators.CollaboratorExists(ctx, box, UserIDForLogin(login))
		if err != nil || !exists {
			return "", false
		}
	}
	if !d.jumpAccountHasKeys(login) {
		return "", false
	}
	return UserIDForLogin(login), true
}

func (d *SelfHostDecider) jumpAccountHasKeys(login string) bool {
	root := d.HomeRoot
	if root == "" {
		root = "/home"
	}
	// #nosec G304 -- login is checked above to contain no path separators.
	data, err := os.ReadFile(filepath.Join(root, login, ".ssh", "authorized_keys"))
	return err == nil && strings.TrimSpace(string(data)) != ""
}

func denyResponse(reason pb.SSHDenyReason, userID string) *pb.AuthorizeSSHResponse {
	return &pb.AuthorizeSSHResponse{
		Decision:   pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY,
		DenyReason: reason,
		UserId:     userID,
	}
}
