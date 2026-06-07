package server

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// maxTTLSeconds caps the duration a caller can request. 604800 seconds
// (7 days) mirrors the 168h ceiling enforced by `containarium ttl set`
// in PR #297 and the proto comment on SetContainerTTLRequest. Larger
// values return InvalidArgument so callers see a clear error rather
// than a silently clamped value — matches the CLI's behavior on the
// same input. Centralized here so the cap is enforced both by the CLI
// (before the round trip, friendly UX) and by the server (defense in
// depth, in case some other client forgets).
const maxTTLSeconds int64 = 7 * 24 * 60 * 60

// SetContainerTTL schedules or clears a container's auto-delete time.
// duration_seconds == 0 clears any existing TTL (the container persists
// indefinitely). duration_seconds > 0 sets ttl_expires_at to now() +
// duration. Capped at maxTTLSeconds; larger values return
// InvalidArgument. Persistence model: the wall-clock expiry is stamped
// onto the Incus container config under user.containarium.ttl_expires_at
// (RFC3339), so it survives daemon restart without a separate store.
// Read by the ttlsweeper goroutine on every tick (PR #299) and by
// toProtoContainer on the list/get read paths so callers see the
// committed value.
//
// Mirrors the username-as-name convention of the other per-container
// RPCs (ToggleAutoSleep, StopContainer, ...): req.Name carries the
// username, the handler resolves <username>-container under the hood
// via manager.Get. Consistency matters because the CLI in PR #297
// passes the bare username and the gRPC stubs flow that value into
// req.Name verbatim.
func (s *ContainerServer) SetContainerTTL(ctx context.Context, req *pb.SetContainerTTLRequest) (*pb.SetContainerTTLResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := validateTTLSeconds(req.DurationSeconds); err != nil {
		return nil, err
	}

	// Treat req.Name as the bare username (matches the per-container
	// RPC convention; see CLI PR #297 which sends the bare username
	// through ttlClientSet). manager.Get appends "-container".
	username := req.Name
	if err := auth.AuthorizeTenant(ctx, username); err != nil {
		return nil, err
	}

	info, err := s.manager.Get(username)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "container for user %s not found: %v", username, err)
	}
	if info.Role.IsCoreRole() {
		return nil, status.Errorf(codes.InvalidArgument, "container %s is a core container; TTL is for user containers only", info.Name)
	}
	containerName := info.Name

	resp := &pb.SetContainerTTLResponse{}
	if req.DurationSeconds == 0 {
		// Clear: remove the key entirely so parseTTLExpiresAt and the
		// sweeper see "absent" rather than "empty string". UnsetConfig
		// is idempotent — clearing an already-clear TTL is a no-op
		// followed by a no-op response (TtlExpiresAt zero-value).
		if err := s.manager.UnsetConfig(containerName, incus.TTLExpiresAtKey); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to clear %s: %v", incus.TTLExpiresAtKey, err)
		}
		log.Printf("[ttl] cleared container=%s", containerName)
		return resp, nil
	}

	// Set: stamp now() + duration in UTC RFC3339 so the sweeper's
	// time.Parse round-trips with the same precision. Capping is
	// already enforced above.
	expiresAt, err := s.stampTTL(containerName, req.DurationSeconds)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to set %s: %v", incus.TTLExpiresAtKey, err)
	}
	log.Printf("[ttl] set container=%s expires_at=%s (duration=%ds)", containerName, expiresAt.Format(time.RFC3339), req.DurationSeconds)
	resp.TtlExpiresAt = timestamppb.New(expiresAt)
	return resp, nil
}

// validateTTLSeconds checks a requested TTL duration against the bounds
// shared by SetContainerTTL and the birth-TTL path in CreateContainer (#523).
// Zero is always valid — it means "no TTL" on create and "clear the TTL" on
// set, so callers handle the zero case themselves. Negative and over-cap
// (> maxTTLSeconds, 7 days) return InvalidArgument so the two entry points
// reject identical input identically.
func validateTTLSeconds(seconds int64) error {
	if seconds < 0 {
		return status.Errorf(codes.InvalidArgument, "ttl seconds must be >= 0, got %d", seconds)
	}
	if seconds > maxTTLSeconds {
		return status.Errorf(codes.InvalidArgument, "ttl seconds %d exceeds maximum of %d (7 days)", seconds, maxTTLSeconds)
	}
	return nil
}

// stampBirthTTL applies a create-time TTL (#523) to a just-created box so it
// is born with a death date the ttlsweeper honors — closing the leak window
// where a box exists with no TTL because the separate `ttl set` call never
// ran. On failure it DELETES the box and returns an error rather than hand
// back a box that was asked to be ephemeral but would otherwise leak forever:
// default-dead, not default-alive (#522). ttlSeconds must be > 0 (the zero
// case is "no TTL" and never reaches here). containerName is the incus name
// (info.Name) for the config write + logs; username is what manager.Delete
// keys on.
func (s *ContainerServer) stampBirthTTL(containerName, username string, ttlSeconds int64) error {
	expiresAt, err := s.stampTTL(containerName, ttlSeconds)
	if err != nil {
		if delErr := s.manager.Delete(username, true); delErr != nil {
			log.Printf("[ttl] birth TTL stamp failed AND cleanup-delete failed for %s: stamp=%v delete=%v", containerName, err, delErr)
		}
		return status.Errorf(codes.Internal, "failed to set birth TTL on %s (box deleted to avoid a leak): %v", containerName, err)
	}
	log.Printf("[ttl] birth TTL set container=%s expires_at=%s (duration=%ds)", containerName, expiresAt.Format(time.RFC3339), ttlSeconds)
	return nil
}

// stampBirthAutoSleep enables auto-sleep on a just-created box (#524) with the
// given idle threshold (minutes), via the same Incus config keys ToggleAutoSleep
// writes — so the box is born with its idle→stop timer and the autosleep loop
// reclaims its CPU/RAM if a job crashes/cancels without anyone calling
// toggle_auto_sleep (the stop half of #522's default-sleep model; birth TTL is
// the delete half). Best-effort: auto-sleep is an optimization, not a leak
// contract, so a failed stamp logs and the box keeps running (it can be toggled
// later) rather than failing the create. idleMinutes must be > 0 (the zero case
// is "no auto-sleep" and never reaches here).
func (s *ContainerServer) stampBirthAutoSleep(containerName string, idleMinutes int32) {
	if err := s.manager.SetConfig(containerName, incus.AutoSleepEnabledKey, "true"); err != nil {
		log.Printf("[autosleep] failed to enable birth auto-sleep on %s: %v (continuing; box has no idle-stop)", containerName, err)
		return
	}
	if err := s.manager.SetConfig(containerName, incus.IdleThresholdMinutesKey, strconv.Itoa(int(idleMinutes))); err != nil {
		log.Printf("[autosleep] enabled auto-sleep on %s but failed to set idle threshold: %v (autosleep loop falls back to its %dm default)", containerName, err, incus.DefaultIdleThresholdMinutes)
		return
	}
	log.Printf("[autosleep] birth auto-sleep enabled container=%s idle_threshold=%dm", containerName, idleMinutes)
}

// stampTTL writes now()+duration as a UTC RFC3339 wall-clock expiry onto the
// container's Incus config under user.containarium.ttl_expires_at — the exact
// key + format the ttlsweeper reads, so create and set agree byte-for-byte.
// durationSeconds MUST be > 0 (validated via validateTTLSeconds); the zero
// case is the caller's responsibility (clear on set, skip on create). Shared
// by SetContainerTTL and CreateContainer's birth-TTL path (#523).
func (s *ContainerServer) stampTTL(containerName string, durationSeconds int64) (time.Time, error) {
	expiresAt := time.Now().Add(time.Duration(durationSeconds) * time.Second).UTC()
	if err := s.manager.SetConfig(containerName, incus.TTLExpiresAtKey, expiresAt.Format(time.RFC3339)); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}
