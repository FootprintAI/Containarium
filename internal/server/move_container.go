package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// migrationDefaults clamps the request to sane ranges and supplies
// defaults for unset fields. Centralizes the policy so the actual
// orchestrator doesn't muddy itself with validation noise.
type migrationParams struct {
	maxIterations         int
	deltaThresholdSeconds int
	stateful              bool
}

func migrationDefaults(req *pb.MoveContainerRequest) migrationParams {
	p := migrationParams{
		maxIterations:         int(req.MaxIterations),
		deltaThresholdSeconds: int(req.DeltaThresholdSeconds),
		stateful:              req.Stateful,
	}
	if p.maxIterations < 0 {
		p.maxIterations = 0
	}
	if p.maxIterations > 10 {
		p.maxIterations = 10
	}
	if p.maxIterations == 0 && req.MaxIterations == 0 {
		// Caller didn't set it; 3 is the sweet spot for typical workloads.
		p.maxIterations = 3
	}
	if p.deltaThresholdSeconds < 1 {
		p.deltaThresholdSeconds = 5
	}
	if p.deltaThresholdSeconds > 60 {
		p.deltaThresholdSeconds = 60
	}
	return p
}

// MoveContainer migrates a container from this daemon to a peer daemon
// using pre-copy + delta-refresh. See proto/containarium/v1/service.proto
// for the high-level contract; the implementation here is the three-
// phase orchestration:
//
//   Phase 1 — initial full copy (source running)
//     snapshot sync0 → incus copy <c>/sync0 <remote>:<c> --instance-only
//
//   Phase 2 — iterative deltas (still running)
//     for i in 1..max_iterations:
//         snapshot sync<i> → incus copy --refresh
//         if elapsed < delta_threshold_seconds: break
//
//   Phase 3 — cutover (source down for the final delta)
//     stop source
//     snapshot final → incus copy --refresh
//     adopt-on-target (registers host user, returns new container IP)
//     update route store: target_ip swap
//     cascade-cleanup on source (delete LXC, host user, etc.)
//
// Failure handling:
//   - any failure before cutover: source container is still running and
//     unchanged. Leftover sync snapshots are cleaned up best-effort.
//   - failure after `stop` but before route swap: we restart the source
//     container so the public hostname recovers — the migration is
//     aborted and the operator can retry.
//   - failure after route swap (very unlikely — just a DB update): the
//     migration is considered complete; the cascade cleanup runs and any
//     residual error is logged but doesn't fail the response.
func (s *ContainerServer) MoveContainer(ctx context.Context, req *pb.MoveContainerRequest) (*pb.MoveContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.TargetBackendId == "" {
		return nil, fmt.Errorf("target_backend_id is required")
	}
	if s.peerPool == nil {
		return nil, fmt.Errorf("peer pool not configured; multi-backend support is disabled on this daemon")
	}
	if req.TargetBackendId == s.peerPool.LocalBackendID() {
		return nil, fmt.Errorf("cannot move container to its own backend (target_backend_id matches local)")
	}
	if s.moveRunner == nil {
		return nil, fmt.Errorf("migration runner not configured; daemon was built without incus migration support")
	}

	targetPeer := s.peerPool.Get(req.TargetBackendId)
	if targetPeer == nil {
		return nil, fmt.Errorf("target backend %q not found in peer pool", req.TargetBackendId)
	}

	containerName := fmt.Sprintf("%s-container", req.Username)

	// Each daemon's incusd knows the others as remotes via `incus
	// remote add`. The convention we use: remote name == peer backend
	// ID. Operators set this up at provisioning time. Auto-bootstrap
	// (daemon-coordinated cert exchange) is a follow-up.
	targetRemote := req.TargetBackendId
	if has, err := s.moveRunner.HasRemote(targetRemote); err != nil {
		return nil, fmt.Errorf("check incus remote: %w", err)
	} else if !has {
		return nil, fmt.Errorf("incus remote %q is not configured on this host; run `incus remote add %s <url>` first", targetRemote, targetRemote)
	}

	params := migrationDefaults(req)

	// Track iterations to surface in the response — useful for
	// operators tuning max_iterations on subsequent moves of similar
	// workloads.
	iterations := int32(0)

	// Snapshot names we'll create. Numbered so retries of a stuck
	// migration don't collide (the underlying CLI is idempotent on
	// "snapshot already exists", but we still want unique-per-iteration
	// names so each delta is referenced precisely).
	createdSnaps := []string{}
	cleanupSnaps := func() {
		for _, s2 := range createdSnaps {
			if err := s.moveRunner.DeleteSnapshot(containerName, s2); err != nil {
				log.Printf("[move] cleanup snapshot %s/%s: %v (ignored)", containerName, s2, err)
			}
		}
	}

	// PHASE 1 — initial copy.
	syncName := "containarium-move-sync0"
	if err := s.moveRunner.Snapshot(containerName, syncName); err != nil {
		return nil, fmt.Errorf("phase 1: snapshot: %w", err)
	}
	createdSnaps = append(createdSnaps, syncName)

	log.Printf("[move] phase 1: initial copy of %s/%s to %s ...", containerName, syncName, targetRemote)
	if err := s.moveRunner.CopyInitial(containerName, syncName, targetRemote); err != nil {
		cleanupSnaps()
		return nil, fmt.Errorf("phase 1: initial copy: %w", err)
	}
	iterations++

	// PHASE 2 — iterative deltas, source still running.
	for i := 1; i <= params.maxIterations; i++ {
		syncName = fmt.Sprintf("containarium-move-sync%d", i)
		start := time.Now()

		if err := s.moveRunner.Snapshot(containerName, syncName); err != nil {
			cleanupSnaps()
			return nil, fmt.Errorf("phase 2 iter %d: snapshot: %w", i, err)
		}
		createdSnaps = append(createdSnaps, syncName)

		log.Printf("[move] phase 2 iter %d: delta refresh of %s/%s ...", i, containerName, syncName)
		if err := s.moveRunner.CopyRefresh(containerName, syncName, targetRemote); err != nil {
			cleanupSnaps()
			return nil, fmt.Errorf("phase 2 iter %d: refresh: %w", i, err)
		}
		iterations++

		elapsed := time.Since(start)
		log.Printf("[move] phase 2 iter %d done in %s", i, elapsed)
		if elapsed < time.Duration(params.deltaThresholdSeconds)*time.Second {
			log.Printf("[move] delta below threshold (%ds), proceeding to cutover", params.deltaThresholdSeconds)
			break
		}
	}

	// PHASE 3 — cutover. From here until the route swap, the
	// container is offline. We measure the gap and surface it as
	// downtime_seconds.
	cutoverStart := time.Now()

	log.Printf("[move] phase 3: stopping source container %s", containerName)
	if err := s.moveRunner.Stop(containerName); err != nil {
		cleanupSnaps()
		return nil, fmt.Errorf("phase 3: stop source: %w", err)
	}

	// Best-effort restart-on-rollback. If anything below this point
	// fails before route swap, we want the source container running
	// so the public hostname comes back.
	rollback := func() {
		if err := s.moveRunner.Start(containerName); err != nil {
			log.Printf("[move] rollback: failed to restart source container: %v", err)
		} else {
			log.Printf("[move] rollback: source container restarted")
		}
	}

	finalSnap := "containarium-move-final"
	if err := s.moveRunner.Snapshot(containerName, finalSnap); err != nil {
		rollback()
		cleanupSnaps()
		return nil, fmt.Errorf("phase 3: final snapshot: %w", err)
	}
	createdSnaps = append(createdSnaps, finalSnap)

	if err := s.moveRunner.CopyRefresh(containerName, finalSnap, targetRemote); err != nil {
		rollback()
		cleanupSnaps()
		return nil, fmt.Errorf("phase 3: final delta copy: %w", err)
	}
	iterations++

	// Tell the destination to adopt the now-copied LXC: create the
	// host user, return the new container IP. We pass the route info
	// over so the destination can prepare matching route store rows
	// if desired (today: it just registers them at the new IP). All
	// of this happens over the PeerClient REST forward — same auth
	// path as other cross-daemon calls.
	sourceRoutes := []string{}
	if s.routeStore != nil {
		routes, err := s.routeStore.ListByContainer(ctx, containerName)
		if err == nil {
			for _, r := range routes {
				sourceRoutes = append(sourceRoutes, fmt.Sprintf("%s|%d|%s", r.FullDomain, r.TargetPort, r.Protocol))
			}
		}
	}

	authToken := extractAuthToken(ctx)
	adoptReq := &pb.AdoptMigratedContainerRequest{
		Username:     req.Username,
		SourceRoutes: sourceRoutes,
	}
	adoptResp, err := adoptFn(targetPeer, authToken, adoptReq)
	if err != nil {
		rollback()
		cleanupSnaps()
		return nil, fmt.Errorf("phase 3: adopt on target: %w", err)
	}
	newIP := adoptResp.NewIpAddress
	if newIP == "" {
		rollback()
		cleanupSnaps()
		return nil, fmt.Errorf("phase 3: target returned empty new IP")
	}

	// Route swap. Past this point, traffic resumes on the new VM.
	// downtime stopwatch can stop.
	if s.routeStore != nil {
		routes, err := s.routeStore.ListByContainer(ctx, containerName)
		if err == nil {
			for _, r := range routes {
				r.TargetIP = newIP
				if err := s.routeStore.Save(ctx, r); err != nil {
					log.Printf("[move] warning: update route %s target_ip failed: %v", r.FullDomain, err)
				}
			}
		}
	}
	downtime := int32(time.Since(cutoverStart).Seconds())

	// Cleanup on source: best-effort cascade (LXC delete, host user
	// removal, route store cleanup). At this point the migration has
	// already succeeded — anything failing here is recoverable by
	// operator action and shouldn't fail the response.
	s.cascadeContainerCleanup(ctx, containerName, req.Username)
	cleanupSnaps() // remove the sync trail on the source

	return &pb.MoveContainerResponse{
		Message:         fmt.Sprintf("Container %s migrated to %s (downtime %ds)", req.Username, req.TargetBackendId, downtime),
		NewIpAddress:    newIP,
		TargetBackendId: req.TargetBackendId,
		IterationsRun:   iterations,
		DowntimeSeconds: downtime,
	}, nil
}

// SetMigrationRunner wires the Incus migration helper so the
// orchestrator above has something to call. Same pattern as the other
// SetXxx methods on ContainerServer (peerPool, routeStore, etc.) —
// DualServer injects after construction, and the field stays nil on
// daemons compiled without migration support (where MoveContainer
// returns "not configured").
func (s *ContainerServer) SetMigrationRunner(r incus.MigrationRunner) {
	s.moveRunner = r
}

// adoptFn is the function the orchestrator calls to ask the
// destination daemon to adopt the just-copied LXC. Production code
// points it at forwardAdoptMigratedContainer (the real HTTP forward
// via PeerClient). Tests swap it via overrideAdoptForTest to assert
// on the orchestration logic without exercising the HTTP path.
var adoptFn = forwardAdoptMigratedContainer

// overrideAdoptForTest replaces the adopt function for the duration
// of a test. Returns a restore-callback for use as `defer prev()`.
// Test-only — see move_container_test.go.
func overrideAdoptForTest(f func(*PeerClient, string, *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error)) func() {
	prev := adoptFn
	adoptFn = f
	return func() { adoptFn = prev }
}

// forwardAdoptMigratedContainer issues the AdoptMigratedContainer
// REST call to a peer over the existing PeerClient generic forwarder.
// Kept in this file so the source-side orchestrator above reads
// linearly without jumping between packages.
func forwardAdoptMigratedContainer(peer *PeerClient, authToken string, req *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error) {
	body, err := json.Marshal(map[string]interface{}{
		"username":      req.Username,
		"source_routes": req.SourceRoutes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal adopt request: %w", err)
	}
	respBody, status, err := peer.ForwardRequest("POST",
		fmt.Sprintf("/v1/containers/%s/adopt", req.Username), authToken, body)
	if err != nil {
		return nil, fmt.Errorf("peer adopt RPC: %w", err)
	}
	if status >= 400 {
		return nil, fmt.Errorf("peer adopt RPC returned %d: %s", status, string(respBody))
	}
	var resp pb.AdoptMigratedContainerResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("decode adopt response: %w", err)
	}
	return &resp, nil
}
