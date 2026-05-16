package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/alert"
	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/guacamole"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/ostype"
	"github.com/footprintai/containarium/pkg/core/stacks"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// PendingCreation tracks an async container creation
type PendingCreation struct {
	Username     string
	StartedAt    time.Time
	Error        error
	Done         bool
	Provisioning bool // container is running but installing stack/packages
}

// ContainerServer implements the gRPC ContainerService
type ContainerServer struct {
	pb.UnimplementedContainerServiceServer
	manager             *container.Manager
	collaboratorManager *container.CollaboratorManager
	emitter             *events.Emitter
	pendingCreations    map[string]*PendingCreation
	pendingMu           sync.RWMutex
	// Monitoring URLs (set by DualServer after setup)
	victoriaMetricsURL  string
	grafanaURL          string
	// Alerting (set by DualServer after setup)
	alertStore           *alert.Store
	alertManager         *alert.Manager
	alertDeliveryStore   *alert.DeliveryStore
	alertWebhookURL      string
	alertWebhookSecret   string
	hostRelayURL         string // e.g. "http://10.100.0.1:8080/internal/alert-relay"
	alertRelayConfigFn   func(webhookURL, secret string) // callback to update gateway relay config
	coreServices         *CoreServices
	daemonConfigStore    *app.DaemonConfigStore
	peerPool             *PeerPool
	// Route / Caddy cleanup deps (set by DualServer wiring, may be nil if
	// the daemon was started without --app-hosting). Used by DeleteContainer
	// to cascade-remove the routes / TLS-automation subjects a container
	// owned, so deleting an LXC actually deletes the public hostname too.
	routeStore           *app.RouteStore
	proxyManager         *app.ProxyManager

	// moveRunner shells out to `incus snapshot/copy/stop/start` for the
	// MoveContainer migration flow. Nil on daemons that don't support
	// migration (MoveContainer returns "not configured" then).
	moveRunner           incus.MigrationRunner

	// secretsStore is the tenant-secrets backend. Nil on daemons
	// that don't have Postgres wired up (--standalone); the
	// SecretsService RPCs return Unavailable in that case.
	// CreateContainer / StartContainer call LoadAllForUser to
	// stamp environment.<NAME>=<value> at LXC start time.
	secretsStore         *secrets.Store

	// otelCollectorEndpoint is the OTLP/HTTP URL of this daemon's
	// core OTel collector LXC (e.g. "http://10.0.3.142:4318").
	// Stamped into containers created with monitoring=true so the
	// SDK inside ships telemetry without app-side config. Empty
	// means the daemon was started without OTel app-monitoring
	// support; create_container with monitoring=true will log a
	// warning and skip the env-var injection.
	otelCollectorEndpoint string
	// Guacamole integration for Windows VM RDP access
	guacamoleClient      *guacamole.Client
	guacamoleUser        string // Guacamole admin username
	guacamolePass        string // Guacamole admin password
}

// NewContainerServer creates a new container server
func NewContainerServer() (*ContainerServer, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create container manager: %w", err)
	}
	return &ContainerServer{
		manager:          mgr,
		emitter:          events.NewEmitter(events.GetBus()),
		pendingCreations: make(map[string]*PendingCreation),
	}, nil
}

// CreateContainer creates a new container
func (s *ContainerServer) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	// Validate request
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// Route to peer if backend_id specifies a remote backend
	if req.BackendId != "" && s.peerPool != nil {
		localID := s.peerPool.LocalBackendID()
		if req.BackendId != localID && req.BackendId != "" {
			peer := s.peerPool.Get(req.BackendId)
			if peer == nil {
				return nil, fmt.Errorf("backend %q not found", req.BackendId)
			}
			if !peer.Healthy {
				return nil, fmt.Errorf("backend %q is not healthy", req.BackendId)
			}
			// Forward to peer — extract auth token from context
			authToken := extractAuthToken(ctx)
			respBody, err := peer.ForwardCreateContainer(authToken, req)
			if err != nil {
				return nil, fmt.Errorf("failed to create container on backend %q: %w", req.BackendId, err)
			}
			return respBody, nil
		}
	}

	// Validate SSH keys at the API boundary to reject placeholder strings early
	for i, key := range req.SshKeys {
		if err := container.ValidateSSHPublicKey(key); err != nil {
			return nil, fmt.Errorf("ssh_keys[%d]: %w", i, err)
		}
	}

	// Build create options
	opts := container.CreateOptions{
		Username:               req.Username,
		Image:                  req.Image,
		SSHKeys:                req.SshKeys,
		Labels:                 req.Labels,
		EnablePodman:           req.EnablePodman,
		EnablePodmanPrivileged: req.EnablePodman, // Enable privileged mode for proper Podman-in-LXC support
		AutoStart:              true,
		Stack:                  req.Stack,
		StackParameters:        req.StackParameters,
		OSType:                 req.OsType,
		// OTel app-monitoring opt-in. The daemon-level collector
		// endpoint is configured at startup via --otel-collector-
		// endpoint (or auto-discovered from the core OTel collector
		// LXC; configured by DualServer). BackendID lets the
		// collector tag emissions with the originating VM for
		// cross-VM Grafana queries. Both are no-ops when
		// req.Monitoring is false.
		Monitoring:             req.Monitoring,
		OTelCollectorEndpoint:  s.otelCollectorEndpoint,
		BackendID:              s.localBackendID(),
	}

	// Set resource limits
	if req.Resources != nil {
		opts.CPU = req.Resources.Cpu
		opts.Memory = req.Resources.Memory
		opts.Disk = req.Resources.Disk
	}

	// Set GPU passthrough
	if req.Gpu != "" {
		opts.GPU = req.Gpu
	}

	// Set static IP if specified
	if req.StaticIp != "" {
		opts.StaticIP = req.StaticIp
	}

	// Use defaults if not specified (os_type takes precedence in manager.go)
	if opts.Image == "" && opts.OSType == 0 {
		opts.Image = "images:ubuntu/24.04"
	}
	if opts.CPU == "" {
		opts.CPU = "4"
	}
	if opts.Memory == "" {
		opts.Memory = "4GB"
	}
	if opts.Disk == "" {
		opts.Disk = "50GB"
	}

	// Async mode - return immediately and create in background
	if req.Async {
		// Check if already creating
		s.pendingMu.Lock()
		if pending, exists := s.pendingCreations[req.Username]; exists && !pending.Done {
			s.pendingMu.Unlock()
			return nil, fmt.Errorf("container creation already in progress for user %s", req.Username)
		}

		// Track pending creation
		s.pendingCreations[req.Username] = &PendingCreation{
			Username:  req.Username,
			StartedAt: time.Now(),
		}
		s.pendingMu.Unlock()

		// Set provisioning callback
		opts.OnProvisioning = func() {
			s.pendingMu.Lock()
			if pending, exists := s.pendingCreations[req.Username]; exists {
				pending.Provisioning = true
			}
			s.pendingMu.Unlock()
		}

		// Start async creation
		go func() {
			info, err := s.manager.Create(opts)

			s.pendingMu.Lock()
			if pending, exists := s.pendingCreations[req.Username]; exists {
				pending.Done = true
				pending.Error = err
			}
			s.pendingMu.Unlock()

			if err != nil {
				log.Printf("Async container creation failed for %s: %v", req.Username, err)
			}

			// Emit event on success
			if err == nil && info != nil {
				s.refreshContainerIPMap()
				s.emitter.EmitContainerCreated(toProtoContainer(info))
			}
		}()

		// Return immediately with CREATING state
		return &pb.CreateContainerResponse{
			Container: &pb.Container{
				Name:     fmt.Sprintf("%s-container", req.Username),
				Username: req.Username,
				State:    pb.ContainerState_CONTAINER_STATE_CREATING,
				Resources: &pb.ResourceLimits{
					Cpu:    opts.CPU,
					Memory: opts.Memory,
					Disk:   opts.Disk,
				},
			},
			Message: fmt.Sprintf("Container creation started for user %s. Poll GET /v1/containers/%s to check status.", req.Username, req.Username),
		}, nil
	}

	// Sync mode - wait for completion
	info, err := s.manager.Create(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Stamp tenant secrets into the LXC's env (best-effort — a
	// failure here doesn't fail the create; secrets can always be
	// retried via RefreshSecrets).
	if s.secretsStore != nil {
		if n, err := s.stampSecretsOnLXC(ctx, req.Username); err != nil {
			log.Printf("[secrets] failed to stamp on %s: %v (continuing)", info.Name, err)
		} else if n > 0 {
			log.Printf("[secrets] stamped %d secret(s) on %s at create time", n, info.Name)
		}
	}

	// Refresh the collector's IP map so the new container's
	// app-emitted OTLP is attributed correctly. Best-effort.
	s.refreshContainerIPMap()

	// Convert to protobuf
	protoContainer := toProtoContainer(info)

	// Emit container created event
	s.emitter.EmitContainerCreated(protoContainer)

	resp := &pb.CreateContainerResponse{
		Container: protoContainer,
		Message:   fmt.Sprintf("Container %s created successfully", info.Name),
	}

	if ostype.IsWindows(req.OsType) {
		// Windows VM: return RDP address, skip jump server account
		resp.RdpAddress = protoContainer.RdpAddress

		// Register RDP connection in Guacamole (best-effort, runs in background)
		go func() {
			rdpPassword := info.Labels["rdp-password"]
			connID := s.registerGuacamoleConnection(info.Name, info.IPAddress, "Administrator", rdpPassword)
			if connID != "" {
				// Store connection ID as a label for cleanup on delete
				_ = s.manager.AddLabel(req.Username, guacamoleConnectionIDLabel, connID)
			}
		}()
	} else {
		// Linux container: return SSH command and ensure jump server account
		resp.SshCommand = fmt.Sprintf("ssh %s@%s", req.Username, info.IPAddress)
		go func() {
			if err := container.EnsureJumpServerAccount(req.Username); err != nil {
				log.Printf("Warning: failed to create jump server account for %s: %v", req.Username, err)
			} else {
				log.Printf("Jump server account ensured for %s", req.Username)
			}
		}()
	}

	return resp, nil
}

// ListContainers lists all containers
func (s *ContainerServer) ListContainers(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	containers, err := s.manager.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Filter containers
	var filtered []incus.ContainerInfo
	for _, c := range containers {
		// Exclude core containers (postgres, caddy) from user-facing listings
		if c.Role.IsCoreRole() {
			continue
		}

		// Filter by username if specified
		if req.Username != "" {
			// Extract username from container name (format: username-container)
			username := c.Name
			if len(c.Name) > 10 && c.Name[len(c.Name)-10:] == "-container" {
				username = c.Name[:len(c.Name)-10]
			}
			if username != req.Username {
				continue
			}
		}

		// Filter by state if specified
		if req.State != pb.ContainerState_CONTAINER_STATE_UNSPECIFIED {
			var containerState pb.ContainerState
			switch c.State {
			case "Running":
				containerState = pb.ContainerState_CONTAINER_STATE_RUNNING
			case "Stopped":
				containerState = pb.ContainerState_CONTAINER_STATE_STOPPED
			case "Frozen":
				containerState = pb.ContainerState_CONTAINER_STATE_FROZEN
			default:
				containerState = pb.ContainerState_CONTAINER_STATE_UNSPECIFIED
			}
			if containerState != req.State {
				continue
			}
		}

		// Filter by labels if specified
		if len(req.LabelFilter) > 0 {
			if !incus.MatchLabels(c.Labels, req.LabelFilter) {
				continue
			}
		}

		filtered = append(filtered, c)
	}

	// Tag local containers with this daemon's backend ID
	if s.peerPool != nil && s.peerPool.LocalBackendID() != "" {
		for i := range filtered {
			filtered[i].BackendID = s.peerPool.LocalBackendID()
		}
	}

	// Convert to protobuf
	var protoContainers []*pb.Container
	for i := range filtered {
		protoContainers = append(protoContainers, toProtoContainer(&filtered[i]))
	}

	// Add containers from peer backends
	if s.peerPool != nil {
		authToken := extractAuthToken(ctx)
		peerContainers := s.peerPool.ListContainers(authToken)
		for i := range peerContainers {
			protoContainers = append(protoContainers, toProtoContainer(&peerContainers[i]))
		}
	}

	return &pb.ListContainersResponse{
		Containers: protoContainers,
		TotalCount: int32(len(protoContainers)),
	}, nil
}

// GetContainer gets information about a specific container
func (s *ContainerServer) GetContainer(ctx context.Context, req *pb.GetContainerRequest) (*pb.GetContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// Check if there's a pending async creation
	s.pendingMu.RLock()
	pending, hasPending := s.pendingCreations[req.Username]
	s.pendingMu.RUnlock()

	if hasPending && !pending.Done {
		// Determine if creating or provisioning
		state := pb.ContainerState_CONTAINER_STATE_CREATING
		if pending.Provisioning {
			state = pb.ContainerState_CONTAINER_STATE_PROVISIONING
		}
		return &pb.GetContainerResponse{
			Container: &pb.Container{
				Name:     fmt.Sprintf("%s-container", req.Username),
				Username: req.Username,
				State:    state,
			},
		}, nil
	}

	if hasPending && pending.Done && pending.Error != nil {
		// Creation failed - return ERROR state with error details
		log.Printf("Async creation failed for %s: %v", req.Username, pending.Error)
		return &pb.GetContainerResponse{
			Container: &pb.Container{
				Name:     fmt.Sprintf("%s-container", req.Username),
				Username: req.Username,
				State:    pb.ContainerState_CONTAINER_STATE_ERROR,
			},
		}, nil
	}

	// Try to get from Incus
	info, err := s.manager.Get(req.Username)
	if err != nil {
		// Not found locally — try peers
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peerContainers := s.peerPool.ListContainers(authToken)
			containerName := req.Username + "-container"
			for _, pc := range peerContainers {
				if pc.Name == containerName {
					proto := toProtoContainer(&pc)
					return &pb.GetContainerResponse{
						Container: proto,
					}, nil
				}
			}
		}

		// If we had a pending creation that completed, clean it up
		if hasPending && pending.Done {
			s.pendingMu.Lock()
			delete(s.pendingCreations, req.Username)
			s.pendingMu.Unlock()
		}
		return nil, fmt.Errorf("failed to get container: %w", err)
	}

	// Clean up pending creation if exists
	if hasPending {
		s.pendingMu.Lock()
		delete(s.pendingCreations, req.Username)
		s.pendingMu.Unlock()
	}

	return &pb.GetContainerResponse{
		Container: toProtoContainer(info),
		// TODO: Add metrics
	}, nil
}

// DeleteContainer deletes a container
func (s *ContainerServer) DeleteContainer(ctx context.Context, req *pb.DeleteContainerRequest) (*pb.DeleteContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	containerName := fmt.Sprintf("%s-container", req.Username)

	// Before deleting, deregister Guacamole connection if this is a Windows VM
	s.deregisterGuacamoleConnection(req.Username)

	err := s.manager.Delete(req.Username, req.Force)
	if err != nil {
		// Not found locally — try peers
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.Username, authToken)
			if peer != nil {
				forceParam := ""
				if req.Force {
					forceParam = "?force=true"
				}
				_, statusCode, fwdErr := peer.ForwardRequest("DELETE", fmt.Sprintf("/v1/containers/%s%s", req.Username, forceParam), authToken, nil)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to delete container on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d for delete", peer.ID, statusCode)
				}
				return &pb.DeleteContainerResponse{
					Message:       fmt.Sprintf("Container for user %s deleted on backend %s", req.Username, peer.ID),
					ContainerName: containerName,
				}, nil
			}
		}
		return nil, fmt.Errorf("failed to delete container: %w", err)
	}

	// Cascade-clean the routes + TLS subjects + host user that this
	// container owned. The LXC is gone above; without these steps the
	// public hostname returns 502 (Caddy route still points at a
	// deleted upstream IP) and Caddy keeps trying to ACME-renew an
	// orphaned cert. All best-effort: any single failure logs a
	// warning but doesn't block the response — the LXC delete already
	// succeeded, and partial-cascade is better than telling the caller
	// "delete failed" when the container is in fact gone.
	s.cascadeContainerCleanup(ctx, containerName, req.Username)

	// Emit container deleted event
	s.emitter.EmitContainerDeleted(containerName)

	// Refresh the collector's IP map so the deleted container's IP
	// is no longer claimed in source-IP attribution.
	s.refreshContainerIPMap()

	return &pb.DeleteContainerResponse{
		Message:       fmt.Sprintf("Container for user %s deleted successfully", req.Username),
		ContainerName: containerName,
	}, nil
}

// cascadeContainerCleanup removes the resources that DeleteContainer's
// LXC-delete leaves behind. Documented as #69 / verified live against
// the demo cluster on 2026-05-14.
//
// Order is deliberate:
//   1. Route store first — kills the source of truth so RouteSyncJob
//      will reap the Caddy srv0 route on its next tick (5s). Deleting
//      directly from Caddy without this step lets the sync job
//      resurrect the route within seconds, producing the 502-after-
//      delete trap.
//   2. TLS subject removal — stops Caddy's ACME renewal loop for the
//      dead hostname. Harmless to keep (no upstream to challenge) but
//      wastes rate-limit budget over time.
//   3. Host user (jump-server account) — removes the Linux user, home,
//      and the containarium-shell wrapper. sshpiper auto-reaps the
//      user from its own config on the next keysync (2 min).
//
// On-disk Caddy cert at /data/caddy/certificates/... is intentionally
// left in place — it's harmless after step 2 (no renewal attempts) and
// avoids a "force" mode that the caller probably doesn't want.
func (s *ContainerServer) cascadeContainerCleanup(ctx context.Context, containerName, username string) {
	// 1. Route store: enumerate this container's routes and drop each.
	//    Skip if routeStore was never wired (daemon without app-hosting).
	if s.routeStore != nil {
		routes, err := s.routeStore.ListByContainer(ctx, containerName)
		if err != nil {
			log.Printf("[delete-cascade] list routes for %s failed: %v", containerName, err)
		}
		for _, r := range routes {
			if err := s.routeStore.Delete(ctx, r.FullDomain); err != nil {
				log.Printf("[delete-cascade] delete route %s failed: %v", r.FullDomain, err)
				continue
			}
			log.Printf("[delete-cascade] removed route %s (RouteSyncJob will reap Caddy entry)", r.FullDomain)

			// 2. TLS subject: only if we also have a proxy manager.
			if s.proxyManager != nil {
				if err := s.proxyManager.RemoveTLSSubject(r.FullDomain); err != nil {
					log.Printf("[delete-cascade] remove TLS subject %s failed: %v", r.FullDomain, err)
				} else {
					log.Printf("[delete-cascade] removed TLS automation subject %s", r.FullDomain)
				}
			}
		}
	}

	// 3. Host user. DeleteJumpServerAccount is idempotent (no-op if the
	//    user doesn't exist), so calling it when there isn't one is fine.
	if err := container.DeleteJumpServerAccount(username, false); err != nil {
		log.Printf("[delete-cascade] delete host user %s failed: %v (manual: sudo userdel -r %s)", username, err, username)
	} else {
		log.Printf("[delete-cascade] removed host user %s", username)
	}
}

// StartContainer starts a stopped container
func (s *ContainerServer) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*pb.StartContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	if err := s.manager.Start(req.Username); err != nil {
		// Try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.Username, authToken)
			if peer != nil {
				_, _, fwdErr := peer.ForwardRequest("POST", fmt.Sprintf("/v1/containers/%s/start", req.Username), authToken, nil)
				if fwdErr == nil {
					return &pb.StartContainerResponse{
						Message: fmt.Sprintf("Container for user %s started on backend %s", req.Username, peer.ID),
					}, nil
				}
			}
		}
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Re-stamp tenant secrets from the current DB state. Picks up
	// any rotations that happened while the container was stopped;
	// existing processes won't see the change (POSIX inherit-at-fork),
	// but new execs will.
	if s.secretsStore != nil {
		if n, err := s.stampSecretsOnLXC(ctx, req.Username); err != nil {
			log.Printf("[secrets] failed to re-stamp on start of %s-container: %v (continuing)", req.Username, err)
		} else if n > 0 {
			log.Printf("[secrets] re-stamped %d secret(s) on %s-container at start time", n, req.Username)
		}
	}

	info, err := s.manager.Get(req.Username)
	if err != nil {
		return nil, fmt.Errorf("container started but failed to get info: %w", err)
	}

	s.emitter.EmitContainerStarted(toProtoContainer(info))

	return &pb.StartContainerResponse{
		Message:   fmt.Sprintf("Container for user %s started successfully", req.Username),
		Container: toProtoContainer(info),
	}, nil
}

// StopContainer stops a running container
func (s *ContainerServer) StopContainer(ctx context.Context, req *pb.StopContainerRequest) (*pb.StopContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	if err := s.manager.Stop(req.Username, req.Force); err != nil {
		// Try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.Username, authToken)
			if peer != nil {
				body, _ := json.Marshal(map[string]bool{"force": req.Force})
				_, _, fwdErr := peer.ForwardRequest("POST", fmt.Sprintf("/v1/containers/%s/stop", req.Username), authToken, body)
				if fwdErr == nil {
					return &pb.StopContainerResponse{
						Message: fmt.Sprintf("Container for user %s stopped on backend %s", req.Username, peer.ID),
					}, nil
				}
			}
		}
		return nil, fmt.Errorf("failed to stop container: %w", err)
	}

	info, err := s.manager.Get(req.Username)
	if err != nil {
		return nil, fmt.Errorf("container stopped but failed to get info: %w", err)
	}

	s.emitter.EmitContainerStopped(toProtoContainer(info))

	return &pb.StopContainerResponse{
		Message:   fmt.Sprintf("Container for user %s stopped successfully", req.Username),
		Container: toProtoContainer(info),
	}, nil
}

// ResizeContainer dynamically resizes container resources
func (s *ContainerServer) ResizeContainer(ctx context.Context, req *pb.ResizeContainerRequest) (*pb.ResizeContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// At least one resource must be specified
	if req.Cpu == "" && req.Memory == "" && req.Disk == "" {
		return nil, fmt.Errorf("at least one resource (cpu, memory, or disk) must be specified")
	}

	containerName := fmt.Sprintf("%s-container", req.Username)

	// Perform resize — try local first, then peer
	if err := s.manager.Resize(containerName, req.Cpu, req.Memory, req.Disk, false); err != nil {
		// Container not found locally — check peers
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			log.Printf("[resize] container %s not local, searching peers (token len=%d)", containerName, len(authToken))
			peer := s.peerPool.FindContainerPeer(req.Username, authToken)
			if peer != nil {
				log.Printf("[resize] found %s on peer %s, forwarding", containerName, peer.ID)
				body, _ := json.Marshal(map[string]string{
					"cpu":    req.Cpu,
					"memory": req.Memory,
					"disk":   req.Disk,
				})
				respBody, statusCode, fwdErr := peer.ForwardRequest("PUT", fmt.Sprintf("/v1/containers/%s/resize", req.Username), authToken, body)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to resize container on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d for resize: %s", peer.ID, statusCode, string(respBody))
				}
				return &pb.ResizeContainerResponse{
					Message: fmt.Sprintf("Container %s resized on backend %s", containerName, peer.ID),
				}, nil
			}
		}
		return nil, fmt.Errorf("failed to resize container: %w", err)
	}

	// Get updated container info
	info, err := s.manager.Get(req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get updated container info: %w", err)
	}

	// Convert to protobuf
	protoContainer := toProtoContainer(info)

	return &pb.ResizeContainerResponse{
		Message:   fmt.Sprintf("Container %s resized successfully", containerName),
		Container: protoContainer,
	}, nil
}

// CleanupDisk frees disk space inside a container
func (s *ContainerServer) CleanupDisk(ctx context.Context, req *pb.CleanupDiskRequest) (*pb.CleanupDiskResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	message, freedBytes, err := s.manager.CleanupDisk(req.Username)
	if err != nil {
		// Try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.Username, authToken)
			if peer != nil {
				respBody, statusCode, fwdErr := peer.ForwardRequest("POST", fmt.Sprintf("/v1/containers/%s/cleanup-disk", req.Username), authToken, nil)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to cleanup disk on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d for cleanup: %s", peer.ID, statusCode, string(respBody))
				}
				// Parse peer response
				var peerResp struct {
					Message    string `json:"message"`
					FreedBytes int64  `json:"freedBytes"`
				}
				if jsonErr := json.Unmarshal(respBody, &peerResp); jsonErr == nil {
					return &pb.CleanupDiskResponse{
						Message:    peerResp.Message,
						FreedBytes: peerResp.FreedBytes,
					}, nil
				}
				return &pb.CleanupDiskResponse{
					Message: fmt.Sprintf("Disk cleaned on backend %s", peer.ID),
				}, nil
			}
		}
		return nil, fmt.Errorf("failed to clean up disk: %w", err)
	}

	// Get updated container info
	info, err := s.manager.Get(req.Username)
	if err != nil {
		return nil, fmt.Errorf("disk cleaned but failed to get container info: %w", err)
	}

	return &pb.CleanupDiskResponse{
		Message:    message,
		FreedBytes: freedBytes,
		Container:  toProtoContainer(info),
	}, nil
}

// InstallStack installs a software stack or base script on a running container
func (s *ContainerServer) InstallStack(ctx context.Context, req *pb.InstallStackRequest) (*pb.InstallStackResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.StackId == "" {
		return nil, fmt.Errorf("stack_id is required")
	}

	// Reject stack installation on Windows VMs
	if containerInfo, getErr := s.manager.Get(req.Username); getErr == nil {
		if osLabel, ok := containerInfo.Labels[ostype.OSTypeLabelKey]; ok {
			if ostype.IsWindows(ostype.OSTypeFromLabel(osLabel)) {
				return nil, fmt.Errorf("stack installation is not supported on Windows VMs")
			}
		}
	}

	if err := s.manager.InstallStack(req.Username, req.StackId); err != nil {
		return nil, fmt.Errorf("failed to install stack: %w", err)
	}

	// Get updated container info
	info, err := s.manager.Get(req.Username)
	if err != nil {
		return nil, fmt.Errorf("stack installed but failed to get container info: %w", err)
	}

	return &pb.InstallStackResponse{
		Message:   fmt.Sprintf("Stack %q installed successfully on %s-container", req.StackId, req.Username),
		Container: toProtoContainer(info),
	}, nil
}

// ListStacks returns the catalog of available software stacks and their
// parameter schemas. The web UI uses this to render the Create Container
// dialog's stack dropdown and any dynamically-shown parameter inputs.
func (s *ContainerServer) ListStacks(ctx context.Context, req *pb.ListStacksRequest) (*pb.ListStacksResponse, error) {
	mgr := stacks.GetDefault()
	all := mgr.GetAllStacks()

	out := make([]*pb.StackInfo, 0, len(all))
	for _, stk := range all {
		params := make([]*pb.StackParameter, 0, len(stk.Parameters))
		for _, p := range stk.Parameters {
			params = append(params, &pb.StackParameter{
				Name:        p.Name,
				Label:       p.Label,
				Description: p.Description,
				Type:        p.Type,
				Default:     p.Default,
				Required:    p.Required,
			})
		}
		out = append(out, &pb.StackInfo{
			Id:          stk.ID,
			Name:        stk.Name,
			Description: stk.Description,
			Icon:        stk.Icon,
			Parameters:  params,
		})
	}

	return &pb.ListStacksResponse{Stacks: out}, nil
}

// AdoptMigratedContainer is the destination-side helper called by a
// peer's MoveContainer after the LXC has been `incus copy`'d to this
// daemon. The LXC exists on this host's incusd but Containarium
// doesn't know about it yet — no host user, no shell wrapper, no
// route record. This RPC fills that in and returns the container's
// new local IP for the source to use in its route store cutover.
//
// Idempotent on retry: if the host user already exists,
// EnsureJumpServerAccount is a no-op; starting an already-running
// container is a no-op; etc. So a transient network failure
// mid-adoption can be safely re-driven.
func (s *ContainerServer) AdoptMigratedContainer(ctx context.Context, req *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	containerName := fmt.Sprintf("%s-container", req.Username)

	// Host-side jump-server account. EnsureJumpServerAccount handles
	// the idempotent case so re-running this RPC won't error.
	if err := container.EnsureJumpServerAccount(req.Username); err != nil {
		return nil, fmt.Errorf("ensure jump server account: %w", err)
	}

	// OTel env-var re-stamping. If the migrated container had
	// monitoring=true on the source, the OTEL_* env vars are still
	// pointing at the SOURCE daemon's collector IP — which is unreachable
	// (or wrong tenant!) from this destination. Re-stamp them with our
	// local collector endpoint before starting the container, so the
	// SDK inside picks up the new endpoint on its first batch flush.
	//
	// Reading MonitoringEnabled from the just-arrived LXC's Incus config
	// is reliable: the env vars themselves are the source of truth, and
	// `incus copy` preserves them, so if the source had monitoring on,
	// OTEL_EXPORTER_OTLP_ENDPOINT is non-empty in the destination's
	// config map right now (just pointing at the wrong place).
	if s.otelCollectorEndpoint != "" {
		if info, _ := s.manager.Get(req.Username); info != nil && info.MonitoringEnabled {
			envVars := container.OTelEnvVarsForMigration(
				req.Username, containerName, s.localBackendID(), s.otelCollectorEndpoint,
			)
			for k, v := range envVars {
				if err := s.manager.SetEnv(containerName, k, v); err != nil {
					log.Printf("[adopt] failed to re-stamp %s on %s: %v (continuing — partial OTel beats none)", k, containerName, err)
				}
			}
			log.Printf("[adopt] re-stamped OTel env vars on %s for destination collector", containerName)
		}
	}

	// Start the container — the source already pushed the LXC's
	// filesystem state. Idempotent if already running.
	if s.moveRunner != nil {
		if err := s.moveRunner.Start(containerName); err != nil {
			return nil, fmt.Errorf("start adopted container: %w", err)
		}
	}

	// Get the new IP. The container manager's Get() reads from incus.
	info, err := s.manager.Get(req.Username)
	if err != nil {
		return nil, fmt.Errorf("get adopted container info: %w", err)
	}
	newIP := ""
	if info != nil {
		newIP = info.IPAddress
	}
	if newIP == "" {
		return nil, fmt.Errorf("adopted container has no IP address yet (still initializing?)")
	}

	// The adopted container now lives on this VM under a new IP —
	// refresh the local collector's IP map so its OTLP traffic is
	// attributed correctly. The source VM will refresh its own map
	// when it deletes/cleans the migrated-out shell.
	s.refreshContainerIPMap()

	// Note: we deliberately do NOT create matching route store rows
	// here. The source-side orchestrator owns the route lifecycle —
	// it updates the existing route rows' target_ip after we return
	// the new IP. This keeps the source of truth on one side and
	// avoids a transient "route exists on both sides at different
	// IPs" window.
	//
	// req.SourceRoutes is accepted (and logged) for forward
	// compatibility: if a future variant of the protocol wants the
	// destination to be authoritative over its own route store, the
	// data is already on the wire.
	if len(req.SourceRoutes) > 0 {
		log.Printf("[adopt] %s arriving with %d source routes (source owns the swap)", req.Username, len(req.SourceRoutes))
	}

	return &pb.AdoptMigratedContainerResponse{
		Message:      fmt.Sprintf("Container %s adopted, ready at %s", req.Username, newIP),
		NewIpAddress: newIP,
	}, nil
}

// otelEnvKeys lists the environment variables the toggle path
// stamps / unsets. Includes both the legacy OTEL_* form (read by
// OTel SDKs auto-discovering) and the split CONTAINARIUM_* form
// (read by the platform sidecar's compose interpolation). Both
// shapes have to be unset on disable so the LXC's env is fully
// clean afterward; otherwise a leftover CONTAINARIUM_CONTAINER_ID
// would still appear in `printenv` and confuse audit / debug.
var otelEnvKeys = []string{
	"OTEL_EXPORTER_OTLP_ENDPOINT",
	"OTEL_EXPORTER_OTLP_PROTOCOL",
	"OTEL_SERVICE_NAME",
	"OTEL_RESOURCE_ATTRIBUTES",
	"CONTAINARIUM_CONTAINER_ID",
	"CONTAINARIUM_BACKEND_ID",
	"CONTAINARIUM_TENANT_ID",
}

// ToggleMonitoring enables / disables app-emitted OTel on an existing
// container without recreating it. Per the OTel design doc's v2 TODO.
//
// Enable path: requires the daemon to have a collector endpoint
// configured (FailedPrecondition if not). Stamps the four OTEL_*
// env vars via incus config-update, then stops + starts the LXC so
// the env reaches the app process — env-var changes don't take
// effect on a running container's processes.
//
// Disable path: deletes the four OTEL_* env keys from the LXC's
// Incus config (so the SDK falls back to its no-endpoint defaults
// rather than seeing literal empty strings, which some SDKs flag
// as misconfig), then stops + starts the LXC.
//
// Core containers are refused — they don't run user code and don't
// need app-emitted telemetry.
func (s *ContainerServer) ToggleMonitoring(ctx context.Context, req *pb.ToggleMonitoringRequest) (*pb.ToggleMonitoringResponse, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}

	info, err := s.manager.Get(req.Username)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "container for user %s not found: %v", req.Username, err)
	}
	if info.Role.IsCoreRole() {
		return nil, status.Errorf(codes.InvalidArgument, "container %s is a core container; monitoring is for user containers only", info.Name)
	}

	containerName := info.Name

	if req.Enabled {
		if s.otelCollectorEndpoint == "" {
			return nil, status.Error(codes.FailedPrecondition, "OTel collector endpoint is not configured on this daemon; cannot enable monitoring")
		}
		envVars := container.OTelEnvVarsForMigration(
			req.Username, containerName, s.localBackendID(), s.otelCollectorEndpoint,
		)
		for k, v := range envVars {
			if err := s.manager.SetEnv(containerName, k, v); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to stamp %s: %v", k, err)
			}
		}
	} else {
		for _, k := range otelEnvKeys {
			if err := s.manager.UnsetEnv(containerName, k); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to unset %s: %v", k, err)
			}
		}
	}

	// Restart so the new env reaches the app. The container was
	// running before — we ignore stop errors (LXC might be already
	// stopped, in which case stop is a no-op).
	wasRunning := info.State == "Running"
	if wasRunning {
		if err := s.manager.Stop(req.Username, false); err != nil {
			log.Printf("[togglemonitor] %s stop returned %v (continuing)", containerName, err)
		}
		if err := s.manager.Start(req.Username); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to start container after env update: %v", err)
		}
	}

	// Refresh the collector's IP map — the container may have a
	// new IP after restart, and we want source-IP attribution to
	// stay accurate.
	s.refreshContainerIPMap()

	msg := "monitoring disabled"
	if req.Enabled {
		msg = "monitoring enabled"
	}
	if wasRunning {
		msg += " — container restarted"
	} else {
		msg += " — container was stopped; new env takes effect on next start"
	}

	return &pb.ToggleMonitoringResponse{
		Message:           msg,
		MonitoringEnabled: req.Enabled,
	}, nil
}

// AddSSHKey appends an SSH public key to the user's host-side
// authorized_keys file (/home/<username>/.ssh/authorized_keys).
//
// Scope note: this writes the host-side file, not the LXC-internal
// one. That's the file sshpiper's keysync (running on the sentinel)
// reads from via /authorized-keys to authenticate inbound SSH. Adding
// only inside the LXC would not let anyone SSH in via the sentinel.
//
// The intended use case is recovery after a lost ephemeral key: an
// agent or operator generates a fresh keypair locally, calls this RPC
// with the public half, and within ~2 minutes (next sentinel keysync
// tick) the new key is live for SSH access.
//
// Idempotent — a key already present is a no-op success.
func (s *ContainerServer) AddSSHKey(ctx context.Context, req *pb.AddSSHKeyRequest) (*pb.AddSSHKeyResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.SshPublicKey == "" {
		return nil, fmt.Errorf("ssh_public_key is required")
	}

	if err := container.AddAuthorizedKey(req.Username, req.SshPublicKey); err != nil {
		return nil, fmt.Errorf("add authorized key: %w", err)
	}

	total, err := container.CountAuthorizedKeys(req.Username)
	if err != nil {
		// Counting failed but the add succeeded — return success with
		// zero so the caller still knows the add went through.
		log.Printf("[add-ssh-key] count after add failed for %s: %v", req.Username, err)
		total = 0
	}

	return &pb.AddSSHKeyResponse{
		Message:   fmt.Sprintf("SSH key added for %s (sentinel keysync will propagate within ~2m)", req.Username),
		TotalKeys: total,
	}, nil
}

// RemoveSSHKey removes a specific SSH public key from the user's
// host-side authorized_keys file. No-op if the key isn't present.
func (s *ContainerServer) RemoveSSHKey(ctx context.Context, req *pb.RemoveSSHKeyRequest) (*pb.RemoveSSHKeyResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.SshPublicKey == "" {
		return nil, fmt.Errorf("ssh_public_key is required")
	}

	if err := container.RemoveAuthorizedKey(req.Username, req.SshPublicKey); err != nil {
		return nil, fmt.Errorf("remove authorized key: %w", err)
	}

	total, err := container.CountAuthorizedKeys(req.Username)
	if err != nil {
		log.Printf("[remove-ssh-key] count after remove failed for %s: %v", req.Username, err)
		total = 0
	}

	return &pb.RemoveSSHKeyResponse{
		Message:   fmt.Sprintf("SSH key removed for %s", req.Username),
		TotalKeys: total,
	}, nil
}

// GetMetrics gets runtime metrics for containers
func (s *ContainerServer) GetMetrics(ctx context.Context, req *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	var protoMetrics []*pb.ContainerMetrics

	if req.Username != "" {
		// Get metrics for a specific container — try local first, then peers
		metrics, err := s.manager.GetMetrics(req.Username)
		if err != nil {
			// Not found locally — try peers
			if s.peerPool != nil {
				authToken := extractAuthToken(ctx)
				peer := s.peerPool.FindContainerPeer(req.Username, authToken)
				if peer != nil {
					body, peerErr := peer.ForwardGetMetrics(authToken, req.Username)
					if peerErr == nil {
						// Parse and return peer metrics (use protojson for enum handling)
						var peerResp pb.GetMetricsResponse
						if jsonErr := protojson.Unmarshal(body, &peerResp); jsonErr == nil {
							return &peerResp, nil
						}
					}
				}
			}
			return nil, fmt.Errorf("failed to get metrics: %w", err)
		}
		protoMetrics = append(protoMetrics, toProtoMetrics(metrics))
	} else {
		// Get metrics for all containers (local)
		allMetrics, err := s.manager.GetAllMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to get metrics: %w", err)
		}
		for _, m := range allMetrics {
			protoMetrics = append(protoMetrics, toProtoMetrics(m))
		}

		// Merge metrics from all healthy peers
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			for _, peer := range s.peerPool.Peers() {
				if !peer.Healthy {
					continue
				}
				body, err := peer.ForwardGetMetrics(authToken, "")
				if err != nil {
					log.Printf("[metrics] peer %s: %v", peer.ID, err)
					continue
				}
				var peerMetricsResp pb.GetMetricsResponse
				if err := protojson.Unmarshal(body, &peerMetricsResp); err != nil {
					log.Printf("[metrics] peer %s parse error: %v", peer.ID, err)
					continue
				}
				protoMetrics = append(protoMetrics, peerMetricsResp.Metrics...)
			}
		}
	}

	return &pb.GetMetricsResponse{
		Metrics: protoMetrics,
	}, nil
}

// GetSystemInfo gets information about the Incus host
func (s *ContainerServer) GetSystemInfo(ctx context.Context, req *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
	// Get basic system info from container manager
	containers, err := s.manager.List()
	if err != nil {
		return nil, fmt.Errorf("failed to get containers: %w", err)
	}

	// Count running/stopped containers
	var running, stopped int32
	for _, c := range containers {
		if c.State == "Running" {
			running++
		} else {
			stopped++
		}
	}

	// Get Incus server info
	client, err := incus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w", err)
	}

	serverInfo, err := client.GetServerInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get server info: %w", err)
	}

	// Get network CIDR
	networkCIDR, err := client.GetNetworkSubnet("incusbr0")
	if err != nil {
		// Fallback to default if network info not available
		networkCIDR = "10.100.0.0/24"
	}

	// Get system resources (CPU, memory, disk)
	sysResources, err := client.GetSystemResources()
	if err != nil {
		// Log warning but continue - resource info is optional
		sysResources = &incus.SystemResources{}
	}

	// Build response
	info := &pb.SystemInfo{
		IncusVersion:          serverInfo.Environment.ServerVersion,
		Os:                    serverInfo.Environment.OSName,
		KernelVersion:         serverInfo.Environment.KernelVersion,
		ContainersRunning:     running,
		ContainersStopped:     stopped,
		ContainersTotal:       int32(len(containers)),
		Hostname:              serverInfo.Environment.ServerName,
		NetworkCidr:           networkCIDR,
		TotalCpus:             sysResources.TotalCPUs,
		TotalMemoryBytes:      sysResources.TotalMemoryBytes,
		AvailableMemoryBytes:  sysResources.TotalMemoryBytes - sysResources.UsedMemoryBytes,
		TotalDiskBytes:        sysResources.TotalDiskBytes,
		AvailableDiskBytes:    sysResources.TotalDiskBytes - sysResources.UsedDiskBytes,
		CpuLoad_1Min:          sysResources.CPULoad1Min,
		CpuLoad_5Min:          sysResources.CPULoad5Min,
		CpuLoad_15Min:         sysResources.CPULoad15Min,
	}

	// Populate GPU info
	for _, gpu := range sysResources.GPUs {
		info.Gpus = append(info.Gpus, &pb.GPUInfo{
			Vendor:        mapGPUVendor(gpu.Vendor),
			Model:         mapGPUModel(gpu.Model),
			ModelName:     gpu.Model,
			PciAddress:    gpu.PCIAddress,
			DriverVersion: gpu.DriverVersion,
			CudaVersion:   gpu.CUDAVersion,
			VramBytes:     gpu.VRAMBytes,
		})
	}

	// Fetch system info from all healthy peers
	var peerInfos []*pb.SystemInfo
	if s.peerPool != nil {
		authToken := extractAuthToken(ctx)
		for _, peer := range s.peerPool.Peers() {
			if !peer.Healthy {
				continue
			}
			body, err := peer.ForwardGetSystemInfo(authToken)
			if err != nil {
				log.Printf("[system-info] peer %s: %v", peer.ID, err)
				continue
			}
			// Use protojson to handle enum string values from gRPC-gateway JSON
			var peerResp pb.GetSystemInfoResponse
			if err := protojson.Unmarshal(body, &peerResp); err != nil {
				log.Printf("[system-info] peer %s parse error: %v", peer.ID, err)
				continue
			}
			if peerResp.Info != nil {
				peerResp.Info.BackendId = peer.ID
				peerInfos = append(peerInfos, peerResp.Info)
			}
		}
	}

	return &pb.GetSystemInfoResponse{
		Info:  info,
		Peers: peerInfos,
	}, nil
}

// mapGPUVendor maps a vendor string to the proto enum.
func mapGPUVendor(vendor string) pb.GPUVendor {
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "nvidia"):
		return pb.GPUVendor_GPU_VENDOR_NVIDIA
	case strings.Contains(v, "amd") || strings.Contains(v, "advanced micro"):
		return pb.GPUVendor_GPU_VENDOR_AMD
	case strings.Contains(v, "intel"):
		return pb.GPUVendor_GPU_VENDOR_INTEL
	default:
		return pb.GPUVendor_GPU_VENDOR_UNSPECIFIED
	}
}

// mapGPUModel maps a model name string to the proto enum.
func mapGPUModel(model string) pb.GPUModel {
	m := strings.ToLower(model)
	switch {
	// NVIDIA Consumer
	case strings.Contains(m, "rtx 5090"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_5090
	case strings.Contains(m, "rtx 5080"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_5080
	case strings.Contains(m, "rtx 4090"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4090
	case strings.Contains(m, "rtx 4080"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4080
	case strings.Contains(m, "rtx 4070 ti"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4070_TI
	case strings.Contains(m, "rtx 4070"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4070
	case strings.Contains(m, "rtx 3090"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_3090
	case strings.Contains(m, "rtx 3080"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_3080
	// NVIDIA Datacenter
	case strings.Contains(m, "b200"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_B200
	case strings.Contains(m, "h200"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_H200
	case strings.Contains(m, "h100"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_H100
	case strings.Contains(m, "a100"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_A100
	case strings.Contains(m, "a10g"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_A10G
	case strings.Contains(m, "a10"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_A10
	case strings.Contains(m, "l40s"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_L40S
	case strings.Contains(m, "l40"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_L40
	case strings.Contains(m, "l4"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_L4
	case strings.Contains(m, "t4"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_T4
	case strings.Contains(m, "v100"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_V100
	// AMD
	case strings.Contains(m, "mi300x"):
		return pb.GPUModel_GPU_MODEL_AMD_MI300X
	case strings.Contains(m, "mi250x"):
		return pb.GPUModel_GPU_MODEL_AMD_MI250X
	case strings.Contains(m, "7900 xtx"):
		return pb.GPUModel_GPU_MODEL_AMD_RX_7900_XTX
	// Intel
	case strings.Contains(m, "max 1550"):
		return pb.GPUModel_GPU_MODEL_INTEL_MAX_1550
	case strings.Contains(m, "a770"):
		return pb.GPUModel_GPU_MODEL_INTEL_ARC_A770
	default:
		return pb.GPUModel_GPU_MODEL_UNSPECIFIED
	}
}

// toProtoMetrics converts internal metrics to protobuf
func toProtoMetrics(m *incus.ContainerMetrics) *pb.ContainerMetrics {
	return &pb.ContainerMetrics{
		Name:             m.Name,
		CpuUsageSeconds:  m.CPUUsageSeconds,
		MemoryUsageBytes: m.MemoryUsageBytes,
		MemoryPeakBytes:  m.MemoryLimitBytes,
		DiskUsageBytes:   m.DiskUsageBytes,
		NetworkRxBytes:   m.NetworkRxBytes,
		NetworkTxBytes:   m.NetworkTxBytes,
		ProcessCount:     m.ProcessCount,
	}
}

// toProtoContainer converts internal container info to protobuf
func toProtoContainer(info *incus.ContainerInfo) *pb.Container {
	// Parse state
	var state pb.ContainerState
	switch info.State {
	case "Running":
		state = pb.ContainerState_CONTAINER_STATE_RUNNING
	case "Stopped":
		state = pb.ContainerState_CONTAINER_STATE_STOPPED
	case "Frozen":
		state = pb.ContainerState_CONTAINER_STATE_FROZEN
	default:
		state = pb.ContainerState_CONTAINER_STATE_UNSPECIFIED
	}

	// Extract username from container name (format: username-container)
	username := info.Name
	if len(info.Name) > 10 && info.Name[len(info.Name)-10:] == "-container" {
		username = info.Name[:len(info.Name)-10]
	}

	// Resolve OS type from labels
	var osTypeEnum pb.OSType
	if osLabel, ok := info.Labels[ostype.OSTypeLabelKey]; ok {
		osTypeEnum = ostype.OSTypeFromLabel(osLabel)
	}

	// Determine access type based on OS
	accessType := pb.AccessType_ACCESS_TYPE_SSH
	var rdpAddress string
	if ostype.IsWindows(osTypeEnum) {
		accessType = pb.AccessType_ACCESS_TYPE_RDP
		if info.IPAddress != "" {
			rdpAddress = fmt.Sprintf("%s:3389", info.IPAddress)
		}
	}

	return &pb.Container{
		Name:     info.Name,
		Username: username,
		State:    state,
		Resources: &pb.ResourceLimits{
			Cpu:    info.CPU,
			Memory: info.Memory,
			Disk:   info.Disk,
		},
		Network: &pb.NetworkInfo{
			IpAddress: info.IPAddress,
		},
		Labels:            info.Labels,
		CreatedAt:         info.CreatedAt.Unix(),
		PodmanEnabled:     true,  // TODO: Get from container config
		Stack:             "",    // TODO: Get from container labels
		GpuDevice:         info.GPU,
		BackendId:         info.BackendID,
		OsType:            osTypeEnum,
		AccessType:        accessType,
		RdpAddress:        rdpAddress,
		MonitoringEnabled: info.MonitoringEnabled,
	}
}

// GetManager returns the container manager for reuse by other components
func (s *ContainerServer) GetManager() *container.Manager {
	return s.manager
}

// extractAuthToken extracts the JWT token from gRPC metadata.
func extractAuthToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if vals := md.Get("authorization"); len(vals) > 0 {
		token := vals[0]
		if len(token) > 7 && token[:7] == "Bearer " {
			return token[7:]
		}
		return token
	}
	return ""
}

// SetPeerPool sets the peer pool for multi-backend support
func (s *ContainerServer) SetPeerPool(pool *PeerPool) {
	s.peerPool = pool
}

// SetOTelCollectorEndpoint wires the OTLP/HTTP URL of this daemon's
// core OTel collector LXC. Stamped into containers created with
// monitoring=true. DualServer calls this after the collector
// container is provisioned (or after looking up its IP if it
// already exists). Empty string disables app-monitoring injection
// for new containers — they'll log a warning and skip stamping.
func (s *ContainerServer) SetOTelCollectorEndpoint(endpoint string) {
	s.otelCollectorEndpoint = endpoint
}

// SetCoreServices wires the CoreServices manager used by
// refreshContainerIPMap to push source-IP attribution updates into
// the collector LXC. Called from dual_server.go alongside
// SetOTelCollectorEndpoint after the collector is ensured. Separate
// setter from SetAlertManager because the alerting path is optional
// and we want OTel attribution to work even on daemons started
// without --alert-webhook-url.
func (s *ContainerServer) SetCoreServices(cs *CoreServices) {
	s.coreServices = cs
}

// refreshContainerIPMap rebuilds the source-IP → container-name map
// and pushes it into the collector LXC. Best-effort: errors are
// logged but never bubbled up — a stale IP map degrades source-IP
// attribution but does not justify failing a container create/delete.
//
// Skips entirely when coreServices is nil (standalone mode) or the
// collector isn't provisioned yet. Core containers are excluded —
// their telemetry never carries app-emitted resource attributes.
func (s *ContainerServer) refreshContainerIPMap() {
	if s.coreServices == nil || s.coreServices.GetOTelCollectorIP() == "" {
		return
	}
	infos, err := s.manager.List()
	if err != nil {
		log.Printf("Warning: failed to list containers for IP map refresh: %v", err)
		return
	}
	ipMap := make(map[string]string, len(infos))
	for _, c := range infos {
		if c.Role.IsCoreRole() || c.IPAddress == "" {
			continue
		}
		ipMap[c.IPAddress] = c.Name
	}
	if err := s.coreServices.WriteContainerIPMap(ipMap); err != nil {
		log.Printf("Warning: failed to push container IP map to collector: %v", err)
	}
}

// localBackendID returns this daemon's backend ID for stamping into
// OTEL_RESOURCE_ATTRIBUTES. Falls back to "local" if the peer pool
// isn't configured (single-host deployments) — that way single-host
// metrics still have a well-known label rather than an empty string,
// keeping Grafana queries simpler.
func (s *ContainerServer) localBackendID() string {
	if s.peerPool == nil {
		return "local"
	}
	if id := s.peerPool.LocalBackendID(); id != "" {
		return id
	}
	return "local"
}

// SetRouteCleanupDeps wires the route store + proxy manager so
// DeleteContainer can cascade-clean a container's routes + TLS
// subjects. Both may be nil if the daemon was started without
// --app-hosting; the cascade will skip those steps gracefully.
func (s *ContainerServer) SetRouteCleanupDeps(routeStore *app.RouteStore, proxyManager *app.ProxyManager) {
	s.routeStore = routeStore
	s.proxyManager = proxyManager
}

// SetCollaboratorManager sets the collaborator manager for handling collaborator operations
func (s *ContainerServer) SetCollaboratorManager(cm *container.CollaboratorManager) {
	s.collaboratorManager = cm
}

// AddCollaborator adds a collaborator to a container
func (s *ContainerServer) AddCollaborator(ctx context.Context, req *pb.AddCollaboratorRequest) (*pb.AddCollaboratorResponse, error) {
	if req.OwnerUsername == "" {
		return nil, fmt.Errorf("owner_username is required")
	}
	if req.CollaboratorUsername == "" {
		return nil, fmt.Errorf("collaborator_username is required")
	}
	if req.SshPublicKey == "" {
		return nil, fmt.Errorf("ssh_public_key is required")
	}

	if s.collaboratorManager == nil {
		// No local collaborator manager — try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.OwnerUsername, authToken)
			if peer != nil {
				body, _ := json.Marshal(map[string]interface{}{
					"collaborator_username":    req.CollaboratorUsername,
					"ssh_public_key":           req.SshPublicKey,
					"grant_sudo":               req.GrantSudo,
					"grant_container_runtime":  req.GrantContainerRuntime,
				})
				respBody, statusCode, fwdErr := peer.ForwardRequest("POST", fmt.Sprintf("/v1/containers/%s/collaborators", req.OwnerUsername), authToken, body)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to add collaborator on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d: %s", peer.ID, statusCode, string(respBody))
				}
				var peerResp struct {
					Collaborator *pb.Collaborator `json:"collaborator"`
					SshCommand   string           `json:"sshCommand"`
					Message      string           `json:"message"`
				}
				if jsonErr := json.Unmarshal(respBody, &peerResp); jsonErr == nil && peerResp.Collaborator != nil {
					return &pb.AddCollaboratorResponse{
						Message:      peerResp.Message,
						Collaborator: peerResp.Collaborator,
						SshCommand:   peerResp.SshCommand,
					}, nil
				}
				return &pb.AddCollaboratorResponse{
					Message: fmt.Sprintf("Collaborator added on backend %s", peer.ID),
				}, nil
			}
		}
		return nil, fmt.Errorf("collaborator management not enabled")
	}

	collab, err := s.collaboratorManager.AddCollaborator(req.OwnerUsername, req.CollaboratorUsername, req.SshPublicKey, req.GrantSudo, req.GrantContainerRuntime)
	if err != nil {
		return nil, fmt.Errorf("failed to add collaborator: %w", err)
	}

	return &pb.AddCollaboratorResponse{
		Message: fmt.Sprintf("Collaborator %s added to %s-container", req.CollaboratorUsername, req.OwnerUsername),
		Collaborator: &pb.Collaborator{
			Id:                   collab.ID,
			ContainerName:        collab.ContainerName,
			OwnerUsername:        collab.OwnerUsername,
			CollaboratorUsername: collab.CollaboratorUsername,
			AccountName:          collab.AccountName,
			SshPublicKey:         collab.SSHPublicKey,
			AddedAt:              collab.CreatedAt.Unix(),
			CreatedBy:            collab.CreatedBy,
			HasSudo:              collab.HasSudo,
			HasContainerRuntime:  collab.HasContainerRuntime,
		},
		SshCommand: s.collaboratorManager.GenerateSSHCommand(req.OwnerUsername, req.CollaboratorUsername, "jumpserver"),
	}, nil
}

// RemoveCollaborator removes a collaborator from a container
func (s *ContainerServer) RemoveCollaborator(ctx context.Context, req *pb.RemoveCollaboratorRequest) (*pb.RemoveCollaboratorResponse, error) {
	if req.OwnerUsername == "" {
		return nil, fmt.Errorf("owner_username is required")
	}
	if req.CollaboratorUsername == "" {
		return nil, fmt.Errorf("collaborator_username is required")
	}

	if s.collaboratorManager == nil {
		// No local collaborator manager — try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.OwnerUsername, authToken)
			if peer != nil {
				_, statusCode, fwdErr := peer.ForwardRequest("DELETE", fmt.Sprintf("/v1/containers/%s/collaborators/%s", req.OwnerUsername, req.CollaboratorUsername), authToken, nil)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to remove collaborator on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d for remove collaborator", peer.ID, statusCode)
				}
				return &pb.RemoveCollaboratorResponse{
					Message: fmt.Sprintf("Collaborator %s removed on backend %s", req.CollaboratorUsername, peer.ID),
				}, nil
			}
		}
		return nil, fmt.Errorf("collaborator management not enabled")
	}

	if err := s.collaboratorManager.RemoveCollaborator(req.OwnerUsername, req.CollaboratorUsername); err != nil {
		return nil, fmt.Errorf("failed to remove collaborator: %w", err)
	}

	return &pb.RemoveCollaboratorResponse{
		Message: fmt.Sprintf("Collaborator %s removed from %s-container", req.CollaboratorUsername, req.OwnerUsername),
	}, nil
}

// ListCollaborators lists all collaborators for a container
func (s *ContainerServer) ListCollaborators(ctx context.Context, req *pb.ListCollaboratorsRequest) (*pb.ListCollaboratorsResponse, error) {
	if req.OwnerUsername == "" {
		return nil, fmt.Errorf("owner_username is required")
	}

	if s.collaboratorManager == nil {
		// No local collaborator manager — try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.OwnerUsername, authToken)
			if peer != nil {
				respBody, statusCode, fwdErr := peer.ForwardRequest("GET", fmt.Sprintf("/v1/containers/%s/collaborators", req.OwnerUsername), authToken, nil)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to list collaborators on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d for list collaborators", peer.ID, statusCode)
				}
				var peerResp pb.ListCollaboratorsResponse
				if jsonErr := json.Unmarshal(respBody, &peerResp); jsonErr == nil {
					return &peerResp, nil
				}
				return &pb.ListCollaboratorsResponse{}, nil
			}
		}
		return nil, fmt.Errorf("collaborator management not enabled")
	}

	collaborators, err := s.collaboratorManager.ListCollaborators(req.OwnerUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to list collaborators: %w", err)
	}

	var protoCollaborators []*pb.Collaborator
	for _, c := range collaborators {
		protoCollaborators = append(protoCollaborators, &pb.Collaborator{
			Id:                   c.ID,
			ContainerName:        c.ContainerName,
			OwnerUsername:        c.OwnerUsername,
			CollaboratorUsername: c.CollaboratorUsername,
			AccountName:          c.AccountName,
			SshPublicKey:         c.SSHPublicKey,
			AddedAt:              c.CreatedAt.Unix(),
			CreatedBy:            c.CreatedBy,
			HasSudo:              c.HasSudo,
			HasContainerRuntime:  c.HasContainerRuntime,
		})
	}

	return &pb.ListCollaboratorsResponse{
		Collaborators: protoCollaborators,
		TotalCount:    int32(len(protoCollaborators)),
	}, nil
}

// SetMonitoringURLs sets the VictoriaMetrics and Grafana URLs for the monitoring info endpoint
func (s *ContainerServer) SetMonitoringURLs(victoriaMetricsURL, grafanaURL string) {
	s.victoriaMetricsURL = victoriaMetricsURL
	s.grafanaURL = grafanaURL
}

// GetMonitoringInfo returns monitoring configuration (Grafana/VictoriaMetrics URLs)
func (s *ContainerServer) GetMonitoringInfo(ctx context.Context, req *pb.GetMonitoringInfoRequest) (*pb.GetMonitoringInfoResponse, error) {
	return &pb.GetMonitoringInfoResponse{
		Enabled:            s.victoriaMetricsURL != "",
		GrafanaUrl:         s.grafanaURL,
		VictoriaMetricsUrl: s.victoriaMetricsURL,
	}, nil
}

// guacamoleConnectionIDLabel is the Incus label key for storing the Guacamole connection ID.
const guacamoleConnectionIDLabel = "guacamole-connection-id"

// SetGuacamoleClient sets the Guacamole client for Windows VM RDP registration.
func (s *ContainerServer) SetGuacamoleClient(client *guacamole.Client, adminUser, adminPass string) {
	s.guacamoleClient = client
	s.guacamoleUser = adminUser
	s.guacamolePass = adminPass
}

// registerGuacamoleConnection registers a Windows VM's RDP connection in Guacamole.
// Returns the connection ID, or "" if Guacamole is not configured.
func (s *ContainerServer) registerGuacamoleConnection(containerName, hostname, rdpUser, rdpPassword string) string {
	if s.guacamoleClient == nil {
		return ""
	}

	token, err := s.guacamoleClient.Authenticate(s.guacamoleUser, s.guacamolePass)
	if err != nil {
		log.Printf("Warning: Guacamole auth failed, skipping RDP registration: %v", err)
		return ""
	}

	connID, err := s.guacamoleClient.CreateConnection(token, guacamole.ConnectionConfig{
		Name:     containerName,
		Hostname: hostname,
		Port:     "3389",
		Username: rdpUser,
		Password: rdpPassword,
	})
	if err != nil {
		log.Printf("Warning: Failed to register Guacamole connection for %s: %v", containerName, err)
		return ""
	}

	log.Printf("Guacamole RDP connection registered for %s (id=%s)", containerName, connID)
	return connID
}

// deregisterGuacamoleConnection removes a Windows VM's RDP connection from Guacamole.
func (s *ContainerServer) deregisterGuacamoleConnection(username string) {
	if s.guacamoleClient == nil {
		return
	}

	// Look up the connection ID from container labels
	info, err := s.manager.Get(username)
	if err != nil {
		return
	}

	connID, ok := info.Labels[guacamoleConnectionIDLabel]
	if !ok || connID == "" {
		return
	}

	token, err := s.guacamoleClient.Authenticate(s.guacamoleUser, s.guacamolePass)
	if err != nil {
		log.Printf("Warning: Guacamole auth failed during deregistration: %v", err)
		return
	}

	if err := s.guacamoleClient.DeleteConnection(token, connID); err != nil {
		log.Printf("Warning: Failed to deregister Guacamole connection %s: %v", connID, err)
		return
	}

	log.Printf("Guacamole RDP connection removed for %s (id=%s)", username, connID)
}
