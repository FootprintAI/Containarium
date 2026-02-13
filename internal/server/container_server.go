package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/container"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// PendingCreation tracks an async container creation
type PendingCreation struct {
	Username  string
	StartedAt time.Time
	Error     error
	Done      bool
}

// ContainerServer implements the gRPC ContainerService
type ContainerServer struct {
	pb.UnimplementedContainerServiceServer
	manager          *container.Manager
	emitter          *events.Emitter
	pendingCreations map[string]*PendingCreation
	pendingMu        sync.RWMutex
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

	// Build create options
	opts := container.CreateOptions{
		Username:               req.Username,
		Image:                  req.Image,
		SSHKeys:                req.SshKeys,
		Labels:                 req.Labels,
		EnableDocker:           req.EnableDocker,
		EnableDockerPrivileged: req.EnableDocker, // Enable privileged mode for proper Docker-in-Docker support
		AutoStart:              true,
	}

	// Set resource limits
	if req.Resources != nil {
		opts.CPU = req.Resources.Cpu
		opts.Memory = req.Resources.Memory
		opts.Disk = req.Resources.Disk
	}

	// Set static IP if specified
	if req.StaticIp != "" {
		opts.StaticIP = req.StaticIp
	}

	// Use defaults if not specified
	if opts.Image == "" {
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

		// Start async creation
		go func() {
			info, err := s.manager.Create(opts)

			s.pendingMu.Lock()
			if pending, exists := s.pendingCreations[req.Username]; exists {
				pending.Done = true
				pending.Error = err
			}
			s.pendingMu.Unlock()

			// Emit event on success
			if err == nil && info != nil {
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

	// Convert to protobuf
	protoContainer := toProtoContainer(info)

	// Emit container created event
	s.emitter.EmitContainerCreated(protoContainer)

	return &pb.CreateContainerResponse{
		Container:  protoContainer,
		Message:    fmt.Sprintf("Container %s created successfully", info.Name),
		SshCommand: fmt.Sprintf("ssh %s@%s", req.Username, info.IPAddress),
	}, nil
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

	// Convert to protobuf
	var protoContainers []*pb.Container
	for i := range filtered {
		protoContainers = append(protoContainers, toProtoContainer(&filtered[i]))
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
		// Still creating - return CREATING state
		return &pb.GetContainerResponse{
			Container: &pb.Container{
				Name:     fmt.Sprintf("%s-container", req.Username),
				Username: req.Username,
				State:    pb.ContainerState_CONTAINER_STATE_CREATING,
			},
		}, nil
	}

	if hasPending && pending.Done && pending.Error != nil {
		// Creation failed - return ERROR state
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

	err := s.manager.Delete(req.Username, req.Force)
	if err != nil {
		return nil, fmt.Errorf("failed to delete container: %w", err)
	}

	// Emit container deleted event
	s.emitter.EmitContainerDeleted(containerName)

	return &pb.DeleteContainerResponse{
		Message:       fmt.Sprintf("Container for user %s deleted successfully", req.Username),
		ContainerName: containerName,
	}, nil
}

// StartContainer starts a stopped container
func (s *ContainerServer) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*pb.StartContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// TODO: Implement start in container manager
	return nil, fmt.Errorf("not implemented yet")
}

// StopContainer stops a running container
func (s *ContainerServer) StopContainer(ctx context.Context, req *pb.StopContainerRequest) (*pb.StopContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// TODO: Implement stop in container manager
	return nil, fmt.Errorf("not implemented yet")
}

// AddSSHKey adds an SSH key to a container
func (s *ContainerServer) AddSSHKey(ctx context.Context, req *pb.AddSSHKeyRequest) (*pb.AddSSHKeyResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.SshPublicKey == "" {
		return nil, fmt.Errorf("ssh_public_key is required")
	}

	// TODO: Implement SSH key management
	return nil, fmt.Errorf("not implemented yet")
}

// RemoveSSHKey removes an SSH key from a container
func (s *ContainerServer) RemoveSSHKey(ctx context.Context, req *pb.RemoveSSHKeyRequest) (*pb.RemoveSSHKeyResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.SshPublicKey == "" {
		return nil, fmt.Errorf("ssh_public_key is required")
	}

	// TODO: Implement SSH key management
	return nil, fmt.Errorf("not implemented yet")
}

// GetMetrics gets runtime metrics for containers
func (s *ContainerServer) GetMetrics(ctx context.Context, req *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	var protoMetrics []*pb.ContainerMetrics

	if req.Username != "" {
		// Get metrics for a specific container
		metrics, err := s.manager.GetMetrics(req.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to get metrics: %w", err)
		}
		protoMetrics = append(protoMetrics, toProtoMetrics(metrics))
	} else {
		// Get metrics for all containers
		allMetrics, err := s.manager.GetAllMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to get metrics: %w", err)
		}
		for _, m := range allMetrics {
			protoMetrics = append(protoMetrics, toProtoMetrics(m))
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

	return &pb.GetSystemInfoResponse{
		Info: info,
	}, nil
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
		Labels:        info.Labels,
		CreatedAt:     info.CreatedAt.Unix(),
		DockerEnabled: true, // TODO: Get from container config
	}
}
