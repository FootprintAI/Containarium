package server

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// NetworkServer implements the NetworkService gRPC service
type NetworkServer struct {
	pb.UnimplementedNetworkServiceServer
	incusClient      *incus.Client
	proxyManager     *app.ProxyManager
	appStore         app.AppStore
	containerNetwork string // e.g., "10.100.0.0/24"
	proxyIP          string // e.g., "10.100.0.1"
}

// NewNetworkServer creates a new network server
func NewNetworkServer(incusClient *incus.Client, proxyManager *app.ProxyManager, appStore app.AppStore, containerNetwork, proxyIP string) *NetworkServer {
	return &NetworkServer{
		incusClient:      incusClient,
		proxyManager:     proxyManager,
		appStore:         appStore,
		containerNetwork: containerNetwork,
		proxyIP:          proxyIP,
	}
}

// GetRoutes lists all proxy routes
func (s *NetworkServer) GetRoutes(ctx context.Context, req *pb.GetRoutesRequest) (*pb.GetRoutesResponse, error) {
	// Check if proxy manager is available
	if s.proxyManager == nil {
		// No proxy configured, return empty routes
		return &pb.GetRoutesResponse{
			Routes:     []*pb.ProxyRoute{},
			TotalCount: 0,
		}, nil
	}

	// Get routes from proxy manager
	routes, err := s.proxyManager.ListRoutes()
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	var pbRoutes []*pb.ProxyRoute
	for _, route := range routes {
		// Optionally filter by username
		if req.Username != "" {
			// Get app to check username
			apps, err := s.appStore.List(ctx, req.Username, pb.AppState_APP_STATE_UNSPECIFIED)
			if err != nil {
				continue
			}
			found := false
			for _, a := range apps {
				if a.Subdomain == route.Subdomain {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		pbRoute := &pb.ProxyRoute{
			Subdomain:   route.Subdomain,
			FullDomain:  route.FullDomain,
			ContainerIp: route.UpstreamIP,
			Port:        int32(route.UpstreamPort),
			Active:      true, // If it's in the list, it's active
		}
		pbRoutes = append(pbRoutes, pbRoute)
	}

	return &pb.GetRoutesResponse{
		Routes:     pbRoutes,
		TotalCount: int32(len(pbRoutes)),
	}, nil
}

// GetContainerACL gets firewall rules for a DevBox container
func (s *NetworkServer) GetContainerACL(ctx context.Context, req *pb.GetContainerACLRequest) (*pb.GetContainerACLResponse, error) {
	containerName := req.Username + "-container"

	// Verify container exists
	_, err := s.incusClient.GetContainer(containerName)
	if err != nil {
		return nil, fmt.Errorf("container not found: %w", err)
	}

	// Get ACL name for this container
	aclName := fmt.Sprintf("acl-%s", req.Username)

	// Try to get ACL info from Incus
	aclInfo, err := s.incusClient.GetACLInfo(aclName)
	if err != nil {
		// ACL doesn't exist, return default/empty
		return &pb.GetContainerACLResponse{
			Acl: &pb.NetworkACL{
				Name:          aclName,
				Description:   "No firewall rules configured",
				Preset:        pb.ACLPreset_ACL_PRESET_UNSPECIFIED,
				ContainerName: containerName,
			},
		}, nil
	}

	// Convert to protobuf
	pbACL := &pb.NetworkACL{
		Name:          aclInfo.Name,
		Description:   aclInfo.Description,
		ContainerName: containerName,
	}

	// Determine preset from rules
	pbACL.Preset = s.detectPreset(aclInfo)

	// Convert ingress rules
	for _, rule := range aclInfo.IngressRules {
		pbACL.IngressRules = append(pbACL.IngressRules, &pb.ACLRule{
			Action:          s.actionToProto(rule.Action),
			Source:          rule.Source,
			Destination:     rule.Destination,
			DestinationPort: rule.DestinationPort,
			Protocol:        rule.Protocol,
			Description:     rule.Description,
		})
	}

	// Convert egress rules
	for _, rule := range aclInfo.EgressRules {
		pbACL.EgressRules = append(pbACL.EgressRules, &pb.ACLRule{
			Action:          s.actionToProto(rule.Action),
			Source:          rule.Source,
			Destination:     rule.Destination,
			DestinationPort: rule.DestinationPort,
			Protocol:        rule.Protocol,
			Description:     rule.Description,
		})
	}

	return &pb.GetContainerACLResponse{Acl: pbACL}, nil
}

// UpdateContainerACL updates firewall rules for a DevBox container
func (s *NetworkServer) UpdateContainerACL(ctx context.Context, req *pb.UpdateContainerACLRequest) (*pb.UpdateContainerACLResponse, error) {
	containerName := req.Username + "-container"

	// Verify container exists
	_, err := s.incusClient.GetContainer(containerName)
	if err != nil {
		return nil, fmt.Errorf("container not found: %w", err)
	}

	aclName := fmt.Sprintf("acl-%s", req.Username)

	var config incus.ACLConfig

	if req.Preset != pb.ACLPreset_ACL_PRESET_CUSTOM && req.Preset != pb.ACLPreset_ACL_PRESET_UNSPECIFIED {
		// Use preset
		preset := s.protoToPreset(req.Preset)
		config = incus.GetPresetACL(preset, s.proxyIP, s.containerNetwork)
		config.Name = aclName
	} else {
		// Custom rules
		config = incus.ACLConfig{
			Name:        aclName,
			Description: "Custom firewall rules",
		}

		for _, rule := range req.IngressRules {
			config.IngressRules = append(config.IngressRules, incus.ACLRule{
				Action:          s.protoToAction(rule.Action),
				Source:          rule.Source,
				Destination:     rule.Destination,
				DestinationPort: rule.DestinationPort,
				Protocol:        rule.Protocol,
				Description:     rule.Description,
			})
		}

		for _, rule := range req.EgressRules {
			config.EgressRules = append(config.EgressRules, incus.ACLRule{
				Action:          s.protoToAction(rule.Action),
				Source:          rule.Source,
				Destination:     rule.Destination,
				DestinationPort: rule.DestinationPort,
				Protocol:        rule.Protocol,
				Description:     rule.Description,
			})
		}
	}

	// Create or update ACL using the container-focused method
	_, err = s.incusClient.EnsureACLForContainer(req.Username, s.protoToPreset(req.Preset), s.proxyIP, s.containerNetwork)
	if err != nil {
		return nil, fmt.Errorf("failed to update ACL: %w", err)
	}

	// Attach ACL to container
	err = s.incusClient.AttachACLToContainer(containerName, aclName, "eth0")
	if err != nil {
		return nil, fmt.Errorf("failed to attach ACL to container: %w", err)
	}

	// Get updated ACL
	getResp, err := s.GetContainerACL(ctx, &pb.GetContainerACLRequest{
		Username: req.Username,
	})
	if err != nil {
		return nil, err
	}

	return &pb.UpdateContainerACLResponse{
		Acl:     getResp.Acl,
		Message: "ACL updated successfully",
	}, nil
}

// GetNetworkTopology returns network visualization data
func (s *NetworkServer) GetNetworkTopology(ctx context.Context, req *pb.GetNetworkTopologyRequest) (*pb.GetNetworkTopologyResponse, error) {
	topology := &pb.NetworkTopology{
		NetworkCidr: s.containerNetwork,
		GatewayIp:   s.proxyIP,
	}

	// Add proxy node only if proxy is configured
	if s.proxyIP != "" {
		topology.Nodes = append(topology.Nodes, &pb.NetworkNode{
			Id:        "proxy",
			Type:      "proxy",
			Name:      "Caddy Reverse Proxy",
			IpAddress: s.proxyIP,
			State:     "running",
		})
	}

	// Get all containers
	containers, err := s.incusClient.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	for _, c := range containers {
		if !req.IncludeStopped && c.State != "Running" {
			continue
		}

		state := "running"
		if c.State != "Running" {
			state = "stopped"
		}

		// Get ACL name
		aclName, _ := s.incusClient.GetContainerACL(c.Name, "eth0")

		topology.Nodes = append(topology.Nodes, &pb.NetworkNode{
			Id:        c.Name,
			Type:      "container",
			Name:      c.Name,
			IpAddress: c.IPAddress,
			State:     state,
			AclName:   aclName,
		})

		// Add edge from proxy to container (only if proxy is configured)
		if s.proxyIP != "" && c.State == "Running" && c.IPAddress != "" {
			topology.Edges = append(topology.Edges, &pb.NetworkEdge{
				Source:   "proxy",
				Target:   c.Name,
				Type:     "route",
				Ports:    "80,443",
				Protocol: "tcp",
			})
		}
	}

	return &pb.GetNetworkTopologyResponse{
		Topology: topology,
	}, nil
}

// ListACLPresets lists available firewall presets
func (s *NetworkServer) ListACLPresets(ctx context.Context, req *pb.ListACLPresetsRequest) (*pb.ListACLPresetsResponse, error) {
	presets := []*pb.ACLPresetInfo{
		{
			Preset:      pb.ACLPreset_ACL_PRESET_FULL_ISOLATION,
			Name:        "Full Isolation",
			Description: "Maximum security: only allow HTTP from proxy, block all inter-container traffic",
		},
		{
			Preset:      pb.ACLPreset_ACL_PRESET_HTTP_ONLY,
			Name:        "HTTP Only",
			Description: "Allow HTTP/HTTPS inbound, standard egress",
		},
		{
			Preset:      pb.ACLPreset_ACL_PRESET_PERMISSIVE,
			Name:        "Permissive",
			Description: "Allow all traffic (for development only)",
		},
		{
			Preset:      pb.ACLPreset_ACL_PRESET_CUSTOM,
			Name:        "Custom",
			Description: "Define your own firewall rules",
		},
	}

	// Add default rules for each preset
	for _, p := range presets {
		if p.Preset == pb.ACLPreset_ACL_PRESET_CUSTOM {
			continue
		}

		preset := s.protoToPreset(p.Preset)
		config := incus.GetPresetACL(preset, s.proxyIP, s.containerNetwork)

		for _, rule := range config.IngressRules {
			p.DefaultIngressRules = append(p.DefaultIngressRules, &pb.ACLRule{
				Action:          s.actionToProto(rule.Action),
				Source:          rule.Source,
				Destination:     rule.Destination,
				DestinationPort: rule.DestinationPort,
				Protocol:        rule.Protocol,
				Description:     rule.Description,
			})
		}

		for _, rule := range config.EgressRules {
			p.DefaultEgressRules = append(p.DefaultEgressRules, &pb.ACLRule{
				Action:          s.actionToProto(rule.Action),
				Source:          rule.Source,
				Destination:     rule.Destination,
				DestinationPort: rule.DestinationPort,
				Protocol:        rule.Protocol,
				Description:     rule.Description,
			})
		}
	}

	return &pb.ListACLPresetsResponse{
		Presets: presets,
	}, nil
}

// Helper functions

func (s *NetworkServer) actionToProto(action string) pb.ACLAction {
	switch action {
	case "allow":
		return pb.ACLAction_ACL_ACTION_ALLOW
	case "drop":
		return pb.ACLAction_ACL_ACTION_DROP
	case "reject":
		return pb.ACLAction_ACL_ACTION_REJECT
	default:
		return pb.ACLAction_ACL_ACTION_UNSPECIFIED
	}
}

func (s *NetworkServer) protoToAction(action pb.ACLAction) string {
	switch action {
	case pb.ACLAction_ACL_ACTION_ALLOW:
		return "allow"
	case pb.ACLAction_ACL_ACTION_DROP:
		return "drop"
	case pb.ACLAction_ACL_ACTION_REJECT:
		return "reject"
	default:
		return "drop"
	}
}

func (s *NetworkServer) protoToPreset(preset pb.ACLPreset) incus.ACLPreset {
	switch preset {
	case pb.ACLPreset_ACL_PRESET_FULL_ISOLATION:
		return incus.ACLPresetFullIsolation
	case pb.ACLPreset_ACL_PRESET_HTTP_ONLY:
		return incus.ACLPresetHTTPOnly
	case pb.ACLPreset_ACL_PRESET_PERMISSIVE:
		return incus.ACLPresetPermissive
	default:
		return incus.ACLPresetFullIsolation
	}
}

func (s *NetworkServer) detectPreset(acl *incus.ACLInfo) pb.ACLPreset {
	// Simple heuristic based on description
	if acl.Description == "" {
		return pb.ACLPreset_ACL_PRESET_CUSTOM
	}

	switch {
	case contains(acl.Description, "Full isolation") || contains(acl.Description, "full-isolation"):
		return pb.ACLPreset_ACL_PRESET_FULL_ISOLATION
	case contains(acl.Description, "HTTP only") || contains(acl.Description, "http-only"):
		return pb.ACLPreset_ACL_PRESET_HTTP_ONLY
	case contains(acl.Description, "Permissive") || contains(acl.Description, "permissive"):
		return pb.ACLPreset_ACL_PRESET_PERMISSIVE
	default:
		return pb.ACLPreset_ACL_PRESET_CUSTOM
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
