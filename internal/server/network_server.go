package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/network"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// NetworkServer implements the NetworkService gRPC service
type NetworkServer struct {
	pb.UnimplementedNetworkServiceServer
	incusClient        *incus.Client
	proxyManager       *app.ProxyManager
	passthroughManager *network.PassthroughManager
	appStore           app.AppStore
	routeStore         *app.RouteStore            // Source of truth for routes (PostgreSQL)
	passthroughStore   *network.PassthroughStore   // Source of truth for passthrough routes (PostgreSQL)
	containerNetwork   string                      // e.g., "10.100.0.0/24"
	proxyIP            string                      // e.g., "10.100.0.1"
	baseDomain         string                      // e.g., "kafeido.app"
	emitter            *events.Emitter
}

// resolveFullDomain determines the full domain from a user-provided domain string.
// - If domain already ends with baseDomain, use as-is.
// - If domain is a simple name (no dots), append baseDomain.
// - Otherwise it's an independent FQDN — use as-is.
func resolveFullDomain(domain, baseDomain string) string {
	if baseDomain != "" {
		if strings.HasSuffix(domain, "."+baseDomain) || domain == baseDomain {
			return domain
		}
		if !strings.Contains(domain, ".") {
			return fmt.Sprintf("%s.%s", domain, baseDomain)
		}
	}
	return domain
}

// NewNetworkServer creates a new network server
func NewNetworkServer(incusClient *incus.Client, proxyManager *app.ProxyManager, appStore app.AppStore, containerNetwork, proxyIP string) *NetworkServer {
	return &NetworkServer{
		incusClient:        incusClient,
		proxyManager:       proxyManager,
		passthroughManager: network.NewPassthroughManager(containerNetwork),
		appStore:           appStore,
		containerNetwork:   containerNetwork,
		proxyIP:            proxyIP,
		emitter:            events.NewEmitter(events.GetBus()),
	}
}

// GetRoutes lists all proxy routes from PostgreSQL (source of truth)
func (s *NetworkServer) GetRoutes(ctx context.Context, req *pb.GetRoutesRequest) (*pb.GetRoutesResponse, error) {
	// If RouteStore is available, use it as source of truth
	if s.routeStore != nil {
		routes, err := s.routeStore.List(ctx, true) // activeOnly = true
		if err != nil {
			return nil, fmt.Errorf("failed to list routes: %w", err)
		}

		// Build IP -> container name map for lookups
		ipToContainer := make(map[string]string)
		if s.incusClient != nil {
			containers, err := s.incusClient.ListContainers()
			if err == nil {
				for _, c := range containers {
					if c.IPAddress != "" {
						ipToContainer[c.IPAddress] = c.Name
					}
				}
			}
		}

		var pbRoutes []*pb.ProxyRoute
		for _, route := range routes {
			// Lookup container name by IP
			containerName := route.ContainerName
			if containerName == "" {
				containerName = ipToContainer[route.TargetIP]
			}

			protocol := pb.RouteProtocol_ROUTE_PROTOCOL_HTTP
			if route.Protocol == "grpc" {
				protocol = pb.RouteProtocol_ROUTE_PROTOCOL_GRPC
			}

			pbRoute := &pb.ProxyRoute{
				Subdomain:   route.Subdomain,
				FullDomain:  route.FullDomain,
				ContainerIp: route.TargetIP,
				Port:        int32(route.TargetPort),
				Active:      route.Active,
				Protocol:    protocol,
				AppName:     containerName,
			}
			pbRoutes = append(pbRoutes, pbRoute)
		}

		return &pb.GetRoutesResponse{
			Routes:     pbRoutes,
			TotalCount: int32(len(pbRoutes)),
		}, nil
	}

	// Fallback to Caddy if RouteStore not available
	if s.proxyManager == nil {
		return &pb.GetRoutesResponse{
			Routes:     []*pb.ProxyRoute{},
			TotalCount: 0,
		}, nil
	}

	// Get routes from proxy manager (legacy fallback)
	routes, err := s.proxyManager.ListRoutes()
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	// Build IP -> container name map for lookups
	ipToContainer := make(map[string]string)
	if s.incusClient != nil {
		containers, err := s.incusClient.ListContainers()
		if err == nil {
			for _, c := range containers {
				if c.IPAddress != "" {
					ipToContainer[c.IPAddress] = c.Name
				}
			}
		}
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

		// Lookup container name by IP
		containerName := ipToContainer[route.UpstreamIP]

		pbRoute := &pb.ProxyRoute{
			Subdomain:   route.Subdomain,
			FullDomain:  route.FullDomain,
			ContainerIp: route.UpstreamIP,
			Port:        int32(route.UpstreamPort),
			Active:      true, // If it's in the list, it's active
			Protocol:    routeProtocolToProto(route.Protocol),
			AppName:     containerName, // Use container name as app name for display
		}
		pbRoutes = append(pbRoutes, pbRoute)
	}

	return &pb.GetRoutesResponse{
		Routes:     pbRoutes,
		TotalCount: int32(len(pbRoutes)),
	}, nil
}

// AddRoute adds a new proxy route (saves to PostgreSQL, sync job updates Caddy)
func (s *NetworkServer) AddRoute(ctx context.Context, req *pb.AddRouteRequest) (*pb.AddRouteResponse, error) {
	// Validate request
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if req.TargetIp == "" {
		return nil, fmt.Errorf("target_ip is required")
	}
	if req.TargetPort <= 0 {
		return nil, fmt.Errorf("target_port must be positive")
	}

	// Determine full domain
	subdomain := req.Domain
	fullDomain := resolveFullDomain(req.Domain, s.baseDomain)

	// Determine protocol
	protocol := "http"
	if req.Protocol == pb.RouteProtocol_ROUTE_PROTOCOL_GRPC {
		protocol = "grpc"
	}

	// If RouteStore is available, save to PostgreSQL (source of truth)
	if s.routeStore != nil {
		routeRecord := &app.RouteRecord{
			Subdomain:     subdomain,
			FullDomain:    fullDomain,
			TargetIP:      req.TargetIp,
			TargetPort:    int(req.TargetPort),
			Protocol:      protocol,
			ContainerName: req.ContainerName,
			Active:        true,
		}

		if err := s.routeStore.Save(ctx, routeRecord); err != nil {
			return nil, fmt.Errorf("failed to save route: %w", err)
		}
	} else if s.proxyManager != nil {
		// Fallback: directly add to Caddy (legacy behavior)
		routeProtocol := protoToRouteProtocol(req.Protocol)
		if routeProtocol == app.RouteProtocolGRPC {
			if err := s.proxyManager.AddGRPCRoute(req.Domain, req.TargetIp, int(req.TargetPort)); err != nil {
				return nil, fmt.Errorf("failed to add gRPC route: %w", err)
			}
		} else {
			if err := s.proxyManager.AddRoute(req.Domain, req.TargetIp, int(req.TargetPort)); err != nil {
				return nil, fmt.Errorf("failed to add route: %w", err)
			}
		}
	} else {
		return nil, fmt.Errorf("route persistence not configured - app hosting must be enabled")
	}

	route := &pb.ProxyRoute{
		Subdomain:   subdomain,
		FullDomain:  fullDomain,
		ContainerIp: req.TargetIp,
		Port:        req.TargetPort,
		Active:      true,
		Protocol:    req.Protocol,
	}

	// Emit route added event
	s.emitter.EmitRouteAdded(route)

	return &pb.AddRouteResponse{
		Route:   route,
		Message: fmt.Sprintf("Route added: %s -> %s:%d (will sync to Caddy)", fullDomain, req.TargetIp, req.TargetPort),
	}, nil
}

// UpdateRoute updates an existing proxy route (updates PostgreSQL, sync job updates Caddy)
func (s *NetworkServer) UpdateRoute(ctx context.Context, req *pb.UpdateRouteRequest) (*pb.UpdateRouteResponse, error) {
	// Validate request
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	// Determine full domain
	subdomain := req.Domain
	fullDomain := resolveFullDomain(req.Domain, s.baseDomain)

	// Determine protocol
	protocol := "http"
	if req.Protocol == pb.RouteProtocol_ROUTE_PROTOCOL_GRPC {
		protocol = "grpc"
	}

	// Handle enable/disable toggle
	if req.Active != nil && !*req.Active {
		// Disable route: set active=false in PostgreSQL
		if s.routeStore != nil {
			if err := s.routeStore.SetActive(ctx, fullDomain, false); err != nil {
				// Try with original domain
				if err := s.routeStore.SetActive(ctx, req.Domain, false); err != nil {
					return nil, fmt.Errorf("failed to disable route: %w", err)
				}
			}
		} else if s.proxyManager != nil {
			// Fallback: directly remove from Caddy
			if err := s.proxyManager.RemoveRoute(req.Domain); err != nil {
				return nil, fmt.Errorf("failed to disable route: %w", err)
			}
		}

		return &pb.UpdateRouteResponse{
			Route: &pb.ProxyRoute{
				Subdomain:   subdomain,
				FullDomain:  fullDomain,
				ContainerIp: req.TargetIp,
				Port:        req.TargetPort,
				Active:      false,
				Protocol:    req.Protocol,
			},
			Message: fmt.Sprintf("Route disabled: %s (will sync to Caddy)", req.Domain),
		}, nil
	}

	// For enabling or updating, we need target info
	if req.TargetIp == "" {
		return nil, fmt.Errorf("target_ip is required")
	}
	if req.TargetPort <= 0 {
		return nil, fmt.Errorf("target_port must be positive")
	}

	// If RouteStore is available, update in PostgreSQL (source of truth)
	if s.routeStore != nil {
		routeRecord := &app.RouteRecord{
			Subdomain:     subdomain,
			FullDomain:    fullDomain,
			TargetIP:      req.TargetIp,
			TargetPort:    int(req.TargetPort),
			Protocol:      protocol,
			ContainerName: req.ContainerName,
			Active:        true,
		}

		if err := s.routeStore.Save(ctx, routeRecord); err != nil {
			return nil, fmt.Errorf("failed to update route: %w", err)
		}
	} else if s.proxyManager != nil {
		// Fallback: directly update in Caddy (legacy behavior)
		routeProtocol := protoToRouteProtocol(req.Protocol)
		if err := s.proxyManager.UpdateRouteWithProtocol(req.Domain, req.TargetIp, int(req.TargetPort), routeProtocol); err != nil {
			return nil, fmt.Errorf("failed to update route: %w", err)
		}
	} else {
		return nil, fmt.Errorf("route persistence not configured - app hosting must be enabled")
	}

	return &pb.UpdateRouteResponse{
		Route: &pb.ProxyRoute{
			Subdomain:   subdomain,
			FullDomain:  fullDomain,
			ContainerIp: req.TargetIp,
			Port:        req.TargetPort,
			Active:      true,
			Protocol:    req.Protocol,
		},
		Message: fmt.Sprintf("Route updated: %s -> %s:%d (will sync to Caddy)", fullDomain, req.TargetIp, req.TargetPort),
	}, nil
}

// DeleteRoute removes a proxy route (deletes from PostgreSQL, sync job updates Caddy)
func (s *NetworkServer) DeleteRoute(ctx context.Context, req *pb.DeleteRouteRequest) (*pb.DeleteRouteResponse, error) {
	// Validate request
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	// Determine full domain for lookup
	fullDomain := resolveFullDomain(req.Domain, s.baseDomain)

	// If RouteStore is available, delete from PostgreSQL (source of truth)
	if s.routeStore != nil {
		// Try both the provided domain and the full domain
		err := s.routeStore.Delete(ctx, fullDomain)
		if err != nil && err == app.ErrRouteNotFound {
			// Try with original domain in case it was already the full domain
			err = s.routeStore.Delete(ctx, req.Domain)
		}
		if err != nil && err != app.ErrRouteNotFound {
			return nil, fmt.Errorf("failed to delete route: %w", err)
		}
	} else if s.proxyManager != nil {
		// Fallback: directly remove from Caddy (legacy behavior)
		if err := s.proxyManager.RemoveRoute(req.Domain); err != nil {
			return nil, fmt.Errorf("failed to delete route: %w", err)
		}
	} else {
		return nil, fmt.Errorf("route persistence not configured - app hosting must be enabled")
	}

	// Emit route deleted event
	s.emitter.EmitRouteDeleted(req.Domain)

	return &pb.DeleteRouteResponse{
		Message: fmt.Sprintf("Route deleted: %s (will sync to Caddy)", req.Domain),
	}, nil
}

// ListPassthroughRoutes lists all TCP/UDP passthrough routes
func (s *NetworkServer) ListPassthroughRoutes(ctx context.Context, req *pb.ListPassthroughRoutesRequest) (*pb.ListPassthroughRoutesResponse, error) {
	// Build IP -> container name map for lookups
	ipToContainer := make(map[string]string)
	if s.incusClient != nil {
		containers, err := s.incusClient.ListContainers()
		if err == nil {
			for _, c := range containers {
				if c.IPAddress != "" {
					ipToContainer[c.IPAddress] = c.Name
				}
			}
		}
	}

	// If PassthroughStore is available, use it as source of truth
	if s.passthroughStore != nil {
		records, err := s.passthroughStore.List(ctx, true) // activeOnly = true
		if err != nil {
			return nil, fmt.Errorf("failed to list passthrough routes: %w", err)
		}

		var pbRoutes []*pb.PassthroughRoute
		for _, rec := range records {
			protocol := pb.RouteProtocol_ROUTE_PROTOCOL_TCP
			if rec.Protocol == "udp" {
				protocol = pb.RouteProtocol_ROUTE_PROTOCOL_UDP
			}

			containerName := rec.ContainerName
			if containerName == "" {
				containerName = ipToContainer[rec.TargetIP]
			}

			pbRoutes = append(pbRoutes, &pb.PassthroughRoute{
				ExternalPort:  int32(rec.ExternalPort),
				TargetIp:      rec.TargetIP,
				TargetPort:    int32(rec.TargetPort),
				Protocol:      protocol,
				Active:        rec.Active,
				ContainerName: containerName,
				Description:   rec.Description,
			})
		}

		return &pb.ListPassthroughRoutesResponse{
			Routes:     pbRoutes,
			TotalCount: int32(len(pbRoutes)),
		}, nil
	}

	// Fallback to iptables (legacy)
	routes, err := s.passthroughManager.ListRoutes()
	if err != nil {
		return nil, fmt.Errorf("failed to list passthrough routes: %w", err)
	}

	var pbRoutes []*pb.PassthroughRoute
	for _, route := range routes {
		protocol := pb.RouteProtocol_ROUTE_PROTOCOL_TCP
		if route.Protocol == "udp" {
			protocol = pb.RouteProtocol_ROUTE_PROTOCOL_UDP
		}

		containerName := route.ContainerName
		if containerName == "" {
			containerName = ipToContainer[route.TargetIP]
		}

		pbRoutes = append(pbRoutes, &pb.PassthroughRoute{
			ExternalPort:  int32(route.ExternalPort),
			TargetIp:      route.TargetIP,
			TargetPort:    int32(route.TargetPort),
			Protocol:      protocol,
			Active:        route.Active,
			ContainerName: containerName,
			Description:   route.Description,
		})
	}

	return &pb.ListPassthroughRoutesResponse{
		Routes:     pbRoutes,
		TotalCount: int32(len(pbRoutes)),
	}, nil
}

// AddPassthroughRoute adds a new TCP/UDP passthrough route
func (s *NetworkServer) AddPassthroughRoute(ctx context.Context, req *pb.AddPassthroughRouteRequest) (*pb.AddPassthroughRouteResponse, error) {
	// Validate request
	if req.ExternalPort <= 0 || req.ExternalPort > 65535 {
		return nil, fmt.Errorf("external_port must be between 1 and 65535")
	}
	if req.TargetIp == "" {
		return nil, fmt.Errorf("target_ip is required")
	}
	if req.TargetPort <= 0 || req.TargetPort > 65535 {
		return nil, fmt.Errorf("target_port must be between 1 and 65535")
	}

	// Determine protocol
	protocol := "tcp"
	if req.Protocol == pb.RouteProtocol_ROUTE_PROTOCOL_UDP {
		protocol = "udp"
	}

	// If PassthroughStore is available, save to PostgreSQL (source of truth)
	if s.passthroughStore != nil {
		record := &network.PassthroughRecord{
			ExternalPort:  int(req.ExternalPort),
			TargetIP:      req.TargetIp,
			TargetPort:    int(req.TargetPort),
			Protocol:      protocol,
			ContainerName: req.ContainerName,
			Description:   req.Description,
			Active:        true,
		}

		if err := s.passthroughStore.Save(ctx, record); err != nil {
			return nil, fmt.Errorf("failed to save passthrough route: %w", err)
		}
	} else {
		// Fallback: directly add to iptables (legacy behavior)
		if err := s.passthroughManager.AddRoute(int(req.ExternalPort), req.TargetIp, int(req.TargetPort), protocol); err != nil {
			return nil, fmt.Errorf("failed to add passthrough route: %w", err)
		}
	}

	route := &pb.PassthroughRoute{
		ExternalPort:  req.ExternalPort,
		TargetIp:      req.TargetIp,
		TargetPort:    req.TargetPort,
		Protocol:      req.Protocol,
		Active:        true,
		ContainerName: req.ContainerName,
		Description:   req.Description,
	}

	return &pb.AddPassthroughRouteResponse{
		Route:   route,
		Message: fmt.Sprintf("Passthrough route added: %s:%d -> %s:%d (will sync to iptables)", protocol, req.ExternalPort, req.TargetIp, req.TargetPort),
	}, nil
}

// DeletePassthroughRoute removes a TCP/UDP passthrough route
func (s *NetworkServer) DeletePassthroughRoute(ctx context.Context, req *pb.DeletePassthroughRouteRequest) (*pb.DeletePassthroughRouteResponse, error) {
	// Validate request
	if req.ExternalPort <= 0 || req.ExternalPort > 65535 {
		return nil, fmt.Errorf("external_port must be between 1 and 65535")
	}

	// Determine protocol
	protocol := "tcp"
	if req.Protocol == pb.RouteProtocol_ROUTE_PROTOCOL_UDP {
		protocol = "udp"
	}

	// If PassthroughStore is available, delete from PostgreSQL (source of truth)
	if s.passthroughStore != nil {
		err := s.passthroughStore.Delete(ctx, int(req.ExternalPort), protocol)
		if err != nil && err != network.ErrPassthroughNotFound {
			return nil, fmt.Errorf("failed to delete passthrough route: %w", err)
		}
	} else {
		// Fallback: directly remove from iptables (legacy behavior)
		if err := s.passthroughManager.RemoveRoute(int(req.ExternalPort), protocol); err != nil {
			return nil, fmt.Errorf("failed to remove passthrough route: %w", err)
		}
	}

	return &pb.DeletePassthroughRouteResponse{
		Message: fmt.Sprintf("Passthrough route removed: %s:%d (will sync to iptables)", protocol, req.ExternalPort),
	}, nil
}

// UpdatePassthroughRoute updates an existing TCP/UDP passthrough route
func (s *NetworkServer) UpdatePassthroughRoute(ctx context.Context, req *pb.UpdatePassthroughRouteRequest) (*pb.UpdatePassthroughRouteResponse, error) {
	// Validate request
	if req.ExternalPort <= 0 || req.ExternalPort > 65535 {
		return nil, fmt.Errorf("external_port must be between 1 and 65535")
	}

	// Determine protocol
	protocol := "tcp"
	pbProtocol := req.Protocol
	if pbProtocol == pb.RouteProtocol_ROUTE_PROTOCOL_UNSPECIFIED {
		pbProtocol = pb.RouteProtocol_ROUTE_PROTOCOL_TCP
	}
	if pbProtocol == pb.RouteProtocol_ROUTE_PROTOCOL_UDP {
		protocol = "udp"
	}

	// Handle enable/disable toggle
	if req.Active != nil && !*req.Active {
		if s.passthroughStore != nil {
			if err := s.passthroughStore.SetActive(ctx, int(req.ExternalPort), protocol, false); err != nil {
				return nil, fmt.Errorf("failed to disable passthrough route: %w", err)
			}
		} else {
			// Fallback: directly remove from iptables
			if err := s.passthroughManager.RemoveRoute(int(req.ExternalPort), protocol); err != nil {
				return nil, fmt.Errorf("failed to disable passthrough route: %w", err)
			}
		}

		return &pb.UpdatePassthroughRouteResponse{
			Route: &pb.PassthroughRoute{
				ExternalPort:  req.ExternalPort,
				TargetIp:      req.TargetIp,
				TargetPort:    req.TargetPort,
				Protocol:      pbProtocol,
				Active:        false,
				ContainerName: req.ContainerName,
				Description:   req.Description,
			},
			Message: fmt.Sprintf("Passthrough route disabled: %s:%d (will sync to iptables)", protocol, req.ExternalPort),
		}, nil
	}

	// For enabling or updating, we need target info
	if req.TargetIp == "" {
		return nil, fmt.Errorf("target_ip is required")
	}
	if req.TargetPort <= 0 || req.TargetPort > 65535 {
		return nil, fmt.Errorf("target_port must be between 1 and 65535")
	}

	if s.passthroughStore != nil {
		record := &network.PassthroughRecord{
			ExternalPort:  int(req.ExternalPort),
			TargetIP:      req.TargetIp,
			TargetPort:    int(req.TargetPort),
			Protocol:      protocol,
			ContainerName: req.ContainerName,
			Description:   req.Description,
			Active:        true,
		}

		if err := s.passthroughStore.Save(ctx, record); err != nil {
			return nil, fmt.Errorf("failed to update passthrough route: %w", err)
		}
	} else {
		// Fallback: directly update iptables (legacy behavior)
		// Remove existing route first (ignore errors if it doesn't exist)
		s.passthroughManager.RemoveRoute(int(req.ExternalPort), protocol)

		if err := s.passthroughManager.AddRoute(int(req.ExternalPort), req.TargetIp, int(req.TargetPort), protocol); err != nil {
			return nil, fmt.Errorf("failed to update passthrough route: %w", err)
		}
	}

	return &pb.UpdatePassthroughRouteResponse{
		Route: &pb.PassthroughRoute{
			ExternalPort:  req.ExternalPort,
			TargetIp:      req.TargetIp,
			TargetPort:    req.TargetPort,
			Protocol:      pbProtocol,
			Active:        true,
			ContainerName: req.ContainerName,
			Description:   req.Description,
		},
		Message: fmt.Sprintf("Passthrough route updated: %s:%d -> %s:%d (will sync to iptables)", protocol, req.ExternalPort, req.TargetIp, req.TargetPort),
	}, nil
}

// ListDNSRecords returns available domains that have TLS certificates (from existing routes)
func (s *NetworkServer) ListDNSRecords(ctx context.Context, req *pb.ListDNSRecordsRequest) (*pb.ListDNSRecordsResponse, error) {
	var records []*pb.DNSRecord

	// Get existing routes from Caddy - these domains have TLS certificates
	if s.proxyManager != nil {
		routes, err := s.proxyManager.ListRoutes()
		if err == nil {
			for _, route := range routes {
				records = append(records, &pb.DNSRecord{
					Type: "A",
					Name: route.Subdomain,
					Data: route.FullDomain,
					Ttl:  600,
				})
			}
		}
	}

	return &pb.ListDNSRecordsResponse{
		Records:    records,
		BaseDomain: s.baseDomain,
		TotalCount: int32(len(records)),
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

// routeProtocolToProto converts app.RouteProtocol to pb.RouteProtocol
func routeProtocolToProto(protocol app.RouteProtocol) pb.RouteProtocol {
	switch protocol {
	case app.RouteProtocolGRPC:
		return pb.RouteProtocol_ROUTE_PROTOCOL_GRPC
	case app.RouteProtocolHTTP:
		return pb.RouteProtocol_ROUTE_PROTOCOL_HTTP
	default:
		return pb.RouteProtocol_ROUTE_PROTOCOL_HTTP
	}
}

// protoToRouteProtocol converts pb.RouteProtocol to app.RouteProtocol
func protoToRouteProtocol(protocol pb.RouteProtocol) app.RouteProtocol {
	switch protocol {
	case pb.RouteProtocol_ROUTE_PROTOCOL_GRPC:
		return app.RouteProtocolGRPC
	case pb.RouteProtocol_ROUTE_PROTOCOL_HTTP:
		return app.RouteProtocolHTTP
	default:
		return app.RouteProtocolHTTP
	}
}
