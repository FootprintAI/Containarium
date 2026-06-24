package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/egressproxy"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/network"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NetworkServer implements the NetworkService gRPC service
type NetworkServer struct {
	pb.UnimplementedNetworkServiceServer
	incusClient        *incus.Client
	proxyManager       *app.ProxyManager
	passthroughManager *network.PassthroughManager
	appStore           app.AppStore
	routeStore         *app.RouteStore          // Source of truth for routes (PostgreSQL)
	passthroughStore   network.PassthroughStore // Source of truth for passthrough routes (PostgreSQL)
	containerNetwork   string                   // e.g., "10.100.0.0/24"
	proxyIP            string                   // e.g., "10.100.0.1"
	baseDomain         string                   // e.g., "example.com"
	emitter            *events.Emitter
	egressMgr          *egressproxy.Manager // egress-via-client relays, keyed by box (#808)
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
		egressMgr:          egressproxy.NewManager(),
	}
}

// GetRoutes lists all proxy routes from PostgreSQL (source of truth)
func (s *NetworkServer) GetRoutes(ctx context.Context, req *pb.GetRoutesRequest) (*pb.GetRoutesResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeRoutesRead); err != nil {
		return nil, err
	}
	// Tenant isolation: non-admin → routes for your apps only.
	subject, roles, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	if !auth.HasRole(roles, auth.RoleAdmin) {
		if req.Username != "" && req.Username != subject {
			return nil, status.Error(codes.PermissionDenied, "not authorized for this tenant")
		}
		req.Username = subject
	}
	// If RouteStore is available, use it as source of truth
	if s.routeStore != nil {
		routes, err := s.routeStore.List(ctx, false) // include disabled routes so UI can show toggle state
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
			// Hide system routes (e.g. management UI) from user-facing listings
			if route.CreatedBy == string(app.RouteCreatorSystem) {
				continue
			}

			// Lookup container name by IP
			containerName := route.ContainerName
			if containerName == "" {
				containerName = ipToContainer[route.TargetIP]
			}

			protocol := pb.RouteProtocol_ROUTE_PROTOCOL_HTTP
			switch route.Protocol {
			case "grpc":
				protocol = pb.RouteProtocol_ROUTE_PROTOCOL_GRPC
			case "tls_passthrough":
				protocol = pb.RouteProtocol_ROUTE_PROTOCOL_TLS_PASSTHROUGH
			}

			pbRoute := &pb.ProxyRoute{
				Subdomain:     route.Subdomain,
				FullDomain:    route.FullDomain,
				ContainerIp:   route.TargetIP,
				Port:          int32(route.TargetPort), // #nosec G115 -- TCP port, always in [0,65535]
				Active:        route.Active,
				Protocol:      protocol,
				AppName:       containerName,
				ContainerName: containerName,
			}
			pbRoutes = append(pbRoutes, pbRoute)
		}

		return &pb.GetRoutesResponse{
			Routes:     pbRoutes,
			TotalCount: safecast.I32(len(pbRoutes)),
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
			Subdomain:     route.Subdomain,
			FullDomain:    route.FullDomain,
			ContainerIp:   route.UpstreamIP,
			Port:          int32(route.UpstreamPort), // #nosec G115 -- TCP port, always in [0,65535]
			Active:        true,                      // If it's in the list, it's active
			Protocol:      routeProtocolToProto(route.Protocol),
			AppName:       containerName, // legacy: container name doubled as app name for display
			ContainerName: containerName,
		}
		pbRoutes = append(pbRoutes, pbRoute)
	}

	return &pb.GetRoutesResponse{
		Routes:     pbRoutes,
		TotalCount: safecast.I32(len(pbRoutes)),
	}, nil
}

// AddRoute adds a new proxy route (saves to PostgreSQL, sync job updates Caddy).
// Admin-only — routes can point at any container IP and steal traffic
// addressed to other tenants.
func (s *NetworkServer) AddRoute(ctx context.Context, req *pb.AddRouteRequest) (*pb.AddRouteResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeRoutesWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
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
	switch req.Protocol {
	case pb.RouteProtocol_ROUTE_PROTOCOL_GRPC:
		protocol = "grpc"
	case pb.RouteProtocol_ROUTE_PROTOCOL_TLS_PASSTHROUGH:
		protocol = "tls_passthrough"
	}

	// Auto-detect container name from target IP if not provided
	containerName := req.ContainerName
	if containerName == "" && s.incusClient != nil {
		containers, err := s.incusClient.ListContainers()
		if err == nil {
			for _, c := range containers {
				if c.IPAddress == req.TargetIp {
					containerName = c.Name
					break
				}
			}
		}
	}

	// If RouteStore is available, save to PostgreSQL (source of truth)
	if s.routeStore != nil {
		routeRecord := &app.RouteRecord{
			Subdomain:     subdomain,
			FullDomain:    fullDomain,
			TargetIP:      req.TargetIp,
			TargetPort:    int(req.TargetPort),
			Protocol:      protocol,
			ContainerName: containerName,
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
		AppName:     containerName,
	}

	// Emit route added event
	s.emitter.EmitRouteAdded(route)

	return &pb.AddRouteResponse{
		Route:   route,
		Message: fmt.Sprintf("Route added: %s -> %s:%d (will sync to Caddy)", fullDomain, req.TargetIp, req.TargetPort),
	}, nil
}

// UpdateRoute updates an existing proxy route (updates PostgreSQL, sync job updates Caddy).
// Admin-only — same blast radius as AddRoute.
func (s *NetworkServer) UpdateRoute(ctx context.Context, req *pb.UpdateRouteRequest) (*pb.UpdateRouteResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeRoutesWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	// Validate request
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	// Determine full domain
	subdomain := req.Domain
	fullDomain := resolveFullDomain(req.Domain, s.baseDomain)

	// Determine protocol
	protocol := "http"
	switch req.Protocol {
	case pb.RouteProtocol_ROUTE_PROTOCOL_GRPC:
		protocol = "grpc"
	case pb.RouteProtocol_ROUTE_PROTOCOL_TLS_PASSTHROUGH:
		protocol = "tls_passthrough"
	}

	// Handle enable/disable toggle
	if req.Active != nil {
		active := *req.Active

		if s.routeStore != nil {
			if err := s.routeStore.SetActive(ctx, fullDomain, active); err != nil {
				// Try with original domain
				if err := s.routeStore.SetActive(ctx, req.Domain, active); err != nil {
					if active {
						return nil, fmt.Errorf("failed to enable route: %w", err)
					}
					return nil, fmt.Errorf("failed to disable route: %w", err)
				}
			}
		} else if s.proxyManager != nil && !active {
			// Fallback: directly remove from Caddy (disable only)
			if err := s.proxyManager.RemoveRoute(req.Domain); err != nil {
				return nil, fmt.Errorf("failed to disable route: %w", err)
			}
		}

		// If this is a pure toggle (no target info provided), return early
		if req.TargetIp == "" && req.TargetPort == 0 {
			action := "enabled"
			if !active {
				action = "disabled"
			}
			return &pb.UpdateRouteResponse{
				Route: &pb.ProxyRoute{
					Subdomain:  subdomain,
					FullDomain: fullDomain,
					Active:     active,
					Protocol:   req.Protocol,
				},
				Message: fmt.Sprintf("Route %s: %s (will sync to Caddy)", action, req.Domain),
			}, nil
		}
	}

	// For updates with new target info, we need target fields
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

// DeleteRoute removes a proxy route (deletes from PostgreSQL, sync job updates Caddy).
// Admin-only — denial-of-service vector if a tenant could remove
// another tenant's route.
func (s *NetworkServer) DeleteRoute(ctx context.Context, req *pb.DeleteRouteRequest) (*pb.DeleteRouteResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeRoutesWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
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

// ListPassthroughRoutes lists all TCP/UDP passthrough routes.
// Admin-only — passthrough routes are cluster-wide infrastructure.
func (s *NetworkServer) ListPassthroughRoutes(ctx context.Context, req *pb.ListPassthroughRoutesRequest) (*pb.ListPassthroughRoutesResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
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

	// If PassthroughStore is available, use it as source of truth
	if s.passthroughStore != nil {
		records, err := s.passthroughStore.List(ctx, false) // include disabled routes so UI can show toggle state
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
				ExternalPort:  safecast.I32(rec.ExternalPort),
				TargetIp:      rec.TargetIP,
				TargetPort:    safecast.I32(rec.TargetPort),
				Protocol:      protocol,
				Active:        rec.Active,
				ContainerName: containerName,
				Description:   rec.Description,
			})
		}

		return &pb.ListPassthroughRoutesResponse{
			Routes:     pbRoutes,
			TotalCount: safecast.I32(len(pbRoutes)),
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
			ExternalPort:  safecast.I32(route.ExternalPort),
			TargetIp:      route.TargetIP,
			TargetPort:    safecast.I32(route.TargetPort),
			Protocol:      protocol,
			Active:        route.Active,
			ContainerName: containerName,
			Description:   route.Description,
		})
	}

	return &pb.ListPassthroughRoutesResponse{
		Routes:     pbRoutes,
		TotalCount: safecast.I32(len(pbRoutes)),
	}, nil
}

// AddPassthroughRoute adds a new TCP/UDP passthrough route.
// Admin-only — passthrough binds a host-wide port (iptables/nftables),
// outside any tenant's scope.
func (s *NetworkServer) AddPassthroughRoute(ctx context.Context, req *pb.AddPassthroughRouteRequest) (*pb.AddPassthroughRouteResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
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

// DeletePassthroughRoute removes a TCP/UDP passthrough route.
// Admin-only.
func (s *NetworkServer) DeletePassthroughRoute(ctx context.Context, req *pb.DeletePassthroughRouteRequest) (*pb.DeletePassthroughRouteResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
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

// UpdatePassthroughRoute updates an existing TCP/UDP passthrough route.
// Admin-only.
func (s *NetworkServer) UpdatePassthroughRoute(ctx context.Context, req *pb.UpdatePassthroughRouteRequest) (*pb.UpdatePassthroughRouteResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
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
	if req.Active != nil {
		active := *req.Active

		if s.passthroughStore != nil {
			if err := s.passthroughStore.SetActive(ctx, int(req.ExternalPort), protocol, active); err != nil {
				if active {
					return nil, fmt.Errorf("failed to enable passthrough route: %w", err)
				}
				return nil, fmt.Errorf("failed to disable passthrough route: %w", err)
			}
		} else if !active {
			// Fallback: directly remove from iptables (disable only)
			if err := s.passthroughManager.RemoveRoute(int(req.ExternalPort), protocol); err != nil {
				return nil, fmt.Errorf("failed to disable passthrough route: %w", err)
			}
		}

		// If this is a pure toggle (no target info provided), return early
		if req.TargetIp == "" && req.TargetPort == 0 {
			action := "enabled"
			if !active {
				action = "disabled"
			}
			return &pb.UpdatePassthroughRouteResponse{
				Route: &pb.PassthroughRoute{
					ExternalPort:  req.ExternalPort,
					Protocol:      pbProtocol,
					Active:        active,
					ContainerName: req.ContainerName,
					Description:   req.Description,
				},
				Message: fmt.Sprintf("Passthrough route %s: %s:%d (will sync to iptables)", action, protocol, req.ExternalPort),
			}, nil
		}
	}

	// For updates with new target info, we need target fields
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
		_ = s.passthroughManager.RemoveRoute(int(req.ExternalPort), protocol)

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

// ListDNSRecords returns available domains that have TLS certificates
// (from existing routes). Admin-only — the full list of domains
// across all tenants is operator-scope.
func (s *NetworkServer) ListDNSRecords(ctx context.Context, req *pb.ListDNSRecordsRequest) (*pb.ListDNSRecordsResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
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
		TotalCount: safecast.I32(len(records)),
	}, nil
}

// GetContainerACL gets firewall rules for a DevBox container
func (s *NetworkServer) GetContainerACL(ctx context.Context, req *pb.GetContainerACLRequest) (*pb.GetContainerACLResponse, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}
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
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}
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

// GetNetworkTopology returns network visualization data.
// Admin-only — the full topology lists every tenant container.
func (s *NetworkServer) GetNetworkTopology(ctx context.Context, req *pb.GetNetworkTopologyRequest) (*pb.GetNetworkTopologyResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
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
	case app.RouteProtocolTLSPassthrough:
		return pb.RouteProtocol_ROUTE_PROTOCOL_TLS_PASSTHROUGH
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
	case pb.RouteProtocol_ROUTE_PROTOCOL_TLS_PASSTHROUGH:
		return app.RouteProtocolTLSPassthrough
	default:
		return app.RouteProtocolHTTP
	}
}

// StartEgressProxy bridges a host-loopback SOCKS (which the caller exposes via
// `ssh -R 127.0.0.1:<upstream_port>:localhost:<their-socks>`) into a box's
// network namespace, so the box egresses with the operator's IP — the
// "egress via client" feature (#808). The daemon runs a source-restricted relay
// on the bridge gateway that ONLY the target box's IP may use, forwarding to
// the host-loopback SOCKS the caller opened. The box points its apps at the
// returned socks_address.
func (s *NetworkServer) StartEgressProxy(ctx context.Context, req *pb.StartEgressProxyRequest) (*pb.StartEgressProxyResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeRoutesWrite); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.GetContainerName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "container_name is required")
	}
	if req.GetUpstreamPort() <= 0 || req.GetUpstreamPort() > 65535 {
		return nil, status.Error(codes.InvalidArgument, "upstream_port must be 1-65535 (the host-loopback port from your `ssh -R`)")
	}
	// Resolve the bridge gateway the box reaches the daemon on. proxyIP is only
	// populated on the app-hosting path; otherwise derive it from the container
	// network CIDR (the gateway is its first host address, e.g. 10.100.0.0/24 ->
	// 10.100.0.1) so egress works on every daemon, not just app-hosting ones.
	gatewayIP := s.proxyIP
	if gatewayIP == "" {
		gatewayIP = bridgeGatewayIP(s.containerNetwork)
	}
	if gatewayIP == "" {
		return nil, status.Error(codes.FailedPrecondition, "could not determine the daemon bridge gateway IP")
	}
	if s.incusClient == nil {
		return nil, status.Error(codes.Unavailable, "container backend unavailable")
	}
	info, err := s.incusClient.GetContainer(name)
	if err != nil || info == nil {
		return nil, status.Errorf(codes.NotFound, "container %q not found", name)
	}
	if info.IPAddress == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "container %q has no IP yet (is it running?)", name)
	}
	if s.egressMgr == nil {
		s.egressMgr = egressproxy.NewManager()
	}

	// listen on the bridge gateway (box-reachable); proxy_port 0 => free port.
	listen := net.JoinHostPort(gatewayIP, strconv.Itoa(int(req.GetProxyPort())))
	// upstream is the host-loopback listener the caller opened via ssh -R.
	upstream := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(req.GetUpstreamPort())))

	// allow ONLY the target box's IP — the multi-tenant boundary so a sibling
	// box on the same bridge can't use this operator's egress channel.
	addr, err := s.egressMgr.Start(name, listen, upstream, []string{info.IPAddress}, log.Printf)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "start egress relay: %v", err)
	}
	log.Printf("[egress-via-client] box %s (%s) -> relay %s -> host-loopback:%d", name, info.IPAddress, addr, req.GetUpstreamPort())
	return &pb.StartEgressProxyResponse{SocksAddress: addr}, nil
}

// StopEgressProxy tears down the egress-via-client relay for a box.
func (s *NetworkServer) StopEgressProxy(ctx context.Context, req *pb.StopEgressProxyRequest) (*pb.StopEgressProxyResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeRoutesWrite); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.GetContainerName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "container_name is required")
	}
	stopped := false
	if s.egressMgr != nil {
		stopped = s.egressMgr.Stop(name)
	}
	return &pb.StopEgressProxyResponse{Stopped: stopped}, nil
}

// bridgeGatewayIP returns the gateway (first host) address of a container
// network CIDR — e.g. "10.100.0.0/24" -> "10.100.0.1" — which is the address a
// box reaches the daemon on (the incus bridge gateway). Returns "" on a CIDR
// it can't parse or a non-IPv4 network.
func bridgeGatewayIP(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return ""
	}
	gw := make(net.IP, len(ip))
	copy(gw, ip)
	gw[3]++ // network address + 1 = the bridge gateway
	return gw.String()
}
