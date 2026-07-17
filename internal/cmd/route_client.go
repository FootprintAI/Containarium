package cmd

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/expose"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// routeAPI is the subset of client methods the route / expose-port verbs need.
// Both *client.GRPCClient and *client.HTTPClient satisfy it, so those verbs can
// honor --http the same way list / create / connect / … already do — instead
// of hardcoding gRPC and failing with an opaque name-resolver error against an
// https:// server. See #909.
type routeAPI interface {
	AddRoute(domain, targetIP string, targetPort int32, containerName, description string) (*pb.ProxyRoute, error)
	ListRoutes(username string, activeOnly bool) ([]*pb.ProxyRoute, int32, error)
	DeleteRoute(domain string) error
	ListContainers() ([]incus.ContainerInfo, error)
	Close() error
}

// newRouteClient returns an HTTP client in --http mode (when a --server is set)
// and a gRPC client otherwise, mirroring how the other verbs pick their
// transport. Caller must Close() the result.
func newRouteClient() (routeAPI, error) {
	if httpMode && serverAddr != "" {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

// exposeAdapter implements expose.APIClient over either transport. LookupContainer
// is a ListContainers + linear scan (the surface has no by-name lookup); this is
// fine at the typical scale and matches the previous gRPC-only adapter.
type exposeAdapter struct{ c routeAPI }

func (a *exposeAdapter) LookupContainer(_ context.Context, username string) (string, string, string, error) {
	containers, err := a.c.ListContainers()
	if err != nil {
		return "", "", "", err
	}
	for _, ci := range containers {
		// Names follow the "<username>-container" convention; accept either
		// the full name or the bare username.
		if ci.Name == username || ci.Name == username+"-container" {
			return ci.Name, ci.IPAddress, ci.State, nil
		}
	}
	return "", "", "", fmt.Errorf("container %q not found", username)
}

func (a *exposeAdapter) CreateRoute(_ context.Context, p expose.AddRouteParams) (*expose.RouteResult, error) {
	route, err := a.c.AddRoute(p.Domain, p.TargetIP, p.TargetPort, p.ContainerName, p.Description)
	if err != nil {
		return nil, err
	}
	// The ProxyRoute response carries FullDomain, not the request's Domain /
	// ContainerName; fall back to what the caller asked for.
	domain := route.GetFullDomain()
	if domain == "" {
		domain = p.Domain
	}
	return &expose.RouteResult{
		Domain:        domain,
		ContainerName: p.ContainerName,
		ContainerIP:   route.GetContainerIp(),
		Port:          route.GetPort(),
	}, nil
}
