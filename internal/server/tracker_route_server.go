package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Scope routes (#2021): which skill a `scope:<role>` label starts on a
// tracker connection. Gated by tracker:admin like connection CRUD — a
// run's tracker:read/write token can never repoint what a label runs.
// See docs/architecture/issue-triggered-agents.md.

// trackerRouteAuditDetail is the audit payload for a route write.
type trackerRouteAuditDetail struct {
	Scope   string `json:"scope"`
	SkillID string `json:"skill_id,omitempty"`
}

// requireTrackerRouteAccess is the shared preamble: scope, store, tenant.
func (s *ContainerServer) requireTrackerRouteAccess(ctx context.Context, username, connection string) error {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerAdmin); err != nil {
		return err
	}
	if s.trackerStore == nil {
		return status.Error(codes.Unavailable, "tracker store not configured on this daemon")
	}
	if username == "" {
		return status.Error(codes.InvalidArgument, "username is required")
	}
	if connection == "" {
		return status.Error(codes.InvalidArgument, "connection is required")
	}
	return auth.AuthorizeTenant(ctx, username)
}

// SetTrackerRoute creates or updates the route for one scope label.
func (s *ContainerServer) SetTrackerRoute(ctx context.Context, req *pb.SetTrackerRouteRequest) (*pb.SetTrackerRouteResponse, error) {
	if err := s.requireTrackerRouteAccess(ctx, req.Username, req.Connection); err != nil {
		return nil, err
	}
	if err := tracker.ValidateRouteScope(req.Scope); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if req.SkillId == "" {
		return nil, status.Error(codes.InvalidArgument, "skill_id is required")
	}

	route, err := s.trackerStore.SetRoute(ctx, tracker.Route{
		Username: req.Username, Connection: req.Connection, Scope: req.Scope, SkillID: req.SkillId,
	})
	if err != nil {
		return nil, mapTrackerRouteError(err)
	}

	msg, action := "route created", "tracker.route_created"
	if !route.CreatedAt.Equal(route.UpdatedAt) {
		msg, action = "route updated", "tracker.route_updated"
	}
	log.Printf("[tracker] route set %s/%s scope=%s skill=%s", req.Username, req.Connection, req.Scope, req.SkillId)
	s.auditTrackerRouteWrite(ctx, action, req.Username, req.Connection, trackerRouteAuditDetail{Scope: req.Scope, SkillID: req.SkillId})
	return &pb.SetTrackerRouteResponse{Message: msg, Route: toProtoTrackerRoute(route)}, nil
}

// ListTrackerRoutes returns a connection's routes, ordered by scope.
func (s *ContainerServer) ListTrackerRoutes(ctx context.Context, req *pb.ListTrackerRoutesRequest) (*pb.ListTrackerRoutesResponse, error) {
	if err := s.requireTrackerRouteAccess(ctx, req.Username, req.Connection); err != nil {
		return nil, err
	}
	routes, err := s.trackerStore.ListRoutes(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, mapTrackerRouteError(err)
	}
	out := make([]*pb.TrackerRoute, 0, len(routes))
	for i := range routes {
		out = append(out, toProtoTrackerRoute(&routes[i]))
	}
	return &pb.ListTrackerRoutesResponse{Routes: out}, nil
}

// DeleteTrackerRoute removes one route.
func (s *ContainerServer) DeleteTrackerRoute(ctx context.Context, req *pb.DeleteTrackerRouteRequest) (*pb.DeleteTrackerRouteResponse, error) {
	if err := s.requireTrackerRouteAccess(ctx, req.Username, req.Connection); err != nil {
		return nil, err
	}
	if req.Scope == "" {
		return nil, status.Error(codes.InvalidArgument, "scope is required")
	}
	if err := s.trackerStore.DeleteRoute(ctx, req.Username, req.Connection, req.Scope); err != nil {
		return nil, mapTrackerRouteError(err)
	}
	log.Printf("[tracker] route deleted %s/%s scope=%s", req.Username, req.Connection, req.Scope)
	s.auditTrackerRouteWrite(ctx, "tracker.route_deleted", req.Username, req.Connection, trackerRouteAuditDetail{Scope: req.Scope})
	return &pb.DeleteTrackerRouteResponse{Message: fmt.Sprintf("route %s deleted", req.Scope)}, nil
}

// mapTrackerRouteError maps route-store errors to gRPC codes. A missing
// connection (FK) and a missing route are both NotFound, with distinct
// messages.
func mapTrackerRouteError(err error) error {
	switch {
	case errors.Is(err, tracker.ErrRouteNotFound):
		return status.Error(codes.NotFound, "tracker route not found")
	case errors.Is(err, tracker.ErrNotFound):
		return status.Error(codes.NotFound, "tracker connection not found")
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

// auditTrackerRouteWrite records a route write. Best-effort, same
// convention as auditTrackerConnectionWrite.
func (s *ContainerServer) auditTrackerRouteWrite(ctx context.Context, action, username, connection string, detail trackerRouteAuditDetail) {
	if s.auditStore == nil {
		return
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		log.Printf("[tracker] marshal route audit detail for %s: %v", action, err)
		return
	}
	if err := s.auditStore.Log(ctx, &audit.AuditEntry{
		Username:     username,
		Action:       action,
		ResourceType: "tracker_route",
		ResourceID:   fmt.Sprintf("%s/%s/%s", username, connection, detail.Scope),
		Detail:       string(payload),
	}); err != nil {
		log.Printf("[tracker] audit %s %s/%s: %v", action, username, connection, err)
	}
}

func toProtoTrackerRoute(r *tracker.Route) *pb.TrackerRoute {
	if r == nil {
		return nil
	}
	return &pb.TrackerRoute{
		Username:   r.Username,
		Connection: r.Connection,
		Scope:      r.Scope,
		SkillId:    r.SkillID,
	}
}
