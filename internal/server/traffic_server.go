package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/internal/traffic"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TrafficServer implements the TrafficService gRPC service
type TrafficServer struct {
	pb.UnimplementedTrafficServiceServer
	collector *traffic.Collector
	eventBus  *events.Bus
	peerPool  *PeerPool
}

// NewTrafficServer creates a new traffic server
func NewTrafficServer(collector *traffic.Collector) *TrafficServer {
	return &TrafficServer{
		collector: collector,
		eventBus:  events.GetBus(),
	}
}

// SetPeerPool sets the peer pool for forwarding traffic queries to peers.
func (s *TrafficServer) SetPeerPool(pool *PeerPool) {
	s.peerPool = pool
}

// GetConnections returns active connections for a container.
// Phase 1.4 — tenant authz via the container_name → owner
// derivation (admins always pass; tenants only on their own
// container; system containers require admin).
func (s *TrafficServer) GetConnections(ctx context.Context, req *pb.GetConnectionsRequest) (*pb.GetConnectionsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrafficRead); err != nil {
		return nil, err
	}
	if req.ContainerName == "" {
		return nil, fmt.Errorf("container_name is required")
	}
	if err := auth.AuthorizeContainerAccess(ctx, req.ContainerName); err != nil {
		return nil, err
	}

	connections := s.collector.GetConnections(req.ContainerName)

	// Apply filters
	var filtered []*pb.Connection
	for _, conn := range connections {
		// Filter by protocol
		if req.Protocol != pb.Protocol_PROTOCOL_UNSPECIFIED && conn.Protocol != req.Protocol {
			continue
		}

		// Filter by destination IP prefix
		if req.DestIpPrefix != "" && !strings.HasPrefix(conn.DestIp, req.DestIpPrefix) {
			continue
		}

		// Filter by destination port
		if req.DestPort != 0 && conn.DestPort != req.DestPort {
			continue
		}

		filtered = append(filtered, conn)
	}

	// Apply limit
	limit := int(req.Limit)
	if limit == 0 {
		limit = 100
	}
	totalCount := len(filtered)
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	return &pb.GetConnectionsResponse{
		Connections: filtered,
		TotalCount:  safecast.I32(totalCount),
	}, nil
}

// GetConnectionSummary returns aggregate connection statistics.
// Phase 1.4 — tenant authz via container_name → owner.
func (s *TrafficServer) GetConnectionSummary(ctx context.Context, req *pb.GetConnectionSummaryRequest) (*pb.GetConnectionSummaryResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrafficRead); err != nil {
		return nil, err
	}
	if req.ContainerName == "" {
		return nil, fmt.Errorf("container_name is required")
	}
	if err := auth.AuthorizeContainerAccess(ctx, req.ContainerName); err != nil {
		return nil, err
	}

	summary := s.collector.GetConnectionSummary(req.ContainerName)

	return &pb.GetConnectionSummaryResponse{
		Summary: summary,
	}, nil
}

// SubscribeTraffic opens a streaming connection for real-time traffic events.
// Phase 1.4 — when ContainerName is set, tenant authz via the
// owner derivation; when blank, the stream would cover all
// containers, so require admin.
func (s *TrafficServer) SubscribeTraffic(req *pb.SubscribeTrafficRequest, stream pb.TrafficService_SubscribeTrafficServer) error {
	ctx := stream.Context()
	if err := auth.RequireScope(ctx, auth.ScopeTrafficRead); err != nil {
		return err
	}
	if req.ContainerName == "" {
		if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
			return err
		}
	} else {
		if err := auth.AuthorizeContainerAccess(ctx, req.ContainerName); err != nil {
			return err
		}
	}
	// Create filter for traffic events only
	filter := &pb.SubscribeEventsRequest{
		ResourceTypes: []pb.ResourceType{pb.ResourceType_RESOURCE_TYPE_TRAFFIC},
	}

	// Subscribe to events
	sub := s.eventBus.Subscribe(filter)
	defer s.eventBus.Unsubscribe(sub.ID)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-sub.Done:
			return nil
		case event := <-sub.Events:
			// Extract traffic event from generic event
			trafficEvent := event.GetTrafficEvent()
			if trafficEvent == nil {
				continue
			}

			// Apply container filter
			if req.ContainerName != "" {
				if trafficEvent.Connection == nil || trafficEvent.Connection.ContainerName != req.ContainerName {
					continue
				}
			}

			// Apply event type filter
			if len(req.EventTypes) > 0 {
				found := false
				for _, et := range req.EventTypes {
					if et == trafficEvent.Type {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			// Apply external only filter.
			// TODO: when req.ExternalOnly is set, skip events whose destination
			// is also a container IP. This requires consulting the IP cache and
			// is not yet implemented.

			if err := stream.Send(trafficEvent); err != nil {
				return err
			}
		}
	}
}

// maxHostWideHistoryWindow bounds a host-wide history query so one call cannot
// scan the whole retention period of every box.
const maxHostWideHistoryWindow = 7 * 24 * time.Hour

// historyQueryParams validates a history request and builds the store query.
// Both window ends are inclusive. An unset end_time means now (it used to be
// read as the Unix epoch, which matched nothing). A host-wide query (no
// container_name) must carry an explicit start_time and stay within
// maxHostWideHistoryWindow.
func historyQueryParams(req *pb.QueryTrafficHistoryRequest, now time.Time) (traffic.QueryParams, error) {
	end := now
	if req.EndTime != nil {
		end = req.EndTime.AsTime()
	}
	var start time.Time
	if req.StartTime != nil {
		start = req.StartTime.AsTime()
	}
	if req.ContainerName == "" {
		if req.StartTime == nil {
			return traffic.QueryParams{}, status.Error(codes.InvalidArgument,
				"start_time is required when container_name is empty (host-wide query)")
		}
		if end.Sub(start) > maxHostWideHistoryWindow {
			return traffic.QueryParams{}, status.Errorf(codes.InvalidArgument,
				"host-wide window is limited to %s; narrow start_time/end_time", maxHostWideHistoryWindow)
		}
	}
	if end.Before(start) {
		return traffic.QueryParams{}, status.Error(codes.InvalidArgument, "end_time is before start_time")
	}
	return traffic.QueryParams{
		ContainerName: req.ContainerName,
		StartTime:     start,
		EndTime:       end,
		DestIP:        req.DestIp,
		DestPort:      int(req.DestPort),
		Offset:        int(req.Offset),
		Limit:         int(req.Limit),
	}, nil
}

// QueryTrafficHistory queries persisted traffic data.
// Phase 1.4 — tenant authz via container_name → owner. With no container_name
// the query spans every box (#2884), which discloses other tenants' history, so
// it requires the admin role (the same rule as SubscribeTraffic).
func (s *TrafficServer) QueryTrafficHistory(ctx context.Context, req *pb.QueryTrafficHistoryRequest) (*pb.QueryTrafficHistoryResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrafficRead); err != nil {
		return nil, err
	}
	if req.ContainerName == "" {
		if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
			return nil, err
		}
	} else if err := auth.AuthorizeContainerAccess(ctx, req.ContainerName); err != nil {
		return nil, err
	}

	var store *traffic.Store
	if s.collector != nil {
		store = s.collector.GetStore()
	}
	if store == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"traffic history is not being persisted on this host (collector or database not enabled); an empty result would be misleading")
	}

	params, err := historyQueryParams(req, time.Now())
	if err != nil {
		return nil, err
	}
	connections, totalCount, err := store.QueryConnections(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query traffic history: %w", err)
	}
	oldest, err := store.OldestRecord(ctx, req.ContainerName)
	if err != nil {
		return nil, err
	}

	resp := &pb.QueryTrafficHistoryResponse{
		Connections: connections,
		TotalCount:  totalCount,
	}
	if oldest != nil {
		resp.OldestRecordTime = timestamppb.New(*oldest)
	}
	return resp, nil
}

// GetTrafficAggregates returns time-series traffic aggregates.
// Phase 1.4 — tenant authz via container_name → owner.
func (s *TrafficServer) GetTrafficAggregates(ctx context.Context, req *pb.GetTrafficAggregatesRequest) (*pb.GetTrafficAggregatesResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrafficRead); err != nil {
		return nil, err
	}
	if req.ContainerName == "" {
		return nil, fmt.Errorf("container_name is required")
	}
	if err := auth.AuthorizeContainerAccess(ctx, req.ContainerName); err != nil {
		return nil, err
	}

	store := s.collector.GetStore()
	if store == nil {
		return nil, fmt.Errorf("traffic persistence not available")
	}

	params := traffic.AggregateParams{
		ContainerName:   req.ContainerName,
		StartTime:       req.StartTime.AsTime(),
		EndTime:         req.EndTime.AsTime(),
		Interval:        req.Interval,
		GroupByDestIP:   req.GroupByDestIp,
		GroupByDestPort: req.GroupByDestPort,
	}

	aggregates, err := store.GetAggregates(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get traffic aggregates: %w", err)
	}

	return &pb.GetTrafficAggregatesResponse{
		Aggregates: aggregates,
	}, nil
}
