package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/traffic"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TrafficServer implements the TrafficService gRPC service
type TrafficServer struct {
	pb.UnimplementedTrafficServiceServer
	collector *traffic.Collector
	eventBus  *events.Bus
}

// NewTrafficServer creates a new traffic server
func NewTrafficServer(collector *traffic.Collector) *TrafficServer {
	return &TrafficServer{
		collector: collector,
		eventBus:  events.GetBus(),
	}
}

// GetConnections returns active connections for a container
func (s *TrafficServer) GetConnections(ctx context.Context, req *pb.GetConnectionsRequest) (*pb.GetConnectionsResponse, error) {
	if req.ContainerName == "" {
		return nil, fmt.Errorf("container_name is required")
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
		TotalCount:  int32(totalCount),
	}, nil
}

// GetConnectionSummary returns aggregate connection statistics
func (s *TrafficServer) GetConnectionSummary(ctx context.Context, req *pb.GetConnectionSummaryRequest) (*pb.GetConnectionSummaryResponse, error) {
	if req.ContainerName == "" {
		return nil, fmt.Errorf("container_name is required")
	}

	summary := s.collector.GetConnectionSummary(req.ContainerName)

	return &pb.GetConnectionSummaryResponse{
		Summary: summary,
	}, nil
}

// SubscribeTraffic opens a streaming connection for real-time traffic events
func (s *TrafficServer) SubscribeTraffic(req *pb.SubscribeTrafficRequest, stream pb.TrafficService_SubscribeTrafficServer) error {
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

			// Apply external only filter
			if req.ExternalOnly && trafficEvent.Connection != nil {
				// Skip if destination is also a container IP
				// This would require checking the cache, simplified for now
			}

			if err := stream.Send(trafficEvent); err != nil {
				return err
			}
		}
	}
}

// QueryTrafficHistory queries persisted traffic data
func (s *TrafficServer) QueryTrafficHistory(ctx context.Context, req *pb.QueryTrafficHistoryRequest) (*pb.QueryTrafficHistoryResponse, error) {
	if req.ContainerName == "" {
		return nil, fmt.Errorf("container_name is required")
	}

	store := s.collector.GetStore()
	if store == nil {
		return nil, fmt.Errorf("traffic persistence not available")
	}

	params := traffic.QueryParams{
		ContainerName: req.ContainerName,
		StartTime:     req.StartTime.AsTime(),
		EndTime:       req.EndTime.AsTime(),
		DestIP:        req.DestIp,
		DestPort:      int(req.DestPort),
		Offset:        int(req.Offset),
		Limit:         int(req.Limit),
	}

	connections, totalCount, err := store.QueryConnections(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query traffic history: %w", err)
	}

	return &pb.QueryTrafficHistoryResponse{
		Connections: connections,
		TotalCount:  totalCount,
	}, nil
}

// GetTrafficAggregates returns time-series traffic aggregates
func (s *TrafficServer) GetTrafficAggregates(ctx context.Context, req *pb.GetTrafficAggregatesRequest) (*pb.GetTrafficAggregatesResponse, error) {
	if req.ContainerName == "" {
		return nil, fmt.Errorf("container_name is required")
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
