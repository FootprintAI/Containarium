package traffic

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/network"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// CollectorConfig holds configuration for the traffic collector
type CollectorConfig struct {
	// NetworkCIDR is the container network CIDR (e.g., "10.100.0.0/24")
	NetworkCIDR string

	// SnapshotInterval is how often to take a full conntrack snapshot
	SnapshotInterval time.Duration

	// CleanupInterval is how often to run database cleanup
	CleanupInterval time.Duration

	// RetentionDays is how many days to keep traffic data
	RetentionDays int

	// PostgresConnString is the database connection string
	PostgresConnString string
}

// DefaultCollectorConfig returns a default configuration
func DefaultCollectorConfig() CollectorConfig {
	return CollectorConfig{
		NetworkCIDR:      "10.100.0.0/24",
		SnapshotInterval: 5 * time.Minute,
		CleanupInterval:  24 * time.Hour,
		RetentionDays:    7,
	}
}

// Collector coordinates traffic monitoring
type Collector struct {
	config      CollectorConfig
	incusClient *incus.Client
	store       *Store
	cache       *ContainerCache
	monitor     ConntrackMonitor
	emitter     *events.Emitter

	mu          sync.RWMutex
	connections map[string]*pb.Connection // conntrack ID -> connection

	ctx    context.Context
	cancel context.CancelFunc
}

// NewCollector creates a new traffic collector
func NewCollector(config CollectorConfig, incusClient *incus.Client, store *Store, emitter *events.Emitter) (*Collector, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize cache
	cache := NewContainerCache(incusClient, config.NetworkCIDR)

	// Initialize conntrack monitor
	monitor, err := NewConntrackMonitor()
	if err != nil {
		cancel()
		// Don't fail if conntrack is not available (e.g., on macOS)
		log.Printf("Warning: conntrack monitoring unavailable: %v", err)
		monitor = nil
	}

	return &Collector{
		config:      config,
		incusClient: incusClient,
		store:       store,
		cache:       cache,
		monitor:     monitor,
		emitter:     emitter,
		connections: make(map[string]*pb.Connection),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// Start begins traffic collection
func (c *Collector) Start() error {
	log.Printf("Starting traffic collector for network %s", c.config.NetworkCIDR)

	// Enable conntrack accounting for byte counters (Linux only)
	if c.monitor != nil {
		if err := network.EnableConntrackAccounting(); err != nil {
			log.Printf("Warning: failed to enable conntrack accounting: %v", err)
		}
	}

	// Start container cache refresh
	go c.cache.StartRefresh(c.ctx, 30*time.Second)

	// Start conntrack event monitoring (if available)
	if c.monitor != nil {
		go c.handleConntrackEvents()
	}

	// Start periodic snapshot
	go c.periodicSnapshot()

	// Start periodic cleanup
	if c.store != nil {
		go c.periodicCleanup()
	}

	return nil
}

// handleConntrackEvents processes real-time conntrack events
func (c *Collector) handleConntrackEvents() {
	eventCh := c.monitor.Events()

	for {
		select {
		case <-c.ctx.Done():
			return
		case event, ok := <-eventCh:
			if !ok {
				return
			}
			c.processConntrackEvent(event)
		}
	}
}

// processConntrackEvent handles a single conntrack event
func (c *Collector) processConntrackEvent(event *ConntrackEvent) {
	// Determine which container this connection belongs to
	containerName := ""
	containerIP := ""
	direction := pb.TrafficDirection_TRAFFIC_DIRECTION_UNSPECIFIED

	// Check source IP first (egress from container)
	if name := c.cache.LookupIP(event.SrcIP); name != "" {
		containerName = name
		containerIP = event.SrcIP
		direction = pb.TrafficDirection_TRAFFIC_DIRECTION_EGRESS
	} else if name := c.cache.LookupIP(event.DstIP); name != "" {
		// Check destination IP (ingress to container)
		containerName = name
		containerIP = event.DstIP
		direction = pb.TrafficDirection_TRAFFIC_DIRECTION_INGRESS
	}

	// Skip if not a container connection
	if containerName == "" {
		return
	}

	// Convert to proto connection
	conn := c.convertToProto(event, containerName, containerIP, direction)

	// Update local cache
	c.mu.Lock()
	if event.Type == ConntrackEventDestroy {
		delete(c.connections, event.ID)
	} else {
		c.connections[event.ID] = conn
	}
	c.mu.Unlock()

	// Emit traffic event
	c.emitTrafficEvent(event.Type, conn)

	// Persist to database on connection close
	if event.Type == ConntrackEventDestroy && c.store != nil {
		go func() {
			if err := c.store.SaveConnection(c.ctx, conn); err != nil {
				log.Printf("Warning: failed to persist connection: %v", err)
			}
		}()
	}
}

// convertToProto converts a ConntrackEvent to a pb.Connection
func (c *Collector) convertToProto(event *ConntrackEvent, containerName, containerIP string, direction pb.TrafficDirection) *pb.Connection {
	conn := &pb.Connection{
		Id:            event.ID,
		ContainerName: containerName,
		ContainerIp:   containerIP,
		Protocol:      protoStringToEnum(event.Protocol),
		SourceIp:      event.SrcIP,
		SourcePort:    uint32(event.SrcPort),
		DestIp:        event.DstIP,
		DestPort:      uint32(event.DstPort),
		State:         stateStringToEnum(event.State),
		Direction:     direction,
		FirstSeen:     timestamppb.New(event.Timestamp),
		LastSeen:      timestamppb.New(event.Timestamp),
		TimeoutSeconds: event.Timeout,
	}

	// Set bytes based on direction
	if direction == pb.TrafficDirection_TRAFFIC_DIRECTION_EGRESS {
		conn.BytesSent = event.BytesOrig
		conn.BytesReceived = event.BytesReply
		conn.PacketsSent = event.PacketsOrig
		conn.PacketsReceived = event.PacketsReply
	} else {
		conn.BytesSent = event.BytesReply
		conn.BytesReceived = event.BytesOrig
		conn.PacketsSent = event.PacketsReply
		conn.PacketsReceived = event.PacketsOrig
	}

	return conn
}

// emitTrafficEvent emits a traffic event to subscribers
func (c *Collector) emitTrafficEvent(eventType ConntrackEventType, conn *pb.Connection) {
	if c.emitter == nil {
		return
	}

	var pbEventType pb.TrafficEventType
	switch eventType {
	case ConntrackEventNew:
		pbEventType = pb.TrafficEventType_TRAFFIC_EVENT_TYPE_NEW
	case ConntrackEventUpdate:
		pbEventType = pb.TrafficEventType_TRAFFIC_EVENT_TYPE_UPDATE
	case ConntrackEventDestroy:
		pbEventType = pb.TrafficEventType_TRAFFIC_EVENT_TYPE_DESTROY
	}

	trafficEvent := &pb.TrafficEvent{
		Type:       pbEventType,
		Connection: conn,
		Timestamp:  timestamppb.Now(),
	}

	c.emitter.EmitTrafficEvent(trafficEvent)
}

// periodicSnapshot takes periodic snapshots of the conntrack table
func (c *Collector) periodicSnapshot() {
	if c.monitor == nil {
		return
	}

	ticker := time.NewTicker(c.config.SnapshotInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.takeSnapshot()
		}
	}
}

// takeSnapshot captures the current conntrack state
func (c *Collector) takeSnapshot() {
	if c.monitor == nil {
		return
	}

	events, err := c.monitor.Snapshot()
	if err != nil {
		log.Printf("Warning: failed to take conntrack snapshot: %v", err)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear old connections and rebuild from snapshot
	c.connections = make(map[string]*pb.Connection)

	matched := 0
	// Update connections from snapshot
	for _, event := range events {
		containerName := ""
		containerIP := ""
		direction := pb.TrafficDirection_TRAFFIC_DIRECTION_UNSPECIFIED

		// Check source IP first (egress from container)
		if name := c.cache.LookupIP(event.SrcIP); name != "" {
			containerName = name
			containerIP = event.SrcIP
			direction = pb.TrafficDirection_TRAFFIC_DIRECTION_EGRESS
		} else if name := c.cache.LookupIP(event.DstIP); name != "" {
			// Check destination IP (ingress to container)
			containerName = name
			containerIP = event.DstIP
			direction = pb.TrafficDirection_TRAFFIC_DIRECTION_INGRESS
		}

		if containerName == "" {
			continue
		}

		matched++
		conn := c.convertToProto(event, containerName, containerIP, direction)
		c.connections[event.ID] = conn
	}

}

// periodicCleanup removes old data from the database
func (c *Collector) periodicCleanup() {
	ticker := time.NewTicker(c.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.store.Cleanup(c.ctx, c.config.RetentionDays); err != nil {
				log.Printf("Warning: traffic cleanup failed: %v", err)
			}
		}
	}
}

// GetConnections returns current active connections for a container
func (c *Collector) GetConnections(containerName string) []*pb.Connection {
	// Ensure cache is refreshed before taking snapshot
	if c.cache.Size() == 0 {
		c.cache.Refresh()
	}

	// Take a fresh snapshot from conntrack for most up-to-date data
	if c.monitor != nil {
		c.takeSnapshot()
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*pb.Connection
	for _, conn := range c.connections {
		if containerName == "" || conn.ContainerName == containerName {
			result = append(result, conn)
		}
	}
	return result
}

// GetConnectionSummary returns aggregate statistics for a container
func (c *Collector) GetConnectionSummary(containerName string) *pb.ConnectionSummary {
	connections := c.GetConnections(containerName)

	summary := &pb.ConnectionSummary{
		ContainerName:     containerName,
		ActiveConnections: int32(len(connections)),
	}

	destCounts := make(map[string]int)
	destBytes := make(map[string]int64)

	for _, conn := range connections {
		if conn.Protocol == pb.Protocol_PROTOCOL_TCP {
			summary.TcpConnections++
		} else if conn.Protocol == pb.Protocol_PROTOCOL_UDP {
			summary.UdpConnections++
		}

		summary.TotalBytesSent += conn.BytesSent
		summary.TotalBytesReceived += conn.BytesReceived

		destCounts[conn.DestIp]++
		destBytes[conn.DestIp] += conn.BytesSent + conn.BytesReceived
	}

	// Top destinations
	for ip, count := range destCounts {
		summary.TopDestinations = append(summary.TopDestinations, &pb.DestinationStats{
			DestIp:          ip,
			ConnectionCount: int32(count),
			BytesTotal:      destBytes[ip],
		})
	}

	return summary
}

// GetStore returns the traffic store
func (c *Collector) GetStore() *Store {
	return c.store
}

// Stop stops the collector
func (c *Collector) Stop() {
	c.cancel()
	if c.monitor != nil {
		c.monitor.Close()
	}
}

// protoStringToEnum converts a protocol string to enum
func protoStringToEnum(proto string) pb.Protocol {
	switch proto {
	case "tcp":
		return pb.Protocol_PROTOCOL_TCP
	case "udp":
		return pb.Protocol_PROTOCOL_UDP
	case "icmp":
		return pb.Protocol_PROTOCOL_ICMP
	default:
		return pb.Protocol_PROTOCOL_UNSPECIFIED
	}
}

// stateStringToEnum converts a TCP state string to enum
func stateStringToEnum(state string) pb.ConnectionState {
	switch state {
	case "SYN_SENT":
		return pb.ConnectionState_CONNECTION_STATE_SYN_SENT
	case "SYN_RECV":
		return pb.ConnectionState_CONNECTION_STATE_SYN_RECV
	case "ESTABLISHED":
		return pb.ConnectionState_CONNECTION_STATE_ESTABLISHED
	case "FIN_WAIT":
		return pb.ConnectionState_CONNECTION_STATE_FIN_WAIT
	case "CLOSE_WAIT":
		return pb.ConnectionState_CONNECTION_STATE_CLOSE_WAIT
	case "LAST_ACK", "TIME_WAIT":
		return pb.ConnectionState_CONNECTION_STATE_TIME_WAIT
	case "CLOSE":
		return pb.ConnectionState_CONNECTION_STATE_CLOSED
	default:
		return pb.ConnectionState_CONNECTION_STATE_UNSPECIFIED
	}
}

// IsAvailable returns true if conntrack monitoring is available
func (c *Collector) IsAvailable() bool {
	return c.monitor != nil
}

// Error returns any collector error message
func (c *Collector) Error() string {
	if c.monitor == nil {
		return fmt.Sprintf("conntrack monitoring unavailable: %v", ErrNotSupported)
	}
	return ""
}
