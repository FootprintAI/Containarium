//go:build linux

package traffic

import (
	"context"
	"fmt"
	"log"
	"sync"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/safecast"

	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

// LinuxConntrackMonitor implements ConntrackMonitor using Linux netlink
type LinuxConntrackMonitor struct {
	conn         *conntrack.Conn // For listening to events
	queryMu      sync.Mutex      // Protects query connection
	events       chan *ConntrackEvent
	ctx          context.Context
	cancel       context.CancelFunc
	lastDropWarn time.Time // Rate-limit drop warnings
}

// NewConntrackMonitor creates a new Linux conntrack monitor
func NewConntrackMonitor() (ConntrackMonitor, error) {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open conntrack: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &LinuxConntrackMonitor{
		conn:   conn,
		events: make(chan *ConntrackEvent, 8192),
		ctx:    ctx,
		cancel: cancel,
	}

	// Start listening for events
	go m.listen()

	return m, nil
}

// listen subscribes to conntrack events via netlink.
//
// We deliberately skip GroupCTUpdate. The kernel emits UPDATE events
// for every accounting tick (~1Hz per active connection) and every TCP
// state transition (SYN → ESTABLISHED → CLOSE_WAIT → ...), so a single
// long-lived connection can generate tens to hundreds of events. On a
// lab box with low flow count we still saw the 8192-buffered event
// channel saturate from update floods alone — verified during the
// daemon-on-lab investigation on 2026-05-13 (#63).
//
// The downstream collector only really needs to know "connection
// started" (to attribute it to a container) and "connection ended"
// (to capture final byte counts for accounting). Interim byte counts
// for active connections are available via Snapshot() on demand.
// Skipping UPDATE drops the event volume by ~100x in typical
// workloads without losing observability.
func (m *LinuxConntrackMonitor) listen() {
	evCh := make(chan conntrack.Event, 8192)

	groups := []netfilter.NetlinkGroup{
		netfilter.GroupCTNew,
		netfilter.GroupCTDestroy,
	}
	errCh, err := m.conn.Listen(evCh, 1, groups)
	if err != nil {
		log.Printf("Failed to listen to conntrack events: %v", err)
		return
	}

	for {
		select {
		case <-m.ctx.Done():
			return
		case ev := <-evCh:
			m.processEvent(ev)
		case err := <-errCh:
			log.Printf("Conntrack error: %v", err)
			return
		}
	}
}

// processEvent converts a conntrack.Event to our ConntrackEvent
func (m *LinuxConntrackMonitor) processEvent(ev conntrack.Event) {
	flow := ev.Flow

	// Skip if IP tuple is not valid
	if !flow.TupleOrig.IP.SourceAddress.IsValid() {
		return
	}

	event := &ConntrackEvent{
		ID:        fmt.Sprintf("%d", flow.ID),
		Protocol:  protoToString(flow.TupleOrig.Proto.Protocol),
		SrcIP:     flow.TupleOrig.IP.SourceAddress.String(),
		SrcPort:   flow.TupleOrig.Proto.SourcePort,
		DstIP:     flow.TupleOrig.IP.DestinationAddress.String(),
		DstPort:   flow.TupleOrig.Proto.DestinationPort,
		Timestamp: time.Now(),
	}

	// Set event type
	switch ev.Type {
	case conntrack.EventNew:
		event.Type = ConntrackEventNew
	case conntrack.EventUpdate:
		event.Type = ConntrackEventUpdate
	case conntrack.EventDestroy:
		event.Type = ConntrackEventDestroy
	}

	// Get byte/packet counters if available
	if flow.CountersOrig.Bytes > 0 {
		event.BytesOrig = safecast.I64FromU64(flow.CountersOrig.Bytes)
		event.PacketsOrig = safecast.I64FromU64(flow.CountersOrig.Packets)
	}
	if flow.CountersReply.Bytes > 0 {
		event.BytesReply = safecast.I64FromU64(flow.CountersReply.Bytes)
		event.PacketsReply = safecast.I64FromU64(flow.CountersReply.Packets)
	}

	// Get TCP state
	if flow.ProtoInfo.TCP != nil {
		event.State = tcpStateToString(flow.ProtoInfo.TCP.State)
	}

	// Get timeout
	if flow.Timeout > 0 {
		event.Timeout = safecast.I32FromU32(flow.Timeout)
	}

	// Send event (non-blocking)
	select {
	case m.events <- event:
	default:
		// Channel full, drop event (rate-limit warning to avoid log flood)
		now := time.Now()
		if now.Sub(m.lastDropWarn) > 30*time.Second {
			m.lastDropWarn = now
			log.Printf("Warning: conntrack event channel full, dropping events")
		}
	}
}

// Events returns the channel of conntrack events
func (m *LinuxConntrackMonitor) Events() <-chan *ConntrackEvent {
	return m.events
}

// Snapshot returns all current connections from the conntrack table
func (m *LinuxConntrackMonitor) Snapshot() ([]*ConntrackEvent, error) {
	// Create a separate connection for querying (can't use event listener conn for queries)
	m.queryMu.Lock()
	defer m.queryMu.Unlock()

	queryConn, err := conntrack.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open conntrack for query: %w", err)
	}
	defer func() { _ = queryConn.Close() }()

	flows, err := queryConn.Dump(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dump conntrack: %w", err)
	}

	var result []*ConntrackEvent
	for _, flow := range flows {
		if !flow.TupleOrig.IP.SourceAddress.IsValid() {
			continue
		}

		event := &ConntrackEvent{
			ID:           fmt.Sprintf("%d", flow.ID),
			Type:         ConntrackEventUpdate,
			Protocol:     protoToString(flow.TupleOrig.Proto.Protocol),
			SrcIP:        flow.TupleOrig.IP.SourceAddress.String(),
			SrcPort:      flow.TupleOrig.Proto.SourcePort,
			DstIP:        flow.TupleOrig.IP.DestinationAddress.String(),
			DstPort:      flow.TupleOrig.Proto.DestinationPort,
			BytesOrig:    safecast.I64FromU64(flow.CountersOrig.Bytes),
			BytesReply:   safecast.I64FromU64(flow.CountersReply.Bytes),
			PacketsOrig:  safecast.I64FromU64(flow.CountersOrig.Packets),
			PacketsReply: safecast.I64FromU64(flow.CountersReply.Packets),
			Timeout:      safecast.I32FromU32(flow.Timeout),
			Timestamp:    time.Now(),
		}

		if flow.ProtoInfo.TCP != nil {
			event.State = tcpStateToString(flow.ProtoInfo.TCP.State)
		}

		result = append(result, event)
	}

	return result, nil
}

// Close stops monitoring and closes the connection
func (m *LinuxConntrackMonitor) Close() error {
	m.cancel()
	close(m.events)
	return m.conn.Close()
}

// protoToString converts a protocol number to string
func protoToString(proto uint8) string {
	switch proto {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_ICMP:
		return "icmp"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

// tcpStateToString converts a TCP state number to string
func tcpStateToString(state uint8) string {
	states := map[uint8]string{
		1:  "SYN_SENT",
		2:  "SYN_RECV",
		3:  "ESTABLISHED",
		4:  "FIN_WAIT",
		5:  "CLOSE_WAIT",
		6:  "LAST_ACK",
		7:  "TIME_WAIT",
		8:  "CLOSE",
		9:  "SYN_SENT2",
		10: "MAX",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return "UNKNOWN"
}
