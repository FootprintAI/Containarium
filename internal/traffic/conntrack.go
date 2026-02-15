package traffic

import (
	"errors"
	"time"
)

// ErrNotSupported is returned when conntrack is not supported on this platform
var ErrNotSupported = errors.New("conntrack monitoring is only supported on Linux")

// ConntrackEventType represents the type of conntrack event
type ConntrackEventType int

const (
	// ConntrackEventNew indicates a new connection
	ConntrackEventNew ConntrackEventType = iota
	// ConntrackEventUpdate indicates a connection update (state/counters)
	ConntrackEventUpdate
	// ConntrackEventDestroy indicates a connection was terminated
	ConntrackEventDestroy
)

// String returns the string representation of the event type
func (t ConntrackEventType) String() string {
	switch t {
	case ConntrackEventNew:
		return "NEW"
	case ConntrackEventUpdate:
		return "UPDATE"
	case ConntrackEventDestroy:
		return "DESTROY"
	default:
		return "UNKNOWN"
	}
}

// ConntrackEvent represents a connection tracking event
type ConntrackEvent struct {
	// ID is a unique identifier for this connection
	ID string

	// Type indicates the event type (new, update, destroy)
	Type ConntrackEventType

	// Protocol is the connection protocol (tcp, udp, icmp)
	Protocol string

	// SrcIP is the source IP address
	SrcIP string

	// SrcPort is the source port (0 for ICMP)
	SrcPort uint16

	// DstIP is the destination IP address
	DstIP string

	// DstPort is the destination port (0 for ICMP)
	DstPort uint16

	// State is the TCP connection state (empty for UDP/ICMP)
	State string

	// BytesOrig is bytes from source to destination (original direction)
	BytesOrig int64

	// BytesReply is bytes from destination to source (reply direction)
	BytesReply int64

	// PacketsOrig is packets from source to destination
	PacketsOrig int64

	// PacketsReply is packets from destination to source
	PacketsReply int64

	// Timeout is seconds until the connection expires
	Timeout int32

	// Timestamp is when the event was received
	Timestamp time.Time
}

// ConntrackMonitor defines the interface for connection tracking
type ConntrackMonitor interface {
	// Events returns a channel of conntrack events
	Events() <-chan *ConntrackEvent

	// Snapshot returns all current connections
	Snapshot() ([]*ConntrackEvent, error)

	// Close stops monitoring and releases resources
	Close() error
}
