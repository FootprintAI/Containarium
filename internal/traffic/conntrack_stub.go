//go:build !linux

package traffic

// stubConntrackMonitor is a stub implementation for non-Linux platforms
type stubConntrackMonitor struct {
	events chan *ConntrackEvent
}

// NewConntrackMonitor returns an error on non-Linux platforms
func NewConntrackMonitor() (ConntrackMonitor, error) {
	return nil, ErrNotSupported
}

// Events returns an empty channel (stub)
func (m *stubConntrackMonitor) Events() <-chan *ConntrackEvent {
	return m.events
}

// Snapshot returns an empty list (stub)
func (m *stubConntrackMonitor) Snapshot() ([]*ConntrackEvent, error) {
	return nil, ErrNotSupported
}

// Close does nothing (stub)
func (m *stubConntrackMonitor) Close() error {
	return nil
}
