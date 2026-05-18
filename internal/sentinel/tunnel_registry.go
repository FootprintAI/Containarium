package sentinel

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// ExternalPortBase is the starting port for external tunnel proxy listeners.
// Each tunnel backend gets ExternalPortBase + index (e.g., 18001, 18002, ...).
const ExternalPortBase = 18000

// TunnelSpot represents a connected remote spot instance.
type TunnelSpot struct {
	ID           string
	Session      *yamux.Session
	LocalIP      string // assigned loopback alias, e.g. "127.0.0.2"
	ExternalPort int    // externally reachable port for API access (e.g., 18001)
	Ports        []int  // ports this spot serves
	Pool         Pool   // optional pool tag for grouping peers; empty = unpooled
	Connected    time.Time

	// Primary self-registration via handshake (slice 6). Non-empty
	// PublicHostname promotes this tunnel into a primary registry entry on
	// connect; cleared on disconnect.
	PublicHostname    string
	PublicAliases     []string
	PublicBaseDomains []string
	PublicPort        int
}

// TunnelRegistry tracks connected tunnel clients and assigns loopback aliases.
type TunnelRegistry struct {
	mu      sync.RWMutex
	spots   map[string]*TunnelSpot
	nextIP  byte // next octet for 127.0.0.X (starts at 2)
	usedIPs map[byte]string // octet -> spotID
}

// NewTunnelRegistry creates a new TunnelRegistry.
func NewTunnelRegistry() *TunnelRegistry {
	return &TunnelRegistry{
		spots:   make(map[string]*TunnelSpot),
		nextIP:  2,
		usedIPs: make(map[byte]string),
	}
}

// Register adds a new spot to the registry, assigns a loopback alias,
// and configures it on the system. Returns the assigned loopback IP.
// Pool, PublicHostname, PublicAliases, PublicPort are read off the
// handshake; PublicHostname being set means the sentinel will promote
// this tunnel into a primary registry entry on connect.
func (r *TunnelRegistry) Register(hs *TunnelHandshake, session *yamux.Session) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	spotID := hs.SpotID

	// If this spotID is already registered, reuse its loopback IP
	// This prevents sshpiper config from going stale during reconnects
	var localIP string
	var octet byte
	if old, ok := r.spots[spotID]; ok {
		log.Printf("[tunnel-registry] spot %q reconnecting, reusing IP %s", spotID, old.LocalIP)
		old.Session.Close()
		localIP = old.LocalIP
		for o, id := range r.usedIPs {
			if id == spotID {
				octet = o
				break
			}
		}
		delete(r.spots, spotID)
	} else {
		var err error
		octet, err = r.allocateOctet(spotID)
		if err != nil {
			return "", err
		}
		localIP = fmt.Sprintf("127.0.0.%d", octet)
		if err := addLoopbackAlias(localIP); err != nil {
			delete(r.usedIPs, octet)
			return "", fmt.Errorf("add loopback alias %s: %w", localIP, err)
		}
	}

	externalPort := ExternalPortBase + int(octet)

	spot := &TunnelSpot{
		ID:                spotID,
		Session:           session,
		LocalIP:           localIP,
		ExternalPort:      externalPort,
		Ports:             hs.Ports,
		Pool:              hs.Pool,
		PublicHostname:    hs.PublicHostname,
		PublicAliases:     hs.PublicAliases,
		PublicBaseDomains: hs.PublicBaseDomains,
		PublicPort:        hs.PublicPort,
		Connected:         time.Now(),
	}
	r.spots[spotID] = spot

	log.Printf("[tunnel-registry] registered spot %q at %s (ports: %v, pool: %q, primary_host: %q)", spotID, localIP, hs.Ports, hs.Pool, hs.PublicHostname)
	return localIP, nil
}

// Unregister removes a spot from the registry and cleans up its loopback alias.
func (r *TunnelRegistry) Unregister(spotID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	spot, ok := r.spots[spotID]
	if !ok {
		return
	}

	spot.Session.Close()
	removeLoopbackAlias(spot.LocalIP)
	delete(r.spots, spotID)

	for octet, id := range r.usedIPs {
		if id == spotID {
			delete(r.usedIPs, octet)
			break
		}
	}

	log.Printf("[tunnel-registry] unregistered spot %q (was at %s)", spotID, spot.LocalIP)
}

// DialTunnel opens a yamux stream to the spot's local service on the given
// port. Used by the SNI router to forward inbound TLS bytes to a
// tunnel-promoted primary's :443 without going through a loopback proxy
// listener (which would conflict with the sentinel's own ConnMux on 443).
//
// The returned net.Conn is a yamux stream — bidirectional, closing it
// closes the stream cleanly.
func (r *TunnelRegistry) DialTunnel(spotID string, port int) (net.Conn, error) {
	r.mu.RLock()
	spot, ok := r.spots[spotID]
	r.mu.RUnlock()
	if !ok || spot == nil || spot.Session == nil {
		return nil, fmt.Errorf("spot %q not registered (or already closed)", spotID)
	}
	stream, err := spot.Session.Open()
	if err != nil {
		return nil, fmt.Errorf("yamux open for spot %q: %w", spotID, err)
	}
	// Wire protocol: 2-byte big-endian port number, then bidirectional copy.
	// Same handshake the existing proxyConnection() uses on the loopback path.
	portBytes := []byte{byte(port >> 8), byte(port & 0xff)}
	if _, err := stream.Write(portBytes); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write port header to spot %q: %w", spotID, err)
	}
	return stream, nil
}

// Get returns the TunnelSpot for the given spotID, or nil.
func (r *TunnelRegistry) Get(spotID string) *TunnelSpot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.spots[spotID]
}

// GetFirst returns the first (and typically only) connected spot.
func (r *TunnelRegistry) GetFirst() *TunnelSpot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, spot := range r.spots {
		return spot
	}
	return nil
}

// Connected returns true if at least one spot is connected.
func (r *TunnelRegistry) Connected() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.spots) > 0
}

// Count returns the number of connected spots.
func (r *TunnelRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.spots)
}

// Spots returns a snapshot of all connected spots.
func (r *TunnelRegistry) Spots() []*TunnelSpot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*TunnelSpot, 0, len(r.spots))
	for _, spot := range r.spots {
		result = append(result, spot)
	}
	return result
}

func (r *TunnelRegistry) allocateOctet(spotID string) (byte, error) {
	// Try from nextIP up to 254
	for i := byte(0); i < 253; i++ {
		candidate := r.nextIP + i
		if candidate > 254 {
			candidate = candidate - 253 + 2 // wrap around
		}
		if _, used := r.usedIPs[candidate]; !used {
			r.usedIPs[candidate] = spotID
			r.nextIP = candidate + 1
			if r.nextIP > 254 {
				r.nextIP = 2
			}
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("no available loopback addresses (all 127.0.0.2-254 in use)")
}

// addLoopbackAlias adds an IP alias to the loopback interface.
func addLoopbackAlias(ip string) error {
	if runtime.GOOS != "linux" {
		log.Printf("[tunnel-registry] loopback alias %s: skipping on %s", ip, runtime.GOOS)
		return nil
	}
	return exec.Command("ip", "addr", "add", ip+"/32", "dev", "lo").Run()
}

// removeLoopbackAlias removes an IP alias from the loopback interface.
func removeLoopbackAlias(ip string) {
	if runtime.GOOS != "linux" {
		return
	}
	if err := exec.Command("ip", "addr", "del", ip+"/32", "dev", "lo").Run(); err != nil {
		log.Printf("[tunnel-registry] failed to remove loopback alias %s: %v", ip, err)
	}
}
