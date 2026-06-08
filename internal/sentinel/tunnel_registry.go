package sentinel

import (
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/safecast"
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
	usedIPs map[byte]string // octet -> spotID
}

// NewTunnelRegistry creates a new TunnelRegistry.
func NewTunnelRegistry() *TunnelRegistry {
	return &TunnelRegistry{
		spots:   make(map[string]*TunnelSpot),
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
		_ = old.Session.Close()
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

// UnregisterAll iterates every registered spot and unregisters it.
// Used on sentinel shutdown so the loopback aliases (127.0.0.x)
// don't persist into the next start. Without this, restarting the
// sentinel can leave the previous run's aliases blocking fresh
// allocations — operators had to `ip addr del` them by hand
// (#337 §"Related observations").
//
// Safe to call concurrently with Register; takes the registry lock.
// Each Unregister closes the yamux session and removes the alias.
func (r *TunnelRegistry) UnregisterAll() {
	r.mu.Lock()
	ids := make([]string, 0, len(r.spots))
	for id := range r.spots {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	for _, id := range ids {
		r.Unregister(id)
	}
}

// Unregister removes a spot from the registry and cleans up its loopback alias.
func (r *TunnelRegistry) Unregister(spotID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	spot, ok := r.spots[spotID]
	if !ok {
		return
	}

	_ = spot.Session.Close()
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
	portBytes := []byte{byte((port >> 8) & 0xff), byte(port & 0xff)}
	if _, err := stream.Write(portBytes); err != nil {
		_ = stream.Close()
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

// allocateOctet picks the 127.0.0.X octet for spotID. The slot is
// derived deterministically from a hash of spotID so a backend that
// disconnects and reconnects (e.g., after a network blip, sshpiper
// reload, or sentinel restart) lands on the same loopback alias
// across the lifetime of the registry — keysync's sshpiper config
// stays valid through churn, and "ss -tlnp" output matches the
// config without operator confusion (#342).
//
// When the preferred slot is occupied by a *different* spotID, we
// linear-probe forward to the next free slot. This keeps the
// existing capacity (127.0.0.2..127.0.0.254 = 253 slots) and only
// drifts under genuine contention. Two backends with the same hash
// land in adjacent slots; the first one keeps the preferred slot,
// the second pays one extra probe.
func (r *TunnelRegistry) allocateOctet(spotID string) (byte, error) {
	preferred := preferredOctet(spotID)
	for i := byte(0); i < 253; i++ {
		// step through the 2..254 range starting from `preferred`,
		// wrapping if we run off the top.
		candidate := preferred + i
		if candidate < 2 || candidate > 254 {
			candidate = safecast.U8(2 + (int(preferred)+int(i)-2)%253)
		}
		if _, used := r.usedIPs[candidate]; !used {
			r.usedIPs[candidate] = spotID
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("no available loopback addresses (all 127.0.0.2-254 in use)")
}

// preferredOctet maps a spotID to a deterministic octet in [2, 254].
// FNV-1a is a non-cryptographic hash — collision resistance is
// irrelevant here because we linear-probe on collision. We just want
// a uniform spread so independent spotIDs don't pile up at slot 2.
func preferredOctet(spotID string) byte {
	h := fnv.New32a()
	_, _ = h.Write([]byte(spotID))
	return byte(2 + (h.Sum32() % 253))
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
