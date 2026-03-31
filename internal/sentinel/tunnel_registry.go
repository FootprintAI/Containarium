package sentinel

import (
	"fmt"
	"log"
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
	Connected    time.Time
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
func (r *TunnelRegistry) Register(spotID string, session *yamux.Session, ports []int) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

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
		ID:           spotID,
		Session:      session,
		LocalIP:      localIP,
		ExternalPort: externalPort,
		Ports:        ports,
		Connected:    time.Now(),
	}
	r.spots[spotID] = spot

	log.Printf("[tunnel-registry] registered spot %q at %s (ports: %v)", spotID, localIP, ports)
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
