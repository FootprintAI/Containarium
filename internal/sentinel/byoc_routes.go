package sentinel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// DefaultBYOCRouteStorePath is where cloud-pushed BYOC public-ingress
// bindings (see BYOCRouteRegisterHandler) are persisted so a sentinel
// restart doesn't drop every tenant subdomain until the cloud's next
// reconcile tick. Mirrors DefaultTunnelTokenStorePath. See #733.
const DefaultBYOCRouteStorePath = "/etc/containarium/byoc-routes.json"

// BYOCRoute is one authoritative `subdomain → BYOC host` binding, pushed
// by the cloud (the sole authority — hosts never self-announce, which
// would let a compromised host hijack another tenant's hostname). The
// sentinel terminates TLS for Hostname with the wildcard it already
// holds and plaintext-forwards to the box over the tunnel:
// DialTunnel(BackendID, Port). See #733.
type BYOCRoute struct {
	// Hostname is the exact public name the cloud minted, e.g.
	// "myapp-acme.containarium.dev". Matched against the TLS SNI.
	Hostname string `json:"hostname"`

	// BackendID is the tunnel spot id the box lives behind (the value
	// the sentinel's tunnel registry keys on; a leading "tunnel-" prefix
	// is tolerated and stripped at dial time, matching the primary path).
	BackendID string `json:"backend_id"`

	// Port is the plaintext port on the host (tunnel-forwarded) that
	// reaches the box's HTTP, e.g. 8080.
	Port int `json:"port"`
}

// BYOCRouteRegistry is the sentinel's in-memory, cloud-authoritative map
// of BYOC public-ingress bindings, consulted by the SNI router. It is a
// sibling of PrimaryRegistry/TunnelRegistry but is NEVER populated by a
// host self-announce — only by ReplaceAll/Upsert from the admin-secret
// -gated push endpoint. Concurrency-safe.
type BYOCRouteRegistry struct {
	mu     sync.RWMutex
	routes map[string]BYOCRoute // keyed by Hostname
}

// NewBYOCRouteRegistry returns an empty registry.
func NewBYOCRouteRegistry() *BYOCRouteRegistry {
	return &BYOCRouteRegistry{routes: make(map[string]BYOCRoute)}
}

// Lookup returns the binding for a hostname, or ok=false.
func (r *BYOCRouteRegistry) Lookup(hostname string) (BYOCRoute, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	route, ok := r.routes[hostname]
	return route, ok
}

// ReplaceAll swaps the entire binding set atomically. This is the primary
// mutation: the cloud pushes the full authoritative set each reconcile
// tick, so a binding the cloud dropped disappears here without a separate
// delete (idempotent, converges after a sentinel restart or a missed
// delete). Entries with an empty Hostname/BackendID or non-positive Port
// are skipped as malformed.
func (r *BYOCRouteRegistry) ReplaceAll(routes []BYOCRoute) {
	next := make(map[string]BYOCRoute, len(routes))
	for _, rt := range routes {
		if rt.Hostname == "" || rt.BackendID == "" || rt.Port <= 0 {
			continue
		}
		next[rt.Hostname] = rt
	}
	r.mu.Lock()
	r.routes = next
	r.mu.Unlock()
}

// Snapshot returns the current bindings as a slice (for persistence).
func (r *BYOCRouteRegistry) Snapshot() []BYOCRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]BYOCRoute, 0, len(r.routes))
	for _, rt := range r.routes {
		out = append(out, rt)
	}
	return out
}

// LoadBYOCRouteStore reads previously-persisted bindings from path. A
// missing file is not an error (fresh sentinel) — returns an empty slice.
func LoadBYOCRouteStore(path string) ([]BYOCRoute, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed, operator-controlled path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read byoc route store %s: %w", path, err)
	}
	if len(b) == 0 {
		return nil, nil
	}
	var routes []BYOCRoute
	if err := json.Unmarshal(b, &routes); err != nil {
		return nil, fmt.Errorf("parse byoc route store %s: %w", path, err)
	}
	return routes, nil
}

// SaveBYOCRouteStore atomically persists the full binding set to path at
// mode 0600. Mirrors SaveTunnelTokenStore. (Bindings aren't secrets, but
// 0600 matches the sentinel's other operator-state files and costs
// nothing.)
func SaveBYOCRouteStore(path string, routes []BYOCRoute) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create byoc route store dir %s: %w", dir, err)
	}
	b, err := json.Marshal(routes)
	if err != nil {
		return fmt.Errorf("marshal byoc route store: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".byoc-routes-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp byoc route store: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op if the rename succeeded
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp byoc route store: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp byoc route store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp byoc route store: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename byoc route store into place: %w", err)
	}
	return nil
}
