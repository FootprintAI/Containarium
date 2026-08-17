package cluster

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemStore is the in-memory Store implementation. It backs the daemon
// before Postgres is available (same degrade posture as the network
// policy and crew-run stores) and the handler unit tests. The Postgres
// implementation and this one are held to the same contract by the
// integration test suite.
type MemStore struct {
	mu       sync.Mutex
	clusters map[string]*Cluster // key: owner + "/" + name
	nodes    map[string]*Node    // key: vm name
	events   map[string][]Event  // key: owner + "/" + name
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		clusters: make(map[string]*Cluster),
		nodes:    make(map[string]*Node),
		events:   make(map[string][]Event),
	}
}

func key(owner, name string) string { return owner + "/" + name }

func copyCluster(c *Cluster) *Cluster {
	out := *c
	out.NodeGroups = append([]NodeGroup(nil), c.NodeGroups...)
	return &out
}

func (m *MemStore) Create(ctx context.Context, c *Cluster) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(c.Owner, c.Name)
	if _, ok := m.clusters[k]; ok {
		return ErrAlreadyExists
	}
	m.clusters[k] = copyCluster(c)
	return nil
}

func (m *MemStore) Get(ctx context.Context, owner, name string) (*Cluster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clusters[key(owner, name)]
	if !ok {
		return nil, ErrNotFound
	}
	return copyCluster(c), nil
}

func (m *MemStore) List(ctx context.Context, owner string) ([]*Cluster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Cluster
	for _, c := range m.clusters {
		if owner == "" || c.Owner == owner {
			out = append(out, copyCluster(c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Owner != out[j].Owner {
			return out[i].Owner < out[j].Owner
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (m *MemStore) SetState(ctx context.Context, owner, name string, st State, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clusters[key(owner, name)]
	if !ok {
		return ErrNotFound
	}
	c.State, c.StateReason, c.UpdatedAt = st, reason, time.Now().UTC()
	return nil
}

func (m *MemStore) SetEndpoint(ctx context.Context, owner, name, endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clusters[key(owner, name)]
	if !ok {
		return ErrNotFound
	}
	c.APIEndpoint, c.UpdatedAt = endpoint, time.Now().UTC()
	return nil
}

func (m *MemStore) UpdateNodeGroups(ctx context.Context, owner, name string, groups []NodeGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clusters[key(owner, name)]
	if !ok {
		return ErrNotFound
	}
	c.NodeGroups = append([]NodeGroup(nil), groups...)
	c.UpdatedAt = time.Now().UTC()
	return nil
}

func (m *MemStore) Delete(ctx context.Context, owner, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(owner, name)
	if _, ok := m.clusters[k]; !ok {
		return ErrNotFound
	}
	delete(m.clusters, k)
	delete(m.events, k)
	for vm, n := range m.nodes {
		if n.Owner == owner && n.Cluster == name {
			delete(m.nodes, vm)
		}
	}
	return nil
}

func (m *MemStore) UpsertNode(ctx context.Context, n *Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clusters[key(n.Owner, n.Cluster)]; !ok {
		return ErrNotFound
	}
	cp := *n
	m.nodes[n.VMName] = &cp
	return nil
}

func (m *MemStore) ListNodes(ctx context.Context, owner, name string) ([]*Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clusters[key(owner, name)]; !ok {
		return nil, ErrNotFound
	}
	var out []*Node
	for _, n := range m.nodes {
		if n.Owner == owner && n.Cluster == name {
			cp := *n
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VMName < out[j].VMName })
	return out, nil
}

func (m *MemStore) DeleteNode(ctx context.Context, owner, name, vmName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[vmName]
	if !ok || n.Owner != owner || n.Cluster != name {
		return ErrNotFound
	}
	delete(m.nodes, vmName)
	return nil
}

func (m *MemStore) AppendEvent(ctx context.Context, owner, name string, e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(owner, name)
	if _, ok := m.clusters[k]; !ok {
		return ErrNotFound
	}
	m.events[k] = append(m.events[k], e)
	return nil
}

func (m *MemStore) ListEvents(ctx context.Context, owner, name string, limit int) ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(owner, name)
	if _, ok := m.clusters[k]; !ok {
		return nil, ErrNotFound
	}
	evs := m.events[k]
	// Newest first.
	out := make([]Event, 0, len(evs))
	for i := len(evs) - 1; i >= 0; i-- {
		out = append(out, evs[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemStore) Close() {}
