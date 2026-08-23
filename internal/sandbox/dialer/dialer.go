// Package dialer caches gRPC connections to agent-box's resident
// SpawnService, one per pool member's bind-mounted unix socket (#1488
// Phase 2/3). A claim reuses an already-established connection instead of
// paying dial cost on every spawn — the whole point of a warm pool is
// that the connection, like the container, is already up before the
// request arrives.
//
// This package deliberately does not reimplement reconnect/backoff logic:
// grpc-go's ClientConn already manages that transparently for a cached
// connection, and honors a call's context deadline regardless — an RPC
// against an unready channel returns once its own ctx expires rather than
// blocking forever, whether or not the call opts into WaitForReady. The
// tests in dialer_test.go exist to prove reconnect-after-disconnect and
// deadline-respecting empirically against a real local socket, not to
// assert this package's own internal state — grpc-go's behavior is
// exactly the contract this package depends on holding.
package dialer

import (
	"fmt"
	"sync"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Dialer caches one *grpc.ClientConn per unix socket path.
type Dialer struct {
	mu    sync.Mutex
	conns map[string]*grpc.ClientConn
}

// New returns an empty Dialer.
func New() *Dialer {
	return &Dialer{conns: make(map[string]*grpc.ClientConn)}
}

// Client returns a SpawnServiceClient for the pool member listening on
// socketPath, dialing at most once per distinct path — a second call with
// the same path reuses the cached connection rather than dialing again.
//
// grpc.NewClient is lazy: this returns immediately without blocking on the
// socket actually being reachable. The first RPC issued through the
// returned client is what surfaces a connection failure, bounded by that
// call's own context deadline (per this package's doc comment) rather
// than a retry loop in here.
func (d *Dialer) Client(socketPath string) (pb.SpawnServiceClient, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if conn, ok := d.conns[socketPath]; ok {
		return pb.NewSpawnServiceClient(conn), nil
	}

	conn, err := grpc.NewClient("unix:"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", socketPath, err)
	}
	d.conns[socketPath] = conn
	return pb.NewSpawnServiceClient(conn), nil
}

// Forget closes and evicts the cached connection for socketPath, if any.
// Use when a pool member is being destroyed (its socket is going away
// permanently, not just reconnecting) so the Dialer doesn't keep dialing
// a path that will never come back — a distinct case from a transient
// disconnect, which grpc-go's own reconnect logic already absorbs without
// needing this.
func (d *Dialer) Forget(socketPath string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	conn, ok := d.conns[socketPath]
	if !ok {
		return nil
	}
	delete(d.conns, socketPath)
	return conn.Close()
}

// Close closes every cached connection. Call on daemon shutdown.
func (d *Dialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var firstErr error
	for path, conn := range d.conns {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close %s: %w", path, err)
		}
	}
	d.conns = make(map[string]*grpc.ClientConn)
	return firstErr
}
