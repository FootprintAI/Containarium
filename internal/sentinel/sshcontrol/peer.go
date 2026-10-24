package sshcontrol

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

// Peer is a local plugin's bounded transport registry and generated RPC client.
type Peer struct {
	Client   pb.SentinelSSHUpstreamServiceClient
	listener pb.SSHBanListener
	conn     *grpc.ClientConn
	mu       sync.Mutex
	refs     map[string]peerRef
}

// peerRef expires abandoned setup metadata without retaining established sessions.
type peerRef struct {
	ref     *pb.SSHUpstreamConnection
	expires time.Time
}

// DialPeer connects only to the configured local operator socket.
func DialPeer(socket string, listener pb.SSHBanListener) (*Peer, error) {
	if !filepath.IsAbs(socket) || (listener != pb.SSHBanListener_SSH_BAN_LISTENER_MAIN && listener != pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS) {
		return nil, errors.New("private upstream socket and listener required")
	}
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Peer{Client: pb.NewSentinelSSHUpstreamServiceClient(conn), listener: listener, conn: conn, refs: map[string]peerRef{}}, nil
}

// Close releases the generated client's transport during plugin shutdown.
func (p *Peer) Close() error { return p.conn.Close() }

// CallContext bounds every private control operation independently of SSH traffic.
func CallContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, time.Second)
}

// Open records a controller-confirmed identity; substitution is never accepted.
func (p *Peer) Open(ctx context.Context, id, remote string) (*pb.SSHUpstreamConnection, error) {
	call, cancel := CallContext(ctx)
	defer cancel()
	ref := &pb.SSHUpstreamConnection{Listener: p.listener, ConnectionId: id, RemoteAddr: remote}
	r, err := p.Client.OpenSSHUpstreamConnection(call, &pb.OpenSSHUpstreamConnectionRequest{Connection: ref})
	if err != nil {
		return nil, err
	}
	ref.ControllerGeneration = r.ControllerGeneration
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for key, r := range p.refs {
		if !now.Before(r.expires) {
			delete(p.refs, key)
		}
	}
	if len(p.refs) >= 4096 {
		return nil, errors.New("plugin upstream metadata capacity")
	}
	if old, ok := p.refs[id]; ok && !proto.Equal(old.ref, ref) {
		return nil, errors.New("plugin upstream identity substitution")
	}
	p.refs[id] = peerRef{ref: ref, expires: now.Add(6 * time.Minute)}
	return proto.Clone(ref).(*pb.SSHUpstreamConnection), nil
}

// Find returns an immutable copy matching both UUID and complete remote address.
func (p *Peer) Find(id, remote string) *pb.SSHUpstreamConnection {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.refs[id]
	if !ok || r.ref.RemoteAddr != remote || !time.Now().Before(r.expires) {
		return nil
	}
	return proto.Clone(r.ref).(*pb.SSHUpstreamConnection)
}

// ByRemote repairs PipeCreateError's missing UUID using registered transport only.
func (p *Peer) ByRemote(remote string) *pb.SSHUpstreamConnection {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.refs {
		if r.ref.RemoteAddr == remote && time.Now().Before(r.expires) {
			return proto.Clone(r.ref).(*pb.SSHUpstreamConnection)
		}
	}
	return nil
}

// Forget drops terminal setup metadata without changing shared risk history.
func (p *Peer) Forget(id string) { p.mu.Lock(); defer p.mu.Unlock(); delete(p.refs, id) }
