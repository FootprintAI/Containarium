package sshban

import (
	"context"
	"net/http"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Proxy forwards admin calls to the process that actually enforces each policy.
// Callers must mount its REST handler behind the sentinel ADMIN HMAC middleware.
type Proxy struct {
	pb.UnimplementedSentinelSSHBanServiceServer
	Sockets map[pb.SSHBanListener]string
	// ResolveSocket permits live listener discovery after metadata reconciliation.
	ResolveSocket func(pb.SSHBanListener) string
}

// Handler creates generated REST routes without introducing a public gRPC port.
func (p *Proxy) Handler() http.Handler {
	mux := runtime.NewServeMux()
	if err := pb.RegisterSentinelSSHBanServiceHandlerServer(context.Background(), mux, p); err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "SSH ban API unavailable", http.StatusServiceUnavailable)
		})
	}
	return mux
}

// client validates the listener before touching any local control socket.
func (p *Proxy) client(listener pb.SSHBanListener) (pb.SentinelSSHBanServiceClient, func(), error) {
	if listener != pb.SSHBanListener_SSH_BAN_LISTENER_MAIN && listener != pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS {
		return nil, nil, status.Error(codes.InvalidArgument, "listener is required")
	}
	path := p.Sockets[listener]
	if p.ResolveSocket != nil {
		path = p.ResolveSocket(listener)
	}
	if path == "" {
		return nil, nil, status.Error(codes.NotFound, "SSH listener is disabled")
	}
	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, status.Error(codes.Unavailable, "SSH ban control unavailable")
	}
	return pb.NewSentinelSSHBanServiceClient(conn), func() { _ = conn.Close() }, nil
}

// GetSSHBan returns live state, never a cached or log-derived approximation.
func (p *Proxy) GetSSHBan(ctx context.Context, r *pb.GetSSHBanRequest) (*pb.GetSSHBanResponse, error) {
	if _, err := parseIP(r.GetIp()); err != nil {
		return nil, err
	}
	c, closeClient, err := p.client(r.GetListener())
	if err != nil {
		return nil, err
	}
	defer closeClient()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := c.GetSSHBan(ctx, r)
	return out, controlError(err)
}

// ListSSHBans forwards a bounded page request to one independent listener.
func (p *Proxy) ListSSHBans(ctx context.Context, r *pb.ListSSHBansRequest) (*pb.ListSSHBansResponse, error) {
	if r.GetPageSize() > 1000 {
		return nil, status.Error(codes.InvalidArgument, "page size must be at most 1000")
	}
	if r.GetPageToken() != "" {
		if _, err := parseIP(r.GetPageToken()); err != nil {
			return nil, err
		}
	}
	c, closeClient, err := p.client(r.GetListener())
	if err != nil {
		return nil, err
	}
	defer closeClient()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := c.ListSSHBans(ctx, r)
	return out, controlError(err)
}

// UnbanSSHSource can clear exactly one validated address on one listener.
func (p *Proxy) UnbanSSHSource(ctx context.Context, r *pb.UnbanSSHSourceRequest) (*pb.UnbanSSHSourceResponse, error) {
	if _, err := parseIP(r.GetIp()); err != nil {
		return nil, err
	}
	c, closeClient, err := p.client(r.GetListener())
	if err != nil {
		return nil, err
	}
	defer closeClient()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := c.UnbanSSHSource(ctx, r)
	return out, controlError(err)
}

// controlError makes an unreachable or wedged plugin an explicit HTTP 503.
func controlError(err error) error {
	if status.Code(err) == codes.Unavailable || status.Code(err) == codes.DeadlineExceeded {
		return status.Error(codes.Unavailable, "SSH ban control unavailable; enforcement state is unknown")
	}
	return err
}
