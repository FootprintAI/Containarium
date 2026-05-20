package auth

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"google.golang.org/grpc/codes"
)

// RequireMTLSUnaryInterceptor refuses any unary RPC whose peer
// wasn't authenticated via mTLS. Wire it onto the gRPC server when
// EnableMTLS=true — without it, the existing JWT-passthrough
// interceptor accepts a plaintext client just as readily as a
// mutual-TLS one, defeating the daemon's "we rely on mTLS"
// security model.
//
// Audit C-HIGH-2: the daemon's gRPC server promised mTLS via
// configuration, but the auth interceptor was a passthrough that
// didn't verify any peer-info. A client connecting with
// `insecure.NewCredentials()` would breeze through.
func RequireMTLSUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if err := assertMTLSPeer(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// RequireMTLSStreamInterceptor is the streaming counterpart.
func RequireMTLSStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := assertMTLSPeer(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// assertMTLSPeer inspects the call's peer info and returns nil
// only when the connection carries verified mTLS credentials with
// at least one client cert. Returns Unauthenticated otherwise.
func assertMTLSPeer(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return status.Error(codes.Unauthenticated, "no peer info on call")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "non-TLS connection rejected (mTLS required)")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return status.Error(codes.Unauthenticated, "no verified client cert on TLS connection (mTLS required)")
	}
	return nil
}

// MTLSPeerCN returns the Common Name of the verified client
// certificate on the call's TLS peer, if any. Useful for logging
// the identity of mTLS-authenticated callers. Returns empty
// string + non-nil error if there's no verified mTLS peer.
func MTLSPeerCN(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return "", fmt.Errorf("no peer info on call")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", fmt.Errorf("no verified client cert on TLS peer")
	}
	return tlsInfo.State.VerifiedChains[0][0].Subject.CommonName, nil
}
