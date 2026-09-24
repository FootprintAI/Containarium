package auth

import (
	"context"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"google.golang.org/grpc/codes"
)

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
