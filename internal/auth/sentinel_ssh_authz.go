package auth

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// SentinelSSHAuthzVerifiedMDKey is reserved identity metadata. Only the
// signature-protected gateway may set it, over the private internal transport.
const SentinelSSHAuthzVerifiedMDKey = "x-containarium-ssh-authz-verified"

type sentinelSSHAuthzVerifiedKey struct{}

func ContextWithVerifiedSentinelSSHAuthz(ctx context.Context) context.Context {
	return context.WithValue(ctx, sentinelSSHAuthzVerifiedKey{}, true)
}
func VerifiedSentinelSSHAuthz(ctx context.Context) bool {
	verified, _ := ctx.Value(sentinelSSHAuthzVerifiedKey{}).(bool)
	return verified
}

// RequireVerifiedSentinelSSHAuthz prevents a scoped JWT or an external gRPC
// peer from reaching this sentinel-only RPC through an alternate gateway path.
func RequireVerifiedSentinelSSHAuthz(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "verified sentinel transport required")
	}
	if _, ok := p.AuthInfo.(InternalAuthInfo); !ok {
		return status.Error(codes.PermissionDenied, "verified sentinel transport required")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	if len(md.Get(SentinelSSHAuthzVerifiedMDKey)) != 1 || md.Get(SentinelSSHAuthzVerifiedMDKey)[0] != "1" {
		return status.Error(codes.PermissionDenied, "verified sentinel signature required")
	}
	return nil
}
