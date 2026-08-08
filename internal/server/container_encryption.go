package server

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Request validation for per-tenant dataset encryption (#1198), phase 2
// of docs/ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md.
//
// The flag is accepted and validated here; the lifecycle hooks that
// actually create an encrypted dataset land in #1199/#1201. Until then a
// daemon with no KeyProvider — which is every OSS daemon today — rejects
// an encrypted create outright, so there is no window in which the API
// accepts "encrypt this" and produces plaintext.

// defaultTenantID is the only tenant a single-tenant daemon recognises.
// Callers may also leave the field unset.
const defaultTenantID = "default"

// validateEncryption rejects an encrypted create when the daemon has no
// key custody wired.
//
// Failing closed is the whole point: silently provisioning an
// unencrypted dataset would hand the caller a guarantee they do not
// have, and they would discover it during an audit rather than at create
// time. FAILED_PRECONDITION rather than INVALID_ARGUMENT because the
// request is well-formed — it is the daemon that is not configured for
// it, so the fix is an operator action, not a caller one.
func validateEncryption(req *pb.CreateContainerRequest, provider zfskey.KeyProvider) error {
	if req == nil || !req.GetEncrypted() {
		return nil
	}
	if provider == nil {
		return status.Error(codes.FailedPrecondition,
			"encrypted=true requires this daemon to be wired with a KeyProvider for per-tenant dataset encryption, "+
				"and none is configured; refusing rather than creating an unencrypted container. "+
				"See docs/ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md")
	}
	return nil
}

// validateTenantID enforces the single-tenant contract of the OSS daemon.
//
// The field exists on the proto so the wire shape is stable across the
// OSS → cloud transition (design resolved decision #1), but accepting a
// real tenant here would be a lie: this build has no tenancy, so every
// "tenant" would end up sharing one encryptionroot and the isolation the
// field implies would not exist. The multi-tenant cloud daemon relaxes
// this; OSS does not pretend.
func validateTenantID(tenantID string) error {
	// Exact match only. Deliberately not trimmed: "  " is an explicit
	// value the caller sent, not an unset field, and quietly reading it
	// as the default would accept a tenant this daemon cannot isolate.
	if tenantID == "" || tenantID == defaultTenantID {
		return nil
	}
	return status.Errorf(codes.InvalidArgument,
		"tenant_id %q is not available on this daemon: it is a single-tenant build, which accepts only "+
			"an unset tenant_id or %q. Multi-tenant placement is a cloud-build feature",
		tenantID, defaultTenantID)
}
