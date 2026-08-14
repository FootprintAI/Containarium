package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Wiring the encrypted create (#1341): CreateContainer resolves the tenant's
// storage before provisioning anything, places the container on it, and
// records where it went.
//
// These pin the wiring and its refusals. Whether the resulting container is
// actually encrypted is a property ZFS computes, asserted on the incus lane.

// encryptedTenantOf is the decision about WHOSE key a container is encrypted
// with. Getting it wrong does not fail — it silently puts two tenants under
// one encryptionroot, which is the boundary the whole feature exists to draw.
func TestEncryptionTenantFor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		req     *pb.CreateContainerRequest
		want    string
		wantWhy string
	}{
		{
			name: "the username is the tenant on an OSS daemon",
			req:  &pb.CreateContainerRequest{Username: "alice"},
			want: "alice",
			wantWhy: "validateTenantID forbids any real tenant_id here, so the username is the " +
				"only tenancy this build has",
		},
		{
			// "default" is what a single-tenant daemon accepts as a synonym
			// for unset. Treating it as the key scope would put EVERY user on
			// one encryptionroot — no isolation at all, silently.
			name:    "tenant_id=default is not a tenant",
			req:     &pb.CreateContainerRequest{Username: "alice", TenantId: "default"},
			want:    "alice",
			wantWhy: "every user would share one key",
		},
		{
			// The cloud build's org-scoped tenancy: a real tenant_id wins,
			// because a tenant's several users must share one encryptionroot.
			name:    "a real tenant_id wins",
			req:     &pb.CreateContainerRequest{Username: "alice", TenantId: "org-acme"},
			want:    "org-acme",
			wantWhy: "one org's containers share one key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := encryptionTenantFor(tc.req); got != tc.want {
				t.Errorf("encryptionTenantFor = %q, want %q — otherwise %s", got, tc.want, tc.wantWhy)
			}
		})
	}
}

// The guard inherited from #1339.
//
// #1339 made a storage pool that IS set impossible to drop silently. This is
// the other half: an encrypted create whose pool could not be resolved must
// fail loudly rather than fall through to the daemon default, where the
// container would be created unencrypted and reported as a success.
//
// Reachable only through a misconfigured daemon — a KeyProvider wired with no
// encryption hooks — which is exactly the shape a future wiring change could
// produce by accident.
func TestCreateContainer_EncryptedWithoutAResolvedPoolFails(t *testing.T) {
	s := &ContainerServer{
		// A provider is present, so validateEncryption lets the request
		// through...
		keyProvider: stubProvider{},
		// ...but the hooks are not wired, so no pool can be resolved.
		encryption: nil,
	}

	_, err := s.CreateContainer(tenantWithScopes("alice", auth.ScopeContainersWrite),
		&pb.CreateContainerRequest{Username: "alice", Encrypted: true})
	if err == nil {
		t.Fatal("an encrypted create with no resolvable storage pool succeeded — the container " +
			"would land on the daemon's default pool, unencrypted, and be reported as encrypted")
	}
	if got := status.Code(err); got != codes.FailedPrecondition && got != codes.Internal {
		t.Errorf("code = %v, want FailedPrecondition or Internal", got)
	}
	// The operator has to be able to tell this from a caller error.
	if !strings.Contains(err.Error(), "pool") {
		t.Errorf("the error does not mention the storage pool, so nobody can act on it: %v", err)
	}
}

// A create that asks for encryption on a daemon with no key custody is still
// refused, and still with FAILED_PRECONDITION — the OSS default is unchanged
// by this wiring. #1294's unconditional refusal is gone because the create
// path now does provision encrypted storage; validateEncryption's
// provider-nil refusal is what keeps the promise honest until #1342.
func TestCreateContainer_StillRefusesEncryptedWithNoKeyProvider(t *testing.T) {
	s := &ContainerServer{}

	_, err := s.CreateContainer(tenantWithScopes("alice", auth.ScopeContainersWrite),
		&pb.CreateContainerRequest{Username: "alice", Encrypted: true})
	if err == nil {
		t.Fatal("an encrypted create succeeded on a daemon with no KeyProvider")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition — a client distinguishes 'not available "+
			"here' from 'your request was malformed' by this code", got)
	}
	if !strings.Contains(err.Error(), "KeyProvider") {
		t.Errorf("the error does not name the missing capability: %v", err)
	}
}

// stubProvider is a KeyProvider that exists but is never expected to be
// called — it is here to get past validateEncryption, not to mint keys.
type stubProvider struct{}

func (stubProvider) Wrap(context.Context, string) (zfskey.Key, zfskey.KeyRef, error) {
	return zfskey.Key{}, zfskey.KeyRef{}, errors.New("stubProvider.Wrap should not be reached")
}

func (stubProvider) Load(context.Context, zfskey.KeyRef) (zfskey.Key, error) {
	return zfskey.Key{}, errors.New("stubProvider.Load should not be reached")
}
