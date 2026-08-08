package server

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// AC: `encrypted=true` with no KeyProvider wired fails with
// FAILED_PRECONDITION — never a silent fall back to plaintext.
//
// This is the criterion the whole flag exists for. A create that accepts
// "encrypt this" and quietly provisions an unencrypted dataset hands the
// caller a guarantee they do not have, and they find out during an audit
// rather than at create time.
func TestValidateEncryptionRequiresAKeyProvider(t *testing.T) {
	err := validateEncryption(&pb.CreateContainerRequest{Encrypted: true}, nil)
	if err == nil {
		t.Fatal("encrypted=true was accepted with no KeyProvider — the request must fail rather than silently produce plaintext")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", got)
	}
	if !strings.Contains(err.Error(), "KeyProvider") {
		t.Errorf("error should name the missing dependency, got %q", err)
	}
}

// With a provider wired, an encrypted create is accepted.
func TestValidateEncryptionAcceptedWithAProvider(t *testing.T) {
	provider, err := zfskey.NewFileKeyProvider(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}
	if err := validateEncryption(&pb.CreateContainerRequest{Encrypted: true}, provider); err != nil {
		t.Errorf("encrypted create rejected despite a wired provider: %v", err)
	}
}

// AC: the default path is unchanged. encrypted=false must not require a
// provider — the overwhelming majority of creates are unencrypted and
// must not start failing on a daemon with no key custody configured.
func TestValidateEncryptionIgnoredWhenNotRequested(t *testing.T) {
	if err := validateEncryption(&pb.CreateContainerRequest{}, nil); err != nil {
		t.Errorf("a plain create must not need a KeyProvider: %v", err)
	}
	if err := validateEncryption(&pb.CreateContainerRequest{Encrypted: false}, nil); err != nil {
		t.Errorf("encrypted=false must not need a KeyProvider: %v", err)
	}
}

// AC: the OSS daemon rejects a non-default tenant_id with
// INVALID_ARGUMENT.
//
// The field is defined on the proto so the wire shape stays stable into
// the multi-tenant cloud build, but accepting a tenant here would be a
// lie: this daemon has no tenancy, so every "tenant" would share one
// encryptionroot and the isolation the field implies would not exist.
func TestValidateTenantIDRejectsRealTenantsOnOSS(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tenantID string
		wantErr  bool
	}{
		{"unset is fine", "", false},
		{"explicit default is fine", "default", false},
		{"a real tenant is rejected", "acme-corp", true},
		{"another tenant is rejected", "org-alice", true},
		{"whitespace is not a smuggled default", "  ", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTenantID(tc.tenantID)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("tenant_id %q was accepted by a single-tenant daemon", tc.tenantID)
				}
				if got := status.Code(err); got != codes.InvalidArgument {
					t.Errorf("code = %v, want InvalidArgument", got)
				}
				return
			}
			if err != nil {
				t.Errorf("tenant_id %q rejected: %v", tc.tenantID, err)
			}
		})
	}
}

// The rejection has to explain itself: an operator hitting this is using
// a field the proto documents as valid, and needs to know it is the
// build, not the request, that is limited.
func TestTenantIDRejectionIsActionable(t *testing.T) {
	err := validateTenantID("acme-corp")
	if err == nil {
		t.Fatal("expected rejection")
	}
	msg := strings.ToLower(err.Error())
	for _, want := range []string{"tenant", "single-tenant"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message should mention %q so the caller understands why; got %q", want, err)
		}
	}
}
