package server

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// CreateContainerRequest.encrypted was accepted and never read (#1199).
//
// The proto says the request "fails with FAILED_PRECONDITION; it never falls
// back to plaintext, because a create that silently ignores this flag would
// hand the caller an encryption guarantee they do not have". The CLI help
// says the same. The server did neither: it created an ordinary container on
// the pool-wide key and reported success.
//
// That is worse than an unimplemented feature. An operator who runs
// `containarium create --encrypted` gets a container they believe is
// tenant-encrypted, and nothing anywhere tells them otherwise.
func TestCreateContainer_RefusesEncryptedRatherThanIgnoringIt(t *testing.T) {
	s := &ContainerServer{}

	_, err := s.CreateContainer(tenantWithScopes("alice", auth.ScopeContainersWrite), &pb.CreateContainerRequest{
		Username:  "alice",
		Encrypted: true,
	})
	if err == nil {
		t.Fatal("a create asking for encryption succeeded — the container would be on the " +
			"pool-wide key and the caller would never know")
	}

	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition — the proto names that code specifically, "+
			"so a client can tell 'not available here' from 'your request was malformed'", got)
	}
	// The caller has to be able to act on this, which means knowing it is a
	// daemon capability gap rather than something they got wrong.
	if !strings.Contains(err.Error(), "not available") {
		t.Errorf("the error does not say the capability is missing: %v", err)
	}
}

// The refusal must not preempt basic request validation: a malformed request
// should still be told what is malformed, not handed a capability error that
// sends the caller looking in the wrong place.
//
// (The mirror case — an unencrypted create being unaffected — is not
// assertable here: a bare ContainerServer panics further down the create
// path, so reaching that point needs a wired backend. Stated rather than
// silently omitted.)
func TestCreateContainer_EncryptionRefusalDoesNotPreemptValidation(t *testing.T) {
	s := &ContainerServer{}

	_, err := s.CreateContainer(tenantWithScopes("alice", auth.ScopeContainersWrite),
		&pb.CreateContainerRequest{Username: "", Encrypted: true})
	if err == nil {
		t.Fatal("a request with no username succeeded")
	}
	if strings.Contains(err.Error(), "per-container encryption") {
		t.Errorf("a request missing its username was refused for encryption instead: %v — the "+
			"caller would go looking at daemon capabilities for a typo", err)
	}
}
