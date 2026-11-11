package server

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/container"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// validateRecipeSSHKeys applies CreateContainer's ssh_keys rules to a recipe
// deploy's keys (#3514): the count and size bounds of
// validateCreateContainerBounds (MaxSSHKeys, MaxSSHKeyLength), then
// container.ValidateSSHPublicKey per key. It runs before the deploy does
// anything, so a refused key leaves no box, no guardrail snapshot and no
// post_start behind, and it answers InvalidArgument naming the offending
// field (the inner create would only surface it wrapped as Internal).
func validateRecipeSSHKeys(keys []string) error {
	if err := validateCreateContainerBounds(&pb.CreateContainerRequest{SshKeys: keys}); err != nil {
		return err
	}
	for i, key := range keys {
		if err := container.ValidateSSHPublicKey(key); err != nil {
			return status.Errorf(codes.InvalidArgument, "ssh_keys[%d]: %v", i, err)
		}
	}
	return nil
}
