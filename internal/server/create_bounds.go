package server

import (
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 3.3 / 3.4 — bounds on unbounded proto fields.
//
// CreateContainerRequest's `ssh_keys` (repeated string),
// `stack_parameters` (map<string,string>) and `labels`
// (map<string,string>) had no wire-level caps. A caller could
// submit a million-entry array or a single key/value of megabytes,
// blowing through memory and downstream config-store limits. The
// proto contract isn't changed (would require a regenerate + a
// breaking-change announcement); the bounds live here, at the
// server's API boundary.

const (
	// MaxSSHKeys caps the number of ssh_keys per CreateContainer.
	// A realistic user has 1–5; 32 is a generous power-of-two ceiling.
	MaxSSHKeys = 32

	// MaxSSHKeyLength caps each individual key string. Real
	// ssh-ed25519 keys are ~80 chars; ssh-rsa 4096 ed25519 are
	// ~720. 8 KiB is well above any legitimate key and still small
	// enough that 32 keys total is bounded.
	MaxSSHKeyLength = 8 * 1024

	// MaxStackParameters caps the stack_parameters map cardinality.
	MaxStackParameters = 64

	// MaxStackParameterValueLen caps each stack-parameter value.
	// Stack parameters become container env vars; the kernel's
	// ARG_MAX is 128 KiB on Linux, so 4 KiB per value keeps even a
	// fully-populated map well under the limit.
	MaxStackParameterValueLen = 4 * 1024

	// MaxStackParameterKeyLen caps each stack-parameter key.
	MaxStackParameterKeyLen = 256

	// MaxLabels caps the labels map cardinality.
	MaxLabels = 64

	// MaxLabelKeyLen / MaxLabelValueLen — labels show up in Incus
	// config, which has its own length limits. 256 chars per
	// component is comfortably within those.
	MaxLabelKeyLen   = 256
	MaxLabelValueLen = 256
)

// validateCreateContainerBounds enforces the size caps above on
// req. Returns nil if every field is within bounds; otherwise a
// gRPC InvalidArgument status that names the offending field +
// limit so the caller can fix.
func validateCreateContainerBounds(req *pb.CreateContainerRequest) error {
	if n := len(req.SshKeys); n > MaxSSHKeys {
		return status.Errorf(codes.InvalidArgument,
			"ssh_keys has %d entries, max is %d", n, MaxSSHKeys)
	}
	for i, key := range req.SshKeys {
		if n := len(key); n > MaxSSHKeyLength {
			return status.Errorf(codes.InvalidArgument,
				"ssh_keys[%d] is %d bytes, max is %d", i, n, MaxSSHKeyLength)
		}
	}

	if n := len(req.StackParameters); n > MaxStackParameters {
		return status.Errorf(codes.InvalidArgument,
			"stack_parameters has %d entries, max is %d", n, MaxStackParameters)
	}
	for k, v := range req.StackParameters {
		if n := len(k); n > MaxStackParameterKeyLen {
			return status.Errorf(codes.InvalidArgument,
				"stack_parameters key is %d bytes, max is %d", n, MaxStackParameterKeyLen)
		}
		if n := len(v); n > MaxStackParameterValueLen {
			return status.Errorf(codes.InvalidArgument,
				"stack_parameters[%q] value is %d bytes, max is %d", k, n, MaxStackParameterValueLen)
		}
	}

	if n := len(req.Labels); n > MaxLabels {
		return status.Errorf(codes.InvalidArgument,
			"labels has %d entries, max is %d", n, MaxLabels)
	}
	for k, v := range req.Labels {
		if n := len(k); n > MaxLabelKeyLen {
			return status.Errorf(codes.InvalidArgument,
				"labels key is %d bytes, max is %d", n, MaxLabelKeyLen)
		}
		if n := len(v); n > MaxLabelValueLen {
			return status.Errorf(codes.InvalidArgument,
				"labels[%q] value is %d bytes, max is %d", k, n, MaxLabelValueLen)
		}
	}

	return nil
}
