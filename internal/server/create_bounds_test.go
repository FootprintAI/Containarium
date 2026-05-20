package server

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 3.3 / 3.4 — bounds enforcement.

func TestValidateBounds_AcceptsRealisticRequest(t *testing.T) {
	req := &pb.CreateContainerRequest{
		SshKeys: []string{"ssh-ed25519 AAAA... user@host"},
		StackParameters: map[string]string{
			"FOO": "bar",
			"BAZ": "qux",
		},
		Labels: map[string]string{
			"role": "test",
			"team": "platform",
		},
	}
	if err := validateCreateContainerBounds(req); err != nil {
		t.Fatalf("typical small request should pass: %v", err)
	}
}

func TestValidateBounds_RejectsTooManySSHKeys(t *testing.T) {
	keys := make([]string, MaxSSHKeys+1)
	for i := range keys {
		keys[i] = "ssh-ed25519 AAAA..."
	}
	req := &pb.CreateContainerRequest{SshKeys: keys}
	err := validateCreateContainerBounds(req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v (%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "ssh_keys") {
		t.Fatalf("error should name the offending field: %v", err)
	}
}

func TestValidateBounds_RejectsOversizedSSHKey(t *testing.T) {
	huge := strings.Repeat("A", MaxSSHKeyLength+1)
	req := &pb.CreateContainerRequest{SshKeys: []string{huge}}
	err := validateCreateContainerBounds(req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", status.Code(err))
	}
}

func TestValidateBounds_RejectsTooManyStackParameters(t *testing.T) {
	params := make(map[string]string, MaxStackParameters+1)
	for i := 0; i <= MaxStackParameters; i++ {
		params[string(rune('A'+i))+strings.Repeat("a", 3)] = "v"
	}
	req := &pb.CreateContainerRequest{StackParameters: params}
	err := validateCreateContainerBounds(req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", status.Code(err))
	}
}

func TestValidateBounds_RejectsOversizedStackParamValue(t *testing.T) {
	req := &pb.CreateContainerRequest{
		StackParameters: map[string]string{
			"BIG_VAR": strings.Repeat("x", MaxStackParameterValueLen+1),
		},
	}
	err := validateCreateContainerBounds(req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", status.Code(err))
	}
	if !strings.Contains(err.Error(), "BIG_VAR") {
		t.Fatalf("error should name the offending key: %v", err)
	}
}

func TestValidateBounds_RejectsOversizedStackParamKey(t *testing.T) {
	req := &pb.CreateContainerRequest{
		StackParameters: map[string]string{
			strings.Repeat("K", MaxStackParameterKeyLen+1): "v",
		},
	}
	err := validateCreateContainerBounds(req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", status.Code(err))
	}
}

func TestValidateBounds_RejectsTooManyLabels(t *testing.T) {
	labels := make(map[string]string, MaxLabels+1)
	for i := 0; i <= MaxLabels; i++ {
		labels["k"+strings.Repeat("a", i+1)] = "v"
	}
	req := &pb.CreateContainerRequest{Labels: labels}
	err := validateCreateContainerBounds(req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", status.Code(err))
	}
}

func TestValidateBounds_RejectsOversizedLabelValue(t *testing.T) {
	req := &pb.CreateContainerRequest{
		Labels: map[string]string{
			"role": strings.Repeat("x", MaxLabelValueLen+1),
		},
	}
	err := validateCreateContainerBounds(req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", status.Code(err))
	}
}

func TestValidateBounds_EmptyRequestPasses(t *testing.T) {
	// Nil / empty fields should be fine — the bounds are on the
	// upper end only.
	req := &pb.CreateContainerRequest{}
	if err := validateCreateContainerBounds(req); err != nil {
		t.Fatalf("empty request should pass: %v", err)
	}
}
