package sshcontrol

import (
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// DefaultSocket is shared by both local SSH listeners, never publicly bound.
	DefaultSocket = "/run/containarium/ssh-upstream/control.sock"
	// DefaultState retains rolling jail risk across sentinel/plugin restarts.
	DefaultState = "/var/lib/containarium/ssh-upstream/risk.json"
)

// ParsePolicy uses the generated contract and rejects unknown configuration keys.
func ParsePolicy(data []byte) (*pb.SSHUpstreamPolicy, error) {
	p := &pb.SSHUpstreamPolicy{}
	if err := protojson.Unmarshal(data, p); err != nil {
		return nil, err
	}
	return p, nil
}
