package sshsession

import (
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func proto_clone(p *pb.SSHSessionRecord) *pb.SSHSessionRecord {
	return proto.Clone(p).(*pb.SSHSessionRecord)
}
