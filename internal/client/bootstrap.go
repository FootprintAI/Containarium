package client

import (
	"strconv"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// BoxBootstrapApplier is what applying a bootstrap bundle through the daemon
// needs from a client (#3694); both GRPCClient and HTTPClient satisfy it.
type BoxBootstrapApplier interface {
	ApplyBoxBootstrap(req *pb.ApplyBoxBootstrapRequest) (*pb.ApplyBoxBootstrapResponse, error)
}

// BootstrapFailureOf returns the typed reason of an ApplyBoxBootstrap error
// and, for a failure of the bundle step, the bundle script's exit code (the
// same one `code install --bootstrap-url` reports). An error without the
// google.rpc.ErrorInfo detail is UNSPECIFIED, 0.
func BootstrapFailureOf(err error) (pb.BoxBootstrapFailure, int) {
	st, ok := status.FromError(err)
	if !ok || err == nil {
		return pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_UNSPECIFIED, 0
	}
	for _, d := range st.Details() {
		info, ok := d.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}
		v, known := pb.BoxBootstrapFailure_value[info.GetReason()]
		if !known {
			continue
		}
		code, _ := strconv.Atoi(info.GetMetadata()["exit_code"])
		return pb.BoxBootstrapFailure(v), code
	}
	return pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_UNSPECIFIED, 0
}
