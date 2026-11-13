package client

import (
	"encoding/json"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

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

// bootstrapHTTPError turns a >= 400 ApplyBoxBootstrap response into a gRPC
// status error with the daemon's code and details. The daemon's gateway
// (gateway.ErrorHandler) writes {"error":"rpc error: code = X desc = ...",
// "code":<HTTP status>,"message":...,"details":[...]}: the gRPC code is read
// from the error text (the "code" field is the HTTP status), the old-daemon
// case is the mux's own 404 ("Not Found"), as in boxFileHTTPError, and each
// detail is decoded back into the status so BootstrapFailureOf works over REST.
func bootstrapHTTPError(statusCode int, body []byte) error {
	base := boxFileHTTPError(statusCode, body, "ApplyBoxBootstrap")
	st, ok := status.FromError(base)
	if !ok || st.Code() == codes.Unimplemented || st.Code() == codes.Unknown || len(st.Proto().GetDetails()) > 0 {
		return base
	}
	var b struct {
		Details []json.RawMessage `json:"details"`
	}
	if json.Unmarshal(body, &b) != nil || len(b.Details) == 0 {
		return base
	}
	p := st.Proto()
	for _, raw := range b.Details {
		var a anypb.Any
		if err := protojson.Unmarshal(raw, &a); err == nil {
			p.Details = append(p.Details, &a)
		}
	}
	return status.ErrorProto(p)
}
