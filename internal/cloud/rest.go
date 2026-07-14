package cloud

// REST transport for the cloud actuation channel (OSS #722).
//
// The gRPC transport (client.go) only works against a control plane that
// serves native gRPC. A managed cloud (e.g. cloud.containarium.dev) often
// fronts the API as REST/grpc-gateway ONLY — native gRPC over :443 there
// returns 403/text-html. A BYO-compute host enrolled against such a control
// plane therefore couldn't enroll, heartbeat, or report its capability, which
// left the host's capacity "unknown" in the operator view and made the
// host-sweeper treat the never-heartbeating host as stranded.
//
// This transport speaks the SAME actuation RPCs over their grpc-gateway REST
// mappings (POST /v1/actuation/{heartbeat,status,enroll}), carrying the host
// bearer as the `Grpc-Metadata-Host-Bearer` header — grpc-gateway strips the
// `Grpc-Metadata-` prefix and forwards it as the `host-bearer` metadata the
// HostBearerInterceptor authenticates on. Requests/responses are the OSS proto
// types via protojson, so the wire matches the gateway by construction.
//
// WatchAssignments (server-streaming) is NOT implemented here: a BYOC host is
// push-driven (the cloud drives it via the sentinel peer-proxy), so it has no
// assignments to pull. REST mode therefore runs heartbeat + status only.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
)

// isRESTControlPlane reports whether the control-plane address is an http(s)
// URL (REST/grpc-gateway) rather than a gRPC host:port. An https:// or http://
// prefix selects the REST transport.
func isRESTControlPlane(controlPlane string) bool {
	cp := strings.TrimSpace(controlPlane)
	return strings.HasPrefix(cp, "https://") || strings.HasPrefix(cp, "http://")
}

// restActuation implements the unary actuation RPCs (Heartbeat, ReportHostStatus)
// over grpc-gateway REST. It satisfies the unaryActuation interface the client
// uses; the gRPC CallOption args are accepted and ignored.
type restActuation struct {
	base   string // control-plane base URL, no trailing slash
	bearer string // host bearer, sent as Grpc-Metadata-Host-Bearer (empty for enroll, which self-auths via the join token)
	hc     *http.Client
}

func newRESTActuation(controlPlane, bearer string) *restActuation {
	return &restActuation{
		base:   strings.TrimRight(strings.TrimSpace(controlPlane), "/"),
		bearer: bearer,
		hc:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (r *restActuation) Heartbeat(ctx context.Context, req *cloudv1.HeartbeatRequest, _ ...grpc.CallOption) (*cloudv1.HeartbeatResponse, error) {
	var resp cloudv1.HeartbeatResponse
	if err := r.post(ctx, "/v1/actuation/heartbeat", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (r *restActuation) ReportHostStatus(ctx context.Context, req *cloudv1.ReportHostStatusRequest, _ ...grpc.CallOption) (*cloudv1.ReportHostStatusResponse, error) {
	var resp cloudv1.ReportHostStatusResponse
	if err := r.post(ctx, "/v1/actuation/status", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// post sends one protojson request to the control plane and decodes the
// protojson response. The host bearer (when set) rides the
// `Grpc-Metadata-Host-Bearer` header → `host-bearer` gRPC metadata at the gateway.
func (r *restActuation) post(ctx context.Context, path string, in, out proto.Message) error {
	body, err := protojson.Marshal(in)
	if err != nil {
		return fmt.Errorf("cloud-rest: marshal %s: %w", path, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.base+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cloud-rest: build %s: %w", path, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if r.bearer != "" {
		httpReq.Header.Set("Grpc-Metadata-Host-Bearer", r.bearer)
	}
	resp, err := r.hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("cloud-rest: POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("cloud-rest: POST %s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if len(raw) == 0 {
		return nil
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, out); err != nil {
		return fmt.Errorf("cloud-rest: decode %s: %w", path, err)
	}
	return nil
}

// enrollREST redeems a join token over REST (POST /v1/actuation/enroll). The
// join token self-authenticates in the body, so no host bearer is sent. See
// Enroll's doc comment for why the returned bearer is rebuilt rather than the
// raw joinToken being reused verbatim.
func enrollREST(ctx context.Context, controlPlane, joinToken string, opts EnrollOptions) (hostID, bearerToken string, err error) {
	r := newRESTActuation(controlPlane, "")
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var resp cloudv1.EnrollHostResponse
	if err := r.post(ctx, "/v1/actuation/enroll", &cloudv1.EnrollHostRequest{
		JoinToken:    joinToken,
		DriverToken:  opts.DriverToken,
		OssBackendId: opts.OSSBackendID,
	}, &resp); err != nil {
		return "", "", fmt.Errorf("cloud: enroll (REST): %w", err)
	}
	return resp.GetHostId(), rebuildBearer(resp.GetHostId(), joinToken), nil
}
