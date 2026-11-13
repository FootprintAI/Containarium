package client

import (
	"context"
	"errors"
	"fmt"
	"github.com/footprintai/containarium/internal/limitio"
	"net/http"
	"net/url"
	"slices"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The typed client for StartBoxRun (#3609): the daemon-API way to start a run
// on a box, with no SSH session. It is the one place a per-run token
// (StartBoxRunRequest.run_token) is sent from, and it sends one only to a
// daemon that advertises BoxRunTokenCapability; a workdir goes only to a daemon
// that advertises BoxRunWorkdirCapability.

// BoxRunTokenCapability is the SystemInfo.capabilities entry of a daemon that
// honours StartBoxRunRequest.run_token.
const BoxRunTokenCapability = "box_run_token"

// BoxRunTokenUnsupportedMessage is what a caller is told when it has a per-run
// token and the daemon does not advertise BoxRunTokenCapability. Such a daemon
// would accept the field and ignore it, so the run would start without the
// credential; the client refuses instead.
const BoxRunTokenUnsupportedMessage = "this daemon does not take a per-run token (StartBoxRunRequest.run_token, capability " +
	BoxRunTokenCapability + "); upgrade it, or start the run without a token"

// BoxRunWorkdirCapability is the SystemInfo.capabilities entry of a daemon that
// honours StartBoxRunRequest.workdir (#3551).
const BoxRunWorkdirCapability = "box_run_workdir"

// BoxRunWorkdirUnsupportedMessage is what a caller is told when it asks for a
// workdir and the daemon does not advertise BoxRunWorkdirCapability. Over gRPC
// such a daemon would drop the field and start the run in the home, so the
// client refuses instead (#3613).
const BoxRunWorkdirUnsupportedMessage = "this daemon does not take a run workdir (StartBoxRunRequest.workdir, capability " +
	BoxRunWorkdirCapability + "); upgrade it, or start the run without a workdir"

// startBoxRunTimeout bounds one StartBoxRun call: the daemon prepares the run
// user, stages its files and spawns the run before it answers.
const startBoxRunTimeout = 2 * time.Minute

// boxRunCapabilityTimeout bounds the capability read made before a token or a
// workdir is sent.
const boxRunCapabilityTimeout = 10 * time.Second

// requireBoxRunCapabilities refuses a request that carries a token unless the
// daemon advertises BoxRunTokenCapability, and one that names a workdir unless
// it advertises BoxRunWorkdirCapability. capabilities is read at most once, and
// only when the request carries either. No error from here ever holds the
// token.
func requireBoxRunCapabilities(req *pb.StartBoxRunRequest, capabilities func() ([]string, error)) error {
	token, workdir := req.GetRunToken() != "", req.GetWorkdir() != ""
	if !token && !workdir {
		return nil
	}
	caps, err := capabilities()
	if err != nil {
		if token {
			return fmt.Errorf("%s capability check: %w", BoxRunTokenCapability, err)
		}
		return fmt.Errorf("%s capability check: %w", BoxRunWorkdirCapability, err)
	}
	if token && !slices.Contains(caps, BoxRunTokenCapability) {
		return errors.New(BoxRunTokenUnsupportedMessage)
	}
	if workdir && !slices.Contains(caps, BoxRunWorkdirCapability) {
		return errors.New(BoxRunWorkdirUnsupportedMessage)
	}
	return nil
}

// StartBoxRun starts (or resumes) a run on a box via gRPC. A request with a
// run_token is refused with BoxRunTokenUnsupportedMessage unless the daemon
// advertises BoxRunTokenCapability, and one with a workdir with
// BoxRunWorkdirUnsupportedMessage unless it advertises BoxRunWorkdirCapability.
// The daemon's error is returned UNWRAPPED so its code survives (an older
// daemon is codes.Unimplemented).
func (c *GRPCClient) StartBoxRun(req *pb.StartBoxRunRequest) (*pb.StartBoxRunResponse, error) {
	err := requireBoxRunCapabilities(req, func() ([]string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), boxRunCapabilityTimeout)
		defer cancel()
		resp, err := c.client.GetSystemInfo(ctx, &pb.GetSystemInfoRequest{})
		if err != nil {
			return nil, err
		}
		return resp.GetInfo().GetCapabilities(), nil
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), startBoxRunTimeout)
	defer cancel()
	return c.client.StartBoxRun(ctx, req)
}

// StartBoxRun is the REST form (POST /v1/containers/{username}/code-runs),
// with the same token and workdir gates. A daemon refusal comes back as a gRPC
// status with the daemon's code; a 404 from a daemon too old to expose the
// route maps to codes.Unimplemented, as on the gRPC transport.
func (c *HTTPClient) StartBoxRun(req *pb.StartBoxRunRequest) (*pb.StartBoxRunResponse, error) {
	err := requireBoxRunCapabilities(req, func() ([]string, error) {
		info, err := c.getSystemInfo()
		if err != nil {
			return nil, err
		}
		return info.GetCapabilities(), nil
	})
	if err != nil {
		return nil, err
	}
	body, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), startBoxRunTimeout)
	defer cancel()
	path := fmt.Sprintf("/v1/containers/%s/code-runs", url.PathEscape(req.GetUsername()))
	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("start box run: %w", err)
	}
	defer drainClose(resp)
	bodyBytes, _ := limitio.ReadAll(resp.Body, limitio.MaxHTTPResponseBytes)
	if resp.StatusCode >= 400 {
		return nil, boxFileHTTPError(resp.StatusCode, bodyBytes, "StartBoxRun")
	}
	out := &pb.StartBoxRunResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}
