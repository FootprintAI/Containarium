package client

import (
	"context"
	"fmt"
	"io"
	"net/http"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// sshAuthzAuthorizePath is the REST route grpc-gateway maps
// SSHAuthzService.Authorize to (ssh_authz.proto).
const sshAuthzAuthorizePath = "/v1/ssh/authorize"

// AuthorizeSSH asks the daemon's SSHAuthzService.Authorize (#2516) whether
// req's credential may open a session as req.Login. The client's token must
// carry the ssh:authorize scope and the daemon must run with
// --ssh-authz-keys-command; otherwise the route is sentinel-only (#2527).
//
// A DENY is a normal response, not an error. An error means no decision was
// made (transport failure, non-2xx status, undecodable body); the caller
// decides what that means for the login. The deadline comes from ctx.
func (c *HTTPClient) AuthorizeSSH(ctx context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	body, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, sshAuthzAuthorizePath, body)
	if err != nil {
		return nil, fmt.Errorf("authorize ssh: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "authorize ssh")
	}
	out := &pb.AuthorizeSSHResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}
