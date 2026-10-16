package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SSH session control (#2522): ContainerService.TerminateUserSessions on both
// transports. `containarium sessions terminate` and the platform MCP tool
// terminate_user_sessions both call through here.

const sessionsTimeout = 30 * time.Second

// SessionsAPI is the transport-independent view of the session RPCs.
type SessionsAPI interface {
	TerminateUserSessions(username string) (*pb.TerminateUserSessionsResponse, error)
	Close() error
}

var (
	_ SessionsAPI = (*GRPCClient)(nil)
	_ SessionsAPI = (*HTTPClient)(nil)
)

// TerminateUserSessionsPath is the REST path of TerminateUserSessions.
func TerminateUserSessionsPath(username string) string {
	return fmt.Sprintf("/v1/users/%s/sessions:terminate", url.PathEscape(username))
}

// TerminateUserSessions ends every live SSH session username holds on the
// backend, via gRPC.
func (c *GRPCClient) TerminateUserSessions(username string) (*pb.TerminateUserSessionsResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sessionsTimeout)
	defer cancel()
	resp, err := c.client.TerminateUserSessions(ctx, &pb.TerminateUserSessionsRequest{Username: username})
	if err != nil {
		return nil, fmt.Errorf("terminate user sessions: %w", err)
	}
	return resp, nil
}

// TerminateUserSessions ends every live SSH session username holds on the
// backend, via REST.
func (c *HTTPClient) TerminateUserSessions(username string) (*pb.TerminateUserSessionsResponse, error) {
	out := &pb.TerminateUserSessionsResponse{}
	if err := c.trackerDoTimeout(sessionsTimeout, http.MethodPost,
		TerminateUserSessionsPath(username), "terminate user sessions", []byte("{}"), out); err != nil {
		return nil, err
	}
	return out, nil
}
