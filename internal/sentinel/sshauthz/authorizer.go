package sshauthz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	AuthorizePath  = "/v1/ssh/authorize"
	DefaultTimeout = 3 * time.Second
	DefaultTTL     = 30 * time.Second
)

// Authorizer uses the generated daemon/cloud contract, never a mirrored DTO.
type Authorizer interface {
	Authorize(context.Context, string, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error)
}

// ErrUpstreamUnavailable is the only error eligible for positive-cache grace.
// HTTP 4xx, malformed responses and local configuration errors must not grant
// grace: they can indicate revoked sentinel trust or a broken contract.
var ErrUpstreamUnavailable = errors.New("SSH authorization upstream unavailable")

// HTTPAuthorizer calls the routed backend, signed with the sentinel's existing
// signer injected by the command. BackendURL is separate from BackendResolver:
// SSH routing addresses and daemon HTTP endpoints are different protocols.
type HTTPAuthorizer struct {
	BackendURL func(string) (string, error)
	Sign       func(*http.Request, []byte)
	Client     *http.Client
	Timeout    time.Duration
}

// Authorize signs the exact generated JSON bytes and sends a bounded query to
// the routed daemon. Only transport/read failures and server errors permit grace.
func (a *HTTPAuthorizer) Authorize(ctx context.Context, backend string, input *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	if a.BackendURL == nil || a.Sign == nil {
		return nil, fmt.Errorf("SSH authorizer requires backend URLs and a signer")
	}
	base, err := a.BackendURL(backend)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("invalid SSH authorization backend URL")
	}
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, err := protojson.Marshal(input)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+AuthorizePath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	a.Sign(req, body)
	client := http.Client{}
	if a.Client != nil {
		client = *a.Client
	}
	// Redirects must not leak sentinel signature headers or silently change the
	// signed destination/method. Copy the injected client, never mutate it.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstreamUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("%w: HTTP %d", ErrUpstreamUnavailable, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SSH authorize HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %v", ErrUpstreamUnavailable, err)
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("SSH authorize response too large")
	}
	out := new(pb.AuthorizeSSHResponse)
	if err := protojson.Unmarshal(data, out); err != nil {
		return nil, fmt.Errorf("decode SSH authorize response: %w", err)
	}
	return out, nil
}
