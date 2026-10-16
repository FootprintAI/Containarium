package sshauthz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const AuthorizePath = "/v1/ssh/authorize"

// HTTPAuthorizer speaks the generated grpc-gateway JSON contract. Sign is the
// existing sentinel signer; BackendURL is resolved anew on every cache miss.
type HTTPAuthorizer struct {
	BackendURL func(string) (string, error)
	Sign       func(*http.Request)
	Client     *http.Client
}

type HTTPError struct{ Status int }

// ProtocolError is an invalid answer, rather than an outage eligible for grace.
type ProtocolError struct{ Err error }

func (e *ProtocolError) Error() string { return e.Err.Error() }
func (e *ProtocolError) Unwrap() error { return e.Err }

func (e *HTTPError) Error() string { return fmt.Sprintf("ssh authorization HTTP %d", e.Status) }
func isOutage(err error) bool {
	var invalid *ProtocolError
	if errors.As(err, &invalid) {
		return false
	}
	var status *HTTPError
	if errors.As(err, &status) {
		return status.Status >= 500
	}
	return true
}

func (a *HTTPAuthorizer) Authorize(ctx context.Context, backend string, in *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	base, err := a.BackendURL(backend)
	if err != nil {
		return nil, err
	}
	body, err := protojson.Marshal(in)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+AuthorizePath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.Sign != nil {
		a.Sign(req)
	}
	client := &http.Client{}
	if a.Client != nil {
		*client = *a.Client
	}
	// A redirect must never leak the signature or turn a failed authorization
	// endpoint into an apparent allow from a different server.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{Status: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, &ProtocolError{errors.New("authorization response too large")}
	}
	out := &pb.AuthorizeSSHResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, out); err != nil {
		return nil, &ProtocolError{err}
	}
	return out, nil
}
