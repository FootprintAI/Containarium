package sshauthz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const DefaultSocket = "/run/containarium/ssh-authz.sock"

type route struct {
	Backend string `json:"backend"`
	Known   bool   `json:"known"`
}

type readiness struct {
	Ready bool `json:"ready"`
}

// BridgeClient joins the separate sshpiperd plugin process to the manager's
// live keystore. Only the manager needs access to sentinel signing secrets.
type BridgeClient struct{ client *http.Client }

func NewBridgeClient(socket string) *BridgeClient {
	return &BridgeClient{client: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}}
}

func (b *BridgeClient) ResolveBackend(ctx context.Context, login string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sentinel/route?login="+url.QueryEscape(login), nil)
	if err != nil {
		return "", false, err
	}
	res, err := b.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", false, &HTTPError{Status: res.StatusCode}
	}
	var out route
	if err := json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&out); err != nil {
		return "", false, err
	}
	if out.Known && out.Backend == "" {
		return "", false, errors.New("empty backend in route")
	}
	return out.Backend, out.Known, nil
}

// RoutingReady asks the manager whether its keystore has synced every healthy
// backend. Any failure reads as not ready: the enforcing plugin refuses the
// unknown login either way, and "not synced" is the safer thing to log.
func (b *BridgeClient) RoutingReady(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sentinel/ready", nil)
	if err != nil {
		return false
	}
	res, err := b.client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false
	}
	var out readiness
	if err := json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&out); err != nil {
		return false
	}
	return out.Ready
}

func (b *BridgeClient) Authorize(ctx context.Context, backend string, in *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= 0 {
		return nil, context.DeadlineExceeded
	}
	// Put the backend in the path prefix; HTTPAuthorizer appends AuthorizePath.
	a := &HTTPAuthorizer{Client: b.client, BackendURL: func(string) (string, error) { return "http://sentinel/backend/" + url.PathEscape(backend), nil }, Sign: func(r *http.Request) {
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining > 0 {
				r.Header.Set("X-SSH-Authz-Timeout", remaining.String())
			}
		}
	}}
	return a.Authorize(ctx, backend, in)
}

// BridgeHandler is local infrastructure plumbing, never a TCP gateway route.
// The backend is checked against the current login route before forwarding.
func BridgeHandler(resolver BackendResolver, authorizer Authorizer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /route", func(w http.ResponseWriter, r *http.Request) {
		backend, known, err := resolver.ResolveBackend(r.Context(), r.URL.Query().Get("login"))
		if err != nil {
			http.Error(w, "routing unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(route{Backend: backend, Known: known})
	})
	// A resolver without a readiness signal is always authoritative.
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		ready := true
		if rr, ok := resolver.(RoutingReadiness); ok {
			ready = rr.RoutingReady(r.Context())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(readiness{Ready: ready})
	})
	mux.HandleFunc("POST /backend/{backend}"+AuthorizePath, func(w http.ResponseWriter, r *http.Request) {
		timeout := DefaultTimeout
		if header := r.Header.Get("X-SSH-Authz-Timeout"); header != "" {
			var err error
			timeout, err = time.ParseDuration(header)
			if err != nil || timeout <= 0 {
				http.Error(w, "invalid timeout", http.StatusBadRequest)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		req := &pb.AuthorizeSSHRequest{}
		if err := protojson.Unmarshal(raw, req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		backend, known, err := resolver.ResolveBackend(r.Context(), req.GetLogin())
		if err != nil {
			http.Error(w, "routing unavailable", http.StatusServiceUnavailable)
			return
		}
		if !known || backend != r.PathValue("backend") {
			http.Error(w, "login route changed", http.StatusConflict)
			return
		}
		res, err := authorizer.Authorize(ctx, backend, req)
		if err != nil {
			status := http.StatusServiceUnavailable
			var invalid *ProtocolError
			if errors.As(err, &invalid) {
				status = http.StatusUnprocessableEntity
			}
			var upstream *HTTPError
			if errors.As(err, &upstream) {
				status = upstream.Status
			}
			http.Error(w, "authorization unavailable", status)
			return
		}
		raw, err = protojson.Marshal(res)
		if err != nil {
			http.Error(w, fmt.Sprint(err), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})
	return mux
}
