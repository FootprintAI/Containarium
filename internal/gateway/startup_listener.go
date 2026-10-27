package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/version"
)

// healthStatus is the /health "status" value.
type healthStatus string

const (
	healthStatusHealthy healthStatus = "healthy"
	// healthStatusDegraded: the daemon is up and answering, but a dependency
	// is not ready yet (#3130). Served with HTTP 200 on purpose — the
	// backend is live, and a liveness probe or tunnel must not treat it as
	// down.
	healthStatusDegraded healthStatus = "degraded"
)

// startupRetryAfterSeconds is the Retry-After hint on the 503s served while
// the daemon is starting.
const startupRetryAfterSeconds = "5"

// StartupListener binds the daemon's HTTP port before the startup waits
// (core containers, Postgres) so the backend is reachable while they run
// (#3130). Until Serve hands it the real gateway handler it answers /health
// with status "degraded" and the current reason, and every other path with
// 503 Service Unavailable — nothing that needs a not-yet-ready dependency is
// served half-initialised.
//
// The listener is never closed in between: Serve swaps the handler on the
// same http.Server, so there is no window where connections are refused.
type StartupListener struct {
	lis net.Listener
	srv *http.Server

	mu      sync.RWMutex
	reason  string
	handler http.Handler // nil until Serve

	done    chan struct{}
	serveMu sync.Mutex
	err     error
}

// ListenStartup binds addr and starts serving the startup responses with
// reason. reason must be a fixed operator-facing phrase, never an error
// string: /health is unauthenticated.
func ListenStartup(addr, reason string) (*StartupListener, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind %s for the startup health endpoint: %w", addr, err)
	}
	sl := &StartupListener{lis: lis, reason: reason, done: make(chan struct{})}
	sl.srv = &http.Server{Handler: sl, ReadHeaderTimeout: 30 * time.Second}
	go func() {
		err := sl.srv.Serve(lis)
		sl.serveMu.Lock()
		sl.err = err
		sl.serveMu.Unlock()
		close(sl.done)
	}()
	return sl, nil
}

// Addr is the bound address.
func (sl *StartupListener) Addr() net.Addr { return sl.lis.Addr() }

// SetReason updates the reason /health reports while the daemon is starting.
func (sl *StartupListener) SetReason(reason string) {
	sl.mu.Lock()
	sl.reason = reason
	sl.mu.Unlock()
}

// Serve installs h as the handler for every request from now on and blocks
// until the server stops. It returns nil after Close.
func (sl *StartupListener) Serve(h http.Handler) error {
	sl.mu.Lock()
	sl.handler = h
	sl.mu.Unlock()
	<-sl.done
	sl.serveMu.Lock()
	defer sl.serveMu.Unlock()
	if errors.Is(sl.err, http.ErrServerClosed) {
		return nil
	}
	return sl.err
}

// Close stops the server and releases the port before it returns.
//
// srv.Close alone is not enough: if the serve goroutine has not registered
// the listener yet, Close returns while the port is still bound, and a
// gateway rebinding right after would race it. So close the listener here
// too and wait for the serve loop to exit.
func (sl *StartupListener) Close() error {
	err := sl.srv.Close()
	_ = sl.lis.Close()
	<-sl.done
	return err
}

// ServeHTTP dispatches to the handed-over handler, or serves the startup
// responses until there is one.
func (sl *StartupListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sl.mu.RLock()
	h, reason := sl.handler, sl.reason
	sl.mu.RUnlock()
	if h != nil {
		h.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(healthResponse{
			Status:  healthStatusDegraded,
			Reason:  reason,
			Version: version.GetVersion(),
		})
		return
	}
	w.Header().Set("Retry-After", startupRetryAfterSeconds)
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(startupUnavailableResponse{
		Error: "daemon is starting: " + reason,
		Code:  http.StatusServiceUnavailable,
	})
}

// startupUnavailableResponse matches the gateway's {"error","code"} shape.
type startupUnavailableResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}
