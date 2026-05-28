package wake

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/auth"
)

// WakeStarter starts a container and blocks until its primary route
// is TCP-ready, or until the wake timeout elapses. Returns ready=false
// (with no error) on timeout; returns err only on a hard failure of
// the underlying Start call.
//
// Implemented by an adapter over ContainerServer.StartContainer.
// Defined as an interface so the HTTP handler can be unit-tested
// without standing up Incus.
type WakeStarter interface {
	WakeForRequest(ctx context.Context, username string) (ready bool, containerIP string, port int, err error)
}

// RouteLookup resolves an incoming request's Host header to the
// container that owns the matching route, plus the route's direct
// target so SwapToDirect can be called after the wake completes.
//
// Returns ok=false on no match (we 404 the request).
type RouteLookup interface {
	ResolveByHost(ctx context.Context, host string) (route *app.RouteRecord, ok bool, err error)
}

// AuditLogger records each wake outcome. Same shape as
// autosleep.AuditLogger so we can reuse the existing adapter.
type AuditLogger interface {
	Log(event string, fields map[string]any)
}

// WakeProxy is the HTTP handler mounted at /wake/. When Caddy
// forwards a request to it (because the container is in wake mode),
// the handler wakes the container, then reverse-proxies the request
// through. Concurrent requests for the same container coalesce on a
// single wake — the leader runs the Start, the followers wait on a
// done channel.
type WakeProxy struct {
	starter     WakeStarter
	routeLookup RouteLookup
	router      *Router // for fire-and-forget SwapToDirect after success
	routeStore  RouteStore // for fetching routes to pass to SwapToDirect
	audit       AuditLogger
	waitTimeout time.Duration

	// Phase 1.9 — source-IP allowlist for the wake handler.
	// Empty == permissive rollout mode (loopback always
	// accepted; everything else gated by a startup WARNING).
	trustedProxies []netip.Prefix

	inflightMu sync.Mutex
	inflight   map[string]*inflightWake // key: containerName
}

// SetTrustedProxies configures the source-IP allowlist for the
// wake handler. Pass nil/empty to keep rollout-mode permissive
// (the constructor's default). Typically wired at dual-server
// startup from LoadTrustedProxies().
func (w *WakeProxy) SetTrustedProxies(p []netip.Prefix) {
	w.trustedProxies = p
}

// RouteStore is the narrow interface WakeProxy needs to fetch a
// container's routes for the SwapToDirect callback. Satisfied by
// *app.RouteStore. Separate from RouteLookup so the proxy can do both
// lookups (one for the resolution, one for the swap-back) without
// either being too wide.
type RouteStore interface {
	ListByContainer(ctx context.Context, containerName string) ([]*app.RouteRecord, error)
}

type inflightWake struct {
	done chan struct{}
	ip   string
	port int
	err  error
}

// NewWakeProxy constructs the handler. waitTimeout defaults to 30s
// if zero or negative is passed.
func NewWakeProxy(
	starter WakeStarter,
	routeLookup RouteLookup,
	routeStore RouteStore,
	router *Router,
	audit AuditLogger,
	waitTimeout time.Duration,
) *WakeProxy {
	if waitTimeout <= 0 {
		waitTimeout = 30 * time.Second
	}
	return &WakeProxy{
		starter:     starter,
		routeLookup: routeLookup,
		routeStore:  routeStore,
		router:      router,
		audit:       audit,
		waitTimeout: waitTimeout,
		inflight:    make(map[string]*inflightWake),
	}
}

// ServeHTTP handles a wake request. The container is resolved from the
// incoming Host header (which Caddy preserves on its reverse-proxy
// hop), the container is started, then the request is proxied through
// to the now-running upstream.
//
// httputil.NewSingleHostReverseProxy handles WebSocket upgrades
// correctly out of the box (Go 1.12+), so no extra logic is needed for
// `Upgrade: websocket` requests — they just work.
func (w *WakeProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()

	// Phase 1.9: source-IP gate. Only loopback (Caddy on the
	// same host, the production shape) or explicitly trusted
	// proxies may invoke /wake/. Other sources see 403 — the
	// wake handler is not a public primitive.
	if !isTrustedSource(req, w.trustedProxies) {
		log.Printf("[wake] refused: remote=%s host=%q (not in trusted-proxy allowlist)", req.RemoteAddr, req.Host)
		http.Error(rw, "wake: source not permitted", http.StatusForbidden)
		return
	}

	host := req.Host
	// Strip the daemon-test prefix if present. Caddy proxies the
	// original path through unchanged, but humans hitting the daemon
	// directly to smoke-test the endpoint will send /wake/foo.
	if strings.HasPrefix(req.URL.Path, "/wake/") {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, "/wake")
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
	}

	// Resolve incoming Host → container.
	route, ok, err := w.routeLookup.ResolveByHost(req.Context(), host)
	if err != nil {
		log.Printf("[wake] route lookup for %q: %v", host, err)
		http.Error(rw, "wake: route lookup failed", http.StatusBadGateway)
		return
	}
	if !ok {
		http.Error(rw, "wake: no matching route", http.StatusNotFound)
		return
	}
	containerName := route.ContainerName
	username := strings.TrimSuffix(containerName, "-container")

	// Coalesce concurrent wakes for the same container.
	w.inflightMu.Lock()
	entry, leader := w.inflight[containerName], false
	if entry == nil {
		entry = &inflightWake{done: make(chan struct{})}
		w.inflight[containerName] = entry
		leader = true
	}
	w.inflightMu.Unlock()

	if leader {
		// Leader: run the actual wake on a derived context so
		// followers' cancellations don't abort the whole group.
		//
		// Wake is a daemon-internal action: the inbound request that
		// triggered it may be unauthenticated (a public route, a health
		// probe), but StartContainer is authz-gated (RequireScope +
		// AuthorizeTenant). Stamp the _system identity so the wake call
		// passes those gates — the same pattern the autosleep ticker
		// and peer forwarders use. Without it, every wake fails with
		// "no authenticated subject in request context".
		ctx, cancel := context.WithTimeout(auth.ContextWithSystemIdentity(context.Background()), w.waitTimeout)
		ready, ip, port, werr := w.starter.WakeForRequest(ctx, username)
		cancel()
		if werr != nil {
			entry.err = werr
		} else if !ready {
			entry.err = fmt.Errorf("wake: timeout after %s", w.waitTimeout)
		} else {
			entry.ip = ip
			entry.port = port
			// Fall back to route's target if starter didn't
			// report them (some adapters may not have a cheap
			// IP lookup).
			if entry.ip == "" {
				entry.ip = route.TargetIP
			}
			if entry.port <= 0 {
				entry.port = route.TargetPort
			}
		}
		close(entry.done)
		// Remove ourselves from inflight so the next wake (after
		// the next sleep cycle) starts fresh.
		w.inflightMu.Lock()
		delete(w.inflight, containerName)
		w.inflightMu.Unlock()
	} else {
		// Follower: wait on the leader.
		select {
		case <-entry.done:
		case <-req.Context().Done():
			http.Error(rw, "wake: client cancelled", http.StatusServiceUnavailable)
			return
		}
	}

	latencyMs := time.Since(start).Milliseconds()

	if entry.err != nil {
		w.logEvent(username, latencyMs, "error", entry.err.Error())
		rw.Header().Set("Retry-After", "5")
		http.Error(rw, fmt.Sprintf("wake: %v", entry.err), http.StatusServiceUnavailable)
		return
	}

	// Successful wake. Schedule the SwapToDirect so subsequent
	// requests bypass the daemon. Fire-and-forget — don't block the
	// response on Caddy mutation latency.
	if leader && w.router != nil && w.routeStore != nil {
		go w.scheduleSwapToDirect(containerName)
	}

	w.logEvent(username, latencyMs, "ready", "")

	// Proxy the request through to the container.
	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", entry.ip, entry.port),
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	// Default director rewrites Host to the upstream's; many app
	// backends key on the original Host header for vhost routing, so
	// preserve it. The default also overwrites X-Forwarded-* which is
	// fine here (Caddy already added them; we're the second hop).
	defaultDirector := proxy.Director
	originalHost := req.Host
	proxy.Director = func(r *http.Request) {
		defaultDirector(r)
		r.Host = originalHost
	}
	proxy.ServeHTTP(rw, req)
}

// scheduleSwapToDirect fetches the container's routes and asks the
// router to flip Caddy back to the direct upstream. Best-effort; if
// the lookup or the Caddy mutation fails, RouteSyncJob will eventually
// re-converge (the tracker entry was already cleared by SwapToDirect).
func (w *WakeProxy) scheduleSwapToDirect(containerName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	routes, err := w.routeStore.ListByContainer(ctx, containerName)
	if err != nil {
		log.Printf("[wake] post-wake route lookup for %s: %v", containerName, err)
		return
	}
	if err := w.router.SwapToDirect(ctx, containerName, routes); err != nil {
		log.Printf("[wake] post-wake swap-to-direct for %s: %v", containerName, err)
	}
}

func (w *WakeProxy) logEvent(username string, latencyMs int64, result, errMsg string) {
	fields := map[string]any{
		"username":        username,
		"wake_latency_ms": latencyMs,
		"triggered_by":    "http",
		"result":          result,
	}
	if errMsg != "" {
		fields["error"] = errMsg
	}
	if w.audit != nil {
		w.audit.Log("autosleep.woken", fields)
		return
	}
	log.Printf("[wake] username=%s result=%s latency_ms=%d err=%q", username, result, latencyMs, errMsg)
}
