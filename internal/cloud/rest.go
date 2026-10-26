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
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

	// mu guards consecutive5xx. Heartbeat, status and trust-bundle calls
	// can run concurrently on one client.
	mu             sync.Mutex
	consecutive5xx int
	recyclePending bool // set at the threshold; honoured at the start of the next request

	// Bounded connection lifetime (#3113). hc is the current client; once its
	// transport is older than maxTransportAge, the next request swaps in a
	// fresh clone and retires the old client. Retired clients keep serving
	// their in-flight requests and are closed once drained. All guarded by mu.
	now           func() time.Time // injectable clock
	transportBorn time.Time
	inflight      map[*http.Client]int
	retired       []*retiredClient
}

// retiredClient is a swapped-out client waiting to drain.
type retiredClient struct {
	hc *http.Client
	// idleSwept is set when a sweep found it with no in-flight request and
	// closed its idle connections; a second such sweep drops it. Two passes
	// because an HTTP/2 stream is released asynchronously after its body is
	// closed, so the first close can find the connection still busy.
	idleSwept bool
}

// maxTransportAge bounds how long one transport, and so one pooled
// connection, serves new requests (#3113). Go's http.Transport has no
// maximum connection age, and CloseIdleConnections cannot close an HTTP/2
// connection that always has a stream in flight, so a continuously busy
// connection could stay pinned to a moved origin. After this age the next
// request goes to a fresh transport (a new dial); the old one finishes its
// in-flight requests undisturbed and is then closed. A connection therefore
// lives at most maxTransportAge plus the duration of its longest request.
// Swapping, rather than closing the connection from a dialer wrapper, never
// aborts an in-flight request.
const maxTransportAge = 15 * time.Minute

// recycleAfter5xx is how many consecutive 5xx responses make the client drop
// its pooled connections so the next request redials (#3077). A heartbeat
// every ~30s keeps one pooled HTTP/2 connection in use, so it is never
// idle-timed-out; if the control plane's origin moves behind the same
// hostname, that connection can stay pinned to the old origin at the edge and
// answer 502 until something closes it.
//
// Limit: CloseIdleConnections does not close an HTTP/2 connection that still
// has an in-flight stream. The close runs at the start of the next request, so
// with the usual 30s heartbeat the connection is idle between beats and is
// closed; a connection kept continuously busy by overlapping requests would
// survive until it goes idle. maxTransportAge closes that gap by bounding the
// lifetime of every connection regardless of traffic.
const recycleAfter5xx = 3

// noteResponse updates the consecutive-5xx counter for one completed HTTP
// exchange and flags a recycle when the threshold is hit; the next request
// closes the idle connections (see recycleIfPending).
// Only a 5xx response counts as a failure: 4xx (e.g. a 401 from a bad bearer)
// is the server answering correctly and says nothing about the connection, so
// it neither counts nor resets. Any other status is a success and resets.
// Transport-level errors (dial failure, timeout, reset) are deliberately not
// counted either: the next request already redials after those, so there is
// nothing pinned to recycle.
func (r *restActuation) noteResponse(status int) {
	r.mu.Lock()
	switch {
	case status >= 500:
		r.consecutive5xx++
	case status >= 400:
		// Neither a connection symptom nor proof of health: leave as is.
	default:
		r.consecutive5xx = 0
	}
	if r.consecutive5xx >= recycleAfter5xx {
		r.consecutive5xx = 0
		r.recyclePending = true
	}
	r.mu.Unlock()
}

// recycleIfPending closes the pooled connections when noteResponse flagged a
// recycle. It runs at the start of the next request rather than at the end of
// the failing one: an HTTP/2 stream is released asynchronously after the body
// is read, so closing immediately can find the connection still "in use" and
// do nothing. By the next request (a heartbeat tick later) it is idle.
func (r *restActuation) recycleIfPending() {
	r.mu.Lock()
	pending := r.recyclePending
	r.recyclePending = false
	r.mu.Unlock()
	if pending {
		log.Printf("[cloud] %d consecutive 5xx from the control plane; closing pooled connections so this request redials", recycleAfter5xx)
		r.mu.Lock()
		hc := r.hc
		r.mu.Unlock()
		hc.CloseIdleConnections()
	}
}

// acquire returns the client for one request, first swapping in a fresh
// transport if the current one has outlived maxTransportAge and sweeping
// drained retired clients. The returned release must be called once the
// response body has been read and closed.
func (r *restActuation) acquire() (*http.Client, func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if tr, ok := r.hc.Transport.(*http.Transport); ok && now.Sub(r.transportBorn) >= maxTransportAge {
		r.retired = append(r.retired, &retiredClient{hc: r.hc})
		r.hc = &http.Client{Timeout: r.hc.Timeout, Transport: tr.Clone()}
		r.transportBorn = now
		log.Printf("[cloud] control-plane transport older than %s; using a fresh connection", maxTransportAge)
	}
	kept := r.retired[:0]
	for _, rc := range r.retired {
		if r.inflight[rc.hc] > 0 {
			rc.idleSwept = false
			kept = append(kept, rc)
			continue
		}
		rc.hc.CloseIdleConnections()
		if !rc.idleSwept {
			rc.idleSwept = true
			kept = append(kept, rc)
		}
	}
	for i := len(kept); i < len(r.retired); i++ {
		r.retired[i] = nil
	}
	r.retired = kept
	hc := r.hc
	if r.inflight == nil {
		r.inflight = make(map[*http.Client]int)
	}
	r.inflight[hc]++
	return hc, func() {
		r.mu.Lock()
		if r.inflight[hc]--; r.inflight[hc] <= 0 {
			delete(r.inflight, hc)
		}
		r.mu.Unlock()
	}
}

func newRESTActuation(controlPlane, bearer string) *restActuation {
	return &restActuation{
		base:   strings.TrimRight(strings.TrimSpace(controlPlane), "/"),
		bearer: bearer,
		// Own transport (a clone of the default, so proxy/HTTP2 behaviour is
		// unchanged) so CloseIdleConnections affects only this client.
		hc:            &http.Client{Timeout: 30 * time.Second, Transport: newTransport()},
		now:           time.Now,
		transportBorn: time.Now(),
	}
}

func newTransport() *http.Transport {
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		return dt.Clone()
	}
	return &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}
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

// GetSSHTrustBundle fetches the CA trust bundle over the RPC's grpc-gateway
// GET mapping (/v1/actuation/ssh-trust-bundle), carrying known_version as a
// query parameter the way grpc-gateway maps a GET request's fields by
// default.
func (r *restActuation) GetSSHTrustBundle(ctx context.Context, req *cloudv1.GetSSHTrustBundleRequest, _ ...grpc.CallOption) (*cloudv1.GetSSHTrustBundleResponse, error) {
	path := "/v1/actuation/ssh-trust-bundle"
	if kv := req.GetKnownVersion(); kv != "" {
		path += "?known_version=" + url.QueryEscape(kv)
	}
	var resp cloudv1.GetSSHTrustBundleResponse
	if err := r.get(ctx, path, &resp); err != nil {
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
	return r.do(httpReq, path, out)
}

// get sends a bearer-authenticated GET and decodes the protojson response.
// Shares response handling with post via do.
func (r *restActuation) get(ctx context.Context, path string, out proto.Message) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+path, nil)
	if err != nil {
		return fmt.Errorf("cloud-rest: build %s: %w", path, err)
	}
	return r.do(httpReq, path, out)
}

// do attaches the host-bearer header, sends httpReq, and decodes the
// protojson response into out. Shared tail of post and get.
func (r *restActuation) do(httpReq *http.Request, path string, out proto.Message) error {
	if r.bearer != "" {
		httpReq.Header.Set("Grpc-Metadata-Host-Bearer", r.bearer)
	}
	r.recycleIfPending()
	hc, release := r.acquire()
	defer release()
	resp, err := hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("cloud-rest: %s %s: %w", httpReq.Method, path, err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	// A recycle is only flagged here; the next request closes the idle
	// connections, once the stream just finished has been released.
	r.noteResponse(resp.StatusCode)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("cloud-rest: %s %s: %d %s", httpReq.Method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if len(raw) == 0 {
		return nil
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, out); err != nil {
		return fmt.Errorf("cloud-rest: decode %s %s: %w", httpReq.Method, path, err)
	}
	return nil
}

// enrollREST redeems a join token over REST (POST /v1/actuation/enroll). The
// join token self-authenticates in the body, so no host bearer is sent. See
// Enroll's doc comment for why the returned bearer is rebuilt rather than the
// raw joinToken being reused verbatim.
func enrollREST(ctx context.Context, controlPlane, joinToken string, opts EnrollOptions) (hostID, bearerToken string, err error) {
	r := newRESTActuation(controlPlane, "")
	// Throwaway client: do not leave its connection pooled after enroll.
	defer r.hc.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var resp cloudv1.EnrollHostResponse
	if err := r.post(ctx, "/v1/actuation/enroll", &cloudv1.EnrollHostRequest{
		JoinToken:    joinToken,
		DriverToken:  opts.DriverToken,
		OssBackendId: opts.OSSBackendID,
		AdoptForeign: opts.AdoptForeign,
	}, &resp); err != nil {
		return "", "", fmt.Errorf("cloud: enroll (REST): %w", err)
	}
	return resp.GetHostId(), rebuildBearer(resp.GetHostId(), joinToken), nil
}
