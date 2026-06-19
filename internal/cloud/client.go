package cloud

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
)

// hostBearerMetadataKey is the gRPC metadata header the cloud-daemon's
// HostBearerInterceptor reads to authenticate the host. Wire contract with the
// cloud repo's internal/auth.HostBearerMetadataKey — a literal here because that
// const lives in the cloud module's internal/ (not importable), and we vendor
// only the proto, not the auth package.
const hostBearerMetadataKey = "host-bearer"

// defaultHeartbeatInterval is the actuation heartbeat cadence. The cloud-side
// staleness threshold is ~3 missed beats; see the cloud container-actuation PRD.
const defaultHeartbeatInterval = 30 * time.Second

// driverRefreshInterval is how often the daemon re-mints and pushes a fresh
// driver token (#557). Set to ⅔ of the 30-day OSS cap so there is always at
// least 10 days of runway before expiry, even if one refresh cycle fails.
const driverRefreshInterval = 20 * 24 * time.Hour

// PolicySink receives each AssignmentBatch's per-org network policies so the
// daemon can converge its NetworkPolicyStore (where the eBPF enforcer applies
// them). The daemon implements this; keeping it an interface lets the client be
// tested with a fake and keeps internal/cloud free of an internal/server import.
type PolicySink interface {
	// SyncNetworkPolicies is handed the full set of policies on the current
	// batch (a snapshot, like assignments). Implementations converge their store
	// to exactly this set, keyed by org.
	SyncNetworkPolicies(ctx context.Context, policies []*cloudv1.NetworkPolicy) error
}

// ContainerSpec is the host-local shape of one cloud assignment the actuator
// acts on. LocalName is the Incus instance name (cld-<short-uuid>); OrgID is
// stamped as the container's user.containarium.tenant label so the network-policy
// enforcer identifies it.
type ContainerSpec struct {
	LocalName string
	OrgID     string
	Image     string
	RAMMB     int32
	DiskGB    int32
	GPUCount  int32
	// SecretEnv are name→value pairs the actuator injects as container
	// environment (from Assignment.secret_env).
	SecretEnv map[string]string
	// Routes are the hostname→port exposures for this container (from
	// Assignment.routes); the actuator registers them at the host edge.
	Routes []RouteSpec
}

// RouteSpec is one hostname→container-port exposure (from cloudv1.PortRoute).
type RouteSpec struct {
	Domain     string
	TargetPort int32
	Protocol   string
}

// ContainerActuator drives local Incus state toward an assignment's
// desired_state. The daemon implements it (create/start/stop/delete + stamp the
// tenant label); the interface keeps internal/cloud free of an Incus dependency
// and lets the reconcile decision be unit-tested with a fake. Each method is
// idempotent — the reconciler may call it for an already-converged container.
type ContainerActuator interface {
	EnsureRunning(ctx context.Context, spec ContainerSpec) error
	EnsureStopped(ctx context.Context, localName string) error
	EnsureDeleted(ctx context.Context, localName string) error
}

// HostCheck is one line of the host's `doctor` self-check — mirrors the
// proto HostCapabilityCheck so callers (the daemon's probe) don't depend on
// generated types.
type HostCheck struct {
	Name   string
	OK     bool
	Detail string
}

// HostStatus is the host's self-measured capability profile + `doctor`
// self-check, reported to the cloud so the BYO fleet view goes live.
type HostStatus struct {
	AgentVersion  string
	CPUCores      int32
	TotalRAMMB    int32
	TotalDiskGB   int32
	TotalGPUCount int32
	GPUSpec       string
	// Spare headroom — currently-available, self-measured.
	AvailRAMMB    int32
	AvailDiskGB   int32
	AvailGPUCount int32
	SelfCheckOK   bool
	Checks        []HostCheck
}

// StatusProbe gathers the host's current capability profile + self-check.
// The daemon implements it (hardware introspection + `containarium doctor`);
// the interface keeps internal/cloud free of those deps and lets the report
// loop be tested with a fake.
type StatusProbe interface {
	Probe(ctx context.Context) (HostStatus, error)
}

// DriverMinter mints a fresh BYOC driver token (an admin JWT signed with this
// host's own jwt.secret). Called by the driver-refresh loop (#557) ~every 20
// days to keep the cloud-stored credential from reaching the 30-day expiry cap.
// Returns the raw JWT string. The function is optional in Deps; nil = no refresh.
type DriverMinter func() (string, error)

// Deps are the daemon-provided collaborators. All optional: nil Policies
// skips network-policy sync, nil Containers skips container reconcile, nil
// Status skips capability reporting. With all nil the client is
// heartbeat-only.
type Deps struct {
	Policies   PolicySink
	Containers ContainerActuator
	Status     StatusProbe
	// Driver, when non-nil, enables autonomous driver-token refresh (#557).
	// The daemon provides this when cloud.yaml has a JWTSecretFile set (i.e.
	// the host enrolled as a BYOC backend with a driver token).
	Driver DriverMinter
}

// unaryActuation is the subset of the actuation API the client drives over a
// unary transport (heartbeat + capability report). Both the gRPC
// ActuationServiceClient and the REST transport (#722) satisfy it; the
// CallOption args are part of the gRPC signature and ignored by REST.
type unaryActuation interface {
	Heartbeat(context.Context, *cloudv1.HeartbeatRequest, ...grpc.CallOption) (*cloudv1.HeartbeatResponse, error)
	ReportHostStatus(context.Context, *cloudv1.ReportHostStatusRequest, ...grpc.CallOption) (*cloudv1.ReportHostStatusResponse, error)
}

// Client is the host-side cloud-actuation client. Slice 3 implements the
// heartbeat; WatchAssignments + the reconciler land in slice 4. The actuation
// proto is vendored (proto/containarium/cloud/v1), so this builds in the default
// OSS binary with no private dependency; it is inert unless the host is enrolled
// (~/.containarium/cloud.yaml present).
type Client struct {
	cfg        *Config
	interval   time.Duration
	sink       PolicySink        // optional; nil = no policy reconcile
	containers ContainerActuator // optional; nil = no container reconcile

	status StatusProbe  // optional; nil = no capability reporting
	driver DriverMinter // optional; nil = no driver-token refresh (#557)

	conn *grpc.ClientConn
	// ac handles the unary actuation RPCs (heartbeat + status); it is either the
	// gRPC client or the REST transport (#722). watchAC is the gRPC client used
	// for the WatchAssignments stream — nil in REST mode, where a (push-driven)
	// BYOC host pulls no assignments and the watch loop is not started.
	ac      unaryActuation
	watchAC cloudv1.ActuationServiceClient

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	failures int // consecutive heartbeat failures, for observability
}

// New builds a client from a validated config. deps are optional collaborators
// (see Deps) — both nil makes the client heartbeat-only.
func New(cfg *Config, deps Deps) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Client{
		cfg: cfg, interval: defaultHeartbeatInterval,
		sink: deps.Policies, containers: deps.Containers,
		status: deps.Status, driver: deps.Driver,
	}, nil
}

// Start dials the control plane and launches the heartbeat loop. A dial error is
// returned; per-beat errors are logged and retried (a control-plane outage must
// not crash the daemon or stop local containers).
func (c *Client) Start(ctx context.Context) error {
	if isRESTControlPlane(c.cfg.ControlPlane) {
		// REST transport (#722): no gRPC dial. WatchAssignments (streaming) is
		// unavailable over REST, so the watch loop is skipped — a BYOC host on a
		// REST-only control plane is push-driven (the cloud drives it via the
		// sentinel peer-proxy) and pulls no assignments.
		c.ac = newRESTActuation(c.cfg.ControlPlane, c.cfg.Token)
	} else {
		conn, err := c.dial()
		if err != nil {
			return fmt.Errorf("cloud: dial control plane %s: %w", c.cfg.ControlPlane, err)
		}
		c.conn = conn
		gc := cloudv1.NewActuationServiceClient(conn)
		c.ac, c.watchAC = gc, gc
	}
	c.ctx, c.cancel = context.WithCancel(ctx)

	c.wg.Add(1)
	go c.heartbeatLoop()
	wantWatch := c.sink != nil || c.containers != nil
	watch := wantWatch && c.watchAC != nil
	if wantWatch && c.watchAC == nil {
		log.Printf("[cloud] REST transport: assignment-watch disabled (push-driven host; policy/container pull is gRPC-only)")
	}
	if watch {
		c.wg.Add(1)
		go c.watchLoop()
	}
	if c.status != nil {
		c.wg.Add(1)
		go c.statusLoop()
	}
	if c.driver != nil {
		c.wg.Add(1)
		go c.driverRefreshLoop()
	}
	log.Printf("[cloud] actuation client started: host=%s control-plane=%s (heartbeat %s, watch=%v, status=%v, driver-refresh=%v)",
		c.cfg.HostID, c.cfg.ControlPlane, c.interval, watch, c.status != nil, c.driver != nil)
	return nil
}

// Stop ends the loops and closes the connection. Safe to call once after Start.
func (c *Client) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func (c *Client) dial() (*grpc.ClientConn, error) {
	return dialControlPlane(c.cfg.ControlPlane, c.cfg.Insecure)
}

// dialControlPlane builds a gRPC client connection to the control plane.
// Shared by the running Client and the one-shot Enroll helper.
func dialControlPlane(addr string, insecureTLS bool) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if insecureTLS {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
}

// EnrollOptions carries the optional BYOC driver-routing fields of EnrollHost
// (cloud #554). Both empty = a plain enroll (host registered + heartbeating but
// not cloud-drivable).
type EnrollOptions struct {
	// DriverToken is an admin JWT this host minted with its own jwt.secret;
	// the cloud seals + replays it to drive this host through the sentinel
	// peer-proxy.
	DriverToken string
	// OSSBackendID is this host's tunnel/`pool join` spot-id — what the
	// sentinel `/peer/<id>/` proxy keys on.
	OSSBackendID string
}

// Enroll redeems a single-use join token against the control plane and returns
// the registered host id. One-shot (no running client / host bearer yet — the
// token authenticates itself in the body). Used by `containarium cloud enroll`
// for the BYO self-service flow; after this, the same token is the host's
// durable bearer (the cloud reuses the token secret as the host bearer).
//
// opts optionally carries the BYOC driver token + backend id (cloud #554) so a
// tunnel-joined host becomes cloud-drivable in the same round-trip.
func Enroll(ctx context.Context, controlPlane, joinToken string, insecureTLS bool, opts EnrollOptions) (string, error) {
	// REST control plane (#722): redeem over grpc-gateway instead of gRPC.
	if isRESTControlPlane(controlPlane) {
		return enrollREST(ctx, controlPlane, joinToken, opts)
	}
	conn, err := dialControlPlane(controlPlane, insecureTLS)
	if err != nil {
		return "", fmt.Errorf("cloud: dial control plane %s: %w", controlPlane, err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := cloudv1.NewActuationServiceClient(conn).EnrollHost(ctx, &cloudv1.EnrollHostRequest{
		JoinToken:    joinToken,
		DriverToken:  opts.DriverToken,
		OssBackendId: opts.OSSBackendID,
	})
	if err != nil {
		return "", fmt.Errorf("cloud: enroll: %w", err)
	}
	return resp.GetHostId(), nil
}

// statusLoop reports the host's capability profile + self-check on the same
// cadence as the heartbeat. Best-effort: a failed probe or RPC is logged and
// retried next tick — capability staleness must never crash the daemon.
func (c *Client) statusLoop() {
	defer c.wg.Done()
	t := time.NewTicker(c.interval)
	defer t.Stop()
	c.reportStatusOnce() // immediate first report so the fleet row goes live fast
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.reportStatusOnce()
		}
	}
}

func (c *Client) reportStatusOnce() {
	st, err := c.status.Probe(c.ctx)
	if err != nil {
		log.Printf("[cloud] status probe failed: %v", err)
		return
	}
	checks := make([]*cloudv1.HostCapabilityCheck, 0, len(st.Checks))
	for _, ck := range st.Checks {
		checks = append(checks, &cloudv1.HostCapabilityCheck{Name: ck.Name, Ok: ck.OK, Detail: ck.Detail})
	}
	ctx, cancel := context.WithTimeout(c.authContext(c.ctx), 10*time.Second)
	defer cancel()
	if _, err := c.ac.ReportHostStatus(ctx, &cloudv1.ReportHostStatusRequest{
		AgentVersion:  st.AgentVersion,
		CpuCores:      st.CPUCores,
		TotalRamMb:    st.TotalRAMMB,
		TotalDiskGb:   st.TotalDiskGB,
		TotalGpuCount: st.TotalGPUCount,
		GpuSpec:       st.GPUSpec,
		AvailRamMb:    st.AvailRAMMB,
		AvailDiskGb:   st.AvailDiskGB,
		AvailGpuCount: st.AvailGPUCount,
		SelfCheckOk:   st.SelfCheckOK,
		Checks:        checks,
	}); err != nil {
		log.Printf("[cloud] report host status: %v", err)
	}
}

// driverRefreshLoop re-mints the BYOC driver token on a ~20-day cycle so the
// cloud-stored credential never reaches the 30-day cap (#557). Fires once
// immediately on startup so a freshly-enrolled daemon pushes a token right
// away, then sleeps for driverRefreshInterval between rounds. Best-effort:
// mint/RPC failures are logged and retried on the next cycle — one missed
// refresh leaves ~10 days of runway before the old token expires.
func (c *Client) driverRefreshLoop() {
	defer c.wg.Done()
	c.refreshDriverTokenOnce()
	t := time.NewTicker(driverRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.refreshDriverTokenOnce()
		}
	}
}

func (c *Client) refreshDriverTokenOnce() {
	tok, err := c.driver()
	if err != nil {
		log.Printf("[cloud] driver-token refresh: mint failed: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(c.authContext(c.ctx), 10*time.Second)
	defer cancel()
	if _, err := c.ac.ReportHostStatus(ctx, &cloudv1.ReportHostStatusRequest{
		DriverToken: tok,
	}); err != nil {
		log.Printf("[cloud] driver-token refresh: push failed: %v", err)
		return
	}
	log.Printf("[cloud] driver-token refreshed (next in %s)", driverRefreshInterval)
}

func (c *Client) heartbeatLoop() {
	defer c.wg.Done()
	t := time.NewTicker(c.interval)
	defer t.Stop()
	c.beat() // immediate first beat so registration shows up without waiting a full interval
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.beat()
		}
	}
}

func (c *Client) beat() {
	if err := c.heartbeatOnce(c.ctx); err != nil {
		c.mu.Lock()
		c.failures++
		n := c.failures
		c.mu.Unlock()
		log.Printf("[cloud] heartbeat failed (%d consecutive): %v", n, err)
		return
	}
	c.mu.Lock()
	hadFailures := c.failures > 0
	c.failures = 0
	c.mu.Unlock()
	if hadFailures {
		log.Printf("[cloud] heartbeat recovered")
	}
}

// heartbeatOnce sends a single Heartbeat with the host-bearer metadata.
func (c *Client) heartbeatOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(c.authContext(ctx), 10*time.Second)
	defer cancel()
	_, err := c.ac.Heartbeat(ctx, &cloudv1.HeartbeatRequest{})
	return err
}

// authContext attaches the host bearer the cloud interceptor authenticates on.
func (c *Client) authContext(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, hostBearerMetadataKey, c.cfg.Token)
}

// watchBackoff is the reconnect schedule for the WatchAssignments stream:
// exponential with a 60s cap. Jitter is omitted (single host per process; no
// thundering herd to spread).
var watchBackoff = []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 60 * time.Second}

// watchLoop opens the WatchAssignments server stream and reconciles each batch,
// reconnecting with capped exponential backoff on any stream error. Runs until
// the client context is cancelled.
func (c *Client) watchLoop() {
	defer c.wg.Done()
	attempt := 0
	for {
		if c.ctx.Err() != nil {
			return
		}
		err := c.watchOnce()
		if c.ctx.Err() != nil {
			return
		}
		// Stream ended (error or clean EOF) — back off, then re-open. A fresh
		// WatchAssignments resends the full snapshot, so the reconcile is
		// self-correcting; we never lose state by reconnecting.
		d := watchBackoff[attempt]
		if attempt < len(watchBackoff)-1 {
			attempt++
		}
		if err != nil {
			log.Printf("[cloud] watch stream ended (%v); reconnecting in %s", err, d)
		}
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(d):
		}
	}
}

// watchOnce opens one stream and reconciles batches until it errors. On the
// first successful batch it resets nothing — the caller's backoff index resets
// only via a successful reconnect cycle (kept simple: any return re-enters the
// loop). Returns the stream error (nil on a clean server close).
func (c *Client) watchOnce() error {
	stream, err := c.watchAC.WatchAssignments(c.authContext(c.ctx), &cloudv1.WatchAssignmentsRequest{})
	if err != nil {
		return err
	}
	for {
		batch, err := stream.Recv()
		if err != nil {
			return err
		}
		c.reconcile(batch)
	}
}

// reconcile applies one batch: (1) converge per-org network policies into the
// sink (the #315 cloud-extension loop), then (2) reconcile each assignment's
// container toward its desired_state.
func (c *Client) reconcile(batch *cloudv1.AssignmentBatch) {
	if c.sink != nil {
		if err := c.sink.SyncNetworkPolicies(c.ctx, batch.GetNetworkPolicies()); err != nil {
			log.Printf("[cloud] sync network policies: %v", err)
		}
	}
	if c.containers != nil {
		for _, a := range batch.GetAssignments() {
			c.reconcileAssignment(a)
		}
	}
}

// reconcileAssignment drives one container toward its desired_state and reports
// the observed state back. The reconcile is idempotent (the actuator no-ops a
// converged container), so re-sent snapshots are safe.
func (c *Client) reconcileAssignment(a *cloudv1.Assignment) {
	name := localContainerName(a.GetContainerId())
	switch a.GetDesiredState() {
	case "running":
		routes := make([]RouteSpec, 0, len(a.GetRoutes()))
		for _, r := range a.GetRoutes() {
			routes = append(routes, RouteSpec{Domain: r.GetDomain(), TargetPort: r.GetTargetPort(), Protocol: r.GetProtocol()})
		}
		if err := c.containers.EnsureRunning(c.ctx, ContainerSpec{
			LocalName: name, OrgID: a.GetOrgId(), Image: a.GetImage(),
			RAMMB: a.GetRamMb(), DiskGB: a.GetDiskGb(), GPUCount: a.GetGpuCount(),
			SecretEnv: a.GetSecretEnv(), Routes: routes,
		}); err != nil {
			log.Printf("[cloud] ensure running %s: %v", name, err)
			return // leave the cloud's observed state stale; next snapshot retries
		}
		c.report(a.GetContainerId(), "active")
	case "stopped":
		if err := c.containers.EnsureStopped(c.ctx, name); err != nil {
			log.Printf("[cloud] ensure stopped %s: %v", name, err)
			return
		}
		c.report(a.GetContainerId(), "stopped")
	case "deleted":
		if err := c.containers.EnsureDeleted(c.ctx, name); err != nil {
			log.Printf("[cloud] ensure deleted %s: %v", name, err)
		}
		// No state report — the cloud releases the assignment once the host
		// stops reporting it (there is no "deleted" observed-state value).
	default:
		// Unknown / empty desired_state — leave it alone (informational only).
	}
}

// report sends observed container state back to the cloud (best-effort). Part
// of the pull/reconcile path, so it only runs in gRPC mode (the REST transport
// runs no watch loop); watchAC is nil otherwise.
func (c *Client) report(containerID, state string) {
	if c.watchAC == nil {
		return
	}
	ctx, cancel := context.WithTimeout(c.authContext(c.ctx), 10*time.Second)
	defer cancel()
	if _, err := c.watchAC.ReportContainerState(ctx, &cloudv1.ReportContainerStateRequest{
		ContainerId: containerID, State: state,
	}); err != nil {
		log.Printf("[cloud] report state %s=%s: %v", containerID, state, err)
	}
}

// localContainerName maps a cloud container UUID to the host-local Incus name.
// The cld- prefix keeps cloud-assigned containers from colliding with
// operator-managed <tenant>-container names. Best-effort short form; the cloud
// container_id is the durable key carried in ReportContainerState.
func localContainerName(containerID string) string {
	short := strings.ReplaceAll(containerID, "-", "")
	if len(short) > 12 {
		short = short[:12]
	}
	if short == "" {
		short = "unknown"
	}
	return "cld-" + short
}
