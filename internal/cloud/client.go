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

// Deps are the daemon-provided collaborators. Both are optional: nil Policies
// skips network-policy sync, nil Containers skips container reconcile. With both
// nil the client is heartbeat-only.
type Deps struct {
	Policies   PolicySink
	Containers ContainerActuator
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

	conn *grpc.ClientConn
	ac   cloudv1.ActuationServiceClient

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
	return &Client{cfg: cfg, interval: defaultHeartbeatInterval, sink: deps.Policies, containers: deps.Containers}, nil
}

// Start dials the control plane and launches the heartbeat loop. A dial error is
// returned; per-beat errors are logged and retried (a control-plane outage must
// not crash the daemon or stop local containers).
func (c *Client) Start(ctx context.Context) error {
	conn, err := c.dial()
	if err != nil {
		return fmt.Errorf("cloud: dial control plane %s: %w", c.cfg.ControlPlane, err)
	}
	c.conn = conn
	c.ac = cloudv1.NewActuationServiceClient(conn)
	c.ctx, c.cancel = context.WithCancel(ctx)

	c.wg.Add(1)
	go c.heartbeatLoop()
	watch := c.sink != nil || c.containers != nil
	if watch {
		c.wg.Add(1)
		go c.watchLoop()
	}
	log.Printf("[cloud] actuation client started: host=%s control-plane=%s (heartbeat %s, watch=%v)",
		c.cfg.HostID, c.cfg.ControlPlane, c.interval, watch)
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
	var creds credentials.TransportCredentials
	if c.cfg.Insecure {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	return grpc.NewClient(c.cfg.ControlPlane, grpc.WithTransportCredentials(creds))
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
	stream, err := c.ac.WatchAssignments(c.authContext(c.ctx), &cloudv1.WatchAssignmentsRequest{})
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

// report sends observed container state back to the cloud (best-effort).
func (c *Client) report(containerID, state string) {
	ctx, cancel := context.WithTimeout(c.authContext(c.ctx), 10*time.Second)
	defer cancel()
	if _, err := c.ac.ReportContainerState(ctx, &cloudv1.ReportContainerStateRequest{
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
