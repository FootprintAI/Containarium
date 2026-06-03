package cloud

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
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

// Client is the host-side cloud-actuation client. Slice 3 implements the
// heartbeat; WatchAssignments + the reconciler land in slice 4. The actuation
// proto is vendored (proto/containarium/cloud/v1), so this builds in the default
// OSS binary with no private dependency; it is inert unless the host is enrolled
// (~/.containarium/cloud.yaml present).
type Client struct {
	cfg      *Config
	interval time.Duration

	conn *grpc.ClientConn
	ac   cloudv1.ActuationServiceClient

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	failures int // consecutive heartbeat failures, for observability
}

// New builds a client from a validated config.
func New(cfg *Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, interval: defaultHeartbeatInterval}, nil
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
	log.Printf("[cloud] actuation client started: host=%s control-plane=%s (heartbeat %s)",
		c.cfg.HostID, c.cfg.ControlPlane, c.interval)
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
