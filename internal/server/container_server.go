package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/alert"
	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/capabilities"
	"github.com/footprintai/containarium/internal/capacity"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/guacamole"
	"github.com/footprintai/containarium/internal/integrity"
	"github.com/footprintai/containarium/internal/releasecheck"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/pkg/core/box"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/ostype"
	"github.com/footprintai/containarium/pkg/core/stacks"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/footprintai/containarium/pkg/version"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PendingCreation tracks an async container creation
type PendingCreation struct {
	Username     string
	StartedAt    time.Time
	Error        error
	Done         bool
	Provisioning bool // container is running but installing stack/packages
}

// ContainerServer implements the gRPC ContainerService
type ContainerServer struct {
	pb.UnimplementedContainerServiceServer
	manager *container.Manager
	// boxBackend is the runtime-neutral seam over the box substrate. Today it
	// wraps the same *container.Manager (LXC/incus); a K8s backend slots in
	// here behind a build tag. Box-lifecycle operations (Create/Get/…) route
	// through it; the LXC-specific surface (Exec, config keys, security scans,
	// app hosting) still calls manager directly during the transition.
	boxBackend          box.BoxBackend
	collaboratorManager *container.CollaboratorManager
	emitter             *events.Emitter
	pendingCreations    map[string]*PendingCreation
	pendingMu           sync.RWMutex
	// Monitoring URLs (set by DualServer after setup)
	victoriaMetricsURL string
	grafanaURL         string
	// Alerting (set by DualServer after setup)
	alertStore         *alert.Store
	alertManager       *alert.Manager
	alertDeliveryStore *alert.DeliveryStore
	alertWebhookURL    string
	alertWebhookSecret string
	hostRelayURL       string                          // e.g. "http://10.100.0.1:8080/internal/alert-relay"
	alertRelayConfigFn func(webhookURL, secret string) // callback to update gateway relay config
	coreServices       *CoreServices
	daemonConfigStore  *app.DaemonConfigStore
	peerPool           *PeerPool
	// capacityStore holds this backend's spare-capacity advertise/withdraw
	// state + local policy (#680). Lazily initialized so an unwired server
	// (tests) still answers GetCapacityHeadroom with "not advertised".
	capacityStore     *capacity.Store
	capacityStoreOnce sync.Once
	// capabilityStore holds this backend's last-recorded hardware capability
	// profile (#681). Lazily initialized like capacityStore so an unwired
	// server (tests) answers GetCapabilityProfile with "not profiled yet".
	capabilityStore     *capabilities.Store
	capabilityStoreOnce sync.Once
	// drainer performs the bounded graceful reclaim of guest workloads when a
	// backend withdraws headroom (#682). Lazily initialized; a single in-flight
	// drain at a time guards against repeated advertise/withdraw cycles wedging
	// the host.
	drainer     *capacity.Drainer
	drainerOnce sync.Once
	// profileMu serializes ProfileBackend: each profile spins a throwaway
	// GPU-probe LXC + a benchmark on the host, so concurrent/repeated calls
	// must coalesce rather than stack a probe storm that can wedge the runtime.
	profileMu sync.Mutex
	// region is the region this backend serves, wired from --region (falling
	// back to the pool name). Recorded into the capability profile. Empty when
	// unset.
	region string
	// integrityConfigState is the integrity-relevant policy/config posture this
	// backend folds into its signed self-measurement (#683): base domain,
	// network-policy enforcement posture, and any other config the control plane
	// verifies hasn't been tampered with. Wired once via SetIntegrityConfig;
	// nil/empty on an unwired server still yields a (config-empty) measurement.
	integrityConfigState map[string]string
	// reportedClass is the self-reported hardware class the operator assigned
	// this backend (defaults to the pool name). Reconciled against the measured
	// class in the capability profile. Empty when unset.
	reportedClass string
	// startTime is when this daemon process started; ListBackends reports
	// the local backend's uptime from it. Set by DualServer wiring
	// (SetStartTime); zero on a server that was never wired, in which case
	// uptime is reported as 0.
	startTime time.Time
	// Route / Caddy cleanup deps (set by DualServer wiring, may be nil if
	// the daemon was started without --app-hosting). Used by DeleteContainer
	// to cascade-remove the routes / TLS-automation subjects a container
	// owned, so deleting an LXC actually deletes the public hostname too.
	routeStore   routeLister
	proxyManager *app.ProxyManager

	// moveRunner shells out to `incus snapshot/copy/stop/start` for the
	// MoveContainer migration flow. Nil on daemons that don't support
	// migration (MoveContainer returns "not configured" then).
	moveRunner incus.MigrationRunner

	// secretsStore is the tenant-secrets backend. Nil on daemons
	// that don't have Postgres wired up (--standalone); the
	// SecretsService RPCs return Unavailable in that case.
	// CreateContainer / StartContainer call LoadAllForUser to
	// stamp environment.<NAME>=<value> at LXC start time.
	secretsStore *secrets.Store

	// KMS status snapshot for the KmsService GetKMSStatus RPC.
	// Set once at startup in dual_server.go alongside the secrets
	// store. Read-only after wiring; reflects CONTAINARIUM_KMS_BACKEND
	// + CONTAINARIUM_REQUIRE_ENVELOPE as resolved at boot.
	kmsBackend      string
	kmsDescription  string
	kmsConfigured   bool
	requireEnvelope bool

	// wakeRouter applies the Caddy route swap when a container is
	// auto-slept (SwapToWake) and woken back up (SwapToDirect).
	// Nil on daemons without app hosting or with auto-sleep disabled;
	// the StopForAutoSleep / StartContainer hooks are nil-safe.
	wakeRouter WakeRouter

	// otelCollectorEndpoint is the OTLP/HTTP URL of this daemon's
	// core OTel collector LXC (e.g. "http://10.0.3.142:4318").
	// Stamped into containers created with monitoring=true so the
	// SDK inside ships telemetry without app-side config. Empty
	// means the daemon was started without OTel app-monitoring
	// support; create_container with monitoring=true will log a
	// warning and skip the env-var injection.
	otelCollectorEndpoint string
	// Guacamole integration for Windows VM RDP access
	guacamoleClient *guacamole.Client
	guacamoleUser   string // Guacamole admin username
	guacamolePass   string // Guacamole admin password

	// sshHost is the public host clients dial to SSH into containers this
	// daemon fronts — the sentinel's SSH endpoint (e.g. "region-a.example.com"),
	// set by DualServer wiring from --ssh-host. Stamped onto Container.ssh_host
	// in the read path (alongside Pool) so a client builds its connect target
	// `username@ssh_host` without inferring the host from the IP / config.
	// Empty (direct mode / no sentinel) leaves ssh_host empty and clients fall
	// back to network.ip_address.
	sshHost string

	// autoUpdater drives on-demand daemon upgrades (TriggerUpgrade). Nil on
	// daemons started without an auto-update source (e.g. no sentinel), in
	// which case TriggerUpgrade for the local backend returns Unavailable.
	// upgradeJobs tracks in-flight/terminal upgrade jobs by upgrade_id, and
	// upgradeBusy guards against concurrent upgrades per backend. A successful
	// LOCAL upgrade restarts the daemon, so its job state does not survive —
	// callers confirm via the backend version in ListBackends. #354 Phase B.
	autoUpdater *AutoUpdater
	upgradeMu   sync.Mutex
	upgradeJobs map[string]*upgradeJob
	upgradeBusy map[string]bool
}

// upgradeJob is the in-memory record of a daemon upgrade triggered via
// TriggerUpgrade, polled by GetUpgradeStatus. #354.
type upgradeJob struct {
	id             string
	backendID      string
	status         string // in_progress | completed | failed | noop
	currentVersion string
	errMsg         string
	completedAt    string
}

// NewContainerServer creates a new container server. runtime selects the box
// backend: "lxc" (default, empty) or "k8s". See RuntimeLXC / RuntimeK8s.
func NewContainerServer(runtime string) (*ContainerServer, error) {
	mgr, err := newManager(runtime)
	if err != nil {
		return nil, fmt.Errorf("failed to create container manager: %w", err)
	}
	bb, err := newBoxBackend(runtime, mgr)
	if err != nil {
		return nil, fmt.Errorf("failed to select box backend: %w", err)
	}
	return &ContainerServer{
		manager:          mgr,
		boxBackend:       bb,
		emitter:          events.NewEmitter(events.GetBus()),
		pendingCreations: make(map[string]*PendingCreation),
	}, nil
}

// boxes returns the box-lifecycle backend. Production wires boxBackend in
// NewContainerServer; this lazily wraps the Manager when it's unset so a
// server constructed directly (legacy tests that set only `manager`) still
// routes lifecycle calls through the same LXC seam. The wrapper is a cheap
// struct over the Manager, so constructing it per call is fine.
func (s *ContainerServer) boxes() box.BoxBackend {
	if s.boxBackend != nil {
		return s.boxBackend
	}
	return boxlxc.New(s.manager)
}

// CreateContainer creates a new container
func (s *ContainerServer) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	// Validate request
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}
	// Audit B-MED-1 / B-MED-2 / B-LOW-1: cap the unbounded
	// repeated-string / map fields before any allocation-heavy
	// work runs. Done after the tenant check (don't enumerate
	// resource caps to unauthenticated callers) but before pool
	// resolution and peer routing.
	if err := validateCreateContainerBounds(req); err != nil {
		return nil, err
	}
	// Birth TTL (#523): reject an out-of-range TTL before we provision
	// anything — fail fast rather than create a box and then reject its
	// death date. Same bound (7 days) as SetContainerTTL; 0 = no TTL.
	if err := validateTTLSeconds(req.TtlSeconds); err != nil {
		return nil, err
	}
	// Birth idle-stop (#524): a negative threshold is nonsense; reject early.
	// 0 = no auto-sleep; > 0 enables it with that idle threshold (minutes).
	if req.IdleStopMinutes < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "idle_stop_minutes must be >= 0, got %d", req.IdleStopMinutes)
	}
	// Birth stopped→delete (#525): same — reject a negative window early.
	// 0 = never delete on stop; > 0 reaps a box left stopped that long.
	if req.DeleteAfterStoppedSeconds < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "delete_after_stopped_seconds must be >= 0, got %d", req.DeleteAfterStoppedSeconds)
	}

	// Pool resolution — if a pool is requested, either validate that
	// the explicit backend_id belongs to that pool, or pick any
	// healthy backend in the pool when backend_id is empty.
	if req.Pool != "" {
		if err := s.resolvePoolPlacement(req); err != nil {
			return nil, err
		}
	}

	// Route to peer if backend_id specifies a remote backend
	if req.BackendId != "" && s.peerPool != nil {
		localID := s.peerPool.LocalBackendID()
		if req.BackendId != localID && req.BackendId != "" {
			peer := s.peerPool.Get(req.BackendId)
			if peer == nil {
				return nil, fmt.Errorf("backend %q not found", req.BackendId)
			}
			if !peer.Healthy {
				return nil, fmt.Errorf("backend %q is not healthy", req.BackendId)
			}
			// Forward to peer — extract auth token from context
			authToken := extractAuthToken(ctx)
			respBody, err := peer.ForwardCreateContainer(authToken, req)
			if err != nil {
				return nil, fmt.Errorf("failed to create container on backend %q: %w", req.BackendId, err)
			}
			return respBody, nil
		}
	}

	// Validate SSH keys at the API boundary to reject placeholder strings early
	for i, key := range req.SshKeys {
		if err := container.ValidateSSHPublicKey(key); err != nil {
			return nil, fmt.Errorf("ssh_keys[%d]: %w", i, err)
		}
	}

	// Audit B-HIGH-1: validate the image against the registry
	// allowlist before any runtime call. Empty allowlist accepts
	// everything (with a startup WARNING); a configured allowlist
	// rejects unknown registries.
	if err := validateImageRegistry(req.Image); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Phase 3.1 follow-up: when CONTAINARIUM_REQUIRE_IMAGE_DIGEST
	// is on, every image reference must carry an `@sha256:<64hex>`
	// suffix so the operator pins the exact image bytes. Disabled
	// by default — opt-in for supply-chain-paranoid deployments.
	if err := validateImageDigest(req.Image); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Phase 3.1 Phase-B: when CONTAINARIUM_VERIFY_IMAGE_DIGEST
	// is on, additionally verify the declared digest matches the
	// registry's published index for that alias. Catches
	// allowlisted-registry MITM and bytes-vs-declared-digest
	// divergence. Pre-pull → fail fast, no bandwidth wasted, no
	// state to clean up. See docs/security/IMAGE-DIGEST-VERIFY-DESIGN.md.
	if err := verifyImageDigestAgainstRegistry(ctx, req.Image); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	// Audit A-HIGH-3: enable_podman=true implies privileged + apparmor=unconfined.
	// Gate that elevation behind CONTAINARIUM_PRIVILEGED_PODMAN_POLICY so
	// non-admin tenants don't auto-escalate just by setting the flag.
	enablePodmanPrivileged := false
	if req.EnablePodman {
		allowed, err := authorizePrivilegedPodman(ctx)
		if err != nil {
			return nil, err
		}
		enablePodmanPrivileged = allowed
	}

	// Build the runtime-neutral box spec
	spec := box.BoxSpec{
		Ref:                    box.BoxRef{Tenant: req.Username},
		Image:                  req.Image,
		SSHKeys:                req.SshKeys,
		Labels:                 req.Labels,
		EnablePodman:           req.EnablePodman,
		EnablePodmanPrivileged: enablePodmanPrivileged,
		AutoStart:              true,
		Stack:                  req.Stack,
		StackParams:            req.StackParameters,
		OSType:                 req.OsType,
		GPUs:                   req.Gpus, // legacy singular `gpu` no longer honored (#673)
		StaticIP:               req.StaticIp,
		// OTel app-monitoring opt-in. The daemon-level collector
		// endpoint is configured at startup via --otel-collector-
		// endpoint (or auto-discovered from the core OTel collector
		// LXC; configured by DualServer). OTelBackendID lets the
		// collector tag emissions with the originating VM for
		// cross-VM Grafana queries. Both are no-ops when
		// req.Monitoring is false.
		Monitoring:            req.Monitoring,
		OTelCollectorEndpoint: s.otelCollectorEndpoint,
		OTelBackendID:         s.localBackendID(),
		// Git source provisioning (optional) — the daemon fetches the
		// repo into the box at create time, no caller→box SSH.
		GitSource:     req.GitSource,
		GitRef:        req.GitRef,
		GitCredential: req.GitCredential,
		WorkspacePath: req.WorkspacePath,
	}
	// Phase 2.5 follow-up — load the OTel bearer for
	// monitoring=true containers. Best-effort: an error
	// loading the bearer leaves OTelBearer empty, which
	// makes the env-stamping path skip the header (pre-2.5
	// behavior). Operators see the WARNING in the daemon log.
	if req.Monitoring {
		bearer, err := LoadOrCreateOTelBearer()
		if err != nil {
			log.Printf("[create] OTel bearer load failed: %v (header omitted; collector remains open)", err)
		}
		spec.OTelBearer = bearer
	}

	// Set resource limits
	if req.Resources != nil {
		spec.Resources.CPU = req.Resources.Cpu
		spec.Resources.Memory = req.Resources.Memory
		spec.Resources.Disk = req.Resources.Disk
	}

	// Use defaults if not specified (os_type takes precedence in manager.go)
	if spec.Image == "" && spec.OSType == 0 {
		spec.Image = "images:ubuntu/24.04"
	}
	if spec.Resources.CPU == "" {
		spec.Resources.CPU = "4"
	}
	if spec.Resources.Memory == "" {
		spec.Resources.Memory = "4GB"
	}
	if spec.Resources.Disk == "" {
		spec.Resources.Disk = "50GB"
	}

	// Async mode - return immediately and create in background
	if req.Async {
		// Check if already creating
		s.pendingMu.Lock()
		if pending, exists := s.pendingCreations[req.Username]; exists && !pending.Done {
			s.pendingMu.Unlock()
			return nil, fmt.Errorf("container creation already in progress for user %s", req.Username)
		}

		// Track pending creation
		s.pendingCreations[req.Username] = &PendingCreation{
			Username:  req.Username,
			StartedAt: time.Now(),
		}
		s.pendingMu.Unlock()

		// Set provisioning callback
		spec.OnProvisioning = func() {
			s.pendingMu.Lock()
			if pending, exists := s.pendingCreations[req.Username]; exists {
				pending.Provisioning = true
			}
			s.pendingMu.Unlock()
		}

		// Start async creation. Use a background context — the request ctx is
		// cancelled once this handler returns the CREATING response.
		go func() {
			info, err := s.boxes().Create(context.Background(), spec)

			// Phase 3.1 Phase-C: post-pull verification.
			// In async mode the HTTP response has already
			// returned with CREATING; mismatch detection
			// here can't reach the caller via the response
			// body, so we delete the container and record
			// the error in the pending state. The operator
			// polling for status sees a Done=true,
			// Error=<digest-mismatch> result.
			if err == nil && info != nil {
				if verr := verifyImageDigestPostPull(context.Background(), req.Image, info.Ref.Name, s.manager); verr != nil {
					if delErr := s.manager.Delete(req.Username, true); delErr != nil {
						log.Printf("[image-digest] async post-pull mismatch: failed to delete container %q: %v", info.Ref.Name, delErr)
					}
					err = verr
					info = nil
				}
			}

			// Birth TTL (#523), async path. The CREATING response already
			// returned, so a failure can't reach the caller via the response
			// body — it surfaces through the pending state (Done=true,
			// Error=<ttl>) the same way the digest-mismatch path above does.
			// stampBirthTTL deletes the box on failure so an ephemeral box
			// never leaks just because the async stamp lost a race.
			if err == nil && info != nil && req.TtlSeconds > 0 {
				if terr := s.stampBirthTTL(info.Ref.Name, req.Username, req.TtlSeconds); terr != nil {
					err = terr
					info = nil
				}
			}

			// Birth idle-stop (#524), async path. Best-effort like the sync
			// path — auto-sleep is an optimization, not a leak contract, so a
			// failed stamp never turns a created box into a failed creation.
			if err == nil && info != nil && req.IdleStopMinutes > 0 {
				s.stampBirthAutoSleep(info.Ref.Name, req.IdleStopMinutes)
			}
			// Birth stopped→delete (#525), async path. Best-effort like above.
			if err == nil && info != nil && req.DeleteAfterStoppedSeconds > 0 {
				s.stampBirthDeleteAfterStopped(info.Ref.Name, req.DeleteAfterStoppedSeconds)
			}

			s.pendingMu.Lock()
			if pending, exists := s.pendingCreations[req.Username]; exists {
				pending.Done = true
				pending.Error = err
			}
			s.pendingMu.Unlock()

			if err != nil {
				log.Printf("Async container creation failed for %s: %v", req.Username, err)
			}

			// Emit event on success
			if err == nil && info != nil {
				s.refreshContainerIPMap()
				s.emitter.EmitContainerCreated(toProtoContainer(info))
			}
		}()

		// Return immediately with CREATING state
		return &pb.CreateContainerResponse{
			Container: &pb.Container{
				Name:     fmt.Sprintf("%s-container", req.Username),
				Username: req.Username,
				State:    pb.ContainerState_CONTAINER_STATE_CREATING,
				Resources: &pb.ResourceLimits{
					Cpu:    spec.Resources.CPU,
					Memory: spec.Resources.Memory,
					Disk:   spec.Resources.Disk,
				},
			},
			Message: fmt.Sprintf("Container creation started for user %s. Poll GET /v1/containers/%s to check status.", req.Username, req.Username),
		}, nil
	}

	// Sync mode - wait for completion
	info, err := s.boxes().Create(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Phase 3.1 Phase-C: post-pull defense-in-depth.
	// Confirm the image landed on disk matches the digest
	// the operator declared. Mismatch means cache tampering
	// or an index race — delete the just-created container
	// rather than leave the attacker's payload running.
	if err := verifyImageDigestPostPull(ctx, req.Image, info.Ref.Name, s.manager); err != nil {
		// Best-effort cleanup; the error we surface is the
		// digest mismatch, which is the load-bearing
		// signal. A failed delete is logged but doesn't
		// shadow the security event.
		if delErr := s.manager.Delete(req.Username, true); delErr != nil {
			log.Printf("[image-digest] failed to delete container %q after post-pull mismatch: %v", info.Ref.Name, delErr)
		}
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	// Birth TTL (#523): stamp the death date now that the box exists, before
	// any best-effort setup, so the ttlsweeper reaps it even if the client
	// dies the instant create returns. stampBirthTTL deletes the box and
	// errors if it can't honor the requested TTL — an ephemeral box that
	// would leak is worse than no box.
	if req.TtlSeconds > 0 {
		if err := s.stampBirthTTL(info.Ref.Name, req.Username, req.TtlSeconds); err != nil {
			return nil, err
		}
	}

	// Birth idle-stop (#524): enable auto-sleep at create with the requested
	// idle threshold, so the box is born with the stop timer and the
	// autosleep loop reclaims its CPU/RAM if a job crashes/cancels without
	// anyone calling toggle_auto_sleep. Best-effort: unlike the TTL (a leak
	// contract), auto-sleep is an optimization — a failed stamp logs and the
	// box keeps running (it can be toggled later), it never fails the create.
	if req.IdleStopMinutes > 0 {
		s.stampBirthAutoSleep(info.Ref.Name, req.IdleStopMinutes)
	}

	// Birth stopped→delete (#525): record the window so the ttlsweeper reaps
	// the box once it's been stopped that long. Best-effort like the other
	// lifecycle stamps. The clock only starts when the box actually stops
	// (StopContainer stamps stopped_at), so just persisting the window here
	// is enough.
	if req.DeleteAfterStoppedSeconds > 0 {
		s.stampBirthDeleteAfterStopped(info.Ref.Name, req.DeleteAfterStoppedSeconds)
	}

	// Stamp tenant secrets into the LXC's env (best-effort — a
	// failure here doesn't fail the create; secrets can always be
	// retried via RefreshSecrets).
	if s.secretsStore != nil {
		if n, err := s.stampSecretsOnLXC(ctx, req.Username); err != nil {
			log.Printf("[secrets] failed to stamp on %s: %v (continuing)", info.Ref.Name, err)
		} else if n > 0 {
			log.Printf("[secrets] stamped %d secret(s) on %s at create time", n, info.Ref.Name)
		}
	}

	// Refresh the collector's IP map so the new container's
	// app-emitted OTLP is attributed correctly. Best-effort.
	s.refreshContainerIPMap()

	// Convert to protobuf
	protoContainer := toProtoContainer(info)
	protoContainer.Pool = s.resolvePool(protoContainer.BackendId)
	protoContainer.SshHost = s.sshHost

	// Emit container created event
	s.emitter.EmitContainerCreated(protoContainer)

	resp := &pb.CreateContainerResponse{
		Container: protoContainer,
		Message:   fmt.Sprintf("Container %s created successfully", info.Ref.Name),
	}

	if ostype.IsWindows(req.OsType) {
		// Windows VM: return RDP address, skip jump server account
		resp.RdpAddress = protoContainer.RdpAddress

		// Register RDP connection in Guacamole (best-effort, runs in background)
		go func() {
			rdpPassword := info.Labels["rdp-password"]
			connID := s.registerGuacamoleConnection(info.Ref.Name, info.IPAddress, "Administrator", rdpPassword)
			if connID != "" {
				// Store connection ID as a label for cleanup on delete
				_ = s.manager.AddLabel(req.Username, guacamoleConnectionIDLabel, connID)
			}
		}()
	} else {
		// Linux container: return SSH command and ensure jump server account.
		resp.SshCommand = sshCommandFor(req.Username, protoContainer.SshHost, info.IPAddress)
		go func() {
			if err := container.EnsureJumpServerAccount(req.Username); err != nil {
				log.Printf("Warning: failed to create jump server account for %s: %v", req.Username, err)
				return
			}
			log.Printf("Jump server account ensured for %s", req.Username)

			// Write the create-request ssh_keys to the HOST-SIDE
			// authorized_keys (the jump-server account's file), the same
			// file AddSSHKey writes and ServeAuthorizedKeys serves to the
			// sentinel keysync. EnsureJumpServerAccount only creates the
			// account with an empty .ssh; the request keys were applied to
			// the LXC-internal authorized_keys (via Container.SSHKeys) but
			// NOT here — so a box created with ssh_keys was reachable on the
			// box itself yet REJECTED at the sentinel (publickey), because
			// sshpiper validates the client against the host-side file. Mirror
			// the request keys here so the sentinel authorizes exactly the
			// keys the box does. Keys are already validated above. (#470)
			for _, key := range req.SshKeys {
				if err := container.AddAuthorizedKey(req.Username, key); err != nil {
					log.Printf("Warning: failed to sync create-request ssh key to jump account for %s: %v", req.Username, err)
				}
			}
		}()
	}

	return resp, nil
}

// ListContainers lists all containers
func (s *ContainerServer) ListContainers(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersRead); err != nil {
		return nil, err
	}
	// Tenant isolation: non-admin callers may only see their own
	// containers. Empty req.Username for a non-admin is rewritten to
	// the authenticated subject (was "list everyone's"); an explicit
	// different username is denied.
	subject, roles, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	if !auth.HasRole(roles, auth.RoleAdmin) {
		if req.Username != "" && req.Username != subject {
			return nil, status.Error(codes.PermissionDenied, "not authorized for this tenant")
		}
		req.Username = subject
	}

	containers, err := s.manager.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Filter containers
	var filtered []incus.ContainerInfo
	for _, c := range containers {
		// Exclude core containers (postgres, caddy) from user-facing listings
		if c.Role.IsCoreRole() {
			continue
		}

		// Filter by username if specified
		if req.Username != "" {
			// Extract username from container name (format: username-container)
			username := c.Name
			if len(c.Name) > 10 && c.Name[len(c.Name)-10:] == "-container" {
				username = c.Name[:len(c.Name)-10]
			}
			if username != req.Username {
				continue
			}
		}

		// Filter by state if specified
		if req.State != pb.ContainerState_CONTAINER_STATE_UNSPECIFIED {
			var containerState pb.ContainerState
			switch c.State {
			case "Running":
				containerState = pb.ContainerState_CONTAINER_STATE_RUNNING
			case "Stopped":
				containerState = pb.ContainerState_CONTAINER_STATE_STOPPED
			case "Frozen":
				containerState = pb.ContainerState_CONTAINER_STATE_FROZEN
			default:
				containerState = pb.ContainerState_CONTAINER_STATE_UNSPECIFIED
			}
			if containerState != req.State {
				continue
			}
		}

		// Filter by labels if specified
		if len(req.LabelFilter) > 0 {
			if !incus.MatchLabels(c.Labels, req.LabelFilter) {
				continue
			}
		}

		filtered = append(filtered, c)
	}

	// Tag local containers with this daemon's backend ID
	if s.peerPool != nil && s.peerPool.LocalBackendID() != "" {
		for i := range filtered {
			filtered[i].BackendID = s.peerPool.LocalBackendID()
		}
	}

	// Convert to protobuf. ListContainers still filters on incus-specific
	// fields (Role) so it stays on the Manager + the exported converter; the
	// proto layer below sees only the runtime-neutral box.BoxStatus.
	var protoContainers []*pb.Container
	for i := range filtered {
		st := boxlxc.StatusFromInfo(&filtered[i])
		pc := toProtoContainer(&st)
		pc.Pool = s.resolvePool(pc.BackendId)
		pc.SshHost = s.sshHost
		protoContainers = append(protoContainers, pc)
	}

	// Add containers from peer backends
	if s.peerPool != nil {
		authToken := extractAuthToken(ctx)
		peerContainers := s.peerPool.ListContainers(authToken)
		for i := range peerContainers {
			st := boxlxc.StatusFromInfo(&peerContainers[i])
			pc := toProtoContainer(&st)
			pc.Pool = s.resolvePool(pc.BackendId)
			pc.SshHost = s.sshHost
			protoContainers = append(protoContainers, pc)
		}
	}

	return &pb.ListContainersResponse{
		Containers: protoContainers,
		TotalCount: safecast.I32(len(protoContainers)),
	}, nil
}

// GetContainer gets information about a specific container
func (s *ContainerServer) GetContainer(ctx context.Context, req *pb.GetContainerRequest) (*pb.GetContainerResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersRead); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	// Check if there's a pending async creation
	s.pendingMu.RLock()
	pending, hasPending := s.pendingCreations[req.Username]
	s.pendingMu.RUnlock()

	if hasPending && !pending.Done {
		// Determine if creating or provisioning
		state := pb.ContainerState_CONTAINER_STATE_CREATING
		if pending.Provisioning {
			state = pb.ContainerState_CONTAINER_STATE_PROVISIONING
		}
		return &pb.GetContainerResponse{
			Container: &pb.Container{
				Name:     fmt.Sprintf("%s-container", req.Username),
				Username: req.Username,
				State:    state,
			},
		}, nil
	}

	if hasPending && pending.Done && pending.Error != nil {
		// Creation failed - return ERROR state with error details
		log.Printf("Async creation failed for %s: %v", req.Username, pending.Error)
		return &pb.GetContainerResponse{
			Container: &pb.Container{
				Name:     fmt.Sprintf("%s-container", req.Username),
				Username: req.Username,
				State:    pb.ContainerState_CONTAINER_STATE_ERROR,
			},
		}, nil
	}

	// Try to get from Incus
	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username})
	if err != nil || info == nil {
		// Not found locally — try peers
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peerContainers := s.peerPool.ListContainers(authToken)
			containerName := req.Username + "-container"
			for _, pc := range peerContainers {
				if pc.Name == containerName {
					st := boxlxc.StatusFromInfo(&pc)
					proto := toProtoContainer(&st)
					proto.Pool = s.resolvePool(proto.BackendId)
					proto.SshHost = s.sshHost
					return &pb.GetContainerResponse{
						Container: proto,
					}, nil
				}
			}
		}

		// If we had a pending creation that completed, clean it up
		if hasPending && pending.Done {
			s.pendingMu.Lock()
			delete(s.pendingCreations, req.Username)
			s.pendingMu.Unlock()
		}
		if err == nil {
			err = fmt.Errorf("container not found")
		}
		return nil, fmt.Errorf("failed to get container: %w", err)
	}

	// Clean up pending creation if exists
	if hasPending {
		s.pendingMu.Lock()
		delete(s.pendingCreations, req.Username)
		s.pendingMu.Unlock()
	}

	protoInfo := toProtoContainer(info)
	protoInfo.Pool = s.resolvePool(protoInfo.BackendId)
	protoInfo.SshHost = s.sshHost
	return &pb.GetContainerResponse{
		Container: protoInfo,
		// TODO: Add metrics
	}, nil
}

// DeleteContainer deletes a container
func (s *ContainerServer) DeleteContainer(ctx context.Context, req *pb.DeleteContainerRequest) (*pb.DeleteContainerResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	containerName := fmt.Sprintf("%s-container", req.Username)

	// Before deleting, deregister Guacamole connection if this is a Windows VM
	s.deregisterGuacamoleConnection(req.Username)

	err := s.manager.Delete(req.Username, req.Force)
	if err != nil {
		// Not found locally — try peers
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.Username, authToken)
			if peer != nil {
				forceParam := ""
				if req.Force {
					forceParam = "?force=true"
				}
				_, statusCode, fwdErr := peer.ForwardRequest("DELETE", fmt.Sprintf("/v1/containers/%s%s", req.Username, forceParam), authToken, nil)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to delete container on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d for delete", peer.ID, statusCode)
				}
				return &pb.DeleteContainerResponse{
					Message:       fmt.Sprintf("Container for user %s deleted on backend %s", req.Username, peer.ID),
					ContainerName: containerName,
				}, nil
			}
		}
		return nil, fmt.Errorf("failed to delete container: %w", err)
	}

	// Cascade-clean the routes + TLS subjects + host user that this
	// container owned. The LXC is gone above; without these steps the
	// public hostname returns 502 (Caddy route still points at a
	// deleted upstream IP) and Caddy keeps trying to ACME-renew an
	// orphaned cert. All best-effort: any single failure logs a
	// warning but doesn't block the response — the LXC delete already
	// succeeded, and partial-cascade is better than telling the caller
	// "delete failed" when the container is in fact gone.
	s.cascadeContainerCleanup(ctx, containerName, req.Username)

	// Emit container deleted event
	s.emitter.EmitContainerDeleted(containerName)

	// Refresh the collector's IP map so the deleted container's IP
	// is no longer claimed in source-IP attribution.
	s.refreshContainerIPMap()

	return &pb.DeleteContainerResponse{
		Message:       fmt.Sprintf("Container for user %s deleted successfully", req.Username),
		ContainerName: containerName,
	}, nil
}

// cascadeContainerCleanup removes the resources that DeleteContainer's
// LXC-delete leaves behind. Documented as #69 / verified live against
// the demo cluster on 2026-05-14.
//
// Order is deliberate:
//  1. Route store first — kills the source of truth so RouteSyncJob
//     will reap the Caddy srv0 route on its next tick (5s). Deleting
//     directly from Caddy without this step lets the sync job
//     resurrect the route within seconds, producing the 502-after-
//     delete trap.
//  2. TLS subject removal — stops Caddy's ACME renewal loop for the
//     dead hostname. Harmless to keep (no upstream to challenge) but
//     wastes rate-limit budget over time.
//  3. Host user (jump-server account) — removes the Linux user, home,
//     and the containarium-shell wrapper. sshpiper auto-reaps the
//     user from its own config on the next keysync (2 min).
//
// On-disk Caddy cert at /data/caddy/certificates/... is intentionally
// left in place — it's harmless after step 2 (no renewal attempts) and
// avoids a "force" mode that the caller probably doesn't want.
func (s *ContainerServer) cascadeContainerCleanup(ctx context.Context, containerName, username string) {
	// 1. Route store: enumerate this container's routes and drop each.
	//    Skip if routeStore was never wired (daemon without app-hosting).
	if s.routeStore != nil {
		routes, err := s.routeStore.ListByContainer(ctx, containerName)
		if err != nil {
			log.Printf("[delete-cascade] list routes for %s failed: %v", containerName, err)
		}
		for _, r := range routes {
			if err := s.routeStore.Delete(ctx, r.FullDomain); err != nil {
				log.Printf("[delete-cascade] delete route %s failed: %v", r.FullDomain, err)
				continue
			}
			log.Printf("[delete-cascade] removed route %s (RouteSyncJob will reap Caddy entry)", r.FullDomain)

			// 2. TLS subject: only if we also have a proxy manager.
			if s.proxyManager != nil {
				if err := s.proxyManager.RemoveTLSSubject(r.FullDomain); err != nil {
					log.Printf("[delete-cascade] remove TLS subject %s failed: %v", r.FullDomain, err)
				} else {
					log.Printf("[delete-cascade] removed TLS automation subject %s", r.FullDomain)
				}
			}
		}
	}

	// 3. Host user. DeleteJumpServerAccount is idempotent (no-op if the
	//    user doesn't exist), so calling it when there isn't one is fine.
	if err := container.DeleteJumpServerAccount(username, false); err != nil {
		log.Printf("[delete-cascade] delete host user %s failed: %v (manual: sudo userdel -r %s)", username, err, username)
	} else {
		log.Printf("[delete-cascade] removed host user %s", username)
	}
}

// StartContainer starts a stopped container
func (s *ContainerServer) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*pb.StartContainerResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	if err := s.manager.Start(req.Username); err != nil {
		// Try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.Username, authToken)
			if peer != nil {
				body, _ := json.Marshal(map[string]interface{}{
					"wait_for_ready":        req.WaitForReady,
					"ready_timeout_seconds": req.ReadyTimeoutSeconds,
				})
				_, _, fwdErr := peer.ForwardRequest("POST", fmt.Sprintf("/v1/containers/%s/start", req.Username), authToken, body)
				if fwdErr == nil {
					return &pb.StartContainerResponse{
						Message: fmt.Sprintf("Container for user %s started on backend %s", req.Username, peer.ID),
					}, nil
				}
			}
		}
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Stamp last-start timestamp so the Phase 2 auto-sleep ticker can
	// enforce its anti-thrash window (don't sleep within 2× threshold
	// of the most recent start). Best-effort — if the SetConfig fails
	// the container is already running, and the worst case is one
	// extra wake → sleep flap.
	if err := s.manager.SetConfig(req.Username+"-container", incus.LastStartedAtKey, time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("[autosleep] failed to stamp %s on %s: %v (continuing)", incus.LastStartedAtKey, req.Username, err)
	}

	// Two-phase reaping (#525): the box is running again, so clear stopped_at.
	// This resets the stopped→delete timer — a box someone keeps waking to
	// investigate never gets reaped; only a box left continuously stopped past
	// its window does. Best-effort + idempotent (UnsetConfig of an absent key
	// is a no-op).
	if err := s.manager.UnsetConfig(req.Username+"-container", incus.StoppedAtKey); err != nil {
		log.Printf("[ttl] failed to clear %s on %s: %v (continuing)", incus.StoppedAtKey, req.Username, err)
	}

	// Re-stamp tenant secrets from the current DB state. Picks up
	// any rotations that happened while the container was stopped;
	// existing processes won't see the change (POSIX inherit-at-fork),
	// but new execs will.
	if s.secretsStore != nil {
		if n, err := s.stampSecretsOnLXC(ctx, req.Username); err != nil {
			log.Printf("[secrets] failed to re-stamp on start of %s-container: %v (continuing)", req.Username, err)
		} else if n > 0 {
			log.Printf("[secrets] re-stamped %d secret(s) on %s-container at start time", n, req.Username)
		}
	}

	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username})
	if err != nil {
		return nil, fmt.Errorf("container started but failed to get info: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("container started but not found on read-back")
	}

	timedOut := false
	if req.WaitForReady {
		timeoutSec := req.ReadyTimeoutSeconds
		if timeoutSec <= 0 {
			timeoutSec = 30
		}
		timedOut = s.waitForContainerReady(ctx, req.Username, info.IPAddress, time.Duration(timeoutSec)*time.Second)
	}

	s.emitter.EmitContainerStarted(toProtoContainer(info))

	// Post-start: point this container's Caddy routes back at the
	// container's direct IP/port (undo the wake-mode swap that
	// StopForAutoSleep applied when the container went to sleep).
	// Only fires for containers with auto-sleep enabled — that's the
	// only path that could have left them in wake mode in the first
	// place. Best-effort; RouteSyncJob re-converges if this fails.
	if s.wakeRouter != nil && s.routeStore != nil && info != nil && info.AutoSleepEnabled {
		containerName := req.Username + "-container"
		routes, err := s.routeStore.ListByContainer(ctx, containerName)
		if err != nil {
			log.Printf("[wake] list routes for %s: %v (skipping swap-to-direct)", containerName, err)
		} else if len(routes) > 0 {
			if err := s.wakeRouter.SwapToDirect(ctx, containerName, routes); err != nil {
				log.Printf("[wake] swap-to-direct %s: %v", containerName, err)
			}
		}
	}

	msg := fmt.Sprintf("Container for user %s started successfully", req.Username)
	if req.WaitForReady && timedOut {
		msg = fmt.Sprintf("Container for user %s started but readiness probe timed out", req.Username)
	}

	return &pb.StartContainerResponse{
		Message:       msg,
		Container:     toProtoContainer(info),
		ReadyTimedOut: timedOut,
	}, nil
}

// waitForContainerReady polls a TCP dial against the container's
// primary exposed port until it accepts or the deadline elapses.
// Returns true when the probe timed out. A nil routeStore, an absent
// route record, an empty container IP, or a non-positive port all
// short-circuit to "ready immediately" — the probe is opportunistic.
func (s *ContainerServer) waitForContainerReady(ctx context.Context, username, containerIP string, total time.Duration) bool {
	if s.routeStore == nil || containerIP == "" {
		return false
	}
	containerName := username + "-container"
	routes, err := s.routeStore.ListByContainer(ctx, containerName)
	if err != nil || len(routes) == 0 {
		return false
	}
	port := routes[0].TargetPort
	if port <= 0 {
		return false
	}

	addr := net.JoinHostPort(containerIP, strconv.Itoa(port))
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return false
		}
		select {
		case <-ctx.Done():
			return true
		case <-time.After(250 * time.Millisecond):
		}
	}
	return true
}

// StopContainer stops a running container
func (s *ContainerServer) StopContainer(ctx context.Context, req *pb.StopContainerRequest) (*pb.StopContainerResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	if err := s.manager.Stop(req.Username, req.Force); err != nil {
		// Try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.Username, authToken)
			if peer != nil {
				body, _ := json.Marshal(map[string]bool{"force": req.Force})
				_, _, fwdErr := peer.ForwardRequest("POST", fmt.Sprintf("/v1/containers/%s/stop", req.Username), authToken, body)
				if fwdErr == nil {
					return &pb.StopContainerResponse{
						Message: fmt.Sprintf("Container for user %s stopped on backend %s", req.Username, peer.ID),
					}, nil
				}
			}
		}
		return nil, fmt.Errorf("failed to stop container: %w", err)
	}

	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username})
	if err != nil {
		return nil, fmt.Errorf("container stopped but failed to get info: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("container stopped but not found on read-back")
	}

	// Two-phase reaping (#525): record when the box became stopped so the
	// ttlsweeper's stopped→delete timer runs from here. Best-effort — a failed
	// stamp just means the stopped→delete clock doesn't start until a later
	// stop restamps it; it never fails the stop. Only matters for boxes that
	// opted into delete_after_stopped, but stamping unconditionally keeps the
	// timestamp honest for any box and costs one config write.
	if serr := s.manager.SetConfig(info.Ref.Name, incus.StoppedAtKey, time.Now().UTC().Format(time.RFC3339)); serr != nil {
		log.Printf("[ttl] failed to stamp %s on %s: %v (stopped→delete timer not started)", incus.StoppedAtKey, info.Ref.Name, serr)
	}

	s.emitter.EmitContainerStopped(toProtoContainer(info))

	return &pb.StopContainerResponse{
		Message:   fmt.Sprintf("Container for user %s stopped successfully", req.Username),
		Container: toProtoContainer(info),
	}, nil
}

// StopForAutoSleep is the entry point for the autosleep ticker. It
// reuses StopContainer's full plumbing (manager.Stop, event emission)
// so observers can't distinguish an auto-sleep from a manual stop on
// the bus — by design — and prepends a tagged log line so operators
// can grep for the reason that triggered it.
//
// Lives on ContainerServer rather than the autosleep package so the
// ticker depends on a narrow interface (Stopper) rather than the full
// internal/server import graph.
func (s *ContainerServer) StopForAutoSleep(ctx context.Context, username, reason string, idleMinutes int) error {
	// Autosleep is daemon-internal — promote the context to the system
	// identity so the StopContainer authz check passes.
	ctx = auth.ContextWithSystemIdentity(ctx)
	log.Printf("[autosleep] stopping username=%s reason=%q idle_minutes=%d", username, reason, idleMinutes)

	// Swap Caddy routes to the wake handler BEFORE stopping the
	// container. Doing the swap first means any request arriving in
	// the brief stop-window lands on /wake/, which (since the
	// container is still Running at that instant) returns ready=true
	// immediately and proxies through — one extra hop, but no 502.
	// The reverse order leaves Caddy pointing at a dead container
	// for the duration of the graceful stop, which is a guaranteed
	// 502 window on every auto-sleep event. See #224.
	if s.wakeRouter != nil && s.routeStore != nil {
		containerName := username + "-container"
		routes, err := s.routeStore.ListByContainer(ctx, containerName)
		if err != nil {
			log.Printf("[autosleep] list routes for %s: %v (skipping swap-to-wake)", containerName, err)
		} else if len(routes) > 0 {
			if err := s.wakeRouter.SwapToWake(ctx, containerName, routes); err != nil {
				log.Printf("[autosleep] swap-to-wake %s: %v", containerName, err)
				// Don't fail the stop — RouteSyncJob will re-converge.
			}
		}
	}

	if _, err := s.StopContainer(ctx, &pb.StopContainerRequest{Username: username, Force: false}); err != nil {
		return err
	}
	return nil
}

// ResizeContainer dynamically resizes container resources
func (s *ContainerServer) ResizeContainer(ctx context.Context, req *pb.ResizeContainerRequest) (*pb.ResizeContainerResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	// At least one resource must be specified
	if req.Cpu == "" && req.Memory == "" && req.Disk == "" {
		return nil, fmt.Errorf("at least one resource (cpu, memory, or disk) must be specified")
	}

	containerName := fmt.Sprintf("%s-container", req.Username)

	// Perform resize — try local first, then peer
	if err := s.manager.Resize(containerName, req.Cpu, req.Memory, req.Disk, false); err != nil {
		// Container not found locally — check peers
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			log.Printf("[resize] container %s not local, searching peers (token len=%d)", containerName, len(authToken))
			peer := s.peerPool.FindContainerPeer(req.Username, authToken)
			if peer != nil {
				log.Printf("[resize] found %s on peer %s, forwarding", containerName, peer.ID)
				body, _ := json.Marshal(map[string]string{
					"cpu":    req.Cpu,
					"memory": req.Memory,
					"disk":   req.Disk,
				})
				respBody, statusCode, fwdErr := peer.ForwardRequest("PUT", fmt.Sprintf("/v1/containers/%s/resize", req.Username), authToken, body)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to resize container on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d for resize: %s", peer.ID, statusCode, string(respBody))
				}
				return &pb.ResizeContainerResponse{
					Message: fmt.Sprintf("Container %s resized on backend %s", containerName, peer.ID),
				}, nil
			}
		}
		return nil, fmt.Errorf("failed to resize container: %w", err)
	}

	// Get updated container info
	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username})
	if err != nil {
		return nil, fmt.Errorf("failed to get updated container info: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("container resized but not found on read-back")
	}

	// Convert to protobuf
	protoContainer := toProtoContainer(info)

	return &pb.ResizeContainerResponse{
		Message:   fmt.Sprintf("Container %s resized successfully", containerName),
		Container: protoContainer,
	}, nil
}

// CleanupDisk frees disk space inside a container
func (s *ContainerServer) CleanupDisk(ctx context.Context, req *pb.CleanupDiskRequest) (*pb.CleanupDiskResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	message, freedBytes, err := s.manager.CleanupDisk(req.Username)
	if err != nil {
		// Try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.Username, authToken)
			if peer != nil {
				respBody, statusCode, fwdErr := peer.ForwardRequest("POST", fmt.Sprintf("/v1/containers/%s/cleanup-disk", req.Username), authToken, nil)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to cleanup disk on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d for cleanup: %s", peer.ID, statusCode, string(respBody))
				}
				// Parse peer response
				var peerResp struct {
					Message    string `json:"message"`
					FreedBytes int64  `json:"freedBytes"`
				}
				if jsonErr := json.Unmarshal(respBody, &peerResp); jsonErr == nil {
					return &pb.CleanupDiskResponse{
						Message:    peerResp.Message,
						FreedBytes: peerResp.FreedBytes,
					}, nil
				}
				return &pb.CleanupDiskResponse{
					Message: fmt.Sprintf("Disk cleaned on backend %s", peer.ID),
				}, nil
			}
		}
		return nil, fmt.Errorf("failed to clean up disk: %w", err)
	}

	// Get updated container info
	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username})
	if err != nil {
		return nil, fmt.Errorf("disk cleaned but failed to get container info: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("disk cleaned but container not found on read-back")
	}

	return &pb.CleanupDiskResponse{
		Message:    message,
		FreedBytes: freedBytes,
		Container:  toProtoContainer(info),
	}, nil
}

// InstallStack installs a software stack or base script on a running container
func (s *ContainerServer) InstallStack(ctx context.Context, req *pb.InstallStackRequest) (*pb.InstallStackResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.StackId == "" {
		return nil, fmt.Errorf("stack_id is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	// Reject stack installation on Windows VMs
	if containerInfo, getErr := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username}); getErr == nil && containerInfo != nil {
		if osLabel, ok := containerInfo.Labels[ostype.OSTypeLabelKey]; ok {
			if ostype.IsWindows(ostype.OSTypeFromLabel(osLabel)) {
				return nil, fmt.Errorf("stack installation is not supported on Windows VMs")
			}
		}
	}

	if err := s.manager.InstallStack(req.Username, req.StackId); err != nil {
		return nil, fmt.Errorf("failed to install stack: %w", err)
	}

	// Get updated container info
	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username})
	if err != nil {
		return nil, fmt.Errorf("stack installed but failed to get container info: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("stack installed but container not found on read-back")
	}

	return &pb.InstallStackResponse{
		Message:   fmt.Sprintf("Stack %q installed successfully on %s-container", req.StackId, req.Username),
		Container: toProtoContainer(info),
	}, nil
}

// ListStacks returns the catalog of available software stacks and their
// parameter schemas. The web UI uses this to render the Create Container
// dialog's stack dropdown and any dynamically-shown parameter inputs.
func (s *ContainerServer) ListStacks(ctx context.Context, req *pb.ListStacksRequest) (*pb.ListStacksResponse, error) {
	mgr := stacks.GetDefault()
	all := mgr.GetAllStacks()

	out := make([]*pb.StackInfo, 0, len(all))
	for _, stk := range all {
		params := make([]*pb.StackParameter, 0, len(stk.Parameters))
		for _, p := range stk.Parameters {
			params = append(params, &pb.StackParameter{
				Name:        p.Name,
				Label:       p.Label,
				Description: p.Description,
				Type:        p.Type,
				Default:     p.Default,
				Required:    p.Required,
			})
		}
		out = append(out, &pb.StackInfo{
			Id:          stk.ID,
			Name:        stk.Name,
			Description: stk.Description,
			Icon:        stk.Icon,
			Parameters:  params,
		})
	}

	return &pb.ListStacksResponse{Stacks: out}, nil
}

// AdoptMigratedContainer is the destination-side helper called by a
// peer's MoveContainer after the LXC has been `incus copy`'d to this
// daemon. The LXC exists on this host's incusd but Containarium
// doesn't know about it yet — no host user, no shell wrapper, no
// route record. This RPC fills that in and returns the container's
// new local IP for the source to use in its route store cutover.
//
// Idempotent on retry: if the host user already exists,
// EnsureJumpServerAccount is a no-op; starting an already-running
// container is a no-op; etc. So a transient network failure
// mid-adoption can be safely re-driven.
func (s *ContainerServer) AdoptMigratedContainer(ctx context.Context, req *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	// AdoptMigratedContainer is called peer-to-peer with the
	// destination daemon's system token (admin role). It has no
	// user-facing semantic — it's the receiving half of
	// MoveContainer's handshake. Admin-only at both gates: the
	// RequireRole check stops any user token from crafting an
	// adoption request, even one that names their own username
	// (which AuthorizeTenant would otherwise pass).
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	containerName := fmt.Sprintf("%s-container", req.Username)

	// Host-side jump-server account. EnsureJumpServerAccount handles
	// the idempotent case so re-running this RPC won't error.
	if err := container.EnsureJumpServerAccount(req.Username); err != nil {
		return nil, fmt.Errorf("ensure jump server account: %w", err)
	}

	// OTel env-var re-stamping. If the migrated container had
	// monitoring=true on the source, the OTEL_* env vars are still
	// pointing at the SOURCE daemon's collector IP — which is unreachable
	// (or wrong tenant!) from this destination. Re-stamp them with our
	// local collector endpoint before starting the container, so the
	// SDK inside picks up the new endpoint on its first batch flush.
	//
	// Reading MonitoringEnabled from the just-arrived LXC's Incus config
	// is reliable: the env vars themselves are the source of truth, and
	// `incus copy` preserves them, so if the source had monitoring on,
	// OTEL_EXPORTER_OTLP_ENDPOINT is non-empty in the destination's
	// config map right now (just pointing at the wrong place).
	if s.otelCollectorEndpoint != "" {
		if info, _ := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username}); info != nil && info.MonitoringEnabled {
			// Phase 2.5 follow-up — re-stamp the bearer at
			// the destination too. Best-effort; an empty
			// bearer omits the header so monitoring still
			// works (collector remains open).
			bearer, _ := LoadOrCreateOTelBearer()
			envVars := container.OTelEnvVarsForMigrationWithBearer(
				req.Username, containerName, s.localBackendID(), s.otelCollectorEndpoint, bearer,
			)
			for k, v := range envVars {
				if err := s.manager.SetEnv(containerName, k, v); err != nil {
					log.Printf("[adopt] failed to re-stamp %s on %s: %v (continuing — partial OTel beats none)", k, containerName, err)
				}
			}
			// Re-drop the dotenv file at the destination too, so
			// docker apps pick up the new collector endpoint. #370.
			if err := s.manager.WriteOTelEnvFile(containerName, envVars); err != nil {
				log.Printf("[adopt] failed to write env file on %s: %v (continuing)", containerName, err)
			}
			log.Printf("[adopt] re-stamped OTel env vars on %s for destination collector", containerName)
		}
	}

	// Start the container — the source already pushed the LXC's
	// filesystem state. Idempotent if already running.
	if s.moveRunner != nil {
		if err := s.moveRunner.Start(containerName); err != nil {
			return nil, fmt.Errorf("start adopted container: %w", err)
		}
	}

	// Get the new IP. The box backend's Get() reads from the substrate.
	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username})
	if err != nil {
		return nil, fmt.Errorf("get adopted container info: %w", err)
	}
	newIP := ""
	if info != nil {
		newIP = info.IPAddress
	}
	if newIP == "" {
		return nil, fmt.Errorf("adopted container has no IP address yet (still initializing?)")
	}

	// The adopted container now lives on this VM under a new IP —
	// refresh the local collector's IP map so its OTLP traffic is
	// attributed correctly. The source VM will refresh its own map
	// when it deletes/cleans the migrated-out shell.
	s.refreshContainerIPMap()

	// Note: we deliberately do NOT create matching route store rows
	// here. The source-side orchestrator owns the route lifecycle —
	// it updates the existing route rows' target_ip after we return
	// the new IP. This keeps the source of truth on one side and
	// avoids a transient "route exists on both sides at different
	// IPs" window.
	//
	// req.SourceRoutes is accepted (and logged) for forward
	// compatibility: if a future variant of the protocol wants the
	// destination to be authoritative over its own route store, the
	// data is already on the wire.
	if len(req.SourceRoutes) > 0 {
		log.Printf("[adopt] %s arriving with %d source routes (source owns the swap)", req.Username, len(req.SourceRoutes))
	}

	return &pb.AdoptMigratedContainerResponse{
		Message:      fmt.Sprintf("Container %s adopted, ready at %s", req.Username, newIP),
		NewIpAddress: newIP,
	}, nil
}

// otelEnvKeys lists the environment variables the toggle path
// stamps / unsets. Includes both the legacy OTEL_* form (read by
// OTel SDKs auto-discovering) and the split CONTAINARIUM_* form
// (read by the platform sidecar's compose interpolation). Both
// shapes have to be unset on disable so the LXC's env is fully
// clean afterward; otherwise a leftover CONTAINARIUM_CONTAINER_ID
// would still appear in `printenv` and confuse audit / debug.
var otelEnvKeys = []string{
	"OTEL_EXPORTER_OTLP_ENDPOINT",
	"OTEL_EXPORTER_OTLP_PROTOCOL",
	"OTEL_EXPORTER_OTLP_HEADERS", // Phase 2.5 follow-up — bearer auth
	"OTEL_SERVICE_NAME",
	"OTEL_RESOURCE_ATTRIBUTES",
	"CONTAINARIUM_CONTAINER_ID",
	"CONTAINARIUM_BACKEND_ID",
	"CONTAINARIUM_TENANT_ID",
}

// ToggleMonitoring enables / disables app-emitted OTel on an existing
// container without recreating it. Per the OTel design doc's v2 TODO.
//
// Enable path: requires the daemon to have a collector endpoint
// configured (FailedPrecondition if not). Stamps the four OTEL_*
// env vars via incus config-update, then stops + starts the LXC so
// the env reaches the app process — env-var changes don't take
// effect on a running container's processes.
//
// Disable path: deletes the four OTEL_* env keys from the LXC's
// Incus config (so the SDK falls back to its no-endpoint defaults
// rather than seeing literal empty strings, which some SDKs flag
// as misconfig), then stops + starts the LXC.
//
// Core containers are refused — they don't run user code and don't
// need app-emitted telemetry.
func (s *ContainerServer) ToggleMonitoring(ctx context.Context, req *pb.ToggleMonitoringRequest) (*pb.ToggleMonitoringResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username})
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "container for user %s not found: %v", req.Username, err)
	}
	if info == nil {
		return nil, status.Errorf(codes.NotFound, "container for user %s not found", req.Username)
	}
	if info.IsCore {
		return nil, status.Errorf(codes.InvalidArgument, "container %s is a core container; monitoring is for user containers only", info.Ref.Name)
	}

	containerName := info.Ref.Name

	if req.Enabled {
		if s.otelCollectorEndpoint == "" {
			return nil, status.Error(codes.FailedPrecondition, "OTel collector endpoint is not configured on this daemon; cannot enable monitoring")
		}
		// Phase 2.5 follow-up — bearer load is best-effort.
		// On failure the header is omitted and the collector
		// stays open (pre-2.5 behavior), so monitoring still
		// works for the operator.
		bearer, _ := LoadOrCreateOTelBearer()
		envVars := container.OTelEnvVarsForMigrationWithBearer(
			req.Username, containerName, s.localBackendID(), s.otelCollectorEndpoint, bearer,
		)
		for k, v := range envVars {
			if err := s.manager.SetEnv(containerName, k, v); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to stamp %s: %v", k, err)
			}
		}
		// Also drop the dotenv file so nested docker / docker-compose
		// apps (which don't inherit the LXC env) can consume the config
		// via `env_file:`. Best-effort — the Incus-config env above
		// already covers native-LXC apps. See #370.
		if err := s.manager.WriteOTelEnvFile(containerName, envVars); err != nil {
			log.Printf("[togglemonitor] %s: failed to write env file: %v (native-LXC env still stamped)", containerName, err)
		}
	} else {
		for _, k := range otelEnvKeys {
			if err := s.manager.UnsetEnv(containerName, k); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to unset %s: %v", k, err)
			}
		}
		if err := s.manager.RemoveOTelEnvFile(containerName); err != nil {
			log.Printf("[togglemonitor] %s: failed to remove env file: %v", containerName, err)
		}
	}

	// Restart so the new env reaches the app. The container was
	// running before — we ignore stop errors (LXC might be already
	// stopped, in which case stop is a no-op).
	wasRunning := info.State == pb.ContainerState_CONTAINER_STATE_RUNNING
	if wasRunning {
		if err := s.manager.Stop(req.Username, false); err != nil {
			log.Printf("[togglemonitor] %s stop returned %v (continuing)", containerName, err)
		}
		if err := s.manager.Start(req.Username); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to start container after env update: %v", err)
		}
	}

	// Refresh the collector's IP map — the container may have a
	// new IP after restart, and we want source-IP attribution to
	// stay accurate.
	s.refreshContainerIPMap()

	msg := "monitoring disabled"
	if req.Enabled {
		msg = "monitoring enabled"
	}
	if wasRunning {
		msg += " — container restarted"
	} else {
		msg += " — container was stopped; new env takes effect on next start"
	}

	return &pb.ToggleMonitoringResponse{
		Message:           msg,
		MonitoringEnabled: req.Enabled,
	}, nil
}

// ToggleAutoSleep writes the per-container auto-sleep opt-in flag
// (Phase 1 of the serverless feature). Works on running or stopped
// containers; Incus accepts config updates in either state.
//
// On enable, both the flag and the threshold key are written. The
// threshold key persists across disables so a re-enable restores
// the prior value; an explicit idle_threshold_minutes > 0 always
// overwrites, otherwise the existing key or the 15-minute default
// applies. Core containers are refused — they don't represent user
// workloads and shouldn't be sleeping.
func (s *ContainerServer) ToggleAutoSleep(ctx context.Context, req *pb.ToggleAutoSleepRequest) (*pb.ToggleAutoSleepResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: req.Username})
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "container for user %s not found: %v", req.Username, err)
	}
	if info == nil {
		return nil, status.Errorf(codes.NotFound, "container for user %s not found", req.Username)
	}
	if info.IsCore {
		return nil, status.Errorf(codes.InvalidArgument, "container %s is a core container; auto-sleep is for user containers only", info.Ref.Name)
	}

	containerName := info.Ref.Name
	effectiveThreshold := info.IdleThresholdMinutes
	if req.IdleThresholdMinutes > 0 {
		effectiveThreshold = req.IdleThresholdMinutes
	}
	if effectiveThreshold < 1 {
		effectiveThreshold = incus.DefaultIdleThresholdMinutes
	}

	enabledStr := "false"
	if req.Enabled {
		enabledStr = "true"
	}
	if err := s.manager.SetConfig(containerName, incus.AutoSleepEnabledKey, enabledStr); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to set %s: %v", incus.AutoSleepEnabledKey, err)
	}
	if req.Enabled || req.IdleThresholdMinutes > 0 {
		if err := s.manager.SetConfig(containerName, incus.IdleThresholdMinutesKey, strconv.Itoa(int(effectiveThreshold))); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to set %s: %v", incus.IdleThresholdMinutesKey, err)
		}
	}

	msg := "auto-sleep disabled"
	if req.Enabled {
		msg = fmt.Sprintf("auto-sleep enabled at %dm", effectiveThreshold)
	}
	return &pb.ToggleAutoSleepResponse{
		Message:              msg,
		AutoSleepEnabled:     req.Enabled,
		IdleThresholdMinutes: effectiveThreshold,
	}, nil
}

// AddSSHKey appends an SSH public key to the user's host-side
// authorized_keys file (/home/<username>/.ssh/authorized_keys).
//
// Scope note: this writes the host-side file, not the LXC-internal
// one. That's the file sshpiper's keysync (running on the sentinel)
// reads from via /authorized-keys to authenticate inbound SSH. Adding
// only inside the LXC would not let anyone SSH in via the sentinel.
//
// The intended use case is recovery after a lost ephemeral key: an
// agent or operator generates a fresh keypair locally, calls this RPC
// with the public half, and within ~2 minutes (next sentinel keysync
// tick) the new key is live for SSH access.
//
// Idempotent — a key already present is a no-op success.
func (s *ContainerServer) AddSSHKey(ctx context.Context, req *pb.AddSSHKeyRequest) (*pb.AddSSHKeyResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSSHWrite); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.SshPublicKey == "" {
		return nil, fmt.Errorf("ssh_public_key is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	if err := container.AddAuthorizedKey(req.Username, req.SshPublicKey); err != nil {
		return nil, fmt.Errorf("add authorized key: %w", err)
	}

	total, err := container.CountAuthorizedKeys(req.Username)
	if err != nil {
		// Counting failed but the add succeeded — return success with
		// zero so the caller still knows the add went through.
		log.Printf("[add-ssh-key] count after add failed for %s: %v", req.Username, err)
		total = 0
	}

	return &pb.AddSSHKeyResponse{
		Message:   fmt.Sprintf("SSH key added for %s (sentinel keysync will propagate within ~2m)", req.Username),
		TotalKeys: total,
	}, nil
}

// RemoveSSHKey removes a specific SSH public key from the user's
// host-side authorized_keys file. No-op if the key isn't present.
func (s *ContainerServer) RemoveSSHKey(ctx context.Context, req *pb.RemoveSSHKeyRequest) (*pb.RemoveSSHKeyResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSSHWrite); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.SshPublicKey == "" {
		return nil, fmt.Errorf("ssh_public_key is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	if err := container.RemoveAuthorizedKey(req.Username, req.SshPublicKey); err != nil {
		return nil, fmt.Errorf("remove authorized key: %w", err)
	}

	total, err := container.CountAuthorizedKeys(req.Username)
	if err != nil {
		log.Printf("[remove-ssh-key] count after remove failed for %s: %v", req.Username, err)
		total = 0
	}

	return &pb.RemoveSSHKeyResponse{
		Message:   fmt.Sprintf("SSH key removed for %s", req.Username),
		TotalKeys: total,
	}, nil
}

// GetMetrics gets runtime metrics for containers
func (s *ContainerServer) GetMetrics(ctx context.Context, req *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	// Tenant isolation: as with ListContainers, empty username for a
	// non-admin is rewritten to the authenticated subject (was "all
	// containers"); a different explicit username is denied.
	subject, roles, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	if !auth.HasRole(roles, auth.RoleAdmin) {
		if req.Username != "" && req.Username != subject {
			return nil, status.Error(codes.PermissionDenied, "not authorized for this tenant")
		}
		req.Username = subject
	}

	var protoMetrics []*pb.ContainerMetrics

	if req.Username != "" {
		// Get metrics for a specific container — try local first, then peers
		metrics, err := s.manager.GetMetrics(req.Username)
		if err != nil {
			// Not found locally — try peers
			if s.peerPool != nil {
				authToken := extractAuthToken(ctx)
				peer := s.peerPool.FindContainerPeer(req.Username, authToken)
				if peer != nil {
					body, peerErr := peer.ForwardGetMetrics(authToken, req.Username)
					if peerErr == nil {
						// Parse and return peer metrics (use protojson for enum handling)
						var peerResp pb.GetMetricsResponse
						if jsonErr := protojson.Unmarshal(body, &peerResp); jsonErr == nil {
							return &peerResp, nil
						}
					}
				}
			}
			return nil, fmt.Errorf("failed to get metrics: %w", err)
		}
		protoMetrics = append(protoMetrics, toProtoMetrics(metrics))
	} else {
		// Get metrics for all containers (local)
		allMetrics, err := s.manager.GetAllMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to get metrics: %w", err)
		}
		for _, m := range allMetrics {
			protoMetrics = append(protoMetrics, toProtoMetrics(m))
		}

		// Merge metrics from all healthy peers
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			for _, peer := range s.peerPool.Peers() {
				if !peer.Healthy {
					continue
				}
				body, err := peer.ForwardGetMetrics(authToken, "")
				if err != nil {
					log.Printf("[metrics] peer %s: %v", peer.ID, err)
					continue
				}
				var peerMetricsResp pb.GetMetricsResponse
				if err := protojson.Unmarshal(body, &peerMetricsResp); err != nil {
					log.Printf("[metrics] peer %s parse error: %v", peer.ID, err)
					continue
				}
				protoMetrics = append(protoMetrics, peerMetricsResp.Metrics...)
			}
		}
	}

	return &pb.GetMetricsResponse{
		Metrics: protoMetrics,
	}, nil
}

// daemonReleaseChecker caches the latest GitHub release across requests so a
// busy fleet's status checks don't burn the unauthenticated GitHub rate
// limit. Package-level (not per-request) for that shared cache. #354.
var daemonReleaseChecker = releasecheck.New()

// GetLatestRelease reports the latest published Containarium release vs this
// daemon's running version. Admin-only, matching the other System endpoints.
// Best-effort: a failed/rate-limited GitHub lookup yields an empty
// latest_release (and update_available=false) rather than an error. #354.
func (s *ContainerServer) GetLatestRelease(ctx context.Context, req *pb.GetLatestReleaseRequest) (*pb.GetLatestReleaseResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	current := version.GetVersion()
	latest, _ := daemonReleaseChecker.Latest(ctx) // empty on persistent failure
	return &pb.GetLatestReleaseResponse{
		LatestRelease:   latest,
		CurrentVersion:  current,
		UpdateAvailable: releasecheck.UpdateAvailable(current, latest),
	}, nil
}

// ValidateGPU launches a throwaway nvidia.runtime LXC on the target backend,
// runs nvidia-smi inside, tears it down, and reports whether the GPU is usable.
// Admin-only. An empty (or local) backend_id runs the check on this daemon's
// own host; a peer backend_id forwards to that peer's daemon, which runs the
// same check locally on its host. See #316.
func (s *ContainerServer) ValidateGPU(ctx context.Context, req *pb.ValidateGPURequest) (*pb.ValidateGPUResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}

	// Remote backend → forward to the owning peer (it validates its own GPU).
	if req.BackendId != "" && req.BackendId != s.localBackendID() {
		if s.peerPool == nil {
			return nil, status.Errorf(codes.Unavailable, "backend %q: no peer pool configured on this daemon", req.BackendId)
		}
		peer := s.peerPool.Get(req.BackendId)
		if peer == nil {
			return nil, status.Errorf(codes.NotFound, "backend %q not found (see 'containarium backends list')", req.BackendId)
		}
		body, err := protojson.Marshal(req)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "marshal validate-gpu request: %v", err)
		}
		respBody, st, err := peer.ForwardRequest("POST", "/v1/validate-gpu", extractAuthToken(ctx), body)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward validate-gpu to %s: %v", req.BackendId, err)
		}
		if st >= 400 {
			return nil, status.Errorf(codes.Internal, "peer %s returned status %d for validate-gpu", req.BackendId, st)
		}
		var resp pb.ValidateGPUResponse
		if err := protojson.Unmarshal(respBody, &resp); err != nil {
			return nil, status.Errorf(codes.Internal, "parse peer %s validate-gpu response: %v", req.BackendId, err)
		}
		resp.BackendId = req.BackendId
		return &resp, nil
	}

	// Local backend.
	res := s.manager.ValidateGPU(req.Pci)
	return &pb.ValidateGPUResponse{
		Status:        gpuValidationStatusToProto(res.Status),
		GpuModel:      res.Model,
		DriverVersion: res.DriverVersion,
		Detail:        res.Detail,
		BackendId:     req.BackendId,
	}, nil
}

// gpuValidationStatusToProto maps the manager's GPU validation status string to
// the proto enum.
func gpuValidationStatusToProto(s string) pb.ValidateGPUResponse_GPUStatus {
	switch s {
	case container.GPUStatusOK:
		return pb.ValidateGPUResponse_GPU_STATUS_OK
	case container.GPUStatusUnavailable:
		return pb.ValidateGPUResponse_GPU_STATUS_UNAVAILABLE
	default:
		return pb.ValidateGPUResponse_GPU_STATUS_UNSPECIFIED
	}
}

// TriggerUpgrade upgrades a backend's daemon to the binary the sentinel
// currently serves, immediately rather than on the periodic auto-update tick.
// Admin-only. An empty (or local) backend_id upgrades this daemon; a peer
// backend_id forwards to that peer, which upgrades itself. The upgrade is
// async: a successful local swap restarts this daemon, so callers confirm the
// result via the backend version in ListBackends (the in-memory job is lost on
// restart, so GetUpgradeStatus then returns "unknown"). #354 Phase B.
func (s *ContainerServer) TriggerUpgrade(ctx context.Context, req *pb.TriggerUpgradeRequest) (*pb.TriggerUpgradeResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}

	// Remote backend → forward to the owning peer (it upgrades its own daemon).
	if req.BackendId != "" && req.BackendId != s.localBackendID() {
		if s.peerPool == nil {
			return nil, status.Errorf(codes.Unavailable, "backend %q: no peer pool configured on this daemon", req.BackendId)
		}
		peer := s.peerPool.Get(req.BackendId)
		if peer == nil {
			return nil, status.Errorf(codes.NotFound, "backend %q not found (see 'containarium backends list')", req.BackendId)
		}
		body, err := protojson.Marshal(req)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "marshal upgrade request: %v", err)
		}
		respBody, st, err := peer.ForwardRequest("POST", "/v1/backends/upgrade", extractAuthToken(ctx), body)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward upgrade to %s: %v", req.BackendId, err)
		}
		if st >= 400 {
			return nil, status.Errorf(codes.Internal, "peer %s returned status %d for upgrade", req.BackendId, st)
		}
		var resp pb.TriggerUpgradeResponse
		if err := protojson.Unmarshal(respBody, &resp); err != nil {
			return nil, status.Errorf(codes.Internal, "parse peer %s upgrade response: %v", req.BackendId, err)
		}
		resp.BackendId = req.BackendId
		return &resp, nil
	}

	// Local backend.
	if s.autoUpdater == nil {
		return nil, status.Error(codes.Unavailable, "auto-update is not configured on this daemon (no sentinel binary source)")
	}

	current := version.GetVersion()
	backendKey := s.localBackendID()

	s.upgradeMu.Lock()
	if s.upgradeJobs == nil {
		s.upgradeJobs = make(map[string]*upgradeJob)
		s.upgradeBusy = make(map[string]bool)
	}
	if s.upgradeBusy[backendKey] {
		s.upgradeMu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "an upgrade is already in progress on this backend")
	}
	id := fmt.Sprintf("upg-%d", time.Now().UnixNano())
	job := &upgradeJob{id: id, backendID: req.BackendId, status: "in_progress", currentVersion: current}
	s.upgradeJobs[id] = job
	s.upgradeBusy[backendKey] = true
	s.upgradeMu.Unlock()

	subject, _, _ := auth.SubjectFromGRPCContext(ctx)
	log.Printf("[upgrade] triggered by %q on backend %q (from %s, force=%v, job=%s)", subject, backendKey, current, req.Force, id)

	// Run async: TriggerNow restarts the daemon on a successful swap, so neither
	// this goroutine nor the in-memory job survives a local upgrade. We still
	// record terminal state for the noop/failure paths, which return WITHOUT a
	// restart. Detach from the request's cancellation (the handler returns
	// immediately) while keeping its values — the upgrade must outlive the RPC.
	upgradeCtx := context.WithoutCancel(ctx)
	go func() {
		changed, err := s.autoUpdater.TriggerNow(upgradeCtx, req.Force)
		s.upgradeMu.Lock()
		defer s.upgradeMu.Unlock()
		s.upgradeBusy[backendKey] = false
		switch {
		case err != nil:
			job.status = "failed"
			job.errMsg = err.Error()
			job.completedAt = time.Now().UTC().Format(time.RFC3339)
			log.Printf("[upgrade] job %s failed: %v", id, err)
		case !changed:
			job.status = "noop"
			job.completedAt = time.Now().UTC().Format(time.RFC3339)
		default:
			// changed: restart imminent; leave status "in_progress".
		}
	}()

	return &pb.TriggerUpgradeResponse{
		UpgradeId:      id,
		Status:         "in_progress",
		CurrentVersion: current,
		Message:        "upgrade started; if a new binary is applied the daemon restarts — confirm via the backend version in ListBackends",
		BackendId:      req.BackendId,
	}, nil
}

// GetUpgradeStatus polls an upgrade started by TriggerUpgrade. Admin-only.
// Returns status "unknown" for an unrecognized id — including the common case
// where a successful local self-upgrade restarted the daemon and dropped the
// in-memory job; callers should compare the backend version in ListBackends.
// #354.
func (s *ContainerServer) GetUpgradeStatus(ctx context.Context, req *pb.GetUpgradeStatusRequest) (*pb.GetUpgradeStatusResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if req.UpgradeId == "" {
		return nil, status.Error(codes.InvalidArgument, "upgrade_id is required")
	}
	s.upgradeMu.Lock()
	job := s.upgradeJobs[req.UpgradeId]
	s.upgradeMu.Unlock()
	if job == nil {
		return &pb.GetUpgradeStatusResponse{
			Status:         "unknown",
			CurrentVersion: version.GetVersion(),
		}, nil
	}
	return &pb.GetUpgradeStatusResponse{
		Status:         job.status,
		CurrentVersion: job.currentVersion,
		Error:          job.errMsg,
		CompletedAt:    job.completedAt,
	}, nil
}

// GetSystemInfo gets information about the Incus host
func (s *ContainerServer) GetSystemInfo(ctx context.Context, req *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
	// Admin-only: exposes fleet-internal details (hostname, OS,
	// Incus version, container counts across tenants). A user
	// token has no legitimate reason to read this — they care
	// about their own container, not the daemon's identity.
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	// Get basic system info from container manager
	containers, err := s.manager.List()
	if err != nil {
		return nil, fmt.Errorf("failed to get containers: %w", err)
	}

	// Count running/stopped containers
	var running, stopped int32
	for _, c := range containers {
		if c.State == "Running" {
			running++
		} else {
			stopped++
		}
	}

	// Get Incus server info
	client, err := incus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w", err)
	}

	serverInfo, err := client.GetServerInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get server info: %w", err)
	}

	// Get network CIDR
	networkCIDR, err := client.GetNetworkSubnet("incusbr0")
	if err != nil {
		// Fallback to default if network info not available
		networkCIDR = "10.100.0.0/24"
	}

	// Get system resources (CPU, memory, disk)
	sysResources, err := client.GetSystemResources()
	if err != nil {
		// Log warning but continue - resource info is optional
		sysResources = &incus.SystemResources{}
	}

	// Build response
	info := &pb.SystemInfo{
		IncusVersion:         serverInfo.Environment.ServerVersion,
		Os:                   serverInfo.Environment.OSName,
		KernelVersion:        serverInfo.Environment.KernelVersion,
		ContainersRunning:    running,
		ContainersStopped:    stopped,
		ContainersTotal:      int32(len(containers)), // #nosec G115 -- container count cannot overflow int32
		Hostname:             serverInfo.Environment.ServerName,
		NetworkCidr:          networkCIDR,
		TotalCpus:            sysResources.TotalCPUs,
		TotalMemoryBytes:     sysResources.TotalMemoryBytes,
		AvailableMemoryBytes: sysResources.TotalMemoryBytes - sysResources.UsedMemoryBytes,
		TotalDiskBytes:       sysResources.TotalDiskBytes,
		AvailableDiskBytes:   sysResources.TotalDiskBytes - sysResources.UsedDiskBytes,
		CpuLoad_1Min:         sysResources.CPULoad1Min,
		CpuLoad_5Min:         sysResources.CPULoad5Min,
		CpuLoad_15Min:        sysResources.CPULoad15Min,
		// Advertise where monitoring=true containers ship telemetry so
		// tenants/agents can point docker-in-LXC apps (which don't
		// inherit the env-stamped value) at the collector. Empty when
		// the daemon has no OTel collector. See #370.
		OtelCollectorEndpoint: s.otelCollectorEndpoint,
		// This backend's daemon version, so the fleet's running versions +
		// drift are visible via get_system_info / /v1/backends. See #354.
		DaemonVersion: version.GetVersion(),
	}

	// Populate GPU info
	for _, gpu := range sysResources.GPUs {
		info.Gpus = append(info.Gpus, &pb.GPUInfo{
			Vendor:        mapGPUVendor(gpu.Vendor),
			Model:         mapGPUModel(gpu.Model),
			ModelName:     gpu.Model,
			PciAddress:    gpu.PCIAddress,
			DriverVersion: gpu.DriverVersion,
			CudaVersion:   gpu.CUDAVersion,
			VramBytes:     gpu.VRAMBytes,
		})
	}

	// Fetch system info from all healthy peers
	var peerInfos []*pb.SystemInfo
	if s.peerPool != nil {
		authToken := extractAuthToken(ctx)
		for _, peer := range s.peerPool.Peers() {
			if !peer.Healthy {
				continue
			}
			body, err := peer.ForwardGetSystemInfo(authToken)
			if err != nil {
				log.Printf("[system-info] peer %s: %v", peer.ID, err)
				continue
			}
			// Use protojson to handle enum string values from gRPC-gateway JSON
			var peerResp pb.GetSystemInfoResponse
			if err := protojson.Unmarshal(body, &peerResp); err != nil {
				log.Printf("[system-info] peer %s parse error: %v", peer.ID, err)
				continue
			}
			if peerResp.Info != nil {
				peerResp.Info.BackendId = peer.ID
				peerInfos = append(peerInfos, peerResp.Info)
			}
		}
	}

	return &pb.GetSystemInfoResponse{
		Info:  info,
		Peers: peerInfos,
	}, nil
}

// ListBackends returns the fleet topology — the local daemon plus any
// tunnel-connected peers — with per-backend health, version, OS, running
// container count, and GPU inventory. This is the proto-first replacement
// for the former hand-coded /v1/backends HTTP handler (#354): the wire
// shape is now generated from BackendInfo, so the CLI / MCP clients and
// the cloud control plane all share one contract that cannot drift.
//
// Admin-only: the response discloses fleet topology (peer IDs, hostnames,
// GPU inventory), which is operator-grade, not tenant-grade. The cloud
// control plane redacts it per-tenant at its own boundary.
func (s *ContainerServer) ListBackends(ctx context.Context, _ *pb.ListBackendsRequest) (*pb.ListBackendsResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}

	// Without a peer pool this daemon has no backend identity to report
	// (the local backend ID comes from the pool), so the fleet view is
	// empty — same behavior as the handler this replaced.
	if s.peerPool == nil {
		return &pb.ListBackendsResponse{}, nil
	}

	backends := make([]*pb.BackendInfo, 0, 1+len(s.peerPool.Peers()))

	// Local backend. OS / container count / GPUs come from GetSystemInfo;
	// uptime from the wired process start time.
	local := &pb.BackendInfo{
		Id:      s.peerPool.LocalBackendID(),
		Type:    "local",
		Healthy: true,
		Version: version.GetVersion(),
	}
	if !s.startTime.IsZero() {
		local.UptimeSeconds = int64(time.Since(s.startTime).Seconds())
	}
	// OS / container count / GPUs come from GetSystemInfo, which needs the
	// container manager + Incus. Guard the nil manager so a daemon (or test)
	// without one still reports the local backend's identity + health
	// instead of panicking.
	if s.manager != nil {
		if sysResp, err := s.GetSystemInfo(ctx, &pb.GetSystemInfoRequest{}); err == nil && sysResp.Info != nil {
			local.Hostname = sysResp.Info.Hostname
			local.Os = sysResp.Info.Os
			local.ContainerCount = sysResp.Info.ContainersRunning
			local.Gpus = backendGPUsFromSystemInfo(sysResp.Info)
		}
	}
	// Surface the local backend's spare-capacity advertisement (#680). Only
	// attach when something is actively advertised — an unadvertised backend
	// leaves headroom null so the control plane can tell "not offering" from
	// "offering zero".
	if h := s.capStore().Current(s.hostStateSnapshot()); h.Advertised {
		local.Headroom = headroomToProto(h)
	}
	// Surface the local backend's last-recorded capability profile (#681).
	// Null until ProfileBackend has run, so the control plane can tell
	// "unprofiled" from "profiled CPU-only".
	if p, ok := s.capabStore().Current(); ok {
		local.CapabilityProfile = profileToProto(p)
	}
	backends = append(backends, local)

	// Peer backends. Forward GetSystemInfo to each healthy peer using the
	// caller's (admin) token — the same mechanism GetSystemInfo's peer
	// fan-out uses.
	authToken := extractAuthToken(ctx)
	for _, peer := range s.peerPool.Peers() {
		pi := &pb.BackendInfo{
			Id:      peer.ID,
			Type:    "tunnel",
			Healthy: peer.Healthy,
		}
		if !peer.LastSeenAt.IsZero() {
			pi.LastSeenAt = peer.LastSeenAt.UTC().Format(time.RFC3339)
		}
		if peer.Healthy {
			if body, err := peer.ForwardGetSystemInfo(authToken); err == nil {
				var peerResp pb.GetSystemInfoResponse
				if protojson.Unmarshal(body, &peerResp) == nil && peerResp.Info != nil {
					pi.Hostname = peerResp.Info.Hostname
					pi.Os = peerResp.Info.Os
					pi.Version = peerResp.Info.DaemonVersion
					pi.ContainerCount = peerResp.Info.ContainersRunning
					pi.Gpus = backendGPUsFromSystemInfo(peerResp.Info)
				}
			}
		}
		backends = append(backends, pi)
	}

	return &pb.ListBackendsResponse{Backends: backends}, nil
}

// capStore returns the lazily-initialized per-daemon capacity store. Safe to
// call from any RPC; the first caller wins.
func (s *ContainerServer) capStore() *capacity.Store {
	s.capacityStoreOnce.Do(func() {
		if s.capacityStore == nil {
			s.capacityStore = capacity.NewStore()
		}
	})
	return s.capacityStore
}

// maxDrainWindow caps a caller-supplied drain window so an absurd value can't
// pin the host (and the drainer's in-flight guard) for an unreasonable time.
// drainCtxGrace is extra headroom past the window for the final force-stop.
const (
	maxDrainWindow = 10 * time.Minute
	drainCtxGrace  = 30 * time.Second
)

// drainHandle returns the lazily-initialized per-daemon drainer. A single
// drainer instance is reused across withdraw calls so its in-flight guard
// coalesces overlapping drains — repeated advertise/withdraw cycles can't stack
// concurrent stop storms and wedge the host (#682). The drainer routes each
// stop back through StopWorkload, which reuses StopContainer's plumbing.
func (s *ContainerServer) drainHandle() *capacity.Drainer {
	s.drainerOnce.Do(func() {
		if s.drainer == nil {
			s.drainer = capacity.NewDrainer(s)
		}
	})
	return s.drainer
}

// StopWorkload stops the workload owned by username, satisfying
// capacity.DrainStopper. It routes through StopContainer so a drained workload
// emits the same stop event a manual stop does and the control plane can
// reschedule it — there is no drain-only side door. The daemon context is
// promoted to the system identity (the drain is daemon-internal, triggered by a
// headroom withdraw, not by an end-user request).
func (s *ContainerServer) StopWorkload(ctx context.Context, username string, force bool) error {
	ctx = auth.ContextWithSystemIdentity(ctx)
	_, err := s.StopContainer(ctx, &pb.StopContainerRequest{Username: username, Force: force})
	return err
}

// hostStateSnapshot gathers the current host-level resource + container
// snapshot the headroom computation consumes. It reuses the same Incus
// system-resources call GetSystemInfo uses and the manager's container list,
// so the figures match what ListBackends already reports. Best-effort: a
// missing manager or Incus call yields a zero-resource snapshot rather than an
// error, so advertise/withdraw still work on an unwired server.
func (s *ContainerServer) hostStateSnapshot() capacity.HostState {
	st := capacity.HostState{Now: time.Now()}
	if s.manager == nil {
		return st
	}
	if containers, err := s.manager.List(); err == nil {
		st.Containers = containers
	}
	client, err := incus.New()
	if err != nil {
		return st
	}
	res, err := client.GetSystemResources()
	if err != nil || res == nil {
		return st
	}
	st.AvailableMemoryBytes = res.TotalMemoryBytes - res.UsedMemoryBytes
	st.AvailableDiskBytes = res.TotalDiskBytes - res.UsedDiskBytes
	// Available CPU cores ≈ total cores minus the 1-minute load average,
	// clamped to [0, TotalCPUs]. This is a COARSE, burstable hint only: load
	// average counts runnable+uninterruptible tasks (I/O wait can inflate it
	// without the CPU being busy), so it neither equals idle cores nor is the
	// binding constraint — RAM and disk are the hard limits on how many guests
	// a host can take. The upper clamp guards against a bogus/negative load
	// reading reporting more spare cores than exist.
	avail := float64(res.TotalCPUs) - res.CPULoad1Min
	if avail < 0 {
		avail = 0
	}
	if avail > float64(res.TotalCPUs) {
		avail = float64(res.TotalCPUs)
	}
	st.AvailableCPUs = int32(avail)
	return st
}

// policyFromProto maps the wire CapacityPolicy onto the internal policy. A nil
// proto policy yields the zero (always-open, no-exclusion) policy.
func policyFromProto(p *pb.CapacityPolicy) capacity.Policy {
	if p == nil {
		return capacity.Policy{}
	}
	return capacity.Policy{
		WindowStartHour:         p.GetWindowStartHour(),
		WindowEndHour:           p.GetWindowEndHour(),
		ExcludedWorkloadClasses: p.GetExcludedWorkloadClasses(),
		ReserveFraction:         p.GetReserveFraction(),
	}
}

// headroomToProto maps the internal headroom onto the wire type.
func headroomToProto(h capacity.Headroom) *pb.CapacityHeadroom {
	out := &pb.CapacityHeadroom{
		Advertised:       h.Advertised,
		SpareCpus:        h.SpareCPUs,
		SpareMemoryBytes: h.SpareMemoryBytes,
		SpareDiskBytes:   h.SpareDiskBytes,
		IdleFraction:     h.IdleFraction,
		Policy: &pb.CapacityPolicy{
			WindowStartHour:         h.Policy.WindowStartHour,
			WindowEndHour:           h.Policy.WindowEndHour,
			ExcludedWorkloadClasses: h.Policy.ExcludedWorkloadClasses,
			ReserveFraction:         h.Policy.ReserveFraction,
		},
	}
	if !h.AdvertisedAt.IsZero() {
		out.AdvertisedAt = h.AdvertisedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// AdvertiseCapacity publishes this backend's spare scheduling headroom to the
// control plane, bounded by the supplied local policy. The advertisement is
// surfaced through ListBackends. Admin-only. See #680.
func (s *ContainerServer) AdvertiseCapacity(ctx context.Context, req *pb.AdvertiseCapacityRequest) (*pb.AdvertiseCapacityResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	// Validate the policy server-side — the CLI checks these, but a direct
	// gRPC/REST caller must not be trusted. A negative reserve_fraction would
	// otherwise clamp to a ZERO reservation (advertising 100% of the host as
	// spare — the opposite of intent); an out-of-range window hour would make
	// the window silently never open.
	if pol := req.GetPolicy(); pol != nil {
		if rf := pol.GetReserveFraction(); rf < 0 || rf >= 1 {
			return nil, status.Errorf(codes.InvalidArgument, "reserve_fraction must be in [0,1), got %v", rf)
		}
		if hs, he := pol.GetWindowStartHour(), pol.GetWindowEndHour(); hs < 0 || hs > 23 || he < 0 || he > 23 {
			return nil, status.Errorf(codes.InvalidArgument, "window hours must be in [0,23], got start=%d end=%d", hs, he)
		}
	}
	p := policyFromProto(req.GetPolicy())
	h := s.capStore().Advertise(p, s.hostStateSnapshot())
	return &pb.AdvertiseCapacityResponse{Headroom: headroomToProto(h)}, nil
}

// WithdrawCapacity withdraws any active headroom advertisement. Idempotent:
// withdrawing when nothing is advertised succeeds as a no-op. Admin-only.
//
// When req.Drain is set the backend also reclaims the guest workloads it had
// implicitly offered: it snapshots the host, selects the same candidate set the
// headroom computation considered free, and drains them gracefully within a
// bounded window (req.DrainWindowSeconds, default 120s) instead of hard-killing
// them. Each drained workload is stopped through the normal StopContainer path
// so the control plane observes a stop event and can reschedule it. Any
// candidate still running when the window expires is force-stopped so the host
// is reliably reclaimed — no wedge on repeated advertise/withdraw cycles, since
// the drainer coalesces an overlapping drain rather than stacking a second one.
// See #680, #682.
func (s *ContainerServer) WithdrawCapacity(ctx context.Context, req *pb.WithdrawCapacityRequest) (*pb.WithdrawCapacityResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}

	// Flip the advertisement off first so no new work is directed here while we
	// drain. Withdraw is idempotent, so the order is safe even if the drain
	// fails partway.
	h := s.capStore().Withdraw()
	resp := &pb.WithdrawCapacityResponse{Headroom: headroomToProto(h)}

	if !req.GetDrain() {
		return resp, nil
	}

	st := s.hostStateSnapshot()
	candidates := capacity.DrainCandidates(s.capStore().Policy(), st)
	if len(candidates) == 0 {
		return resp, nil
	}

	window := time.Duration(req.GetDrainWindowSeconds()) * time.Second
	if window > maxDrainWindow {
		window = maxDrainWindow // clamp an absurd request so the drain can't pin the host for ages
	}
	// Detach the drain from the request context and bound it by the window: a
	// graceful drain can take the full window (default 120s), far longer than a
	// typical CLI / grpc-gateway HTTP timeout — we must NOT abandon a
	// half-finished reclaim just because the caller disconnected. (Same posture
	// as the upgrade path's context.WithoutCancel.) The +grace covers the final
	// force-stop after the window elapses.
	effectiveWindow := window
	if effectiveWindow <= 0 {
		effectiveWindow = capacity.DefaultDrainWindow
	}
	drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), effectiveWindow+drainCtxGrace)
	defer cancel()
	result, skipped := s.drainHandle().Drain(drainCtx, candidates, window)
	if skipped {
		// A drain was already in flight (e.g. a rapid second withdraw). The
		// advertisement is already off; the running drain reclaims the host.
		log.Printf("[drain] withdraw coalesced: a drain is already in flight")
		return resp, nil
	}

	resp.Drained = result.Drained
	resp.ForceStopped = result.ForceStopped
	resp.DrainWindowExceeded = result.WindowExceeded
	// Surface guests that couldn't be stopped even after force — a non-empty
	// map means the host is NOT fully reclaimed, so the control plane must not
	// treat their resources as freed.
	if len(result.Failed) > 0 {
		resp.Failed = result.Failed
	}
	log.Printf("[drain] withdraw drained=%d force_stopped=%d failed=%d window_exceeded=%t elapsed=%s",
		len(result.Drained), len(result.ForceStopped), len(result.Failed), result.WindowExceeded, result.Elapsed)
	return resp, nil
}

// GetCapacityHeadroom returns this backend's current advertisement with spare
// figures recomputed against the live host snapshot. Admin-only. See #680.
func (s *ContainerServer) GetCapacityHeadroom(ctx context.Context, _ *pb.GetCapacityHeadroomRequest) (*pb.GetCapacityHeadroomResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	h := s.capStore().Current(s.hostStateSnapshot())
	return &pb.GetCapacityHeadroomResponse{Headroom: headroomToProto(h)}, nil
}

// capabStore returns the lazily-initialized per-daemon capability-profile
// store. Safe to call from any RPC; the first caller wins.
func (s *ContainerServer) capabStore() *capabilities.Store {
	s.capabilityStoreOnce.Do(func() {
		if s.capabilityStore == nil {
			s.capabilityStore = capabilities.NewStore()
		}
	})
	return s.capabilityStore
}

// gatherHostFacts collects the inputs the capability profile is computed from:
// host system resources (CPU cores + model, RAM, disk) via the same Incus call
// GetSystemInfo uses, the GPU passthrough probe (unless skipped), the bounded
// CPU/memory micro-benchmark, and the operator-set region / reported class.
// Best-effort on the resource read: a missing Incus client yields zero hardware
// figures rather than an error, so a profile is always recordable.
func (s *ContainerServer) gatherHostFacts(skipGPU bool) capabilities.HostFacts {
	f := capabilities.HostFacts{
		Now:           time.Now(),
		Region:        s.region,
		ReportedClass: s.reportedClass,
	}

	if client, err := incus.New(); err == nil {
		if res, err := client.GetSystemResources(); err == nil && res != nil {
			f.CPUCores = res.TotalCPUs
			f.CPUModel = res.CPUModel
			f.TotalMemoryBytes = res.TotalMemoryBytes
			f.TotalDiskBytes = res.TotalDiskBytes
		}
	}

	// GPU model/driver from the existing nvidia.runtime passthrough probe —
	// the same ValidateGPU the validate-gpu command runs. Skipped on request
	// (CPU-only backends) or when no container manager is wired.
	if !skipGPU && s.manager != nil {
		res := s.manager.ValidateGPU("")
		if res.Status == container.GPUStatusOK {
			f.GPUAvailable = true
			f.GPUModel = res.Model
			f.GPUDriverVersion = res.DriverVersion
		}
	}

	// Bounded CPU/memory micro-benchmark.
	b := container.RunBenchmark()
	f.Benchmark = capabilities.Benchmark{
		CPUOpsPerSec:   b.CPUOpsPerSec,
		MemBytesPerSec: b.MemBytesPerSec,
		DurationMs:     b.DurationMs,
	}
	return f
}

// profileToProto maps the internal capability profile onto the wire type.
func profileToProto(p capabilities.Profile) *pb.CapabilityProfile {
	out := &pb.CapabilityProfile{
		CpuCores:         p.CPUCores,
		CpuModel:         p.CPUModel,
		TotalMemoryBytes: p.TotalMemoryBytes,
		TotalDiskBytes:   p.TotalDiskBytes,
		GpuModel:         p.GPUModel,
		GpuDriverVersion: p.GPUDriverVersion,
		GpuAvailable:     p.GPUAvailable,
		Region:           p.Region,
		ReportedClass:    p.ReportedClass,
		MeasuredClass:    p.MeasuredClass,
		ClassConsistent:  p.ClassConsistent,
		Benchmark: &pb.CapabilityBenchmark{
			CpuOpsPerSec:   p.Benchmark.CPUOpsPerSec,
			MemBytesPerSec: p.Benchmark.MemBytesPerSec,
			DurationMs:     p.Benchmark.DurationMs,
		},
	}
	if !p.ProfiledAt.IsZero() {
		out.ProfiledAt = p.ProfiledAt.UTC().Format(time.RFC3339)
	}
	return out
}

// ProfileBackend records a backend's hardware capability profile: read system
// info, run the GPU passthrough probe + bounded micro-benchmark, derive the
// measured class, reconcile it against the self-reported class, and persist it.
// Admin-only. An empty (or local) backend_id profiles this daemon; a peer
// backend_id forwards to that peer, which profiles itself. See #681.
func (s *ContainerServer) ProfileBackend(ctx context.Context, req *pb.ProfileBackendRequest) (*pb.ProfileBackendResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}

	// Remote backend → forward to the owning peer (it profiles its own host).
	if req.BackendId != "" && req.BackendId != s.localBackendID() {
		if s.peerPool == nil {
			return nil, status.Errorf(codes.Unavailable, "backend %q: no peer pool configured on this daemon", req.BackendId)
		}
		peer := s.peerPool.Get(req.BackendId)
		if peer == nil {
			return nil, status.Errorf(codes.NotFound, "backend %q not found (see 'containarium backends list')", req.BackendId)
		}
		body, err := protojson.Marshal(req)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "marshal profile request: %v", err)
		}
		respBody, st, err := peer.ForwardRequest("POST", "/v1/capabilities/profile", extractAuthToken(ctx), body)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward profile to %s: %v", req.BackendId, err)
		}
		if st >= 400 {
			return nil, status.Errorf(codes.Internal, "peer %s returned status %d for profile", req.BackendId, st)
		}
		var resp pb.ProfileBackendResponse
		if err := protojson.Unmarshal(respBody, &resp); err != nil {
			return nil, status.Errorf(codes.Internal, "parse peer %s profile response: %v", req.BackendId, err)
		}
		resp.BackendId = req.BackendId
		return &resp, nil
	}

	// Local backend. Serialize against concurrent profiles: gatherHostFacts
	// spins a throwaway GPU-probe LXC + runs a benchmark, so a second caller
	// (retry, multi-replica control plane) must not stack a second probe.
	if !s.profileMu.TryLock() {
		return nil, status.Error(codes.Aborted, "a backend profile is already in progress; retry shortly")
	}
	defer s.profileMu.Unlock()
	p := s.capabStore().Record(s.gatherHostFacts(req.SkipGpu))
	return &pb.ProfileBackendResponse{
		Profile:   profileToProto(p),
		BackendId: req.BackendId,
	}, nil
}

// GetCapabilityProfile returns a backend's last-recorded capability profile
// without re-running the benchmark/probe. Admin-only. A peer backend_id
// forwards to that peer. Returns a null profile when nothing has been recorded
// yet. See #681.
func (s *ContainerServer) GetCapabilityProfile(ctx context.Context, req *pb.GetCapabilityProfileRequest) (*pb.GetCapabilityProfileResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}

	if req.BackendId != "" && req.BackendId != s.localBackendID() {
		if s.peerPool == nil {
			return nil, status.Errorf(codes.Unavailable, "backend %q: no peer pool configured on this daemon", req.BackendId)
		}
		peer := s.peerPool.Get(req.BackendId)
		if peer == nil {
			return nil, status.Errorf(codes.NotFound, "backend %q not found (see 'containarium backends list')", req.BackendId)
		}
		respBody, st, err := peer.ForwardRequest("GET", "/v1/capabilities/profile", extractAuthToken(ctx), nil)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward get-profile to %s: %v", req.BackendId, err)
		}
		if st >= 400 {
			return nil, status.Errorf(codes.Internal, "peer %s returned status %d for get-profile", req.BackendId, st)
		}
		var resp pb.GetCapabilityProfileResponse
		if err := protojson.Unmarshal(respBody, &resp); err != nil {
			return nil, status.Errorf(codes.Internal, "parse peer %s get-profile response: %v", req.BackendId, err)
		}
		resp.BackendId = req.BackendId
		return &resp, nil
	}

	resp := &pb.GetCapabilityProfileResponse{BackendId: req.BackendId}
	if p, ok := s.capabStore().Current(); ok {
		resp.Profile = profileToProto(p)
	}
	return resp, nil
}

// GetSelfMeasurement computes and signs a fresh integrity self-measurement for
// a backend: digests of the running daemon binary, the loaded in-kernel
// network-policy program object(s), and the canonical policy/config state,
// signed with the node's identity key (the sentinel-issued peer leaf reused
// from the peer-PKI plumbing). The daemon also emits the same measurement on
// its heartbeat. A peer backend_id forwards to that peer (which measures
// itself). Admin-only. The control plane verifies the measurement to detect
// tampering; the verification half lives elsewhere. See #683.
func (s *ContainerServer) GetSelfMeasurement(ctx context.Context, req *pb.GetSelfMeasurementRequest) (*pb.GetSelfMeasurementResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}

	// Remote backend → forward to the owning peer (it measures its own host).
	if req.BackendId != "" && req.BackendId != s.localBackendID() {
		if s.peerPool == nil {
			return nil, status.Errorf(codes.Unavailable, "backend %q: no peer pool configured on this daemon", req.BackendId)
		}
		peer := s.peerPool.Get(req.BackendId)
		if peer == nil {
			return nil, status.Errorf(codes.NotFound, "backend %q not found (see 'containarium backends list')", req.BackendId)
		}
		respBody, st, err := peer.ForwardRequest("GET", "/v1/integrity/self-measurement", extractAuthToken(ctx), nil)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward self-measurement to %s: %v", req.BackendId, err)
		}
		if st >= 400 {
			return nil, status.Errorf(codes.Internal, "peer %s returned status %d for self-measurement", req.BackendId, st)
		}
		var resp pb.GetSelfMeasurementResponse
		if err := protojson.Unmarshal(respBody, &resp); err != nil {
			return nil, status.Errorf(codes.Internal, "parse peer %s self-measurement response: %v", req.BackendId, err)
		}
		resp.BackendId = req.BackendId
		return &resp, nil
	}

	// Local backend.
	m, err := s.computeSelfMeasurement()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "compute self-measurement: %v", err)
	}
	return &pb.GetSelfMeasurementResponse{
		Measurement: measurementToProto(m),
		BackendId:   req.BackendId,
	}, nil
}

// computeSelfMeasurement gathers this backend's integrity inputs (running
// binary path, loaded in-kernel network-policy program object(s), policy/config
// state, node identity signer) and computes the signed measurement. The signer
// is the sentinel-issued peer leaf from the peer pool; when no PKI has been
// bootstrapped the measurement is produced unsigned.
func (s *ContainerServer) computeSelfMeasurement() (integrity.Measurement, error) {
	in := integrity.Inputs{
		ConfigState:   s.integrityConfigState,
		DaemonVersion: version.Version,
		Now:           time.Now(),
	}

	// Running daemon binary on disk. Best-effort: a path we can't resolve
	// leaves the binary digest empty rather than failing the measurement.
	if exe, err := os.Executable(); err == nil {
		in.BinaryPath = exe
	}

	// Loaded in-kernel network-policy program object(s). The daemon arms the
	// per-veth enforcer only when CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT points
	// at an object on disk; that object's bytes are exactly what we attest.
	if bpfObj := strings.TrimSpace(os.Getenv("CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT")); bpfObj != "" {
		in.Programs = append(in.Programs, integrity.ProgramObject{Name: bpfObj, Path: bpfObj})
	}

	// Node identity signer: the sentinel-issued peer leaf key.
	if s.peerPool != nil {
		signer, certPEM := s.peerPool.IdentitySigner()
		in.Signer = signer
		in.SigningCertPEM = certPEM
		// TPM-backed signing is a future hook; the software peer key signs today.
		in.TPMBacked = false
	}

	return integrity.Compute(in)
}

// SetIntegrityConfig wires the integrity-relevant policy/config posture this
// backend folds into its signed self-measurement (#683): base domain and the
// network-policy enforcement posture. Called once from DualServer setup with
// the resolved config; either field may be empty. The map is canonicalized
// (sorted keys) before hashing, so caller ordering is irrelevant.
func (s *ContainerServer) SetIntegrityConfig(state map[string]string) {
	s.integrityConfigState = state
}

// measurementToProto maps the internal integrity measurement onto the wire type.
func measurementToProto(m integrity.Measurement) *pb.SelfMeasurement {
	out := &pb.SelfMeasurement{
		HashAlgorithm:      m.HashAlgorithm,
		BinaryDigest:       m.BinaryDigest,
		ConfigDigest:       m.ConfigDigest,
		MeasurementDigest:  m.MeasurementDigest,
		Signature:          m.Signature,
		SignatureAlgorithm: m.SignatureAlgorithm,
		TpmBacked:          m.TPMBacked,
		Signed:             m.Signed,
		SigningCertPem:     m.SigningCertPEM,
		// RFC3339Nano (not RFC3339): the signed canonical form uses nanosecond
		// precision, so the wire MUST carry the same precision or a verifier
		// reconstructing the canonical bytes computes a different digest and
		// the signature never verifies.
		MeasuredAt:    m.MeasuredAt.UTC().Format(time.RFC3339Nano),
		DaemonVersion: m.DaemonVersion,
	}
	for _, p := range m.ProgramDigests {
		out.ProgramDigests = append(out.ProgramDigests, &pb.ProgramDigest{
			Name:   p.Name,
			Digest: p.Digest,
		})
	}
	return out
}

// backendGPUsFromSystemInfo projects a SystemInfo's GPU list onto the
// BackendInfo GPU wire shape (vendor string, model name, VRAM bytes).
func backendGPUsFromSystemInfo(info *pb.SystemInfo) []*pb.BackendGPU {
	if len(info.Gpus) == 0 {
		return nil
	}
	out := make([]*pb.BackendGPU, 0, len(info.Gpus))
	for _, g := range info.Gpus {
		out = append(out, &pb.BackendGPU{
			Vendor:    g.Vendor.String(),
			ModelName: g.ModelName,
			VramBytes: g.VramBytes,
		})
	}
	return out
}

// mapGPUVendor maps a vendor string to the proto enum.
func mapGPUVendor(vendor string) pb.GPUVendor {
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "nvidia"):
		return pb.GPUVendor_GPU_VENDOR_NVIDIA
	case strings.Contains(v, "amd") || strings.Contains(v, "advanced micro"):
		return pb.GPUVendor_GPU_VENDOR_AMD
	case strings.Contains(v, "intel"):
		return pb.GPUVendor_GPU_VENDOR_INTEL
	default:
		return pb.GPUVendor_GPU_VENDOR_UNSPECIFIED
	}
}

// mapGPUModel maps a model name string to the proto enum.
func mapGPUModel(model string) pb.GPUModel {
	m := strings.ToLower(model)
	switch {
	// NVIDIA Consumer
	case strings.Contains(m, "rtx 5090"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_5090
	case strings.Contains(m, "rtx 5080"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_5080
	case strings.Contains(m, "rtx 4090"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4090
	case strings.Contains(m, "rtx 4080"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4080
	case strings.Contains(m, "rtx 4070 ti"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4070_TI
	case strings.Contains(m, "rtx 4070"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4070
	case strings.Contains(m, "rtx 3090"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_3090
	case strings.Contains(m, "rtx 3080"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_RTX_3080
	// NVIDIA Datacenter
	case strings.Contains(m, "b200"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_B200
	case strings.Contains(m, "h200"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_H200
	case strings.Contains(m, "h100"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_H100
	case strings.Contains(m, "a100"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_A100
	case strings.Contains(m, "a10g"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_A10G
	case strings.Contains(m, "a10"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_A10
	case strings.Contains(m, "l40s"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_L40S
	case strings.Contains(m, "l40"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_L40
	case strings.Contains(m, "l4"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_L4
	case strings.Contains(m, "t4"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_T4
	case strings.Contains(m, "v100"):
		return pb.GPUModel_GPU_MODEL_NVIDIA_V100
	// AMD
	case strings.Contains(m, "mi300x"):
		return pb.GPUModel_GPU_MODEL_AMD_MI300X
	case strings.Contains(m, "mi250x"):
		return pb.GPUModel_GPU_MODEL_AMD_MI250X
	case strings.Contains(m, "7900 xtx"):
		return pb.GPUModel_GPU_MODEL_AMD_RX_7900_XTX
	// Intel
	case strings.Contains(m, "max 1550"):
		return pb.GPUModel_GPU_MODEL_INTEL_MAX_1550
	case strings.Contains(m, "a770"):
		return pb.GPUModel_GPU_MODEL_INTEL_ARC_A770
	default:
		return pb.GPUModel_GPU_MODEL_UNSPECIFIED
	}
}

// toProtoMetrics converts internal metrics to protobuf
func toProtoMetrics(m *incus.ContainerMetrics) *pb.ContainerMetrics {
	return &pb.ContainerMetrics{
		Name:             m.Name,
		CpuUsageSeconds:  m.CPUUsageSeconds,
		MemoryUsageBytes: m.MemoryUsageBytes,
		MemoryPeakBytes:  m.MemoryLimitBytes,
		DiskUsageBytes:   m.DiskUsageBytes,
		NetworkRxBytes:   m.NetworkRxBytes,
		NetworkTxBytes:   m.NetworkTxBytes,
		ProcessCount:     m.ProcessCount,
	}
}

// toProtoContainer converts internal container info to protobuf
func toProtoContainer(st *box.BoxStatus) *pb.Container {
	// Resolve OS type from labels
	var osTypeEnum pb.OSType
	if osLabel, ok := st.Labels[ostype.OSTypeLabelKey]; ok {
		osTypeEnum = ostype.OSTypeFromLabel(osLabel)
	}

	// Determine access type based on OS
	accessType := pb.AccessType_ACCESS_TYPE_SSH
	var rdpAddress string
	if ostype.IsWindows(osTypeEnum) {
		accessType = pb.AccessType_ACCESS_TYPE_RDP
		if st.IPAddress != "" {
			rdpAddress = fmt.Sprintf("%s:3389", st.IPAddress)
		}
	}

	pc := &pb.Container{
		Name:     st.Ref.Name,
		Username: st.Ref.Tenant,
		State:    st.State,
		Resources: &pb.ResourceLimits{
			Cpu:    st.Resources.CPU,
			Memory: st.Resources.Memory,
			Disk:   st.Resources.Disk,
		},
		Network: &pb.NetworkInfo{
			IpAddress: st.IPAddress,
		},
		Labels:               st.Labels,
		CreatedAt:            st.CreatedAt.Unix(),
		PodmanEnabled:        true, // TODO: Get from container config
		Stack:                "",   // TODO: Get from container labels
		GpuDevice:            st.GPU,
		GpuDevices:           st.GPUs,
		BackendId:            st.BackendID,
		OsType:               osTypeEnum,
		AccessType:           accessType,
		RdpAddress:           rdpAddress,
		MonitoringEnabled:    st.MonitoringEnabled,
		AutoSleepEnabled:     st.AutoSleepEnabled,
		IdleThresholdMinutes: st.IdleThresholdMinutes,
	}
	// TTL — populated by SetContainerTTL on the writer side. Zero value means
	// no TTL set (parser silently drops missing/unparseable keys; a corrupted
	// key shouldn't 5xx the list endpoint).
	if !st.TTLExpiresAt.IsZero() {
		pc.TtlExpiresAt = timestamppb.New(st.TTLExpiresAt)
	}
	// Two-phase reaping status (#525): stopped_at (cleared on start, so unset
	// while running) + the stopped→delete window, so a reader sees the full
	// lifecycle (#264).
	if !st.StoppedAt.IsZero() {
		pc.StoppedAt = timestamppb.New(st.StoppedAt)
	}
	pc.DeleteAfterStoppedSeconds = st.DeleteAfterStoppedSeconds
	// Delete policy (#284): protected boxes are skipped by the ttlsweeper
	// auto-reap and `containarium prune`. Absent / any non-"protected" value
	// maps to UNSPECIFIED (the default, unprotected).
	if st.DeletePolicy == incus.DeletePolicyProtected {
		pc.DeletePolicy = pb.DeletePolicy_DELETE_POLICY_PROTECTED
	}
	return pc
}

// GetManager returns the container manager for reuse by other components
func (s *ContainerServer) GetManager() *container.Manager {
	return s.manager
}

// extractAuthToken extracts the JWT token from gRPC metadata.
func extractAuthToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if vals := md.Get("authorization"); len(vals) > 0 {
		token := vals[0]
		if len(token) > 7 && token[:7] == "Bearer " {
			return token[7:]
		}
		return token
	}
	return ""
}

// SetPeerPool sets the peer pool for multi-backend support
func (s *ContainerServer) SetPeerPool(pool *PeerPool) {
	s.peerPool = pool
}

// SetStartTime wires the daemon's process start time so ListBackends can
// report the local backend's uptime. Called once from DualServer setup.
func (s *ContainerServer) SetStartTime(t time.Time) {
	s.startTime = t
}

// SetCapabilityIdentity wires the region this backend serves and its
// self-reported hardware class into the capability profile (#681). Both are
// operator-set: region from --region (falling back to the pool name) and the
// reported class from the pool name. Called once from DualServer setup; either
// may be empty.
func (s *ContainerServer) SetCapabilityIdentity(region, reportedClass string) {
	s.region = region
	s.reportedClass = reportedClass
}

// SetSSHHost wires the public SSH host clients dial to reach this daemon's
// containers (the sentinel's SSH endpoint, from --ssh-host). Stamped onto
// Container.ssh_host in the read path. Empty leaves ssh_host empty so clients
// fall back to the container IP. Called once from DualServer setup.
func (s *ContainerServer) SetSSHHost(host string) {
	s.sshHost = host
}

// sshCommandFor builds the ssh_command returned by CreateContainer from the
// reachable target — the daemon-stamped ssh_host (the sentinel this container
// belongs to) when set, falling back to the container IP only for direct /
// no-sentinel deployments. Using the private IP unconditionally produced an
// ssh_command that callers off the backend LAN (notably MCP agents) couldn't
// reach — they'd see `ssh user@10.x.x.x` and give up. See #658.
func sshCommandFor(username, sshHost, ip string) string {
	target := ip
	if sshHost != "" {
		target = sshHost
	}
	return fmt.Sprintf("ssh %s@%s", username, target)
}

// SetAutoUpdater wires the daemon's auto-updater so TriggerUpgrade can run an
// upgrade on demand (vs only on the periodic tick). DualServer calls this when
// a sentinel binary source is configured; nil leaves local TriggerUpgrade
// returning Unavailable. #354.
func (s *ContainerServer) SetAutoUpdater(u *AutoUpdater) {
	s.autoUpdater = u
}

// SetOTelCollectorEndpoint wires the OTLP/HTTP URL of this daemon's
// core OTel collector LXC. Stamped into containers created with
// monitoring=true. DualServer calls this after the collector
// container is provisioned (or after looking up its IP if it
// already exists). Empty string disables app-monitoring injection
// for new containers — they'll log a warning and skip stamping.
func (s *ContainerServer) SetOTelCollectorEndpoint(endpoint string) {
	s.otelCollectorEndpoint = endpoint
}

// SetCoreServices wires the CoreServices manager used by
// refreshContainerIPMap to push source-IP attribution updates into
// the collector LXC. Called from dual_server.go alongside
// SetOTelCollectorEndpoint after the collector is ensured. Separate
// setter from SetAlertManager because the alerting path is optional
// and we want OTel attribution to work even on daemons started
// without --alert-webhook-url.
func (s *ContainerServer) SetCoreServices(cs *CoreServices) {
	s.coreServices = cs
}

// refreshContainerIPMap rebuilds the source-IP → container-name map
// and pushes it into the collector LXC. Best-effort: errors are
// logged but never bubbled up — a stale IP map degrades source-IP
// attribution but does not justify failing a container create/delete.
//
// Skips entirely when coreServices is nil (standalone mode) or the
// collector isn't provisioned yet. Core containers are excluded —
// their telemetry never carries app-emitted resource attributes.
func (s *ContainerServer) refreshContainerIPMap() {
	if s.coreServices == nil || s.coreServices.GetOTelCollectorIP() == "" {
		return
	}
	infos, err := s.manager.List()
	if err != nil {
		log.Printf("Warning: failed to list containers for IP map refresh: %v", err)
		return
	}
	if err := s.coreServices.WriteContainerIPMap(buildContainerIPMap(infos)); err != nil {
		log.Printf("Warning: failed to push container IP map to collector: %v", err)
	}
}

// cloudContainerIDLabel is the container label the cloud control plane stamps
// with its container UUID (ossprimary.LabelCloudContainerID on the cloud side).
// The OSS daemon is generic about labels; we read this one by its literal key
// to carry the cloud's join identity into container_ips.json.
const cloudContainerIDLabel = "cloud_container_id"

// buildContainerIPMap projects the live container list into the source-IP →
// identity map the OTel collector attributes telemetry by. Pure (no IO) so the
// projection is unit-tested directly. Core containers and IP-less boxes (not
// placed yet) are skipped — neither emits app telemetry to attribute.
func buildContainerIPMap(infos []incus.ContainerInfo) map[string]ContainerIPEntry {
	ipMap := make(map[string]ContainerIPEntry, len(infos))
	for _, c := range infos {
		if c.Role.IsCoreRole() || c.IPAddress == "" {
			continue
		}
		ipMap[c.IPAddress] = ContainerIPEntry{
			Name:             c.Name,
			CloudContainerID: c.Labels[cloudContainerIDLabel],
		}
	}
	return ipMap
}

// localBackendID returns this daemon's backend ID for stamping into
// OTEL_RESOURCE_ATTRIBUTES. Falls back to "local" if the peer pool
// isn't configured (single-host deployments) — that way single-host
// metrics still have a well-known label rather than an empty string,
// keeping Grafana queries simpler.
func (s *ContainerServer) localBackendID() string {
	if s.peerPool == nil {
		return "local"
	}
	if id := s.peerPool.LocalBackendID(); id != "" {
		return id
	}
	return "local"
}

// resolvePool returns the pool tag for the given backend_id. The local
// backend's pool comes from the PeerPool's --pool configuration;
// remote backends carry the tag they registered with the sentinel.
// Returns "" when the peer pool isn't configured or the backend is
// unknown.
func (s *ContainerServer) resolvePool(backendID string) string {
	if s.peerPool == nil {
		return ""
	}
	if backendID == "" || backendID == s.peerPool.LocalBackendID() {
		return s.peerPool.LocalPool()
	}
	if peer := s.peerPool.Get(backendID); peer != nil {
		return peer.Pool
	}
	return ""
}

// resolvePoolPlacement validates or assigns req.BackendId based on
// req.Pool. Called only when req.Pool is non-empty. When backend_id
// is already set, it must belong to the requested pool. When empty,
// any healthy backend in the pool (including the local one) is a
// valid placement; the first healthy candidate wins. Returns an
// error if no eligible backend can be found.
func (s *ContainerServer) resolvePoolPlacement(req *pb.CreateContainerRequest) error {
	if s.peerPool == nil {
		return fmt.Errorf("pool=%q requested but peer pool is not configured on this daemon", req.Pool)
	}

	if req.BackendId != "" {
		actual := s.resolvePool(req.BackendId)
		if actual != req.Pool {
			return fmt.Errorf("backend %q is in pool %q, not %q", req.BackendId, actual, req.Pool)
		}
		return nil
	}

	// No explicit backend_id — find a candidate in the requested pool.
	if s.peerPool.LocalPool() == req.Pool {
		req.BackendId = s.peerPool.LocalBackendID()
		return nil
	}
	candidates := s.peerPool.HealthyPeersInPool(req.Pool)
	if len(candidates) == 0 {
		return fmt.Errorf("no healthy backend found in pool %q", req.Pool)
	}
	req.BackendId = candidates[0].ID
	return nil
}

// SetRouteCleanupDeps wires the route store + proxy manager so
// DeleteContainer can cascade-clean a container's routes + TLS
// subjects. Both may be nil if the daemon was started without
// --app-hosting; the cascade will skip those steps gracefully.
func (s *ContainerServer) SetRouteCleanupDeps(routeStore *app.RouteStore, proxyManager *app.ProxyManager) {
	s.routeStore = routeStore
	s.proxyManager = proxyManager
}

// SetCollaboratorManager sets the collaborator manager for handling collaborator operations
func (s *ContainerServer) SetCollaboratorManager(cm *container.CollaboratorManager) {
	s.collaboratorManager = cm
}

// AddCollaborator adds a collaborator to a container
// collaboratorKeysFromRequest resolves the collaborator's SSH keys from
// the request, preferring the repeated ssh_public_keys and falling back
// to the legacy single ssh_public_key for back-compat. Returns nil when
// neither is set. #369.
func collaboratorKeysFromRequest(req *pb.AddCollaboratorRequest) []string {
	if len(req.GetSshPublicKeys()) > 0 {
		return req.GetSshPublicKeys()
	}
	if req.GetSshPublicKey() != "" {
		return []string{req.GetSshPublicKey()}
	}
	return nil
}

func (s *ContainerServer) AddCollaborator(ctx context.Context, req *pb.AddCollaboratorRequest) (*pb.AddCollaboratorResponse, error) {
	if req.OwnerUsername == "" {
		return nil, fmt.Errorf("owner_username is required")
	}
	if req.CollaboratorUsername == "" {
		return nil, fmt.Errorf("collaborator_username is required")
	}
	// Accept either the repeated ssh_public_keys (preferred) or the
	// legacy single ssh_public_key. #369.
	sshKeys := collaboratorKeysFromRequest(req)
	if len(sshKeys) == 0 {
		return nil, fmt.Errorf("at least one of ssh_public_keys or ssh_public_key is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.OwnerUsername); err != nil {
		return nil, err
	}

	if s.collaboratorManager == nil {
		// No local collaborator manager — try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.OwnerUsername, authToken)
			if peer != nil {
				body, _ := json.Marshal(map[string]interface{}{
					"collaborator_username": req.CollaboratorUsername,
					// ssh_public_key kept for older peers; ssh_public_keys
					// carries the full set for #369-aware peers.
					"ssh_public_key":          sshKeys[0],
					"ssh_public_keys":         sshKeys,
					"grant_sudo":              req.GrantSudo,
					"grant_container_runtime": req.GrantContainerRuntime,
				})
				respBody, statusCode, fwdErr := peer.ForwardRequest("POST", fmt.Sprintf("/v1/containers/%s/collaborators", req.OwnerUsername), authToken, body)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to add collaborator on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d: %s", peer.ID, statusCode, string(respBody))
				}
				var peerResp struct {
					Collaborator *pb.Collaborator `json:"collaborator"`
					SshCommand   string           `json:"sshCommand"`
					Message      string           `json:"message"`
				}
				if jsonErr := json.Unmarshal(respBody, &peerResp); jsonErr == nil && peerResp.Collaborator != nil {
					return &pb.AddCollaboratorResponse{
						Message:      peerResp.Message,
						Collaborator: peerResp.Collaborator,
						SshCommand:   peerResp.SshCommand,
					}, nil
				}
				return &pb.AddCollaboratorResponse{
					Message: fmt.Sprintf("Collaborator added on backend %s", peer.ID),
				}, nil
			}
		}
		return nil, fmt.Errorf("collaborator management not enabled")
	}

	collab, err := s.collaboratorManager.AddCollaborator(req.OwnerUsername, req.CollaboratorUsername, sshKeys, req.GrantSudo, req.GrantContainerRuntime)
	if err != nil {
		return nil, fmt.Errorf("failed to add collaborator: %w", err)
	}

	return &pb.AddCollaboratorResponse{
		Message: fmt.Sprintf("Collaborator %s added to %s-container", req.CollaboratorUsername, req.OwnerUsername),
		Collaborator: &pb.Collaborator{
			Id:                   collab.ID,
			ContainerName:        collab.ContainerName,
			OwnerUsername:        collab.OwnerUsername,
			CollaboratorUsername: collab.CollaboratorUsername,
			AccountName:          collab.AccountName,
			SshPublicKey:         collab.SSHPublicKey,
			AddedAt:              collab.CreatedAt.Unix(),
			CreatedBy:            collab.CreatedBy,
			HasSudo:              collab.HasSudo,
			HasContainerRuntime:  collab.HasContainerRuntime,
		},
		SshCommand: s.collaboratorManager.GenerateSSHCommand(req.OwnerUsername, req.CollaboratorUsername, "jumpserver"),
	}, nil
}

// RemoveCollaborator removes a collaborator from a container
func (s *ContainerServer) RemoveCollaborator(ctx context.Context, req *pb.RemoveCollaboratorRequest) (*pb.RemoveCollaboratorResponse, error) {
	if req.OwnerUsername == "" {
		return nil, fmt.Errorf("owner_username is required")
	}
	if req.CollaboratorUsername == "" {
		return nil, fmt.Errorf("collaborator_username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.OwnerUsername); err != nil {
		return nil, err
	}

	if s.collaboratorManager == nil {
		// No local collaborator manager — try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.OwnerUsername, authToken)
			if peer != nil {
				_, statusCode, fwdErr := peer.ForwardRequest("DELETE", fmt.Sprintf("/v1/containers/%s/collaborators/%s", req.OwnerUsername, req.CollaboratorUsername), authToken, nil)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to remove collaborator on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d for remove collaborator", peer.ID, statusCode)
				}
				return &pb.RemoveCollaboratorResponse{
					Message: fmt.Sprintf("Collaborator %s removed on backend %s", req.CollaboratorUsername, peer.ID),
				}, nil
			}
		}
		return nil, fmt.Errorf("collaborator management not enabled")
	}

	if err := s.collaboratorManager.RemoveCollaborator(req.OwnerUsername, req.CollaboratorUsername); err != nil {
		return nil, fmt.Errorf("failed to remove collaborator: %w", err)
	}

	return &pb.RemoveCollaboratorResponse{
		Message: fmt.Sprintf("Collaborator %s removed from %s-container", req.CollaboratorUsername, req.OwnerUsername),
	}, nil
}

// ListCollaborators lists all collaborators for a container
func (s *ContainerServer) ListCollaborators(ctx context.Context, req *pb.ListCollaboratorsRequest) (*pb.ListCollaboratorsResponse, error) {
	if req.OwnerUsername == "" {
		return nil, fmt.Errorf("owner_username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.OwnerUsername); err != nil {
		return nil, err
	}

	if s.collaboratorManager == nil {
		// No local collaborator manager — try peer
		if s.peerPool != nil {
			authToken := extractAuthToken(ctx)
			peer := s.peerPool.FindContainerPeer(req.OwnerUsername, authToken)
			if peer != nil {
				respBody, statusCode, fwdErr := peer.ForwardRequest("GET", fmt.Sprintf("/v1/containers/%s/collaborators", req.OwnerUsername), authToken, nil)
				if fwdErr != nil {
					return nil, fmt.Errorf("failed to list collaborators on peer %s: %w", peer.ID, fwdErr)
				}
				if statusCode >= 400 {
					return nil, fmt.Errorf("peer %s returned status %d for list collaborators", peer.ID, statusCode)
				}
				var peerResp pb.ListCollaboratorsResponse
				if jsonErr := json.Unmarshal(respBody, &peerResp); jsonErr == nil {
					return &peerResp, nil
				}
				return &pb.ListCollaboratorsResponse{}, nil
			}
		}
		return nil, fmt.Errorf("collaborator management not enabled")
	}

	collaborators, err := s.collaboratorManager.ListCollaborators(req.OwnerUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to list collaborators: %w", err)
	}

	var protoCollaborators []*pb.Collaborator
	for _, c := range collaborators {
		protoCollaborators = append(protoCollaborators, &pb.Collaborator{
			Id:                   c.ID,
			ContainerName:        c.ContainerName,
			OwnerUsername:        c.OwnerUsername,
			CollaboratorUsername: c.CollaboratorUsername,
			AccountName:          c.AccountName,
			SshPublicKey:         c.SSHPublicKey,
			AddedAt:              c.CreatedAt.Unix(),
			CreatedBy:            c.CreatedBy,
			HasSudo:              c.HasSudo,
			HasContainerRuntime:  c.HasContainerRuntime,
		})
	}

	return &pb.ListCollaboratorsResponse{
		Collaborators: protoCollaborators,
		TotalCount:    safecast.I32(len(protoCollaborators)),
	}, nil
}

// SetMonitoringURLs sets the VictoriaMetrics and Grafana URLs for the monitoring info endpoint
func (s *ContainerServer) SetMonitoringURLs(victoriaMetricsURL, grafanaURL string) {
	s.victoriaMetricsURL = victoriaMetricsURL
	s.grafanaURL = grafanaURL
}

// GetMonitoringInfo returns monitoring configuration (Grafana/VictoriaMetrics URLs)
func (s *ContainerServer) GetMonitoringInfo(ctx context.Context, req *pb.GetMonitoringInfoRequest) (*pb.GetMonitoringInfoResponse, error) {
	return &pb.GetMonitoringInfoResponse{
		Enabled:            s.victoriaMetricsURL != "",
		GrafanaUrl:         s.grafanaURL,
		VictoriaMetricsUrl: s.victoriaMetricsURL,
	}, nil
}

// guacamoleConnectionIDLabel is the Incus label key for storing the Guacamole connection ID.
const guacamoleConnectionIDLabel = "guacamole-connection-id"

// SetGuacamoleClient sets the Guacamole client for Windows VM RDP registration.
func (s *ContainerServer) SetGuacamoleClient(client *guacamole.Client, adminUser, adminPass string) {
	s.guacamoleClient = client
	s.guacamoleUser = adminUser
	s.guacamolePass = adminPass
}

// registerGuacamoleConnection registers a Windows VM's RDP connection in Guacamole.
// Returns the connection ID, or "" if Guacamole is not configured.
func (s *ContainerServer) registerGuacamoleConnection(containerName, hostname, rdpUser, rdpPassword string) string {
	if s.guacamoleClient == nil {
		return ""
	}

	token, err := s.guacamoleClient.Authenticate(s.guacamoleUser, s.guacamolePass)
	if err != nil {
		log.Printf("Warning: Guacamole auth failed, skipping RDP registration: %v", err)
		return ""
	}

	connID, err := s.guacamoleClient.CreateConnection(token, guacamole.ConnectionConfig{
		Name:     containerName,
		Hostname: hostname,
		Port:     "3389",
		Username: rdpUser,
		Password: rdpPassword,
	})
	if err != nil {
		log.Printf("Warning: Failed to register Guacamole connection for %s: %v", containerName, err)
		return ""
	}

	log.Printf("Guacamole RDP connection registered for %s (id=%s)", containerName, connID)
	return connID
}

// deregisterGuacamoleConnection removes a Windows VM's RDP connection from Guacamole.
func (s *ContainerServer) deregisterGuacamoleConnection(username string) {
	if s.guacamoleClient == nil {
		return
	}

	// Look up the connection ID from container labels
	info, err := s.boxes().Get(context.Background(), box.BoxRef{Tenant: username})
	if err != nil || info == nil {
		return
	}

	connID, ok := info.Labels[guacamoleConnectionIDLabel]
	if !ok || connID == "" {
		return
	}

	token, err := s.guacamoleClient.Authenticate(s.guacamoleUser, s.guacamolePass)
	if err != nil {
		log.Printf("Warning: Guacamole auth failed during deregistration: %v", err)
		return
	}

	if err := s.guacamoleClient.DeleteConnection(token, connID); err != nil {
		log.Printf("Warning: Failed to deregister Guacamole connection %s: %v", connID, err)
		return
	}

	log.Printf("Guacamole RDP connection removed for %s (id=%s)", username, connID)
}
