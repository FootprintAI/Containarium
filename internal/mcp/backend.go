package mcp

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/footprintai/containarium/internal/credentials"
)

// API is the contract the MCP tool handlers consume. It has two
// implementations behind a single factory (newBackend):
//
//   - *Client       — the OSS daemon backend: the full surface.
//   - cloudClient   — the hosted control plane: host-LEVEL operations
//     (system info, release/upgrade, per-box debug) have no tenant-safe
//     meaning, so they return a clear "not available here" instead of a
//     round-trip the cloud could only reject.
//
// Handlers take an API and never branch on the target themselves — the
// divergence lives in the implementation, not in `if isCloud {…}` guards
// scattered across handlers. newBackend classifies the target from the
// credential (a `ctnr_` token ⇒ cloud) and hands back the right one.
//
// The method set is exactly *Client's exported surface; the compile-time
// assertions below pin both implementations to it.
type API interface {
	// Containers + lifecycle.
	CreateContainer(req CreateContainerRequest) (*CreateContainerResponse, error)
	ListContainers() (*ListContainersResponse, error)
	GetContainer(username string) (*GetContainerResponse, error)
	DeleteContainer(username string, force bool) (*DeleteContainerResponse, error)
	StartContainer(username string, waitForReady bool) (*StartContainerResponse, error)
	StopContainer(username string, force bool) (*StopContainerResponse, error)
	ResizeContainer(username, cpu, memory, disk string) (*ResizeContainerResponse, error)
	ToggleMonitoring(username string, enabled bool) (*ToggleMonitoringResponse, error)
	ToggleAutoSleep(username string, enabled bool, idleThresholdMinutes int32) (*ToggleAutoSleepResponse, error)
	GetMetrics(username string) (*GetMetricsResponse, error)

	// Recipes / agents / crews.
	ListRecipes() (*ListRecipesResponse, error)
	DeployRecipe(req DeployRecipeRequest) (*DeployRecipeResponse, error)
	ListAgentSkills() (*ListAgentSkillsResponse, error)
	RunAgentSkill(req RunAgentSkillRequest) (*RunAgentSkillResponse, error)
	CallAgent(req CallAgentRequest) (*CallAgentResponse, error)
	ListCrews() (*ListCrewsResponse, error)
	RunCrew(req RunCrewRequest) (*RunCrewResponse, error)

	// Backups.
	CreateBackup(req CreateBackupRequest) (*CreateBackupResponse, error)
	ListBackups(username string) (*ListBackupsResponse, error)
	RestoreBackup(req RestoreBackupRequest) (*RestoreBackupResponse, error)

	// Secrets / KMS.
	SetSecret(username, name, value string) (*SecretResponse, error)
	GetSecret(username, name string) (string, error)
	ListSecrets(username string) ([]map[string]interface{}, error)
	DeleteSecret(username, name string) error
	RefreshSecrets(username string) (*RefreshSecretsResponse, error)
	GetKMSStatus() (*KMSStatusResponse, error)
	GetEnvelopeCoverage() (*EnvelopeCoverageResponse, error)
	MigrateToEnvelope(req MigrateToEnvelopeBody) (*MigrateToEnvelopeResponse, error)

	// Routes / backends.
	AddRoute(req AddRouteRequest) (*AddRouteResponse, error)
	ListRoutes(username string, activeOnly bool) (*ListRoutesResponse, error)
	DeleteRoute(domain string) error
	ListBackends() (*ListBackendsResponse, error)
	GetBackend(id string) (*Backend, error)
	ValidateGPU(backendID, pci string) (*ValidateGPUResult, error)

	// Security.
	TriggerSecurityScan(kind, containerName, username string) (*SecurityScanResponse, error)
	ListSecurityFindings(kind, containerName string) ([]SecurityFinding, error)
	RemediateSecurityFinding(findingID int64) (*SecurityRemediateResponse, error)

	// Tokens.
	RevokeToken(jti, reason, expiresAt string) (string, error)

	// Host-LEVEL operations — overridden as unsupported on the cloud backend.
	GetSystemInfo() (*GetSystemInfoResponse, error)
	GetLatestRelease() (*LatestReleaseResponse, error)
	DebugContainer(username string) (*DebugContainerResponse, error)
	TriggerUpgrade(backendID string, force bool) (*TriggerUpgradeResponse, error)
	GetUpgradeStatus(upgradeID string) (*UpgradeStatusResponse, error)
	// SetMetricsExport / GetMetricsExport (#1069) toggle and inspect
	// opt-in export of this host's infra metrics to its cloud's native
	// monitoring. Host-level like GetSystemInfo — the credential probe
	// (GCP ADC) is specific to the box the daemon runs on, so it has no
	// tenant-safe meaning on the hosted control plane.
	SetMetricsExport(enabled bool, provider string) (*SetMetricsExportResponse, error)
	GetMetricsExport() (*GetMetricsExportResponse, error)
	// InstallZap downloads and installs OWASP ZAP into this host's
	// security container. Host-level — a daemon manages exactly one
	// security container, so there's no per-tenant scoping.
	InstallZap() (*InstallZapResponse, error)

	// Transport-level escape hatches used by handlers that issue a raw
	// request (compose, move, connect) or need the effective token (scope
	// filtering). Unexported → only this package's types satisfy the
	// contract. The cloud backend inherits these unchanged from *Client
	// (they map identically through the cloud's OSS-compatible shim).
	doRequest(method, path string, body interface{}) ([]byte, error)
	readToken() (string, error)
	composeDispatch(verb, username string, body any) (json.RawMessage, error)
	composeStatus(username, dir string) (json.RawMessage, error)
}

// Both backends must satisfy the contract; a missing or mistyped method is a
// compile error here rather than a runtime panic at dispatch.
var (
	_ API = (*Client)(nil)
	_ API = cloudClient{}
)

// cloudClient is the hosted-control-plane backend. It embeds *Client for the
// shared surface (create / list / expose / … map identically through the
// cloud's OSS-compatible REST shim) and overrides ONLY the host-level
// operations that have no tenant-safe meaning on the cloud.
type cloudClient struct{ *Client }

// errUnsupportedOnCloud is the clear, actionable error the cloud backend
// returns for a host-level op — instead of a round-trip the cloud can only
// 404/501. `alt` names what to use instead (may be empty).
func errUnsupportedOnCloud(op, alt string) error {
	msg := fmt.Sprintf("%s is a host-level operation and is not available on the hosted control plane", op)
	if alt != "" {
		msg += "; " + alt
	}
	return errors.New(msg)
}

func (cloudClient) GetSystemInfo() (*GetSystemInfoResponse, error) {
	return nil, errUnsupportedOnCloud("get_system_info", "use list_backends for the (redacted) fleet view")
}

func (cloudClient) GetLatestRelease() (*LatestReleaseResponse, error) {
	return nil, errUnsupportedOnCloud("check_for_updates", "the platform keeps the control plane current")
}

func (cloudClient) DebugContainer(string) (*DebugContainerResponse, error) {
	return nil, errUnsupportedOnCloud("debug_container", "use connect (exec) to inspect the box")
}

func (cloudClient) TriggerUpgrade(string, bool) (*TriggerUpgradeResponse, error) {
	return nil, errUnsupportedOnCloud("upgrade_backend", "the platform operator owns control-plane upgrades")
}

func (cloudClient) GetUpgradeStatus(string) (*UpgradeStatusResponse, error) {
	return nil, errUnsupportedOnCloud("get_upgrade_status", "")
}

func (cloudClient) InstallZap() (*InstallZapResponse, error) {
	return nil, errUnsupportedOnCloud("install_zap", "the platform provisions ZAP on managed hosts")
}

func (cloudClient) SetMetricsExport(bool, string) (*SetMetricsExportResponse, error) {
	return nil, errUnsupportedOnCloud("set_metrics_export", "the credential probe is specific to a BYOC host; run this against the host's own daemon")
}

func (cloudClient) GetMetricsExport() (*GetMetricsExportResponse, error) {
	return nil, errUnsupportedOnCloud("get_metrics_export", "")
}

// newBackend builds the API the handlers use, classifying the target from the
// credential. Token-file mode (rotation-without-restart) is wired onto the
// shared base either way; the classification reads the effective token once
// (best-effort — a token that can't be read yet just yields the daemon
// backend, and the real per-request error still surfaces on first call).
func newBackend(cfg *Config) API {
	base := NewClient(cfg.ServerURL, cfg.JWTToken)
	if cfg.JWTTokenFile != "" {
		base.SetTokenFile(cfg.JWTTokenFile)
	}
	tok, _ := base.readToken()
	if credentials.IsCloudToken(tok) {
		return cloudClient{base}
	}
	return base
}
