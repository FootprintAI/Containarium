package client

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/footprintai/containarium/internal/mtls"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCClient wraps a gRPC connection to the containarium daemon
type GRPCClient struct {
	conn          *grpc.ClientConn
	client        pb.ContainerServiceClient
	appClient     pb.AppServiceClient
	networkClient pb.NetworkServiceClient
	recipeClient  pb.RecipeServiceClient
	backupClient  pb.BackupServiceClient
	kmsClient     pb.KmsServiceClient
}

// NewGRPCClient creates a new gRPC client
func NewGRPCClient(serverAddr string, certsDir string, insecureConn bool) (*GRPCClient, error) {
	var opts []grpc.DialOption

	if insecureConn {
		// Insecure connection (not recommended)
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// Use mTLS
		if certsDir == "" {
			// Default to ~/.config/containarium/certs
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to get home directory: %w", err)
			}
			certsDir = filepath.Join(homeDir, ".config", "containarium", "certs")
		}

		// Load certificates
		paths := mtls.CertPaths{
			CACert:     filepath.Join(certsDir, "ca.crt"),
			ClientCert: filepath.Join(certsDir, "client.crt"),
			ClientKey:  filepath.Join(certsDir, "client.key"),
		}

		// Check if certificates exist
		if _, err := os.Stat(paths.CACert); os.IsNotExist(err) {
			return nil, fmt.Errorf("CA certificate not found at %s\nPlease download certificates from the server:\n  gcloud compute scp SERVER:/etc/containarium/certs/ca.crt %s\n  gcloud compute scp SERVER:/etc/containarium/certs/client.crt %s\n  gcloud compute scp SERVER:/etc/containarium/certs/client.key %s",
				paths.CACert, paths.CACert, paths.ClientCert, paths.ClientKey)
		}

		// Load client dial options
		dialOpts, err := mtls.LoadClientDialOptions(paths, serverAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, dialOpts...)
	}

	// Connect to server
	conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial server: %w", err)
	}

	// Create clients
	client := pb.NewContainerServiceClient(conn)
	appClient := pb.NewAppServiceClient(conn)
	networkClient := pb.NewNetworkServiceClient(conn)
	recipeClient := pb.NewRecipeServiceClient(conn)
	backupClient := pb.NewBackupServiceClient(conn)
	kmsClient := pb.NewKmsServiceClient(conn)

	return &GRPCClient{
		conn:          conn,
		client:        client,
		appClient:     appClient,
		networkClient: networkClient,
		recipeClient:  recipeClient,
		backupClient:  backupClient,
		kmsClient:     kmsClient,
	}, nil
}

// Close closes the gRPC connection
func (c *GRPCClient) Close() error {
	return c.conn.Close()
}

// Conn returns the underlying *grpc.ClientConn for callers that need
// to instantiate typed clients beyond the ones this wrapper pre-builds
// (container/app/network). Useful for adding a new service without
// also adding pre-built helper methods here for every RPC.
//
// Callers should NOT close the returned conn — its lifetime is owned
// by this GRPCClient and is freed in Close().
func (c *GRPCClient) Conn() *grpc.ClientConn {
	return c.conn
}

// ListContainers lists all containers via gRPC
func (c *GRPCClient) ListContainers() ([]incus.ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.client.ListContainers(ctx, &pb.ListContainersRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Convert protobuf response to incus.ContainerInfo
	var containers []incus.ContainerInfo
	for _, container := range resp.Containers {
		info := incus.ContainerInfo{
			Name:                 container.Name,
			Username:             container.Username,
			State:                container.State.String(),
			MonitoringEnabled:    container.MonitoringEnabled,
			AutoSleepEnabled:     container.AutoSleepEnabled,
			IdleThresholdMinutes: container.IdleThresholdMinutes,
		}

		// Get IP address from network info
		if container.Network != nil {
			info.IPAddress = container.Network.IpAddress
		}

		// Get resource limits
		if container.Resources != nil {
			info.CPU = container.Resources.Cpu
			info.Memory = container.Resources.Memory
		}

		// Convert Unix timestamp to time.Time
		if container.CreatedAt > 0 {
			info.CreatedAt = time.Unix(container.CreatedAt, 0)
		}

		containers = append(containers, info)
	}

	return containers, nil
}

// CreateContainer creates a container via gRPC
func (c *GRPCClient) CreateContainer(username, image, cpu, memory, disk string, sshKeys []string, enablePodman bool, stack, gpu string, osType pb.OSType, monitoring bool, pool, backendID string, git GitSourceOpts) (*incus.ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute) // Container creation can take time (includes ultra-aggressive retry logic for google_guest_agent)
	defer cancel()

	req := &pb.CreateContainerRequest{
		Username: username,
		Resources: &pb.ResourceLimits{
			Cpu:    cpu,
			Memory: memory,
			Disk:   disk,
		},
		SshKeys:       sshKeys,
		Image:         image,
		EnablePodman:  enablePodman,
		Stack:         stack,
		Gpu:           gpu,
		OsType:        osType,
		Monitoring:    monitoring,
		Pool:          pool,
		BackendId:     backendID,
		GitSource:     git.Source,
		GitRef:        git.Ref,
		GitCredential: git.Credential,
		WorkspacePath: git.WorkspacePath,
	}

	resp, err := c.client.CreateContainer(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Convert protobuf Container to incus.ContainerInfo
	container := resp.Container
	info := &incus.ContainerInfo{
		Name:     container.Name,
		Username: container.Username,
		State:    container.State.String(),
	}

	if container.Network != nil {
		info.IPAddress = container.Network.IpAddress
	}

	if container.Resources != nil {
		info.CPU = container.Resources.Cpu
		info.Memory = container.Resources.Memory
	}

	if container.CreatedAt > 0 {
		info.CreatedAt = time.Unix(container.CreatedAt, 0)
	}

	return info, nil
}

// ToggleMonitoring enables / disables OTel app telemetry on an
// existing container. Returns the new monitoring_enabled state and
// a human-readable summary of what changed.
func (c *GRPCClient) ToggleMonitoring(username string, enabled bool) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req := &pb.ToggleMonitoringRequest{
		Username: username,
		Enabled:  enabled,
	}
	resp, err := c.client.ToggleMonitoring(ctx, req)
	if err != nil {
		return "", false, fmt.Errorf("failed to toggle monitoring: %w", err)
	}
	return resp.Message, resp.MonitoringEnabled, nil
}

// ToggleAutoSleep writes the per-container auto-sleep opt-in metadata.
// idleThresholdMinutes is ignored when enabled is false; 0 means
// "leave the existing key or fall back to the 15-minute default".
func (c *GRPCClient) ToggleAutoSleep(username string, enabled bool, idleThresholdMinutes int32) (*pb.ToggleAutoSleepResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &pb.ToggleAutoSleepRequest{
		Username:             username,
		Enabled:              enabled,
		IdleThresholdMinutes: idleThresholdMinutes,
	}
	resp, err := c.client.ToggleAutoSleep(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to toggle auto-sleep: %w", err)
	}
	return resp, nil
}

// StartContainer starts a stopped container via gRPC. When
// waitForReady is true the server blocks until the container's
// primary TCP port accepts or readyTimeoutSeconds elapses (0 falls
// back to the server-side 30s default).
func (c *GRPCClient) StartContainer(username string, waitForReady bool, readyTimeoutSeconds int32) (*pb.StartContainerResponse, error) {
	timeout := 60 * time.Second
	if waitForReady && readyTimeoutSeconds > 0 {
		timeout = time.Duration(readyTimeoutSeconds+10) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resp, err := c.client.StartContainer(ctx, &pb.StartContainerRequest{
		Username:            username,
		WaitForReady:        waitForReady,
		ReadyTimeoutSeconds: readyTimeoutSeconds,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}
	return resp, nil
}

// StopContainer stops a running container via gRPC.
func (c *GRPCClient) StopContainer(username string, force bool) (*pb.StopContainerResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := c.client.StopContainer(ctx, &pb.StopContainerRequest{
		Username: username,
		Force:    force,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to stop container: %w", err)
	}
	return resp, nil
}

// DeleteContainer deletes a container via gRPC
func (c *GRPCClient) DeleteContainer(username string, force bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &pb.DeleteContainerRequest{
		Username: username,
		Force:    force,
	}

	_, err := c.client.DeleteContainer(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}

	return nil
}

// SetSecret creates or updates a tenant secret via gRPC. Idempotent —
// repeated calls with the same (username, name) bump the version.
// `delivery` is "" (server normalizes to env), "env", or "file"
// (Phase 4.3 — Phase A lands the field).
func (c *GRPCClient) SetSecret(username, name, value, delivery string) (*pb.SecretMetadata, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.client.SetSecret(ctx, &pb.SetSecretRequest{
		Username: username, Name: name, Value: value, Delivery: delivery,
	})
	if err != nil {
		return nil, "", fmt.Errorf("set secret: %w", err)
	}
	return resp.Secret, resp.Message, nil
}

// GetSecret reads a single secret's plaintext value via gRPC.
func (c *GRPCClient) GetSecret(username, name string) (*pb.SecretMetadata, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.client.GetSecret(ctx, &pb.GetSecretRequest{
		Username: username, Name: name,
	})
	if err != nil {
		return nil, "", fmt.Errorf("get secret: %w", err)
	}
	return resp.Secret, resp.Value, nil
}

// ListSecrets returns metadata for every secret owned by the tenant.
func (c *GRPCClient) ListSecrets(username string) ([]*pb.SecretMetadata, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.client.ListSecrets(ctx, &pb.ListSecretsRequest{Username: username})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	return resp.Secrets, nil
}

// DeleteSecret removes a tenant secret via gRPC.
func (c *GRPCClient) DeleteSecret(username, name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.client.DeleteSecret(ctx, &pb.DeleteSecretRequest{
		Username: username, Name: name,
	})
	if err != nil {
		return "", fmt.Errorf("delete secret: %w", err)
	}
	return resp.Message, nil
}

// RefreshSecrets re-stamps the LXC's env from the current secret DB
// state for the tenant. Running processes keep their old env; new
// execs see the refreshed values.
func (c *GRPCClient) RefreshSecrets(username string) (string, int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.client.RefreshSecrets(ctx, &pb.RefreshSecretsRequest{Username: username})
	if err != nil {
		return "", 0, fmt.Errorf("refresh secrets: %w", err)
	}
	return resp.Message, resp.Stamped, nil
}

// ResizeContainer changes a container's CPU / memory / disk via gRPC.
// Empty string for any field means "no change". Disk can only grow —
// the server rejects shrinks.
func (c *GRPCClient) ResizeContainer(username, cpu, memory, disk string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req := &pb.ResizeContainerRequest{
		Username: username,
		Cpu:      cpu,
		Memory:   memory,
		Disk:     disk,
	}
	resp, err := c.client.ResizeContainer(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to resize container: %w", err)
	}
	return resp.Message, nil
}

// GetContainer gets information about a specific container via gRPC
func (c *GRPCClient) GetContainer(username string) (*incus.ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &pb.GetContainerRequest{
		Username: username,
	}

	resp, err := c.client.GetContainer(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	}

	// Convert protobuf Container to incus.ContainerInfo
	container := resp.Container
	info := &incus.ContainerInfo{
		Name:                 container.Name,
		Username:             container.Username,
		State:                container.State.String(),
		MonitoringEnabled:    container.MonitoringEnabled,
		AutoSleepEnabled:     container.AutoSleepEnabled,
		IdleThresholdMinutes: container.IdleThresholdMinutes,
	}

	if container.Network != nil {
		info.IPAddress = container.Network.IpAddress
	}

	if container.Resources != nil {
		info.CPU = container.Resources.Cpu
		info.Memory = container.Resources.Memory
	}

	if container.CreatedAt > 0 {
		info.CreatedAt = time.Unix(container.CreatedAt, 0)
	}

	return info, nil
}

// DebugContainer returns a diagnostic report for a container's SSH path.
func (c *GRPCClient) DebugContainer(username string) (*pb.DebugContainerResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.client.DebugContainer(ctx, &pb.DebugContainerRequest{Username: username})
	if err != nil {
		return nil, fmt.Errorf("failed to debug container: %w", err)
	}
	return resp, nil
}

// InstallStack installs a stack or base script on a running container via gRPC
func (c *GRPCClient) InstallStack(username, stackID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	req := &pb.InstallStackRequest{
		Username: username,
		StackId:  stackID,
	}

	_, err := c.client.InstallStack(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to install stack: %w", err)
	}

	return nil
}

// GetSystemInfo gets system information via gRPC
func (c *GRPCClient) GetSystemInfo() (*incus.ServerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.client.GetSystemInfo(ctx, &pb.GetSystemInfoRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get system info: %w", err)
	}

	// Convert to incus.ServerInfo
	info := &incus.ServerInfo{
		Version:       resp.Info.IncusVersion,
		KernelVersion: resp.Info.KernelVersion,
	}

	return info, nil
}

// ============================================
// App Service Methods
// ============================================

// DeployApp deploys an application via gRPC
func (c *GRPCClient) DeployApp(username, appName string, sourceTarball []byte, port int32, envVars map[string]string, subdomain string) (*pb.App, *pb.DetectedLanguage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute) // Build can take time
	defer cancel()

	req := &pb.DeployAppRequest{
		Username:      username,
		AppName:       appName,
		SourceTarball: sourceTarball,
		Port:          port,
		EnvVars:       envVars,
		Subdomain:     subdomain,
	}

	resp, err := c.appClient.DeployApp(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to deploy app: %w", err)
	}

	return resp.App, resp.DetectedLanguage, nil
}

// ListRecipes lists all built-in recipes via gRPC.
func (c *GRPCClient) ListRecipes() ([]*pb.Recipe, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.recipeClient.ListRecipes(ctx, &pb.ListRecipesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list recipes: %w", err)
	}
	return resp.Recipes, nil
}

// GetRecipe fetches a single recipe definition via gRPC.
func (c *GRPCClient) GetRecipe(id string) (*pb.Recipe, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.recipeClient.GetRecipe(ctx, &pb.GetRecipeRequest{Id: id})
	if err != nil {
		return nil, fmt.Errorf("failed to get recipe: %w", err)
	}
	return resp.Recipe, nil
}

// DeployRecipe provisions a new dedicated container from a recipe via gRPC.
func (c *GRPCClient) DeployRecipe(recipeID, name, gpu, backendID, pool string, params map[string]string) (*pb.DeployRecipeResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute) // image + model pulls can take time
	defer cancel()

	req := &pb.DeployRecipeRequest{
		RecipeId:   recipeID,
		Name:       name,
		Gpu:        gpu,
		BackendId:  backendID,
		Pool:       pool,
		Parameters: params,
	}
	resp, err := c.recipeClient.DeployRecipe(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to deploy recipe: %w", err)
	}
	return resp, nil
}

// CreateBackup dumps a tenant's database and stores it off-host via gRPC.
func (c *GRPCClient) CreateBackup(req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute) // large dumps + upload can take time
	defer cancel()

	resp, err := c.backupClient.CreateBackup(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create backup: %w", err)
	}
	return resp, nil
}

// ListBackups lists stored backups via gRPC.
func (c *GRPCClient) ListBackups(username string) ([]*pb.BackupRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.backupClient.ListBackups(ctx, &pb.ListBackupsRequest{Username: username})
	if err != nil {
		return nil, fmt.Errorf("failed to list backups: %w", err)
	}
	return resp.Records, nil
}

// GetBackup fetches a single backup record via gRPC.
func (c *GRPCClient) GetBackup(id string) (*pb.BackupRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.backupClient.GetBackup(ctx, &pb.GetBackupRequest{Id: id})
	if err != nil {
		return nil, fmt.Errorf("failed to get backup: %w", err)
	}
	return resp.Record, nil
}

// RestoreBackup restores a stored dump via gRPC.
func (c *GRPCClient) RestoreBackup(req *pb.RestoreBackupRequest) (*pb.RestoreBackupResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute) // download + pg_restore can take time
	defer cancel()

	resp, err := c.backupClient.RestoreBackup(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to restore backup: %w", err)
	}
	return resp, nil
}

// DeleteBackup removes a stored dump and its index entry via gRPC.
func (c *GRPCClient) DeleteBackup(id string) (*pb.DeleteBackupResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.backupClient.DeleteBackup(ctx, &pb.DeleteBackupRequest{Id: id})
	if err != nil {
		return nil, fmt.Errorf("failed to delete backup: %w", err)
	}
	return resp, nil
}

// GetKMSStatus reports the active KMS backend + envelope state via gRPC.
func (c *GRPCClient) GetKMSStatus() (*pb.GetKMSStatusResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.kmsClient.GetKMSStatus(ctx, &pb.GetKMSStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("get kms status: %w", err)
	}
	return resp, nil
}

// GetEnvelopeCoverage reports secret counts by encryption mode via gRPC.
func (c *GRPCClient) GetEnvelopeCoverage() (*pb.GetEnvelopeCoverageResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.kmsClient.GetEnvelopeCoverage(ctx, &pb.GetEnvelopeCoverageRequest{})
	if err != nil {
		return nil, fmt.Errorf("get envelope coverage: %w", err)
	}
	return resp, nil
}

// MigrateToEnvelope triggers the legacy→envelope re-wrap via gRPC. A
// large backlog can exceed the default deadline; the timeout scales
// loosely with maxRows (0 = unlimited → a generous ceiling).
func (c *GRPCClient) MigrateToEnvelope(req *pb.MigrateToEnvelopeRequest) (*pb.MigrateToEnvelopeResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	resp, err := c.kmsClient.MigrateToEnvelope(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("migrate to envelope: %w", err)
	}
	return resp, nil
}

// ListApps lists all applications via gRPC
func (c *GRPCClient) ListApps(username string, stateFilter pb.AppState) ([]*pb.App, int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &pb.ListAppsRequest{
		Username:    username,
		StateFilter: stateFilter,
	}

	resp, err := c.appClient.ListApps(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list apps: %w", err)
	}

	return resp.Apps, resp.TotalCount, nil
}

// GetApp gets information about a specific application via gRPC
func (c *GRPCClient) GetApp(username, appName string) (*pb.App, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &pb.GetAppRequest{
		Username: username,
		AppName:  appName,
	}

	resp, err := c.appClient.GetApp(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get app: %w", err)
	}

	return resp.App, nil
}

// StopApp stops an application via gRPC
func (c *GRPCClient) StopApp(username, appName string) (*pb.App, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &pb.StopAppRequest{
		Username: username,
		AppName:  appName,
	}

	resp, err := c.appClient.StopApp(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to stop app: %w", err)
	}

	return resp.App, nil
}

// StartApp starts an application via gRPC
func (c *GRPCClient) StartApp(username, appName string) (*pb.App, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &pb.StartAppRequest{
		Username: username,
		AppName:  appName,
	}

	resp, err := c.appClient.StartApp(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to start app: %w", err)
	}

	return resp.App, nil
}

// RestartApp restarts an application via gRPC
func (c *GRPCClient) RestartApp(username, appName string) (*pb.App, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req := &pb.RestartAppRequest{
		Username: username,
		AppName:  appName,
	}

	resp, err := c.appClient.RestartApp(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to restart app: %w", err)
	}

	return resp.App, nil
}

// DeleteApp deletes an application via gRPC
func (c *GRPCClient) DeleteApp(username, appName string, removeData bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &pb.DeleteAppRequest{
		Username:   username,
		AppName:    appName,
		RemoveData: removeData,
	}

	_, err := c.appClient.DeleteApp(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to delete app: %w", err)
	}

	return nil
}

// GetAppLogs gets application logs via gRPC
func (c *GRPCClient) GetAppLogs(username, appName string, tailLines int32) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &pb.GetAppLogsRequest{
		Username:  username,
		AppName:   appName,
		TailLines: tailLines,
		Follow:    false,
	}

	stream, err := c.appClient.GetAppLogs(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get app logs: %w", err)
	}

	var logs []string
	for {
		resp, err := stream.Recv()
		if err != nil {
			break // End of stream or error
		}
		logs = append(logs, resp.LogLines...)
	}

	return logs, nil
}

// ============================================
// Network Service Methods
// ============================================

// ListRoutes lists all proxy routes via gRPC
func (c *GRPCClient) ListRoutes(username string, activeOnly bool) ([]*pb.ProxyRoute, int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &pb.GetRoutesRequest{
		Username:   username,
		ActiveOnly: activeOnly,
	}

	resp, err := c.networkClient.GetRoutes(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list routes: %w", err)
	}

	return resp.Routes, resp.TotalCount, nil
}

// AddRoute adds a new proxy route via gRPC
func (c *GRPCClient) AddRoute(domain, targetIP string, targetPort int32, containerName, description string) (*pb.ProxyRoute, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &pb.AddRouteRequest{
		Domain:        domain,
		TargetIp:      targetIP,
		TargetPort:    targetPort,
		ContainerName: containerName,
		Description:   description,
	}

	resp, err := c.networkClient.AddRoute(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to add route: %w", err)
	}

	return resp.Route, nil
}

// UpdateRoute updates an existing proxy route via gRPC
func (c *GRPCClient) UpdateRoute(domain, targetIP string, targetPort int32, containerName, description string) (*pb.ProxyRoute, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &pb.UpdateRouteRequest{
		Domain:        domain,
		TargetIp:      targetIP,
		TargetPort:    targetPort,
		ContainerName: containerName,
		Description:   description,
	}

	resp, err := c.networkClient.UpdateRoute(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update route: %w", err)
	}

	return resp.Route, nil
}

// DeleteRoute deletes a proxy route via gRPC
func (c *GRPCClient) DeleteRoute(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &pb.DeleteRouteRequest{
		Domain: domain,
	}

	_, err := c.networkClient.DeleteRoute(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to delete route: %w", err)
	}

	return nil
}
