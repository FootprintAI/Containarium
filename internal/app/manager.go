package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/app/buildpack"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	v1 "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Manager orchestrates app deployment workflow
type Manager struct {
	store       AppStore
	builder     *Builder
	proxy       *ProxyManager
	incusClient incus.Backend
	baseDomain  string
}

// ManagerConfig holds configuration for the manager
type ManagerConfig struct {
	// BaseDomain is the domain for app subdomains (e.g., "containarium.dev")
	BaseDomain string

	// CaddyAdminURL is the URL for Caddy's admin API
	CaddyAdminURL string
}

// NewManager creates a new app manager
func NewManager(store AppStore, incusClient incus.Backend, config ManagerConfig) *Manager {
	detector := buildpack.NewDetector()
	builder := NewBuilder(incusClient, detector)
	proxy := NewProxyManager(config.CaddyAdminURL, config.BaseDomain)

	return &Manager{
		store:       store,
		builder:     builder,
		proxy:       proxy,
		incusClient: incusClient,
		baseDomain:  config.BaseDomain,
	}
}

// DeployApp deploys a new application or updates an existing one
func (m *Manager) DeployApp(ctx context.Context, req *v1.DeployAppRequest) (*v1.App, *v1.DetectedLanguage, error) {
	// Validate app name
	if err := container.ValidateUserContainerName(req.AppName); err != nil {
		return nil, nil, fmt.Errorf("invalid app name: %w", err)
	}

	// Get user's container info
	containerName := req.Username + "-container" // User container follows {username}-container naming
	containerInfo, err := m.incusClient.GetContainer(containerName)
	if err != nil {
		return nil, nil, fmt.Errorf("user container not found: %w", err)
	}

	if containerInfo.State != "Running" {
		return nil, nil, fmt.Errorf("user container is not running")
	}

	// Generate subdomain if not provided
	subdomain := req.Subdomain
	if subdomain == "" {
		subdomain = fmt.Sprintf("%s-%s", req.Username, req.AppName)
	}

	// Default port
	port := req.Port
	if port == 0 {
		port = 3000
	}

	// Check if app already exists
	existingApp, err := m.store.GetByName(ctx, req.Username, req.AppName)
	var app *v1.App

	if err == nil && existingApp != nil {
		// Update existing app
		app = existingApp
		app.Port = port
		app.EnvVars = req.EnvVars
		app.State = v1.AppState_APP_STATE_UPLOADING
		app.UpdatedAt = timestamppb.Now()
		app.ErrorMessage = ""
	} else {
		// Create new app
		app = &v1.App{
			Id:            uuid.New().String(),
			Name:          req.AppName,
			Username:      req.Username,
			ContainerName: containerName,
			Subdomain:     subdomain,
			FullDomain:    fmt.Sprintf("%s.%s", subdomain, m.baseDomain),
			Port:          port,
			State:         v1.AppState_APP_STATE_UPLOADING,
			EnvVars:       req.EnvVars,
			CreatedAt:     timestamppb.Now(),
			UpdatedAt:     timestamppb.Now(),
		}
	}

	// Save initial state
	if err := m.store.Save(ctx, app); err != nil {
		return nil, nil, fmt.Errorf("failed to save app: %w", err)
	}

	// Extract and analyze source tarball
	files, err := m.extractSourceFiles(req.SourceTarball)
	if err != nil {
		app.State = v1.AppState_APP_STATE_FAILED
		app.ErrorMessage = fmt.Sprintf("failed to extract source: %v", err)
		m.store.Save(ctx, app)
		return nil, nil, fmt.Errorf("failed to extract source: %w", err)
	}

	// Detect language or use provided Dockerfile
	var detectedLang *v1.DetectedLanguage
	hasDockerfile := m.hasDockerfile(files, req.DockerfilePath)

	if hasDockerfile {
		detectedLang = &v1.DetectedLanguage{
			Name:               "Custom",
			DockerfileProvided: true,
		}
	} else {
		// Detect language using buildpack system
		lang, version, err := m.builder.detector.Detect(files)
		if err != nil {
			app.State = v1.AppState_APP_STATE_FAILED
			app.ErrorMessage = fmt.Sprintf("failed to detect language: %v", err)
			m.store.Save(ctx, app)
			return nil, nil, fmt.Errorf("failed to detect language: %w", err)
		}
		detectedLang = &v1.DetectedLanguage{
			Name:               lang,
			Version:            version,
			DockerfileProvided: false,
		}
	}

	// Update app state to building
	app.State = v1.AppState_APP_STATE_BUILDING
	app.UpdatedAt = timestamppb.Now()
	if err := m.store.Save(ctx, app); err != nil {
		return nil, nil, fmt.Errorf("failed to save app state: %w", err)
	}

	// Upload source to container
	appDir := fmt.Sprintf("/home/%s/apps/%s", req.Username, req.AppName)
	if err := m.uploadSource(ctx, containerName, appDir, req.SourceTarball); err != nil {
		app.State = v1.AppState_APP_STATE_FAILED
		app.ErrorMessage = fmt.Sprintf("failed to upload source: %v", err)
		m.store.Save(ctx, app)
		return nil, nil, fmt.Errorf("failed to upload source: %w", err)
	}

	// Build the container image using Podman
	buildReq := &BuildRequest{
		ContainerName:   containerName,
		AppName:         req.AppName,
		Username:        req.Username,
		SourceDir:       appDir,
		DockerfilePath:  req.DockerfilePath,
		Port:            int(port),
		Files:           files,
		BuildpackOpts:   req.Buildpack,
		GenerateIfNoDoc: !hasDockerfile,
	}

	buildResult, err := m.builder.Build(ctx, buildReq)
	if err != nil {
		app.State = v1.AppState_APP_STATE_FAILED
		app.ErrorMessage = fmt.Sprintf("build failed: %v", err)
		m.store.Save(ctx, app)
		return nil, nil, fmt.Errorf("build failed: %w", err)
	}

	app.ContainerImage = buildResult.ImageTag

	// Run the Podman container
	if err := m.runContainer(ctx, containerName, app, req.EnvVars); err != nil {
		app.State = v1.AppState_APP_STATE_FAILED
		app.ErrorMessage = fmt.Sprintf("failed to run container: %v", err)
		m.store.Save(ctx, app)
		return nil, nil, fmt.Errorf("failed to run container: %w", err)
	}

	// Configure reverse proxy
	if err := m.proxy.AddRoute(subdomain, containerInfo.IPAddress, int(port)); err != nil {
		// Log but don't fail - app is running, just not publicly accessible
		app.ErrorMessage = fmt.Sprintf("warning: proxy configuration failed: %v", err)
	}

	// Update final state
	app.State = v1.AppState_APP_STATE_RUNNING
	app.DeployedAt = timestamppb.Now()
	app.UpdatedAt = timestamppb.Now()
	if err := m.store.Save(ctx, app); err != nil {
		return nil, nil, fmt.Errorf("failed to save final state: %w", err)
	}

	return app, detectedLang, nil
}

// StopApp stops a running application
func (m *Manager) StopApp(ctx context.Context, username, appName string) (*v1.App, error) {
	app, err := m.store.GetByName(ctx, username, appName)
	if err != nil {
		return nil, fmt.Errorf("app not found: %w", err)
	}

	if app.State != v1.AppState_APP_STATE_RUNNING {
		return nil, fmt.Errorf("app is not running (current state: %s)", app.State.String())
	}

	// Stop the Podman container inside the user's LXC container
	podmanContainerName := m.podmanContainerName(app)
	stopCmd := []string{"podman", "stop", podmanContainerName}
	if err := m.incusClient.Exec(app.ContainerName, stopCmd); err != nil {
		return nil, fmt.Errorf("failed to stop podman container: %w", err)
	}

	// Update state
	app.State = v1.AppState_APP_STATE_STOPPED
	app.UpdatedAt = timestamppb.Now()
	if err := m.store.Save(ctx, app); err != nil {
		return nil, fmt.Errorf("failed to save state: %w", err)
	}

	return app, nil
}

// StartApp starts a stopped application
func (m *Manager) StartApp(ctx context.Context, username, appName string) (*v1.App, error) {
	app, err := m.store.GetByName(ctx, username, appName)
	if err != nil {
		return nil, fmt.Errorf("app not found: %w", err)
	}

	if app.State != v1.AppState_APP_STATE_STOPPED {
		return nil, fmt.Errorf("app is not stopped (current state: %s)", app.State.String())
	}

	// Start the Podman container
	podmanContainerName := m.podmanContainerName(app)
	startCmd := []string{"podman", "start", podmanContainerName}
	if err := m.incusClient.Exec(app.ContainerName, startCmd); err != nil {
		return nil, fmt.Errorf("failed to start podman container: %w", err)
	}

	// Update state
	app.State = v1.AppState_APP_STATE_RUNNING
	app.UpdatedAt = timestamppb.Now()
	if err := m.store.Save(ctx, app); err != nil {
		return nil, fmt.Errorf("failed to save state: %w", err)
	}

	return app, nil
}

// RestartApp restarts an application
func (m *Manager) RestartApp(ctx context.Context, username, appName string) (*v1.App, error) {
	app, err := m.store.GetByName(ctx, username, appName)
	if err != nil {
		return nil, fmt.Errorf("app not found: %w", err)
	}

	// Update state to restarting
	app.State = v1.AppState_APP_STATE_RESTARTING
	app.UpdatedAt = timestamppb.Now()
	if err := m.store.Save(ctx, app); err != nil {
		return nil, fmt.Errorf("failed to save state: %w", err)
	}

	// Restart the Podman container
	podmanContainerName := m.podmanContainerName(app)
	restartCmd := []string{"podman", "restart", podmanContainerName}
	if err := m.incusClient.Exec(app.ContainerName, restartCmd); err != nil {
		app.State = v1.AppState_APP_STATE_FAILED
		app.ErrorMessage = fmt.Sprintf("restart failed: %v", err)
		m.store.Save(ctx, app)
		return nil, fmt.Errorf("failed to restart podman container: %w", err)
	}

	// Update state
	app.State = v1.AppState_APP_STATE_RUNNING
	app.RestartCount++
	app.UpdatedAt = timestamppb.Now()
	if err := m.store.Save(ctx, app); err != nil {
		return nil, fmt.Errorf("failed to save state: %w", err)
	}

	return app, nil
}

// DeleteApp deletes an application
func (m *Manager) DeleteApp(ctx context.Context, username, appName string, removeData bool) error {
	app, err := m.store.GetByName(ctx, username, appName)
	if err != nil {
		return fmt.Errorf("app not found: %w", err)
	}

	// Stop and remove Podman container
	podmanContainerName := m.podmanContainerName(app)
	rmCmd := []string{"podman", "rm", "-f", podmanContainerName}
	m.incusClient.Exec(app.ContainerName, rmCmd) // Ignore errors

	// Remove Podman image
	if app.ContainerImage != "" {
		rmiCmd := []string{"podman", "rmi", "-f", app.ContainerImage}
		m.incusClient.Exec(app.ContainerName, rmiCmd) // Ignore errors
	}

	// Remove source directory if requested
	if removeData {
		appDir := fmt.Sprintf("/home/%s/apps/%s", username, appName)
		rmDirCmd := []string{"rm", "-rf", appDir}
		m.incusClient.Exec(app.ContainerName, rmDirCmd) // Ignore errors
	}

	// Remove proxy route
	m.proxy.RemoveRoute(app.Subdomain) // Ignore errors

	// Delete from store
	if err := m.store.Delete(ctx, app.Id); err != nil {
		return fmt.Errorf("failed to delete app from store: %w", err)
	}

	return nil
}

// GetLogs retrieves application logs
func (m *Manager) GetLogs(ctx context.Context, username, appName string, tailLines int32, follow bool) ([]string, error) {
	app, err := m.store.GetByName(ctx, username, appName)
	if err != nil {
		return nil, fmt.Errorf("app not found: %w", err)
	}

	if tailLines == 0 {
		tailLines = 100
	}

	podmanContainerName := m.podmanContainerName(app)
	logsCmd := []string{"podman", "logs", "--tail", fmt.Sprintf("%d", tailLines), podmanContainerName}

	stdout, stderr, err := m.incusClient.ExecWithOutput(app.ContainerName, logsCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}

	// Combine stdout and stderr
	var lines []string
	if stdout != "" {
		lines = append(lines, strings.Split(stdout, "\n")...)
	}
	if stderr != "" {
		lines = append(lines, strings.Split(stderr, "\n")...)
	}

	return lines, nil
}

// Helper functions

func (m *Manager) podmanContainerName(app *v1.App) string {
	return fmt.Sprintf("app-%s-%s", app.Username, app.Name)
}

func (m *Manager) extractSourceFiles(tarball []byte) ([]string, error) {
	var files []string

	gzr, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tarball: %w", err)
		}

		// Clean and normalize path
		name := filepath.Clean(header.Name)
		if header.Typeflag == tar.TypeReg {
			files = append(files, name)
		}
	}

	return files, nil
}

func (m *Manager) hasDockerfile(files []string, dockerfilePath string) bool {
	if dockerfilePath == "" {
		dockerfilePath = "Dockerfile"
	}

	for _, f := range files {
		if f == dockerfilePath || filepath.Base(f) == dockerfilePath {
			return true
		}
	}
	return false
}

func (m *Manager) uploadSource(ctx context.Context, containerName, appDir string, tarball []byte) error {
	// Create app directory
	mkdirCmd := []string{"mkdir", "-p", appDir}
	if err := m.incusClient.Exec(containerName, mkdirCmd); err != nil {
		return fmt.Errorf("failed to create app directory: %w", err)
	}

	// Write tarball to container
	tarPath := appDir + "/source.tar.gz"
	if err := m.incusClient.WriteFile(containerName, tarPath, tarball, "0644"); err != nil {
		return fmt.Errorf("failed to write tarball: %w", err)
	}

	// Extract tarball
	extractCmd := []string{"tar", "-xzf", tarPath, "-C", appDir}
	if err := m.incusClient.Exec(containerName, extractCmd); err != nil {
		return fmt.Errorf("failed to extract tarball: %w", err)
	}

	// Clean up tarball
	rmCmd := []string{"rm", tarPath}
	m.incusClient.Exec(containerName, rmCmd) // Ignore errors

	return nil
}

func (m *Manager) runContainer(ctx context.Context, containerName string, app *v1.App, envVars map[string]string) error {
	podmanContainerName := m.podmanContainerName(app)

	// Build podman run command
	args := []string{
		"podman", "run", "-d",
		"--name", podmanContainerName,
		"--restart", "unless-stopped",
		"-p", fmt.Sprintf("%d:%d", app.Port, app.Port),
	}

	// Add environment variables
	for key, value := range envVars {
		args = append(args, "-e", fmt.Sprintf("%s=%s", key, value))
	}

	// Add the image
	args = append(args, app.ContainerImage)

	// Remove existing container if any
	rmCmd := []string{"podman", "rm", "-f", podmanContainerName}
	m.incusClient.Exec(containerName, rmCmd) // Ignore errors

	// Run the new container
	if err := m.incusClient.Exec(containerName, args); err != nil {
		return fmt.Errorf("failed to run podman container: %w", err)
	}

	return nil
}
