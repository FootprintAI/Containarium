package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/app/buildpack"
	v1 "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Builder handles Docker image builds inside user containers
type Builder struct {
	incusClient IncusClient
	detector    *buildpack.Detector
}

// BuildRequest contains parameters for building an app
type BuildRequest struct {
	ContainerName   string
	AppName         string
	Username        string
	SourceDir       string
	DockerfilePath  string
	Port            int
	Files           []string
	BuildpackOpts   *v1.BuildpackOptions
	GenerateIfNoDoc bool
}

// BuildResult contains the result of a build operation
type BuildResult struct {
	ImageTag  string
	BuildLogs []string
	Success   bool
}

// NewBuilder creates a new app builder
func NewBuilder(incusClient IncusClient, detector *buildpack.Detector) *Builder {
	return &Builder{
		incusClient: incusClient,
		detector:    detector,
	}
}

// Build builds a Docker image for the app
func (b *Builder) Build(ctx context.Context, req *BuildRequest) (*BuildResult, error) {
	imageTag := fmt.Sprintf("%s/%s:latest", req.Username, req.AppName)
	result := &BuildResult{
		ImageTag: imageTag,
	}

	// Check if Dockerfile exists, or generate one
	dockerfilePath := req.DockerfilePath
	if dockerfilePath == "" {
		dockerfilePath = "Dockerfile"
	}

	fullDockerfilePath := fmt.Sprintf("%s/%s", req.SourceDir, dockerfilePath)

	if req.GenerateIfNoDoc {
		// Generate Dockerfile using buildpack
		dockerfile, err := b.generateDockerfile(req)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dockerfile: %w", err)
		}

		// Write generated Dockerfile to container
		if err := b.incusClient.WriteFile(req.ContainerName, fullDockerfilePath, []byte(dockerfile), "0644"); err != nil {
			return nil, fmt.Errorf("failed to write Dockerfile: %w", err)
		}
	}

	// Build the Docker image
	buildCmd := []string{
		"docker", "build",
		"-t", imageTag,
		"-f", fullDockerfilePath,
		req.SourceDir,
	}

	stdout, stderr, err := b.incusClient.ExecWithOutput(req.ContainerName, buildCmd)
	if err != nil {
		result.Success = false
		result.BuildLogs = append(result.BuildLogs, stderr)
		return nil, fmt.Errorf("docker build failed: %w\nOutput: %s", err, stderr)
	}

	result.Success = true
	result.BuildLogs = strings.Split(stdout+stderr, "\n")

	return result, nil
}

// generateDockerfile creates a Dockerfile based on detected language
func (b *Builder) generateDockerfile(req *BuildRequest) (string, error) {
	langName, _, err := b.detector.Detect(req.Files)
	if err != nil {
		return "", err
	}

	opts := buildpack.GenerateOptions{
		Port:  req.Port,
		Files: req.Files,
	}

	// Apply buildpack options if provided
	if req.BuildpackOpts != nil {
		opts.NodeVersion = req.BuildpackOpts.NodeVersion
		opts.PythonVersion = req.BuildpackOpts.PythonVersion
		opts.GoVersion = req.BuildpackOpts.GoVersion
		opts.RustVersion = req.BuildpackOpts.RustVersion
	}

	return b.detector.GenerateDockerfile(langName, opts)
}

// GetBuildLogs retrieves build logs for an app
func (b *Builder) GetBuildLogs(ctx context.Context, containerName, appName string) ([]string, error) {
	// For now, we don't persist build logs separately
	// In a future version, we could store them in Redis or a file
	return nil, fmt.Errorf("build logs not available")
}
