package cmd

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/spf13/cobra"
)

var (
	deploySource    string
	deployPort      int32
	deploySubdomain string
	deployEnvVars   []string
	deployUsername  string
)

var appDeployCmd = &cobra.Command{
	Use:   "deploy <app-name>",
	Short: "Deploy an application",
	Long: `Deploy an application to your container.

The source directory should contain either:
  - A Dockerfile (recommended for custom builds)
  - Project files for auto-detection (package.json, requirements.txt, go.mod, etc.)

Supported languages for auto-detection:
  - Node.js (package.json)
  - Python (requirements.txt, Pipfile, pyproject.toml)
  - Go (go.mod)
  - Rust (Cargo.toml)
  - Ruby (Gemfile)
  - PHP (composer.json)
  - Static sites (index.html)

Examples:
  # Deploy from current directory
  containarium app deploy myapp --source .

  # Deploy with custom port
  containarium app deploy myapp --source ./app --port 8080

  # Deploy with environment variables
  containarium app deploy myapp --source . --env "DB_HOST=localhost" --env "DEBUG=true"

  # Deploy with custom subdomain
  containarium app deploy myapp --source . --subdomain my-custom-app`,
	Args: cobra.ExactArgs(1),
	RunE: runAppDeploy,
}

func init() {
	appCmd.AddCommand(appDeployCmd)

	appDeployCmd.Flags().StringVarP(&deploySource, "source", "s", ".", "Source directory to deploy")
	appDeployCmd.Flags().Int32VarP(&deployPort, "port", "p", 3000, "Application port")
	appDeployCmd.Flags().StringVar(&deploySubdomain, "subdomain", "", "Custom subdomain (default: username-appname)")
	appDeployCmd.Flags().StringArrayVarP(&deployEnvVars, "env", "e", nil, "Environment variables (KEY=VALUE)")
	appDeployCmd.Flags().StringVarP(&deployUsername, "user", "u", "", "Username (required for remote deployment)")
}

func runAppDeploy(cmd *cobra.Command, args []string) error {
	appName := args[0]

	// Validate app name
	if appName == "" {
		return fmt.Errorf("app name is required")
	}

	// For remote server, username is required
	if serverAddr != "" && deployUsername == "" {
		return fmt.Errorf("--user is required when deploying to a remote server")
	}

	// Create tarball from source directory
	fmt.Printf("Packaging source from %s...\n", deploySource)
	tarball, err := createSourceTarball(deploySource)
	if err != nil {
		return fmt.Errorf("failed to package source: %w", err)
	}
	fmt.Printf("Package size: %.2f KB\n", float64(len(tarball))/1024)

	// Parse environment variables
	envVars := make(map[string]string)
	for _, env := range deployEnvVars {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid environment variable format: %s (expected KEY=VALUE)", env)
		}
		envVars[parts[0]] = parts[1]
	}

	// Deploy via gRPC
	if serverAddr == "" {
		return fmt.Errorf("--server is required for app deployment (remote deployment only)")
	}

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer grpcClient.Close()

	fmt.Printf("Deploying %s...\n", appName)
	app, detectedLang, err := grpcClient.DeployApp(deployUsername, appName, tarball, deployPort, envVars, deploySubdomain)
	if err != nil {
		return fmt.Errorf("deployment failed: %w", err)
	}

	// Print result
	fmt.Println()
	fmt.Println("Deployment successful!")
	fmt.Println()
	fmt.Printf("App Name:    %s\n", app.Name)
	fmt.Printf("State:       %s\n", app.State.String())
	fmt.Printf("URL:         https://%s\n", app.FullDomain)
	fmt.Printf("Port:        %d\n", app.Port)

	if detectedLang != nil {
		if detectedLang.DockerfileProvided {
			fmt.Printf("Dockerfile:  Provided\n")
		} else {
			fmt.Printf("Language:    %s %s (auto-detected)\n", detectedLang.Name, detectedLang.Version)
		}
	}

	fmt.Println()
	fmt.Printf("View logs: containarium app logs %s --server %s --user %s\n", appName, serverAddr, deployUsername)

	return nil
}

// createSourceTarball creates a gzipped tarball from a source directory
func createSourceTarball(sourceDir string) ([]byte, error) {
	// Resolve absolute path
	absPath, err := filepath.Abs(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Check if directory exists
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("source directory not found: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("source path is not a directory: %s", absPath)
	}

	// Create tarball in memory
	var buf strings.Builder
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	// Walk the directory
	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden files and common ignore patterns
		base := filepath.Base(path)
		if strings.HasPrefix(base, ".") && base != "." {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip common directories that shouldn't be included
		if info.IsDir() {
			switch base {
			case "node_modules", "__pycache__", ".git", ".svn", "vendor", "target":
				return filepath.SkipDir
			}
		}

		// Get relative path
		relPath, err := filepath.Rel(absPath, path)
		if err != nil {
			return err
		}

		// Skip the root directory itself
		if relPath == "." {
			return nil
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		// Write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// If it's a file, write its contents
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tw, file); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create tarball: %w", err)
	}

	// Close writers
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return []byte(buf.String()), nil
}
