package integration

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tfembed "github.com/footprintai/containarium/terraform/embed"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2ERebootPersistenceTerraform is an E2E test using Terraform for infrastructure
func TestE2ERebootPersistenceTerraform(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Check required environment variables
	projectID := os.Getenv("GCP_PROJECT")
	if projectID == "" {
		t.Skip("GCP_PROJECT not set, skipping E2E test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	// Setup test workspace
	workspace := setupTerraformWorkspace(t)
	defer cleanupTerraformWorkspace(t, workspace)

	t.Logf("Starting E2E reboot persistence test with Terraform...")
	t.Logf("  Project: %s", projectID)
	t.Logf("  Workspace: %s", workspace)

	var instanceIP string
	var instanceName string
	var zone string

	// Cleanup function
	defer func() {
		if !t.Failed() || os.Getenv("KEEP_INSTANCE") != "true" {
			t.Log("Destroying infrastructure...")
			destroyTerraform(t, ctx, workspace)
		} else {
			t.Logf("Test failed - keeping infrastructure for debugging")
			t.Logf("To cleanup: cd %s && terraform destroy -auto-approve", workspace)
		}
	}()

	// Step 1: Deploy infrastructure with Terraform
	t.Run("DeployInfrastructure", func(t *testing.T) {
		deployTerraform(t, ctx, workspace, projectID)
	})

	// Step 2: Get instance details from Terraform outputs
	t.Run("GetInstanceInfo", func(t *testing.T) {
		var err error
		instanceIP, instanceName, zone, err = getTerraformOutputs(t, ctx, workspace)
		require.NoError(t, err)
		require.NotEmpty(t, instanceIP, "Instance IP should not be empty")
		require.NotEmpty(t, instanceName, "Instance name should not be empty")
		require.NotEmpty(t, zone, "Zone should not be empty")
		t.Logf("Instance: %s at IP: %s in zone: %s", instanceName, instanceIP, zone)
	})

	// Step 3: Wait for instance to be ready
	t.Run("WaitForInstanceReady", func(t *testing.T) {
		waitForInstanceReadyTF(t, ctx, instanceName, zone)
	})

	// Step 4: Verify ZFS setup
	t.Run("VerifyZFSSetup", func(t *testing.T) {
		verifyZFSSetupTF(t, ctx, instanceName, zone)
	})

	// Step 5: Create container with test data
	testData := ""
	expectedChecksum := ""
	t.Run("CreateContainerWithData", func(t *testing.T) {
		testData, expectedChecksum = createContainerWithTestDataTF(t, ctx, instanceName, zone)
		require.NotEmpty(t, testData, "Test data should not be empty")
		require.NotEmpty(t, expectedChecksum, "Checksum should not be empty")
		t.Logf("Test data written with checksum: %s", expectedChecksum)
	})

	// Step 6: Reboot instance using gcloud (Terraform doesn't support reboot action)
	t.Run("RebootInstance", func(t *testing.T) {
		rebootInstanceTF(t, ctx, instanceName, zone)
	})

	// Step 7: Wait for instance to come back
	t.Run("WaitAfterReboot", func(t *testing.T) {
		waitForInstanceReadyTF(t, ctx, instanceName, zone)
		t.Log("Instance is back online after reboot")
	})

	// Step 8: Verify data persisted
	t.Run("VerifyDataPersistence", func(t *testing.T) {
		verifyDataPersistedTF(t, ctx, instanceName, zone, testData, expectedChecksum)
	})

	t.Log("✅ E2E Reboot Persistence Test with Terraform PASSED!")
}

// setupTerraformWorkspace creates a temporary Terraform workspace for testing
func setupTerraformWorkspace(t *testing.T) string {
	// Create temp directory for test workspace
	tmpDir, err := os.MkdirTemp("", "containarium-e2e-*")
	require.NoError(t, err, "Failed to create temp directory")

	// Write all embedded Terraform files to workspace
	for filename, content := range tfembed.AllFiles() {
		destPath := filepath.Join(tmpDir, filename)

		// Create parent directory if needed
		err := os.MkdirAll(filepath.Dir(destPath), 0755)
		require.NoError(t, err, "Failed to create directory for %s", filename)

		// Write file content
		err = os.WriteFile(destPath, []byte(content), 0644)
		require.NoError(t, err, "Failed to write %s", filename)
	}

	t.Logf("Terraform workspace created at: %s", tmpDir)
	return tmpDir
}

// cleanupTerraformWorkspace removes the temporary workspace
func cleanupTerraformWorkspace(t *testing.T, workspace string) {
	if os.Getenv("KEEP_WORKSPACE") == "true" {
		t.Logf("Keeping workspace: %s", workspace)
		return
	}
	os.RemoveAll(workspace)
}

// deployTerraform deploys infrastructure using Terraform
func deployTerraform(t *testing.T, ctx context.Context, workspace, projectID string) {
	t.Log("Deploying infrastructure with Terraform...")

	// Create tfvars file
	instanceName := fmt.Sprintf("containarium-e2e-%d", time.Now().Unix())
	tfvarsPath := filepath.Join(workspace, "e2e-test.tfvars")

	tfvarsContent := fmt.Sprintf(`# E2E Test Configuration
project_id = "%s"

# Test instance configuration
instance_name = "%s"
machine_type = "e2-standard-2"
use_spot_instance = true
use_persistent_disk = true

# Disk sizes
boot_disk_size = 100
data_disk_size = 100

# Security - allow from anywhere for testing
allowed_ssh_sources = ["0.0.0.0/0"]

# Admin SSH keys (use your own or CI service account)
admin_ssh_keys = {}

# Containarium daemon
enable_containarium_daemon = false
containarium_version = "dev"
containarium_binary_url = ""

# Single server setup
enable_horizontal_scaling = false
jump_server_count = 1
enable_load_balancer = false

# Monitoring and backups
enable_monitoring = false
enable_disk_snapshots = false

# Region/Zone
region = "asia-east1"
zone = "asia-east1-a"

# Labels
labels = {
  environment = "e2e-test"
  managed_by  = "go-test"
  test_run    = "%d"
}
`, projectID, instanceName, time.Now().Unix())

	err := os.WriteFile(tfvarsPath, []byte(tfvarsContent), 0644)
	require.NoError(t, err, "Failed to write tfvars file")

	// Initialize Terraform
	t.Log("Running terraform init...")
	cmd := exec.CommandContext(ctx, "terraform", "init")
	cmd.Dir = workspace
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("terraform init failed: %v\nOutput: %s", err, output)
	}

	// Apply Terraform configuration
	t.Log("Running terraform apply...")
	cmd = exec.CommandContext(ctx, "terraform", "apply",
		"-var-file=e2e-test.tfvars",
		"-auto-approve",
	)
	cmd.Dir = workspace
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Logf("Terraform output:\n%s", output)
		t.Fatalf("terraform apply failed: %v", err)
	}

	t.Log("✓ Infrastructure deployed successfully")
}

// getTerraformOutputs extracts instance information from Terraform outputs
func getTerraformOutputs(t *testing.T, ctx context.Context, workspace string) (ip, name, zone string, err error) {
	t.Log("Getting Terraform outputs...")

	cmd := exec.CommandContext(ctx, "terraform", "output", "-json")
	cmd.Dir = workspace
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", "", fmt.Errorf("terraform output failed: %w\nOutput: %s", err, output)
	}

	// Parse JSON outputs
	var outputs map[string]struct {
		Value interface{} `json:"value"`
	}
	err = json.Unmarshal(output, &outputs)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse terraform outputs: %w", err)
	}

	// Extract IP
	if ipOutput, ok := outputs["jump_server_ip"]; ok {
		ip = fmt.Sprintf("%v", ipOutput.Value)
	}

	// Extract instance name
	if nameOutput, ok := outputs["instance_name"]; ok {
		name = fmt.Sprintf("%v", nameOutput.Value)
	}

	// Extract zone
	if zoneOutput, ok := outputs["zone"]; ok {
		zone = fmt.Sprintf("%v", zoneOutput.Value)
	}

	if ip == "" || name == "" || zone == "" {
		return "", "", "", fmt.Errorf("missing required outputs (ip=%s, name=%s, zone=%s)", ip, name, zone)
	}

	return ip, name, zone, nil
}

// destroyTerraform destroys the infrastructure
func destroyTerraform(t *testing.T, ctx context.Context, workspace string) {
	t.Log("Running terraform destroy...")

	cmd := exec.CommandContext(ctx, "terraform", "destroy",
		"-var-file=e2e-test.tfvars",
		"-auto-approve",
	)
	cmd.Dir = workspace
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Warning: terraform destroy failed: %v\nOutput: %s", err, output)
	} else {
		t.Log("✓ Infrastructure destroyed")
	}
}

// waitForInstanceReadyTF waits for instance to be ready using gcloud
func waitForInstanceReadyTF(t *testing.T, ctx context.Context, instanceName, zone string) {
	t.Log("Waiting for instance to be ready...")

	// Wait for SSH to be ready
	maxAttempts := 60
	for i := 0; i < maxAttempts; i++ {
		cmd := exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
			"--zone="+zone,
			"--command=echo ready",
			"--ssh-flag=-o ConnectTimeout=5",
		)
		output, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(output), "ready") {
			t.Log("✓ SSH is ready")
			break
		}
		if i == maxAttempts-1 {
			t.Fatalf("SSH not ready after %d attempts", maxAttempts)
		}
		t.Logf("Attempt %d/%d: Waiting for SSH...", i+1, maxAttempts)
		time.Sleep(10 * time.Second)
	}

	// Wait for startup script to complete
	t.Log("Waiting for startup script to complete...")
	for i := 0; i < 120; i++ {
		cmd := exec.CommandContext(ctx, "gcloud", "compute", "instances",
			"get-serial-port-output", instanceName,
			"--zone="+zone,
		)
		output, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(output), "Containarium Setup Complete") {
			t.Log("✓ Startup script completed")
			return
		}
		if i%10 == 0 {
			t.Logf("Attempt %d/120: Waiting for startup...", i+1)
		}
		time.Sleep(5 * time.Second)
	}

	t.Fatal("Startup script did not complete in expected time")
}

// verifyZFSSetupTF verifies ZFS is properly configured
func verifyZFSSetupTF(t *testing.T, ctx context.Context, instanceName, zone string) {
	t.Log("Verifying ZFS setup...")

	// Check ZFS pool
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--zone="+zone,
		"--command=sudo zpool status incus-pool",
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to check ZFS pool: %s", output)
	assert.Contains(t, string(output), "ONLINE", "ZFS pool should be ONLINE")
	t.Log("✓ ZFS pool is ONLINE")

	// Check Incus storage driver
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--zone="+zone,
		"--command=sudo incus storage show default",
	)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to check Incus storage: %s", output)
	assert.Contains(t, string(output), "driver: zfs", "Incus should use ZFS driver")
	t.Log("✓ Incus using ZFS storage driver")

	// Verify ZFS properties
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--zone="+zone,
		"--command=sudo zfs get compression incus-pool",
	)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to check ZFS compression: %s", output)
	assert.Contains(t, string(output), "lz4", "ZFS should have lz4 compression")
	t.Log("✓ ZFS compression enabled (lz4)")
}

// createContainerWithTestDataTF creates container and writes test data
func createContainerWithTestDataTF(t *testing.T, ctx context.Context, instanceName, zone string) (string, string) {
	t.Log("Creating container with test data...")

	containerName := "persistence-test"
	testData := fmt.Sprintf("PERSISTENCE_TEST_%d_%x", time.Now().Unix(), time.Now().UnixNano())

	// Create container with quota
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--zone="+zone,
		"--command=sudo incus launch images:ubuntu/24.04 "+containerName+" -d root,size=20GB",
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create container: %s", output)
	t.Log("✓ Container created with 20GB quota")

	// Wait for container to be ready
	time.Sleep(15 * time.Second)

	// Write test data
	sshCmd := fmt.Sprintf("echo '%s' | sudo incus exec %s -- tee /root/test-data.txt", testData, containerName)
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--zone="+zone,
		"--command="+sshCmd,
	)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to write test data: %s", output)
	t.Log("✓ Test data written")

	// Calculate checksum
	checksum := fmt.Sprintf("%x", md5.Sum([]byte(testData+"\n")))
	t.Logf("Test data checksum: %s", checksum)

	// Verify quota is enforced
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--zone="+zone,
		"--command=sudo incus exec "+containerName+" -- df -h /",
	)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to check quota: %s", output)

	// Container should see ~20GB, not the full disk
	outputStr := string(output)
	assert.Contains(t, outputStr, "20G", "Container should see 20GB quota")
	t.Logf("Container disk quota verified:\n%s", outputStr)

	return testData, checksum
}

// rebootInstanceTF reboots the instance
func rebootInstanceTF(t *testing.T, ctx context.Context, instanceName, zone string) {
	t.Log("Rebooting instance...")

	// Stop instance
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "instances", "stop", instanceName,
		"--zone="+zone,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to stop instance: %s", output)
	t.Log("✓ Instance stopped")

	// Wait a bit
	time.Sleep(10 * time.Second)

	// Start instance
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "instances", "start", instanceName,
		"--zone="+zone,
	)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to start instance: %s", output)
	t.Log("✓ Instance started")
}

// verifyDataPersistedTF verifies data survived the reboot
func verifyDataPersistedTF(t *testing.T, ctx context.Context, instanceName, zone, expectedData, expectedChecksum string) {
	t.Log("Verifying data persisted after reboot...")

	containerName := "persistence-test"

	// Check container still exists
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--zone="+zone,
		"--command=sudo incus list "+containerName,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to list container: %s", output)
	assert.Contains(t, string(output), containerName, "Container should still exist")
	t.Log("✓ Container still exists after reboot")

	// Read data
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--zone="+zone,
		"--command=sudo incus exec "+containerName+" -- cat /root/test-data.txt",
	)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to read test data: %s", output)

	actualData := strings.TrimSpace(string(output))
	actualChecksum := fmt.Sprintf("%x", md5.Sum([]byte(actualData+"\n")))

	t.Logf("Expected data: %s", expectedData)
	t.Logf("Actual data:   %s", actualData)
	t.Logf("Expected checksum: %s", expectedChecksum)
	t.Logf("Actual checksum:   %s", actualChecksum)

	assert.Equal(t, expectedData, actualData, "Data should match exactly")
	assert.Equal(t, expectedChecksum, actualChecksum, "Checksum should match")

	t.Log("✅ Data persisted correctly after reboot!")
}

// Helper functions
