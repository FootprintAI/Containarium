package integration

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2ERebootPersistence is an end-to-end test that:
// 1. Creates a GCE instance with ZFS
// 2. Sets up firewall rules
// 3. Creates a guest container
// 4. Writes test data
// 5. Reboots the instance
// 6. Verifies data persists
func TestE2ERebootPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Check required environment variables
	projectID := os.Getenv("GCP_PROJECT")
	if projectID == "" {
		t.Skip("GCP_PROJECT not set, skipping E2E test")
	}

	zone := getEnv("GCP_ZONE", "asia-east1-a")
	instanceName := fmt.Sprintf("containarium-e2e-test-%d", time.Now().Unix())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	t.Logf("Starting E2E reboot persistence test...")
	t.Logf("  Project: %s", projectID)
	t.Logf("  Zone: %s", zone)
	t.Logf("  Instance: %s", instanceName)

	// Cleanup function
	defer func() {
		if !t.Failed() || os.Getenv("KEEP_INSTANCE") == "true" {
			// Only cleanup if test passed or KEEP_INSTANCE not set
			t.Log("Cleaning up test instance...")
			cleanupInstance(t, projectID, zone, instanceName)
		} else {
			t.Logf("Test failed - keeping instance %s for debugging", instanceName)
			t.Logf("To cleanup: gcloud compute instances delete %s --zone=%s --quiet", instanceName, zone)
		}
	}()

	// Step 1: Create instance
	t.Run("CreateInstance", func(t *testing.T) {
		createTestInstance(t, ctx, projectID, zone, instanceName)
	})

	// Step 2: Wait for instance to be ready
	instanceIP := ""
	t.Run("WaitForInstance", func(t *testing.T) {
		instanceIP = waitForInstanceReady(t, ctx, projectID, zone, instanceName)
		require.NotEmpty(t, instanceIP, "Instance IP should not be empty")
		t.Logf("Instance ready at IP: %s", instanceIP)
	})

	// Step 3: Verify ZFS setup
	t.Run("VerifyZFS", func(t *testing.T) {
		verifyZFSSetup(t, ctx, projectID, zone, instanceName)
	})

	// Step 4: Create container with test data
	testData := ""
	expectedChecksum := ""
	t.Run("CreateContainerWithData", func(t *testing.T) {
		testData, expectedChecksum = createContainerWithTestData(t, ctx, projectID, zone, instanceName)
		require.NotEmpty(t, testData, "Test data should not be empty")
		require.NotEmpty(t, expectedChecksum, "Checksum should not be empty")
		t.Logf("Test data written with checksum: %s", expectedChecksum)
	})

	// Step 5: Reboot instance
	t.Run("RebootInstance", func(t *testing.T) {
		rebootInstance(t, ctx, projectID, zone, instanceName)
	})

	// Step 6: Wait for instance to come back
	t.Run("WaitAfterReboot", func(t *testing.T) {
		waitForInstanceReady(t, ctx, projectID, zone, instanceName)
		t.Log("Instance is back online after reboot")
	})

	// Step 7: Verify data persisted
	t.Run("VerifyDataPersistence", func(t *testing.T) {
		verifyDataPersisted(t, ctx, projectID, zone, instanceName, testData, expectedChecksum)
	})

	t.Log("✅ E2E Reboot Persistence Test PASSED!")
}

// createTestInstance creates a GCE instance with ZFS configuration
func createTestInstance(t *testing.T, ctx context.Context, projectID, zone, instanceName string) {
	t.Log("Creating GCE instance with ZFS...")

	// Get the current directory to find startup script
	startupScript := "../../terraform/gce/scripts/startup-spot.sh"
	if _, err := os.Stat(startupScript); os.IsNotExist(err) {
		t.Fatalf("Startup script not found: %s", startupScript)
	}

	// Create instance using gcloud
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "instances", "create", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--machine-type=e2-standard-2",
		"--image-family=ubuntu-2404-lts-amd64",
		"--image-project=ubuntu-os-cloud",
		"--boot-disk-size=100GB",
		"--boot-disk-type=pd-balanced",
		"--metadata-from-file=startup-script="+startupScript,
		fmt.Sprintf("--metadata=incus_version=,admin_users=testuser,enable_monitoring=false,USE_PERSISTENT_DISK=true,containarium_version=dev,containarium_binary_url="),
		"--tags=containarium-server",
		"--provisioning-model=SPOT",
		"--instance-termination-action=STOP",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to create instance: %v\nOutput: %s", err, output)
	}

	// Create persistent disk
	diskName := instanceName + "-data"
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "disks", "create", diskName,
		"--project="+projectID,
		"--zone="+zone,
		"--size=100GB",
		"--type=pd-balanced",
	)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Logf("Warning: Failed to create persistent disk: %v\nOutput: %s", err, output)
	}

	// Attach disk
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "instances", "attach-disk", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--disk="+diskName,
		"--device-name=incus-data",
	)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Logf("Warning: Failed to attach disk: %v\nOutput: %s", err, output)
	}

	// Create firewall rules
	createFirewallRules(t, ctx, projectID)

	t.Log("✓ Instance created successfully")
}

// createFirewallRules creates necessary firewall rules
func createFirewallRules(t *testing.T, ctx context.Context, projectID string) {
	t.Log("Creating firewall rules...")

	// SSH rule
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "firewall-rules", "create",
		"containarium-e2e-ssh",
		"--project="+projectID,
		"--allow=tcp:22",
		"--target-tags=containarium-server",
		"--source-ranges=0.0.0.0/0",
	)
	output, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(output), "already exists") {
		t.Logf("Warning: Failed to create SSH firewall rule: %v\nOutput: %s", err, output)
	}

	// gRPC rule
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "firewall-rules", "create",
		"containarium-e2e-grpc",
		"--project="+projectID,
		"--allow=tcp:50051",
		"--target-tags=containarium-server",
		"--source-ranges=0.0.0.0/0",
	)
	output, err = cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(output), "already exists") {
		t.Logf("Warning: Failed to create gRPC firewall rule: %v\nOutput: %s", err, output)
	}

	t.Log("✓ Firewall rules created")
}

// waitForInstanceReady waits for the instance to be fully ready
func waitForInstanceReady(t *testing.T, ctx context.Context, projectID, zone, instanceName string) string {
	t.Log("Waiting for instance to be ready...")

	// Wait for instance to be RUNNING
	maxAttempts := 60
	for i := 0; i < maxAttempts; i++ {
		cmd := exec.CommandContext(ctx, "gcloud", "compute", "instances", "describe", instanceName,
			"--project="+projectID,
			"--zone="+zone,
			"--format=get(status)",
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("Attempt %d/%d: Instance not ready yet", i+1, maxAttempts)
			time.Sleep(10 * time.Second)
			continue
		}

		status := strings.TrimSpace(string(output))
		if status == "RUNNING" {
			break
		}

		t.Logf("Attempt %d/%d: Instance status: %s", i+1, maxAttempts, status)
		time.Sleep(10 * time.Second)
	}

	// Get instance IP
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "instances", "describe", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--format=get(networkInterfaces[0].accessConfigs[0].natIP)",
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to get instance IP")
	instanceIP := strings.TrimSpace(string(output))

	// Wait for SSH to be ready
	t.Log("Waiting for SSH to be ready...")
	for i := 0; i < 60; i++ {
		cmd := exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
			"--project="+projectID,
			"--zone="+zone,
			"--command=echo ready",
			"--ssh-flag=-o ConnectTimeout=5",
		)
		output, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(output), "ready") {
			t.Log("✓ SSH is ready")
			break
		}
		t.Logf("Attempt %d/60: Waiting for SSH...", i+1)
		time.Sleep(10 * time.Second)
	}

	// Wait for startup script to complete
	t.Log("Waiting for startup script to complete...")
	for i := 0; i < 120; i++ {
		cmd := exec.CommandContext(ctx, "gcloud", "compute", "instances", "get-serial-port-output", instanceName,
			"--project="+projectID,
			"--zone="+zone,
		)
		output, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(output), "Containarium Setup Complete") {
			t.Log("✓ Startup script completed")
			break
		}
		t.Logf("Attempt %d/120: Waiting for startup...", i+1)
		time.Sleep(5 * time.Second)
	}

	return instanceIP
}

// verifyZFSSetup verifies ZFS is properly configured
func verifyZFSSetup(t *testing.T, ctx context.Context, projectID, zone, instanceName string) {
	t.Log("Verifying ZFS setup...")

	// Check ZFS pool
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--command=sudo zpool status incus-pool",
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to check ZFS pool")
	assert.Contains(t, string(output), "ONLINE", "ZFS pool should be ONLINE")
	t.Log("✓ ZFS pool is ONLINE")

	// Check Incus storage driver
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--command=sudo incus storage show default",
	)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to check Incus storage")
	assert.Contains(t, string(output), "driver: zfs", "Incus should use ZFS driver")
	t.Log("✓ Incus using ZFS storage driver")
}

// createContainerWithTestData creates a container and writes test data
func createContainerWithTestData(t *testing.T, ctx context.Context, projectID, zone, instanceName string) (string, string) {
	t.Log("Creating container with test data...")

	containerName := "persistence-test"
	testData := fmt.Sprintf("PERSISTENCE_TEST_%d_%s", time.Now().Unix(), randHex(16))

	// Create container with quota
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--command=sudo incus launch images:ubuntu/24.04 "+containerName+" -d root,size=20GB",
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create container: %s", output)
	t.Log("✓ Container created")

	// Wait for container to be ready
	time.Sleep(15 * time.Second)

	// Write test data
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--command=echo '"+testData+"' | sudo incus exec "+containerName+" -- tee /root/test-data.txt",
	)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to write test data: %s", output)
	t.Log("✓ Test data written")

	// Calculate checksum
	checksum := fmt.Sprintf("%x", md5.Sum([]byte(testData+"\n")))
	t.Logf("Test data checksum: %s", checksum)

	// Verify quota
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--command=sudo incus exec "+containerName+" -- df -h /",
	)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to check quota")
	t.Logf("Container disk usage:\n%s", output)

	return testData, checksum
}

// rebootInstance reboots the instance
func rebootInstance(t *testing.T, ctx context.Context, projectID, zone, instanceName string) {
	t.Log("Rebooting instance...")

	// Stop instance
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "instances", "stop", instanceName,
		"--project="+projectID,
		"--zone="+zone,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to stop instance: %s", output)
	t.Log("✓ Instance stopped")

	// Wait a bit
	time.Sleep(10 * time.Second)

	// Start instance
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "instances", "start", instanceName,
		"--project="+projectID,
		"--zone="+zone,
	)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to start instance: %s", output)
	t.Log("✓ Instance started")
}

// verifyDataPersisted verifies the test data survived the reboot
func verifyDataPersisted(t *testing.T, ctx context.Context, projectID, zone, instanceName, expectedData, expectedChecksum string) {
	t.Log("Verifying data persisted after reboot...")

	containerName := "persistence-test"

	// Check container still exists
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--command=sudo incus list "+containerName,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to list container: %s", output)
	assert.Contains(t, string(output), containerName, "Container should still exist")
	t.Log("✓ Container still exists")

	// Read data
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--project="+projectID,
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

	assert.Equal(t, expectedData, actualData, "Data should match")
	assert.Equal(t, expectedChecksum, actualChecksum, "Checksum should match")

	t.Log("✅ Data persisted correctly after reboot!")
}

// cleanupInstance deletes the test instance and associated resources
func cleanupInstance(t *testing.T, projectID, zone, instanceName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Delete instance
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "instances", "delete", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--quiet",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("Warning: Failed to delete instance: %v\nOutput: %s", err, output)
	}

	// Delete disk
	diskName := instanceName + "-data"
	cmd = exec.CommandContext(ctx, "gcloud", "compute", "disks", "delete", diskName,
		"--project="+projectID,
		"--zone="+zone,
		"--quiet",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("Warning: Failed to delete disk: %v\nOutput: %s", err, output)
	}

	t.Log("✓ Cleanup complete")
}

// Helper functions

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func randHex(n int) string {
	return fmt.Sprintf("%x", time.Now().UnixNano())[:n]
}
