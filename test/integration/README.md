# Containarium Integration Tests

This directory contains integration tests for Containarium, focusing on critical production scenarios like storage quotas and data persistence across instance reboots.

## Test Types

### 1. Storage Tests (`storage_test.go`)
- Container creation with disk quotas
- Quota enforcement verification
- Multi-container isolation
- ZFS compression

### 2. E2E Reboot Tests
- **Terraform-based** (`e2e_terraform_test.go`) - **RECOMMENDED**
  - Reuses production Terraform configuration
  - Full infrastructure lifecycle testing
  - Automated setup and teardown

- **gcloud-based** (`e2e_reboot_test.go`) - Alternative
  - Uses raw gcloud commands
  - More flexible but requires manual sync with Terraform

**See [TERRAFORM-E2E.md](TERRAFORM-E2E.md) for Terraform approach details.**

## Overview

Integration tests verify that all components work together correctly in a real environment:

- **Storage Tests**: Verify ZFS quota enforcement and compression
- **Persistence Tests**: Verify data survives instance reboots
- **Multi-tenant Tests**: Verify container isolation

## Prerequisites

### 1. Running Containarium Instance

You need a running Containarium instance to test against:

```bash
# Deploy via Terraform
cd terraform/gce
terraform apply

# Get instance IP
export CONTAINARIUM_SERVER=$(terraform output -raw jump_server_ip):50051
```

### 2. Build the Binary

```bash
# Build for your local platform
make build

# Or for Linux (if deploying to GCE)
make build-linux
```

### 3. Install Test Dependencies

```bash
go get github.com/stretchr/testify
go mod tidy
```

### 4. Setup Certificates (if using mTLS)

```bash
# Download client certificates from server
mkdir -p ~/.config/containarium/certs
gcloud compute scp --recurse hsinhoyeh@containarium-test:/etc/containarium/certs/client* ~/.config/containarium/certs/
gcloud compute scp hsinhoyeh@containarium-test:/etc/containarium/certs/ca.crt ~/.config/containarium/certs/
```

## Running Tests

### Quick Test (No Reboot)

```bash
# Run storage quota tests
make test-integration

# Or directly with go test
cd test/integration
CONTAINARIUM_SERVER=35.229.246.67:50051 go test -v -timeout 10m
```

### Full Reboot Persistence Test

The reboot test requires multiple steps:

#### Option 1: Automated Script (Recommended)

```bash
# Run full automated test
CONTAINARIUM_PROJECT=your-gcp-project ./scripts/reboot-persistence-test.sh full

# Or step-by-step
./scripts/reboot-persistence-test.sh prepare   # Create test data
./scripts/reboot-persistence-test.sh reboot    # Reboot instance
./scripts/reboot-persistence-test.sh verify    # Verify after reboot
./scripts/reboot-persistence-test.sh cleanup   # Clean up
```

#### Option 2: Manual Testing

**Step 1: Prepare**
```bash
CONTAINARIUM_SERVER=35.229.246.67:50051 \
CONTAINARIUM_INSECURE=true \
go test -v -run TestStoragePersistence -timeout 10m
```

This will create a test container and save state to `/tmp/containarium-reboot-test-state.json`.

**Step 2: Write Test Data**

The test will output instructions like:
```bash
sudo incus exec test-persist-1234567890-container -- \
  bash -c 'echo "TEST_DATA_abc123" > /home/test-persist-1234567890/test-data.txt'
```

Execute this command on the jump server.

**Step 3: Reboot**
```bash
# Via gcloud
gcloud compute instances stop containarium-test --zone=asia-east1-a
gcloud compute instances start containarium-test --zone=asia-east1-a

# Or SSH to server and run
sudo reboot
```

**Step 4: Verify After Reboot**
```bash
# Wait for instance to come back up, then run test again
CONTAINARIUM_SERVER=35.229.246.67:50051 \
CONTAINARIUM_INSECURE=true \
go test -v -run TestStoragePersistence -timeout 10m
```

The test will detect the state file and verify data persistence.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONTAINARIUM_SERVER` | Server address with port | `localhost:50051` |
| `CONTAINARIUM_INSECURE` | Use insecure connection (no mTLS) | `false` |
| `CONTAINARIUM_CERTS_DIR` | Directory with mTLS certificates | `~/.config/containarium/certs` |
| `CONTAINARIUM_PROJECT` | GCP project (for reboot test) | - |
| `CONTAINARIUM_INSTANCE` | GCE instance name | `containarium-test` |
| `CONTAINARIUM_ZONE` | GCE zone | `asia-east1-a` |

## Test Coverage

### Storage Quota Tests

1. **CreateContainerWithQuota**: Creates container with specific disk quota
2. **QuotaEnforcementPreventsExceed**: Verifies quota prevents exceeding disk limits
3. **MultipleContainersIsolation**: Verifies quotas are isolated between containers
4. **CompressionEnabled**: Verifies ZFS compression is active

### Persistence Tests

1. **PrepareDataForRebootTest**: Creates test data before reboot
2. **DataPersistenceAfterReboot**: Verifies data survived reboot

## Expected Results

### ✅ Passing Tests

```
=== RUN   TestStorageQuotaEnforcement
=== RUN   TestStorageQuotaEnforcement/CreateContainerWithQuota
    storage_test.go:82: ✓ Container created successfully: test-quota-1234567890-container (10.0.3.123)
=== RUN   TestStorageQuotaEnforcement/QuotaEnforcementPreventsExceed
    storage_test.go:128: ✓ Container created with quota enforcement enabled
=== RUN   TestStorageQuotaEnforcement/MultipleContainersIsolation
    storage_test.go:162: ✓ Multiple containers created with isolated quotas
    storage_test.go:163:   - test-alice-1234567890: 10GB quota
    storage_test.go:164:   - test-bob-1234567890: 15GB quota
=== RUN   TestStorageQuotaEnforcement/CompressionEnabled
    storage_test.go:181: ✓ Container created (compression verification requires ZFS access)
--- PASS: TestStorageQuotaEnforcement (45.23s)

=== RUN   TestStoragePersistence
    storage_test.go:234: ✓ Test container created and state saved
    storage_test.go:240: REBOOT TEST PREPARATION COMPLETE
--- PASS: TestStoragePersistence (32.15s)

PASS
ok      github.com/footprintai/containarium/test/integration    77.384s
```

### ❌ Failing Tests (Quota Not Enforced)

If using `dir` storage driver instead of `zfs`, quota tests will fail:

```
=== RUN   TestStorageQuotaEnforcement/QuotaEnforcementPreventsExceed
    storage_test.go:125: Container can use entire disk despite quota!
    storage_test.go:126: ✗ Quota enforcement FAILED
--- FAIL: TestStorageQuotaEnforcement/QuotaEnforcementPreventsExceed (12.45s)
```

This indicates ZFS is not properly configured.

## Troubleshooting

### Test Timeout

```bash
# Increase timeout for slow networks
go test -v -timeout 20m
```

### Connection Refused

```bash
# Check daemon is running
ssh hsinhoyeh@$SERVER_IP "sudo systemctl status containarium"

# Check firewall allows port 50051
gcloud compute firewall-rules list --filter="name:containarium"
```

### Container Creation Fails

```bash
# Check Incus is running
ssh hsinhoyeh@$SERVER_IP "sudo incus list"

# Check ZFS pool
ssh hsinhoyeh@$SERVER_IP "sudo zpool status"
```

### Reboot Test State Not Found

```bash
# Check state file exists
ls -la /tmp/containarium-reboot-test-state.json

# View state
cat /tmp/containarium-reboot-test-state.json
```

### Permission Denied (Certificates)

```bash
# Ensure certificates are readable
chmod 644 ~/.config/containarium/certs/*

# Or use insecure mode for testing
export CONTAINARIUM_INSECURE=true
```

## Advanced Usage

### Running Specific Tests

```bash
# Only quota tests
go test -v -run TestStorageQuotaEnforcement

# Only persistence tests
go test -v -run TestStoragePersistence

# Specific sub-test
go test -v -run TestStorageQuotaEnforcement/CreateContainerWithQuota
```

### Parallel Test Execution

```bash
# Run tests in parallel (careful with resource limits)
go test -v -parallel 4
```

### Generate Test Report

```bash
# With coverage
go test -v -coverprofile=coverage.out
go tool cover -html=coverage.out

# With JSON output
go test -v -json | tee test-results.json
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Deploy test instance
        env:
          GCP_SA_KEY: ${{ secrets.GCP_SA_KEY }}
        run: |
          cd terraform/gce
          terraform init
          terraform apply -auto-approve

      - name: Run integration tests
        env:
          CONTAINARIUM_SERVER: ${{ steps.deploy.outputs.server_ip }}:50051
          CONTAINARIUM_INSECURE: true
        run: make test-integration

      - name: Cleanup
        if: always()
        run: |
          cd terraform/gce
          terraform destroy -auto-approve
```

## Writing New Integration Tests

### Test Structure

```go
func TestNewFeature(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }

    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    defer cancel()

    serverAddr := getServerAddr(t)
    grpcClient := createGRPCClient(t, serverAddr)
    defer grpcClient.Close()

    t.Run("SubTest1", func(t *testing.T) {
        // Test implementation
    })
}
```

### Best Practices

1. **Always cleanup**: Use `defer` to cleanup test resources
2. **Use unique names**: Add timestamps to avoid conflicts
3. **Check for Short mode**: Allow skipping with `-short` flag
4. **Use subtests**: Organize related tests with `t.Run()`
5. **Set timeouts**: Use `context.WithTimeout()` to prevent hanging
6. **Log progress**: Use `t.Logf()` for debugging
7. **Graceful failure**: Don't panic, use `t.Fatal()` or `require.*`

### Example Test

```go
func TestContainerNetworking(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }

    serverAddr := getServerAddr(t)
    grpcClient := createGRPCClient(t, serverAddr)
    defer grpcClient.Close()

    username := fmt.Sprintf("test-net-%d", time.Now().Unix())

    // Create container
    container, err := grpcClient.CreateContainer(username, "images:ubuntu/24.04", 1, "1GB", "10GB", []string{}, false)
    require.NoError(t, err)
    defer grpcClient.DeleteContainer(username, true)

    // Test network connectivity
    assert.NotEmpty(t, container.IPAddress, "Container should have IP address")
    assert.Contains(t, container.IPAddress, "10.0.3.", "IP should be in container network range")

    t.Logf("✓ Container has IP: %s", container.IPAddress)
}
```

## Support

For issues with integration tests:

1. Check the [main README](../../README.md)
2. Review [deployment guide](../../docs/DEPLOYMENT-GUIDE.md)
3. Open an issue on GitHub with:
   - Test command used
   - Full test output
   - Environment details (OS, Go version, instance type)

## Related Documentation

- [Storage Test Plan](../../scripts/zfs_disk_quota_test_plan.md)
- [Migration Guide](../../scripts/migration_guide_dir_to_zfs.md)
- [Deployment Guide](../../docs/DEPLOYMENT-GUIDE.md)
