# End-to-End Reboot Persistence Test

## Overview

`e2e_reboot_test.go` is a comprehensive integration test that validates the entire reboot persistence workflow from infrastructure creation to data verification.

## What It Tests

The test performs the following steps automatically:

1. **Creates GCE Instance**: Deploys a spot instance with ZFS configuration
2. **Sets Up Persistent Disk**: Attaches 100GB persistent disk for container data
3. **Configures Firewall**: Creates SSH and gRPC firewall rules
4. **Waits for Startup**: Monitors instance until startup script completes
5. **Verifies ZFS**: Checks ZFS pool is created and Incus is using ZFS driver
6. **Creates Container**: Launches a container with 20GB disk quota
7. **Writes Test Data**: Creates unique test data with MD5 checksum
8. **Reboots Instance**: Stops and starts the instance (simulating reboot)
9. **Verifies Persistence**: Confirms container and data survived reboot
10. **Cleanup**: Deletes instance and resources (unless test failed)

## Prerequisites

1. **GCP Project**: Active GCP project with Compute Engine API enabled
2. **gcloud CLI**: Installed and authenticated (`gcloud auth login`)
3. **Go**: Version 1.21+ installed
4. **Dependencies**: Run `go mod tidy` to install test dependencies

## Running the Test

### Quick Start

```bash
# Set your GCP project
export GCP_PROJECT=your-gcp-project-id

# Run the E2E test
make test-e2e
```

### Manual Execution

```bash
# Set environment variables
export GCP_PROJECT=your-gcp-project-id
export GCP_ZONE=asia-east1-a  # Optional, defaults to asia-east1-a

# Run test
cd test/integration
go test -v -run TestE2ERebootPersistence -timeout 45m
```

### Advanced Options

```bash
# Keep instance after test failure for debugging
export KEEP_INSTANCE=true
make test-e2e

# Use different zone
export GCP_ZONE=us-central1-a
make test-e2e

# Run only this test (skip other integration tests)
cd test/integration
go test -v -run TestE2ERebootPersistence
```

## Expected Duration

- **Total Time**: 20-30 minutes
  - Instance creation: 2-3 minutes
  - Startup script: 2-3 minutes
  - Container creation: 1 minute
  - Reboot: 5-10 minutes
  - Verification: 1 minute
  - Cleanup: 2 minutes

## Test Output

### Successful Run

```
=== RUN   TestE2ERebootPersistence
    e2e_reboot_test.go:45: Starting E2E reboot persistence test...
    e2e_reboot_test.go:46:   Project: my-project
    e2e_reboot_test.go:47:   Zone: asia-east1-a
    e2e_reboot_test.go:48:   Instance: containarium-e2e-test-1234567890
=== RUN   TestE2ERebootPersistence/CreateInstance
    e2e_reboot_test.go:74: Creating GCE instance with ZFS...
    e2e_reboot_test.go:115: ✓ Instance created successfully
=== RUN   TestE2ERebootPersistence/WaitForInstance
    e2e_reboot_test.go:139: Waiting for instance to be ready...
    e2e_reboot_test.go:219: ✓ SSH is ready
    e2e_reboot_test.go:235: ✓ Startup script completed
    e2e_reboot_test.go:73: Instance ready at IP: 35.229.246.67
=== RUN   TestE2ERebootPersistence/VerifyZFS
    e2e_reboot_test.go:245: Verifying ZFS setup...
    e2e_reboot_test.go:255: ✓ ZFS pool is ONLINE
    e2e_reboot_test.go:265: ✓ Incus using ZFS storage driver
=== RUN   TestE2ERebootPersistence/CreateContainerWithData
    e2e_reboot_test.go:270: Creating container with test data...
    e2e_reboot_test.go:283: ✓ Container created
    e2e_reboot_test.go:293: ✓ Test data written
    e2e_reboot_test.go:296: Test data checksum: abc123def456...
    e2e_reboot_test.go:82: Test data written with checksum: abc123def456...
=== RUN   TestE2ERebootPersistence/RebootInstance
    e2e_reboot_test.go:314: Rebooting instance...
    e2e_reboot_test.go:321: ✓ Instance stopped
    e2e_reboot_test.go:332: ✓ Instance started
=== RUN   TestE2ERebootPersistence/WaitAfterReboot
    e2e_reboot_test.go:91: Instance is back online after reboot
=== RUN   TestE2ERebootPersistence/VerifyDataPersistence
    e2e_reboot_test.go:339: Verifying data persisted after reboot...
    e2e_reboot_test.go:350: ✓ Container still exists
    e2e_reboot_test.go:370: ✅ Data persisted correctly after reboot!
    e2e_reboot_test.go:103: ✅ E2E Reboot Persistence Test PASSED!
    e2e_reboot_test.go:391: ✓ Cleanup complete
--- PASS: TestE2ERebootPersistence (1534.23s)
PASS
ok      github.com/footprintai/containarium/test/integration    1534.234s
```

### Failed Run

If test fails, the instance is kept for debugging:

```
--- FAIL: TestE2ERebootPersistence (245.67s)
    e2e_reboot_test.go:59: Test failed - keeping instance containarium-e2e-test-1234567890 for debugging
    e2e_reboot_test.go:60: To cleanup: gcloud compute instances delete containarium-e2e-test-1234567890 --zone=asia-east1-a --quiet
```

## Debugging Failed Tests

### View Instance Logs

```bash
# Get serial console output (startup logs)
gcloud compute instances get-serial-port-output containarium-e2e-test-1234567890 \
  --zone=asia-east1-a

# SSH to instance
gcloud compute ssh containarium-e2e-test-1234567890 --zone=asia-east1-a

# Check ZFS status
gcloud compute ssh containarium-e2e-test-1234567890 --zone=asia-east1-a \
  --command='sudo zpool status'

# Check containers
gcloud compute ssh containarium-e2e-test-1234567890 --zone=asia-east1-a \
  --command='sudo incus list'
```

### Manual Cleanup

```bash
# Delete instance
gcloud compute instances delete containarium-e2e-test-1234567890 \
  --zone=asia-east1-a --quiet

# Delete persistent disk
gcloud compute disks delete containarium-e2e-test-1234567890-data \
  --zone=asia-east1-a --quiet

# Delete firewall rules (if needed)
gcloud compute firewall-rules delete containarium-e2e-ssh --quiet
gcloud compute firewall-rules delete containarium-e2e-grpc --quiet
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: E2E Reboot Test

on:
  push:
    branches: [main]
  pull_request:

jobs:
  e2e-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Run E2E Test
        env:
          GCP_PROJECT: ${{ secrets.GCP_PROJECT }}
        run: make test-e2e
```

## What Gets Verified

### Infrastructure
- ✅ GCE instance created with spot provisioning
- ✅ Persistent disk attached to instance
- ✅ Firewall rules allow SSH and gRPC access
- ✅ Startup script executes successfully

### ZFS Storage
- ✅ ZFS kernel module loaded
- ✅ ZFS pool created on persistent disk
- ✅ ZFS pool health is ONLINE
- ✅ Incus using ZFS storage driver (not `dir`)
- ✅ Compression enabled (lz4)

### Container
- ✅ Container created with disk quota (20GB)
- ✅ Quota is enforced (container sees 20GB, not full disk)
- ✅ Test data written successfully
- ✅ MD5 checksum calculated

### Persistence
- ✅ Instance survives stop/start cycle
- ✅ Container still exists after reboot
- ✅ Container is in RUNNING state
- ✅ Test data matches original data exactly
- ✅ MD5 checksum matches original checksum

## Cost Considerations

### Per Test Run
- **Spot Instance (e2-standard-2)**: ~$0.01-0.02 for 30 minutes
- **Persistent Disk (100GB)**: ~$0.02 for 30 minutes
- **Network Egress**: Minimal (< $0.01)
- **Total**: < $0.05 per test run

### Recommendations
- Run E2E test on PR merge, not on every commit
- Use spot instances (already configured)
- Cleanup always runs (unless test fails)
- Set budget alerts in GCP

## Limitations

1. **Requires GCP Access**: Test needs active GCP project and credentials
2. **Long Duration**: Takes 20-30 minutes to complete
3. **Network Dependent**: Requires internet access for GCP API calls
4. **Single Instance**: Only tests one instance at a time
5. **No Parallel Execution**: Multiple instances would conflict

## Troubleshooting

### "GCP_PROJECT not set"
```bash
export GCP_PROJECT=your-project-id
```

### "Permission Denied"
```bash
# Ensure you're authenticated
gcloud auth login
gcloud config set project your-project-id

# Check you have Compute Engine permissions
gcloud compute instances list
```

### "Startup script failed"
```bash
# View startup logs
gcloud compute instances get-serial-port-output INSTANCE_NAME --zone=ZONE

# Look for errors in ZFS setup or Incus initialization
```

### "Container not found after reboot"
```bash
# SSH to instance
gcloud compute ssh INSTANCE_NAME --zone=ZONE

# Check ZFS pool status
sudo zpool status

# Check if pool was imported
sudo zpool import

# Check Incus storage
sudo incus storage list
sudo incus list
```

## Related Documentation

- [Main Testing Guide](../../TESTING.md)
- [Integration Test README](README.md)
- [ZFS Test Plan](/tmp/zfs_disk_quota_test_plan.md)
- [Deployment Guide](../../docs/DEPLOYMENT-GUIDE.md)

## Support

For issues:
1. Check logs: `gcloud compute instances get-serial-port-output`
2. SSH to instance: `gcloud compute ssh`
3. Review test output for specific error messages
4. Open GitHub issue with logs and error details
