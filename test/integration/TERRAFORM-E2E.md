# E2E Testing with Terraform

## Overview

The Terraform-based E2E test (`e2e_terraform_test.go`) leverages the existing Terraform configuration in `terraform/gce/` to deploy infrastructure, providing better consistency and maintainability compared to using raw `gcloud` commands.

## Why Use Terraform for E2E Tests?

### ✅ Advantages

1. **Reuses Existing Configuration**
   - Uses the same `.tf` files as production deployment
   - One source of truth for infrastructure
   - Changes to Terraform automatically reflected in tests

2. **Better State Management**
   - Terraform tracks infrastructure state
   - Safer cleanup with dependency management
   - Can detect drift

3. **Easier Maintenance**
   - Modify infrastructure in one place (`.tf` files)
   - No duplicate infrastructure code
   - Consistent with production deployments

4. **More Reliable**
   - Terraform handles dependencies automatically
   - Built-in retry logic
   - Proper resource ordering

5. **Type Safety**
   - Terraform validates configuration
   - Catches errors before deployment
   - Clear variable definitions

### ⚠️ Comparison with gcloud Approach

| Aspect | Terraform | gcloud Commands |
|--------|-----------|-----------------|
| **Code Reuse** | ✅ Reuses terraform/gce/ | ❌ Duplicate infrastructure code |
| **Maintenance** | ✅ Single source of truth | ❌ Must update test and Terraform |
| **Dependencies** | ✅ Automatic ordering | ⚠️ Manual ordering required |
| **State Tracking** | ✅ Built-in state | ❌ No state tracking |
| **Cleanup** | ✅ Handles dependencies | ⚠️ Manual cleanup order |
| **Validation** | ✅ Type checking | ❌ Runtime errors only |

## How It Works

### Test Workflow

```
1. Create Temporary Workspace
   ├─ Symlink .tf files from terraform/gce/
   ├─ Symlink startup scripts
   └─ Generate e2e-test.tfvars

2. Deploy with Terraform
   ├─ terraform init
   ├─ terraform apply -var-file=e2e-test.tfvars
   └─ Wait for completion

3. Get Outputs
   ├─ terraform output -json
   ├─ Extract instance IP
   └─ Extract instance name

4. Run Tests
   ├─ Verify ZFS setup
   ├─ Create container with data
   ├─ Reboot instance (using gcloud)
   └─ Verify data persisted

5. Cleanup
   ├─ terraform destroy
   └─ Remove temporary workspace
```

### Workspace Structure

```
/tmp/containarium-e2e-12345/
├── main.tf                    (embedded via go:embed)
├── spot-instance.tf          (embedded via go:embed)
├── variables.tf              (embedded via go:embed)
├── outputs.tf                (embedded via go:embed)
├── scripts/
│   ├── startup-spot.sh       (embedded via go:embed)
│   └── startup.sh            (embedded via go:embed)
├── e2e-test.tfvars           (generated for test)
├── terraform.tfstate         (created by Terraform)
└── .terraform/               (Terraform cache)
```

**Note**: All Terraform files are embedded using `go:embed` via the `terraform/embed` package, making the test completely portable without needing relative paths or symlinks.

## Running the Test

### Quick Start

```bash
# Set your GCP project
export GCP_PROJECT=your-gcp-project-id

# Run E2E test with Terraform
make test-e2e
```

### Manual Execution

```bash
cd test/integration
export GCP_PROJECT=your-gcp-project-id
go test -v -run TestE2ERebootPersistenceTerraform -timeout 45m
```

### Custom Configuration

```bash
# Use different zone
export GCP_ZONE=us-central1-a

# Keep infrastructure after failure for debugging
export KEEP_INSTANCE=true

# Keep Terraform workspace after test
export KEEP_WORKSPACE=true

# Run test
make test-e2e
```

## Test Configuration

### Generated tfvars

The test automatically generates `e2e-test.tfvars` with:

```hcl
# E2E Test Configuration
project_id = "your-project"
instance_name = "containarium-e2e-1234567890"
machine_type = "e2-standard-2"
use_spot_instance = true
use_persistent_disk = true

boot_disk_size = 100
data_disk_size = 100

allowed_ssh_sources = ["0.0.0.0/0"]
admin_ssh_keys = {}

enable_containarium_daemon = false
enable_monitoring = false
enable_disk_snapshots = false

region = "asia-east1"
zone = "asia-east1-a"

labels = {
  environment = "e2e-test"
  managed_by  = "go-test"
  test_run    = "1234567890"
}
```

### Customization

To customize the test configuration:

1. **Modify Test Code**: Edit `setupTerraformWorkspace()` in `e2e_terraform_test.go`
2. **Override Variables**: Set environment variables before running test
3. **Update Terraform**: Changes to `terraform/gce/*.tf` automatically apply

## Expected Output

```
=== RUN   TestE2ERebootPersistenceTerraform
    e2e_terraform_test.go:32: Starting E2E reboot persistence test with Terraform...
    e2e_terraform_test.go:33:   Project: my-project
    e2e_terraform_test.go:34:   Workspace: /tmp/containarium-e2e-1234567890

=== RUN   TestE2ERebootPersistenceTerraform/DeployInfrastructure
    e2e_terraform_test.go:157: Deploying infrastructure with Terraform...
    e2e_terraform_test.go:191: Running terraform init...
    e2e_terraform_test.go:198: Running terraform apply...
    e2e_terraform_test.go:207: ✓ Infrastructure deployed successfully

=== RUN   TestE2ERebootPersistenceTerraform/GetInstanceInfo
    e2e_terraform_test.go:213: Getting Terraform outputs...
    e2e_terraform_test.go:72: Instance: containarium-e2e-1234567890 at IP: 35.229.246.67

=== RUN   TestE2ERebootPersistenceTerraform/WaitForInstanceReady
    e2e_terraform_test.go:282: Waiting for instance to be ready...
    e2e_terraform_test.go:295: ✓ SSH is ready
    e2e_terraform_test.go:310: ✓ Startup script completed

=== RUN   TestE2ERebootPersistenceTerraform/VerifyZFSSetup
    e2e_terraform_test.go:320: Verifying ZFS setup...
    e2e_terraform_test.go:329: ✓ ZFS pool is ONLINE
    e2e_terraform_test.go:339: ✓ Incus using ZFS storage driver
    e2e_terraform_test.go:348: ✓ ZFS compression enabled (lz4)

=== RUN   TestE2ERebootPersistenceTerraform/CreateContainerWithData
    e2e_terraform_test.go:353: Creating container with test data...
    e2e_terraform_test.go:365: ✓ Container created with 20GB quota
    e2e_terraform_test.go:377: ✓ Test data written
    e2e_terraform_test.go:381: Test data checksum: abc123def456...

=== RUN   TestE2ERebootPersistenceTerraform/RebootInstance
    e2e_terraform_test.go:405: Rebooting instance...
    e2e_terraform_test.go:414: ✓ Instance stopped
    e2e_terraform_test.go:424: ✓ Instance started

=== RUN   TestE2ERebootPersistenceTerraform/WaitAfterReboot
    e2e_terraform_test.go:92: Instance is back online after reboot

=== RUN   TestE2ERebootPersistenceTerraform/VerifyDataPersistence
    e2e_terraform_test.go:431: Verifying data persisted after reboot...
    e2e_terraform_test.go:441: ✓ Container still exists after reboot
    e2e_terraform_test.go:461: ✅ Data persisted correctly after reboot!

    e2e_terraform_test.go:103: ✅ E2E Reboot Persistence Test with Terraform PASSED!
    e2e_terraform_test.go:248: Running terraform destroy...
    e2e_terraform_test.go:257: ✓ Infrastructure destroyed

--- PASS: TestE2ERebootPersistenceTerraform (1624.34s)
PASS
```

## Terraform Outputs Used

The test relies on these Terraform outputs:

```hcl
# terraform/gce/outputs.tf
output "jump_server_ip" {
  description = "Public IP of the jump server"
  value       = google_compute_address.jump_server_ip.address
}

output "instance_name" {
  description = "Name of the instance"
  value       = google_compute_instance.jump_server_spot[0].name
}
```

## Debugging

### View Terraform Workspace

```bash
# If test fails, check the workspace
export KEEP_WORKSPACE=true
make test-e2e

# Workspace location will be printed:
# "Terraform workspace created at: /tmp/containarium-e2e-12345"

# Navigate and inspect
cd /tmp/containarium-e2e-12345
terraform show
terraform output
```

### Manual Terraform Operations

```bash
# Navigate to workspace
cd /tmp/containarium-e2e-12345

# View state
terraform show

# Get outputs
terraform output -json

# Manually destroy
terraform destroy -var-file=e2e-test.tfvars -auto-approve
```

### View Instance Logs

```bash
# Get instance name from test output
INSTANCE_NAME=containarium-e2e-1234567890

# View startup logs
gcloud compute instances get-serial-port-output $INSTANCE_NAME \
  --zone=asia-east1-a

# SSH to instance
gcloud compute ssh $INSTANCE_NAME --zone=asia-east1-a

# Check ZFS
sudo zpool status
sudo zfs list

# Check containers
sudo incus list
```

## Cleanup After Failed Tests

### Automatic Cleanup

By default, infrastructure is kept if test fails:

```bash
# Test output shows:
# "Test failed - keeping infrastructure for debugging"
# "To cleanup: cd /tmp/containarium-e2e-12345 && terraform destroy -auto-approve"

# Follow the instructions
cd /tmp/containarium-e2e-12345
terraform destroy -var-file=e2e-test.tfvars -auto-approve
```

### Force Cleanup

```bash
# Set to always cleanup
export KEEP_INSTANCE=false
make test-e2e

# Or manually destroy by instance name
gcloud compute instances delete containarium-e2e-1234567890 \
  --zone=asia-east1-a --quiet
```

## CI/CD Integration

### GitHub Actions

```yaml
name: E2E Test with Terraform

on:
  push:
    branches: [main]
  pull_request:

jobs:
  e2e-terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - uses: hashicorp/setup-terraform@v2
        with:
          terraform_version: '1.5.0'

      - uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Run E2E Test
        env:
          GCP_PROJECT: ${{ secrets.GCP_PROJECT }}
        run: make test-e2e
```

## Advantages Over gcloud Approach

### 1. Configuration Consistency

**Terraform Approach:**
```go
// Uses actual Terraform configuration
deployTerraform(t, ctx, workspace, projectID)
// Automatically gets:
// - Correct machine type
// - Proper disk configuration
// - Network settings
// - Firewall rules
// - All from terraform/gce/*.tf
```

**gcloud Approach:**
```go
// Must manually specify everything
cmd := exec.Command("gcloud", "compute", "instances", "create",
    "--machine-type=e2-standard-2",
    "--image-family=ubuntu-2404-lts-amd64",
    "--boot-disk-size=100GB",
    // ... many more flags
    // Risk of divergence from Terraform config
)
```

### 2. State Management

**Terraform:**
- Tracks what was created
- Handles dependencies
- Safe cleanup even if partially created

**gcloud:**
- No state tracking
- Manual cleanup order
- Risk of orphaned resources

### 3. Changes Propagate Automatically

**Terraform:**
```bash
# Update Terraform configuration
vim terraform/gce/main.tf

# Tests automatically use new configuration
make test-e2e
```

**gcloud:**
```bash
# Update Terraform configuration
vim terraform/gce/main.tf

# Must also update test code
vim test/integration/e2e_reboot_test.go

# Easy to forget - tests diverge from reality
```

## Limitations

1. **Terraform Required**: Must have Terraform installed
2. **Temp Workspace**: Creates temporary files (cleaned up after test)
3. **gcloud Still Used**: For instance operations (stop/start/ssh)
4. **Local State**: Each test run creates new state (no remote backend)

## Best Practices

1. **Always Run Cleanup**: Don't skip cleanup to avoid orphaned resources
2. **Use Labels**: Test adds labels for easy identification
3. **Check State**: If test hangs, check Terraform workspace
4. **Unique Names**: Instance names include timestamp to avoid conflicts
5. **Cost Control**: Set GCP budget alerts

## Cost Estimate

Same as gcloud approach: **~$0.05 per test run**

- Spot instance (e2-standard-2): ~$0.01-0.02 for 30 min
- Persistent disk (100GB): ~$0.02 for 30 min
- Network egress: < $0.01
- **Terraform overhead**: None (free)

## Migration Guide

### From gcloud to Terraform

Already using `TestE2ERebootPersistence`? Switch to Terraform version:

```bash
# Old way
make test-e2e-gcloud

# New way (recommended)
make test-e2e
```

Both tests validate the same functionality, but Terraform version:
- ✅ Uses production Terraform config
- ✅ Easier to maintain
- ✅ More reliable cleanup
- ✅ Better state management

## Summary

The Terraform-based E2E test provides:
- ✅ **Better maintainability**: Single source of truth
- ✅ **Consistency**: Tests use production config
- ✅ **Reliability**: Terraform state management
- ✅ **Automation**: Infrastructure as code

**Recommended for all E2E testing!**
