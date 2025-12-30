# Terraform Embed Package

This package provides embedded Terraform configuration files for use in Go tests and other applications.

## Purpose

Using `go:embed`, this package embeds the Terraform configuration from `terraform/gce/` into the compiled Go binary, making it easy to:

1. **Use in tests** - No need for relative paths or symlinks
2. **Portable** - Works regardless of working directory
3. **Version controlled** - Terraform config embedded at compile time
4. **Type safe** - Access files through Go constants and functions

## Usage

### In Tests

```go
package integration

import (
    tfembed "github.com/footprintai/containarium/terraform/embed"
)

func TestWithTerraform(t *testing.T) {
    // Create temporary workspace
    tmpDir, _ := os.MkdirTemp("", "test-*")
    defer os.RemoveAll(tmpDir)

    // Write all Terraform files to workspace
    for filename, content := range tfembed.AllFiles() {
        os.MkdirAll(filepath.Dir(filepath.Join(tmpDir, filename)), 0755)
        os.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0644)
    }

    // Now run terraform commands in tmpDir
    // ...
}
```

### Access Specific Files

```go
import tfembed "github.com/footprintai/containarium/terraform/embed"

// Get main.tf content
mainContent := tfembed.MainTF

// Get startup script
startupScript := tfembed.StartupSpotSH

// Get all .tf files
tfFiles := tfembed.TerraformFiles()

// Get all script files
scripts := tfembed.ScriptFiles()

// Get everything
allFiles := tfembed.AllFiles()
```

## Available Files

### Terraform Configuration

- `main.tf` - Main infrastructure configuration
- `spot-instance.tf` - Spot instance configuration
- `horizontal-scaling.tf` - Horizontal scaling setup
- `variables.tf` - Variable definitions
- `outputs.tf` - Output definitions
- `providers.tf` - Provider configuration

### Scripts

- `scripts/startup-spot.sh` - Spot instance startup script
- `scripts/startup.sh` - Regular instance startup script

## Functions

### `TerraformFiles() map[string]string`

Returns a map of all `.tf` files with filenames as keys and content as values.

```go
files := tfembed.TerraformFiles()
// files["main.tf"] = "resource \"google_compute_instance\" ..."
// files["variables.tf"] = "variable \"project_id\" ..."
```

### `ScriptFiles() map[string]string`

Returns a map of all script files with relative paths as keys.

```go
scripts := tfembed.ScriptFiles()
// scripts["scripts/startup-spot.sh"] = "#!/bin/bash\n..."
```

### `AllFiles() map[string]string`

Returns all files (Terraform + scripts) in a single map.

```go
all := tfembed.AllFiles()
// Includes both .tf files and scripts
```

## Benefits vs Alternatives

### ✅ go:embed (This Package)

```go
// Clean and portable
import tfembed "github.com/footprintai/containarium/terraform/embed"

files := tfembed.AllFiles()
// Works anywhere, no path issues
```

**Pros:**
- ✅ No relative paths needed
- ✅ Works regardless of working directory
- ✅ Embedded at compile time
- ✅ Type safe
- ✅ Version controlled

**Cons:**
- ⚠️ Must rebuild to pick up Terraform changes
- ⚠️ Slightly larger binary size (~50KB)

### ❌ Relative Paths

```go
// Fragile and error-prone
content, _ := os.ReadFile("../../terraform/gce/main.tf")
// Breaks if working directory changes
```

**Cons:**
- ❌ Breaks if working directory changes
- ❌ Different paths in tests vs production
- ❌ Hard to maintain

### ⚠️ Symlinks

```go
// Complex and platform-specific
os.Symlink("/abs/path/to/terraform/gce/main.tf", "/tmp/test/main.tf")
// Doesn't work on all platforms
```

**Cons:**
- ❌ Doesn't work on Windows
- ❌ Requires absolute paths
- ❌ More complex setup

## When Files are Embedded

Files are embedded **at compile time** when you run:

```bash
go build
go test
```

### Important Notes

1. **Changes require rebuild**: After modifying Terraform files, rebuild the binary or re-run tests
2. **Dev workflow**: In development, files are re-embedded on each `go test` run
3. **CI/CD**: Files are automatically embedded when building in CI/CD

### Example: Update Terraform and Test

```bash
# 1. Edit Terraform configuration
vim terraform/gce/main.tf

# 2. Run test (automatically re-embeds files)
cd test/integration
go test -run TestE2ERebootPersistenceTerraform

# Files are re-embedded on test run ✅
```

## Adding New Files

To add a new Terraform file to the embed package:

1. **Add to `terraform/gce/`**:
   ```bash
   vim terraform/gce/new-file.tf
   ```

2. **Add embed directive** to `terraform.go`:
   ```go
   //go:embed ../gce/new-file.tf
   var NewFileTF string
   ```

3. **Add to map** in `TerraformFiles()`:
   ```go
   func TerraformFiles() map[string]string {
       return map[string]string{
           // ...existing files...
           "new-file.tf": NewFileTF,
       }
   }
   ```

4. **Rebuild/test**:
   ```bash
   go test ./test/integration/
   ```

## Example: E2E Test

See `test/integration/e2e_terraform_test.go` for a complete example:

```go
func setupTerraformWorkspace(t *testing.T) string {
    tmpDir, _ := os.MkdirTemp("", "containarium-e2e-*")

    // Write all embedded files to workspace
    for filename, content := range tfembed.AllFiles() {
        destPath := filepath.Join(tmpDir, filename)
        os.MkdirAll(filepath.Dir(destPath), 0755)
        os.WriteFile(destPath, []byte(content), 0644)
    }

    return tmpDir
}
```

This creates a complete Terraform workspace from embedded files, ready for `terraform init` and `terraform apply`.

## Comparison

| Method | Portability | Maintenance | Type Safety |
|--------|-------------|-------------|-------------|
| **go:embed** | ✅ Excellent | ✅ Easy | ✅ Yes |
| Relative paths | ❌ Poor | ⚠️ Medium | ❌ No |
| Symlinks | ⚠️ Platform-specific | ❌ Complex | ❌ No |

## Summary

The `terraform/embed` package provides a **clean, portable, and type-safe** way to access Terraform configuration in Go code, especially useful for integration tests.

**Recommended for all tests that need Terraform configuration!**
