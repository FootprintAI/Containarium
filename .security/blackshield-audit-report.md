# BlackShield Security Audit Report — `FootprintAI/Containarium`

- **Scanned Commit:** `12accc90f2481fb4a2ca48432c12c8f84d4ea09f`
- **Actionable Findings:** `8` (`1 Critical`, `7 High`, `2 Medium`, `8 Low`)
- **BlackShield Platform & Continuous Zero-Cost PR Protection:** [https://blackshield.chaplau.com](https://blackshield.chaplau.com)

## Detailed Findings & Remediation Guide

### 1. [CRITICAL] `db-conn-postgres` — PostgreSQL Connection String with Credentials

- **Category:** `secret`
- **Location:** `internal/cmd/daemon.go:192`
- **Details:** Potential hardcoded credential or secret detected in `internal/cmd/daemon.go:192` (rule `db-conn-postgres`). Raw value redacted (`***REDACTED***`) for safe disclosure.
- **Recommended Fix:** Revoke leaked credential immediately and rotate in secret manager.

### 2. [HIGH] `CKV_DOCKER_6` — CKV_DOCKER_6: SSH Port 22 Exposed in Container

- **Category:** `misconfiguration`
- **Location:** `images/agent-box/Dockerfile:66`
- **Details:** Containers should not expose SSH port 22; communicate via orchestrator or secure agents instead.
- **Recommended Fix:** Remove 'EXPOSE 22' and avoid running OpenSSH daemon in application containers.

### 3. [HIGH] `CKV_DOCKER_6` — CKV_DOCKER_6: SSH Port 22 Exposed in Container

- **Category:** `misconfiguration`
- **Location:** `images/sshpiper/Dockerfile:88`
- **Details:** Containers should not expose SSH port 22; communicate via orchestrator or secure agents instead.
- **Recommended Fix:** Remove 'EXPOSE 22' and avoid running OpenSSH daemon in application containers.

### 4. [HIGH] `database-connection-url` — Database Connection URL with Embedded Password Detected

- **Category:** `secret`
- **Location:** `internal/app/store.go:31`
- **Details:** Potential hardcoded credential or secret detected in `internal/app/store.go:31` (rule `database-connection-url`). Raw value redacted (`***REDACTED***`) for safe disclosure.
- **Recommended Fix:** Revoke leaked credential immediately and rotate in secret manager.

### 5. [HIGH] `sec-debug-enabled` — sec-debug-enabled: Debug Mode Enabled in Production Application

- **Category:** `sast`
- **Location:** `internal/cmd/app_deploy.go:50`
- **Details:** Running web frameworks with debug mode enabled leaks stack traces, environment variables, and source code. at internal/cmd/app_deploy.go:50
- **Recommended Fix:** Disable debug mode in production environments and load configuration via environment variables.

### 6. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `sidecars/otel-sidecar/Dockerfile:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 7. [HIGH] `CVE-2022-25883` — CVE-2022-25883 in semver@6.3.1

- **Category:** `vulnerability`
- **Location:** `web-ui/package-lock.json`
- **Affected Package:** `semver@6.3.1`
- **Details:** Regular Expression Denial of Service (ReDoS) in semver range parser.
- **Recommended Fix:** Upgrade `semver` to `7.5.2` or newer

### 8. [HIGH] `CVE-2024-39338` — CVE-2024-39338 in axios@1.7.0

- **Category:** `vulnerability`
- **Location:** `web-ui/package.json`
- **Affected Package:** `axios@1.7.0`
- **Details:** Server-Side Request Forgery (SSRF) bypass via absoluteURL leading slash handling in Axios.
- **Recommended Fix:** Upgrade `axios` to `1.7.4` or newer

