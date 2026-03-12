# Release Notes Template

Use this template when creating GitHub releases. Combine user-facing changes from CHANGELOG.md with detailed technical information.

---

## Example Release: v0.3.0 - REST API Support

### 🎉 Major Features

#### REST API via grpc-gateway
Added complete REST/HTTP API alongside existing gRPC for maximum flexibility and ease of integration.

**What's New:**
- 🌐 HTTP/JSON REST API on port 8080
- 🔐 JWT Bearer token authentication
- 📚 Interactive Swagger UI at `/swagger-ui/`
- 📄 OpenAPI specification at `/swagger.json`
- 🔧 Token generation CLI: `containarium token generate`
- ⚡ Dual-protocol support: gRPC + REST simultaneously
- 🔙 Fully backward compatible

**API Endpoints:**
- `POST /v1/containers` - Create container
- `GET /v1/containers` - List containers
- `GET /v1/containers/{username}` - Get container details
- `DELETE /v1/containers/{username}` - Delete container
- `POST /v1/containers/{username}/start` - Start container
- `POST /v1/containers/{username}/stop` - Stop container
- `POST /v1/containers/{username}/ssh-keys` - Add SSH key
- `DELETE /v1/containers/{username}/ssh-keys/{key}` - Remove SSH key
- `GET /v1/metrics` - Get metrics
- `GET /v1/system/info` - System information

**Quick Start:**
```bash
# Start daemon with REST API
containarium daemon --mtls --rest --jwt-secret your-secret

# Generate token
TOKEN=$(containarium token generate --username admin --secret your-secret)

# Use REST API
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/containers

# Access Swagger UI
open http://localhost:8080/swagger-ui/
```

---

### 📦 Pull Requests

This release includes the following pull requests:

- #XX - Add grpc-gateway REST API support (@contributor)
  - Commits: `abc1234`, `def5678`, `ghi9012`
- #XX - Implement JWT authentication (@contributor)
  - Commits: `jkl3456`, `mno7890`
- #XX - Add Swagger UI integration (@contributor)
  - Commits: `pqr1234`, `stu5678`
- #XX - Add token generation command (@contributor)
  - Commits: `vwx9012`, `yza3456`

---

### 🔧 Detailed Changes

#### Dependencies Added
- `github.com/grpc-ecosystem/grpc-gateway/v2@v2.27.4`
- `github.com/golang-jwt/jwt/v5@v5.2.1`
- `github.com/rs/cors@v1.11.0`
- `google.golang.org/genproto/googleapis/api`

#### New Files
- `internal/auth/token.go` - JWT token manager
- `internal/auth/middleware.go` - HTTP auth middleware
- `internal/gateway/gateway.go` - HTTP gateway server
- `internal/gateway/swagger.go` - Swagger UI serving
- `internal/server/dual_server.go` - Dual protocol server
- `internal/cmd/token.go` - Token generation command
- `scripts/download-swagger-ui.sh` - Swagger UI download script

#### Modified Files
- `proto/containarium/v1/service.proto` - Added HTTP annotations
- `buf.gen.yaml` - Added gateway and OpenAPI plugins
- `internal/cmd/daemon.go` - Added REST flags and dual server support
- `Makefile` - Added `swagger-ui` target

#### Bug Fixes
- Fixed proto package typo: `continariumv1` → `containariumv1`

---

### 🔐 Security Notes

- REST API uses JWT Bearer token authentication
- Tokens are configurable with custom expiry times
- CORS support with configurable allowed origins
- gRPC continues to use mTLS (unchanged)
- Token secrets should be stored securely (use `--jwt-secret-file` in production)

**Security Best Practices:**
```bash
# Generate strong JWT secret
openssl rand -base64 32 > /etc/containarium/jwt.secret
chmod 600 /etc/containarium/jwt.secret

# Start daemon with secret file
containarium daemon --mtls --rest --jwt-secret-file /etc/containarium/jwt.secret
```

---

### 📊 Statistics

- **New Files:** 8
- **Modified Files:** 5
- **Lines Added:** ~2,500
- **Lines Removed:** ~100
- **New API Endpoints:** 10
- **New CLI Commands:** 1 (`token generate`)

---

### 🙏 Contributors

Thanks to all contributors who made this release possible:
- @username1 - REST API implementation
- @username2 - Authentication system
- @username3 - Documentation

---

### 🚀 Upgrade Instructions

#### From v0.2.0 to v0.3.0

1. **Download new binary:**
   ```bash
   curl -LO https://github.com/footprintai/containarium/releases/download/v0.3.0/containarium-linux-amd64
   sudo install -m 755 containarium-linux-amd64 /usr/local/bin/containarium
   ```

2. **Generate JWT secret (for REST API):**
   ```bash
   openssl rand -base64 32 | sudo tee /etc/containarium/jwt.secret
   sudo chmod 600 /etc/containarium/jwt.secret
   ```

3. **Update daemon flags (optional - for REST API):**
   ```bash
   # Edit /etc/systemd/system/containarium.service
   ExecStart=/usr/local/bin/containarium daemon \
       --mtls \
       --rest \
       --jwt-secret-file /etc/containarium/jwt.secret

   sudo systemctl daemon-reload
   sudo systemctl restart containarium
   ```

4. **Verify installation:**
   ```bash
   containarium version
   curl http://localhost:8080/health  # If REST is enabled
   ```

**Note:** REST API is optional. If you don't add `--rest` flag, the daemon continues to work exactly as before (gRPC only).

---

### 🐛 Known Issues

None currently. Please report issues at: https://github.com/footprintai/containarium/issues

---

### 📚 Documentation

- [REST API Documentation](https://github.com/footprintai/containarium/blob/main/docs/REST-API.md)
- [CHANGELOG](https://github.com/footprintai/containarium/blob/main/CHANGELOG.md)
- [Full Documentation](https://github.com/footprintai/containarium/blob/main/README.md)

---

### 💾 Downloads

| Platform | Architecture | Download |
|----------|--------------|----------|
| Linux | amd64 | [containarium-linux-amd64](https://github.com/footprintai/containarium/releases/download/v0.3.0/containarium-linux-amd64) |
| macOS | amd64 | [containarium-darwin-amd64](https://github.com/footprintai/containarium/releases/download/v0.3.0/containarium-darwin-amd64) |
| macOS | arm64 | [containarium-darwin-arm64](https://github.com/footprintai/containarium/releases/download/v0.3.0/containarium-darwin-arm64) |

**Checksums:** See [checksums.txt](https://github.com/footprintai/containarium/releases/download/v0.3.0/checksums.txt)

---

### 🔗 Links

- **Full Changelog:** https://github.com/footprintai/containarium/compare/v0.2.0...v0.3.0
- **All Commits:** View the full list of commits in this release
- **Milestone:** https://github.com/footprintai/containarium/milestone/X
