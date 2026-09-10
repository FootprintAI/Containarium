# REST API Quick Start Guide

## Overview

Containarium now supports both gRPC and REST APIs running simultaneously:
- **gRPC**: Port 50051 (mTLS authentication)
- **REST**: Port 8080 (JWT Bearer token authentication)

---

## Quick Start

### 1. Start the Daemon

#### Development (Auto-Generated Secret)
```bash
containariumd daemon --rest

# Output will show:
# ═══════════════════════════════════════════════════════════════
#   🔐 JWT Secret (Auto-Generated)
# ═══════════════════════════════════════════════════════════════
#   <your-random-secret>
# ...
```

#### Production (Environment Variable - Recommended)
```bash
# Set secret via environment
export CONTAINARIUM_JWT_SECRET="your-secure-secret-key"

# Start daemon
containariumd daemon --rest

# Secret is used but not printed - production ready!
```

#### Production (Secret File)
```bash
# Generate secret
openssl rand -base64 32 > /etc/containarium/jwt.secret
chmod 600 /etc/containarium/jwt.secret

# Start daemon
containariumd daemon --rest --jwt-secret-file /etc/containarium/jwt.secret
```

---

### 2. Generate API Token

```bash
# Get the JWT secret from daemon startup or config
TOKEN=$(containarium token generate \
  --username admin \
  --roles admin \
  --expiry 720h \
  --secret "your-jwt-secret" | grep "Token:" | awk '{print $2}')

# Or use secret file
TOKEN=$(containarium token generate \
  --username admin \
  --roles admin \
  --expiry 720h \
  --secret-file /etc/containarium/jwt.secret | grep "Token:" | awk '{print $2}')

# Set as environment variable
export TOKEN="$TOKEN"
```

---

### 3. Use the REST API

#### List Containers
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/containers
```

#### Create Container
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "resources": {
      "cpu": "4",
      "memory": "8GB",
      "disk": "100GB"
    },
    "ssh_keys": ["ssh-rsa AAAAB3... user@host"],
    "image": "ubuntu:24.04",
    "enable_docker": true
  }' \
  http://localhost:8080/v1/containers
```

#### Get Container Details
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/containers/alice
```

#### Start Container
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://localhost:8080/v1/containers/alice/start
```

#### Stop Container
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"timeout": 30, "force": false}' \
  http://localhost:8080/v1/containers/alice/stop
```

#### Add SSH Key
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "ssh_public_key": "ssh-rsa AAAAB3NzaC1... user@host"
  }' \
  http://localhost:8080/v1/containers/alice/ssh-keys
```

#### Get Metrics
```bash
# All containers
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/metrics

# Specific container
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/metrics/alice
```

#### Get System Info
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/system/info
```

#### Delete Container
```bash
curl -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/containers/alice?force=true
```

---

## Interactive API Exploration

### Swagger UI

Access the interactive Swagger UI at:
```
http://localhost:8080/swagger-ui/
```

Features:
- Try out API calls directly from your browser
- View request/response schemas
- See example payloads
- Test authentication

### OpenAPI Specification

Download or view the OpenAPI spec:
```bash
curl http://localhost:8080/swagger.json
```

Use this spec with tools like:
- Postman
- Insomnia
- OpenAPI Generator (client code generation)
- API testing frameworks

---

## JWT Secret Configuration Priority

The daemon checks for JWT secret in this order:

1. **`CONTAINARIUM_JWT_SECRET` environment variable** (highest priority)
   - Production use
   - Clean and secure
   - Not printed in logs

2. **`--jwt-secret-file` flag**
   - Production use
   - File-based configuration
   - Good for systemd services

3. **`--jwt-secret` flag**
   - Testing/development
   - Quick setup
   - Logged in startup

4. **Auto-generated** (lowest priority)
   - Development only
   - Printed prominently in logs
   - Changes on every restart
   - Tokens become invalid after restart

---

## Token Management

### Token Expiry Recommendations

| Use Case | Recommended Expiry |
|----------|-------------------|
| Admin users | 720h (30 days) |
| Regular users | 168h (7 days) |
| Service accounts | 8760h (1 year) |
| Development | 24h |
| CI/CD | Per-job (1-2h) |

### Generate Tokens

```bash
# Admin token (30 days)
containarium token generate \
  --username admin \
  --roles admin \
  --expiry 720h \
  --secret-file /etc/containarium/jwt.secret

# User token (7 days)
containarium token generate \
  --username developer \
  --roles user,developer \
  --expiry 168h \
  --secret-file /etc/containarium/jwt.secret

# Non-expiring service token (use with caution)
containarium token generate \
  --username ci-bot \
  --roles service \
  --expiry 0 \
  --secret-file /etc/containarium/jwt.secret
```

---

## Security Best Practices

### 1. Protect JWT Secret
```bash
# Generate strong secret
openssl rand -base64 32 > /etc/containarium/jwt.secret

# Secure permissions
chmod 600 /etc/containarium/jwt.secret
chown root:root /etc/containarium/jwt.secret
```

### 2. Use HTTPS in Production

Use a reverse proxy (nginx, caddy) with TLS:

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. Rotate Secrets Regularly

```bash
# Generate new secret
NEW_SECRET=$(openssl rand -base64 32)

# Update configuration
echo "$NEW_SECRET" > /etc/containarium/jwt.secret

# Restart daemon
systemctl restart containarium

# Regenerate all tokens with new secret
```

### 4. Token Security
- Store tokens securely (password manager, secrets vault)
- Never commit tokens to version control
- Use short expiry times when possible
- Revoke compromised tokens by rotating the JWT secret

---

## Troubleshooting

### Token Generation Fails
```bash
# Check if daemon is using the same secret
systemctl status containarium | grep "JWT"

# Verify secret file permissions
ls -l /etc/containarium/jwt.secret

# Should show: -rw------- (600)
```

### 401 Unauthorized Error
```bash
# Verify token is not expired
# Decode token (without verification):
echo "your.jwt.token" | cut -d'.' -f2 | base64 -d | jq .

# Check exp (expiry) field
```

### Connection Refused
```bash
# Check if REST API is enabled
ps aux | grep containarium | grep rest

# Check if port is listening
ss -tlnp | grep 8080

# Test without auth (should get 401)
curl -v http://localhost:8080/v1/containers
```

---

## API Endpoint Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/containers` | Create container |
| `GET` | `/v1/containers` | List containers |
| `GET` | `/v1/containers/{username}` | Get container |
| `DELETE` | `/v1/containers/{username}` | Delete container |
| `POST` | `/v1/containers/{username}/start` | Start container |
| `POST` | `/v1/containers/{username}/stop` | Stop container |
| `POST` | `/v1/containers/{username}/ssh-keys` | Add SSH key |
| `DELETE` | `/v1/containers/{username}/ssh-keys/{key}` | Remove SSH key |
| `GET` | `/v1/metrics` | Get all metrics |
| `GET` | `/v1/metrics/{username}` | Get container metrics |
| `GET` | `/v1/system/info` | System information |
| `GET` | `/health` | Health check (no auth) |
| `GET` | `/swagger.json` | OpenAPI spec (no auth) |
| `GET` | `/swagger-ui/` | Swagger UI (no auth) |

---

## Examples

### Complete Workflow

```bash
#!/bin/bash
set -e

# Configuration
SERVER="localhost:8080"
JWT_SECRET_FILE="/etc/containarium/jwt.secret"

# 1. Generate token
echo "Generating token..."
TOKEN=$(containarium token generate \
  --username admin \
  --roles admin \
  --expiry 24h \
  --secret-file "$JWT_SECRET_FILE" | grep "Token:" | awk '{print $2}')

echo "Token obtained"

# 2. Create container
echo "Creating container..."
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "resources": {"cpu": "2", "memory": "4GB", "disk": "50GB"},
    "image": "ubuntu:24.04"
  }' \
  "http://${SERVER}/v1/containers" | jq .

# 3. Wait for container to be ready
sleep 5

# 4. Get container info
echo "Getting container info..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://${SERVER}/v1/containers/testuser" | jq .

# 5. Add SSH key
echo "Adding SSH key..."
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "ssh_public_key": "'"$(cat ~/.ssh/id_rsa.pub)"'"
  }' \
  "http://${SERVER}/v1/containers/testuser/ssh-keys" | jq .

# 6. Get metrics
echo "Getting metrics..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://${SERVER}/v1/metrics/testuser" | jq .

echo "Setup complete!"
```

---

## Additional Resources

- **Full API Documentation**: See `/swagger-ui/` for interactive docs
- **CHANGELOG**: See `CHANGELOG.md` for version history
- **Examples**: See `examples/` directory for more samples
- **Issues**: Report bugs at https://github.com/footprintai/containarium/issues
