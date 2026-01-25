# App Hosting Guide

Containarium provides a simple way to deploy and host web applications. Apps are deployed to user containers and are accessible via HTTPS subdomains.

## Quick Start

### 1. Deploy an Application

```bash
# Deploy from current directory
containarium app deploy myapp --source . --server <host:port> --user <username>

# Deploy with custom port
containarium app deploy myapp --source ./app --port 8080 --server <host:port> --user <username>

# Deploy with environment variables
containarium app deploy myapp --source . \
  --env "DATABASE_URL=postgres://..." \
  --env "API_KEY=secret" \
  --server <host:port> --user <username>
```

### 2. View Your Apps

```bash
# List all apps
containarium app list --server <host:port> --user <username>

# Get detailed info
containarium app get myapp --server <host:port> --user <username>
```

### 3. Manage Your App

```bash
# View logs
containarium app logs myapp --server <host:port> --user <username>

# Stop/start/restart
containarium app stop myapp --server <host:port> --user <username>
containarium app start myapp --server <host:port> --user <username>
containarium app restart myapp --server <host:port> --user <username>

# Delete
containarium app delete myapp --server <host:port> --user <username>
```

## How It Works

### Deployment Flow

1. **Package**: Your source code is packaged into a tarball (excluding `node_modules`, `.git`, etc.)
2. **Upload**: The tarball is uploaded to your container
3. **Detect**: If no Dockerfile is provided, the language is auto-detected
4. **Build**: A Docker image is built inside your container
5. **Run**: The Docker container is started with your app
6. **Route**: A reverse proxy route is configured for HTTPS access

### Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────────────┐
│             Caddy Reverse Proxy             │
│  (HTTPS termination, auto TLS via Let's    │
│   Encrypt)                                  │
└─────────────────────────────────────────────┘
    │
    │  myapp.containarium.dev → 10.0.3.x:3000
    │
    ▼
┌─────────────────────────────────────────────┐
│            User Container (LXC)             │
│  ┌───────────────────────────────────────┐  │
│  │     Docker Container (your app)       │  │
│  │     - Built from your source          │  │
│  │     - Running on port 3000            │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## Providing a Dockerfile

For full control over your build, provide a `Dockerfile` in your project root:

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

If you provide a Dockerfile, Containarium will use it as-is without auto-detection.

## Auto-Detection (Buildpacks)

If no Dockerfile is present, Containarium automatically detects your language and generates an appropriate Dockerfile. See [BUILDPACKS.md](BUILDPACKS.md) for details.

**Supported Languages:**
- Node.js (package.json)
- Python (requirements.txt, Pipfile, pyproject.toml)
- Go (go.mod)
- Rust (Cargo.toml)
- Ruby (Gemfile)
- PHP (composer.json)
- Static sites (index.html)

## Environment Variables

Pass environment variables during deployment:

```bash
containarium app deploy myapp --source . \
  --env "NODE_ENV=production" \
  --env "DATABASE_URL=postgres://user:pass@host:5432/db" \
  --env "SECRET_KEY=your-secret-key" \
  --server <host:port> --user <username>
```

Environment variables are securely passed to your Docker container at runtime.

## Custom Subdomains

By default, your app is accessible at `<username>-<appname>.containarium.dev`. You can customize this:

```bash
containarium app deploy myapp --source . \
  --subdomain my-custom-app \
  --server <host:port> --user <username>
```

Your app will be accessible at `my-custom-app.containarium.dev`.

## Ports

The default port is 3000. Specify a different port with `--port`:

```bash
containarium app deploy myapp --source . --port 8080 --server <host:port> --user <username>
```

Your app must listen on this port inside the container.

## Logs

View application logs:

```bash
# Last 100 lines (default)
containarium app logs myapp --server <host:port> --user <username>

# Last 500 lines
containarium app logs myapp --tail 500 --server <host:port> --user <username>
```

## App States

| State | Description |
|-------|-------------|
| UPLOADING | Source code is being uploaded |
| BUILDING | Docker image is being built |
| RUNNING | App is running and healthy |
| STOPPED | App was stopped by user |
| FAILED | Build or runtime failure |
| RESTARTING | App is being restarted |

## Troubleshooting

### Build Failed

Check the build logs:
```bash
containarium app logs myapp --server <host:port> --user <username>
```

Common causes:
- Missing dependencies in package.json/requirements.txt
- Syntax errors in Dockerfile
- Network issues during package installation

### App Not Accessible

1. Check app state: `containarium app get myapp ...`
2. Verify port matches your app's listening port
3. Check logs for startup errors

### App Crashes on Startup

1. Check logs for error messages
2. Verify all required environment variables are set
3. Ensure your app handles the PORT environment variable

## Best Practices

1. **Use .dockerignore**: Exclude unnecessary files from the build context
2. **Pin dependencies**: Lock your package versions for reproducible builds
3. **Health checks**: Implement a `/health` endpoint for monitoring
4. **Environment config**: Use environment variables for configuration
5. **Logging**: Write logs to stdout/stderr for easy access

## API Access

Apps can also be managed via the REST API:

```bash
# Deploy
curl -X POST https://<server>/v1/apps \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "app_name": "myapp", ...}'

# List
curl https://<server>/v1/apps \
  -H "Authorization: Bearer <token>"

# Get
curl https://<server>/v1/apps/alice/myapp \
  -H "Authorization: Bearer <token>"

# Stop
curl -X POST https://<server>/v1/apps/alice/myapp/stop \
  -H "Authorization: Bearer <token>"

# Delete
curl -X DELETE https://<server>/v1/apps/alice/myapp \
  -H "Authorization: Bearer <token>"
```

See the Swagger UI at `/swagger-ui/` for full API documentation.
