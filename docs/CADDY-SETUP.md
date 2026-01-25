# Caddy Setup for App Hosting

This guide covers setting up Caddy as a reverse proxy with automatic TLS for the Containarium app hosting feature.

## Overview

Containarium uses Caddy to:
- Route requests to deployed apps based on subdomain (e.g., `username-appname.containarium.dev`)
- Automatically provision and renew TLS certificates
- Provide HTTPS for all deployed applications

## Prerequisites

- A domain you control (e.g., `containarium.dev`)
- DNS provider with API access (Cloudflare, Route53, Google Cloud DNS, etc.)
- Server with ports 80 and 443 accessible

## Installation

### Option 1: Use the Setup Script (Recommended)

```bash
# For Cloudflare DNS
./scripts/setup-caddy.sh --dns cloudflare

# For AWS Route53
./scripts/setup-caddy.sh --dns route53

# For Google Cloud DNS
./scripts/setup-caddy.sh --dns googleclouddns
```

### Option 2: Manual Installation

1. Install xcaddy (Caddy build tool):
```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

2. Build Caddy with your DNS provider plugin:
```bash
# Cloudflare
xcaddy build --with github.com/caddy-dns/cloudflare --output /usr/local/bin/caddy

# AWS Route53
xcaddy build --with github.com/caddy-dns/route53 --output /usr/local/bin/caddy

# Google Cloud DNS
xcaddy build --with github.com/caddy-dns/googleclouddns --output /usr/local/bin/caddy

# DigitalOcean
xcaddy build --with github.com/caddy-dns/digitalocean --output /usr/local/bin/caddy
```

3. Verify installation:
```bash
caddy version
caddy list-modules | grep dns
```

## DNS Configuration

### Wildcard DNS Record

Add these DNS records to your domain:

| Type | Name | Value |
|------|------|-------|
| A | `*.containarium.dev` | `<your-server-ip>` |
| A | `containarium.dev` | `<your-server-ip>` |

### API Token Setup

#### Cloudflare

1. Go to Cloudflare Dashboard → My Profile → API Tokens
2. Create a token with:
   - Zone:DNS:Edit permission
   - Zone:Zone:Read permission
   - Include your zone (domain)
3. Save the token securely

#### AWS Route53

1. Create an IAM user or role with `route53:ChangeResourceRecordSets` and `route53:ListHostedZones` permissions
2. Generate access keys

#### Google Cloud DNS

1. Create a service account with DNS Administrator role
2. Download the JSON key file

## Caddy Configuration

### Caddyfile for Wildcard TLS

Create `/etc/caddy/Caddyfile`:

```caddyfile
{
    # Admin API for dynamic route configuration
    admin localhost:2019

    # Email for Let's Encrypt notifications
    email admin@containarium.dev
}

# Wildcard domain with DNS-01 challenge
*.containarium.dev {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }

    # Reverse proxy to apps
    # Routes are added dynamically via admin API
    reverse_proxy /* {
        # Placeholder - routes configured via API
        to localhost:9999
    }
}

# Main domain - API gateway
containarium.dev {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }

    reverse_proxy /* localhost:8080
}
```

### Environment Variables

Set the appropriate environment variable for your DNS provider:

```bash
# Cloudflare
export CF_API_TOKEN="your-cloudflare-api-token"

# AWS Route53
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"

# Google Cloud DNS
export GCP_PROJECT="your-project-id"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
```

### Systemd Service

Create `/etc/systemd/system/caddy.service`:

```ini
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
Environment=CF_API_TOKEN=your-token-here
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable caddy
sudo systemctl start caddy
```

## Dynamic Route Configuration

Containarium automatically configures routes when apps are deployed. The `ProxyManager` uses Caddy's admin API to add/remove routes.

### Manual Route Management

Add a route:
```bash
curl -X POST "http://localhost:2019/config/apps/http/servers/srv0/routes" \
  -H "Content-Type: application/json" \
  -d '{
    "@id": "username-appname",
    "match": [{"host": ["username-appname.containarium.dev"]}],
    "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.100.0.15:3000"}]}]
  }'
```

Remove a route:
```bash
curl -X DELETE "http://localhost:2019/id/username-appname"
```

List routes:
```bash
curl "http://localhost:2019/config/apps/http/servers/srv0/routes"
```

## Verification

### Check Certificate Status

```bash
# Check if certificate was issued
curl -vI https://username-appname.containarium.dev 2>&1 | grep -A5 "Server certificate"

# Check Caddy logs
journalctl -u caddy -f
```

### Test Routing

```bash
# Should return your app's response
curl https://username-appname.containarium.dev

# Test with specific host header (for local testing)
curl -H "Host: username-appname.containarium.dev" https://your-server-ip --insecure
```

## Troubleshooting

### Certificate Not Issued

1. Check DNS propagation:
   ```bash
   dig +short username-appname.containarium.dev
   ```

2. Check Caddy logs:
   ```bash
   journalctl -u caddy -n 100
   ```

3. Verify API token permissions

### Route Not Working

1. Check if route exists:
   ```bash
   curl http://localhost:2019/config/apps/http/servers/srv0/routes
   ```

2. Verify upstream is reachable:
   ```bash
   curl http://10.100.0.15:3000
   ```

### Admin API Not Accessible

Ensure Caddy is configured with admin API:
```caddyfile
{
    admin localhost:2019
}
```

## Security Considerations

1. **API Token Security**: Store DNS API tokens securely (use environment variables or secrets manager)
2. **Admin API**: Only bind to localhost (`admin localhost:2019`)
3. **Rate Limits**: Let's Encrypt has rate limits; use staging for testing:
   ```caddyfile
   tls {
       dns cloudflare {env.CF_API_TOKEN}
       ca https://acme-staging-v02.api.letsencrypt.org/directory
   }
   ```

## Integration with Containarium

When starting the Containarium daemon with app hosting:

```bash
containarium daemon \
  --app-hosting \
  --postgres "postgres://user:pass@localhost:5432/containarium" \
  --base-domain "containarium.dev" \
  --caddy-admin-url "http://localhost:2019"
```

The daemon will automatically:
1. Configure routes when apps are deployed
2. Remove routes when apps are deleted
3. Update routes when apps are redeployed
