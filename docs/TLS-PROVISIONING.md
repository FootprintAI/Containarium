# Automatic TLS Certificate Provisioning

Containarium automatically provisions TLS certificates for domains when adding proxy routes. This ensures all routes have HTTPS enabled without manual certificate management.

## Overview

When you add a new proxy route (e.g., `myapp.example.com`), Containarium:

1. Adds the reverse proxy route to Caddy
2. Adds the domain to Caddy's TLS automation policy
3. Caddy automatically obtains a certificate via ACME (Let's Encrypt or ZeroSSL)

## How It Works

### Adding a Route with TLS

When you add a route via the API or Web UI:

```bash
# Via CLI (future)
containarium route add myapp.example.com --target 10.0.3.100:8080

# Via REST API
curl -X POST https://<cluster>.example.com/v1/network/routes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "myapp.example.com",
    "target_ip": "10.0.3.100",
    "target_port": 8080
  }'
```

Containarium will:

1. **Add the route** to Caddy's HTTP server configuration
2. **Provision TLS** by adding the domain to Caddy's automation policy

### TLS Automation Policy

Caddy uses an automation policy to manage certificates. When a domain is added, Containarium updates the policy:

```json
{
  "subjects": ["myapp.example.com", "other.example.com"],
  "issuers": [
    {"module": "acme"},
    {"module": "acme", "ca": "https://acme.zerossl.com/v2/DV90"}
  ]
}
```

This configures:
- **Let's Encrypt** as the primary certificate authority
- **ZeroSSL** as a fallback CA

## Certificate Issuance Process

1. **Domain Added**: Route is created, domain added to TLS policy
2. **ACME Challenge**: Caddy performs HTTP-01 or TLS-ALPN-01 challenge
3. **Certificate Issued**: Certificate is obtained and stored
4. **Auto-Renewal**: Caddy automatically renews before expiration

## Requirements

### DNS Configuration

The domain must resolve to the Caddy server's IP address:

```bash
# Example: point myapp.example.com to your server
myapp.example.com.  IN  A  35.xxx.xxx.xxx
```

### Firewall Rules

Ports 80 and 443 must be accessible for ACME challenges:

```bash
# GCP firewall rule example
gcloud compute firewall-rules create allow-http-https \
  --allow tcp:80,tcp:443 \
  --target-tags containarium
```

### Caddy Admin API

The Caddy Admin API must be accessible (default: `http://localhost:2019`):

```bash
# Verify Caddy Admin API is running
curl http://localhost:2019/config/
```

## Web UI Integration

The Network tab in the Web UI provides route management with automatic TLS:

1. Navigate to **Network** tab
2. Click **Add Route**
3. Select or enter a domain (e.g., `myapp.example.com`)
4. Select target container and port
5. Click **Add Route**

The certificate is provisioned automatically in the background.

## Wildcard Certificates

For wildcard certificates (e.g., `*.example.com`), use DNS-01 challenge:

1. Configure Caddy with a DNS provider plugin (Cloudflare, Route53, etc.)
2. Set up DNS API credentials
3. Configure the Caddyfile with DNS challenge:

```caddyfile
*.example.com {
    tls {
        dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    }
    
    @subdomain host *.example.com
    handle @subdomain {
        reverse_proxy {http.request.host.labels.2}:8080
    }
}
```

See [CADDY-SETUP.md](CADDY-SETUP.md) for detailed DNS provider configuration.

## Troubleshooting

### Certificate Not Issued

Check Caddy logs for ACME errors:

```bash
# If Caddy runs in a container
incus exec containarium-core-caddy -- journalctl -u caddy -f

# Or check Caddy's stderr
incus exec containarium-core-caddy -- tail -f /var/log/caddy/error.log
```

Common issues:
- DNS not pointing to server
- Ports 80/443 blocked
- Rate limits (Let's Encrypt limits to 50 certs/domain/week)

### TLS Policy Not Updated

Verify the TLS automation policy:

```bash
curl -s http://localhost:2019/config/apps/tls/automation/policies | jq
```

### Certificate Already Exists

If a domain already has a certificate (e.g., wildcard), the provisioning gracefully skips:

```
Warning: Failed to provision TLS for myapp.example.com: domain already in policy
```

This is expected behavior - the existing certificate will be used.

## API Reference

### ProvisionTLS Method

The `ProxyManager.ProvisionTLS(domain string)` method:

```go
// ProvisionTLS provisions a TLS certificate for the given domain
// via Caddy's TLS automation policy with ACME issuers
func (p *ProxyManager) ProvisionTLS(domain string) error
```

**Parameters:**
- `domain`: Full domain name (e.g., `myapp.example.com`)

**Returns:**
- `nil` on success
- Error if TLS provisioning fails (route is still added)

### Caddy Admin API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/config/apps/tls/automation/policies` | GET | Get existing TLS policies |
| `/config/apps/tls/automation/policies` | PATCH | Update policy with new domain |
| `/config/apps/tls/automation/policies` | POST | Create new policy if none exists |

## Security Considerations

1. **Certificate Storage**: Certificates are stored in Caddy's data directory
2. **Private Keys**: Never leave the server; managed entirely by Caddy
3. **ACME Account**: Automatically created and managed by Caddy
4. **Renewal**: Automatic, no manual intervention required
