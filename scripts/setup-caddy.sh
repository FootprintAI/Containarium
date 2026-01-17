#!/bin/bash
#
# Setup Caddy with DNS provider plugin for wildcard TLS
#
# Usage:
#   ./setup-caddy.sh --dns cloudflare --domain containarium.dev --email admin@example.com
#   ./setup-caddy.sh --dns route53 --domain myplatform.io --email admin@example.com
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
DNS_PROVIDER=""
DOMAIN=""
EMAIL=""
CADDY_USER="caddy"
CADDY_BIN="/usr/local/bin/caddy"
CADDYFILE="/etc/caddy/Caddyfile"
INSTALL_DIR="/tmp/caddy-build"

# DNS provider to module mapping
declare -A DNS_MODULES=(
    ["cloudflare"]="github.com/caddy-dns/cloudflare"
    ["route53"]="github.com/caddy-dns/route53"
    ["googleclouddns"]="github.com/caddy-dns/googleclouddns"
    ["digitalocean"]="github.com/caddy-dns/digitalocean"
    ["azure"]="github.com/caddy-dns/azure"
    ["vultr"]="github.com/caddy-dns/vultr"
    ["duckdns"]="github.com/caddy-dns/duckdns"
    ["namecheap"]="github.com/caddy-dns/namecheap"
)

# DNS provider to environment variable mapping
declare -A DNS_ENV_VARS=(
    ["cloudflare"]="CF_API_TOKEN"
    ["route53"]="AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
    ["googleclouddns"]="GCP_PROJECT, GOOGLE_APPLICATION_CREDENTIALS"
    ["digitalocean"]="DO_AUTH_TOKEN"
    ["azure"]="AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET"
    ["vultr"]="VULTR_API_KEY"
    ["duckdns"]="DUCKDNS_API_TOKEN"
    ["namecheap"]="NAMECHEAP_API_USER, NAMECHEAP_API_KEY"
)

print_usage() {
    echo "Usage: $0 --dns <provider> --domain <domain> --email <email>"
    echo ""
    echo "Options:"
    echo "  --dns       DNS provider (cloudflare, route53, googleclouddns, digitalocean, azure, vultr, duckdns, namecheap)"
    echo "  --domain    Base domain for app hosting (e.g., containarium.dev)"
    echo "  --email     Email for Let's Encrypt notifications"
    echo "  --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --dns cloudflare --domain containarium.dev --email admin@example.com"
    echo "  $0 --dns route53 --domain myplatform.io --email devops@company.com"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."

    # Check for Go
    if ! command -v go &> /dev/null; then
        log_error "Go is required but not installed. Please install Go 1.21+ first."
        exit 1
    fi

    GO_VERSION=$(go version | grep -oP 'go\d+\.\d+' | grep -oP '\d+\.\d+')
    log_info "Found Go version: $GO_VERSION"
}

install_xcaddy() {
    log_info "Installing xcaddy..."

    # Install xcaddy
    GOBIN=/usr/local/bin go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

    if ! command -v xcaddy &> /dev/null; then
        log_error "xcaddy installation failed"
        exit 1
    fi

    log_info "xcaddy installed successfully"
}

build_caddy() {
    local dns_module="${DNS_MODULES[$DNS_PROVIDER]}"

    if [[ -z "$dns_module" ]]; then
        log_error "Unknown DNS provider: $DNS_PROVIDER"
        log_error "Supported providers: ${!DNS_MODULES[*]}"
        exit 1
    fi

    log_info "Building Caddy with $DNS_PROVIDER DNS plugin..."

    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"

    xcaddy build --with "$dns_module" --output "$CADDY_BIN"

    if [[ ! -f "$CADDY_BIN" ]]; then
        log_error "Caddy build failed"
        exit 1
    fi

    chmod +x "$CADDY_BIN"
    log_info "Caddy built successfully at $CADDY_BIN"

    # Verify DNS module is included
    if $CADDY_BIN list-modules | grep -q "dns.providers"; then
        log_info "DNS provider module verified"
    else
        log_warn "DNS provider module not found in build"
    fi
}

create_caddy_user() {
    if id "$CADDY_USER" &>/dev/null; then
        log_info "User $CADDY_USER already exists"
    else
        log_info "Creating caddy user..."
        useradd --system --home /var/lib/caddy --shell /usr/sbin/nologin $CADDY_USER
        mkdir -p /var/lib/caddy
        chown -R $CADDY_USER:$CADDY_USER /var/lib/caddy
    fi
}

create_caddyfile() {
    log_info "Creating Caddyfile..."

    mkdir -p /etc/caddy

    # Determine the DNS config syntax based on provider
    local dns_config=""
    case $DNS_PROVIDER in
        cloudflare)
            dns_config="dns cloudflare {env.CF_API_TOKEN}"
            ;;
        route53)
            dns_config="dns route53"
            ;;
        googleclouddns)
            dns_config="dns googleclouddns {env.GCP_PROJECT}"
            ;;
        digitalocean)
            dns_config="dns digitalocean {env.DO_AUTH_TOKEN}"
            ;;
        azure)
            dns_config="dns azure"
            ;;
        vultr)
            dns_config="dns vultr {env.VULTR_API_KEY}"
            ;;
        duckdns)
            dns_config="dns duckdns {env.DUCKDNS_API_TOKEN}"
            ;;
        namecheap)
            dns_config="dns namecheap"
            ;;
    esac

    cat > "$CADDYFILE" << EOF
# Caddy configuration for Containarium App Hosting
# Generated by setup-caddy.sh on $(date)

{
    # Admin API for dynamic route configuration
    admin localhost:2019

    # Email for Let's Encrypt notifications
    email $EMAIL
}

# Wildcard domain with DNS-01 challenge for automatic TLS
*.$DOMAIN {
    tls {
        $dns_config
    }

    # Default response for unconfigured subdomains
    respond "App not found" 404
}

# Main domain - Containarium API gateway
$DOMAIN {
    tls {
        $dns_config
    }

    # Proxy to Containarium REST API
    reverse_proxy localhost:8080
}
EOF

    chown $CADDY_USER:$CADDY_USER "$CADDYFILE"
    log_info "Caddyfile created at $CADDYFILE"
}

create_systemd_service() {
    log_info "Creating systemd service..."

    local env_vars="${DNS_ENV_VARS[$DNS_PROVIDER]}"

    cat > /etc/systemd/system/caddy.service << EOF
[Unit]
Description=Caddy - App Hosting Reverse Proxy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=$CADDY_USER
Group=$CADDY_USER
ExecStart=$CADDY_BIN run --environ --config $CADDYFILE
ExecReload=$CADDY_BIN reload --config $CADDYFILE --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Uncomment and set your DNS provider credentials:
# Environment=$env_vars=your-value-here

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd service created"
}

print_next_steps() {
    local env_vars="${DNS_ENV_VARS[$DNS_PROVIDER]}"

    echo ""
    echo "=========================================="
    echo -e "${GREEN}Caddy Setup Complete!${NC}"
    echo "=========================================="
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Set up DNS records:"
    echo "   - Add A record: *.$DOMAIN -> <your-server-ip>"
    echo "   - Add A record: $DOMAIN -> <your-server-ip>"
    echo ""
    echo "2. Configure DNS provider credentials:"
    echo "   Edit /etc/systemd/system/caddy.service and set:"
    echo "   Environment=$env_vars=<your-credentials>"
    echo ""
    echo "   Or set environment variables:"
    for var in $(echo "$env_vars" | tr ',' '\n'); do
        var=$(echo "$var" | xargs)  # trim whitespace
        echo "   export $var=<your-value>"
    done
    echo ""
    echo "3. Start Caddy:"
    echo "   sudo systemctl enable caddy"
    echo "   sudo systemctl start caddy"
    echo ""
    echo "4. Start Containarium daemon with app hosting:"
    echo "   containarium daemon \\"
    echo "     --app-hosting \\"
    echo "     --postgres 'postgres://user:pass@localhost:5432/containarium' \\"
    echo "     --base-domain '$DOMAIN' \\"
    echo "     --caddy-admin-url 'http://localhost:2019'"
    echo ""
    echo "5. Verify setup:"
    echo "   curl https://test.$DOMAIN"
    echo "   journalctl -u caddy -f"
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dns)
            DNS_PROVIDER="$2"
            shift 2
            ;;
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --email)
            EMAIL="$2"
            shift 2
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z "$DNS_PROVIDER" ]]; then
    log_error "DNS provider is required (--dns)"
    print_usage
    exit 1
fi

if [[ -z "$DOMAIN" ]]; then
    log_error "Domain is required (--domain)"
    print_usage
    exit 1
fi

if [[ -z "$EMAIL" ]]; then
    log_error "Email is required (--email)"
    print_usage
    exit 1
fi

# Main execution
check_root
check_dependencies
install_xcaddy
build_caddy
create_caddy_user
create_caddyfile
create_systemd_service
print_next_steps

log_info "Setup complete!"
