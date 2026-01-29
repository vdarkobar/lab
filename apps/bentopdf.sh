#!/bin/bash

#############################################################################
# BentoPDF Installer - Debian 13                                            #
# Self-hosted PDF editor with modern web interface                          #
#############################################################################

readonly SCRIPT_VERSION="1.0.0"

# Handle --help flag early
case "${1:-}" in
    --help|-h)
        echo "BentoPDF Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"BentoPDF\""
        echo
        echo "What it does:"
        echo "  - Installs Node.js 24.x"
        echo "  - Downloads and builds BentoPDF"
        echo "  - Configures systemd service"
        echo "  - Opens firewall port 8080"
        echo
        echo "Environment variables:"
        echo "  SKIP_REBOOT=true    Skip reboot prompt"
        echo "  BENTOPDF_PORT=8080  Override default port"
        echo
        echo "Files created:"
        echo "  /opt/bentopdf                  Application directory"
        echo "  /lib/systemd/system/bentopdf.service  Systemd service"
        echo "  /var/log/lab/bentopdf-*.log   Installation log"
        echo
        echo "Default access:"
        echo "  http://<server-ip>:8080"
        exit 0
        ;;
esac

set -euo pipefail

#############################################################################
# Configuration
#############################################################################

readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Installation paths
readonly INSTALL_DIR="/opt/bentopdf"
readonly NODE_MAJOR="24"
readonly BENTOPDF_PORT="${BENTOPDF_PORT:-8080}"
readonly BENTOPDF_REPO="alam00000/bentopdf"

# Logging directory (created early so LOG_FILE can be set)
readonly LOG_DIR="/var/log/lab"
mkdir -p "$LOG_DIR" 2>/dev/null || true

export DEBIAN_FRONTEND=noninteractive

#############################################################################
# Load Formatting Library
#############################################################################

REPO_ROOT="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)" || REPO_ROOT="$SCRIPT_DIR"

if [[ -f "$REPO_ROOT/lib/formatting.sh" ]]; then
    source "$REPO_ROOT/lib/formatting.sh"
elif [[ -f "$SCRIPT_DIR/../lib/formatting.sh" ]]; then
    source "$SCRIPT_DIR/../lib/formatting.sh"
elif [[ -f "$HOME/lab/lib/formatting.sh" ]]; then
    source "$HOME/lab/lib/formatting.sh"
else
    # Minimal fallback formatting
    print_header() { echo -e "\n━━━ $1 ━━━"; }
    print_success() { echo "✓ $1"; }
    print_error() { echo "✗ $1" >&2; }
    print_warning() { echo "⚠ $1"; }
    print_info() { echo "ℹ $1"; }
    print_step() { echo "→ $1"; }
    print_subheader() { echo "  • $1"; }
    print_kv() { printf "%-20s %s\n" "$1:" "$2"; }
    draw_separator() { echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }
    draw_box() { echo -e "\n╔══════════════════════════════════════════════════════╗"; echo "║  $1"; echo "╚══════════════════════════════════════════════════════╝"; }
    die() { print_error "$1"; exit 1; }
    log() { local level="$1"; shift; echo "[$level] $*"; }
fi

# Now safe to set LOG_FILE (formatting.sh is loaded, directory exists)
readonly LOG_FILE="${LOG_DIR}/bentopdf-$(date +%Y%m%d-%H%M%S).log"

#############################################################################
# Utility Functions
#############################################################################

show_header() {
    draw_box "BentoPDF Installer v${SCRIPT_VERSION}"
    log INFO "Self-hosted PDF editor with Node.js ${NODE_MAJOR}"
    echo
}

check_privileges() {
    # Check if running on PVE host (should not be)
    if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
        die "This script should not run on Proxmox VE host. Run inside a VM or LXC container."
    fi
    
    if [[ "$EUID" -ne 0 ]]; then
        die "This script must be run as root or with sudo"
    fi
}

check_environment() {
    log STEP "Checking environment"
    
    # Check for systemd
    if ! command -v systemctl >/dev/null 2>&1; then
        die "systemd not found (is this container systemd-enabled?)"
    fi
    
    # Check for apt
    if ! command -v apt-get >/dev/null 2>&1; then
        die "apt-get not found (not a Debian system?)"
    fi
    
    # Check if BentoPDF already installed
    if [[ -d "$INSTALL_DIR" ]] && [[ -d "$INSTALL_DIR/dist" ]]; then
        die "${INSTALL_DIR}/dist already exists - BentoPDF may already be installed"
    fi
    
    # Check if nginx site already configured for bentopdf
    if [[ -f /etc/nginx/sites-enabled/bentopdf ]]; then
        die "Nginx site 'bentopdf' already configured"
    fi
    
    log SUCCESS "Environment checks passed"
}

get_local_ip() {
    hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost"
}

setup_logging() {
    mkdir -p "$LOG_DIR"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    {
        echo "========================================"
        echo "bentopdf.sh started at $(date)"
        echo "Log: $LOG_FILE"
        echo "========================================"
    } >> "$LOG_FILE"
}

cleanup() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        log ERROR "Installation failed - check log: $LOG_FILE"
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

#############################################################################
# Installation Functions
#############################################################################

install_base_packages() {
    log STEP "Installing base packages"
    
    # Stop unattended upgrades if running
    print_subheader "Stopping unattended-upgrades if running..."
    systemctl stop unattended-upgrades 2>/dev/null || true
    
    # Wait for apt lock
    local wait_count=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [[ $wait_count -eq 0 ]]; then
            print_subheader "Waiting for apt lock to be released..."
        fi
        sleep 2
        ((wait_count++))
        if [[ $wait_count -gt 30 ]]; then
            die "Timed out waiting for apt lock"
        fi
    done
    
    print_subheader "Updating package lists..."
    apt-get update -y >>"$LOG_FILE" 2>&1 || die "apt-get update failed"
    
    print_subheader "Installing dependencies..."
    apt-get install -y \
        ca-certificates curl git gnupg \
        >>"$LOG_FILE" 2>&1 || die "Failed to install base packages"
    
    log SUCCESS "Base packages installed"
}

install_nodejs() {
    log STEP "Installing Node.js ${NODE_MAJOR}"
    
    # Check if Node.js is already installed with correct version
    if command -v node >/dev/null 2>&1; then
        local current_version
        current_version=$(node --version 2>/dev/null | sed 's/v//' | cut -d. -f1)
        if [[ "$current_version" -ge "$NODE_MAJOR" ]]; then
            log SUCCESS "Node.js v$(node --version) already installed"
            return 0
        fi
        print_subheader "Upgrading Node.js from v${current_version} to v${NODE_MAJOR}..."
    fi
    
    # Setup NodeSource repository
    print_subheader "Adding NodeSource repository..."
    mkdir -p /etc/apt/keyrings
    
    if [[ ! -f /etc/apt/keyrings/nodesource.gpg ]]; then
        curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | \
            gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg >>"$LOG_FILE" 2>&1
    fi
    
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" > \
        /etc/apt/sources.list.d/nodesource.list
    
    print_subheader "Installing Node.js..."
    apt-get update -y >>"$LOG_FILE" 2>&1
    apt-get install -y nodejs >>"$LOG_FILE" 2>&1 || die "Failed to install Node.js"
    
    # Verify installation
    if ! command -v node >/dev/null 2>&1; then
        die "Node.js installation failed - node command not found"
    fi
    
    log SUCCESS "Node.js $(node --version) installed"
}

fetch_bentopdf() {
    log STEP "Downloading BentoPDF"
    
    print_subheader "Fetching latest release from GitHub..."
    
    # Get latest release info
    local release_info
    release_info=$(curl -fsSL "https://api.github.com/repos/${BENTOPDF_REPO}/releases/latest" 2>>"$LOG_FILE")
    
    if [[ -z "$release_info" ]]; then
        die "Failed to fetch release information from GitHub"
    fi
    
    local tarball_url
    tarball_url=$(echo "$release_info" | grep -o '"tarball_url": *"[^"]*"' | cut -d'"' -f4)
    local version
    version=$(echo "$release_info" | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)
    
    if [[ -z "$tarball_url" ]]; then
        die "Failed to parse release tarball URL"
    fi
    
    print_subheader "Downloading version ${version}..."
    
    # Create install directory
    mkdir -p "$INSTALL_DIR"
    
    # Download and extract
    local tmp_tarball="/tmp/bentopdf-${version}.tar.gz"
    curl -fsSL "$tarball_url" -o "$tmp_tarball" >>"$LOG_FILE" 2>&1 || die "Failed to download tarball"
    
    print_subheader "Extracting to ${INSTALL_DIR}..."
    tar -xzf "$tmp_tarball" -C "$INSTALL_DIR" --strip-components=1 >>"$LOG_FILE" 2>&1 || die "Failed to extract tarball"
    rm -f "$tmp_tarball"
    
    # Verify extraction
    if [[ ! -f "${INSTALL_DIR}/package.json" ]]; then
        die "Extraction failed - package.json not found"
    fi
    
    log SUCCESS "BentoPDF ${version} downloaded"
}

build_bentopdf() {
    log STEP "Building BentoPDF"
    
    cd "$INSTALL_DIR"
    
    print_subheader "Installing npm dependencies (this may take a while)..."
    npm ci --no-audit --no-fund >>"$LOG_FILE" 2>&1 || die "Failed to install npm dependencies"
    
    print_subheader "Building application (this may take a while)..."
    export SIMPLE_MODE=true
    npm run build -- --mode production >>"$LOG_FILE" 2>&1 || die "Failed to build BentoPDF"
    
    # Verify build output
    if [[ ! -d "${INSTALL_DIR}/dist" ]]; then
        die "Build failed - dist directory not found"
    fi
    
    log SUCCESS "BentoPDF built successfully"
}

install_nginx() {
    log STEP "Installing Nginx"
    
    if command -v nginx >/dev/null 2>&1; then
        log SUCCESS "Nginx already installed"
        return 0
    fi
    
    print_subheader "Installing nginx..."
    apt-get install -y nginx >>"$LOG_FILE" 2>&1 || die "Failed to install nginx"
    
    log SUCCESS "Nginx installed"
}

configure_nginx() {
    log STEP "Configuring Nginx for BentoPDF"
    
    # Create nginx config for BentoPDF
    cat <<'EOF' >/etc/nginx/sites-available/bentopdf
server {
    listen 8080;
    listen [::]:8080;
    
    server_name _;
    
    root /opt/bentopdf/dist;
    index index.html index.htm;
    
    # Include standard MIME types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Add WASM MIME type
    types {
        application/wasm wasm;
    }
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json application/xml application/wasm;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|wasm)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # No cache for HTML
    location ~* \.html$ {
        expires -1;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
    }
}
EOF

    # Update port if non-default
    if [[ "$BENTOPDF_PORT" != "8080" ]]; then
        sed -i "s/listen 8080/listen ${BENTOPDF_PORT}/g" /etc/nginx/sites-available/bentopdf
        sed -i "s/listen \[::\]:8080/listen [::]:${BENTOPDF_PORT}/g" /etc/nginx/sites-available/bentopdf
    fi
    
    # Enable the site
    ln -sf /etc/nginx/sites-available/bentopdf /etc/nginx/sites-enabled/bentopdf
    
    # Remove default site if it exists
    rm -f /etc/nginx/sites-enabled/default
    
    # Test nginx config
    if ! nginx -t >>"$LOG_FILE" 2>&1; then
        cat /etc/nginx/sites-available/bentopdf >> "$LOG_FILE"
        die "Nginx configuration test failed"
    fi
    
    log SUCCESS "Nginx configured"
}

create_systemd_service() {
    log STEP "Creating systemd service"
    
    # We'll use nginx's built-in service, just ensure it's enabled
    systemctl daemon-reload >>"$LOG_FILE" 2>&1
    
    log SUCCESS "Using nginx.service for BentoPDF"
}

configure_firewall() {
    log STEP "Configuring firewall"
    
    # Check if UFW is installed
    if ! command -v ufw >/dev/null 2>&1; then
        log WARN "UFW not installed - skipping firewall configuration"
        return 0
    fi
    
    # Test if UFW is functional
    if ! ufw status >/dev/null 2>&1; then
        log WARN "UFW not functional in this environment"
        log INFO "Configure firewall on the host instead"
        log INFO "Required port: ${BENTOPDF_PORT}/tcp"
        return 0
    fi
    
    # Check if UFW is active
    if ! ufw status | grep -q "Status: active"; then
        log WARN "UFW not active - skipping firewall configuration"
        return 0
    fi
    
    print_subheader "Opening port ${BENTOPDF_PORT}/tcp..."
    if ufw allow "${BENTOPDF_PORT}/tcp" comment 'BentoPDF Web UI' >>"$LOG_FILE" 2>&1; then
        log INFO "Port ${BENTOPDF_PORT}/tcp opened"
    else
        log WARN "Failed to open port ${BENTOPDF_PORT}/tcp"
    fi
    
    log SUCCESS "Firewall configured"
}

start_services() {
    log STEP "Starting services"
    
    print_subheader "Enabling and starting Nginx..."
    systemctl enable nginx >>"$LOG_FILE" 2>&1 || true
    systemctl restart nginx >>"$LOG_FILE" 2>&1 || die "Failed to start Nginx"
    
    # Wait for service to start
    sleep 2
    
    log SUCCESS "Services started"
}

verify_installation() {
    log STEP "Verifying installation"
    
    local failed=false
    
    if systemctl is-active --quiet nginx; then
        log SUCCESS "Nginx service is running"
    else
        log ERROR "Nginx service is not running"
        print_subheader "Checking service status..."
        systemctl status nginx --no-pager >> "$LOG_FILE" 2>&1 || true
        failed=true
    fi
    
    # Test HTTP response
    sleep 2
    if curl -fsSL "http://localhost:${BENTOPDF_PORT}" >/dev/null 2>&1; then
        log SUCCESS "BentoPDF responding on port ${BENTOPDF_PORT}"
    else
        log WARN "BentoPDF not responding yet (may need more time to start)"
    fi
    
    if [[ "$failed" == true ]]; then
        log WARN "Service failed to start - check logs: journalctl -u nginx"
    fi
}

show_summary() {
    local ip
    ip=$(get_local_ip)
    
    echo
    draw_separator
    log SUCCESS "Installation Complete"
    draw_separator
    echo
    print_kv "BentoPDF URL" "http://${ip}:${BENTOPDF_PORT}"
    print_kv "Install Directory" "$INSTALL_DIR"
    print_kv "Web Root" "${INSTALL_DIR}/dist"
    print_kv "Service" "nginx.service"
    print_kv "Log File" "$LOG_FILE"
    echo
    print_header "Management Commands"
    echo "  systemctl status nginx       # Check status"
    echo "  systemctl restart nginx      # Restart service"
    echo "  journalctl -u nginx -f       # View logs"
    echo
}

prompt_reboot() {
    if [[ "${SKIP_REBOOT:-false}" == "true" ]]; then
        log INFO "Skipping reboot (SKIP_REBOOT=true)"
        return 0
    fi
    
    echo
    print_header "Reboot Recommended"
    echo
    print_info "A reboot is recommended to ensure all services start properly."
    echo
    
    while true; do
        echo -n "Reboot now? (yes/no): "
        read -r response
        
        case "${response,,}" in
            yes|y)
                log INFO "Rebooting system..."
                reboot
                exit 0
                ;;
            no|n)
                log INFO "Reboot cancelled"
                print_warning "Remember to reboot later: sudo reboot"
                break
                ;;
            *)
                print_error "Please answer yes or no"
                ;;
        esac
    done
}

#############################################################################
# Main
#############################################################################

main() {
    check_privileges
    setup_logging      # Creates LOG_DIR with root privileges
    show_header        # Now log() can write to LOG_FILE
    check_environment
    
    install_base_packages
    install_nodejs
    install_nginx
    fetch_bentopdf
    build_bentopdf
    
    configure_nginx
    create_systemd_service
    configure_firewall
    start_services
    
    verify_installation
    show_summary
    
    prompt_reboot
}

main "$@"