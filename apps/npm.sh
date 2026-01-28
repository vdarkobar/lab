#!/bin/bash

###################################################################################
# Nginx Proxy Manager Installer - Debian 13                                     #
###################################################################################

# Handle --help flag early
case "${1:-}" in
    --help|-h)
        echo "Nginx Proxy Manager Installer v2.0.0"
        echo
        echo "Usage: $0 [--help]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"Nginx Proxy Manager\""
        echo
        echo "Environment variables:"
        echo "  SKIP_REBOOT=true       Skip reboot prompt"
        echo "  OPENRESTY_DIST=<name>  Override Debian codename for OpenResty repo"
        echo "                         (useful when OpenResty doesn't support latest Debian)"
        echo
        echo "What it does:"
        echo "  - Installs OpenResty (nginx)"
        echo "  - Installs Node.js 22.x"
        echo "  - Installs Certbot with Cloudflare DNS plugin"
        echo "  - Builds NPM frontend and backend"
        echo "  - Configures systemd services"
        echo "  - Opens firewall ports 80, 443, 81"
        echo
        echo "Ports:"
        echo "  81/tcp   NPM Admin UI"
        echo "  80/tcp   HTTP Proxy"
        echo "  443/tcp  HTTPS Proxy"
        echo
        echo "Default credentials:"
        echo "  Email:    admin@example.com"
        echo "  Password: changeme"
        echo
        echo "Files created:"
        echo "  /app                        Application directory"
        echo "  /data                       Data directory (SQLite)"
        echo "  /var/log/lab/npm-*.log      Installation log"
        exit 0
        ;;
esac

###################################################################################
#
# DESCRIPTION:
#   Installs Nginx Proxy Manager (NPM) with OpenResty, Node.js, and all
#   dependencies. Configures firewall rules and systemd services.
#
# LOCATION: lab/apps/npm.sh
# REPOSITORY: https://github.com/vdarkobar/lab
#
# USAGE:
#   As root or with sudo:
#     sudo ./npm.sh
#
#   Non-interactive (skip reboot prompt):
#     SKIP_REBOOT=true sudo ./npm.sh
#
# REQUIREMENTS:
#   - Debian 13 (Trixie)
#   - Root/sudo access
#   - Internet connection
#   - LXC container or VM with systemd
#
# PORTS OPENED:
#   - 81/tcp  - NPM Admin UI
#   - 80/tcp  - HTTP Proxy
#   - 443/tcp - HTTPS Proxy
#
# VERSION: 2.0.0
# LICENSE: MIT
#
###################################################################################

set -euo pipefail

###################################################################################
# CONFIGURATION
###################################################################################

readonly SCRIPT_VERSION="2.1.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source formatting library (also loads helpers.sh if present)
if [[ -f "${SCRIPT_DIR}/../lib/formatting.sh" ]]; then
    source "${SCRIPT_DIR}/../lib/formatting.sh"
else
    echo "ERROR: formatting.sh not found at ${SCRIPT_DIR}/../lib/formatting.sh" >&2
    exit 1
fi

# Check if helpers were loaded (for codename detection)
HELPERS_LOADED=false
if type get_supported_codename &>/dev/null; then
    HELPERS_LOADED=true
fi

###################################################################################
# Codename Detection (inline fallback if helpers not loaded)                      #
###################################################################################

get_openresty_codename() {
    # If helpers loaded, use the proper function
    if [[ "$HELPERS_LOADED" == true ]]; then
        get_supported_codename openresty
        return
    fi
    
    # Inline fallback implementation
    local detected override_val
    
    # Check for env override first
    override_val="${OPENRESTY_DIST:-}"
    if [[ -n "$override_val" ]]; then
        echo "$override_val"
        return 0
    fi
    
    # Detect codename (use subshell to avoid variable conflicts)
    if [[ -f /etc/os-release ]]; then
        detected="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    fi
    [[ -z "$detected" ]] && detected="$(lsb_release -cs 2>/dev/null || echo "unknown")"
    
    # Check if supported, fallback if not
    case "$detected" in
        bookworm|bullseye)
            echo "$detected"
            ;;
        *)
            log WARN "'$detected' may not be in OpenResty repo, using bookworm"
            log WARN "Override with OPENRESTY_DIST=<codename>"
            echo "bookworm"
            ;;
    esac
}

# Set up logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/npm-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR"

# Installation paths
readonly SRC_DIR="/opt/nginxproxymanager"
readonly APP_DIR="/app"
readonly DATA_DIR="/data"
readonly NGINX_ETC="/etc/nginx"
readonly NODE_MAJOR="22"

# Environment
export DEBIAN_FRONTEND=noninteractive

###################################################################################
# UTILITY FUNCTIONS
###################################################################################

show_header() {
    draw_box "Nginx Proxy Manager Installer v${SCRIPT_VERSION}"
    log INFO "Installs NPM with OpenResty and Node.js ${NODE_MAJOR}"
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
    
    # Check if NPM already installed
    if systemctl list-unit-files 2>/dev/null | grep -qE '^npm\.service'; then
        die "npm.service already exists - NPM may already be installed"
    fi
    
    if [[ -d "$APP_DIR" ]] && [[ -f "$APP_DIR/package.json" ]]; then
        die "${APP_DIR} already populated - NPM may already be installed"
    fi
    
    log SUCCESS "Environment checks passed"
}

get_local_ip() {
    hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost"
}

cleanup() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        log ERROR "Installation failed - check log: $LOG_FILE"
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

###################################################################################
# INSTALLATION FUNCTIONS
###################################################################################

install_base_packages() {
    log STEP "Installing base packages"
    
    print_subheader "Updating package lists..."
    apt-get update -y >>"$LOG_FILE" 2>&1 || die "apt-get update failed"
    
    print_subheader "Installing dependencies..."
    apt-get install -y \
        ca-certificates curl git jq rsync unzip tar openssl \
        apache2-utils logrotate build-essential \
        python3 python3-venv python3-pip python3-dev python3-cffi \
        sqlite3 gpg \
        >>"$LOG_FILE" 2>&1 || die "Failed to install base packages"
    
    log SUCCESS "Base packages installed"
}

setup_certbot() {
    log STEP "Setting up Certbot"
    
    print_subheader "Creating Python virtual environment..."
    python3 -m venv /opt/certbot >>"$LOG_FILE" 2>&1 || die "Failed to create certbot venv"
    
    print_subheader "Installing Certbot..."
    /opt/certbot/bin/pip install --upgrade pip setuptools wheel >>"$LOG_FILE" 2>&1
    /opt/certbot/bin/pip install certbot certbot-dns-cloudflare >>"$LOG_FILE" 2>&1 || die "Failed to install certbot"
    
    ln -sf /opt/certbot/bin/certbot /usr/local/bin/certbot
    
    log SUCCESS "Certbot installed"
}

install_openresty() {
    log STEP "Installing OpenResty"
    
    # Get appropriate codename for OpenResty repo
    local codename
    codename="$(get_openresty_codename)"
    log INFO "Using Debian codename for OpenResty repo: $codename"
    
    print_subheader "Adding OpenResty repository..."
    curl -fsSL "https://openresty.org/package/pubkey.gpg" \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/openresty.gpg 2>>"$LOG_FILE"
    
    cat >/etc/apt/sources.list.d/openresty.sources <<EOF
Types: deb
URIs: http://openresty.org/package/debian/
Suites: ${codename}
Components: openresty
Signed-By: /etc/apt/trusted.gpg.d/openresty.gpg
EOF
    
    print_subheader "Installing OpenResty package..."
    apt-get update -y >>"$LOG_FILE" 2>&1
    apt-get install -y openresty >>"$LOG_FILE" 2>&1 || die "Failed to install OpenResty"
    
    log SUCCESS "OpenResty installed"
}

install_nodejs() {
    log STEP "Installing Node.js ${NODE_MAJOR}.x"
    
    print_subheader "Adding Node.js repository..."
    mkdir -p /etc/apt/keyrings
    
    curl -fsSL "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key" \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg 2>>"$LOG_FILE"
    
    cat >/etc/apt/sources.list.d/nodesource.list <<EOF
deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main
EOF
    
    print_subheader "Installing Node.js and Yarn..."
    apt-get update -y >>"$LOG_FILE" 2>&1
    apt-get install -y nodejs >>"$LOG_FILE" 2>&1 || die "Failed to install Node.js"
    
    corepack enable >>"$LOG_FILE" 2>&1 || true
    corepack prepare yarn@stable --activate >>"$LOG_FILE" 2>&1 || true
    
    local node_version=$(node -v 2>/dev/null || echo "unknown")
    local yarn_version=$(yarn -v 2>/dev/null || echo "unknown")
    
    log SUCCESS "Node.js ${node_version} and Yarn ${yarn_version} installed"
}

fetch_npm_sources() {
    log STEP "Fetching Nginx Proxy Manager sources"
    
    print_subheader "Getting latest release from GitHub..."
    local tag=$(curl -fsSL https://api.github.com/repos/NginxProxyManager/nginx-proxy-manager/releases/latest 2>>"$LOG_FILE" | jq -r '.tag_name')
    
    if [[ -z "$tag" || "$tag" == "null" ]]; then
        die "Could not determine latest NPM release from GitHub"
    fi
    
    local release="${tag#v}"
    log INFO "Latest release: ${tag} (${release})"
    
    print_subheader "Downloading sources..."
    rm -rf "$SRC_DIR"
    mkdir -p "$SRC_DIR"
    
    curl -fsSL "https://github.com/NginxProxyManager/nginx-proxy-manager/archive/refs/tags/${tag}.tar.gz" \
        -o /tmp/npm.tar.gz >>"$LOG_FILE" 2>&1 || die "Failed to download NPM sources"
    
    print_subheader "Extracting sources..."
    tar -xzf /tmp/npm.tar.gz -C /tmp >>"$LOG_FILE" 2>&1 || die "Failed to extract tarball"
    
    local extracted=$(find /tmp -maxdepth 1 -type d -name "nginx-proxy-manager-*" 2>/dev/null | head -n1)
    if [[ -z "$extracted" ]]; then
        die "Failed to find extracted directory"
    fi
    
    rsync -a "${extracted}/" "${SRC_DIR}/" >>"$LOG_FILE" 2>&1
    rm -f /tmp/npm.tar.gz
    rm -rf "$extracted"
    
    # Update version in package.json
    sed -i "s|\"version\": \"2.0.0\"|\"version\": \"${release}\"|" "$SRC_DIR/backend/package.json" 2>/dev/null || true
    sed -i "s|\"version\": \"2.0.0\"|\"version\": \"${release}\"|" "$SRC_DIR/frontend/package.json" 2>/dev/null || true
    
    log SUCCESS "Sources deployed to ${SRC_DIR}"
}

setup_environment() {
    log STEP "Setting up runtime environment"
    
    print_subheader "Creating symbolic links..."
    ln -sf /usr/bin/python3 /usr/bin/python
    ln -sf /usr/local/openresty/nginx/sbin/nginx /usr/sbin/nginx
    ln -sf /usr/local/openresty/nginx/ "$NGINX_ETC"
    
    print_subheader "Configuring nginx..."
    sed -i 's+^daemon+#daemon+g' "$SRC_DIR/docker/rootfs/etc/nginx/nginx.conf" 2>/dev/null || true
    
    local confs=$(find "$SRC_DIR" -type f -name "*.conf" 2>/dev/null || true)
    for f in $confs; do
        sed -i 's+include conf.d+include /etc/nginx/conf.d+g' "$f" 2>/dev/null || true
    done
    
    print_subheader "Creating directories..."
    mkdir -p /var/www/html "$NGINX_ETC/logs"
    
    cp -r "$SRC_DIR/docker/rootfs/var/www/html/"* /var/www/html/ >>"$LOG_FILE" 2>&1 || true
    cp -r "$SRC_DIR/docker/rootfs/etc/nginx/"* "$NGINX_ETC/" >>"$LOG_FILE" 2>&1 || true
    cp "$SRC_DIR/docker/rootfs/etc/letsencrypt.ini" /etc/letsencrypt.ini >>"$LOG_FILE" 2>&1 || true
    cp "$SRC_DIR/docker/rootfs/etc/logrotate.d/nginx-proxy-manager" /etc/logrotate.d/nginx-proxy-manager >>"$LOG_FILE" 2>&1 || true
    
    ln -sf "$NGINX_ETC/nginx.conf" "$NGINX_ETC/conf/nginx.conf" 2>/dev/null || true
    rm -f "$NGINX_ETC/conf.d/dev.conf" 2>/dev/null || true
    
    print_subheader "Creating data directories..."
    mkdir -p /tmp/nginx/body \
        /run/nginx \
        "${DATA_DIR}/nginx" \
        "${DATA_DIR}/custom_ssl" \
        "${DATA_DIR}/logs" \
        "${DATA_DIR}/access" \
        "${DATA_DIR}/nginx/default_host" \
        "${DATA_DIR}/nginx/default_www" \
        "${DATA_DIR}/nginx/proxy_host" \
        "${DATA_DIR}/nginx/redirection_host" \
        "${DATA_DIR}/nginx/stream" \
        "${DATA_DIR}/nginx/dead_host" \
        "${DATA_DIR}/nginx/temp" \
        /var/lib/nginx/cache/public \
        /var/lib/nginx/cache/private \
        /var/cache/nginx/proxy_temp
    
    chmod -R 777 /var/cache/nginx
    chown root /tmp/nginx
    
    print_subheader "Configuring DNS resolvers..."
    echo resolver "$(awk 'BEGIN{ORS=" "} $1=="nameserver" {print ($2 ~ ":")? "["$2"]": $2}' /etc/resolv.conf);" \
        >"${NGINX_ETC}/conf.d/include/resolvers.conf"
    
    print_subheader "Generating dummy certificates..."
    if [[ ! -f "${DATA_DIR}/nginx/dummycert.pem" ]] || [[ ! -f "${DATA_DIR}/nginx/dummykey.pem" ]]; then
        openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
            -subj "/O=Nginx Proxy Manager/OU=Dummy Certificate/CN=localhost" \
            -keyout "${DATA_DIR}/nginx/dummykey.pem" \
            -out "${DATA_DIR}/nginx/dummycert.pem" >>"$LOG_FILE" 2>&1
    fi
    
    mkdir -p "${APP_DIR}/frontend/images"
    rsync -a "${SRC_DIR}/backend/" "${APP_DIR}/" >>"$LOG_FILE" 2>&1
    
    log SUCCESS "Environment configured"
}

build_frontend() {
    log STEP "Building frontend"
    
    export NODE_OPTIONS="--max_old_space_size=2048 --openssl-legacy-provider"
    
    cd "${SRC_DIR}/frontend"
    
    print_subheader "Updating package.json..."
    sed -E -i 's/"node-sass" *: *"([^"]*)"/"sass": "\1"/g' package.json 2>/dev/null || true
    
    print_subheader "Installing dependencies (this may take a while)..."
    yarn install --network-timeout 600000 >>"$LOG_FILE" 2>&1 || die "Failed to install frontend dependencies"
    
    print_subheader "Compiling locales..."
    yarn locale-compile >>"$LOG_FILE" 2>&1 || die "Failed to compile locales"
    
    print_subheader "Building frontend (this may take a while)..."
    yarn build >>"$LOG_FILE" 2>&1 || die "Failed to build frontend"
    
    print_subheader "Deploying frontend files..."
    rsync -a "${SRC_DIR}/frontend/dist/" "${APP_DIR}/frontend/" >>"$LOG_FILE" 2>&1
    rsync -a "${SRC_DIR}/frontend/public/images/" "${APP_DIR}/frontend/images/" >>"$LOG_FILE" 2>&1
    
    log SUCCESS "Frontend built"
}

setup_backend() {
    log STEP "Setting up backend"
    
    rm -rf "${APP_DIR}/config/default.json" 2>/dev/null || true
    
    print_subheader "Creating production configuration..."
    if [[ ! -f "${APP_DIR}/config/production.json" ]]; then
        mkdir -p "${APP_DIR}/config"
        cat <<'EOF' >"${APP_DIR}/config/production.json"
{
  "database": {
    "engine": "knex-native",
    "knex": {
      "client": "sqlite3",
      "connection": {
        "filename": "/data/database.sqlite"
      }
    }
  }
}
EOF
    fi
    
    print_subheader "Installing backend dependencies (this may take a while)..."
    cd "${APP_DIR}"
    yarn install --network-timeout 600000 >>"$LOG_FILE" 2>&1 || die "Failed to install backend dependencies"
    
    log SUCCESS "Backend configured"
}

create_systemd_service() {
    log STEP "Creating systemd service"
    
    cat <<'EOF' >/lib/systemd/system/npm.service
[Unit]
Description=Nginx Proxy Manager
After=network.target
Wants=openresty.service

[Service]
Type=simple
Environment=NODE_ENV=production
ExecStartPre=-/usr/bin/mkdir -p /tmp/nginx/body /data/letsencrypt-acme-challenge
ExecStart=/usr/bin/node index.js --abort_on_uncaught_exception --max_old_space_size=250
WorkingDirectory=/app
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload >>"$LOG_FILE" 2>&1
    
    log SUCCESS "Systemd service created"
}

configure_firewall() {
    log STEP "Configuring firewall"
    
    # Check if UFW is installed and active
    if ! command -v ufw >/dev/null 2>&1; then
        log WARN "UFW not installed - skipping firewall configuration"
        return 0
    fi
    
    if ! ufw status 2>/dev/null | grep -q "Status: active"; then
        log WARN "UFW not active - skipping firewall configuration"
        return 0
    fi
    
    local ports=(
        "81/tcp|NPM Admin UI"
        "80/tcp|HTTP Proxy"
        "443/tcp|HTTPS Proxy"
    )
    
    for rule in "${ports[@]}"; do
        IFS='|' read -r port comment <<< "$rule"
        
        print_subheader "Opening port ${port}..."
        if ufw allow "$port" comment "$comment" >>"$LOG_FILE" 2>&1; then
            log INFO "Port ${port} opened: ${comment}"
        else
            log WARN "Failed to open port ${port}"
        fi
    done
    
    print_subheader "Reloading firewall..."
    ufw reload >>"$LOG_FILE" 2>&1 || true
    
    log SUCCESS "Firewall configured"
}

start_services() {
    log STEP "Starting services"
    
    print_subheader "Configuring OpenResty..."
    sed -i 's/user npm/user root/g; s/^pid/#pid/g' /usr/local/openresty/nginx/conf/nginx.conf >>"$LOG_FILE" 2>&1 || true
    sed -r -i 's/^([[:space:]]*)su npm npm/\1#su npm npm/g;' /etc/logrotate.d/nginx-proxy-manager >>"$LOG_FILE" 2>&1 || true
    
    print_subheader "Enabling and starting OpenResty..."
    systemctl enable --now openresty >>"$LOG_FILE" 2>&1 || die "Failed to start OpenResty"
    
    print_subheader "Enabling and starting NPM..."
    systemctl enable --now npm >>"$LOG_FILE" 2>&1 || die "Failed to start NPM"
    
    print_subheader "Restarting OpenResty..."
    systemctl restart openresty >>"$LOG_FILE" 2>&1 || true
    
    # Wait for services to start
    sleep 3
    
    log SUCCESS "Services started"
}

verify_installation() {
    log STEP "Verifying installation"
    
    local failed=false
    
    if systemctl is-active --quiet openresty; then
        log SUCCESS "OpenResty is running"
    else
        log ERROR "OpenResty is not running"
        failed=true
    fi
    
    if systemctl is-active --quiet npm; then
        log SUCCESS "NPM service is running"
    else
        log ERROR "NPM service is not running"
        failed=true
    fi
    
    if [[ "$failed" == true ]]; then
        log WARN "Some services failed to start - check logs"
    fi
}

show_summary() {
    local ip=$(get_local_ip)
    
    echo
    draw_separator
    log SUCCESS "Installation Complete"
    draw_separator
    echo
    print_kv "NPM Admin UI" "http://${ip}:81"
    print_kv "HTTP Proxy" "Port 80"
    print_kv "HTTPS Proxy" "Port 443"
    print_kv "App Directory" "$APP_DIR"
    print_kv "Data Directory" "$DATA_DIR (SQLite database)"
    print_kv "Log File" "$LOG_FILE"
    echo
    print_header "Default Credentials"
    print_kv "Email" "admin@example.com"
    print_kv "Password" "changeme"
    echo
    print_warning "Change the default password immediately after first login!"
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
                break
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

###################################################################################
# MAIN
###################################################################################

main() {
    show_header
    check_privileges
    check_environment
    
    install_base_packages
    setup_certbot
    install_openresty
    install_nodejs
    
    fetch_npm_sources
    setup_environment
    
    build_frontend
    setup_backend
    
    create_systemd_service
    configure_firewall
    start_services
    
    verify_installation
    show_summary
    
    prompt_reboot
}

main "$@"