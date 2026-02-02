#!/usr/bin/env bash
set -Eeuo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
#  cloudflared.sh - Cloudflare Tunnel Setup for Debian 13
# ═══════════════════════════════════════════════════════════════════════════════
#  Part of: https://github.com/vdarkobar/lab
#  Target:  Debian 13 (Proxmox LXC/VM)
#
#  Environment Variables (for automation):
#    CLOUDFLARED_TUNNEL_TOKEN  - Pre-generated tunnel token (required for silent)
#    CLOUDFLARED_SKIP_UFW      - Skip UFW configuration (true/false)
#    CLOUDFLARED_SILENT        - Run non-interactively (true/false)
#
#  Usage:
#    Interactive:  ./cloudflared.sh
#    Automated:    CLOUDFLARED_TUNNEL_TOKEN="xxx" CLOUDFLARED_SILENT=true ./cloudflared.sh
#    Post-install: ./cloudflared.sh --help | --status | --configure | --uninstall
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
#  Script Configuration
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_NAME="cloudflared"
SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Logging
LOG_DIR="/var/log/lab"
LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}.log"

# Cloudflared paths
CLOUDFLARED_BIN="/usr/bin/cloudflared"
CLOUDFLARED_CONFIG_DIR="/etc/cloudflared"
CLOUDFLARED_SERVICE="cloudflared"

# Environment variable defaults
CLOUDFLARED_TUNNEL_TOKEN="${CLOUDFLARED_TUNNEL_TOKEN:-}"
CLOUDFLARED_SKIP_UFW="${CLOUDFLARED_SKIP_UFW:-false}"
CLOUDFLARED_SILENT="${CLOUDFLARED_SILENT:-false}"

# ─────────────────────────────────────────────────────────────────────────────
#  Library Loading
# ─────────────────────────────────────────────────────────────────────────────

load_formatting_library() {
    local lib_paths=(
        "${SCRIPT_DIR}/../lib/formatting.sh"
        "${SCRIPT_DIR}/lib/formatting.sh"
        "/opt/lab/lib/formatting.sh"
        "./lib/formatting.sh"
    )
    
    for lib_path in "${lib_paths[@]}"; do
        if [[ -f "$lib_path" ]]; then
            # shellcheck source=/dev/null
            source "$lib_path"
            return 0
        fi
    done
    
    # Fallback: Define formatting when library not available
    # Colors (simplified)
    if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
        C_RESET=$(tput sgr0)
        C_BOLD=$(tput bold)
        C_DIM=$(tput dim)
        C_RED=$(tput setaf 1)
        C_GREEN=$(tput setaf 2)
        C_YELLOW=$(tput setaf 3)
        C_BLUE=$(tput setaf 4)
        C_CYAN=$(tput setaf 6)
        C_WHITE=$(tput setaf 7)
    else
        C_RESET="" C_BOLD="" C_DIM=""
        C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN="" C_WHITE=""
    fi
    
    # Symbols
    if [[ "${LANG:-}" =~ UTF-8 ]] || [[ "${LC_ALL:-}" =~ UTF-8 ]]; then
        SYMBOL_SUCCESS="✓" SYMBOL_ERROR="✗" SYMBOL_WARNING="⚠"
        SYMBOL_INFO="ℹ" SYMBOL_ARROW="→" SYMBOL_BULLET="•"
    else
        SYMBOL_SUCCESS="+" SYMBOL_ERROR="x" SYMBOL_WARNING="!"
        SYMBOL_INFO="i" SYMBOL_ARROW=">" SYMBOL_BULLET="*"
    fi
    
    # Output functions
    print_success()   { echo "${C_GREEN}${C_BOLD}${SYMBOL_SUCCESS}${C_RESET} ${C_GREEN}$*${C_RESET}"; }
    print_error()     { echo "${C_RED}${C_BOLD}${SYMBOL_ERROR}${C_RESET} ${C_RED}$*${C_RESET}" >&2; }
    print_warning()   { echo "${C_YELLOW}${C_BOLD}${SYMBOL_WARNING}${C_RESET} ${C_YELLOW}$*${C_RESET}"; }
    print_info()      { echo "${C_BLUE}${C_BOLD}${SYMBOL_INFO}${C_RESET} ${C_BLUE}$*${C_RESET}"; }
    print_step()      { echo "${C_CYAN}${C_BOLD}${SYMBOL_ARROW}${C_RESET} ${C_CYAN}$*${C_RESET}"; }
    print_header()    { echo; echo "${C_BOLD}${C_CYAN}━━━ $* ━━━${C_RESET}"; }
    print_subheader() { echo "${C_DIM}${SYMBOL_BULLET} $*${C_RESET}"; }
    print_kv()        { printf "${C_CYAN}%-20s${C_RESET} ${C_WHITE}%s${C_RESET}\n" "$1:" "$2"; }
    draw_separator()  { echo "${C_DIM}$(printf '─%.0s' $(seq 1 70))${C_RESET}"; }
    draw_box() {
        local text="$1" width=68
        local padding=$(( (width - ${#text} - 2) / 2 ))
        echo "${C_CYAN}"
        echo "╔$(printf '═%.0s' $(seq 1 $width))╗"
        printf "║%*s%s%*s║\n" $padding "" "$text" $padding ""
        echo "╚$(printf '═%.0s' $(seq 1 $width))╝"
        echo "${C_RESET}"
    }
    log() {
        local level="$1"; shift
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        [[ -n "${LOG_FILE:-}" ]] && echo "${timestamp} [${level}] $*" >> "$LOG_FILE"
        case "$level" in
            SUCCESS) print_success "$*" ;;
            ERROR)   print_error "$*" ;;
            WARN)    print_warning "$*" ;;
            INFO)    print_info "$*" ;;
            STEP)    print_step "$*" ;;
            *)       echo "$*" ;;
        esac
    }
    die() { log ERROR "$@"; exit 1; }
    
    return 0
}

load_formatting_library

# ─────────────────────────────────────────────────────────────────────────────
#  Logging Functions
# ─────────────────────────────────────────────────────────────────────────────

setup_logging() {
    # Create log directory with proper permissions
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR" 2>/dev/null || {
            # If running as non-root via sudo, try with sudo
            sudo mkdir -p "$LOG_DIR" 2>/dev/null || true
        }
    fi
    
    # Ensure log file exists and is writable
    if [[ -n "${SUDO_USER:-}" ]]; then
        # Running via sudo - ensure the invoking user can write
        sudo touch "$LOG_FILE" 2>/dev/null || touch "$LOG_FILE" 2>/dev/null || true
        sudo chown "${SUDO_USER}:${SUDO_USER}" "$LOG_FILE" 2>/dev/null || true
    else
        touch "$LOG_FILE" 2>/dev/null || true
    fi
}

log_info()  { log INFO "$@"; }
log_warn()  { log WARN "$@"; }
log_error() { log ERROR "$@"; }
log_ok()    { log SUCCESS "$@"; }

# ─────────────────────────────────────────────────────────────────────────────
#  Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

is_silent() {
    [[ "$CLOUDFLARED_SILENT" == "true" ]]
}

is_root() {
    [[ $EUID -eq 0 ]]
}

require_root() {
    if ! is_root; then
        print_error "This operation requires root privileges."
        print_info "Please run with: sudo $0 $*"
        exit 1
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

service_exists() {
    systemctl list-unit-files "${1}.service" &>/dev/null
}

service_is_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

service_is_enabled() {
    systemctl is-enabled --quiet "$1" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────────────
#  Dependency Installation
# ─────────────────────────────────────────────────────────────────────────────

install_dependencies() {
    local deps_needed=()
    
    # Check for curl
    if ! command_exists curl; then
        deps_needed+=("curl")
    fi
    
    # Check for gpg (provided by gnupg)
    if ! command_exists gpg && ! command_exists gpg2; then
        deps_needed+=("gnupg")
    fi
    
    # Check for lsb_release (provided by lsb-release)
    if ! command_exists lsb_release; then
        deps_needed+=("lsb-release")
    fi
    
    # Install if needed
    if [[ ${#deps_needed[@]} -gt 0 ]]; then
        print_header "Installing Dependencies"
        
        print_info "Required packages: ${deps_needed[*]}"
        log_info "Installing dependencies: ${deps_needed[*]}"
        
        # Update package lists
        print_info "Updating package lists..."
        if ! apt-get update -qq; then
            print_error "Failed to update package lists"
            log_error "apt-get update failed"
            exit 1
        fi
        
        # Install dependencies
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "${deps_needed[@]}"; then
            print_error "Failed to install dependencies"
            log_error "apt-get install failed for: ${deps_needed[*]}"
            exit 1
        fi
        
        print_success "Dependencies installed"
        log_ok "Dependencies installed: ${deps_needed[*]}"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  Preflight Checks
# ─────────────────────────────────────────────────────────────────────────────

preflight_checks() {
    print_header "Preflight Checks"
    local errors=0
    
    # Check for Debian
    if [[ ! -f /etc/debian_version ]]; then
        print_error "This script is designed for Debian-based systems."
        log_error "Not a Debian-based system"
        ((errors++))
    else
        local debian_version
        debian_version=$(cat /etc/debian_version)
        print_success "Debian detected: $debian_version"
        log_info "Debian version: $debian_version"
    fi
    
    # Check for systemd
    if ! command_exists systemctl; then
        print_error "systemd is required but not found."
        log_error "systemd not found"
        ((errors++))
    else
        print_success "systemd available"
    fi
    
    # Check internet connectivity
    if ! ping -c 1 -W 3 cloudflare.com &>/dev/null; then
        print_error "Cannot reach cloudflare.com - check internet connectivity."
        log_error "No internet connectivity to cloudflare.com"
        ((errors++))
    else
        print_success "Internet connectivity verified"
    fi
    
    # Verify required tools are now available
    for tool in curl gpg apt-get; do
        if ! command_exists "$tool"; then
            print_error "Required tool not found: $tool"
            log_error "Missing required tool: $tool"
            ((errors++))
        fi
    done
    
    if [[ $errors -gt 0 ]]; then
        print_error "Preflight checks failed with $errors error(s)."
        exit 1
    fi
    
    print_success "All preflight checks passed"
    log_info "Preflight checks completed successfully"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Token Handling
# ─────────────────────────────────────────────────────────────────────────────

get_tunnel_token() {
    # Check if token already provided via environment
    if [[ -n "$CLOUDFLARED_TUNNEL_TOKEN" ]]; then
        print_success "Using tunnel token from environment variable"
        log_info "Token provided via CLOUDFLARED_TUNNEL_TOKEN"
        return 0
    fi
    
    # In silent mode, token is required
    if is_silent; then
        print_error "CLOUDFLARED_TUNNEL_TOKEN is required for silent installation."
        log_error "Silent mode requires CLOUDFLARED_TUNNEL_TOKEN"
        exit 1
    fi
    
    # Interactive prompt
    print_header "Tunnel Token Configuration"
    
    echo ""
    print_info "A Cloudflare Tunnel token is required to connect this machine to your tunnel."
    echo ""
    echo "  To get your token:"
    echo "    1. Log in to Cloudflare Zero Trust dashboard"
    echo "    2. Go to: Networks → Tunnels"
    echo "    3. Create a new tunnel or select existing"
    echo "    4. Copy the token from the installation command"
    echo ""
    echo "  The token looks like: eyJhIjoiNjk2..."
    echo ""
    
    while true; do
        read -rp "Enter your Cloudflare Tunnel token: " CLOUDFLARED_TUNNEL_TOKEN
        
        if [[ -z "$CLOUDFLARED_TUNNEL_TOKEN" ]]; then
            print_warning "Token cannot be empty. Please try again."
            continue
        fi
        
        # Basic validation - tokens are base64-encoded JSON, typically start with eyJ
        if [[ ! "$CLOUDFLARED_TUNNEL_TOKEN" =~ ^eyJ ]]; then
            print_warning "Token format looks unusual (should start with 'eyJ')."
            read -rp "Continue anyway? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                continue
            fi
        fi
        
        # Confirm token
        echo ""
        print_info "Token received (${#CLOUDFLARED_TUNNEL_TOKEN} characters)"
        read -rp "Is this correct? [Y/n]: " confirm
        if [[ ! "$confirm" =~ ^[Nn] ]]; then
            break
        fi
    done
    
    log_info "Token configured interactively (${#CLOUDFLARED_TUNNEL_TOKEN} chars)"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Installation Functions
# ─────────────────────────────────────────────────────────────────────────────

install_cloudflared() {
    print_header "Installing Cloudflared"
    
    # Check if already installed
    if command_exists cloudflared; then
        local current_version
        current_version=$(cloudflared --version 2>/dev/null | head -1 || echo "unknown")
        print_info "Cloudflared already installed: $current_version"
        log_info "Cloudflared already installed: $current_version"
        
        if ! is_silent; then
            read -rp "Reinstall/upgrade? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                print_info "Skipping installation"
                return 0
            fi
        fi
    fi
    
    print_info "Adding Cloudflare repository..."
    log_info "Adding Cloudflare APT repository"
    
    # Create keyrings directory if needed
    mkdir -p /usr/share/keyrings
    
    # Add Cloudflare GPG key
    if ! curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | \
         gpg --dearmor -o /usr/share/keyrings/cloudflare-main.gpg 2>/dev/null; then
        print_error "Failed to add Cloudflare GPG key"
        log_error "Failed to download/install Cloudflare GPG key"
        exit 1
    fi
    print_success "Cloudflare GPG key added"
    
    # Determine codename (fallback for Debian 13/trixie)
    local codename
    codename=$(lsb_release -cs 2>/dev/null || echo "bookworm")
    
    # Cloudflare may not have packages for newest Debian yet
    # Fall back to bookworm if trixie packages don't exist
    if [[ "$codename" == "trixie" ]]; then
        print_info "Debian 13 (trixie) detected, checking package availability..."
        # Try trixie first, fall back to bookworm
        if ! curl -fsSL "https://pkg.cloudflare.com/cloudflared/dists/${codename}/main/binary-amd64/Packages" &>/dev/null; then
            print_warning "Trixie packages not available, using bookworm repository"
            log_warn "Using bookworm repository for Debian 13"
            codename="bookworm"
        fi
    fi
    
    # Add repository
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared ${codename} main" \
        > /etc/apt/sources.list.d/cloudflared.list
    print_success "Repository added for: $codename"
    
    # Update and install
    print_info "Updating package lists..."
    if ! apt-get update -qq; then
        print_error "Failed to update package lists"
        log_error "apt-get update failed"
        exit 1
    fi
    
    print_info "Installing cloudflared..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y cloudflared; then
        print_error "Failed to install cloudflared"
        log_error "apt-get install cloudflared failed"
        exit 1
    fi
    
    # Verify installation
    if command_exists cloudflared; then
        local version
        version=$(cloudflared --version 2>/dev/null | head -1 || echo "unknown")
        print_success "Cloudflared installed: $version"
        log_ok "Cloudflared installed successfully: $version"
    else
        print_error "Installation verification failed"
        log_error "cloudflared binary not found after installation"
        exit 1
    fi
}

configure_service() {
    print_header "Configuring Cloudflare Tunnel Service"
    
    # Stop existing service if running
    if service_is_active "$CLOUDFLARED_SERVICE"; then
        print_info "Stopping existing cloudflared service..."
        systemctl stop "$CLOUDFLARED_SERVICE" 2>/dev/null || true
    fi
    
    # Remove old service configuration if exists
    if [[ -f "/etc/systemd/system/${CLOUDFLARED_SERVICE}.service" ]]; then
        print_info "Removing old service configuration..."
        systemctl disable "$CLOUDFLARED_SERVICE" 2>/dev/null || true
        rm -f "/etc/systemd/system/${CLOUDFLARED_SERVICE}.service"
        rm -f "/etc/systemd/system/${CLOUDFLARED_SERVICE}@.service"
        systemctl daemon-reload
    fi
    
    # Clean up old config directory
    if [[ -d "$CLOUDFLARED_CONFIG_DIR" ]]; then
        print_info "Cleaning up old configuration..."
        rm -rf "$CLOUDFLARED_CONFIG_DIR"
    fi
    
    print_info "Installing tunnel service with token..."
    log_info "Running cloudflared service install"
    
    # Install service with token
    # The service install command creates systemd unit and config
    if ! cloudflared service install "$CLOUDFLARED_TUNNEL_TOKEN" 2>&1; then
        print_error "Failed to install cloudflared service"
        log_error "cloudflared service install failed"
        exit 1
    fi
    
    print_success "Service installed successfully"
    log_ok "Cloudflared service installed"
    
    # Enable and start service
    print_info "Enabling and starting service..."
    systemctl daemon-reload
    
    if ! systemctl enable "$CLOUDFLARED_SERVICE"; then
        print_warning "Failed to enable service"
        log_warn "systemctl enable failed"
    fi
    
    if ! systemctl start "$CLOUDFLARED_SERVICE"; then
        print_error "Failed to start cloudflared service"
        log_error "systemctl start failed"
        journalctl -u "$CLOUDFLARED_SERVICE" --no-pager -n 20 >&2
        exit 1
    fi
    
    # Verify service is running
    sleep 2
    if service_is_active "$CLOUDFLARED_SERVICE"; then
        print_success "Cloudflared service is running"
        log_ok "Service started successfully"
    else
        print_error "Service failed to start"
        log_error "Service not active after start"
        journalctl -u "$CLOUDFLARED_SERVICE" --no-pager -n 20 >&2
        exit 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  UFW Configuration (Optional)
# ─────────────────────────────────────────────────────────────────────────────

configure_ufw() {
    # Skip if requested
    if [[ "$CLOUDFLARED_SKIP_UFW" == "true" ]]; then
        print_info "Skipping UFW configuration (CLOUDFLARED_SKIP_UFW=true)"
        log_info "UFW configuration skipped by environment variable"
        return 0
    fi
    
    # Check if UFW is available and functional
    if ! command_exists ufw; then
        print_info "UFW not installed, skipping firewall configuration"
        log_info "UFW not found, skipping"
        return 0
    fi
    
    # Test UFW functionality (works even in unprivileged LXC)
    if ! ufw status &>/dev/null; then
        print_info "UFW not functional in this environment, skipping"
        log_info "UFW status check failed, skipping"
        return 0
    fi
    
    print_header "Firewall Configuration"
    
    print_info "Cloudflared uses outbound HTTPS connections only."
    print_info "No inbound firewall rules are required."
    
    # Ensure outbound HTTPS is allowed (usually default)
    local ufw_status
    ufw_status=$(ufw status 2>/dev/null || echo "inactive")
    
    if echo "$ufw_status" | grep -q "Status: active"; then
        print_success "UFW is active"
        
        # Cloudflared needs outbound 443 and 7844 (QUIC)
        # Most UFW configs allow all outbound by default
        # Only add rules if specifically blocking outbound
        
        if ufw status verbose 2>/dev/null | grep -q "deny (outgoing)"; then
            print_info "Adding outbound rules for cloudflared..."
            ufw allow out 443/tcp comment "Cloudflared HTTPS" 2>/dev/null || true
            ufw allow out 7844/udp comment "Cloudflared QUIC" 2>/dev/null || true
            print_success "Outbound rules added"
            log_info "Added UFW outbound rules for cloudflared"
        else
            print_success "Default outbound policy allows cloudflared traffic"
        fi
    else
        print_info "UFW is not active, no rules needed"
    fi
    
    log_info "UFW configuration completed"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Post-Install Management Functions
# ─────────────────────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
${SCRIPT_NAME}.sh v${SCRIPT_VERSION} - Cloudflare Tunnel Setup for Debian 13

INSTALLATION:
  Interactive:    sudo ./cloudflared.sh
  Automated:      sudo CLOUDFLARED_TUNNEL_TOKEN="xxx" CLOUDFLARED_SILENT=true ./cloudflared.sh

POST-INSTALL MANAGEMENT:
  --help          Show this help message
  --status        Show tunnel status and connection info
  --configure     Reconfigure tunnel with new token
  --logs          Show recent service logs
  --uninstall     Remove cloudflared and clean up

ENVIRONMENT VARIABLES:
  CLOUDFLARED_TUNNEL_TOKEN   Pre-generated tunnel token (required for silent mode)
  CLOUDFLARED_SKIP_UFW       Skip UFW configuration (true/false)
  CLOUDFLARED_SILENT         Run non-interactively (true/false)

EXAMPLES:
  # Interactive installation
  sudo ./cloudflared.sh

  # Automated installation with token
  sudo CLOUDFLARED_TUNNEL_TOKEN="eyJhIjoi..." CLOUDFLARED_SILENT=true ./cloudflared.sh

  # Check tunnel status
  ./cloudflared.sh --status

  # View logs
  ./cloudflared.sh --logs

  # Reconfigure with new token
  sudo ./cloudflared.sh --configure

FILES CREATED:
  /etc/cloudflared/                    Configuration directory
  /etc/apt/sources.list.d/cloudflared.list  APT repository
  /usr/share/keyrings/cloudflare-main.gpg   GPG key
  /var/log/lab/${SCRIPT_NAME}.log           Installation log
  /etc/systemd/system/cloudflared.service   Systemd unit

For more information: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/
EOF
}

show_status() {
    print_header "Cloudflared Status"
    
    # Check if installed
    if ! command_exists cloudflared; then
        print_error "Cloudflared is not installed"
        exit 1
    fi
    
    # Version info
    echo "Version:"
    cloudflared --version 2>/dev/null || echo "  Unable to determine version"
    echo ""
    
    # Service status
    echo "Service Status:"
    if service_is_active "$CLOUDFLARED_SERVICE"; then
        print_success "cloudflared.service is running"
        systemctl status "$CLOUDFLARED_SERVICE" --no-pager -l 2>/dev/null | head -20 || true
    else
        print_warning "cloudflared.service is not running"
        systemctl status "$CLOUDFLARED_SERVICE" --no-pager 2>/dev/null | head -10 || true
    fi
    echo ""
    
    # Tunnel info (if available)
    echo "Tunnel Information:"
    if [[ -f "${CLOUDFLARED_CONFIG_DIR}/config.yml" ]]; then
        print_info "Configuration found at ${CLOUDFLARED_CONFIG_DIR}/config.yml"
    fi
    
    # Connection status via metrics
    if service_is_active "$CLOUDFLARED_SERVICE"; then
        echo ""
        echo "Recent Connections:"
        journalctl -u "$CLOUDFLARED_SERVICE" --no-pager -n 5 --grep -i "connection\|registered\|tunnel" 2>/dev/null || \
            echo "  No recent connection logs found"
    fi
}

show_logs() {
    print_header "Cloudflared Logs"
    
    local lines="${1:-50}"
    
    echo "Last $lines lines from cloudflared service:"
    echo ""
    journalctl -u "$CLOUDFLARED_SERVICE" --no-pager -n "$lines" 2>/dev/null || {
        print_error "Unable to retrieve logs"
        exit 1
    }
}

reconfigure() {
    require_root
    
    print_header "Reconfigure Cloudflare Tunnel"
    
    print_warning "This will replace the current tunnel configuration."
    
    if ! is_silent; then
        read -rp "Continue? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy] ]]; then
            print_info "Reconfiguration cancelled"
            exit 0
        fi
    fi
    
    # Clear existing token to force re-prompt
    CLOUDFLARED_TUNNEL_TOKEN=""
    
    # Get new token
    get_tunnel_token
    
    # Reconfigure service
    configure_service
    
    print_success "Tunnel reconfigured successfully"
    log_ok "Tunnel reconfigured"
}

uninstall() {
    require_root
    
    print_header "Uninstall Cloudflared"
    
    print_warning "This will remove cloudflared and all configuration."
    
    if ! is_silent; then
        read -rp "Are you sure? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy] ]]; then
            print_info "Uninstall cancelled"
            exit 0
        fi
    fi
    
    # Stop and disable service
    if service_exists "$CLOUDFLARED_SERVICE"; then
        print_info "Stopping cloudflared service..."
        systemctl stop "$CLOUDFLARED_SERVICE" 2>/dev/null || true
        systemctl disable "$CLOUDFLARED_SERVICE" 2>/dev/null || true
    fi
    
    # Uninstall service
    if command_exists cloudflared; then
        print_info "Uninstalling cloudflared service..."
        cloudflared service uninstall 2>/dev/null || true
    fi
    
    # Remove package
    print_info "Removing cloudflared package..."
    apt-get remove --purge -y cloudflared 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
    
    # Clean up configuration
    print_info "Removing configuration files..."
    rm -rf "$CLOUDFLARED_CONFIG_DIR"
    rm -f /etc/apt/sources.list.d/cloudflared.list
    rm -f /usr/share/keyrings/cloudflare-main.gpg
    
    # Update package lists
    apt-get update -qq 2>/dev/null || true
    
    print_success "Cloudflared has been removed"
    log_ok "Cloudflared uninstalled successfully"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Installation Summary
# ─────────────────────────────────────────────────────────────────────────────

show_summary() {
    print_header "Installation Complete"
    
    local version
    version=$(cloudflared --version 2>/dev/null | head -1 || echo "unknown")
    
    echo "  Cloudflared: $version"
    echo "  Service:     $(systemctl is-active $CLOUDFLARED_SERVICE 2>/dev/null || echo 'unknown')"
    echo "  Config:      ${CLOUDFLARED_CONFIG_DIR}/"
    echo "  Logs:        journalctl -u $CLOUDFLARED_SERVICE"
    echo ""
    echo "  Management commands:"
    echo "    $0 --status      Show tunnel status"
    echo "    $0 --logs        Show service logs"
    echo "    $0 --configure   Reconfigure tunnel"
    echo "    $0 --uninstall   Remove cloudflared"
    echo ""
    print_info "Configure your tunnel routes in the Cloudflare Zero Trust dashboard"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Main Entry Point
# ─────────────────────────────────────────────────────────────────────────────

main() {
    # Handle command-line flags (post-install management)
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --status)
            show_status
            exit 0
            ;;
        --logs)
            show_logs "${2:-50}"
            exit 0
            ;;
        --configure)
            reconfigure
            exit 0
            ;;
        --uninstall)
            uninstall
            exit 0
            ;;
        --version|-v)
            echo "${SCRIPT_NAME}.sh v${SCRIPT_VERSION}"
            exit 0
            ;;
        "")
            # No flag - proceed with installation
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
    
    # Installation requires root
    require_root
    
    # Setup logging
    setup_logging
    log_info "Starting ${SCRIPT_NAME} installation v${SCRIPT_VERSION}"
    
    # Show print_header
    print_header "Cloudflare Tunnel Setup"
    echo "  Target:  Debian 13 LXC/VM"
    echo "  Version: ${SCRIPT_VERSION}"
    echo ""
    
    # Run installation steps
    install_dependencies
    preflight_checks
    get_tunnel_token
    install_cloudflared
    configure_service
    configure_ufw
    
    # Show summary
    show_summary
    
    log_ok "Installation completed successfully"
}

# Run main function with all arguments
main "$@"
