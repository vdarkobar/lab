#!/bin/bash

#############################################################################
# Nginx Proxy Manager Installation Script                                   #
# Installs Docker + Compose and deploys NPM with MariaDB                   #
#############################################################################

readonly SCRIPT_VERSION="1.1.0"
readonly SCRIPT_NAME="npm-docker"

# Handle --help flag early (before sourcing libraries)
case "${1:-}" in
    --help|-h)
        echo "Nginx Proxy Manager Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help] [--status] [--logs [N]] [--configure] [--uninstall]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"Nginx Proxy Manager\""
        echo "  OR run standalone after hardening"
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Internet connectivity required"
        echo "  - Ports 80, 443, and custom admin port must be available"
        echo
        echo "What it does:"
        echo "  - Installs Docker CE and Docker Compose v2 (if not present)"
        echo "  - Creates NPM directory structure in ~/npm"
        echo "  - Generates secure database passwords"
        echo "  - Creates docker-compose.yml with NPM, MariaDB, Watchtower"
        echo "  - Configures UFW firewall rules"
        echo "  - Optionally starts the stack"
        echo
        echo "Environment variables:"
        echo "  DOCKER_DIST=<codename>   Override Debian codename for Docker repo"
        echo "  NPM_SILENT=true          Non-interactive mode (safe defaults)"
        echo "  NPM_SKIP_UFW=true        Skip firewall configuration"
        echo "  NPM_PORT=<port>          Pre-set admin port (49152-65535)"
        echo "  NPM_TZ=<timezone>        Pre-set timezone (e.g., Europe/Berlin)"
        echo
        echo "Post-install commands:"
        echo "  --status      Show service status and access info"
        echo "  --logs [N]    Show last N lines of logs (default: 50)"
        echo "  --configure   Reconfigure application"
        echo "  --uninstall   Remove application"
        echo "  --version     Show version"
        echo
        echo "Network requirements:"
        echo "  Inbound 80/tcp           HTTP proxy"
        echo "  Inbound 443/tcp          HTTPS proxy"
        echo "  Inbound <admin-port>/tcp Admin web UI"
        echo
        echo "Files created:"
        echo "  ~/npm/docker-compose.yml         Docker Compose configuration"
        echo "  ~/npm/.env                       Environment variables"
        echo "  ~/npm/.secrets/                  Database credentials"
        echo "  ~/npm/data/                      NPM application data"
        echo "  ~/npm/letsencrypt/               SSL certificates"
        echo "  ~/npm/mysql/                     MariaDB data"
        echo "  /var/log/lab/npm-docker-*.log    Installation logs"
        echo
        echo "First time setup:"
        echo "  Open the Admin URL and create your admin account"
        exit 0
        ;;
esac

#############################################################################
# Script Configuration                                                      #
#############################################################################

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Secure file creation by default
umask 077

# Track services we stop (to restart later)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

# App config (env overrides)
NPM_SILENT="${NPM_SILENT:-false}"; SILENT="$NPM_SILENT"
NPM_SKIP_UFW="${NPM_SKIP_UFW:-false}"; SKIP_FIREWALL="$NPM_SKIP_UFW"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"

#############################################################################
# Terminal Formatting (embedded from formatting.sh)                         #
#############################################################################

# Check if terminal supports colors
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    COLORS_SUPPORTED=true
    
    # Colors
    readonly C_RESET=$(tput sgr0)
    readonly C_BOLD=$(tput bold)
    readonly C_DIM=$(tput dim)
    
    # Foreground colors
    readonly C_RED=$(tput setaf 1)
    readonly C_GREEN=$(tput setaf 2)
    readonly C_YELLOW=$(tput setaf 3)
    readonly C_BLUE=$(tput setaf 4)
    readonly C_CYAN=$(tput setaf 6)
    readonly C_WHITE=$(tput setaf 7)
    
    # Bright colors (if supported)
    readonly C_BRIGHT_GREEN=$(tput setaf 10 2>/dev/null || tput setaf 2)
    readonly C_BRIGHT_RED=$(tput setaf 9 2>/dev/null || tput setaf 1)
    readonly C_BRIGHT_YELLOW=$(tput setaf 11 2>/dev/null || tput setaf 3)
    readonly C_BRIGHT_BLUE=$(tput setaf 12 2>/dev/null || tput setaf 4)
else
    COLORS_SUPPORTED=false
    readonly C_RESET=""
    readonly C_BOLD=""
    readonly C_DIM=""
    readonly C_RED=""
    readonly C_GREEN=""
    readonly C_YELLOW=""
    readonly C_BLUE=""
    readonly C_CYAN=""
    readonly C_WHITE=""
    readonly C_BRIGHT_GREEN=""
    readonly C_BRIGHT_RED=""
    readonly C_BRIGHT_YELLOW=""
    readonly C_BRIGHT_BLUE=""
fi

# Unicode symbols (with ASCII fallbacks)
if [[ "${LANG:-}" =~ UTF-8 ]] || [[ "${LC_ALL:-}" =~ UTF-8 ]]; then
    readonly SYMBOL_SUCCESS="✓"
    readonly SYMBOL_ERROR="✗"
    readonly SYMBOL_WARNING="⚠"
    readonly SYMBOL_INFO="ℹ"
    readonly SYMBOL_ARROW="→"
    readonly SYMBOL_BULLET="•"
else
    readonly SYMBOL_SUCCESS="+"
    readonly SYMBOL_ERROR="x"
    readonly SYMBOL_WARNING="!"
    readonly SYMBOL_INFO="i"
    readonly SYMBOL_ARROW=">"
    readonly SYMBOL_BULLET="*"
fi

#############################################################################
# Spinner Characters (optional - only needed if run_with_spinner is used)  #
#############################################################################

if [[ "${LANG:-}" =~ UTF-8 ]] || [[ "${LC_ALL:-}" =~ UTF-8 ]]; then
    readonly SPINNER_CHARS='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
else
    readonly SPINNER_CHARS='|/-\'
fi

#############################################################################
# Output Functions                                                          #
#############################################################################

print_success() {
    local msg="$*"
    echo "${C_BRIGHT_GREEN}${C_BOLD}${SYMBOL_SUCCESS}${C_RESET} ${C_GREEN}${msg}${C_RESET}"
}

print_error() {
    local msg="$*"
    echo "${C_BRIGHT_RED}${C_BOLD}${SYMBOL_ERROR}${C_RESET} ${C_RED}${msg}${C_RESET}" >&2
}

print_warning() {
    local msg="$*"
    echo "${C_BRIGHT_YELLOW}${C_BOLD}${SYMBOL_WARNING}${C_RESET} ${C_YELLOW}${msg}${C_RESET}"
}

print_info() {
    local msg="$*"
    echo "${C_BRIGHT_BLUE}${C_BOLD}${SYMBOL_INFO}${C_RESET} ${C_BLUE}${msg}${C_RESET}"
}

print_step() {
    local msg="$*"
    echo "${C_CYAN}${C_BOLD}${SYMBOL_ARROW}${C_RESET} ${C_CYAN}${msg}${C_RESET}"
}

print_header() {
    local msg="$*"
    echo
    echo "${C_BOLD}${C_CYAN}━━━ ${msg} ━━━${C_RESET}"
}

print_subheader() {
    local msg="$*"
    echo "${C_DIM}${SYMBOL_BULLET} ${msg}${C_RESET}"
}

print_kv() {
    local key="$1"
    local value="$2"
    printf "${C_CYAN}%-20s${C_RESET} ${C_WHITE}%s${C_RESET}\n" "$key:" "$value"
}

#############################################################################
# Visual Elements                                                           #
#############################################################################

draw_box() {
    local text="$1"
    local width=68
    local padding=$(( (width - ${#text} - 2) / 2 ))
    
    echo "${C_CYAN}"
    echo "╔$(printf '═%.0s' $(seq 1 $width))╗"
    printf "║%*s%s%*s║\n" $padding "" "$text" $padding ""
    echo "╚$(printf '═%.0s' $(seq 1 $width))╝"
    echo "${C_RESET}"
}

draw_separator() {
    echo "${C_DIM}$(printf '─%.0s' $(seq 1 70))${C_RESET}"
}

#############################################################################
# Logging                                                                   #
#############################################################################

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Write plain text to log file (strip ANSI color codes)
    if [[ -n "${LOG_FILE:-}" ]] && [[ -w "${LOG_FILE:-}" || -w "$(dirname "${LOG_FILE:-/tmp}")" ]]; then
        echo "[$timestamp] [$level] $message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE" 2>/dev/null || true
    fi
    
    # Display to console with formatting
    case "$level" in
        SUCCESS) print_success "$message" ;;
        ERROR)   print_error "$message" ;;
        WARN)    print_warning "$message" ;;
        INFO)    print_info "$message" ;;
        STEP)    print_step "$message" ;;
        *)       echo "$message" ;;
    esac
}

die() {
    log ERROR "$@"
    exit 1
}

# Error trap for better debugging (set after print_error is defined)
trap 'print_error "Error at line $LINENO: $BASH_COMMAND"; log ERROR "Error at line $LINENO: $BASH_COMMAND"' ERR

#############################################################################
# Helper Functions                                                          #
#############################################################################

is_silent() {
    [[ "${SILENT:-false}" == "true" ]]
}

command_exists() {
    command -v "$1" &>/dev/null
}

service_is_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

service_is_enabled() {
    systemctl is-enabled --quiet "$1" 2>/dev/null
}

# Uses ip route first, hostname -I as fallback
get_local_ip() {
    local ip_address
    ip_address=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    [[ -z "$ip_address" ]] && ip_address=$(hostname -I 2>/dev/null | awk '{print $1}')
    ip_address=${ip_address:-"localhost"}
    echo "$ip_address"
}

check_port_availability() {
    local ports=("$@")
    local ports_in_use=()
    
    print_step "Checking port availability..."
    
    if command_exists ss; then
        for port in "${ports[@]}"; do
            if ss -tuln 2>/dev/null | grep -q ":${port} "; then
                ports_in_use+=("$port")
            fi
        done
    elif command_exists netstat; then
        for port in "${ports[@]}"; do
            if netstat -tuln 2>/dev/null | grep -q ":${port} "; then
                ports_in_use+=("$port")
            fi
        done
    else
        print_warning "Cannot check ports (ss/netstat not available)"
        return 0
    fi
    
    if [[ ${#ports_in_use[@]} -gt 0 ]]; then
        print_warning "Ports already in use: ${ports_in_use[*]}"
        print_info "Ensure these ports are free before starting the service."
        return 1
    fi
    
    print_success "Required ports are available: ${ports[*]}"
    return 0
}

prepare_apt() {
    # Stop unattended-upgrades to avoid apt locks (best-effort)
    if service_is_active unattended-upgrades; then
        UNATTENDED_UPGRADES_WAS_ACTIVE=true
        sudo systemctl stop unattended-upgrades 2>/dev/null || true
        print_info "Temporarily stopped unattended-upgrades"
    fi

    # Wait for dpkg lock (best-effort)
    local wait_count=0
    while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [[ $wait_count -eq 0 ]]; then
            print_subheader "Waiting for apt/dpkg lock..."
        fi
        wait_count=$((wait_count + 1))
        sleep 2
        if [[ $wait_count -ge 60 ]]; then
            print_warning "Still waiting for apt lock (60s+) — continuing anyway"
            break
        fi
    done
}

#############################################################################
# Spinner for Long Operations (optional)                                    #
#############################################################################

# Run a command with an animated spinner, elapsed timer, and log capture.
# All command output is redirected to LOG_FILE. Console shows a spinner
# that resolves to ✓/✗ on completion with elapsed time.
#
# Usage:
#   if ! run_with_spinner "Installing packages" sudo apt-get install -y pkg; then
#       die "Failed to install packages"
#   fi
#
# Notes:
#   - Command runs in a background subshell (trap ERR does not fire for it)
#   - Safe with set -e: uses 'wait || exit_code=$?' to prevent errexit from
#     killing the function before cleanup (temp file removal, log capture)
#   - Exit code is preserved and returned to caller
#   - Falls back to running without spinner if mktemp fails

run_with_spinner() {
    local msg="$1"
    shift
    local pid tmp_out exit_code=0
    local spin_idx=0 start_ts now_ts elapsed

    tmp_out="$(mktemp)" || { log WARN "mktemp failed, running without spinner"; "$@"; return $?; }
    start_ts="$(date +%s)"

    log STEP "$msg" 2>/dev/null || true

    # Run command in background, capture all output
    "$@" >"$tmp_out" 2>&1 &
    pid=$!

    # Show spinner while command runs
    printf "  %s " "$msg"
    while kill -0 "$pid" 2>/dev/null; do
        now_ts="$(date +%s)"
        elapsed=$((now_ts - start_ts))
        printf "\r  %s %s (%ds)" "$msg" "${SPINNER_CHARS:spin_idx++%${#SPINNER_CHARS}:1}" "$elapsed"
        sleep 0.1
    done

    # Capture exit code (|| prevents set -e from killing before cleanup)
    wait "$pid" || exit_code=$?

    # Append command output to log file
    if [[ -n "${LOG_FILE:-}" ]] && [[ -w "${LOG_FILE:-}" ]]; then
        cat "$tmp_out" >> "$LOG_FILE" 2>/dev/null || true
    fi
    rm -f "$tmp_out"

    # Show result with elapsed time
    now_ts="$(date +%s)"
    elapsed=$((now_ts - start_ts))
    if [[ $exit_code -eq 0 ]]; then
        printf "\r  %s %s (%ds)\n" "$msg" "${C_GREEN}${SYMBOL_SUCCESS}${C_RESET}" "$elapsed"
    else
        printf "\r  %s %s (%ds)\n" "$msg" "${C_RED}${SYMBOL_ERROR}${C_RESET}" "$elapsed"
    fi

    return $exit_code
}

#############################################################################
# Configuration Variables                                                   #
#############################################################################

readonly WORK_DIR="$HOME/npm"
readonly SECRETS_DIR="$WORK_DIR/.secrets"
readonly DEFAULT_TZ="Europe/Berlin"
readonly MIN_PORT=49152
readonly MAX_PORT=65535

#############################################################################
# Setup Logging                                                             #
#############################################################################

setup_logging() {
    # Create log directory with sudo
    if [[ ! -d "$LOG_DIR" ]]; then
        sudo mkdir -p "$LOG_DIR" 2>/dev/null || true
    fi
    
    # Create log file and set ownership to current user
    sudo touch "$LOG_FILE" 2>/dev/null || true
    sudo chown "$(whoami):$(id -gn)" "$LOG_FILE" 2>/dev/null || true
    sudo chmod 644 "$LOG_FILE" 2>/dev/null || true
    
    log INFO "=== ${SCRIPT_NAME} Started ==="
    log INFO "Version: $SCRIPT_VERSION"
    log INFO "User: $(whoami)"
    log INFO "Date: $(date)"
}

#############################################################################
# Pre-flight Checks                                                         #
#############################################################################

preflight_checks() {
    print_header "Pre-flight Checks"
    
    # CRITICAL: Enforce non-root execution
    if [[ ${EUID} -eq 0 ]]; then
        echo
        print_error "This script must NOT be run as root!"
        echo
        print_info "Correct usage:"
        echo "  ${C_CYAN}./$(basename "$0")${C_RESET}"
        echo
        print_info "The script will use sudo internally when needed."
        echo
        die "Execution blocked: Running as root user"
    fi
    print_success "Running as non-root user: ${C_BOLD}$(whoami)${C_RESET}"
    
    # sudo must exist on minimal images
    if ! command_exists sudo; then
        echo
        print_error "sudo is not installed. This script requires sudo."
        echo
        print_info "Fix (run as root):"
        echo "  apt-get update && apt-get install -y sudo"
        echo "  usermod -aG sudo $(whoami)"
        echo "  # then logout/login"
        echo
        die "Execution blocked: sudo not installed"
    fi
    
    # Verify sudo access (may prompt)
    if ! sudo -v 2>/dev/null; then
        echo
        print_error "User $(whoami) does not have sudo privileges"
        echo
        print_info "To grant sudo access (run as root):"
        echo "  ${C_CYAN}usermod -aG sudo $(whoami)${C_RESET}"
        echo "  ${C_CYAN}# then logout/login${C_RESET}"
        echo
        die "Execution blocked: No sudo privileges"
    fi
    print_success "Sudo privileges confirmed"
    
    # Check if running on PVE host (should not be)
    if [[ -f /etc/pve/.version ]] || command_exists pveversion; then
        die "This script must not run on the Proxmox VE host. Run inside a VM or LXC container."
    fi
    print_success "Not running on Proxmox host"
    
    # Check for systemd (required)
    if ! command_exists systemctl; then
        die "systemd not found (is this container systemd-enabled?)"
    fi
    print_success "systemd available"
    
    # Check OS (warn if not Debian)
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "${ID:-}" != "debian" ]]; then
            print_warning "Designed for Debian. Detected: ${ID:-unknown}"
        else
            print_success "Debian detected: ${VERSION:-unknown}"
        fi
    else
        print_warning "Cannot determine OS version (/etc/os-release missing)"
    fi
    
    # Check internet connectivity (multiple methods for minimal systems)
    print_step "Testing internet connectivity..."
    local internet_ok=false
    
    if command_exists curl; then
        if curl -s --max-time 5 --head https://deb.debian.org >/dev/null 2>&1; then
            print_success "Internet connectivity verified (curl)"
            internet_ok=true
        fi
    fi
    
    if [[ "$internet_ok" == false ]] && command_exists wget; then
        if wget -q --timeout=5 --spider https://deb.debian.org 2>/dev/null; then
            print_success "Internet connectivity verified (wget)"
            internet_ok=true
        fi
    fi
    
    if [[ "$internet_ok" == false ]]; then
        # Bash built-in TCP check (no external tools)
        if timeout 5 bash -c 'cat < /dev/null > /dev/tcp/deb.debian.org/80' 2>/dev/null; then
            print_success "Internet connectivity verified (dev/tcp)"
            internet_ok=true
        fi
    fi
    
    if [[ "$internet_ok" == false ]]; then
        print_warning "Could not verify internet with available tools"
        print_info "Will verify connectivity during package installation..."
    fi
    
    # Check if ports 80/443 are available
    check_port_availability 80 443
    
    echo
}

#############################################################################
# Install Missing Prerequisites                                             #
#############################################################################

install_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Packages that should already be installed by hardening.sh
    # but we check anyway for standalone usage
    local required_packages=(
        curl
        wget
        ca-certificates
        gnupg
        lsb-release
    )
    
    local missing_packages=()
    
    for pkg in "${required_packages[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            print_success "Package installed: $pkg"
        else
            missing_packages+=("$pkg")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        if ! run_with_spinner "Updating package lists" sudo apt-get update -y; then
            die "Failed to update package lists"
        fi
        if ! run_with_spinner "Installing prerequisites: ${missing_packages[*]}" sudo apt-get install -y "${missing_packages[@]}"; then
            die "Failed to install prerequisites"
        fi
    fi
    
    echo
}

#############################################################################
# Docker Installation (idempotent)                                          #
#############################################################################

get_docker_codename() {
    # Check for manual override first
    local override_val="${DOCKER_DIST:-}"
    if [[ -n "$override_val" ]]; then
        echo "$override_val"
        return 0
    fi
    
    # Detect system codename from /etc/os-release
    local detected=""
    if [[ -f /etc/os-release ]]; then
        detected="$(grep '^VERSION_CODENAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
    fi
    
    # Fallback to lsb_release if os-release didn't work
    [[ -z "$detected" ]] && detected="$(lsb_release -cs 2>/dev/null || echo "")"
    
    # Test if Docker repo exists for detected codename
    if [[ -n "$detected" ]]; then
        local test_url="https://download.docker.com/linux/debian/dists/${detected}/Release"
        if curl -sSf --head --max-time 5 "$test_url" >/dev/null 2>&1; then
            echo "$detected"
            return 0
        fi
        echo "INFO: Docker repo not found for '$detected', falling back to bookworm" >&2
    fi
    
    echo "bookworm"
}

install_docker() {
    print_header "Docker Installation"
    
    # Check if Docker is already installed and working
    if command_exists docker && sudo docker info >/dev/null 2>&1; then
        print_success "Docker is already installed and running"
        sudo docker --version
        sudo docker compose version
        echo
        return 0
    fi
    
    local need_apt_update=true
    
    # Handle apt locks and unattended-upgrades
    prepare_apt
    
    # Docker GPG key
    print_step "Setting up Docker repository..."
    sudo mkdir -p /etc/apt/keyrings
    
    if [[ ! -s /etc/apt/keyrings/docker.gpg ]]; then
        print_subheader "Adding Docker GPG key..."
        curl -fsSL https://download.docker.com/linux/debian/gpg | \
            sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
    else
        print_success "Docker GPG key already present"
    fi
    
    # Docker repository
    local docker_list="/etc/apt/sources.list.d/docker.list"
    local arch="$(dpkg --print-architecture)"
    local codename="$(get_docker_codename)"
    local desired_line="deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${codename} stable"
    
    print_kv "Architecture" "$arch"
    print_kv "Codename" "$codename"
    
    if [[ -f "$docker_list" ]] && grep -Fqx "$desired_line" "$docker_list"; then
        print_success "Docker repository already configured"
        need_apt_update=false
    else
        print_subheader "Configuring Docker repository..."
        echo "$desired_line" | sudo tee "$docker_list" >/dev/null
    fi
    
    # Install Docker packages
    local docker_packages=(
        docker-ce
        docker-ce-cli
        containerd.io
        docker-buildx-plugin
        docker-compose-plugin
    )
    
    print_step "Installing Docker packages..."
    
    for pkg in "${docker_packages[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            print_success "Already installed: $pkg"
        else
            if [[ "$need_apt_update" == true ]]; then
                if ! run_with_spinner "Updating package lists" sudo apt-get update -y; then
                    die "Failed to update package lists"
                fi
                need_apt_update=false
            fi
            if ! run_with_spinner "Installing: $pkg" sudo apt-get install -y "$pkg"; then
                die "Failed to install $pkg"
            fi
        fi
    done
    
    # Enable and start Docker
    print_step "Enabling Docker service..."
    sudo systemctl enable --now docker >/dev/null 2>&1
    print_success "Docker service enabled and started"
    
    # Add user to docker group
    local user_name="$(id -un)"
    if id -nG "$user_name" | tr ' ' '\n' | grep -qx docker; then
        print_success "User already in docker group: $user_name"
    else
        print_step "Adding user to docker group..."
        sudo usermod -aG docker "$user_name"
        print_warning "Group membership active after logout/login or: newgrp docker"
    fi
    
    # Verify installation
    print_step "Verifying Docker installation..."
    if sudo docker --version && sudo docker compose version; then
        print_success "Docker and Docker Compose are working"
    else
        die "Docker installation verification failed"
    fi
    
    echo
}

#############################################################################
# Backup Helper                                                             #
#############################################################################

backup_if_exists() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    local backup="${file}.$(date +%Y%m%d-%H%M%S).bak"
    cp -a "$file" "$backup"
    print_info "Backed up: ${file/$HOME/~} → ${backup/$HOME/~}"
}

#############################################################################
# NPM Directory Setup                                                       #
#############################################################################

setup_npm_directories() {
    print_header "Setting Up NPM Directory Structure"
    
    local directories=(
        "$WORK_DIR"
        "$SECRETS_DIR"
        "$WORK_DIR/data"
        "$WORK_DIR/letsencrypt"
        "$WORK_DIR/mysql"
    )
    
    for dir in "${directories[@]}"; do
        if [[ -d "$dir" ]]; then
            print_success "Directory exists: ${dir/$HOME/~}"
        else
            mkdir -p "$dir"
            print_success "Created: ${dir/$HOME/~}"
        fi
    done
    
    # Set proper permissions
    chmod 700 "$SECRETS_DIR"
    print_success "Secrets directory secured (700)"
    
    echo
}

#############################################################################
# Generate Secrets                                                          #
#############################################################################

# Generate secure password of exact length (loop ensures we always get enough)
generate_password() {
    local length="${1:-35}"
    local password=""
    while [[ ${#password} -lt $length ]]; do
        password+=$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' 2>/dev/null || true)
    done
    printf '%s' "${password:0:$length}"
}

generate_secrets() {
    print_header "Generating Database Credentials"
    
    ensure_secret "$SECRETS_DIR/db_root_pwd.secret" 35 "DB root password"
    ensure_secret "$SECRETS_DIR/mysql_pwd.secret" 35 "MySQL user password"
    
    echo
}

# Idempotent + atomic secret creation helper (never prints secret values)
ensure_secret() {
    local file="$1"
    local length="${2:-35}"
    local label="${3:-secret}"

    if [[ -f "$file" ]] && [[ -s "$file" ]]; then
        log INFO "${label} already exists (not regenerating)"
        return 0
    fi

    # Write atomically to avoid partial secrets on interruption
    local tmp
    tmp="$(mktemp "${file}.tmp.XXXXXX")"
    generate_password "$length" > "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$file"

    log SUCCESS "Generated ${label}"
}

#############################################################################
# User Configuration Input                                                  #
#############################################################################

get_user_configuration() {
    print_header "Configuration"
    
    # Timezone selection
    print_step "Configuring timezone..."
    
    # Check for environment variable override
    if [[ -n "${NPM_TZ:-}" ]]; then
        TIMEZONE="$NPM_TZ"
        print_success "Using timezone from environment: $TIMEZONE"
    elif is_silent; then
        TIMEZONE="$DEFAULT_TZ"
        print_success "Silent mode - using default timezone: $TIMEZONE"
    else
        # Get list of timezones
        if command_exists timedatectl; then
            local tzones
            tzones="$(timedatectl list-timezones 2>/dev/null)" || true
            
            echo
            print_info "Enter timezone (default: ${C_CYAN}$DEFAULT_TZ${C_RESET})"
            print_subheader "Examples: Europe/London, America/New_York, Asia/Tokyo"
            echo
            
            while true; do
                printf "%b" "${C_CYAN}Timezone: ${C_RESET}"
                read -r TIMEZONE
                
                # Use default if empty
                if [[ -z "$TIMEZONE" ]]; then
                    TIMEZONE="$DEFAULT_TZ"
                fi
                
                # Validate timezone
                if echo "$tzones" | grep -qx "$TIMEZONE"; then
                    print_success "Timezone selected: $TIMEZONE"
                    break
                else
                    print_error "Invalid timezone. Please try again."
                fi
            done
        else
            TIMEZONE="$DEFAULT_TZ"
            print_warning "timedatectl not available, using default: $TIMEZONE"
        fi
    fi
    
    echo
    
    # Port selection
    print_step "Configuring admin port..."
    
    if [[ -n "${NPM_PORT:-}" ]]; then
        ADMIN_PORT="$NPM_PORT"
        print_success "Using port from environment: $ADMIN_PORT"
    elif is_silent; then
        ADMIN_PORT="$MIN_PORT"
        print_success "Silent mode - using default port: $ADMIN_PORT"
    else
        print_info "NPM admin interface port (${C_CYAN}${MIN_PORT}-${MAX_PORT}${C_RESET})"
        print_subheader "This is for the web UI, not for proxied services"
        echo
        
        while true; do
            printf "%b" "${C_CYAN}Admin Port: ${C_RESET}"
            read -r ADMIN_PORT
            
            # Validate port number
            if [[ "$ADMIN_PORT" =~ ^[0-9]+$ ]] && \
               [[ "$ADMIN_PORT" -ge "$MIN_PORT" ]] && \
               [[ "$ADMIN_PORT" -le "$MAX_PORT" ]]; then
                
                # Check if port is in use
                if ss -tuln 2>/dev/null | grep -q ":${ADMIN_PORT} "; then
                    print_warning "Port $ADMIN_PORT is already in use"
                    print_info "Choose a different port or ensure the service is stopped"
                    continue
                fi
                
                print_success "Admin port selected: $ADMIN_PORT"
                break
            else
                print_error "Invalid port. Enter a number between $MIN_PORT and $MAX_PORT"
            fi
        done
    fi
    
    echo
}

#############################################################################
# Create Docker Compose File                                                #
#############################################################################

create_docker_compose() {
    print_header "Creating Docker Compose Configuration"
    
    local compose_file="$WORK_DIR/docker-compose.yml"
    
    # Backup existing file if present
    backup_if_exists "$compose_file"
    
    print_step "Writing docker-compose.yml..."
    
    cat > "$compose_file" << 'COMPOSE_EOF'
# Nginx Proxy Manager Stack
# Generated by npm.sh - https://github.com/vdarkobar/lab

networks:
  npm:
    name: npm
    driver: bridge

secrets:
  DB_ROOT_PWD:
    file: .secrets/db_root_pwd.secret
  MYSQL_PWD:
    file: .secrets/mysql_pwd.secret

services:

  # Nginx Proxy Manager - Expose your services easily and securely
  app:
    image: jc21/nginx-proxy-manager:latest
    restart: unless-stopped
    networks:
      - npm
    ports:
      - "80:80"
      - "${NPM_ADMIN_PORT}:81"
      - "443:443"
    environment:
      - DB_MYSQL_HOST=db
      - DB_MYSQL_PORT=3306
      - DB_MYSQL_USER=npm_user
      - DB_MYSQL_PASSWORD__FILE=/run/secrets/MYSQL_PWD
      - DB_MYSQL_NAME=npm_db
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
    secrets:
      - MYSQL_PWD
    depends_on:
      - db
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

  # MariaDB - Database backend for NPM
  db:
    image: jc21/mariadb-aria:latest
    restart: unless-stopped
    networks:
      - npm
    environment:
      - MYSQL_ROOT_PASSWORD__FILE=/run/secrets/DB_ROOT_PWD
      - MYSQL_DATABASE=npm_db
      - MYSQL_USER=npm_user
      - MYSQL_PASSWORD__FILE=/run/secrets/MYSQL_PWD
    volumes:
      - ./mysql:/var/lib/mysql
    secrets:
      - DB_ROOT_PWD
      - MYSQL_PWD
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

  # Watchtower - Automatic container updates (label-enabled, only updates labeled containers)
  watchtower:
    image: containrrr/watchtower:latest
    container_name: watchtower
    restart: always
    networks:
      - npm
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - TZ=${NPM_TZ}
      - DOCKER_API_VERSION=${DOCKER_API_VERSION}
      - WATCHTOWER_DEBUG=false
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_REMOVE_VOLUMES=false
      - WATCHTOWER_INCLUDE_STOPPED=true
      - WATCHTOWER_LABEL_ENABLE=true
      - WATCHTOWER_SCHEDULE=0 30 5 * * *
COMPOSE_EOF

    print_success "Created: ${compose_file/$HOME/~}"
    echo
}

#############################################################################
# Create Environment File                                                   #
#############################################################################

create_env_file() {
    print_step "Creating environment file..."
    
    local env_file="$WORK_DIR/.env"
    
    # Backup existing file if present
    backup_if_exists "$env_file"
    
    # Detect Docker API version for Watchtower compatibility
    local docker_api_version
    docker_api_version=$(sudo docker version --format '{{.Server.APIVersion}}' 2>/dev/null || echo "1.44")
    
    cat > "$env_file" << EOF
# NPM Environment Configuration
# Generated by npm.sh
# Using namespaced variables to avoid conflicts with shell environment

COMPOSE_PROJECT_NAME=npm
NPM_TZ=${TIMEZONE}
NPM_ADMIN_PORT=${ADMIN_PORT}
DOCKER_API_VERSION=${docker_api_version}
EOF

    chmod 600 "$env_file"
    print_success "Created: ${env_file/$HOME/~}"
    print_kv "Timezone" "$TIMEZONE"
    print_kv "Admin Port" "$ADMIN_PORT"
    print_kv "Docker API" "$docker_api_version"
    
    echo
}

#############################################################################
# Configure Firewall                                                        #
#############################################################################

configure_firewall() {
    print_header "Configuring Firewall"
    
    if [[ "${SKIP_FIREWALL:-false}" == "true" ]]; then
        log INFO "Firewall configuration skipped (NPM_SKIP_UFW=true)"
        echo
        return 0
    fi
    
    # Test if UFW is available and functional
    local ufw_status
    if ! ufw_status=$(sudo ufw status 2>&1); then
        log WARN "UFW not available or not functional"
        log INFO "Output: $ufw_status"
        log INFO "Configure firewall on the host instead"
        log INFO "Required ports: 80/tcp, 443/tcp, ${ADMIN_PORT}/tcp"
        echo
        return 0
    fi
    
    # Check if UFW is active
    if ! echo "$ufw_status" | grep -q "Status: active"; then
        log INFO "UFW is not active - skipping firewall configuration"
        log INFO "To enable UFW manually: sudo ufw enable"
        echo
        return 0
    fi
    
    log SUCCESS "UFW is active"
    print_step "Adding firewall rules..."
    
    # Allow HTTP (port 80)
    if echo "$ufw_status" | grep -qE "80/tcp.*ALLOW"; then
        log SUCCESS "Port 80/tcp already allowed"
    else
        if sudo ufw allow 80/tcp comment "NPM HTTP" >/dev/null 2>&1; then
            log SUCCESS "Allowed port 80/tcp (NPM HTTP)"
        else
            if sudo ufw allow 80/tcp >/dev/null 2>&1; then
                log SUCCESS "Allowed port 80/tcp"
            else
                log WARN "Failed to add UFW rule for port 80/tcp"
            fi
        fi
    fi
    
    # Allow HTTPS (port 443)
    if echo "$ufw_status" | grep -qE "443/tcp.*ALLOW"; then
        log SUCCESS "Port 443/tcp already allowed"
    else
        if sudo ufw allow 443/tcp comment "NPM HTTPS" >/dev/null 2>&1; then
            log SUCCESS "Allowed port 443/tcp (NPM HTTPS)"
        else
            if sudo ufw allow 443/tcp >/dev/null 2>&1; then
                log SUCCESS "Allowed port 443/tcp"
            else
                log WARN "Failed to add UFW rule for port 443/tcp"
            fi
        fi
    fi
    
    # Allow admin port (user-defined)
    if echo "$ufw_status" | grep -qE "${ADMIN_PORT}/tcp.*ALLOW"; then
        log SUCCESS "Port ${ADMIN_PORT}/tcp already allowed"
    else
        if sudo ufw allow "${ADMIN_PORT}/tcp" comment "NPM Admin UI" >/dev/null 2>&1; then
            log SUCCESS "Allowed port ${ADMIN_PORT}/tcp (NPM Admin UI)"
        else
            if sudo ufw allow "${ADMIN_PORT}/tcp" >/dev/null 2>&1; then
                log SUCCESS "Allowed port ${ADMIN_PORT}/tcp"
            else
                log WARN "Failed to add UFW rule for port ${ADMIN_PORT}/tcp"
            fi
        fi
    fi
    
    log SUCCESS "Firewall configuration complete"
    echo
}

#############################################################################
# Start Docker Compose                                                      #
#############################################################################

start_docker_compose() {
    print_header "Deploy NPM Stack"
    
    local do_start=false
    
    if is_silent; then
        do_start=true
        print_info "Silent mode - starting NPM stack automatically"
    else
        echo
        print_info "Ready to start the NPM stack"
        print_subheader "This will pull images and start containers"
        echo
        
        while true; do
            printf "%b" "${C_CYAN}${C_BOLD}Start NPM now?${C_RESET} ${C_DIM}(yes/no)${C_RESET} "
            read -r response
            response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
            
            case "$response" in
                yes|y) do_start=true; break ;;
                no|n)
                    print_info "Stack not started"
                    print_info "Start manually with: cd $WORK_DIR && sudo docker compose up -d"
                    return 0
                    ;;
                *) print_error "Please answer 'yes' or 'no'" ;;
            esac
        done
    fi
    
    if [[ "$do_start" == true ]]; then
        echo
        print_step "Starting NPM stack..."
        print_info "This may take a few minutes on first run..."
        echo
        
        cd "$WORK_DIR"
        
        # Test if docker works without sudo (group may not be active in current session)
        if docker info >/dev/null 2>&1; then
            if docker compose up -d; then
                print_success "NPM stack started successfully"
            else
                print_error "Docker compose failed"
                print_info "Check logs with: docker compose -f $WORK_DIR/docker-compose.yml logs"
                return 1
            fi
        else
            if sudo docker compose up -d; then
                print_success "NPM stack started successfully"
            else
                print_error "Docker compose failed"
                print_info "Check logs with: sudo docker compose -f $WORK_DIR/docker-compose.yml logs"
                return 1
            fi
        fi
        
        echo
        print_step "Waiting for services to be ready..."
        sleep 10
        
        # Check container status
        print_step "Checking container status..."
        if docker info >/dev/null 2>&1; then
            docker compose ps
        else
            sudo docker compose ps
        fi
    fi
}

#############################################################################
# Show Summary                                                              #
#############################################################################

show_summary() {
    local ip_address
    ip_address=$(get_local_ip)
    
    echo
    draw_box "Installation Complete"
    
    echo
    print_header "NPM Access Information"
    print_kv "Admin URL" "http://${ip_address}:${ADMIN_PORT}"
    print_kv "HTTP Proxy" "http://${ip_address}:80"
    print_kv "HTTPS Proxy" "https://${ip_address}:443"
    
    echo
    print_header "First Time Setup"
    print_info "Open the Admin URL in your browser"
    print_info "You will be prompted to create an admin account"
    
    echo
    print_header "Management Commands"
    printf "  %b\n" "${C_DIM}# Check status${C_RESET}"
    printf "  %b\n" "${C_CYAN}./npm-docker.sh --status${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}./npm-docker.sh --logs${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Reconfigure${C_RESET}"
    printf "  %b\n" "${C_CYAN}./npm-docker.sh --configure${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart stack${C_RESET}"
    printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose restart${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Update containers${C_RESET}"
    printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose pull && sudo docker compose up -d${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Uninstall${C_RESET}"
    printf "  %b\n" "${C_CYAN}./npm-docker.sh --uninstall${C_RESET}"
    
    echo
    print_header "File Locations"
    print_kv "Working Directory" "$WORK_DIR"
    print_kv "Compose File" "$WORK_DIR/docker-compose.yml"
    print_kv "Environment" "$WORK_DIR/.env"
    print_kv "Secrets" "$SECRETS_DIR/"
    print_kv "SSL Certificates" "$WORK_DIR/letsencrypt/"
    print_kv "Installation Log" "$LOG_FILE"
    
    echo
    draw_separator
    echo
    
    log INFO "=== ${SCRIPT_NAME} Installation Completed ==="
}

#############################################################################
# Post-Install Commands                                                     #
#############################################################################

cmd_status() {
    print_header "Nginx Proxy Manager Status"
    
    # Read config from .env if it exists
    local admin_port="unknown"
    if [[ -f "$WORK_DIR/.env" ]]; then
        admin_port=$(grep '^NPM_ADMIN_PORT=' "$WORK_DIR/.env" 2>/dev/null | cut -d= -f2) || true
    fi
    
    local ip_address
    ip_address=$(get_local_ip)
    
    print_kv "Script Version" "$SCRIPT_VERSION"
    print_kv "Working Directory" "$WORK_DIR"
    echo
    
    # Container status
    print_header "Container Status"
    if docker info >/dev/null 2>&1; then
        cd "$WORK_DIR" && docker compose ps 2>/dev/null || print_warning "Could not get container status"
    else
        cd "$WORK_DIR" && sudo docker compose ps 2>/dev/null || print_warning "Could not get container status"
    fi
    
    echo
    print_header "Access Information"
    print_kv "Admin URL" "http://${ip_address}:${admin_port}"
    print_kv "HTTP Proxy" "http://${ip_address}:80"
    print_kv "HTTPS Proxy" "https://${ip_address}:443"
    
    echo
}

cmd_logs() {
    local lines="${1:-50}"
    
    print_header "NPM Logs (last $lines lines)"
    echo
    
    if docker info >/dev/null 2>&1; then
        cd "$WORK_DIR" && docker compose logs --tail="$lines"
    else
        cd "$WORK_DIR" && sudo docker compose logs --tail="$lines"
    fi
}

cmd_configure() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Reconfigure NPM"
    
    if [[ ! -f "$WORK_DIR/docker-compose.yml" ]]; then
        die "NPM is not installed (no docker-compose.yml found)"
    fi
    
    print_warning "This will replace the current configuration."
    
    if ! is_silent; then
        echo
        while true; do
            echo -n "${C_BOLD}${C_CYAN}Continue? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
            
            case "$choice" in
                yes|y) break ;;
                no|n)
                    print_info "Reconfiguration cancelled"
                    exit 0
                    ;;
                *) print_error "Invalid input. Please enter 'yes' or 'no'" ;;
            esac
        done
    fi
    
    # Re-run configuration
    get_user_configuration
    create_env_file
    
    # Restart stack with new config
    print_step "Restarting NPM stack..."
    if docker info >/dev/null 2>&1; then
        cd "$WORK_DIR" && docker compose up -d
    else
        cd "$WORK_DIR" && sudo docker compose up -d
    fi
    
    log SUCCESS "Configuration updated successfully"
}

cmd_uninstall() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Uninstall Nginx Proxy Manager"
    
    if [[ ! -d "$WORK_DIR" ]]; then
        print_info "NPM is not installed (directory ~/npm not found)"
        exit 0
    fi
    
    print_warning "This will remove:"
    print_subheader "Docker containers and images"
    print_subheader "NPM directory (~/$WORK_DIR)"
    print_subheader "Database and configuration"
    print_subheader "SSL certificates"
    
    if ! is_silent; then
        echo
        while true; do
            echo -n "${C_BOLD}${C_RED}Are you sure? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
            
            case "$choice" in
                yes|y) break ;;
                no|n)
                    print_info "Uninstall cancelled"
                    exit 0
                    ;;
                *) print_error "Invalid input. Please enter 'yes' or 'no'" ;;
            esac
        done
    fi
    
    # Stop and remove containers
    print_step "Stopping containers..."
    if docker info >/dev/null 2>&1; then
        cd "$WORK_DIR" && docker compose down --remove-orphans 2>/dev/null || true
    else
        cd "$WORK_DIR" && sudo docker compose down --remove-orphans 2>/dev/null || true
    fi
    
    # Remove NPM directory
    print_step "Removing NPM directory..."
    cd "$HOME"
    rm -rf "$WORK_DIR"
    
    # Remove firewall rules (only if UFW active)
    if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        print_step "Removing firewall rules..."
        sudo ufw delete allow 80/tcp 2>/dev/null || true
        sudo ufw delete allow 443/tcp 2>/dev/null || true
        # Try to remove admin port rule if .env was readable
        # (already removed with directory, so best-effort only)
    fi
    
    log SUCCESS "Nginx Proxy Manager has been removed"
    echo
}

#############################################################################
# Cleanup / Restore Services                                                #
#############################################################################

cleanup() {
    local exit_code=$?
    
    # Restart unattended-upgrades if we stopped it
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == true ]]; then
        if sudo systemctl start unattended-upgrades 2>/dev/null; then
            print_info "Restarted unattended-upgrades service"
        fi
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        log ERROR "Installation failed - check log: $LOG_FILE"
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

#############################################################################
# Main Execution                                                            #
#############################################################################

main() {
    # Handle post-install commands
    case "${1:-}" in
        --status)    cmd_status; exit 0 ;;
        --logs)      cmd_logs "${2:-50}"; exit 0 ;;
        --configure) cmd_configure; exit 0 ;;
        --uninstall) cmd_uninstall; exit 0 ;;
        --version|-v) echo "${SCRIPT_NAME}.sh v${SCRIPT_VERSION}"; exit 0 ;;
        "") ;;  # Continue with installation
        *) die "Unknown option: $1 (use --help for usage)" ;;
    esac
    
    # Early sudo check (before logging)
    if ! command_exists sudo; then
        echo "ERROR: sudo is not installed" >&2
        exit 1
    fi
    if [[ ${EUID} -eq 0 ]]; then
        echo "ERROR: Do not run as root" >&2
        exit 1
    fi
    if ! sudo -v 2>/dev/null; then
        echo "ERROR: No sudo privileges" >&2
        exit 1
    fi
    
    # Check if already installed (idempotency)
    if [[ -d "$HOME/npm" ]] && [[ -f "$HOME/npm/docker-compose.yml" ]]; then
        # Clear screen if running directly
        [[ "${BASH_SOURCE[0]}" == "${0}" ]] && clear || true
        
        draw_box "Nginx Proxy Manager — Already Installed"
        echo
        print_warning "NPM directory already exists: ~/npm"
        
        echo
        print_header "Management Commands"
        printf "  %b\n" "${C_DIM}# Check status${C_RESET}"
        printf "  %b\n" "${C_CYAN}./npm-docker.sh --status${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
        printf "  %b\n" "${C_CYAN}./npm-docker.sh --logs${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# Reconfigure${C_RESET}"
        printf "  %b\n" "${C_CYAN}./npm-docker.sh --configure${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# Restart stack${C_RESET}"
        printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose restart${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# Update containers${C_RESET}"
        printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose pull && sudo docker compose up -d${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# Uninstall${C_RESET}"
        printf "  %b\n" "${C_CYAN}./npm-docker.sh --uninstall${C_RESET}"
        echo
        
        print_info "To reinstall, first remove the existing installation:"
        printf "  %b\n" "${C_CYAN}./npm-docker.sh --uninstall${C_RESET}"
        echo
        exit 0
    fi
    
    # Handle incomplete installation
    if [[ -d "$HOME/npm" ]]; then
        print_warning "Incomplete NPM installation detected (missing docker-compose.yml)"
        print_info "To clean up and reinstall:"
        printf "  %b\n" "${C_CYAN}rm -rf ~/npm && ./npm-docker.sh${C_RESET}"
        echo
        exit 0
    fi
    
    # Clear screen if running directly
    [[ "${BASH_SOURCE[0]}" == "${0}" ]] && clear || true
    
    draw_box "Nginx Proxy Manager Installer v${SCRIPT_VERSION}"
    
    # Setup logging
    setup_logging
    
    # Run installation steps
    preflight_checks
    install_prerequisites
    install_docker
    setup_npm_directories
    generate_secrets
    get_user_configuration
    create_docker_compose
    create_env_file
    configure_firewall
    start_docker_compose
    show_summary
}

# Run main function
main "$@"
