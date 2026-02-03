#!/bin/bash

#############################################################################
# Nginx Proxy Manager Installation Script                                   #
# Installs Docker + Compose and deploys NPM with MariaDB                   #
#############################################################################

readonly SCRIPT_VERSION="1.0.0"

# Handle --help flag early (before sourcing libraries)
case "${1:-}" in
    --help|-h)
        echo "Nginx Proxy Manager Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help]"
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
        echo "  NPM_PORT=<port>          Pre-set admin port (49152-65535)"
        echo "  NPM_TZ=<timezone>        Pre-set timezone (e.g., Europe/Berlin)"
        echo
        echo "Files created:"
        echo "  ~/npm/docker-compose.yml         Docker Compose configuration"
        echo "  ~/npm/.env                       Environment variables"
        echo "  ~/npm/.secrets/                  Database credentials"
        echo "  ~/npm/data/                      NPM application data"
        echo "  ~/npm/letsencrypt/               SSL certificates"
        echo "  ~/npm/mysql/                     MariaDB data"
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

# Secure file creation by default
umask 077

# Track services we stop (to restart later)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    readonly C_BLACK=$(tput setaf 0)
    readonly C_RED=$(tput setaf 1)
    readonly C_GREEN=$(tput setaf 2)
    readonly C_YELLOW=$(tput setaf 3)
    readonly C_BLUE=$(tput setaf 4)
    readonly C_MAGENTA=$(tput setaf 5)
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
    readonly C_BLACK=""
    readonly C_RED=""
    readonly C_GREEN=""
    readonly C_YELLOW=""
    readonly C_BLUE=""
    readonly C_MAGENTA=""
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
    print_error "$@"
    exit 1
}

# Error trap for better debugging (set after print_error is defined)
trap 'print_error "Error on line $LINENO: $BASH_COMMAND"' ERR

#############################################################################
# Configuration Variables                                                   #
#############################################################################

readonly WORK_DIR="$HOME/npm"
readonly SECRETS_DIR="$WORK_DIR/.secrets"
readonly DEFAULT_TZ="Europe/Berlin"
readonly MIN_PORT=49152
readonly MAX_PORT=65535

#############################################################################
# Pre-flight Checks                                                         #
#############################################################################

preflight_checks() {
    print_header "Pre-flight Checks"
    
    # Must not run as root
    if [[ ${EUID} -eq 0 ]]; then
        print_error "This script must NOT be run as root!"
        print_info "Correct usage: ${C_CYAN}./$(basename "$0")${C_RESET}"
        die "Execution blocked: Running as root user"
    fi
    print_success "Running as non-root user: ${C_BOLD}$(whoami)${C_RESET}"
    
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "User $(whoami) does not have sudo privileges"
    fi
    print_success "Sudo privileges confirmed"
    
    # Check if running on PVE host
    if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
        die "This script should not run on Proxmox VE host. Run inside a VM or LXC."
    fi
    print_success "Not running on Proxmox host"
    
    # Check internet connectivity (try multiple methods for minimal systems)
    # Use download.docker.com as it's more representative of actual needs
    print_step "Testing internet connectivity..."
    local internet_ok=false
    
    # Method 1: curl (if available)
    if command -v curl >/dev/null 2>&1; then
        if curl -s --max-time 5 --head https://download.docker.com >/dev/null 2>&1; then
            print_success "Internet connectivity verified (curl)"
            internet_ok=true
        fi
    fi
    
    # Method 2: wget (if available)
    if [[ "$internet_ok" == false ]] && command -v wget >/dev/null 2>&1; then
        if wget -q --timeout=5 --spider https://download.docker.com 2>/dev/null; then
            print_success "Internet connectivity verified (wget)"
            internet_ok=true
        fi
    fi
    
    # Method 3: Bash /dev/tcp (built-in, no external tools needed)
    if [[ "$internet_ok" == false ]]; then
        if (echo >/dev/tcp/download.docker.com/443) 2>/dev/null; then
            print_success "Internet connectivity verified (tcp)"
            internet_ok=true
        fi
    fi
    
    # Method 4: If all methods fail, warn but continue - let apt-get be the real test
    if [[ "$internet_ok" == false ]]; then
        print_warning "Could not verify internet with available tools"
        print_info "Will verify connectivity when installing packages..."
    fi
    
    # Check if ports 80/443 are available
    print_step "Checking port availability..."
    local ports_in_use=()
    
    # Only check if ss or netstat is available
    if command -v ss >/dev/null 2>&1; then
        for port in 80 443; do
            if ss -tuln 2>/dev/null | grep -q ":${port} "; then
                ports_in_use+=("$port")
            fi
        done
    elif command -v netstat >/dev/null 2>&1; then
        for port in 80 443; do
            if netstat -tuln 2>/dev/null | grep -q ":${port} "; then
                ports_in_use+=("$port")
            fi
        done
    else
        print_warning "Cannot check ports (ss/netstat not available)"
    fi
    
    if [[ ${#ports_in_use[@]} -gt 0 ]]; then
        print_warning "Ports already in use: ${ports_in_use[*]}"
        print_info "NPM requires ports 80 and 443. Ensure they're free before starting."
    elif command -v ss >/dev/null 2>&1 || command -v netstat >/dev/null 2>&1; then
        print_success "Ports 80 and 443 are available"
    fi
    
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
        print_step "Installing missing packages: ${missing_packages[*]}"
        sudo apt-get update >/dev/null 2>&1
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_packages[@]}" >/dev/null 2>&1
        print_success "Missing packages installed"
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
    if command -v docker >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
        print_success "Docker is already installed and running"
        sudo docker --version
        sudo docker compose version
        echo
        return 0
    fi
    
    local need_apt_update=true
    
    # Stop unattended upgrades if running (track state to restart later)
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
        UNATTENDED_UPGRADES_WAS_ACTIVE=true
        sudo systemctl stop unattended-upgrades 2>/dev/null || true
        print_info "Temporarily stopped unattended-upgrades"
    fi
    
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
                sudo apt-get update >/dev/null 2>&1
                need_apt_update=false
            fi
            print_subheader "Installing: $pkg"
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1
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
    
    local db_root_secret="$SECRETS_DIR/db_root_pwd.secret"
    local mysql_secret="$SECRETS_DIR/mysql_pwd.secret"
    
    # Generate secure passwords (35 chars, alphanumeric)
    if [[ -f "$db_root_secret" ]] && [[ -s "$db_root_secret" ]]; then
        print_info "DB root password already exists (not regenerating)"
    else
        generate_password 35 > "$db_root_secret"
        chmod 600 "$db_root_secret"
        print_success "Generated DB root password"
    fi
    
    if [[ -f "$mysql_secret" ]] && [[ -s "$mysql_secret" ]]; then
        print_info "MySQL user password already exists (not regenerating)"
    else
        generate_password 35 > "$mysql_secret"
        chmod 600 "$mysql_secret"
        print_success "Generated MySQL user password"
    fi
    
    echo
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
    else
        # Get list of timezones
        if command -v timedatectl &>/dev/null; then
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

# Helper: Add UFW rule with comment (fallback to without comment if unsupported)
ufw_allow_with_comment() {
    local port="$1"
    local comment="$2"
    
    # Try with comment first (UFW 0.35+)
    if sudo ufw allow "${port}" comment "${comment}" >/dev/null 2>&1; then
        return 0
    fi
    
    # Fallback: try without comment (older UFW versions)
    if sudo ufw allow "${port}" >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

configure_firewall() {
    print_header "Configuring Firewall"
    
    # Check if UFW command is available
    if ! command -v ufw >/dev/null 2>&1; then
        print_warning "UFW not installed, skipping firewall configuration"
        print_info "Install UFW: sudo apt install ufw"
        echo
        return
    fi
    
    # Test if UFW is functional (may fail in unprivileged containers)
    # This catches permission issues before we try to modify rules
    if ! sudo ufw status >/dev/null 2>&1; then
        print_warning "UFW not functional (possibly running in unprivileged container)"
        print_info "Configure firewall on the Proxmox host instead"
        echo
        return
    fi
    
    # Check if UFW is active
    local ufw_status
    ufw_status=$(sudo ufw status 2>/dev/null)
    
    if ! echo "$ufw_status" | grep -q "Status: active"; then
        print_warning "UFW is installed but not active"
        print_info "Enable with: sudo ufw enable"
        print_info "Then add rules for ports 80, 443, and ${ADMIN_PORT}"
        echo
        return
    fi
    
    print_success "UFW is active"
    print_step "Adding firewall rules for NPM..."
    
    # Allow HTTP (port 80)
    if echo "$ufw_status" | grep -qE "80/tcp.*ALLOW"; then
        print_success "Port 80/tcp already allowed"
    else
        if ufw_allow_with_comment "80/tcp" "NPM HTTP"; then
            print_success "Allowed port 80/tcp (NPM HTTP)"
        else
            print_warning "Failed to add rule for port 80/tcp"
        fi
    fi
    
    # Allow HTTPS (port 443)
    if echo "$ufw_status" | grep -qE "443/tcp.*ALLOW"; then
        print_success "Port 443/tcp already allowed"
    else
        if ufw_allow_with_comment "443/tcp" "NPM HTTPS"; then
            print_success "Allowed port 443/tcp (NPM HTTPS)"
        else
            print_warning "Failed to add rule for port 443/tcp"
        fi
    fi
    
    # Allow admin port (user-defined)
    if echo "$ufw_status" | grep -qE "${ADMIN_PORT}/tcp.*ALLOW"; then
        print_success "Port ${ADMIN_PORT}/tcp already allowed"
    else
        if ufw_allow_with_comment "${ADMIN_PORT}/tcp" "NPM Admin UI"; then
            print_success "Allowed port ${ADMIN_PORT}/tcp (NPM Admin UI)"
        else
            print_warning "Failed to add rule for port ${ADMIN_PORT}/tcp"
        fi
    fi
    
    # Reload UFW to apply changes
    print_step "Reloading firewall..."
    if sudo ufw reload >/dev/null 2>&1; then
        print_success "Firewall rules applied and reloaded"
    else
        print_warning "UFW reload failed (rules may still be active)"
    fi
    
    # Show current relevant rules
    echo
    print_step "Current NPM-related firewall rules:"
    sudo ufw status | grep -E "(80|443|${ADMIN_PORT})/tcp" | while read -r line; do
        print_subheader "$line"
    done
    echo
}

#############################################################################
# Start Docker Compose                                                      #
#############################################################################

start_docker_compose() {
    print_header "Deploy NPM Stack"
    
    echo
    print_info "Ready to start the NPM stack"
    print_subheader "This will pull images and start containers"
    echo
    
    while true; do
        printf "%b" "${C_CYAN}${C_BOLD}Start NPM now?${C_RESET} ${C_DIM}(yes/no)${C_RESET} "
        read -r response
        response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
        
        case "$response" in
            yes|y)
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
                
                return 0
                ;;
            no|n)
                print_info "Stack not started"
                print_info "Start manually with: cd $WORK_DIR && sudo docker compose up -d"
                return 0
                ;;
            *)
                print_error "Please answer 'yes' or 'no'"
                ;;
        esac
    done
}

#############################################################################
# Show Summary                                                              #
#############################################################################

show_summary() {
    # Better IP detection: use ip route to find the interface that reaches the internet
    local ip_address
    ip_address=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    # Fallback to hostname -I if ip route fails
    [[ -z "$ip_address" ]] && ip_address=$(hostname -I 2>/dev/null | awk '{print $1}')
    ip_address=${ip_address:-"<your-ip>"}
    
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
    print_header "Useful Commands"
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose logs -f${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart stack${C_RESET}"
    printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose restart${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Stop stack${C_RESET}"
    printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose down${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Update containers${C_RESET}"
    printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose pull && sudo docker compose up -d${C_RESET}"
    
    echo
    print_header "File Locations"
    print_kv "Working Directory" "$WORK_DIR"
    print_kv "Compose File" "$WORK_DIR/docker-compose.yml"
    print_kv "Environment" "$WORK_DIR/.env"
    print_kv "Secrets" "$SECRETS_DIR/"
    print_kv "SSL Certificates" "$WORK_DIR/letsencrypt/"
    
    echo
    draw_separator
    echo
}

#############################################################################
# Main Execution                                                            #
#############################################################################

#############################################################################
# Cleanup / Restore Services                                                #
#############################################################################

cleanup() {
    # Restart unattended-upgrades if we stopped it
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == true ]]; then
        if sudo systemctl start unattended-upgrades 2>/dev/null; then
            print_info "Restarted unattended-upgrades service"
        fi
    fi
}

#############################################################################
# Main Execution                                                            #
#############################################################################

main() {
    # Clear screen if running directly
    [[ "${BASH_SOURCE[0]}" == "${0}" ]] && clear || true
    
    draw_box "Nginx Proxy Manager Installer v${SCRIPT_VERSION}"
    
    # Check if NPM directory already exists
    if [[ -d "$HOME/npm" ]]; then
        echo
        print_warning "NPM directory already exists: ~/npm"
        echo
        
        # Check if it's a complete installation
        if [[ -f "$HOME/npm/docker-compose.yml" ]]; then
            print_header "Management Commands"
            printf "  %b\n" "${C_DIM}# View status${C_RESET}"
            printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose ps${C_RESET}"
            echo
            printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
            printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose logs -f${C_RESET}"
            echo
            printf "  %b\n" "${C_DIM}# Restart stack${C_RESET}"
            printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose restart${C_RESET}"
            echo
            printf "  %b\n" "${C_DIM}# Update containers${C_RESET}"
            printf "  %b\n" "${C_CYAN}cd ~/npm && sudo docker compose pull && sudo docker compose up -d${C_RESET}"
            echo
            printf "  %b\n" "${C_DIM}# Edit configuration${C_RESET}"
            printf "  %b\n" "${C_CYAN}nano ~/npm/.env${C_RESET}"
        else
            print_warning "Incomplete installation detected (missing docker-compose.yml)"
        fi
        
        echo
        print_info "To reinstall, first remove the existing installation:"
        printf "  %b\n" "${C_CYAN}cd ~ && sudo docker compose -f ~/npm/docker-compose.yml down 2>/dev/null; sudo rm -rf ~/npm${C_RESET}"
        printf "  %b\n" "${C_CYAN}./npm.sh${C_RESET}"
        echo
        exit 0
    fi
    
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
    
    # Restore any services we stopped
    cleanup
}

# Run main function
main "$@"
