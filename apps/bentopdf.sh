#!/bin/bash

#############################################################################
# BentoPDF Installation Script                                              #
# Self-hosted PDF toolkit with modern web interface                         #
#############################################################################

readonly SCRIPT_VERSION="2.3.0"

# Handle --help flag early (before defining functions)
case "${1:-}" in
    --help|-h)
        echo "BentoPDF Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help] [--force]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"BentoPDF\""
        echo "  OR run standalone after hardening"
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Do NOT run with: sudo $0"
        echo "  - Internet connectivity required"
        echo "  - Port 8080 must be available (or set BENTOPDF_PORT)"
        echo "  - Minimum 2GB RAM recommended for build process"
        echo
        echo "What it does:"
        echo "  - Installs Node.js 24.x from NodeSource"
        echo "  - Installs 'serve' static file server"
        echo "  - Downloads and builds BentoPDF from source"
        echo "  - Creates systemd service for auto-start"
        echo "  - Configures UFW firewall rules"
        echo
        echo "Options:"
        echo "  --force    Remove existing installation and reinstall"
        echo
        echo "Environment variables:"
        echo "  BENTOPDF_PORT=<port>       Override default port (default: 8080)"
        echo "  BENTOPDF_BIND=<ip>         Bind address (default: 0.0.0.0, use 127.0.0.1 for local only)"
        echo
        echo "Files created:"
        echo "  /opt/bentopdf/                        Application directory"
        echo "  /etc/systemd/system/bentopdf.service  Systemd service"
        echo "  /var/log/lab/bentopdf-*.log           Installation log"
        echo
        echo "Default access:"
        echo "  http://<server-ip>:8080"
        exit 0
        ;;
esac

#############################################################################
# Professional edition with enhanced output formatting                      #
#                                                                           #
# EXECUTION REQUIREMENTS:                                                   #
#   - Must be run as a NON-ROOT user                                        #
#   - User must have sudo privileges                                        #
#   - Script will use sudo internally for privileged operations             #
#                                                                           #
# CORRECT USAGE:                                                            #
#   ./bentopdf.sh                                                           #
#                                                                           #
# INCORRECT USAGE:                                                          #
#   sudo ./bentopdf.sh  ← DO NOT DO THIS                                    #
#   # ./bentopdf.sh     ← DO NOT DO THIS                                    #
#############################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures

#############################################################################
# Script Configuration                                                      #
#############################################################################

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Track services we stop (to restart on cleanup)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

# Installation paths
readonly INSTALL_DIR="/opt/bentopdf"
readonly NODE_MAJOR="24"
readonly BENTOPDF_REPO="alam00000/bentopdf"

# Configurable options with defaults
BENTOPDF_PORT="${BENTOPDF_PORT:-8080}"
BENTOPDF_BIND="${BENTOPDF_BIND:-0.0.0.0}"

# Logging
readonly LOG_DIR="/var/log/lab"
LOG_FILE=""  # Set after sudo verification

# Handle --force flag
FORCE_INSTALL=false
for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE_INSTALL=true ;;
    esac
done

#############################################################################
# Terminal Formatting (embedded - no external dependency)                   #
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
    print_error "$@"
    exit 1
}

# Error trap for better debugging (set after print_error is defined)
trap 'print_error "Error on line $LINENO: $BASH_COMMAND"' ERR

#############################################################################
# Cleanup / Restore Services                                                #
#############################################################################

cleanup() {
    local exit_code=$?
    
    # Restore unattended-upgrades if we stopped it
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == true ]]; then
        if sudo systemctl start unattended-upgrades 2>/dev/null; then
            print_info "Restored unattended-upgrades service"
        fi
    fi
    
    exit $exit_code
}

# Register cleanup on exit (normal or error)
trap cleanup EXIT

#############################################################################
# Input Validation                                                          #
#############################################################################

validate_configuration() {
    # Validate BENTOPDF_PORT
    if [[ ! "$BENTOPDF_PORT" =~ ^[0-9]+$ ]]; then
        die "Invalid BENTOPDF_PORT: '$BENTOPDF_PORT' (must be a number)"
    fi
    
    if [[ "$BENTOPDF_PORT" -lt 1 ]] || [[ "$BENTOPDF_PORT" -gt 65535 ]]; then
        die "Invalid BENTOPDF_PORT: $BENTOPDF_PORT (must be 1-65535)"
    fi
    
    # Validate BENTOPDF_BIND (basic IP format check)
    if [[ ! "$BENTOPDF_BIND" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        die "Invalid BENTOPDF_BIND: '$BENTOPDF_BIND' (must be an IPv4 address)"
    fi
}

#############################################################################
# Network Information Detection                                             #
#############################################################################

detect_network_info() {
    # Get hostname
    HOSTNAME=$(hostname -s) || HOSTNAME="unknown"
    
    # Detect domain name
    if command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved; then
        DOMAIN_LOCAL=$(resolvectl status | awk '/DNS Domain:/ {print $3; exit}' | head -n1)
    fi
    
    # Fallback to /etc/resolv.conf
    if [[ -z "${DOMAIN_LOCAL:-}" ]]; then
        DOMAIN_LOCAL=$(awk '/^domain|^search/ {print $2; exit}' /etc/resolv.conf 2>/dev/null)
    fi
    
    # Final fallback
    DOMAIN_LOCAL=${DOMAIN_LOCAL:-"local"}
    
    # Detect primary IP address
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    
    # Fallback IP detection
    if [[ -z "$LOCAL_IP" ]] || [[ "$LOCAL_IP" == "127.0.0.1" ]]; then
        LOCAL_IP=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
    fi
    
    # Final fallback
    LOCAL_IP=${LOCAL_IP:-"127.0.0.1"}
}

#############################################################################
# Previous Installation Detection                                           #
#############################################################################

check_previous_installation() {
    # Check for BentoPDF installation marker
    if [[ -f /etc/systemd/system/bentopdf.service ]] && [[ -d "$INSTALL_DIR" ]]; then
        return 0  # Previously installed
    fi
    return 1  # Not installed yet
}

show_already_installed_menu() {
    clear
    draw_box "BentoPDF Already Installed"
    
    echo
    print_header "Installation Status"
    
    # Show what's installed
    [[ -d "$INSTALL_DIR" ]] && print_success "Application directory exists"
    [[ -f /etc/systemd/system/bentopdf.service ]] && print_success "Systemd service configured"
    
    # Check service status
    echo
    print_header "Service Status"
    if systemctl is-active --quiet bentopdf 2>/dev/null; then
        print_success "BentoPDF: running"
    else
        print_warning "BentoPDF: not running"
    fi
    
    # Show access URL
    echo
    print_header "Access Information"
    print_kv "BentoPDF URL" "http://${LOCAL_IP}:${BENTOPDF_PORT}"
    
    echo
    print_header "Management Commands"
    printf "  %b\n" "${C_DIM}# Check status${C_RESET}"
    printf "  %b\n" "${C_CYAN}systemctl status bentopdf${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}journalctl -u bentopdf -f${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart service${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl restart bentopdf${C_RESET}"
    
    echo
    print_header "Reinstall Option"
    print_info "To reinstall, run with --force flag:"
    printf "  %b\n" "${C_CYAN}./bentopdf.sh --force${C_RESET}"
    
    echo
    draw_separator
    echo
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
    
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        echo
        print_error "User $(whoami) does not have sudo privileges"
        echo
        print_info "To grant sudo access, run as root:"
        echo "  ${C_CYAN}usermod -aG sudo $(whoami)${C_RESET}"
        echo "  ${C_CYAN}# Then logout and login again${C_RESET}"
        echo
        die "Execution blocked: No sudo privileges"
    fi
    print_success "Sudo privileges confirmed"
    
    # Test sudo authentication
    if ! sudo -n true 2>/dev/null; then
        print_info "Sudo authentication required"
        if ! sudo -v; then
            die "Sudo authentication failed"
        fi
    fi
    print_success "Sudo authentication successful"
    
    # Check if running on PVE host
    if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
        die "This script should not run on Proxmox VE host. Run inside a VM or LXC."
    fi
    print_success "Not running on Proxmox host"
    
    # Check for systemd (robust check - verify it's actually running as PID1)
    # Fix #4: /run/systemd/system exists only when systemd is the init system
    if [[ ! -d /run/systemd/system ]]; then
        die "systemd is not running (container not systemd-enabled?)"
    fi
    print_success "systemd is running"
    
    # Check Debian version
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "debian" ]]; then
            print_warning "This script is designed for Debian. Detected: $ID"
        else
            print_success "Debian system detected: $VERSION"
        fi
    else
        print_warning "Cannot determine OS version"
    fi
    
    # Check disk space (need at least 2GB free for Node.js build)
    local free_space=$(df / | awk 'NR==2 {print $4}')
    local free_gb=$((free_space / 1048576))
    if [[ $free_space -lt 2097152 ]]; then
        die "Insufficient disk space. Need at least 2GB free, have ${free_gb}GB"
    fi
    print_success "Sufficient disk space available (${free_gb}GB free)"
    
    # Check internet connectivity
    print_step "Testing internet connectivity..."
    if command -v curl >/dev/null 2>&1; then
        if curl -s --max-time 5 --head https://github.com >/dev/null 2>&1; then
            print_success "Internet connectivity verified (via curl)"
        else
            die "No internet connectivity detected (curl test failed)"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q --timeout=5 --spider https://github.com 2>/dev/null; then
            print_success "Internet connectivity verified (via wget)"
        else
            die "No internet connectivity detected (wget test failed)"
        fi
    else
        print_warning "Cannot verify internet (curl/wget not available yet)"
        print_info "Assuming connectivity OK - will install curl in next step"
    fi
    
    # Fix #6: Check if port is available - FATAL if in use
    print_step "Checking port availability..."
    if command -v ss >/dev/null 2>&1; then
        if ss -tuln 2>/dev/null | grep -q ":${BENTOPDF_PORT} "; then
            echo
            print_error "Port ${BENTOPDF_PORT} is already in use!"
            echo
            print_info "Options:"
            echo "  ${C_CYAN}1. Stop the service using port ${BENTOPDF_PORT}${C_RESET}"
            echo "  ${C_CYAN}2. Set a different port: BENTOPDF_PORT=8081 ./bentopdf.sh${C_RESET}"
            echo
            die "Port ${BENTOPDF_PORT} is not available"
        else
            print_success "Port ${BENTOPDF_PORT} is available"
        fi
    else
        print_warning "Cannot check port (ss not available)"
    fi
    
    echo
}

#############################################################################
# Display Introduction                                                      #
#############################################################################

show_intro() {
    clear
    
    draw_box "BentoPDF Installer v${SCRIPT_VERSION}"
    
    echo
    print_header "System Information"
    print_kv "IP Address" "$LOCAL_IP"
    print_kv "Hostname" "$HOSTNAME"
    print_kv "Domain" "$DOMAIN_LOCAL"
    print_kv "Executing User" "$(whoami)"
    echo
}

#############################################################################
# Show Installation Plan (after preflight)                                  #
#############################################################################

show_install_plan() {
    print_header "Installation Steps"
    print_subheader "Install base packages (curl, git, jq, build-essential)"
    print_subheader "Install Node.js ${NODE_MAJOR}.x from NodeSource"
    print_subheader "Install 'serve' static file server"
    print_subheader "Download BentoPDF from GitHub"
    print_subheader "Build application (npm ci + npm run build)"
    print_subheader "Create systemd service"
    print_subheader "Configure UFW firewall rules"
    
    echo
    print_header "Configuration"
    print_kv "Install Directory" "$INSTALL_DIR"
    print_kv "Web Port" "$BENTOPDF_PORT"
    print_kv "Bind Address" "$BENTOPDF_BIND"
    if [[ "$BENTOPDF_BIND" == "127.0.0.1" ]]; then
        print_kv "Access URL" "http://localhost:${BENTOPDF_PORT} (local only)"
    else
        print_kv "Access URL" "http://${LOCAL_IP}:${BENTOPDF_PORT}"
    fi
    
    echo
    print_warning "Build may take 3-5 minutes depending on system resources"
    echo
    print_info "Log file: ${C_DIM}${LOG_FILE}${C_RESET}"
    echo
}

#############################################################################
# Confirm Script Execution                                                  #
#############################################################################

confirm_start() {
    draw_separator
    echo
    while true; do
        echo -n "${C_BOLD}${C_CYAN}Proceed with installation? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
        read -r choice
        choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
        
        case "$choice" in
            yes|y)
                log INFO "User confirmed, starting installation..."
                echo
                return 0
                ;;
            no|n)
                log INFO "User cancelled installation"
                print_info "Installation cancelled by user"
                exit 0
                ;;
            *)
                print_error "Invalid input. Please enter 'yes' or 'no'"
                ;;
        esac
    done
}

#############################################################################
# Confirm Force Reinstall (destructive action)                              #
#############################################################################

# Fix #3: Confirm BEFORE deleting anything
confirm_force_reinstall() {
    echo
    print_warning "This will DELETE the existing BentoPDF installation!"
    echo
    print_info "The following will be removed:"
    echo "  ${C_RED}• ${INSTALL_DIR}${C_RESET}"
    echo "  ${C_RED}• /etc/systemd/system/bentopdf.service${C_RESET}"
    echo
    
    while true; do
        echo -n "${C_BOLD}${C_RED}Type 'DELETE' to confirm removal: ${C_RESET}"
        read -r confirmation
        
        if [[ "$confirmation" == "DELETE" ]]; then
            log INFO "User confirmed force reinstall"
            return 0
        elif [[ "$confirmation" == "no" ]] || [[ "$confirmation" == "n" ]] || [[ -z "$confirmation" ]]; then
            print_info "Reinstall cancelled"
            exit 0
        else
            print_error "Type exactly 'DELETE' to confirm, or press Enter to cancel"
        fi
    done
}

#############################################################################
# Initialize Logging                                                        #
#############################################################################

init_logging() {
    # Create log directory
    sudo mkdir -p "$LOG_DIR"
    sudo chown "$(whoami):$(id -gn)" "$LOG_DIR"
    
    # Set log file path
    LOG_FILE="${LOG_DIR}/bentopdf-$(date +%Y%m%d-%H%M%S).log"
    
    # Create log file
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    log INFO "=== BentoPDF Installation Started ==="
    log INFO "Version: $SCRIPT_VERSION"
    log INFO "User: $(whoami)"
    log INFO "Date: $(date)"
}

#############################################################################
# Install Base Packages                                                     #
#############################################################################

install_base_packages() {
    print_header "Installing Base Packages"
    
    # Stop unattended upgrades if running (track state to restart later)
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
        UNATTENDED_UPGRADES_WAS_ACTIVE=true
        sudo systemctl stop unattended-upgrades 2>/dev/null || true
        print_info "Temporarily stopped unattended-upgrades"
    fi
    
    # Wait for apt lock
    # Fix #1: Use ((++wait_count)) instead of ((wait_count++)) to avoid exit on 0
    print_step "Waiting for apt lock..."
    local wait_count=0
    while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [[ $wait_count -eq 0 ]]; then
            print_subheader "Another process is using apt, waiting..."
        fi
        sleep 2
        ((++wait_count))  # Pre-increment returns new value, safe with set -e
        if [[ $wait_count -gt 30 ]]; then
            die "Timed out waiting for apt lock"
        fi
    done
    
    # Update package lists
    print_step "Updating package repositories..."
    if ! sudo apt-get update -y >/dev/null 2>&1; then
        die "Failed to update package repositories"
    fi
    print_success "Package lists updated"
    
    # Fix #8: Include build-essential for potential native npm dependencies
    local packages=(
        build-essential
        ca-certificates
        curl
        git
        gnupg
        jq
        make
        g++
        python3
    )
    
    print_step "Installing packages..."
    print_subheader "${C_DIM}${packages[*]}${C_RESET}"
    if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" >/dev/null 2>&1; then
        die "Failed to install packages"
    fi
    
    log SUCCESS "Base packages installed"
    echo
}

#############################################################################
# Install Node.js                                                           #
#############################################################################

install_nodejs() {
    print_header "Installing Node.js ${NODE_MAJOR}"
    
    # Check if Node.js is already installed with correct version
    if command -v node >/dev/null 2>&1; then
        local current_version
        current_version=$(node --version 2>/dev/null | sed 's/v//' | cut -d. -f1)
        if [[ "$current_version" -ge "$NODE_MAJOR" ]]; then
            print_success "Node.js v$(node --version) already installed"
            echo
            return 0
        fi
        print_info "Upgrading Node.js from v${current_version} to v${NODE_MAJOR}..."
    fi
    
    # Setup NodeSource repository
    print_step "Adding NodeSource repository..."
    sudo mkdir -p /etc/apt/keyrings
    
    if [[ ! -f /etc/apt/keyrings/nodesource.gpg ]]; then
        print_subheader "Downloading GPG key..."
        curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | \
            sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
        print_success "GPG key added"
    else
        print_success "GPG key already present"
    fi
    
    # Add repository
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" | \
        sudo tee /etc/apt/sources.list.d/nodesource.list >/dev/null
    print_success "Repository configured"
    
    # Install Node.js
    print_step "Installing Node.js (this may take a moment)..."
    sudo apt-get update -y >/dev/null 2>&1
    if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs >/dev/null 2>&1; then
        die "Failed to install Node.js"
    fi
    
    # Verify installation
    if ! command -v node >/dev/null 2>&1; then
        die "Node.js installation failed - node command not found"
    fi
    
    print_success "Node.js $(node --version) installed"
    print_success "npm $(npm --version) installed"
    
    log SUCCESS "Node.js ${NODE_MAJOR} installed"
    echo
}

#############################################################################
# Install serve package globally                                            #
#############################################################################

install_serve() {
    print_header "Installing Static File Server"
    
    print_step "Installing 'serve' package globally..."
    if ! sudo npm install -g serve >>"$LOG_FILE" 2>&1; then
        die "Failed to install serve package"
    fi
    
    # Verify installation
    if ! command -v serve >/dev/null 2>&1; then
        die "serve installation failed - command not found"
    fi
    
    print_success "serve $(serve --version 2>/dev/null || echo 'installed')"
    log SUCCESS "serve package installed"
    echo
}

#############################################################################
# Download BentoPDF                                                         #
#############################################################################

download_bentopdf() {
    print_header "Downloading BentoPDF"
    
    print_step "Fetching latest release from GitHub..."
    
    # Fix #2: Handle curl failure properly before command substitution aborts
    local release_info
    if ! release_info=$(curl -fsSL "https://api.github.com/repos/${BENTOPDF_REPO}/releases/latest" 2>&1); then
        die "Failed to fetch release information from GitHub (rate limit/network error?)"
    fi
    
    if [[ -z "$release_info" ]]; then
        die "Empty response from GitHub API"
    fi
    
    local tarball_url
    tarball_url=$(echo "$release_info" | jq -r '.tarball_url // empty')
    local version
    version=$(echo "$release_info" | jq -r '.tag_name // empty')
    
    if [[ -z "$tarball_url" ]]; then
        die "Failed to parse release tarball URL (invalid JSON or no releases?)"
    fi
    
    print_success "Found version: ${version}"
    
    print_step "Downloading source tarball..."
    
    # Create install directory
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown "$(whoami):$(id -gn)" "$INSTALL_DIR"
    
    # Download and extract
    local tmp_tarball="/tmp/bentopdf-${version}.tar.gz"
    if ! curl -fsSL "$tarball_url" -o "$tmp_tarball"; then
        die "Failed to download tarball"
    fi
    print_success "Downloaded: $(du -h "$tmp_tarball" | cut -f1)"
    
    print_step "Extracting to ${INSTALL_DIR}..."
    if ! tar -xzf "$tmp_tarball" -C "$INSTALL_DIR" --strip-components=1; then
        die "Failed to extract tarball"
    fi
    rm -f "$tmp_tarball"
    
    # Verify extraction
    if [[ ! -f "${INSTALL_DIR}/package.json" ]]; then
        die "Extraction failed - package.json not found"
    fi
    
    log SUCCESS "BentoPDF ${version} downloaded"
    echo
}

#############################################################################
# Build BentoPDF                                                            #
#############################################################################

build_bentopdf() {
    print_header "Building BentoPDF"
    
    cd "$INSTALL_DIR"
    
    print_step "Installing npm dependencies (this may take several minutes)..."
    print_subheader "Running: npm ci --no-audit --no-fund"
    
    if ! npm ci --no-audit --no-fund >>"$LOG_FILE" 2>&1; then
        print_error "npm ci failed - check log: $LOG_FILE"
        die "Failed to install npm dependencies"
    fi
    print_success "Dependencies installed"
    
    print_step "Building application (this may take several minutes)..."
    print_subheader "Running: SIMPLE_MODE=true npm run build -- --mode production"
    
    # Build with SIMPLE_MODE (matches community-scripts approach)
    # This creates a static build optimized for self-hosting
    export SIMPLE_MODE=true
    
    if ! npm run build -- --mode production >>"$LOG_FILE" 2>&1; then
        print_error "Build failed - check log: $LOG_FILE"
        print_info "Hint: Check if you have enough memory (recommend 2GB+ free)"
        die "Failed to build BentoPDF"
    fi
    
    # Verify build output
    if [[ ! -d "${INSTALL_DIR}/dist" ]]; then
        die "Build failed - dist directory not found"
    fi
    
    # Verify critical files exist
    local missing_files=()
    [[ ! -f "${INSTALL_DIR}/dist/index.html" ]] && missing_files+=("index.html")
    [[ ! -f "${INSTALL_DIR}/dist/qpdf.wasm" ]] && missing_files+=("qpdf.wasm")
    [[ ! -d "${INSTALL_DIR}/dist/assets" ]] && missing_files+=("assets/")
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        print_warning "Missing expected files: ${missing_files[*]}"
    fi
    
    local dist_size
    dist_size=$(du -sh "${INSTALL_DIR}/dist" | cut -f1)
    print_success "Build complete: ${dist_size}"
    
    log SUCCESS "BentoPDF built successfully"
    echo
}

#############################################################################
# Create Systemd Service                                                    #
#############################################################################

create_systemd_service() {
    print_header "Creating Systemd Service"
    
    print_step "Creating bentopdf.service..."
    
    # Build the ExecStart command
    local exec_cmd="/usr/bin/npx serve dist -p ${BENTOPDF_PORT}"
    
    # Add listen address if binding to specific IP
    if [[ "$BENTOPDF_BIND" != "0.0.0.0" ]]; then
        exec_cmd="/usr/bin/npx serve dist -l tcp://${BENTOPDF_BIND}:${BENTOPDF_PORT}"
    fi
    
    sudo tee /etc/systemd/system/bentopdf.service > /dev/null << EOF
[Unit]
Description=BentoPDF Service
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${exec_cmd}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Service file created"
    
    # Reload systemd
    print_step "Reloading systemd daemon..."
    sudo systemctl daemon-reload
    
    log SUCCESS "Systemd service created"
    echo
}

#############################################################################
# Configure Firewall                                                        #
#############################################################################

configure_firewall() {
    print_header "Configuring Firewall"
    
    # Skip firewall config if binding to localhost only
    if [[ "$BENTOPDF_BIND" == "127.0.0.1" ]]; then
        log INFO "Binding to localhost only - no firewall changes needed"
        echo
        return 0
    fi
    
    # Test if UFW is available and functional
    local ufw_status
    if ! ufw_status=$(sudo ufw status 2>&1); then
        log WARN "UFW not available or not functional"
        log INFO "Output: $ufw_status"
        log INFO "Configure firewall on the host instead"
        log INFO "Required port: ${BENTOPDF_PORT}/tcp"
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
    
    # Allow BentoPDF port
    if echo "$ufw_status" | grep -qE "${BENTOPDF_PORT}/tcp.*ALLOW"; then
        log SUCCESS "Port ${BENTOPDF_PORT}/tcp already allowed"
    else
        if sudo ufw allow "${BENTOPDF_PORT}/tcp" comment "BentoPDF Web UI" >> "$LOG_FILE" 2>&1; then
            log SUCCESS "Allowed port ${BENTOPDF_PORT}/tcp (BentoPDF Web UI)"
        else
            # Try without comment for older UFW versions
            if sudo ufw allow "${BENTOPDF_PORT}/tcp" >> "$LOG_FILE" 2>&1; then
                log SUCCESS "Allowed port ${BENTOPDF_PORT}/tcp"
            else
                log WARN "Failed to add UFW rule for port ${BENTOPDF_PORT}/tcp"
            fi
        fi
    fi
    
    log SUCCESS "Firewall configuration complete"
    echo
}

#############################################################################
# Start Services                                                            #
#############################################################################

start_services() {
    print_header "Starting Services"
    
    print_step "Enabling BentoPDF service..."
    if ! sudo systemctl enable bentopdf >/dev/null 2>&1; then
        print_warning "Failed to enable service"
    fi
    
    print_step "Starting BentoPDF service..."
    if ! sudo systemctl start bentopdf; then
        print_error "Failed to start BentoPDF service"
        print_info "Check logs: journalctl -u bentopdf"
        die "Service start failed"
    fi
    
    # Wait for service to start
    sleep 3
    
    if systemctl is-active --quiet bentopdf; then
        print_success "BentoPDF service is running"
    else
        print_warning "Service may not be running correctly"
        print_info "Check status: systemctl status bentopdf"
    fi
    
    # Test HTTP response
    print_step "Testing HTTP response..."
    sleep 2
    
    local test_url="http://localhost:${BENTOPDF_PORT}"
    if curl -fsSL "$test_url" >/dev/null 2>&1; then
        print_success "BentoPDF responding on port ${BENTOPDF_PORT}"
    else
        print_warning "BentoPDF not responding yet (may need more time)"
        print_info "Check logs: journalctl -u bentopdf -f"
    fi
    
    log SUCCESS "Services started"
    echo
}

#############################################################################
# Show Summary                                                              #
#############################################################################

show_summary() {
    echo
    draw_box "Installation Complete"
    
    echo
    print_header "Access Information"
    if [[ "$BENTOPDF_BIND" == "127.0.0.1" ]]; then
        print_kv "BentoPDF URL" "http://localhost:${BENTOPDF_PORT} (local only)"
        print_warning "Bound to localhost - use a reverse proxy for external access"
    else
        print_kv "BentoPDF URL" "http://${LOCAL_IP}:${BENTOPDF_PORT}"
    fi
    print_kv "Install Directory" "$INSTALL_DIR"
    print_kv "Service" "bentopdf.service"
    
    echo
    print_header "Management Commands"
    printf "  %b\n" "${C_DIM}# Check status${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl status bentopdf${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo journalctl -u bentopdf -f${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart service${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl restart bentopdf${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Stop service${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl stop bentopdf${C_RESET}"
    
    echo
    print_header "Reinstall / Update"
    printf "  %b\n" "${C_CYAN}sudo ./bentopdf.sh --force${C_RESET}"
    
    echo
    print_header "Log File"
    print_kv "Installation Log" "$LOG_FILE"
    
    echo
    draw_separator
    echo
    
    log INFO "=== BentoPDF Installation Completed ==="
}

#############################################################################
# Handle Force Reinstall                                                    #
#############################################################################

handle_force_reinstall() {
    print_header "Removing Existing Installation"
    
    print_step "Stopping BentoPDF service..."
    sudo systemctl stop bentopdf 2>/dev/null || true
    sudo systemctl disable bentopdf 2>/dev/null || true
    
    print_step "Removing systemd service..."
    sudo rm -f /etc/systemd/system/bentopdf.service
    sudo systemctl daemon-reload
    print_success "Removed service file"
    
    print_step "Removing application directory..."
    sudo rm -rf "$INSTALL_DIR"
    print_success "Removed: $INSTALL_DIR"
    
    log INFO "Existing installation removed (--force)"
    echo
}

#############################################################################
# Main Execution                                                            #
#############################################################################

main() {
    # Early check: Verify sudo is available before we do anything
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: sudo is not installed or not in PATH" >&2
        echo "This script requires sudo. Please install it first:" >&2
        echo "  apt update && apt install sudo" >&2
        exit 1
    fi
    
    # Validate configuration early (Fix #7)
    validate_configuration
    
    # Detect network info early (needed for display)
    detect_network_info
    
    # Check for previous installation
    if check_previous_installation; then
        if [[ "$FORCE_INSTALL" == true ]]; then
            # Fix #3: Confirm BEFORE deleting anything
            clear
            draw_box "BentoPDF Reinstall (--force)"
            echo
            preflight_checks
            init_logging
            
            # Get confirmation before destructive action
            confirm_force_reinstall
            
            # Now safe to remove
            handle_force_reinstall
        else
            # Show management menu and exit
            show_already_installed_menu
            exit 0
        fi
    else
        # Fresh installation - consolidated intro screen
        show_intro
        preflight_checks
        init_logging
    fi
    
    # Show what will be installed and get confirmation
    show_install_plan
    confirm_start
    
    # Execute installation steps
    install_base_packages
    install_nodejs
    install_serve
    download_bentopdf
    build_bentopdf
    create_systemd_service
    configure_firewall
    start_services
    
    # Show summary
    show_summary
}

# Run main function
main "$@"
