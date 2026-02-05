#!/bin/bash

###################################################################################
# Cloudflare Tunnel Installer - Debian 13                                         #
###################################################################################

readonly SCRIPT_VERSION="2.1.0"

# Handle --help flag early (before defining functions)
case "${1:-}" in
    --help|-h)
        echo "Cloudflare Tunnel Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help|--status|--logs|--configure|--uninstall]"
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Do NOT run with: sudo $0"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"Cloudflare Tunnel\""
        echo "  Or run directly: ./cloudflared.sh"
        echo
        echo "Environment variables:"
        echo "  CLOUDFLARED_TUNNEL_TOKEN   Pre-generated tunnel token (required for silent)"
        echo "  CLOUDFLARED_SKIP_UFW       Skip UFW configuration (true/false)"
        echo "  CLOUDFLARED_SILENT         Run non-interactively (true/false)"
        echo
        echo "What it does:"
        echo "  - Installs cloudflared from official Cloudflare repository"
        echo "  - Configures systemd service with tunnel token"
        echo "  - Optionally configures UFW firewall rules"
        echo
        echo "Post-install commands:"
        echo "  --status      Show tunnel status and connection info"
        echo "  --logs [N]    Show last N lines of logs (default: 50)"
        echo "  --configure   Reconfigure tunnel with new token"
        echo "  --uninstall   Remove cloudflared and clean up"
        echo
        echo "Network requirements:"
        echo "  Outbound 443/tcp   HTTPS to Cloudflare edge"
        echo "  Outbound 7844/udp  QUIC protocol (optional, faster)"
        echo
        echo "Files created:"
        echo "  /etc/cloudflared/                       Configuration directory"
        echo "  /etc/apt/sources.list.d/cloudflared.list  APT repository"
        echo "  /usr/share/keyrings/cloudflare-public-v2.gpg  GPG key"
        echo "  /var/log/lab/cloudflared-*.log            Installation log"
        echo
        echo "Getting your tunnel token:"
        echo "  1. Log in to Cloudflare Zero Trust dashboard"
        echo "  2. Go to: Networks → Tunnels"
        echo "  3. Create a new tunnel or select existing"
        echo "  4. Copy the token from the installation command"
        echo
        echo "Examples:"
        echo "  # Interactive installation"
        echo "  ./cloudflared.sh"
        echo
        echo "  # Automated installation"
        echo "  CLOUDFLARED_TUNNEL_TOKEN=\"eyJhIjoi...\" CLOUDFLARED_SILENT=true ./cloudflared.sh"
        exit 0
        ;;
esac

###################################################################################
#                                                                                 #
# DESCRIPTION:                                                                    #
#   Installs Cloudflare Tunnel (cloudflared) daemon and configures it to run      #
#   as a systemd service. Supports both interactive and automated installation.   #
#                                                                                 #
# LOCATION: lab/apps/cloudflared.sh                                               #
# REPOSITORY: https://github.com/vdarkobar/lab                                    #
#                                                                                 #
# EXECUTION REQUIREMENTS:                                                         #
#   - Must be run as a NON-ROOT user                                              #
#   - User must have sudo privileges                                              #
#   - Script will use sudo internally for privileged operations                   #
#                                                                                 #
# CORRECT USAGE:                                                                  #
#   ./cloudflared.sh                                                              #
#                                                                                 #
# INCORRECT USAGE:                                                                #
#   sudo ./cloudflared.sh  ← DO NOT DO THIS                                      #
#   # ./cloudflared.sh     ← DO NOT DO THIS                                      #
#                                                                                 #
# REQUIREMENTS:                                                                   #
#   - Debian 13 (Trixie) or Debian 12 (Bookworm)                                 #
#   - Sudo privileges                                                             #
#   - Internet connection                                                         #
#   - Cloudflare account with tunnel token                                        #
#                                                                                 #
# VERSION: 2.1.0                                                                  #
# LICENSE: MIT                                                                    #
#                                                                                 #
###################################################################################

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Secure file creation (tunnel tokens handled)
umask 077

# Track services we stop (to restart on cleanup)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

###################################################################################
# Script Configuration                                                            #
###################################################################################

readonly SCRIPT_NAME="cloudflared"

# App config (env overrides)
CLOUDFLARED_TUNNEL_TOKEN="${CLOUDFLARED_TUNNEL_TOKEN:-}";  TUNNEL_TOKEN="$CLOUDFLARED_TUNNEL_TOKEN"
CLOUDFLARED_SKIP_UFW="${CLOUDFLARED_SKIP_UFW:-false}";     SKIP_FIREWALL="$CLOUDFLARED_SKIP_UFW"
CLOUDFLARED_SILENT="${CLOUDFLARED_SILENT:-false}";          SILENT="$CLOUDFLARED_SILENT"

# Logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Cloudflared paths
readonly CLOUDFLARED_BIN="/usr/bin/cloudflared"
readonly CLOUDFLARED_CONFIG_DIR="/etc/cloudflared"
readonly CLOUDFLARED_SERVICE="cloudflared"

###################################################################################
# Terminal Formatting (embedded - no external dependency)                         #
###################################################################################

# Check if terminal supports colors
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    COLORS_SUPPORTED=true
    
    readonly C_RESET=$(tput sgr0)
    readonly C_BOLD=$(tput bold)
    readonly C_DIM=$(tput dim)
    
    readonly C_RED=$(tput setaf 1)
    readonly C_GREEN=$(tput setaf 2)
    readonly C_YELLOW=$(tput setaf 3)
    readonly C_BLUE=$(tput setaf 4)
    readonly C_CYAN=$(tput setaf 6)
    readonly C_WHITE=$(tput setaf 7)
    
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

###################################################################################
# Spinner Characters (optional - only needed if run_with_spinner is used)         #
###################################################################################

if [[ "${LANG:-}" =~ UTF-8 ]] || [[ "${LC_ALL:-}" =~ UTF-8 ]]; then
    readonly SPINNER_CHARS='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
else
    readonly SPINNER_CHARS='|/-\'
fi

###################################################################################
# Output Functions                                                                #
###################################################################################

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

###################################################################################
# Visual Elements                                                                 #
###################################################################################

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

###################################################################################
# Logging                                                                         #
###################################################################################

log() {
    local level="$1"; shift
    local message="$*"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

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
    local msg="$*"
    log ERROR "$msg"
    exit 1
}

# Error trap for better debugging (set after print_error is defined)
trap 'print_error "Error at line $LINENO: $BASH_COMMAND"; log ERROR "Error at line $LINENO: $BASH_COMMAND"' ERR

###################################################################################
# Spinner for Long Operations (optional)                                          #
###################################################################################

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

###################################################################################
# Cleanup / Restore Services                                                      #
###################################################################################

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

###################################################################################
# Helper Functions                                                                #
###################################################################################

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

###################################################################################
# Setup Logging Directory                                                         #
###################################################################################

setup_logging() {
    # Note: sudo existence check should be done BEFORE calling this function
    
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

###################################################################################
# Pre-flight Checks                                                               #
###################################################################################

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
    if ! command -v sudo >/dev/null 2>&1; then
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

    # Check if cloudflared already installed (binary exists but service not running)
    if command_exists cloudflared; then
        local current_version
        current_version=$(cloudflared --version 2>/dev/null | head -1 || echo "unknown")
        print_warning "Cloudflared already installed: $current_version"
        
        if ! is_silent; then
            echo
            while true; do
                echo -n "${C_BOLD}${C_CYAN}Reinstall/upgrade? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
                read -r choice
                choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
                
                case "$choice" in
                    yes|y)
                        log INFO "User chose to reinstall"
                        break
                        ;;
                    no|n)
                        log INFO "User cancelled reinstallation"
                        print_info "Installation cancelled"
                        exit 0
                        ;;
                    *)
                        print_error "Invalid input. Please enter 'yes' or 'no'"
                        ;;
                esac
            done
        fi
    fi

    echo
}

###################################################################################
# APT Lock Handling                                                               #
###################################################################################

prepare_apt() {
    # Stop unattended-upgrades to avoid apt locks (best-effort)
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
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

###################################################################################
# Install Dependencies                                                            #
###################################################################################

install_dependencies() {
    print_header "Checking Prerequisites"
    
    # Packages needed for cloudflared installation
    local required_packages=(
        curl
        gnupg
        lsb-release
        ca-certificates
    )
    
    local missing_packages=()
    
    # Check which packages are already installed
    for pkg in "${required_packages[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            print_success "Package installed: $pkg"
        else
            missing_packages+=("$pkg")
        fi
    done
    
    # If all packages present, we're done
    if [[ ${#missing_packages[@]} -eq 0 ]]; then
        print_success "All prerequisites already installed"
        echo
        return 0
    fi
    
    print_step "Installing missing packages: ${missing_packages[*]}"
    
    # Handle apt locks
    prepare_apt
    
    if ! run_with_spinner "Updating package lists" sudo apt-get update -y; then
        die "apt-get update failed"
    fi
    
    if ! run_with_spinner "Installing ${missing_packages[*]}" sudo apt-get install -y "${missing_packages[@]}"; then
        die "Failed to install dependencies: ${missing_packages[*]}"
    fi
    
    log SUCCESS "Missing packages installed"
    echo
}

###################################################################################
# Get Tunnel Token                                                                #
###################################################################################

get_tunnel_token() {
    print_header "Tunnel Token Configuration"
    
    # Check if token provided via environment
    if [[ -n "$TUNNEL_TOKEN" ]]; then
        print_success "Using tunnel token from environment variable"
        log INFO "Token provided via CLOUDFLARED_TUNNEL_TOKEN (${#TUNNEL_TOKEN} chars)"
        echo
        return 0
    fi
    
    # In silent mode, token is required
    if is_silent; then
        die "CLOUDFLARED_TUNNEL_TOKEN is required for silent installation"
    fi
    
    # Interactive prompt
    echo
    print_info "A Cloudflare Tunnel token is required to connect this machine to your tunnel."
    echo
    echo "  ${C_DIM}To get your token:${C_RESET}"
    echo "    ${C_CYAN}1.${C_RESET} Log in to Cloudflare Zero Trust dashboard"
    echo "    ${C_CYAN}2.${C_RESET} Go to: Networks → Tunnels"
    echo "    ${C_CYAN}3.${C_RESET} Create a new tunnel or select existing"
    echo "    ${C_CYAN}4.${C_RESET} Copy the token from the installation command"
    echo
    echo "  ${C_DIM}The token looks like: eyJhIjoiNjk2...${C_RESET}"
    echo
    
    while true; do
        echo
        print_info "Paste your tunnel token (input hidden for security)"
        echo -ne "${C_CYAN}Token: ${C_RESET}"
        read -r TUNNEL_TOKEN
        
        if [[ -z "$TUNNEL_TOKEN" ]]; then
            print_error "Token cannot be empty"
            continue
        fi
        
        # Basic validation - tokens are base64-encoded JSON, typically start with eyJ
        if [[ ! "$TUNNEL_TOKEN" =~ ^eyJ ]]; then
            print_warning "Token format looks unusual (should start with 'eyJ')"
            echo -n "${C_CYAN}Continue anyway? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                continue
            fi
        fi
        
        # Confirm token
        echo
        print_info "Token received (${#TUNNEL_TOKEN} characters)"
        echo -n "${C_CYAN}Is this correct? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
        read -r confirm
        if [[ "$confirm" =~ ^[Yy] ]] || [[ -z "$confirm" ]]; then
            break
        fi
    done
    
    log INFO "Token configured (${#TUNNEL_TOKEN} chars)"
    echo
}

###################################################################################
# Install Cloudflared                                                             #
###################################################################################

install_cloudflared() {
    print_header "Installing Cloudflared"
    
    local need_apt_update=true
    local gpg_key="/usr/share/keyrings/cloudflare-public-v2.gpg"
    local cloudflared_list="/etc/apt/sources.list.d/cloudflared.list"
    local desired_line="deb [signed-by=${gpg_key}] https://pkg.cloudflare.com/cloudflared any main"
    
    # Create keyrings directory with proper permissions
    print_step "Setting up Cloudflare repository..."
    sudo mkdir -p --mode=0755 /usr/share/keyrings
    
    # Add Cloudflare GPG key (idempotent)
    if [[ -s "$gpg_key" ]]; then
        print_success "Cloudflare GPG key already present"
    else
        print_subheader "Adding Cloudflare GPG key..."
        if ! curl -fsSL https://pkg.cloudflare.com/cloudflare-public-v2.gpg | \
             sudo tee "$gpg_key" >/dev/null 2>>"$LOG_FILE"; then
            die "Failed to add Cloudflare GPG key"
        fi
        print_success "GPG key added"
    fi
    
    # Configure repository (idempotent)
    if [[ -f "$cloudflared_list" ]] && grep -Fqx "$desired_line" "$cloudflared_list"; then
        print_success "Cloudflare repository already configured"
        need_apt_update=false
    else
        print_subheader "Configuring Cloudflare repository..."
        echo "$desired_line" | sudo tee "$cloudflared_list" >/dev/null
        print_success "Repository added"
    fi
    
    # Install cloudflared package
    print_step "Installing cloudflared package..."
    
    if dpkg -s cloudflared >/dev/null 2>&1; then
        print_success "Package already installed, upgrading if available..."
    fi
    
    if [[ "$need_apt_update" == true ]]; then
        if ! run_with_spinner "Updating package lists" sudo apt-get update -y; then
            die "apt-get update failed"
        fi
    fi
    
    if ! run_with_spinner "Installing cloudflared" sudo apt-get install -y cloudflared; then
        die "Failed to install cloudflared"
    fi
    
    # Verify installation
    if command_exists cloudflared; then
        local version
        version=$(cloudflared --version 2>/dev/null | head -1 || echo "unknown")
        log SUCCESS "Cloudflared installed: $version"
    else
        die "Installation verification failed - cloudflared binary not found"
    fi
    
    echo
}

###################################################################################
# Configure Service                                                               #
###################################################################################

configure_service() {
    print_header "Configuring Cloudflare Tunnel Service"
    
    # Stop existing service if running
    if service_is_active "$CLOUDFLARED_SERVICE"; then
        print_step "Stopping existing cloudflared service..."
        sudo systemctl stop "$CLOUDFLARED_SERVICE" 2>/dev/null || true
    fi
    
    # Remove old service configuration if exists
    if [[ -f "/etc/systemd/system/${CLOUDFLARED_SERVICE}.service" ]]; then
        print_step "Removing old service configuration..."
        sudo systemctl disable "$CLOUDFLARED_SERVICE" 2>/dev/null || true
        sudo rm -f "/etc/systemd/system/${CLOUDFLARED_SERVICE}.service"
        sudo rm -f "/etc/systemd/system/${CLOUDFLARED_SERVICE}@.service"
        sudo systemctl daemon-reload
    fi
    
    # Clean up old config directory
    if [[ -d "$CLOUDFLARED_CONFIG_DIR" ]]; then
        print_step "Cleaning up old configuration..."
        sudo rm -rf "$CLOUDFLARED_CONFIG_DIR"
    fi
    
    # Install service with token
    print_step "Installing tunnel service with token..."
    log INFO "Running: cloudflared service install [TOKEN]"
    
    if ! sudo cloudflared service install "$TUNNEL_TOKEN" >>"$LOG_FILE" 2>&1; then
        die "Failed to install cloudflared service"
    fi
    print_success "Service installed"
    
    # Enable and start service
    print_step "Enabling and starting service..."
    sudo systemctl daemon-reload
    
    if ! sudo systemctl enable "$CLOUDFLARED_SERVICE" >>"$LOG_FILE" 2>&1; then
        print_warning "Failed to enable service"
    fi
    
    if ! sudo systemctl start "$CLOUDFLARED_SERVICE" >>"$LOG_FILE" 2>&1; then
        die "Failed to start cloudflared service - check: journalctl -u $CLOUDFLARED_SERVICE"
    fi
    
    # Verify service is running
    sleep 3
    
    if service_is_active "$CLOUDFLARED_SERVICE"; then
        log SUCCESS "Cloudflared service is running"
    else
        die "Service failed to start - check: journalctl -u $CLOUDFLARED_SERVICE"
    fi
    
    echo
}

###################################################################################
# Configure Firewall                                                              #
###################################################################################

configure_firewall() {
    print_header "Configuring Firewall"
    
    # Skip if requested
    if [[ "${SKIP_FIREWALL:-false}" == "true" ]]; then
        log INFO "Firewall configuration skipped (CLOUDFLARED_SKIP_UFW=true)"
        echo
        return 0
    fi
    
    # Test if UFW is available and functional
    local ufw_status
    if ! ufw_status=$(sudo ufw status verbose 2>&1); then
        log WARN "UFW not available or not functional"
        log INFO "Output: $ufw_status"
        log INFO "Configure firewall on the host instead"
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
    log INFO "Cloudflared uses outbound connections only - no inbound rules needed"
    
    # Check if outbound is blocked (rare, but possible)
    if echo "$ufw_status" | grep -q "deny (outgoing)"; then
        log STEP "Adding outbound rules for cloudflared..."
        
        if sudo ufw allow out 443/tcp comment "Cloudflared HTTPS" >> "$LOG_FILE" 2>&1; then
            log SUCCESS "Allowed outbound 443/tcp (Cloudflared HTTPS)"
        else
            if sudo ufw allow out 443/tcp >> "$LOG_FILE" 2>&1; then
                log SUCCESS "Allowed outbound 443/tcp"
            else
                log WARN "Failed to add outbound rule for 443/tcp"
            fi
        fi
        
        if sudo ufw allow out 7844/udp comment "Cloudflared QUIC" >> "$LOG_FILE" 2>&1; then
            log SUCCESS "Allowed outbound 7844/udp (Cloudflared QUIC)"
        else
            if sudo ufw allow out 7844/udp >> "$LOG_FILE" 2>&1; then
                log SUCCESS "Allowed outbound 7844/udp"
            else
                log WARN "Failed to add outbound rule for 7844/udp"
            fi
        fi
    else
        log SUCCESS "Default outbound policy allows cloudflared traffic"
    fi
    
    log SUCCESS "Firewall configuration complete"
    echo
}

###################################################################################
# Show Summary                                                                    #
###################################################################################

show_summary() {
    local ip_address
    ip_address=$(get_local_ip)
    local version
    version=$(cloudflared --version 2>/dev/null | head -1 || echo "unknown")
    
    echo
    draw_box "Installation Complete"
    
    echo
    print_header "Summary"
    print_kv "Version" "$version"
    print_kv "Service Status" "$(systemctl is-active $CLOUDFLARED_SERVICE 2>/dev/null || echo 'unknown')"
    print_kv "Config Directory" "$CLOUDFLARED_CONFIG_DIR"
    print_kv "Log File" "$LOG_FILE"
    print_kv "Server IP" "$ip_address"
    print_kv "Installed By" "$(whoami)"
    
    echo
    print_header "Management Commands"
    printf "  %b\n" "${C_DIM}# View tunnel status${C_RESET}"
    printf "  %b\n" "${C_CYAN}./cloudflared.sh --status${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View service logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}./cloudflared.sh --logs${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Reconfigure with new token${C_RESET}"
    printf "  %b\n" "${C_CYAN}./cloudflared.sh --configure${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart service${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl restart cloudflared${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Uninstall${C_RESET}"
    printf "  %b\n" "${C_CYAN}./cloudflared.sh --uninstall${C_RESET}"
    
    echo
    print_header "Next Steps"
    print_info "Configure your tunnel routes in the Cloudflare Zero Trust dashboard"
    print_info "Dashboard: ${C_CYAN}https://one.dash.cloudflare.com${C_RESET}"
    
    echo
    print_header "File Locations"
    print_kv "Configuration" "$CLOUDFLARED_CONFIG_DIR"
    print_kv "Installation Log" "$LOG_FILE"
    
    echo
    draw_separator
    echo
    
    log INFO "=== Cloudflared Installation Completed ==="
}

###################################################################################
# Post-Install Commands                                                           #
###################################################################################

cmd_status() {
    print_header "Cloudflared Status"
    
    # Check if installed
    if ! command_exists cloudflared; then
        die "Cloudflared is not installed"
    fi
    
    # Version info
    local version
    version=$(cloudflared --version 2>/dev/null | head -1 || echo "unknown")
    print_kv "Version" "$version"
    
    # Service status
    echo
    print_header "Service Status"
    if service_is_active "$CLOUDFLARED_SERVICE"; then
        print_success "Service: running"
    else
        print_warning "Service: not running"
    fi
    
    if service_is_enabled "$CLOUDFLARED_SERVICE"; then
        print_success "Enabled: yes (starts on boot)"
    else
        print_warning "Enabled: no"
    fi
    
    # Configuration info
    echo
    print_header "Configuration"
    
    # Check if using token-based config (token embedded in systemd service file)
    if sudo systemctl cat cloudflared 2>/dev/null | grep -q -- "--token"; then
        print_success "Token-based configuration"
        print_info "Tunnel routes managed via Cloudflare Zero Trust dashboard"
        print_subheader "Dashboard: https://one.dash.cloudflare.com"
    elif [[ -f "${CLOUDFLARED_CONFIG_DIR}/config.yml" ]]; then
        print_success "Config file-based configuration"
        print_kv "Config File" "${CLOUDFLARED_CONFIG_DIR}/config.yml"
    elif [[ -d "$CLOUDFLARED_CONFIG_DIR" ]]; then
        print_kv "Config Directory" "$CLOUDFLARED_CONFIG_DIR"
        print_warning "No config.yml found"
    else
        print_warning "No configuration found"
    fi
    
    # Show recent logs
    echo
    print_header "Recent Activity (last 10 lines)"
    sudo journalctl -u "$CLOUDFLARED_SERVICE" --no-pager -n 10 2>/dev/null || \
        echo "  No logs available"
    
    echo
}

cmd_logs() {
    local lines="${1:-50}"
    
    print_header "Cloudflared Logs (last $lines lines)"
    echo
    
    sudo journalctl -u "$CLOUDFLARED_SERVICE" -n "$lines" --no-pager 2>/dev/null || \
        die "Unable to retrieve logs"
}

cmd_configure() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Reconfigure Cloudflare Tunnel"
    
    print_warning "This will replace the current tunnel configuration."
    
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
    
    # Clear existing token to force re-prompt
    TUNNEL_TOKEN=""
    
    # Get new token and reconfigure
    get_tunnel_token
    configure_service
    
    log SUCCESS "Tunnel reconfigured successfully"
}

cmd_uninstall() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Uninstall Cloudflared"
    
    if ! command_exists cloudflared; then
        print_info "Cloudflared is not installed"
        exit 0
    fi
    
    print_warning "This will remove:"
    print_subheader "Cloudflared package and configuration"
    print_subheader "Systemd service"
    print_subheader "APT repository and GPG key"
    
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
    
    # Stop and disable service
    print_step "Stopping cloudflared service..."
    sudo systemctl stop "$CLOUDFLARED_SERVICE" 2>/dev/null || true
    sudo systemctl disable "$CLOUDFLARED_SERVICE" 2>/dev/null || true
    
    # Uninstall service
    if command_exists cloudflared; then
        print_step "Uninstalling cloudflared service..."
        sudo cloudflared service uninstall 2>/dev/null || true
    fi
    
    # Remove package
    if ! run_with_spinner "Removing cloudflared package" sudo apt-get remove --purge -y cloudflared; then
        print_warning "Package removal encountered issues, continuing..."
    fi
    
    if ! run_with_spinner "Cleaning up unused packages" sudo apt-get autoremove -y; then
        print_warning "Autoremove encountered issues, continuing..."
    fi
    
    # Clean up configuration
    print_step "Removing configuration files..."
    sudo rm -rf "$CLOUDFLARED_CONFIG_DIR"
    sudo rm -f /etc/apt/sources.list.d/cloudflared.list
    # Remove both old and new GPG key files for compatibility
    sudo rm -f /usr/share/keyrings/cloudflare-public-v2.gpg
    sudo rm -f /usr/share/keyrings/cloudflare-main.gpg
    
    # Remove firewall rules (only if UFW active)
    if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        print_step "Removing firewall rules..."
        sudo ufw delete allow out 443/tcp 2>/dev/null || true
        sudo ufw delete allow out 7844/udp 2>/dev/null || true
    fi
    
    # Update package lists
    if ! run_with_spinner "Updating package lists" sudo apt-get update -qq; then
        print_warning "Package list update failed, continuing..."
    fi
    
    log SUCCESS "Cloudflared has been removed"
    echo
}

###################################################################################
# Show Introduction                                                               #
###################################################################################

show_intro() {
    clear
    
    draw_box "Cloudflare Tunnel Installer v${SCRIPT_VERSION}"
    
    echo
    print_header "System Information"
    print_kv "IP Address" "$(get_local_ip)"
    print_kv "Hostname" "$(hostname -s)"
    print_kv "Executing User" "$(whoami)"
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        print_kv "OS" "${PRETTY_NAME:-$ID}"
    fi
    
    echo
    print_header "Installation Steps"
    print_subheader "Install dependencies (curl, gnupg)"
    print_subheader "Add Cloudflare APT repository"
    print_subheader "Install cloudflared package"
    print_subheader "Configure tunnel with your token"
    print_subheader "Enable and start systemd service"
    
    echo
    print_header "Requirements"
    print_warning "Script must run as non-root user (currently: $(whoami))"
    print_warning "User must have sudo privileges (will prompt if needed)"
    print_warning "Cloudflare tunnel token required"
    
    echo
    print_info "Logs will be saved to: ${C_DIM}${LOG_FILE}${C_RESET}"
    echo
}

###################################################################################
# Main Execution                                                                  #
###################################################################################

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
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: sudo is not installed or not in PATH" >&2
        echo "This script requires sudo. Please install it first:" >&2
        echo "  apt update && apt install sudo" >&2
        exit 1
    fi
    if [[ ${EUID} -eq 0 ]]; then
        echo "ERROR: This script must NOT be run as root!" >&2
        echo "Run as a regular user with sudo privileges:" >&2
        echo "  ./$(basename "$0")" >&2
        exit 1
    fi
    if ! sudo -v 2>/dev/null; then
        echo "ERROR: Current user $(whoami) does not have sudo privileges" >&2
        echo "Please add user to sudo group:" >&2
        echo "  usermod -aG sudo $(whoami)" >&2
        echo "Then logout and login again" >&2
        exit 1
    fi
    
    # Check if already installed (idempotency)
    if command -v cloudflared >/dev/null 2>&1 && systemctl is-active --quiet cloudflared 2>/dev/null; then
        clear
        draw_box "Cloudflare Tunnel - Already Installed"
        
        local version
        version=$(cloudflared --version 2>/dev/null | head -1 || echo "unknown")
        
        echo
        print_header "Current Installation"
        print_kv "Version" "$version"
        print_kv "Service Status" "$(systemctl is-active cloudflared 2>/dev/null || echo 'unknown')"
        print_kv "Enabled" "$(systemctl is-enabled cloudflared 2>/dev/null || echo 'unknown')"
        
        echo
        print_header "Management Commands"
        printf "  %b\n" "${C_DIM}# View status${C_RESET}"
        printf "  %b\n" "${C_CYAN}./cloudflared.sh --status${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
        printf "  %b\n" "${C_CYAN}./cloudflared.sh --logs${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# Reconfigure tunnel${C_RESET}"
        printf "  %b\n" "${C_CYAN}./cloudflared.sh --configure${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# Uninstall${C_RESET}"
        printf "  %b\n" "${C_CYAN}./cloudflared.sh --uninstall${C_RESET}"
        
        echo
        print_info "To reinstall, first uninstall the existing installation:"
        printf "  %b\n" "${C_CYAN}./cloudflared.sh --uninstall${C_RESET}"
        printf "  %b\n" "${C_CYAN}./cloudflared.sh${C_RESET}"
        echo
        exit 0
    fi
    
    # Setup logging
    setup_logging
    
    # Show introduction (unless silent)
    if ! is_silent; then
        show_intro
    fi
    
    # Run installation
    preflight_checks
    install_dependencies
    get_tunnel_token
    install_cloudflared
    configure_service
    configure_firewall
    show_summary
}

main "$@"
