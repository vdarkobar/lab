#!/bin/bash

#############################################################################
# Docker + Docker Compose (v2) Installation Script                          #
# Installs Docker CE, CLI, containerd, and Compose/Buildx plugins           #
#############################################################################

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="docker"  # lowercase, matches filename without .sh

# Handle --help flag early (before defining functions)
case "${1:-}" in
    --help|-h)
        echo "${SCRIPT_NAME}.sh v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--status] [--logs [N]] [--configure] [--uninstall] [--version]"
        echo
        echo "Default action (no args): Install Docker CE + Compose v2 plugin"
        echo
        echo "Commands:"
        echo "  --status        Show Docker service/app status"
        echo "  --logs [N]      Show Docker service logs (default: 50 lines)"
        echo "  --configure     Re-run post-install steps (docker group membership)"
        echo "  --uninstall     Remove Docker packages (interactive unless silent)"
        echo "  --version, -v   Print script version"
        echo
        echo "Environment variables:"
        echo "  DOCKER_SILENT=true        Non-interactive mode (safe defaults)"
        echo "  DOCKER_DIST=<codename>    Override repo codename (e.g. bookworm)"
        echo
        echo "Notes:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - NEVER run on the Proxmox VE host (run inside a VM/LXC)"
        echo "  - After install: logout/login or run: newgrp docker"
        exit 0
        ;;
esac

#############################################################################
# Script Configuration                                                      #
#############################################################################

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Track services we stop (to restart on cleanup)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

# Non-interactive controls
SILENT="${DOCKER_SILENT:-false}"
DOCKER_DIST_OVERRIDE="${DOCKER_DIST:-}"

#############################################################################
# Terminal Formatting (embedded - no external dependency)                   #
#############################################################################

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

# Error trap for better debugging (set after print_error is defined)
trap 'print_error "Error at line $LINENO: $BASH_COMMAND"; log ERROR "Error at line $LINENO: $BASH_COMMAND"' ERR

#############################################################################
# Cleanup Contract (Standard)                                               #
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
# APT Lock Handling (Recommended)                                           #
#############################################################################

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

#############################################################################
# Pre-flight Checks (Standard)                                              #
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

    echo
}

#############################################################################
# Docker Install / Management                                               #
#############################################################################

get_os_id() {
    local os_id="debian"
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        os_id="${ID:-debian}"
    fi
    echo "$os_id"
}

get_os_codename() {
    local codename=""
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        codename="${VERSION_CODENAME:-}"
    fi
    if [[ -z "$codename" ]] && command_exists lsb_release; then
        codename="$(lsb_release -cs 2>/dev/null || true)"
    fi
    echo "$codename"
}

docker_repo_base_url() {
    local os_id
    os_id="$(get_os_id)"
    case "$os_id" in
        ubuntu) echo "https://download.docker.com/linux/ubuntu" ;;
        debian|*) echo "https://download.docker.com/linux/debian" ;;
    esac
}

docker_repo_has_codename() {
    local codename="$1"
    local base_url
    base_url="$(docker_repo_base_url)"
    local url="${base_url}/dists/${codename}/Release"

    if command_exists curl; then
        curl -fsSL --max-time 10 "$url" >/dev/null 2>&1
        return $?
    fi

    if command_exists wget; then
        wget -q --timeout=10 --spider "$url" >/dev/null 2>&1
        return $?
    fi

    # Fallback: no curl/wget (best-effort)
    return 1
}

select_docker_codename() {
    local detected codename os_id
    os_id="$(get_os_id)"
    detected="$(get_os_codename)"

    if [[ -n "${DOCKER_DIST_OVERRIDE:-}" ]]; then
        if docker_repo_has_codename "$DOCKER_DIST_OVERRIDE"; then
            echo "$DOCKER_DIST_OVERRIDE"
            return 0
        fi
        log WARN "DOCKER_DIST override '${DOCKER_DIST_OVERRIDE}' not available in Docker repo"
    fi

    local candidates=()
    if [[ -n "$detected" ]]; then
        candidates+=("$detected")
    fi

    if [[ "$os_id" == "ubuntu" ]]; then
        candidates+=("noble" "jammy" "focal")
    else
        # Debian fallback order: try current codename, then the latest stable(s)
        candidates+=("bookworm" "bullseye")
    fi

    local c
    for c in "${candidates[@]}"; do
        [[ -z "$c" ]] && continue
        if docker_repo_has_codename "$c"; then
            echo "$c"
            return 0
        fi
    done

    # Last resort: return detected even if not verifiable
    echo "${detected:-bookworm}"
}

install_prereqs() {
    print_header "Installing Prerequisites"
    prepare_apt

    if ! run_with_spinner "Updating apt package lists" sudo apt-get update; then
        die "apt-get update failed"
    fi

    if ! run_with_spinner "Installing prerequisites (ca-certificates, curl, gnupg)" sudo apt-get install -y ca-certificates curl gnupg; then
        die "Failed to install prerequisites"
    fi
}

setup_docker_repo() {
    print_header "Configuring Docker APT Repository"

    local base_url codename os_id arch
    base_url="$(docker_repo_base_url)"
    os_id="$(get_os_id)"
    codename="$(select_docker_codename)"
    arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"

    log INFO "Using OS: ${os_id}"
    log INFO "Using Docker repo codename: ${codename}"
    log INFO "Using architecture: ${arch}"

    # Create keyrings dir
    if ! run_with_spinner "Creating /etc/apt/keyrings" sudo install -m 0755 -d /etc/apt/keyrings; then
        die "Failed to create /etc/apt/keyrings"
    fi

    # Fetch GPG key
    if ! run_with_spinner "Fetching Docker GPG key" sudo bash -c "curl -fsSL ${base_url}/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"; then
        die "Failed to fetch Docker GPG key"
    fi
    sudo chmod a+r /etc/apt/keyrings/docker.gpg 2>/dev/null || true

    # Write repo file (idempotent)
    local repo_line
    repo_line="deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] ${base_url} ${codename} stable"

    if [[ -f /etc/apt/sources.list.d/docker.list ]] && grep -qF "$repo_line" /etc/apt/sources.list.d/docker.list 2>/dev/null; then
        log INFO "Docker repo already configured"
        return 0
    fi

    if ! run_with_spinner "Writing /etc/apt/sources.list.d/docker.list" sudo bash -c "printf '%s\n' '$repo_line' > /etc/apt/sources.list.d/docker.list"; then
        die "Failed to write docker.list"
    fi
}

install_docker_packages() {
    print_header "Installing Docker"

    prepare_apt

    if ! run_with_spinner "Updating apt package lists (Docker repo)" sudo apt-get update; then
        die "apt-get update failed (Docker repo)"
    fi

    if ! run_with_spinner "Installing Docker CE + plugins" sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
        die "Failed to install Docker packages"
    fi

    if ! run_with_spinner "Enabling and starting Docker service" sudo systemctl enable --now docker; then
        die "Failed to enable/start Docker"
    fi
}

post_install() {
    print_header "Post-install Configuration"

    # Add user to docker group (idempotent)
    if getent group docker >/dev/null 2>&1; then
        :
    else
        sudo groupadd docker >/dev/null 2>&1 || true
    fi

    if id -nG "$USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
        log INFO "User already in docker group: $USER"
    else
        if ! run_with_spinner "Adding user '$USER' to docker group" sudo usermod -aG docker "$USER"; then
            die "Failed to add user to docker group"
        fi
        log WARN "Group membership updated. You must logout/login or run: newgrp docker"
    fi

    # Quick validation (best-effort)
    if command_exists docker; then
        log INFO "Docker version: $(docker --version 2>/dev/null || true)"
    fi
    if command_exists docker && docker compose version >/dev/null 2>&1; then
        log INFO "Docker Compose: $(docker compose version 2>/dev/null || true)"
    fi
}

show_summary() {
    draw_box "Docker Installation Complete"

    print_kv "Docker" "$(docker --version 2>/dev/null || echo "installed")"
    print_kv "Compose" "$(docker compose version 2>/dev/null | head -n1 || echo "installed")"
    print_kv "Service" "$(systemctl is-active docker 2>/dev/null || echo "unknown")"
    print_kv "User" "$(whoami)"
    print_kv "Log file" "$LOG_FILE"
    echo
    print_info "If you cannot run docker without sudo yet:"
    echo "  ${C_CYAN}newgrp docker${C_RESET}"
    echo "  ${C_CYAN}# or logout/login${C_RESET}"
    echo
    print_info "Useful commands:"
    echo "  ${C_CYAN}systemctl status docker${C_RESET}"
    echo "  ${C_CYAN}journalctl -u docker -n 100 --no-pager${C_RESET}"
    echo "  ${C_CYAN}docker info${C_RESET}"
    echo
}

#############################################################################
# CLI Commands                                                              #
#############################################################################

cmd_status() {
    print_header "Docker Status"

    if command_exists docker; then
        print_kv "Docker" "$(docker --version 2>/dev/null || echo "unknown")"
    else
        print_kv "Docker" "not installed"
    fi

    if command_exists docker && docker compose version >/dev/null 2>&1; then
        print_kv "Compose" "$(docker compose version 2>/dev/null | head -n1)"
    else
        print_kv "Compose" "not available"
    fi

    if command_exists systemctl; then
        print_kv "Service active" "$(systemctl is-active docker 2>/dev/null || echo "unknown")"
        print_kv "Service enabled" "$(systemctl is-enabled docker 2>/dev/null || echo "unknown")"
    fi

    if id -nG "$USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
        print_kv "Docker group" "yes (user in group)"
    else
        print_kv "Docker group" "no (run --configure)"
    fi

    echo
}

cmd_logs() {
    local lines="${1:-50}"
    if ! [[ "$lines" =~ ^[0-9]+$ ]]; then
        die "Invalid log line count: $lines"
    fi

    print_header "Docker Logs (last ${lines} lines)"
    if command_exists journalctl; then
        sudo journalctl -u docker -n "$lines" --no-pager
    else
        die "journalctl not available"
    fi
}

cmd_configure() {
    print_header "Configure Docker"

    if ! command_exists docker; then
        die "Docker not installed"
    fi

    SILENT="${DOCKER_SILENT:-false}"

    # Re-run docker group membership step
    if id -nG "$USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
        log INFO "User already in docker group: $USER"
    else
        if ! run_with_spinner "Adding user '$USER' to docker group" sudo usermod -aG docker "$USER"; then
            die "Failed to add user to docker group"
        fi
        log WARN "Group membership updated. You must logout/login or run: newgrp docker"
    fi

    print_success "Configuration complete"
}

cmd_uninstall() {
    print_header "Uninstall Docker"

    if ! command_exists docker && ! dpkg -l 2>/dev/null | awk '{print $2}' | grep -q '^docker-ce$'; then
        print_info "Docker does not appear to be installed"
        exit 0
    fi

    if ! is_silent; then
        while true; do
            echo -n "${C_BOLD}${C_CYAN}Proceed with uninstall? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')

            case "$choice" in
                yes|y) break ;;
                no|n)
                    print_info "Cancelled by user"
                    exit 0
                    ;;
                *) print_error "Invalid input. Please enter 'yes' or 'no'" ;;
            esac
        done
    fi

    local remove_data="no"
    if ! is_silent; then
        echo -ne "${C_CYAN}Remove Docker data (/var/lib/docker, /var/lib/containerd)? (yes/no) [default: no]: ${C_RESET}"
        read -r remove_data
        remove_data="${remove_data:-no}"
    fi

    prepare_apt

    # Stop service (best-effort)
    sudo systemctl stop docker 2>/dev/null || true
    sudo systemctl disable docker 2>/dev/null || true

    if ! run_with_spinner "Removing Docker packages" sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
        die "Failed to remove Docker packages"
    fi

    if ! run_with_spinner "Removing unused dependencies" sudo apt-get autoremove -y; then
        die "Failed to autoremove packages"
    fi

    # Remove repo/key (best-effort)
    sudo rm -f /etc/apt/sources.list.d/docker.list 2>/dev/null || true
    sudo rm -f /etc/apt/keyrings/docker.gpg 2>/dev/null || true

    case "${remove_data,,}" in
        yes|y)
            if ! run_with_spinner "Removing Docker data directories" sudo rm -rf /var/lib/docker /var/lib/containerd; then
                die "Failed to remove Docker data directories"
            fi
            ;;
        no|n) : ;;
        *) print_warning "Unrecognized input for data removal; leaving data intact" ;;
    esac

    print_success "Docker uninstalled"
    print_kv "Log file" "$LOG_FILE"
}

#############################################################################
# Main                                                                      #
#############################################################################

install_docker() {
    # If already installed, treat as idempotent unless user wants reinstall
    if command_exists docker; then
        print_warning "Docker is already installed."
        print_info "Use: --status, --logs, --configure, --uninstall"
        if is_silent; then
            return 0
        fi

        while true; do
            echo -n "${C_BOLD}${C_CYAN}Reinstall/repair (re-run install steps)? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
            case "$choice" in
                yes|y) break ;;
                no|n) return 0 ;;
                *) print_error "Invalid input. Please enter 'yes' or 'no'" ;;
            esac
        done
    fi

    preflight_checks
    install_prereqs
    setup_docker_repo
    install_docker_packages
    post_install
    show_summary
}

main() {
    # Version does not require sudo/logging
    case "${1:-}" in
        --version|-v)
            echo "${SCRIPT_NAME}.sh v${SCRIPT_VERSION}"
            exit 0
            ;;
    esac

    # Early check: Verify sudo is available before we do anything
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: sudo is not installed or not in PATH" >&2
        echo "This script requires sudo. Please install it first:" >&2
        echo "  apt update && apt install sudo" >&2
        exit 1
    fi

    # Verify user has sudo access before creating log file
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

    # Refuse Proxmox VE host execution (mandatory)
    if [[ -f /etc/pve/.version ]] || command -v pveversion >/dev/null 2>&1; then
        echo "ERROR: This script must not run on the Proxmox VE host. Run inside a VM or LXC." >&2
        exit 1
    fi

    # Setup logging (for all non-help operations)
    setup_logging

    # Handle commands
    case "${1:-}" in
        --status)    cmd_status ;;
        --logs)      cmd_logs "${2:-50}" ;;
        --configure) cmd_configure ;;
        --uninstall) cmd_uninstall ;;
        "")          install_docker ;;
        *)           die "Unknown option: $1 (use --help for usage)" ;;
    esac
}

main "$@"
