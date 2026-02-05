#!/bin/bash
readonly SCRIPT_VERSION="3.1.0"
readonly SCRIPT_NAME="bentopdf"

# Handle --help early (before defining functions)
case "${1:-}" in
    --help|-h)
        echo "BentoPDF Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help] [--status] [--logs [N]] [--configure] [--uninstall] [--force]"
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Do NOT run with: sudo $0"
        echo "  - Internet connectivity required"
        echo "  - Minimum 2GB RAM recommended for build process"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"BentoPDF\""
        echo "  OR run standalone after hardening"
        echo
        echo "What it does:"
        echo "  - Installs Node.js 24.x from NodeSource"
        echo "  - Installs 'serve' static file server"
        echo "  - Downloads and builds BentoPDF from source"
        echo "  - Creates systemd service for auto-start"
        echo "  - Configures UFW firewall rules"
        echo
        echo "Environment variables:"
        echo "  BENTOPDF_SILENT=true     Non-interactive mode"
        echo "  BENTOPDF_SKIP_UFW=true   Skip firewall configuration"
        echo "  BENTOPDF_PORT=8080       Override default port (default: 8080)"
        echo "  BENTOPDF_BIND=0.0.0.0    Bind address (default: 0.0.0.0, use 127.0.0.1 for local only)"
        echo
        echo "Post-install commands:"
        echo "  --status      Show service status and access info"
        echo "  --logs [N]    Show last N lines of logs (default: 50)"
        echo "  --configure   Reconfigure and restart service"
        echo "  --uninstall   Remove BentoPDF completely"
        echo "  --force       Remove existing installation and reinstall"
        echo
        echo "Network requirements:"
        echo "  Inbound ${BENTOPDF_PORT:-8080}/tcp    BentoPDF web interface"
        echo
        echo "Files created:"
        echo "  /opt/bentopdf/                        Application directory"
        echo "  /etc/systemd/system/bentopdf.service  Systemd service"
        echo "  /var/log/lab/bentopdf-*.log           Installation logs"
        exit 0
        ;;
esac

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Track services we stop (to restart on cleanup)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

# App config (env overrides)
BENTOPDF_SILENT="${BENTOPDF_SILENT:-false}"; SILENT="$BENTOPDF_SILENT"
BENTOPDF_SKIP_UFW="${BENTOPDF_SKIP_UFW:-false}"; SKIP_FIREWALL="$BENTOPDF_SKIP_UFW"
BENTOPDF_PORT="${BENTOPDF_PORT:-8080}"; APP_PORT="$BENTOPDF_PORT"
BENTOPDF_BIND="${BENTOPDF_BIND:-0.0.0.0}"

# Force reinstall flag (set by --force in main)
FORCE_INSTALL=false

# Installation paths
readonly INSTALL_DIR="/opt/bentopdf"
readonly NODE_MAJOR="24"
readonly BENTOPDF_REPO="alam00000/bentopdf"

# Logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"

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
# Input Validation                                                          #
#############################################################################

validate_configuration() {
    # Validate BENTOPDF_PORT
    if [[ ! "$APP_PORT" =~ ^[0-9]+$ ]]; then
        die "Invalid BENTOPDF_PORT: '$APP_PORT' (must be a number)"
    fi
    
    if [[ "$APP_PORT" -lt 1 ]] || [[ "$APP_PORT" -gt 65535 ]]; then
        die "Invalid BENTOPDF_PORT: $APP_PORT (must be 1-65535)"
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
    
    # Detect domain name (resolvectl first, then resolv.conf)
    if command_exists resolvectl && service_is_active systemd-resolved; then
        DOMAIN_LOCAL=$(resolvectl status | awk '/DNS Domain:/ {print $3; exit}' | head -n1)
    fi
    
    # Fallback to /etc/resolv.conf
    if [[ -z "${DOMAIN_LOCAL:-}" ]]; then
        DOMAIN_LOCAL=$(awk '/^domain|^search/ {print $2; exit}' /etc/resolv.conf 2>/dev/null)
    fi
    
    # Final fallback
    DOMAIN_LOCAL=${DOMAIN_LOCAL:-"local"}
    
    # Detect primary IP address
    LOCAL_IP=$(get_local_ip)
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

    # Check disk space (need at least 2GB free for Node.js build)
    local free_space
    free_space=$(df / | awk 'NR==2 {print $4}')
    local free_gb=$((free_space / 1048576))
    if [[ $free_space -lt 2097152 ]]; then
        die "Insufficient disk space. Need at least 2GB free, have ${free_gb}GB"
    fi
    print_success "Sufficient disk space available (${free_gb}GB free)"

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

    # Check port availability
    check_port_availability "$APP_PORT"

    echo
}

#############################################################################
# Port Availability Check                                                   #
#############################################################################

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
        echo
        print_error "Ports already in use: ${ports_in_use[*]}"
        echo
        print_info "Options:"
        echo "  ${C_CYAN}1. Stop the service using port ${ports_in_use[*]}${C_RESET}"
        echo "  ${C_CYAN}2. Set a different port: BENTOPDF_PORT=8081 ./bentopdf.sh${C_RESET}"
        echo
        die "Required ports not available: ${ports_in_use[*]}"
    fi
    
    print_success "Required ports are available: ${ports[*]}"
    return 0
}

#############################################################################
# APT Lock Handling                                                         #
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
# Previous Installation Detection                                           #
#############################################################################

check_previous_installation() {
    if [[ -f /etc/systemd/system/bentopdf.service ]] && [[ -d "$INSTALL_DIR" ]]; then
        return 0  # Previously installed
    fi
    return 1  # Not installed yet
}

show_already_installed_menu() {
    local ip_address
    ip_address=$(get_local_ip)
    
    clear
    draw_box "BentoPDF Already Installed"
    
    echo
    print_header "Installation Status"
    [[ -d "$INSTALL_DIR" ]] && print_success "Application directory exists"
    [[ -f /etc/systemd/system/bentopdf.service ]] && print_success "Systemd service configured"
    
    echo
    print_header "Service Status"
    if service_is_active bentopdf; then
        print_success "BentoPDF: running"
    else
        print_warning "BentoPDF: not running"
    fi
    
    echo
    print_header "Access Information"
    print_kv "BentoPDF URL" "http://${ip_address}:${APP_PORT}"
    
    echo
    print_header "Management Commands"
    printf "  %b\n" "${C_DIM}# Check status${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --status${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --logs${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Reconfigure${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --configure${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart service${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl restart bentopdf${C_RESET}"
    
    echo
    print_header "Reinstall Option"
    print_info "To reinstall, run with --force flag:"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --force${C_RESET}"
    
    echo
    draw_separator
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
# Show Installation Plan                                                    #
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
    print_kv "Web Port" "$APP_PORT"
    print_kv "Bind Address" "$BENTOPDF_BIND"
    if [[ "$BENTOPDF_BIND" == "127.0.0.1" ]]; then
        print_kv "Access URL" "http://localhost:${APP_PORT} (local only)"
    else
        print_kv "Access URL" "http://${LOCAL_IP}:${APP_PORT}"
    fi
    
    echo
    print_warning "Build may take 3-5 minutes depending on system resources"
    echo
    print_info "Log file: ${C_DIM}${LOG_FILE}${C_RESET}"
    echo
}

#############################################################################
# Confirm Installation                                                      #
#############################################################################

confirm_start() {
    if is_silent; then
        log INFO "Silent mode - skipping confirmation"
        return 0
    fi
    
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

confirm_force_reinstall() {
    if is_silent; then
        log INFO "Silent mode - skipping force reinstall confirmation"
        return 0
    fi
    
    echo
    print_warning "This will DELETE the existing BentoPDF installation!"
    echo
    print_info "The following will be removed:"
    echo "  ${C_RED}${SYMBOL_BULLET} ${INSTALL_DIR}${C_RESET}"
    echo "  ${C_RED}${SYMBOL_BULLET} /etc/systemd/system/bentopdf.service${C_RESET}"
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
    
    # Remove firewall rules (only if UFW active)
    if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        print_step "Removing firewall rules..."
        sudo ufw delete allow "${APP_PORT}/tcp" 2>/dev/null || true
    fi
    
    log INFO "Existing installation removed (--force)"
    echo
}

#############################################################################
# Install Base Packages                                                     #
#############################################################################

install_base_packages() {
    print_header "Installing Base Packages"
    
    prepare_apt
    
    # Update package lists
    if ! run_with_spinner "Updating package repositories" sudo apt-get update -y; then
        die "Failed to update package repositories"
    fi
    
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
    
    print_subheader "${C_DIM}${packages[*]}${C_RESET}"
    if ! run_with_spinner "Installing base packages" sudo apt-get install -y "${packages[@]}"; then
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
    if command_exists node; then
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
    if ! run_with_spinner "Updating package lists" sudo apt-get update -y; then
        die "Failed to update package lists after adding NodeSource"
    fi
    
    if ! run_with_spinner "Installing Node.js ${NODE_MAJOR}" sudo apt-get install -y nodejs; then
        die "Failed to install Node.js"
    fi
    
    # Verify installation
    if ! command_exists node; then
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
    
    if ! run_with_spinner "Installing 'serve' package globally" sudo npm install -g serve; then
        die "Failed to install serve package"
    fi
    
    # Verify installation
    if ! command_exists serve; then
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
    
    # Create install directory
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown "$(whoami):$(id -gn)" "$INSTALL_DIR"
    
    # Download tarball
    local tmp_tarball="/tmp/bentopdf-${version}.tar.gz"
    if ! run_with_spinner "Downloading source tarball" curl -fsSL "$tarball_url" -o "$tmp_tarball"; then
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
    
    if ! run_with_spinner "Installing npm dependencies" npm ci --no-audit --no-fund; then
        print_info "Hint: Check log for details: $LOG_FILE"
        die "Failed to install npm dependencies"
    fi
    
    # Build with SIMPLE_MODE (creates a static build optimized for self-hosting)
    export SIMPLE_MODE=true
    
    if ! run_with_spinner "Building application (production)" npm run build -- --mode production; then
        print_info "Hint: Check if you have enough memory (recommend 2GB+ free)"
        print_info "Log: $LOG_FILE"
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
    local exec_cmd="/usr/bin/npx serve dist -p ${APP_PORT}"
    
    # Add listen address if binding to specific IP
    if [[ "$BENTOPDF_BIND" != "0.0.0.0" ]]; then
        exec_cmd="/usr/bin/npx serve dist -l tcp://${BENTOPDF_BIND}:${APP_PORT}"
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
    
    # Skip if env var set
    if [[ "${SKIP_FIREWALL:-false}" == "true" ]]; then
        log INFO "Firewall configuration skipped (BENTOPDF_SKIP_UFW=true)"
        echo
        return 0
    fi
    
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
        log INFO "Required port: ${APP_PORT}/tcp"
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
    if echo "$ufw_status" | grep -qE "${APP_PORT}/tcp.*ALLOW"; then
        log SUCCESS "Port ${APP_PORT}/tcp already allowed"
    else
        if sudo ufw allow "${APP_PORT}/tcp" comment "BentoPDF Web UI" >/dev/null 2>&1; then
            log SUCCESS "Allowed port ${APP_PORT}/tcp (BentoPDF Web UI)"
        else
            # Fallback: try without comment for older UFW versions
            if sudo ufw allow "${APP_PORT}/tcp" >/dev/null 2>&1; then
                log SUCCESS "Allowed port ${APP_PORT}/tcp"
            else
                log WARN "Failed to add UFW rule for port ${APP_PORT}/tcp"
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
    
    if service_is_active bentopdf; then
        print_success "BentoPDF service is running"
    else
        print_warning "Service may not be running correctly"
        print_info "Check status: systemctl status bentopdf"
    fi
    
    # Test HTTP response
    if command_exists curl; then
        print_step "Testing HTTP response..."
        sleep 2
        
        local test_url="http://localhost:${APP_PORT}"
        if curl -fsSL "$test_url" >/dev/null 2>&1; then
            print_success "BentoPDF responding on port ${APP_PORT}"
        else
            print_warning "BentoPDF not responding yet (may need more time)"
            print_info "Check logs: journalctl -u bentopdf -f"
        fi
    fi
    
    log SUCCESS "Services started"
    echo
}

#############################################################################
# Installation Summary                                                      #
#############################################################################

show_summary() {
    local ip_address
    ip_address=$(get_local_ip)
    
    echo
    draw_box "Installation Complete"
    
    echo
    print_header "Access Information"
    if [[ "$BENTOPDF_BIND" == "127.0.0.1" ]]; then
        print_kv "URL" "http://localhost:${APP_PORT} (local only)"
        print_warning "Bound to localhost - use a reverse proxy for external access"
    else
        print_kv "URL" "http://${ip_address}:${APP_PORT}"
    fi
    print_kv "Install Directory" "$INSTALL_DIR"
    
    echo
    print_header "Management Commands"
    printf "  %b\n" "${C_DIM}# Check status${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --status${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --logs${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Reconfigure${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --configure${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart service${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl restart bentopdf${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Uninstall${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --uninstall${C_RESET}"
    
    echo
    print_header "File Locations"
    print_kv "Application" "$INSTALL_DIR"
    print_kv "Installation Log" "$LOG_FILE"
    
    echo
    draw_separator
    echo
    
    log INFO "=== BentoPDF Installation Completed ==="
}

#############################################################################
# Post-Install Commands                                                     #
#############################################################################

cmd_status() {
    print_header "BentoPDF Status"
    
    local ip_address
    ip_address=$(get_local_ip)
    
    if [[ -d "$INSTALL_DIR" ]]; then
        print_kv "Installed" "yes"
    else
        print_kv "Installed" "no"
        return
    fi
    
    print_kv "Service Status" "$(systemctl is-active bentopdf 2>/dev/null || echo 'unknown')"
    print_kv "Enabled" "$(systemctl is-enabled bentopdf 2>/dev/null || echo 'unknown')"
    
    if command_exists node; then
        print_kv "Node.js" "$(node --version 2>/dev/null || echo 'unknown')"
    fi
    
    echo
    print_header "Access Information"
    print_kv "URL" "http://${ip_address}:${APP_PORT}"
    print_kv "Install Directory" "$INSTALL_DIR"
    
    echo
}

cmd_logs() {
    local lines="${1:-50}"
    
    print_header "BentoPDF Logs (last $lines lines)"
    echo
    
    # For systemd service
    sudo journalctl -u bentopdf -n "$lines" --no-pager
}

cmd_configure() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Reconfigure BentoPDF"
    
    print_warning "This will regenerate the systemd service and restart BentoPDF."
    print_info "Current configuration:"
    print_kv "Port" "$APP_PORT"
    print_kv "Bind Address" "$BENTOPDF_BIND"
    
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
    
    # Regenerate systemd service with current env vars
    create_systemd_service
    
    # Restart service
    print_step "Restarting BentoPDF service..."
    if sudo systemctl restart bentopdf; then
        sleep 2
        if service_is_active bentopdf; then
            log SUCCESS "BentoPDF reconfigured and running"
        else
            print_warning "Service may not be running correctly after restart"
        fi
    else
        print_error "Failed to restart BentoPDF"
    fi
    
    echo
}

cmd_uninstall() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Uninstall BentoPDF"
    
    if ! check_previous_installation; then
        print_info "BentoPDF is not installed"
        exit 0
    fi
    
    print_warning "This will remove:"
    print_subheader "Application directory ($INSTALL_DIR)"
    print_subheader "Systemd service (bentopdf.service)"
    
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
    print_step "Stopping service..."
    sudo systemctl stop bentopdf 2>/dev/null || true
    sudo systemctl disable bentopdf 2>/dev/null || true
    
    # Remove service file
    print_step "Removing systemd service..."
    sudo rm -f /etc/systemd/system/bentopdf.service
    sudo systemctl daemon-reload
    
    # Remove application directory
    print_step "Removing application directory..."
    sudo rm -rf "$INSTALL_DIR"
    
    # Remove firewall rules (only if UFW active)
    if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        print_step "Removing firewall rules..."
        sudo ufw delete allow "${APP_PORT}/tcp" 2>/dev/null || true
    fi
    
    log SUCCESS "BentoPDF has been removed"
    echo
}

#############################################################################
# Main Execution                                                            #
#############################################################################

main() {
    # Handle post-install commands
    case "${1:-}" in
        --status)     cmd_status; exit 0 ;;
        --logs)       cmd_logs "${2:-50}"; exit 0 ;;
        --configure)  cmd_configure; exit 0 ;;
        --uninstall)  cmd_uninstall; exit 0 ;;
        --version|-v) echo "${SCRIPT_NAME}.sh v${SCRIPT_VERSION}"; exit 0 ;;
        --force|-f)   FORCE_INSTALL=true ;;
        "")           ;;  # Continue with installation
        *)            die "Unknown option: $1 (use --help for usage)" ;;
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
    
    # Validate configuration early
    validate_configuration
    
    # Detect network info (needed for display)
    detect_network_info
    
    # Check if already installed (idempotency)
    if check_previous_installation; then
        if [[ "$FORCE_INSTALL" == true ]]; then
            clear
            draw_box "BentoPDF Reinstall (--force)"
            echo
            setup_logging
            preflight_checks
            confirm_force_reinstall
            handle_force_reinstall
        else
            # Show management menu and exit
            show_already_installed_menu
            exit 0
        fi
    else
        # Fresh installation
        show_intro
        setup_logging
        preflight_checks
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

main "$@"
