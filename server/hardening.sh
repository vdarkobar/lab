#!/bin/bash

#############################################################################
# Debian 13 VM/LXC Server Hardening Script                                  #
#############################################################################

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="hardening"

# Handle --help flag early (before defining functions)
case "${1:-}" in
    --help|-h)
        echo "Debian Server Hardening Script v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [COMMAND]"
        echo
        echo "Commands:"
        echo "  (no args)     Install / harden the system (default)"
        echo "  --help, -h    Show this help and exit"
        echo "  --status      Show hardening and service status"
        echo "  --logs [N]    Show recent log entries (default: 50)"
        echo "  --version, -v Print version and exit"
        echo
        echo "Environment variables:"
        echo "  HARDENING_SILENT=true       Skip all interactive prompts"
        echo "  HARDENING_SKIP_UFW=true     Skip firewall configuration"
        echo "  HARDENING_SKIP_APPS=true    Skip app installation menu"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → Select \"Harden Debian System\""
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Do NOT run with: sudo $0"
        echo
        echo "What it does:"
        echo "  - Installs security packages (fail2ban, ufw, etc.)"
        echo "  - Configures SSH hardening (disables password auth)"
        echo "  - Sets up UFW firewall"
        echo "  - Configures automatic security updates"
        echo "  - Hardens sysctl settings"
        echo "  - Locks root account"
        echo "  - Offers app installation menu (Docker, NPM, Unbound, etc.)"
        echo
        echo "Files created:"
        echo "  /var/log/lab/hardening-*.log                      Installation log"
        echo "  /root/hardening-backups-*/                        Config backups"
        echo "  /etc/ssh/sshd_config.d/99-lab-hardening.conf      SSH hardening"
        echo "  /etc/fail2ban/jail.d/99-lab-hardening.conf        Fail2Ban config"
        echo "  /etc/sysctl.d/99-lab-hardening.conf               Sysctl hardening"
        echo "  /etc/apt/apt.conf.d/52lab-unattended-upgrades     Auto-updates config"
        echo
        echo "Available apps (via menu):"
        echo "  - Docker + Compose v2"
        echo "  - Nginx Proxy Manager (native)"
        echo "  - Nginx Proxy Manager (Docker)"
        echo "  - Cloudflare Tunnel"
        echo "  - Unbound DNS"
        echo "  - Samba File Server"
        echo "  - BookStack Wiki"
        echo "  - BentoPDF"
        exit 0
        ;;
    --version|-v)
        echo "${SCRIPT_NAME}.sh version ${SCRIPT_VERSION}"
        exit 0
        ;;
esac

#############################################################################
# Professional edition with enhanced output formatting                      #
#                                                                            #
# EXECUTION REQUIREMENTS:                                                   #
#   - Must be run as a NON-ROOT user                                        #
#   - User must have sudo privileges                                        #
#   - Script will use sudo internally for privileged operations             #
#                                                                            #
# CORRECT USAGE:                                                            #
#   ./hardening.sh                                                          #
#                                                                            #
# INCORRECT USAGE:                                                          #
#   sudo ./hardening.sh  ← DO NOT DO THIS                                   #
#   # ./hardening.sh     ← DO NOT DO THIS                                   #
#############################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures
export DEBIAN_FRONTEND=noninteractive

#############################################################################
# Script Configuration                                                      #
#############################################################################

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Track services we stop (to restart on cleanup)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

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
# Spinner (Optional - For Long-Running Operations)                         #
#############################################################################

# Spinner characters (with ASCII fallback for non-UTF-8 terminals)
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

print_section() {
    local msg="$*"
    echo
    echo "${C_BOLD}${C_WHITE}═══ ${msg} ═══${C_RESET}"
    echo
}

# Hardening-specific output helpers
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
    local title="$1"
    shift
    local lines=("$@")
    
    # Calculate max width
    local max_width=0
    for line in "${lines[@]}"; do
        local stripped_line
        stripped_line=$(echo "$line" | sed -r 's/\x1B\[[0-9;]*[mK]//g')
        [[ ${#stripped_line} -gt $max_width ]] && max_width=${#stripped_line}
    done
    
    # Ensure minimum width for title
    [[ ${#title} -gt $max_width ]] && max_width=${#title}
    
    local box_width=$((max_width + 2))
    local border
    border=$(printf '═%.0s' $(seq 1 $box_width))
    
    # Top border
    echo "${C_CYAN}╔${border}╗${C_RESET}"
    
    # Title (centered)
    if [[ -n "$title" ]]; then
        local title_padding=$(( (box_width - ${#title}) / 2 ))
        local title_line
        title_line=$(printf "%-${box_width}s" "$(printf "%${title_padding}s")${title}")
        echo "${C_CYAN}║${C_RESET} ${C_BOLD}${C_WHITE}${title_line}${C_RESET} ${C_CYAN}║${C_RESET}"
        echo "${C_CYAN}╠${border}╣${C_RESET}"
    fi
    
    # Content lines
    for line in "${lines[@]}"; do
        local stripped_line
        stripped_line=$(echo "$line" | sed -r 's/\x1B\[[0-9;]*[mK]//g')
        local padding=$((box_width - ${#stripped_line}))
        local padded_line="${line}$(printf ' %.0s' $(seq 1 $padding))"
        echo "${C_CYAN}║${C_RESET} ${padded_line} ${C_CYAN}║${C_RESET}"
    done
    
    # Bottom border
    echo "${C_CYAN}╚${border}╝${C_RESET}"
}

draw_separator() {
    local char="${1:-─}"
    local width="${2:-80}"
    printf "${C_CYAN}%${width}s${C_RESET}\n" | tr ' ' "$char"
}

#############################################################################
# Logging Functions                                                         #
#############################################################################

# Strip ANSI codes for clean log files
strip_ansi() {
    echo "$1" | sed -r 's/\x1B\[[0-9;]*[mK]//g'
}

# Unified logging function
log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local stripped_msg
    stripped_msg=$(strip_ansi "$msg")
    
    # Append to log file (if LOG_FILE is set and writable)
    if [[ -n "${LOG_FILE:-}" ]] && [[ -w "${LOG_FILE:-}" ]]; then
        echo "[${timestamp}] [${level}] ${stripped_msg}" >> "${LOG_FILE}" 2>/dev/null || true
    fi
    
    # Display to console with formatting
    case "$level" in
        SUCCESS) print_success "$msg" ;;
        ERROR)   print_error "$msg" ;;
        WARN)    print_warning "$msg" ;;
        INFO)    print_info "$msg" ;;
        STEP)    print_step "$msg" ;;
        *)       echo "$msg" ;;
    esac
}

# Fatal error handler
die() {
    local msg="$*"
    print_error "$msg"
    log ERROR "$msg"
    exit 1
}

# Setup logging directory and file
setup_logging() {
    if [[ ! -d "$LOG_DIR" ]]; then
        sudo mkdir -p "$LOG_DIR" || {
            print_error "Failed to create log directory: $LOG_DIR"
            exit 1
        }
        sudo chmod 755 "$LOG_DIR"
    fi
    
    # Create log file (as current user)
    if ! touch "$LOG_FILE" 2>/dev/null; then
        if ! sudo touch "$LOG_FILE"; then
            print_error "Failed to create log file: $LOG_FILE"
            exit 1
        fi
        sudo chown "$(whoami):$(whoami)" "$LOG_FILE"
    fi
    
    chmod 644 "$LOG_FILE" 2>/dev/null || true
    
    log INFO "=== ${SCRIPT_NAME}.sh v${SCRIPT_VERSION} started ==="
    log INFO "Executed by: $(whoami)"
    log INFO "Host: $(hostname)"
    log INFO "Date: $(date)"
}

#############################################################################
# Helper Functions                                                          #
#############################################################################

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

service_is_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

is_silent() {
    [[ "${HARDENING_SILENT:-false}" == "true" ]]
}

# Get local IP (primary interface)
get_local_ip() {
    local ip
    
    # Try ip route first (most reliable)
    ip=$(ip -4 route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[0-9.]+')
    
    # Fallback to hostname -I (first IP)
    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    
    # Final fallback
    if [[ -z "$ip" ]]; then
        ip="<IP>"
    fi
    
    echo "$ip"
}

#############################################################################
# Spinner Function                                                          #
#############################################################################

# Run a command with an animated spinner, elapsed timer, and log capture.
# All command output is redirected to LOG_FILE. Console shows a spinner
# that resolves to ✓/✗ on completion with elapsed time.
#
# Usage:
#   run_with_spinner "Message" command arg1 arg2...

run_with_spinner() {
    local msg="$1"
    shift
    local pid tmp_out exit_code=0
    local spin_idx=0 start_ts now_ts elapsed

    # Skip spinner in non-interactive mode
    if ! [[ -t 1 ]] || is_silent; then
        print_step "$msg"
        log STEP "$msg"
        if "$@"; then
            print_success "Done"
            log SUCCESS "$msg - completed"
            return 0
        else
            print_error "Failed"
            log ERROR "$msg - failed"
            return 1
        fi
    fi

    tmp_out="$(mktemp)" || { log WARN "mktemp failed, running without spinner"; "$@"; return $?; }
    start_ts="$(date +%s)"

    log STEP "$msg" 2>/dev/null || true

    # Run command in background, capture all output
    "$@" >"$tmp_out" 2>&1 &
    pid=$!

    # Show spinner while command runs (no color codes — avoids glyph artifacts)
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

    # Show result with elapsed time (colors only on final line)
    now_ts="$(date +%s)"
    elapsed=$((now_ts - start_ts))
    if [[ $exit_code -eq 0 ]]; then
        printf "\r  %s %s (%ds)\n" "$msg" "${C_GREEN}${SYMBOL_SUCCESS}${C_RESET}" "$elapsed"
    else
        printf "\r  %s %s (%ds)\n" "$msg" "${C_RED}${SYMBOL_ERROR}${C_RESET}" "$elapsed"
    fi

    return $exit_code
}

# Error trap for better debugging
trap 'log ERROR "Command failed at line $LINENO: $BASH_COMMAND"' ERR

#############################################################################
# Cleanup Handler                                                           #
#############################################################################

cleanup() {
    local exit_code=$?
    
    # Restart unattended-upgrades if we stopped it
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == "true" ]]; then
        sudo systemctl start unattended-upgrades 2>/dev/null || true
    fi
    
    # Write to log file only (no console output during cleanup)
    if [[ -n "${LOG_FILE:-}" ]] && [[ -w "${LOG_FILE:-}" ]]; then
        local timestamp
        timestamp=$(date '+%Y-%m-%d %H:%M:%S') 2>/dev/null || true
        if [[ $exit_code -eq 0 ]]; then
            echo "[${timestamp}] [INFO] === Script finished (exit 0) ===" >> "${LOG_FILE}" 2>/dev/null || true
        else
            echo "[${timestamp}] [ERROR] === Script failed (exit ${exit_code}) ===" >> "${LOG_FILE}" 2>/dev/null || true
        fi
    fi
}

# EXIT runs cleanup on any exit. INT/TERM exit immediately (which triggers EXIT).
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

#################################################################
# Application Registry - ADD NEW APPS HERE                      #
#################################################################

# Easy app registration - just add new entries to this array
# Format: "display_name|script_name|detection_command"
readonly APP_REGISTRY=(
    "Docker|docker.sh|command -v docker >/dev/null 2>&1"
    "Nginx Proxy Manager (native)|npm.sh|systemctl is-active --quiet openresty || systemctl is-active --quiet nginx-proxy-manager"
    "Nginx Proxy Manager (Docker)|npm-docker.sh|[[ -f \$HOME/npm/docker-compose.yml ]]"
    "Cloudflare Tunnel|cloudflared.sh|systemctl is-active --quiet cloudflared"
    "Unbound DNS|unbound.sh|systemctl is-active --quiet unbound"
    "Samba File Server|samba.sh|systemctl is-active --quiet smbd"
    "BookStack Wiki|bookstack.sh|[[ -f /etc/apache2/sites-enabled/bookstack.conf ]] && [[ -d /opt/bookstack ]]"
    "BentoPDF|bentopdf.sh|[[ -f /etc/nginx/sites-enabled/bentopdf ]] && [[ -f /opt/bentopdf/index.html ]]"
    # Add more apps here - one per line
    # "App Name|script.sh|detection command that returns 0 if installed"
)

# Base URL for app scripts
readonly APPS_BASE_URL="https://raw.githubusercontent.com/vdarkobar/lab/main/apps"

#################################################################
# Configuration                                                  #
#################################################################

readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"
readonly BACKUP_DIR="/root/hardening-backups-$(date +%Y%m%d-%H%M%S)"

# Hardening marker files (used for detection)
readonly HARDENING_MARKER="/etc/ssh/sshd_config.d/99-lab-hardening.conf"

#################################################################
# CLI Commands                                                   #
#################################################################

cmd_status() {
    echo
    draw_box "Hardening Status" \
        "Script: ${SCRIPT_NAME}.sh v${SCRIPT_VERSION}" \
        "Host:   $(hostname)" \
        "IP:     $(get_local_ip)"
    echo
    
    print_section "Configuration Files"
    
    if [[ -f /etc/ssh/sshd_config.d/99-lab-hardening.conf ]]; then
        print_success "SSH hardening configured"
    else
        print_warning "SSH hardening not found"
    fi
    
    if [[ -f /etc/fail2ban/jail.d/99-lab-hardening.conf ]]; then
        print_success "Fail2Ban configured"
    else
        print_warning "Fail2Ban config not found"
    fi
    
    if [[ -f /etc/sysctl.d/99-lab-hardening.conf ]]; then
        print_success "Sysctl hardening configured"
    else
        print_warning "Sysctl hardening not found"
    fi
    
    if [[ -f /etc/apt/apt.conf.d/52lab-unattended-upgrades ]]; then
        print_success "Unattended-upgrades configured"
    else
        print_warning "Unattended-upgrades config not found"
    fi
    
    print_section "Service Status"
    
    service_is_active sshd 2>/dev/null || service_is_active ssh 2>/dev/null && \
        print_success "SSH: running" || print_warning "SSH: not running"
    service_is_active fail2ban && \
        print_success "Fail2Ban: running" || print_warning "Fail2Ban: not running"
    
    # Check UFW status
    local ufw_cmd
    if command_exists ufw; then
        ufw_cmd="ufw"
    elif [[ -x /usr/sbin/ufw ]]; then
        ufw_cmd="/usr/sbin/ufw"
    fi
    
    if [[ -n "${ufw_cmd:-}" ]]; then
        if sudo "$ufw_cmd" status 2>/dev/null | grep -q "Status: active"; then
            print_success "UFW: active"
        else
            print_warning "UFW: inactive"
        fi
    else
        print_warning "UFW: not installed"
    fi
    
    service_is_active unattended-upgrades && \
        print_success "Unattended-upgrades: running" || print_warning "Unattended-upgrades: not running"
    
    print_section "Management"
    echo "  ${SCRIPT_NAME}.sh --status      Show this status"
    echo "  ${SCRIPT_NAME}.sh --logs [N]    Show recent log entries"
    echo "  ${SCRIPT_NAME}.sh --help        Show full help"
    echo
}

cmd_logs() {
    local lines="${1:-50}"
    local log_dir="/var/log/lab"
    
    # Find the most recent hardening log
    local latest_log
    latest_log=$(ls -t "${log_dir}/${SCRIPT_NAME}"-*.log 2>/dev/null | head -1)
    
    if [[ -z "$latest_log" ]]; then
        # Fall back to legacy log location
        latest_log=$(ls -t /var/log/hardening-*.log 2>/dev/null | head -1)
    fi
    
    if [[ -z "$latest_log" ]]; then
        print_warning "No hardening log files found"
        return 1
    fi
    
    print_info "Log file: $latest_log"
    echo
    tail -n "$lines" "$latest_log"
}

#################################################################
# Previous Run Detection                                         #
#################################################################

check_previous_hardening() {
    # Check for hardening marker files
    if [[ -f "$HARDENING_MARKER" ]]; then
        return 0  # Previously hardened
    fi
    return 1  # Not hardened yet
}

show_already_hardened_menu() {
    # Banner already displayed at start of main()
    draw_box "System Already Hardened"
    
    echo
    print_section "Detected Hardening"
    
    # Show which hardening configs exist
    [[ -f /etc/ssh/sshd_config.d/99-lab-hardening.conf ]] && print_success "SSH hardening configured"
    [[ -f /etc/fail2ban/jail.d/99-lab-hardening.conf ]] && print_success "Fail2Ban configured"
    [[ -f /etc/sysctl.d/99-lab-hardening.conf ]] && print_success "Sysctl hardening configured"
    
    # Check service status
    echo
    print_section "Service Status"
    service_is_active sshd 2>/dev/null || service_is_active ssh 2>/dev/null && \
        print_success "SSH: running" || print_warning "SSH: not running"
    service_is_active fail2ban && \
        print_success "Fail2Ban: running" || print_warning "Fail2Ban: not running"
    
    local ufw_cmd
    if command_exists ufw; then
        ufw_cmd="ufw"
    elif [[ -x /usr/sbin/ufw ]]; then
        ufw_cmd="/usr/sbin/ufw"
    fi
    if [[ -n "${ufw_cmd:-}" ]]; then
        sudo "$ufw_cmd" status 2>/dev/null | grep -q "Status: active" && \
            print_success "UFW: active" || print_warning "UFW: inactive"
    else
        print_warning "UFW: not installed"
    fi
    
    echo
    print_info "Hardening steps will be skipped"
    print_info "You can install additional applications below"
    echo
    
    # Offer app menu (unless silent or skipped)
    if [[ "${HARDENING_SKIP_APPS:-false}" != "true" ]]; then
        if ! is_silent; then
            if show_app_menu; then
                log SUCCESS "Application installation completed"
            else
                print_info "No application selected"
            fi
        fi
    fi
    
    echo
    draw_separator
    echo
}

#################################################################
# Pre-flight Checks                                             #
#################################################################

preflight_checks() {
    print_section "Pre-flight Checks"
    
    # Refuse Proxmox host execution
    if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
        die "This script must not run on the Proxmox VE host. Run inside a VM or LXC."
    fi
    
    # Check systemd
    if [[ ! -d /run/systemd/system ]]; then
        die "This script requires systemd. Non-systemd environments are not supported."
    fi
    
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
    
    # Check OS version
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" != "debian" ]]; then
            print_warning "This script is designed for Debian. Detected: $ID"
        else
            print_success "Debian system detected: $VERSION"
        fi
        log INFO "OS: $PRETTY_NAME"
    else
        print_warning "Cannot determine OS version"
    fi
    
    # Check disk space (need at least 1GB free)
    local free_space=$(df / | awk 'NR==2 {print $4}')
    local free_gb=$((free_space / 1048576))
    if [[ $free_space -lt 1048576 ]]; then
        die "Insufficient disk space. Need at least 1GB free, have ${free_gb}GB"
    fi
    print_success "Sufficient disk space available (${free_gb}GB free)"
    
    # Check internet connectivity (use HTTP instead of ICMP for container compatibility)
    print_step "Testing internet connectivity..."
    if command_exists curl; then
        if curl -s --max-time 5 --head https://deb.debian.org >/dev/null 2>&1; then
            print_success "Internet connectivity verified (via curl)"
        else
            die "No internet connectivity detected (curl test failed)"
        fi
    elif command_exists wget; then
        if wget -q --timeout=5 --spider https://deb.debian.org 2>/dev/null; then
            print_success "Internet connectivity verified (via wget)"
        else
            die "No internet connectivity detected (wget test failed)"
        fi
    else
        print_warning "Cannot verify internet (curl/wget not available yet)"
        print_info "Assuming connectivity OK - will install curl in next step"
    fi
    
    # Stop unattended-upgrades if running
    if service_is_active unattended-upgrades; then
        UNATTENDED_UPGRADES_WAS_ACTIVE=true
        print_step "Stopping unattended-upgrades service..."
        sudo systemctl stop unattended-upgrades
        log INFO "Stopped unattended-upgrades service"
    fi
    
    print_success "Pre-flight checks passed"
    log SUCCESS "Pre-flight checks completed"
    echo
}

#################################################################
# Environment Detection                                          #
#################################################################

detect_environment() {
    print_section "Environment Detection"
    
    # Detect virtualization type
    if command_exists systemd-detect-virt; then
        if systemd-detect-virt --container >/dev/null 2>&1; then
            CONTAINER_TYPE=$(systemd-detect-virt --container)
            IS_CONTAINER=true
            IS_PRIVILEGED=false
            
            # Check if privileged container using multiple indicators
            # Different container runtimes expose different capabilities
            if [[ -c /dev/kmsg ]] || \
               [[ -w /sys/kernel ]] || \
               [[ -e /dev/net/tun ]] || \
               capsh --print 2>/dev/null | grep -q 'cap_sys_admin' || \
               [[ -w /proc/sys/net ]]; then
                IS_PRIVILEGED=true
            fi
        elif systemd-detect-virt --vm >/dev/null 2>&1; then
            CONTAINER_TYPE=$(systemd-detect-virt --vm)
            IS_CONTAINER=false
            IS_PRIVILEGED=true
        else
            CONTAINER_TYPE="bare-metal"
            IS_CONTAINER=false
            IS_PRIVILEGED=true
        fi
    else
        print_warning "systemd-detect-virt not found, assuming VM"
        CONTAINER_TYPE="unknown"
        IS_CONTAINER=false
        IS_PRIVILEGED=true
    fi
    
    print_kv "Environment Type" "$CONTAINER_TYPE"
    print_kv "Is Container" "$IS_CONTAINER"
    print_kv "Is Privileged" "$IS_PRIVILEGED"
    echo
}

#################################################################
# Network Information Detection                                  #
#################################################################

detect_network_info() {
    print_section "Network Configuration"
    
    # Get hostname
    HOSTNAME=$(hostname -s) || HOSTNAME="unknown"
    
    # Detect domain name
    if command_exists resolvectl && service_is_active systemd-resolved; then
        DOMAIN_LOCAL=$(resolvectl status | awk '/DNS Domain:/ {print $3; exit}' | head -n1)
    fi
    
    # Fallback to /etc/resolv.conf
    if [[ -z "${DOMAIN_LOCAL:-}" ]]; then
        DOMAIN_LOCAL=$(awk '/^domain|^search/ {print $2; exit}' /etc/resolv.conf 2>/dev/null)
    fi
    
    # Final fallback
    DOMAIN_LOCAL=${DOMAIN_LOCAL:-"local"}
    
    # Detect primary IP address using standardized helper
    LOCAL_IP=$(get_local_ip)
    
    print_kv "Hostname" "$HOSTNAME"
    print_kv "Domain" "$DOMAIN_LOCAL"
    print_kv "IP Address" "$LOCAL_IP"
    print_kv "FQDN" "$HOSTNAME.$DOMAIN_LOCAL"
    echo
}

#################################################################
# Display Introduction                                           #
#################################################################

show_intro() {
    # Banner already displayed at start of main()
    print_section "System Information"
    print_kv "IP Address" "$LOCAL_IP"
    print_kv "Hostname" "$HOSTNAME"
    print_kv "Domain" "$DOMAIN_LOCAL"
    print_kv "Environment" "$CONTAINER_TYPE"
    print_kv "Executing User" "$(whoami)"
    
    echo
    print_section "Hardening Steps"
    print_subheader "Install security packages (UFW, Fail2Ban, etc.)"
    print_subheader "Configure firewall rules"
    print_subheader "Set up intrusion prevention"
    print_subheader "Harden SSH configuration"
    print_subheader "Enable automatic security updates"
    print_subheader "Apply system security settings"
    print_subheader "Configure SSH key authentication"
    
    echo
    print_section "Requirements"
    print_warning "Script must run as non-root user (currently: $(whoami))"
    print_warning "User must have sudo privileges (will prompt if needed)"
    print_warning "SSH public key required for authentication"
    
    echo
    print_info "Logs will be saved to: ${C_DIM}${LOG_FILE}${C_RESET}"
    print_info "Backups will be saved to: ${C_DIM}${BACKUP_DIR}${C_RESET}"
    echo
}

#################################################################
# Confirm Script Execution                                       #
#################################################################

confirm_start() {
    # Skip in silent mode
    if is_silent; then
        log INFO "Silent mode: auto-confirming start"
        return 0
    fi
    
    draw_separator
    echo
    while true; do
        echo -n "${C_BOLD}${C_CYAN}Proceed with hardening? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
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

#################################################################
# Create Backup Directory                                        #
#################################################################

create_backup_dir() {
    if ! sudo mkdir -p "$BACKUP_DIR"; then
        die "Failed to create backup directory: $BACKUP_DIR"
    fi
    # Give ownership to current user so they can access backups
    sudo chown "$(whoami):$(id -gn)" "$BACKUP_DIR"
    log SUCCESS "Backup directory created"
}

#################################################################
# Backup File                                                    #
#################################################################

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_path="$BACKUP_DIR$(dirname "$file")"
        sudo mkdir -p "$backup_path"
        sudo cp -a "$file" "$backup_path/" || log WARN "Failed to backup $file"
        log INFO "Backed up: ${file}"
    fi
}

#################################################################
# Install Required Packages                                      #
#################################################################

install_packages() {
    print_section "Installing Security Packages"
    
    # Stop unattended upgrades if running (track state to restart later)
    if service_is_active unattended-upgrades; then
        UNATTENDED_UPGRADES_WAS_ACTIVE=true
        sudo systemctl stop unattended-upgrades 2>/dev/null || true
        print_info "Temporarily stopped unattended-upgrades"
    fi
    
    # Update package lists
    run_with_spinner "Updating package repositories" sudo apt-get update \
        || die "Failed to update package repositories"
    
    # Install packages
    local packages=(
        ufw
        fail2ban
        wget
        curl
        gnupg2
        argon2
        lsb-release
        gnupg-agent
        libpam-tmpdir
        bash-completion
        ca-certificates
        qemu-guest-agent
        unattended-upgrades
        cloud-initramfs-growroot
    )
    
    print_subheader "${C_DIM}${packages[*]}${C_RESET}"
    run_with_spinner "Installing security packages" sudo apt-get install -y "${packages[@]}" \
        || die "Failed to install packages"
    
    echo
}

#################################################################
# Configure Hosts File                                           #
#################################################################

configure_hosts() {
    print_section "Configuring System Hosts File"
    
    backup_file "/etc/hosts"
    
    # Create new hosts file
    local temp_hosts=$(mktemp)
    
    {
        echo "127.0.0.1       localhost"
        echo "::1             localhost ip6-localhost ip6-loopback"
        echo "ff02::1         ip6-allnodes"
        echo "ff02::2         ip6-allrouters"
        echo ""
        echo "# Host configuration (FQDN first, then shortname)"
        echo "$LOCAL_IP       $HOSTNAME.$DOMAIN_LOCAL $HOSTNAME"
        echo ""
        echo "# Existing entries (if any)"
        grep -v -E '^(127\.0\.0\.1|::1|ff02::|#.*|^$)' /etc/hosts 2>/dev/null | \
        grep -v "$HOSTNAME" || true
    } > "$temp_hosts"
    
    if sudo mv "$temp_hosts" /etc/hosts; then
        sudo chmod 644 /etc/hosts
        log SUCCESS "Hosts file configured"
    else
        die "Failed to update /etc/hosts"
    fi
    echo
}

#################################################################
# Configure Unattended Upgrades                                  #
#################################################################

configure_unattended_upgrades() {
    print_section "Configuring Automatic Security Updates"
    
    # Enable unattended-upgrades
    print_step "Enabling unattended-upgrades..."
    if ! echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | \
         sudo debconf-set-selections; then
        die "Failed to configure unattended-upgrades"
    fi
    
    if ! sudo dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1; then
        die "Failed to enable unattended-upgrades"
    fi
    
    # Use drop-in file instead of modifying vendor config (survives package upgrades)
    local dropin_file="/etc/apt/apt.conf.d/52lab-unattended-upgrades"
    
    print_step "Creating unattended-upgrades drop-in configuration..."
    
    # Write drop-in config (overwrites if exists - idempotent)
    sudo tee "$dropin_file" > /dev/null << 'EOF'
// Managed by lab/hardening.sh - do not edit manually
// Overrides settings in 50unattended-upgrades

Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
    
    log SUCCESS "Unattended-upgrades drop-in config created: $dropin_file"
    print_info "System will automatically reboot at 02:00 if needed"
    echo
}

#################################################################
# Configure Fail2Ban                                             #
#################################################################

configure_fail2ban() {
    print_section "Configuring Fail2Ban Intrusion Prevention"
    
    if ! command_exists fail2ban-server; then
        die "Fail2Ban is not installed"
    fi
    
    # Use drop-in config instead of editing jail.local
    # This survives package upgrades and is fully idempotent
    local dropin_dir="/etc/fail2ban/jail.d"
    local dropin_file="${dropin_dir}/99-lab-hardening.conf"
    
    print_step "Creating Fail2Ban drop-in configuration..."
    sudo mkdir -p "$dropin_dir"
    
    # Write drop-in config (overwrites if exists - idempotent)
    sudo tee "$dropin_file" > /dev/null << 'EOF'
# Managed by lab/hardening.sh - do not edit manually
# User customizations belong in jail.local or other jail.d/ files

[DEFAULT]
# Use systemd backend (fixes Debian bug with auto backend)
backend = systemd

# Stricter limits: 3 attempts, 15 minute ban
bantime = 15m
maxretry = 3
findtime = 10m

[sshd]
enabled = true
EOF
    
    log SUCCESS "Fail2Ban drop-in config created: $dropin_file"
    
    # Restart Fail2Ban to apply changes
    print_step "Restarting Fail2Ban service..."
    if sudo systemctl restart fail2ban; then
        sleep 1
        if service_is_active fail2ban; then
            log SUCCESS "Fail2Ban configured and running"
        else
            print_warning "Fail2Ban may not be running after restart"
        fi
    else
        print_warning "Fail2Ban restart failed, may need manual intervention"
    fi
    echo
}

#################################################################
# Configure UFW Firewall                                         #
#################################################################

configure_ufw() {
    print_section "Configuring UFW Firewall"
    
    # Skip if requested via environment variable
    if [[ "${HARDENING_SKIP_UFW:-false}" == "true" ]]; then
        print_warning "Skipping firewall configuration (HARDENING_SKIP_UFW=true)"
        log WARN "Firewall configuration skipped by user request"
        return 0
    fi
    
    # Test if UFW can actually work by trying to reset it
    # This is more reliable than checking container privilege indicators
    print_step "Testing UFW availability..."
    if ! sudo ufw --force reset >/dev/null 2>&1; then
        # Check if it's a permission/capability issue
        if [[ "$IS_CONTAINER" == "true" ]]; then
            print_warning "UFW not functional in this container (missing capabilities)"
            print_info "Configure firewall on the Proxmox host instead"
        else
            print_warning "UFW reset failed - firewall may need manual configuration"
        fi
        echo
        return
    fi
    print_success "UFW is functional"
    
    # Set default policies
    print_step "Setting default policies..."
    sudo ufw default deny incoming >/dev/null
    sudo ufw default allow outgoing >/dev/null
    
    # Allow SSH (rate limited)
    print_step "Allowing SSH with rate limiting..."
    sudo ufw limit 22/tcp comment "SSH" >/dev/null
    
    # Enable UFW
    if sudo ufw --force enable >/dev/null 2>&1; then
        log SUCCESS "UFW firewall configured and enabled"
    else
        print_warning "UFW enable failed, may need manual configuration"
    fi
    echo
}

#################################################################
# Configure Sysctl (Network Security)                            #
#################################################################

configure_sysctl() {
    print_section "Applying Network Security Settings"
    
    local sysctl_file="/etc/sysctl.d/99-lab-hardening.conf"
    
    backup_file "$sysctl_file"
    
    print_step "Creating sysctl drop-in configuration..."
    # Create sysctl configuration (overwrites if exists - idempotent)
    sudo tee "$sysctl_file" > /dev/null << 'EOF'
# Managed by lab/hardening.sh - do not edit manually
# Network security hardening settings

# Note: ip_forward not disabled here (breaks Docker/WireGuard)
# Add manually if this server will never need forwarding

# Reverse path filtering
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# TCP hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
EOF

    log SUCCESS "Sysctl drop-in config created: $sysctl_file"

    # Apply settings (may fail in unprivileged containers)
    print_step "Applying sysctl settings..."
    if sudo sysctl -p "$sysctl_file" >/dev/null 2>&1; then
        log SUCCESS "Network security settings applied"
    else
        print_warning "Some settings failed (expected in unprivileged containers)"
        # Show which settings were denied (|| true prevents pipefail exit)
        sudo sysctl -p "$sysctl_file" 2>&1 | grep -i "permission denied" | \
        while read -r line; do
            print_subheader "Denied: $(echo "$line" | awk '{print $2}')"
        done || true
    fi
    echo
}

#################################################################
# Configure SSH Key Authentication                               #
#################################################################

configure_ssh_keys() {
    print_section "Configuring SSH Key Authentication"
    
    # Skip in silent mode (key must be pre-configured)
    if is_silent; then
        local auth_keys="$HOME/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]] && [[ -s "$auth_keys" ]]; then
            print_success "SSH authorized_keys file exists (silent mode)"
            log INFO "Silent mode: SSH key already configured"
            return 0
        else
            die "Silent mode requires SSH key to be pre-configured in $auth_keys"
        fi
    fi
    
    local user=$(whoami)
    local ssh_dir="$HOME/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"
    
    # Create .ssh directory if it doesn't exist
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
        print_success "Created .ssh directory"
    fi
    
    # Create authorized_keys if it doesn't exist
    if [[ ! -f "$auth_keys" ]]; then
        touch "$auth_keys"
        chmod 600 "$auth_keys"
        print_success "Created authorized_keys file"
    fi
    
    # Request SSH public key
    echo
    draw_separator
    echo
    print_info "SSH Public Key Configuration"
    echo
    print_subheader "Paste your SSH public key below"
    print_subheader "Recommended: ed25519 keys for better security"
    echo
    echo "  ${C_DIM}Example: ssh-ed25519 AAAAC3Nza... user@host${C_RESET}"
    echo
    
    while true; do
        echo -n "${C_CYAN}Public Key: ${C_RESET}"
        read -r public_key
        
        # Trim leading/trailing whitespace
        public_key=$(echo "$public_key" | xargs)
        
        # Check if input is empty
        if [[ -z "$public_key" ]]; then
            print_error "No input received"
            continue
        fi
        
        # Check if user accidentally pasted a private key
        if [[ "$public_key" == *"-----BEGIN"* ]] || [[ "$public_key" == *"PRIVATE KEY"* ]]; then
            print_error "That looks like a PRIVATE key! Never share your private key."
            print_info "Paste your PUBLIC key (usually from ~/.ssh/id_ed25519.pub)"
            continue
        fi
        
        # Validate SSH key format
        if [[ "$public_key" =~ ^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-ed25519)[[:space:]][A-Za-z0-9+/]+[=]{0,3}([[:space:]].*)?$ ]]; then
            # Check if key already exists
            if grep -Fq "$public_key" "$auth_keys" 2>/dev/null; then
                print_info "SSH key already exists in authorized_keys"
                break
            fi
            
            # Add key to authorized_keys
            echo "$public_key" >> "$auth_keys"
            chmod 600 "$auth_keys"
            log SUCCESS "SSH public key added successfully"
            break
        else
            print_error "Invalid SSH key format"
            print_subheader "Valid formats: ssh-rsa, ssh-ed25519, ecdsa-sha2-*"
        fi
    done
    
    echo
}

#################################################################
# Lock Root Account                                              #
#################################################################

lock_root_account() {
    print_section "Securing Root Account"
    
    # Check if root is already locked
    if sudo passwd -S root | grep -q " L "; then
        print_info "Root account password already locked"
    else
        if sudo passwd -l root >/dev/null 2>&1; then
            log SUCCESS "Root account password locked"
        else
            print_warning "Failed to lock root account"
        fi
    fi
    echo
}

#################################################################
# Configure SSH Daemon                                           #
#################################################################

configure_sshd() {
    print_section "Hardening SSH Configuration"
    
    local sshd_config="/etc/ssh/sshd_config"
    local dropin_dir="/etc/ssh/sshd_config.d"
    local dropin_file="${dropin_dir}/99-lab-hardening.conf"
    local backup="/tmp/sshd_lab_backup_$$"
    local user=$(whoami)
    
    backup_file "$sshd_config"
    
    # Ensure drop-in directory exists
    sudo mkdir -p "$dropin_dir"
    
    # Check if Include directive exists in main config
    print_step "Checking SSH Include directive..."
    if ! grep -qE '^[[:space:]]*Include.*/etc/ssh/sshd_config\.d/' "$sshd_config" 2>/dev/null; then
        print_warning "Adding Include directive to $sshd_config"
        # Portable prepend: create new file with Include + original content
        local include_line="Include /etc/ssh/sshd_config.d/*.conf"
        local tmpfile="${sshd_config}.labtmp"
        { printf '%s\n' "$include_line"; sudo cat "$sshd_config"; } | sudo tee "$tmpfile" > /dev/null
        sudo mv "$tmpfile" "$sshd_config"
    else
        print_success "Include directive already present"
    fi
    
    # Backup current drop-in if exists
    [[ -f "$dropin_file" ]] && sudo cp "$dropin_file" "$backup"
    
    print_step "Creating SSH hardening drop-in configuration..."
    
    # Write drop-in config (overwrites if exists - idempotent)
    # Note: Removed deprecated options: Protocol 2, ChallengeResponseAuthentication, Compression delayed
    sudo tee "$dropin_file" > /dev/null << EOF
# Managed by lab/hardening.sh - do not edit manually
# SSH security hardening settings

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM no

# Security limits
MaxAuthTries 3
MaxSessions 2
X11Forwarding no
StrictModes yes
IgnoreRhosts yes
GSSAPIAuthentication no

# Connection timeouts
ClientAliveInterval 300
ClientAliveCountMax 2

# Rate limiting
MaxStartups 10:30:60
LoginGraceTime 30

# Security hardening
PermitUserEnvironment no
LogLevel VERBOSE

# Allowed ciphers and algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Restrict SSH access to current user
AllowUsers ${user}
EOF

    log SUCCESS "SSH drop-in config created: $dropin_file"
    
    # Validate SSH configuration before restart
    print_step "Validating SSH configuration..."
    local validation_output
    if ! validation_output=$(sudo sshd -t -f "$sshd_config" 2>&1); then
        print_error "SSH configuration has errors, rolling back..."
        print_error "Validation error: $validation_output"
        if [[ -f "$backup" ]]; then
            sudo mv "$backup" "$dropin_file"
        else
            sudo rm -f "$dropin_file"
        fi
        # Restart after rollback
        sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null || true
        die "SSH configuration validation failed"
    fi
    log SUCCESS "SSH configuration is valid"
    
    # Restart SSH service (reload often fails with config changes)
    print_step "Restarting SSH service..."
    local svc=""
    if systemctl list-unit-files ssh.service &>/dev/null; then
        svc="ssh"
    elif systemctl list-unit-files sshd.service &>/dev/null; then
        svc="sshd"
    fi
    
    if [[ -n "$svc" ]] && sudo systemctl restart "$svc"; then
        sleep 1
        if service_is_active "$svc"; then
            log SUCCESS "SSH service restarted and running"
        else
            print_error "SSH service not active after restart, rolling back..."
            if [[ -f "$backup" ]]; then
                sudo mv "$backup" "$dropin_file"
            else
                sudo rm -f "$dropin_file"
            fi
            sudo systemctl restart "$svc" || true
            die "SSH service failed after restart"
        fi
    else
        print_warning "Failed to restart SSH service"
    fi
    
    rm -f "$backup"
    echo
}

#################################################################
# Check if Application is Installed                             #
#################################################################

check_app_installed() {
    local detection_cmd="$1"
    
    # Run detection command, suppress output
    if eval "$detection_cmd" 2>/dev/null; then
        return 0  # Installed
    else
        return 1  # Not installed
    fi
}

#################################################################
# Show Application Menu                                         #
#################################################################

show_app_menu() {
    print_section "Application Installation"
    
    echo
    print_info "Available applications to install:"
    echo
    
    local available_apps=()
    local app_count=0
    
    # Build menu of available (not installed) apps
    for app_entry in "${APP_REGISTRY[@]}"; do
        IFS='|' read -r display_name script_name detection_cmd <<< "$app_entry"
        
        if check_app_installed "$detection_cmd"; then
            print_subheader "${C_DIM}$display_name - Already installed ✓${C_RESET}"
        else
            ((app_count++)) || true
            available_apps+=("$app_entry")
            print_subheader "${C_CYAN}${app_count})${C_RESET} $display_name ${C_DIM}(${script_name})${C_RESET}"
        fi
    done
    
    echo
    print_subheader "${C_CYAN}$((app_count + 1)))${C_RESET} Skip - No application installation"
    echo
    
    # If no apps available, skip
    if [[ $app_count -eq 0 ]]; then
        print_warning "All applications already installed"
        return 1
    fi
    
    # Get user selection
    while true; do
        echo -n "${C_CYAN}${C_BOLD}Select application to install [1-$((app_count + 1))]:${C_RESET} "
        read -r selection
        
        # Validate numeric input first (before any integer comparisons)
        if [[ ! "$selection" =~ ^[0-9]+$ ]]; then
            print_error "Invalid selection. Enter a number."
            continue
        fi
        
        # Check if user wants to skip
        if [[ "$selection" -eq $((app_count + 1)) ]]; then
            print_info "Skipping application installation"
            return 1
        fi
        
        # Validate selection range
        if [[ "$selection" -ge 1 ]] && [[ "$selection" -le $app_count ]]; then
            # Get selected app
            local selected_app="${available_apps[$((selection - 1))]}"
            IFS='|' read -r display_name script_name detection_cmd <<< "$selected_app"
            
            print_success "Selected: $display_name"
            echo
            
            # Install from local script (falls back to download if not found)
            install_app "$script_name" "$display_name"
            return 0
        else
            print_error "Invalid selection. Please enter a number between 1 and $((app_count + 1))"
        fi
    done
}

#################################################################
# Install Application from Local Scripts                        #
#################################################################

install_app() {
    local script_name="$1"
    local display_name="$2"
    local local_script="${SCRIPT_DIR}/../apps/${script_name}"
    local checksums_file="${SCRIPT_DIR}/../CHECKSUMS.txt"
    local checksum_verified=false
    
    print_section "Installing: $display_name"
    
    # Check if local script exists
    if [[ -f "$local_script" ]]; then
        print_success "Found local script: ${local_script}"
        
        # Verify checksum
        print_step "Verifying integrity..."
        
        if [[ -f "$checksums_file" ]]; then
            local expected_hash=$(grep "apps/${script_name}" "$checksums_file" | grep -v '^#' | awk '{print $1}')
            
            if [[ -n "$expected_hash" ]]; then
                local actual_hash=$(sha256sum "$local_script" | awk '{print $1}')
                
                if [[ "$actual_hash" == "$expected_hash" ]]; then
                    print_success "Checksum verified: ${C_DIM}${actual_hash:0:16}...${C_RESET}"
                    checksum_verified=true
                else
                    print_error "Expected: ${C_DIM}${expected_hash:0:16}...${C_RESET}"
                    print_error "Got:      ${C_DIM}${actual_hash:0:16}...${C_RESET}"
                    print_error "Checksum verification FAILED!"
                    print_error "Local script may have been modified or is outdated"
                    return 1
                fi
            else
                print_warning "No checksum found for ${script_name}"
            fi
        else
            print_warning "CHECKSUMS.txt not found"
        fi
        
        # Execute the local script
        echo
        print_step "Executing ${script_name}..."
        chmod +x "$local_script"
        
        if bash "$local_script"; then
            log SUCCESS "${display_name} installed successfully"
            print_success "${display_name} installation completed"
        else
            log ERROR "${display_name} installation failed (exit code: $?)"
            print_error "${display_name} installation failed"
            return 1
        fi
    else
        # Fallback: download if local script not found
        print_warning "Local script not found: ${local_script}"
        print_step "Falling back to download..."
        download_and_install_app "$script_name" "$display_name"
        return $?
    fi
    
    echo
}

#################################################################
# Download and Install Application (fallback)                   #
#################################################################

download_and_install_app() {
    local script_name="$1"
    local display_name="$2"
    local script_url="${APPS_BASE_URL}/${script_name}"
    local tmp_script="/tmp/app-install-$RANDOM.sh"
    local checksum_verified=false
    
    # Remote checksums URL
    local checksums_url="https://raw.githubusercontent.com/vdarkobar/lab/main/CHECKSUMS.txt"
    local tmp_checksums="/tmp/checksums-$RANDOM.txt"
    
    print_section "Installing: $display_name (downloading)"
    
    # Download script
    print_step "Downloading ${script_name}..."
    print_subheader "Source: ${C_DIM}${script_url}${C_RESET}"
    
    if ! curl -fsSL "$script_url" -o "$tmp_script"; then
        print_error "Failed to download ${script_name}"
        return 1
    fi
    
    local file_size=$(stat -c%s "$tmp_script" 2>/dev/null || stat -f%z "$tmp_script" 2>/dev/null || echo "unknown")
    print_success "Script downloaded (${file_size} bytes)"
    
    # Download checksums from repo for verification
    print_step "Downloading checksums for verification..."
    
    if curl -fsSL "$checksums_url" -o "$tmp_checksums" 2>/dev/null; then
        print_success "Downloaded CHECKSUMS.txt from repository"
        
        # Extract expected hash for this script
        local expected_hash=$(grep "apps/${script_name}" "$tmp_checksums" | grep -v '^#' | awk '{print $1}')
        rm -f "$tmp_checksums"
        
        if [[ -n "$expected_hash" ]]; then
            local actual_hash=$(sha256sum "$tmp_script" | awk '{print $1}')
            
            print_step "Verifying integrity..."
            if [[ "$actual_hash" == "$expected_hash" ]]; then
                print_success "Checksum verified: ${C_DIM}${actual_hash:0:16}...${C_RESET}"
                checksum_verified=true
            else
                rm -f "$tmp_script"
                print_error "Expected: ${C_DIM}${expected_hash:0:16}...${C_RESET}"
                print_error "Got:      ${C_DIM}${actual_hash:0:16}...${C_RESET}"
                print_error "Checksum verification FAILED!"
                return 1
            fi
        else
            print_warning "No checksum found in CHECKSUMS.txt for ${script_name}"
        fi
    else
        print_warning "Failed to download CHECKSUMS.txt from repository"
        rm -f "$tmp_checksums"
    fi
    
    # If no checksum verification, ask user
    if [[ "$checksum_verified" == false ]]; then
        if is_silent; then
            rm -f "$tmp_script"
            die "Silent mode: cannot execute unverified script"
        fi
        
        print_warning "Proceeding without verification (not recommended)"
        
        # Show what we're about to run
        echo
        print_step "Script preview (first 20 lines):"
        echo "${C_DIM}"
        head -20 "$tmp_script"
        echo "${C_RESET}"
        echo
        
        # Ask for confirmation
        while true; do
            echo -n "${C_BOLD}${C_RED}Execute unverified script? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r response
            
            case "$(echo "$response" | tr '[:upper:]' '[:lower:]')" in
                yes|y)
                    print_warning "Proceeding without verification"
                    break
                    ;;
                no|n)
                    rm -f "$tmp_script"
                    print_info "Installation cancelled"
                    return 1
                    ;;
                *)
                    print_error "Invalid input. Please enter 'yes' or 'no'"
                    ;;
            esac
        done
    fi
    
    # Execute the script
    echo
    print_step "Executing ${script_name}..."
    chmod +x "$tmp_script"
    
    if bash "$tmp_script"; then
        log SUCCESS "${display_name} installed successfully"
        print_success "${display_name} installation completed"
    else
        log ERROR "${display_name} installation failed (exit code: $?)"
        print_error "${display_name} installation failed"
    fi
    
    # Cleanup
    rm -f "$tmp_script"
    echo
}

#################################################################
# Final Summary                                                  #
#################################################################

show_summary() {
    echo
    draw_box "Hardening Completed Successfully" \
        "All security measures have been applied"
    
    echo
    print_section "Summary"
    print_success "Security packages installed and configured"
    print_success "Firewall (UFW) enabled and configured"
    print_success "Fail2Ban active for intrusion prevention"
    print_success "SSH hardened (password auth disabled)"
    print_success "Automatic security updates enabled"
    print_success "System security settings applied"
    
    echo
    print_section "Critical Next Steps"
    echo
    print_warning "Test SSH access from another terminal NOW"
    print_warning "Verify SSH key authentication works"
    print_warning "Do NOT close this session until verified"
    
    echo
    print_section "Important Information"
    print_kv "Log File" "$LOG_FILE"
    print_kv "Backups" "$BACKUP_DIR"
    print_kv "FQDN" "$HOSTNAME.$DOMAIN_LOCAL"
    print_kv "IP Address" "$LOCAL_IP"
    print_kv "SSH User" "$(whoami)"
    
    echo
    print_section "Management Commands"
    echo "  ${C_CYAN}${C_BOLD}${SCRIPT_NAME}.sh --status${C_RESET}      Show hardening status"
    echo "  ${C_CYAN}${C_BOLD}${SCRIPT_NAME}.sh --logs${C_RESET}        Show recent logs"
    echo
    
    print_section "Next SSH Connection"
    echo "  ${C_CYAN}${C_BOLD}ssh $(whoami)@$LOCAL_IP${C_RESET}"
    echo
    
    draw_separator
    echo
}

#################################################################
# Main Execution                                                 #
#################################################################

main() {
    # Show banner first — all output flows below it
    [[ -t 1 ]] && ! is_silent && clear
    echo
    draw_box "Debian Server Hardening Script v${SCRIPT_VERSION}" \
        "Secure your Debian 13 server"
    echo

    # Early check: Verify sudo is available before we do anything
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: sudo is not installed or not in PATH" >&2
        echo "This script requires sudo. Please install it first:" >&2
        echo "  apt update && apt install sudo" >&2
        exit 1
    fi
    
    # Refuse root execution early (before any sudo calls)
    if [[ ${EUID} -eq 0 ]]; then
        echo "ERROR: This script must NOT be run as root!" >&2
        echo "Run as a regular user with sudo privileges:" >&2
        echo "  ./$(basename "$0")" >&2
        exit 1
    fi
    
    # Verify user has sudo access before creating log file
    if ! sudo -v 2>/dev/null; then
        echo "ERROR: Current user $(whoami) does not have sudo privileges" >&2
        echo "Please add user to sudo group:" >&2
        echo "  usermod -aG sudo $(whoami)" >&2
        echo "Then logout and login again" >&2
        exit 1
    fi
    
    # Check for previous hardening run
    if check_previous_hardening; then
        show_already_hardened_menu
        exit 0
    fi
    
    # Initialize logging
    setup_logging
    
    # Run checks and setup
    preflight_checks
    detect_environment
    detect_network_info
    create_backup_dir
    
    # Show intro and get confirmation
    show_intro
    confirm_start
    
    # Execute hardening steps
    install_packages
    configure_hosts
    configure_unattended_upgrades
    configure_fail2ban
    configure_ufw
    configure_sysctl
    configure_ssh_keys
    lock_root_account
    configure_sshd
    
    # Show application installation menu (unless skipped)
    if [[ "${HARDENING_SKIP_APPS:-false}" != "true" ]] && ! is_silent; then
        if show_app_menu; then
            log SUCCESS "Application installation completed"
        else
            print_info "Application installation skipped"
        fi
    else
        if is_silent; then
            log INFO "Silent mode: skipping app installation menu"
        else
            log INFO "Application installation skipped (HARDENING_SKIP_APPS=true)"
        fi
    fi
    
    # Show summary
    show_summary
    
    log INFO "=== Server Hardening Script Completed ==="
}

# Route CLI commands
case "${1:-}" in
    --status)
        cmd_status
        exit 0
        ;;
    --logs)
        cmd_logs "${2:-50}"
        exit 0
        ;;
    "")
        # Default: install/harden
        main
        ;;
    *)
        echo "Unknown option: $1" >&2
        echo "Run '$0 --help' for usage" >&2
        exit 1
        ;;
esac
