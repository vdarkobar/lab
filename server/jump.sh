#!/bin/bash

#############################################################################
# Bastion Host / Jump Server Setup                                          #
# Hardens a Debian server for secure SSH access with 2FA                    #
#############################################################################

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="jump"

# Handle --help and --version early (before set -euo pipefail)
case "${1:-}" in
    --help|-h)
        echo "Bastion Host / Jump Server Setup v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [COMMAND]"
        echo
        echo "Commands:"
        echo "  (no args)       Install / harden bastion host (default)"
        echo "  --help, -h      Show this help and exit"
        echo "  --version, -v   Show version and exit"
        echo "  --status        Show service status and access info"
        echo "  --logs [N]      Show recent logs (default 50 lines)"
        echo "  --configure     Re-run 2FA / SSH key setup"
        echo "  --uninstall     Reverse hardening (interactive)"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"Jump Server\""
        echo "  Or run directly: ./jump.sh"
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Clean Debian 13 VM or LXC container"
        echo "  - Internet connection"
        echo
        echo "What it does:"
        echo "  - Installs security packages (fail2ban, ufw, etc.)"
        echo "  - Configures SSH with 2FA (Google Authenticator)"
        echo "  - Sets up UFW firewall (SSH on port 22)"
        echo "  - Hardens sysctl settings (LXC-safe)"
        echo "  - Generates Ed25519 SSH key pair"
        echo "  - Locks root account"
        echo
        echo "Environment variables:"
        echo "  JUMP_SILENT=true       Non-interactive mode (no prompts)"
        echo "  JUMP_SKIP_UFW=true     Skip firewall configuration"
        echo "  JUMP_SKIP_2FA=true     Skip Google Authenticator setup"
        echo "  JUMP_SKIP_KEYGEN=true  Skip SSH key generation"
        echo "  JUMP_SKIP_REBOOT=true  Skip reboot prompt"
        echo
        echo "Files created:"
        echo "  /var/log/lab/jump-*.log                         Installation log"
        echo "  ~/.ssh/id_ed25519                               SSH private key"
        echo "  ~/.ssh/id_ed25519.pub                           SSH public key"
        echo "  /etc/ssh/sshd_config.d/99-lab-bastion.conf      SSH hardening"
        echo "  /etc/sysctl.d/99-lab-bastion.conf               Sysctl hardening"
        echo "  /etc/fail2ban/jail.d/99-lab-bastion.conf        Fail2Ban config"
        echo "  /etc/apt/apt.conf.d/99-lab-bastion              Unattended upgrades"
        echo
        echo "Post-install:"
        echo "  SSH: ssh user@host -p 22"
        echo "  Jump: ssh -J user@bastion:22 user@remote_host"
        exit 0
        ;;
    --version|-v)
        echo "${SCRIPT_NAME} v${SCRIPT_VERSION}"
        exit 0
        ;;
esac

#############################################################################
# Strict Mode & Globals                                                     #
#############################################################################

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

UNATTENDED_UPGRADES_WAS_ACTIVE=false

# App-prefixed environment variables
readonly SILENT="${JUMP_SILENT:-false}"
readonly SKIP_UFW="${JUMP_SKIP_UFW:-false}"
readonly SKIP_2FA="${JUMP_SKIP_2FA:-false}"
readonly SKIP_KEYGEN="${JUMP_SKIP_KEYGEN:-false}"
readonly SKIP_REBOOT="${JUMP_SKIP_REBOOT:-false}"

# Logging
readonly LOG_DIR="/var/log/lab"
LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Bastion markers (for already-installed detection)
readonly BASTION_SSH_DROPIN="/etc/ssh/sshd_config.d/99-lab-bastion.conf"
readonly BASTION_SYSCTL_DROPIN="/etc/sysctl.d/99-lab-bastion.conf"
readonly BASTION_F2B_DROPIN="/etc/fail2ban/jail.d/99-lab-bastion.conf"
readonly BASTION_UAU_DROPIN="/etc/apt/apt.conf.d/99-lab-bastion"

#############################################################################
# Early Safety Checks (before any functions — plain echo only)              #
#############################################################################

# Check sudo is available before we do anything
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
    
    local box_width=$((max_width + 4))
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
    if [[ -w "${LOG_FILE:-}" ]]; then
        echo "[${timestamp}] [${level}] ${stripped_msg}" >> "${LOG_FILE}" 2>/dev/null || true
    fi
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
    [[ "${SILENT:-false}" == "true" ]]
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
# Spinner (Optional - For Long-Running Operations)                          #
#############################################################################

# Run a command with an animated spinner, elapsed timer, and log capture.
# All command output is redirected to LOG_FILE. Console shows a spinner
# that resolves to ✓/✗ on completion with elapsed time.
#
# Usage:
#   run_with_spinner "Message" command arg1 arg2...
#
# Notes:
#   - Command runs in a background subshell (trap ERR does not fire for it)
#   - Safe with set -e: uses 'wait || exit_code=$?' to prevent errexit from
#     killing the function before cleanup (temp file removal, log capture)
#   - Exit code is preserved and returned to caller
#   - Falls back to running without spinner if mktemp fails
#   - No ANSI color codes during spin loop (avoids tput sgr0 glyph artifacts)

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

    # Show spinner while command runs
    # IMPORTANT: No color codes in the spin loop — tput sgr0 emits \033(B
    # (G0 charset reset) which renders as a white square next to braille
    # characters on many terminals. Colors are only used on the final line.
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

#############################################################################
# Cleanup Handler                                                           #
#############################################################################

cleanup() {
    local exit_code=$?
    
    # Restart unattended-upgrades if we stopped it
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == "true" ]]; then
        print_step "Restarting unattended-upgrades service..."
        sudo systemctl start unattended-upgrades 2>/dev/null || true
        log INFO "Restarted unattended-upgrades service"
    fi
    
    if [[ $exit_code -eq 0 ]]; then
        log INFO "=== Installation completed successfully ==="
    else
        log ERROR "=== Installation failed with exit code: $exit_code ==="
    fi
}

trap cleanup EXIT INT TERM

# ERR trap for debugging
trap 'log ERROR "Command failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

#############################################################################
# Pre-flight Checks                                                         #
#############################################################################

preflight_checks() {
    print_section "Pre-flight Checks"
    
    # Refuse Proxmox host execution
    if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
        die "This script must not run on the Proxmox VE host. Run inside a VM or LXC."
    fi
    
    # Check systemd
    if [[ ! -d /run/systemd/system ]]; then
        die "This script requires systemd"
    fi
    
    # Check OS version
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" != "debian" ]]; then
            print_warning "This script is designed for Debian"
        fi
        print_info "Detected OS: $PRETTY_NAME"
        log INFO "OS: $PRETTY_NAME"
    fi
    
    # Check internet connectivity
    print_step "Testing internet connectivity..."
    if command_exists curl; then
        if curl -s --max-time 5 --head https://www.google.com >/dev/null 2>&1; then
            print_success "Internet connectivity verified"
            log INFO "Internet connectivity verified"
        else
            die "No internet connectivity detected"
        fi
    elif command_exists wget; then
        if wget -q --timeout=5 --spider https://www.google.com 2>/dev/null; then
            print_success "Internet connectivity verified"
            log INFO "Internet connectivity verified"
        else
            die "No internet connectivity detected"
        fi
    else
        print_warning "Cannot verify internet (curl/wget not available yet)"
        log WARN "Cannot verify internet connectivity"
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
}

#############################################################################
# Network Detection                                                         #
#############################################################################

# Network info (populated by detect_network_info)
DETECTED_HOSTNAME=""
DETECTED_DOMAIN=""
DETECTED_IP=""

detect_network_info() {
    print_section "Network Detection"
    
    # Get hostname
    DETECTED_HOSTNAME=$(hostname -s)
    print_success "Hostname: $DETECTED_HOSTNAME"
    log INFO "Hostname: $DETECTED_HOSTNAME"
    
    # Extract domain from /etc/resolv.conf
    DETECTED_DOMAIN=$(awk -F' ' '/^domain/ {print $2; exit}' /etc/resolv.conf)
    if [[ -z "$DETECTED_DOMAIN" ]]; then
        DETECTED_DOMAIN=$(awk -F' ' '/^search/ {print $2; exit}' /etc/resolv.conf)
    fi
    
    if [[ -n "$DETECTED_DOMAIN" ]]; then
        print_success "Domain: $DETECTED_DOMAIN"
        log INFO "Domain: $DETECTED_DOMAIN"
    else
        print_warning "Domain not found in /etc/resolv.conf"
        log WARN "Domain not found, defaulting to 'local'"
        DETECTED_DOMAIN="local"
    fi
    
    # Get IP address (standard method)
    DETECTED_IP=$(get_local_ip)
    print_success "IP Address: $DETECTED_IP"
    log INFO "IP Address: $DETECTED_IP"
}

#############################################################################
# Interactive Elements                                                      #
#############################################################################

show_intro() {
    [[ -t 1 ]] && ! is_silent && clear
    
    local local_ip
    local_ip=$(get_local_ip)
    
    draw_box "Bastion Host / Jump Server Setup v${SCRIPT_VERSION}" \
        "" \
        "${C_BOLD}System Information${C_RESET}" \
        "  ${SYMBOL_BULLET} Hostname: $(hostname)" \
        "  ${SYMBOL_BULLET} IP Address: ${local_ip}" \
        "  ${SYMBOL_BULLET} User: $(whoami)" \
        "" \
        "${C_BOLD}Installation Steps${C_RESET}" \
        "  ${SYMBOL_BULLET} Install security packages" \
        "  ${SYMBOL_BULLET} Configure /etc/hosts" \
        "  ${SYMBOL_BULLET} Setup unattended upgrades" \
        "  ${SYMBOL_BULLET} Configure UFW firewall" \
        "  ${SYMBOL_BULLET} Configure Fail2Ban" \
        "  ${SYMBOL_BULLET} Harden sysctl settings (LXC-safe)" \
        "  ${SYMBOL_BULLET} Lock root account" \
        "  ${SYMBOL_BULLET} Configure PAM + SSH with 2FA" \
        "  ${SYMBOL_BULLET} Generate SSH key pair" \
        "  ${SYMBOL_BULLET} Setup Google Authenticator" \
        "" \
        "${C_BOLD}Requirements${C_RESET}" \
        "  ${SYMBOL_BULLET} Debian 13 (Trixie) or 12 (Bookworm)" \
        "  ${SYMBOL_BULLET} Non-root user with sudo" \
        "  ${SYMBOL_BULLET} Internet connectivity" \
        ""
    
    echo
}

confirm_start() {
    if is_silent; then
        return 0
    fi
    
    local response
    read -r -p "${C_YELLOW}${C_BOLD}Continue with installation? [y/N]:${C_RESET} " response
    
    case "$response" in
        [yY][eE][sS]|[yY])
            log INFO "User confirmed installation"
            return 0
            ;;
        *)
            print_info "Installation cancelled by user"
            log INFO "Installation cancelled by user"
            exit 0
            ;;
    esac
}

show_already_installed() {
    local local_ip
    local_ip=$(get_local_ip)
    local user
    user=$(whoami)
    
    draw_box "Bastion Host Already Configured" \
        "" \
        "${C_BOLD}Access Information${C_RESET}" \
        "  ${SYMBOL_BULLET} SSH: ssh ${user}@${local_ip}" \
        "  ${SYMBOL_BULLET} Jump: ssh -J ${user}@${local_ip}:22 user@remote" \
        "" \
        "${C_BOLD}Management Commands${C_RESET}" \
        "  ${SYMBOL_BULLET} Status:    $0 --status" \
        "  ${SYMBOL_BULLET} Logs:      $0 --logs [N]" \
        "  ${SYMBOL_BULLET} Configure: $0 --configure" \
        "  ${SYMBOL_BULLET} Uninstall: $0 --uninstall" \
        ""
    
    echo
    exit 0
}

#############################################################################
# Package Installation                                                      #
#############################################################################

install_packages() {
    print_section "Package Installation"
    
    local packages_to_check=(
        ufw
        gnupg2
        fail2ban
        libpam-tmpdir
        qemu-guest-agent
        unattended-upgrades
        libpam-google-authenticator
    )
    
    local packages_needed=()
    
    # Check which packages need installation
    for pkg in "${packages_to_check[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            packages_needed+=("$pkg")
        fi
    done
    
    if [[ ${#packages_needed[@]} -eq 0 ]]; then
        print_info "All required packages already installed"
        log INFO "No packages need installation"
        return 0
    fi
    
    print_step "Installing packages: ${packages_needed[*]}"
    log INFO "Installing: ${packages_needed[*]}"
    
    run_with_spinner "Updating package index" sudo apt-get update -qq
    run_with_spinner "Installing packages" sudo apt-get install -y "${packages_needed[@]}"
    
    print_success "Packages installed"
    log SUCCESS "Package installation completed"
}

#############################################################################
# Configure /etc/hosts                                                      #
#############################################################################

configure_hosts() {
    print_section "Hosts Configuration"
    
    local new_line="${DETECTED_IP} ${DETECTED_HOSTNAME} ${DETECTED_HOSTNAME}.${DETECTED_DOMAIN}"
    local config_file="/etc/hosts"
    
    # Check if already configured (idempotent)
    if grep -qF "$new_line" "$config_file" 2>/dev/null; then
        print_info "Hosts file already configured"
        log INFO "Hosts file already configured"
        return 0
    fi
    
    # Backup on change
    sudo cp "$config_file" "${config_file}.bak"
    log INFO "Backed up $config_file to ${config_file}.bak"
    
    # Atomic write: build temp file then move
    local temp_file="${config_file}.tmp"
    {
        echo "$new_line"
        grep -v "$DETECTED_HOSTNAME" "$config_file" || true
    } | sudo tee "$temp_file" >/dev/null
    
    sudo mv "$temp_file" "$config_file"
    
    print_success "Updated /etc/hosts"
    log SUCCESS "Hosts file updated"
}

#############################################################################
# Unattended Upgrades                                                       #
#############################################################################

configure_unattended_upgrades() {
    print_section "Unattended Upgrades"
    
    # Enable unattended-upgrades via debconf
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true \
        | sudo debconf-set-selections
    sudo dpkg-reconfigure -f noninteractive unattended-upgrades
    
    local dropin_file="$BASTION_UAU_DROPIN"
    local temp_file="${dropin_file}.tmp"
    
    print_step "Creating unattended-upgrades drop-in configuration..."
    
    # Atomic write: write to temp, then move
    # Drop-in in /etc/apt/apt.conf.d/ with higher priority (99) overrides 50unattended-upgrades
    sudo tee "$temp_file" > /dev/null << 'EOF'
// Managed by lab/jump.sh - do not edit manually
// Bastion host unattended-upgrades overrides

Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
    
    # Check if config changed
    local config_changed=false
    if [[ -f "$dropin_file" ]]; then
        if ! sudo diff -q "$dropin_file" "$temp_file" >/dev/null 2>&1; then
            config_changed=true
            sudo cp "$dropin_file" "${dropin_file}.bak"
            log INFO "Backed up existing unattended-upgrades drop-in"
        fi
    else
        config_changed=true
    fi
    
    sudo mv "$temp_file" "$dropin_file"
    sudo chmod 644 "$dropin_file"
    
    print_success "Unattended-upgrades drop-in created: $dropin_file"
    log SUCCESS "Unattended-upgrades drop-in written"
    
    if [[ "$config_changed" == "false" ]]; then
        print_info "Configuration unchanged"
        log INFO "Unattended-upgrades config unchanged"
    fi
}

#############################################################################
# UFW Firewall                                                              #
# NOTE: Bastion exception — this script intentionally enables UFW and sets  #
# default policies. Standard app scripts MUST NOT do this.                  #
#############################################################################

configure_ufw() {
    print_section "Firewall Configuration"
    
    # Skip if requested
    if [[ "${SKIP_UFW}" == "true" ]]; then
        print_warning "Skipping firewall configuration (JUMP_SKIP_UFW=true)"
        log WARN "Firewall configuration skipped by user request"
        return 0
    fi
    
    # Check if UFW exists
    if ! command_exists ufw; then
        local ufw_cmd=""
        if [[ -x /usr/sbin/ufw ]]; then
            ufw_cmd="/usr/sbin/ufw"
        else
            print_warning "UFW not installed - skipping firewall configuration"
            log WARN "UFW not available"
            return 0
        fi
    fi
    
    # Verify we can access ufw
    local ufw_cmd
    if command -v ufw >/dev/null 2>&1; then
        ufw_cmd="ufw"
    elif [[ -x /usr/sbin/ufw ]]; then
        ufw_cmd="/usr/sbin/ufw"
    else
        print_warning "UFW command not accessible - skipping firewall configuration"
        log WARN "UFW binary not in PATH or /usr/sbin"
        return 0
    fi
    
    # BASTION EXCEPTION: Set default policies
    print_step "Setting default policies..."
    sudo $ufw_cmd default deny incoming >/dev/null 2>&1
    sudo $ufw_cmd default allow outgoing >/dev/null 2>&1
    log INFO "UFW default policies set (bastion exception)"
    
    # Add SSH rate limiting (idempotent check)
    print_step "Configuring SSH rate limiting..."
    if sudo $ufw_cmd status numbered | grep -q "22/tcp"; then
        print_info "Firewall rule for port 22/tcp already exists"
        log INFO "UFW rule for 22/tcp already configured"
    else
        if sudo $ufw_cmd limit 22/tcp comment "${SCRIPT_NAME}" 2>/dev/null; then
            print_success "Added firewall rule: limit 22/tcp"
            log SUCCESS "UFW rule added: limit 22/tcp"
        else
            # Fallback: try without comment (older UFW versions)
            if sudo $ufw_cmd limit 22/tcp 2>/dev/null; then
                print_success "Added firewall rule: limit 22/tcp (no comment support)"
                log SUCCESS "UFW rule added: limit 22/tcp (no comment)"
            else
                print_warning "Failed to add SSH rate limit rule"
                log WARN "UFW rule addition failed for 22/tcp"
            fi
        fi
    fi
    
    # BASTION EXCEPTION: Enable UFW
    print_step "Enabling UFW..."
    sudo $ufw_cmd --force enable >/dev/null 2>&1
    log INFO "UFW enabled (bastion exception)"
    
    sudo $ufw_cmd reload >/dev/null 2>&1
    
    print_success "UFW configured and enabled"
    log SUCCESS "Firewall configuration completed"
}

#############################################################################
# Fail2Ban                                                                  #
#############################################################################

configure_fail2ban() {
    print_section "Fail2Ban Configuration"
    
    if ! command_exists fail2ban-server; then
        print_warning "Fail2Ban not installed, skipping"
        log WARN "Fail2Ban not installed"
        return 0
    fi
    
    local dropin_dir="/etc/fail2ban/jail.d"
    local dropin_file="$BASTION_F2B_DROPIN"
    local temp_file="${dropin_file}.tmp"
    
    print_step "Creating Fail2Ban drop-in configuration..."
    sudo mkdir -p "$dropin_dir"
    
    # Atomic write: write to temp, then move
    sudo tee "$temp_file" > /dev/null << 'EOF'
# Managed by lab/jump.sh - do not edit manually
# Bastion host Fail2Ban settings

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
    
    # Check if config changed
    local config_changed=false
    if [[ -f "$dropin_file" ]]; then
        if ! sudo diff -q "$dropin_file" "$temp_file" >/dev/null 2>&1; then
            config_changed=true
            sudo cp "$dropin_file" "${dropin_file}.bak"
            log INFO "Backed up existing Fail2Ban config"
        fi
    else
        config_changed=true
    fi
    
    sudo mv "$temp_file" "$dropin_file"
    sudo chmod 644 "$dropin_file"
    
    print_success "Fail2Ban drop-in config created: $dropin_file"
    log SUCCESS "Fail2Ban config written"
    
    # Restart only if config changed
    if [[ "$config_changed" == "true" ]]; then
        print_step "Restarting Fail2Ban..."
        sudo systemctl enable fail2ban >/dev/null 2>&1
        sudo systemctl restart fail2ban >/dev/null 2>&1
        
        sleep 2
        
        if service_is_active fail2ban; then
            print_success "Fail2Ban is running"
            log SUCCESS "Fail2Ban restarted successfully"
        else
            print_warning "Fail2Ban may not be running properly"
            log WARN "Fail2Ban service check uncertain after restart"
        fi
    else
        print_info "Configuration unchanged - no restart needed"
        log INFO "Fail2Ban config unchanged"
    fi
}

#############################################################################
# Secure Shared Memory                                                      #
#############################################################################

secure_shared_memory() {
    print_section "Shared Memory Hardening"
    
    local line="none /run/shm tmpfs defaults,ro 0 0"
    
    # Idempotent check
    if grep -qF "$line" /etc/fstab 2>/dev/null; then
        print_info "Shared memory already secured"
        log INFO "Shared memory already hardened"
        return 0
    fi
    
    # Backup fstab before modifying
    sudo cp /etc/fstab /etc/fstab.bak
    log INFO "Backed up /etc/fstab"
    
    echo "$line" | sudo tee -a /etc/fstab >/dev/null
    print_success "Added tmpfs mount for /run/shm"
    log SUCCESS "Shared memory hardened in fstab"
}

#############################################################################
# Sysctl Hardening (LXC-safe)                                               #
#############################################################################

configure_sysctl() {
    print_section "Sysctl Hardening (LXC-safe)"
    
    local dropin="$BASTION_SYSCTL_DROPIN"
    local temp_file="${dropin}.tmp"
    
    print_step "Creating sysctl drop-in configuration..."
    
    # Atomic write: write to temp, then move
    sudo tee "$temp_file" >/dev/null <<'EOF'
# Managed by lab/jump.sh - do not edit manually
# Bastion hardening sysctl settings (LXC-safe)

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

# Log martian packets
net.ipv4.conf.all.log_martians = 1
EOF
    
    # Check if config changed
    local config_changed=false
    if [[ -f "$dropin" ]]; then
        if ! sudo diff -q "$dropin" "$temp_file" >/dev/null 2>&1; then
            config_changed=true
            sudo cp "$dropin" "${dropin}.bak"
            log INFO "Backed up existing sysctl config"
        fi
    else
        config_changed=true
    fi
    
    sudo mv "$temp_file" "$dropin"
    sudo chmod 644 "$dropin"
    
    print_success "Sysctl drop-in config created: $dropin"
    log SUCCESS "Sysctl config written"
    
    # Apply only if changed
    if [[ "$config_changed" == "true" ]]; then
        print_step "Applying sysctl settings..."
        if sudo sysctl -p "$dropin" >/dev/null 2>&1; then
            print_success "Sysctl settings applied"
            log SUCCESS "Sysctl settings applied"
        else
            print_warning "Some sysctl keys denied (normal in unprivileged LXC)"
            log WARN "Some sysctl settings could not be applied (LXC restriction)"
            # Suppress errors, || true prevents pipefail exit
            sudo sysctl -p "$dropin" 2>/dev/null || true
        fi
    else
        print_info "Configuration unchanged - no reload needed"
        log INFO "Sysctl config unchanged"
    fi
}

#############################################################################
# Lock Root Account                                                         #
#############################################################################

lock_root_account() {
    print_section "Root Account Lockdown"
    
    if sudo passwd -S root | grep -q ' L '; then
        print_info "Root account already locked"
        log INFO "Root account already locked"
    else
        sudo passwd -l root >/dev/null 2>&1
        print_success "Root account locked"
        log SUCCESS "Root account locked"
    fi
}

#############################################################################
# Configure PAM for 2FA                                                     #
#############################################################################

configure_pam_2fa() {
    print_section "PAM 2FA Configuration"
    
    local pam_sshd="/etc/pam.d/sshd"
    local ga_line="auth required pam_google_authenticator.so nullok"
    
    # Backup PAM config before modifying
    if [[ ! -f "${pam_sshd}.bak" ]]; then
        sudo cp "$pam_sshd" "${pam_sshd}.bak"
        log INFO "Backed up $pam_sshd"
    fi
    
    # Comment out common-auth to prevent password prompt without 2FA
    if grep -q "^@include common-auth" "$pam_sshd"; then
        sudo sed -i 's|^@include common-auth|#@include common-auth|g' "$pam_sshd"
        print_success "Disabled password-only auth in PAM"
        log SUCCESS "Disabled password-only auth in PAM"
    else
        print_info "common-auth already disabled in PAM"
        log INFO "common-auth already disabled"
    fi
    
    # Add Google Authenticator PAM module (idempotent)
    if ! grep -qF "$ga_line" "$pam_sshd"; then
        echo "$ga_line" | sudo tee -a "$pam_sshd" >/dev/null
        print_success "Added Google Authenticator to PAM"
        log SUCCESS "Google Authenticator added to PAM"
    else
        print_info "Google Authenticator already in PAM"
        log INFO "Google Authenticator already configured in PAM"
    fi
}

#############################################################################
# Configure SSH                                                             #
#############################################################################

configure_ssh() {
    print_section "SSH Hardening"
    
    local sshd_config="/etc/ssh/sshd_config"
    local dropin_dir="/etc/ssh/sshd_config.d"
    local dropin_file="$BASTION_SSH_DROPIN"
    local backup="/tmp/sshd_bastion_backup_$$"
    local temp_file="${dropin_file}.tmp"
    local user
    user=$(whoami)
    
    # Ensure drop-in directory exists
    sudo mkdir -p "$dropin_dir"
    
    # Check if Include directive exists in main config
    print_step "Checking SSH Include directive..."
    if ! grep -qE '^[[:space:]]*Include.*/etc/ssh/sshd_config\.d/' "$sshd_config" 2>/dev/null; then
        print_warning "Adding Include directive to $sshd_config"
        local include_line="Include /etc/ssh/sshd_config.d/*.conf"
        local tmpfile="${sshd_config}.labtmp"
        { printf '%s\n' "$include_line"; sudo cat "$sshd_config"; } | sudo tee "$tmpfile" > /dev/null
        sudo mv "$tmpfile" "$sshd_config"
        log INFO "Added Include directive to sshd_config"
    else
        print_info "Include directive already present"
        log INFO "SSH Include directive already present"
    fi
    
    # Backup original config if not done
    if [[ ! -f "${sshd_config}.orig" ]]; then
        sudo cp "$sshd_config" "${sshd_config}.orig"
        log INFO "Backed up original sshd_config"
    fi
    
    # Backup current drop-in if exists (for rollback)
    [[ -f "$dropin_file" ]] && sudo cp "$dropin_file" "$backup"
    
    print_step "Creating SSH bastion drop-in configuration..."
    
    # Write to temp file first (atomic write)
    sudo tee "$temp_file" > /dev/null << EOF
# Managed by lab/jump.sh - do not edit manually
# Bastion/Jump Server SSH configuration with 2FA support

# Logging
LogLevel VERBOSE

# Authentication
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
IgnoreRhosts yes

# Password/key auth
PasswordAuthentication no
PermitEmptyPasswords no
GSSAPIAuthentication no

# 2FA / Challenge-Response authentication
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes
AuthenticationMethods keyboard-interactive

# Agent forwarding for jump functionality
AllowAgentForwarding yes

# Allowed ciphers and algorithms
Protocol 2
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Restrict SSH access to current user
AllowUsers ${user}
EOF
    
    sudo mv "$temp_file" "$dropin_file"
    sudo chmod 644 "$dropin_file"
    
    print_success "SSH bastion drop-in config created: $dropin_file"
    log SUCCESS "SSH drop-in config written"
    
    # Validate SSH configuration (before restart)
    print_step "Validating SSH configuration..."
    if ! sudo sshd -t -f "$sshd_config" 2>/dev/null; then
        print_error "SSH configuration has errors, rolling back..."
        log ERROR "SSH configuration validation failed"
        if [[ -f "$backup" ]]; then
            sudo mv "$backup" "$dropin_file"
        else
            sudo rm -f "$dropin_file"
        fi
        sudo systemctl restart sshd 2>/dev/null || true
        die "SSH configuration validation failed"
    fi
    print_success "SSH configuration is valid"
    log SUCCESS "SSH configuration validated"
    
    # Restart SSH service
    print_step "Restarting SSH service..."
    if sudo systemctl restart sshd 2>/dev/null || sudo systemctl restart ssh 2>/dev/null; then
        sleep 2
        if service_is_active sshd || service_is_active ssh; then
            print_success "SSH service restarted and running"
            log SUCCESS "SSH service restarted"
        else
            print_error "SSH service not active after restart, rolling back..."
            log ERROR "SSH service failed after restart"
            if [[ -f "$backup" ]]; then
                sudo mv "$backup" "$dropin_file"
            else
                sudo rm -f "$dropin_file"
            fi
            sudo systemctl restart sshd 2>/dev/null || sudo systemctl restart ssh 2>/dev/null || true
            die "SSH service failed after restart"
        fi
    else
        print_warning "SSH service restart may have failed"
        log WARN "SSH restart returned non-zero"
    fi
    
    rm -f "$backup"
}

#############################################################################
# Generate SSH Key                                                          #
#############################################################################

generate_ssh_key() {
    print_section "SSH Key Generation"
    
    if [[ "${SKIP_KEYGEN}" == "true" ]]; then
        print_warning "SSH key generation skipped (JUMP_SKIP_KEYGEN=true)"
        log INFO "SSH key generation skipped by user"
        return 0
    fi
    
    local keyfile="$HOME/.ssh/id_ed25519"
    
    # Idempotent: key already exists
    if [[ -f "$keyfile" ]]; then
        print_info "SSH key already exists: $keyfile"
        
        if ! is_silent; then
            local response
            read -r -p "${C_YELLOW}${C_BOLD}Overwrite existing key? [y/N]:${C_RESET} " response
            case "$response" in
                [yY][eE][sS]|[yY])
                    log INFO "User chose to overwrite existing SSH key"
                    ;;
                *)
                    print_info "Keeping existing key"
                    log INFO "Existing SSH key preserved"
                    return 0
                    ;;
            esac
        else
            print_info "Keeping existing key (silent mode)"
            log INFO "Existing SSH key preserved (silent mode)"
            return 0
        fi
    fi
    
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    
    print_step "Generating Ed25519 key (200 KDF rounds)..."
    ssh-keygen -t ed25519 -a 200 -N "" -f "$keyfile" -q
    
    print_success "SSH key generated: $keyfile"
    log SUCCESS "SSH key generated: $keyfile"
}

#############################################################################
# Setup Google Authenticator                                                #
#############################################################################

setup_google_authenticator() {
    print_section "Google Authenticator Setup"
    
    if [[ "${SKIP_2FA}" == "true" ]]; then
        print_warning "2FA setup skipped (JUMP_SKIP_2FA=true)"
        log INFO "2FA setup skipped by user"
        return 0
    fi
    
    if ! command_exists google-authenticator; then
        print_warning "google-authenticator not installed, skipping"
        log WARN "google-authenticator binary not found"
        return 0
    fi
    
    if is_silent; then
        print_warning "Skipping interactive 2FA setup (silent mode)"
        log INFO "2FA setup skipped (silent mode)"
        return 0
    fi
    
    echo
    print_info "Scan the QR code with Google Authenticator app"
    print_info "Save the emergency scratch codes!"
    echo
    
    # Options:
    # -d: disallow reuse of same token
    # -f: force create new secret
    # -t: time-based tokens
    # -r 3 -R 30: rate limit (3 attempts per 30 seconds)
    # -W: show warmup codes
    # Note: must use /dev/tty for QR code to render (bypasses tee logging)
    google-authenticator -d -f -t -r 3 -R 30 -W </dev/tty >/dev/tty
    
    print_success "Google Authenticator configured"
    log SUCCESS "Google Authenticator configured"
}

#############################################################################
# CLI Commands: --status, --logs, --configure, --uninstall                  #
#############################################################################

cmd_status() {
    echo "${C_BOLD}Service Status:${C_RESET}"
    echo
    
    # SSH service
    local ssh_svc="sshd"
    service_is_active sshd || ssh_svc="ssh"
    if service_is_active "$ssh_svc"; then
        echo "  ${C_GREEN}${SYMBOL_SUCCESS}${C_RESET} ${ssh_svc}: ${C_GREEN}active${C_RESET}"
    else
        echo "  ${C_RED}${SYMBOL_ERROR}${C_RESET} ${ssh_svc}: ${C_RED}inactive${C_RESET}"
    fi
    
    # Fail2Ban
    if service_is_active fail2ban; then
        echo "  ${C_GREEN}${SYMBOL_SUCCESS}${C_RESET} fail2ban: ${C_GREEN}active${C_RESET}"
    else
        echo "  ${C_RED}${SYMBOL_ERROR}${C_RESET} fail2ban: ${C_RED}inactive${C_RESET}"
    fi
    
    # UFW status
    echo
    echo "${C_BOLD}Firewall Status:${C_RESET}"
    if command_exists ufw || [[ -x /usr/sbin/ufw ]]; then
        sudo ufw status 2>/dev/null || echo "  Unable to query UFW"
    else
        echo "  UFW not installed"
    fi
    
    echo
    echo "${C_BOLD}Access Information:${C_RESET}"
    local local_ip
    local_ip=$(get_local_ip)
    local user
    user=$(whoami)
    echo "  SSH:  ssh ${user}@${local_ip}"
    echo "  Jump: ssh -J ${user}@${local_ip}:22 user@remote_host"
    
    echo
    echo "${C_BOLD}Configuration:${C_RESET}"
    echo "  SSH drop-in:     $BASTION_SSH_DROPIN"
    echo "  Fail2Ban:        $BASTION_F2B_DROPIN"
    echo "  Sysctl:          $BASTION_SYSCTL_DROPIN"
    echo "  Unattended-upg:  $BASTION_UAU_DROPIN"
    
    echo
    echo "${C_BOLD}Management:${C_RESET}"
    echo "  Logs:      $0 --logs [N]"
    echo "  Configure: $0 --configure"
    echo "  Uninstall: $0 --uninstall"
}

cmd_logs() {
    local lines="${1:-50}"
    
    echo "${C_BOLD}SSH Logs (last ${lines} lines):${C_RESET}"
    echo
    sudo journalctl -u sshd -u ssh -n "$lines" --no-pager 2>/dev/null || \
        echo "  No SSH journal entries found"
    
    echo
    echo "${C_BOLD}Fail2Ban Logs (last ${lines} lines):${C_RESET}"
    echo
    sudo journalctl -u fail2ban -n "$lines" --no-pager 2>/dev/null || \
        echo "  No Fail2Ban journal entries found"
    
    echo
    echo "${C_BOLD}Installation Logs:${C_RESET}"
    local latest_log
    latest_log=$(ls -t "${LOG_DIR}/${SCRIPT_NAME}"-*.log 2>/dev/null | head -1)
    if [[ -n "$latest_log" ]]; then
        echo "  Latest: $latest_log"
        echo
        tail -n "$lines" "$latest_log"
    else
        echo "  No installation logs found"
    fi
}

cmd_configure() {
    print_section "Reconfigure Bastion"
    
    echo
    print_info "This will re-run the interactive configuration steps."
    print_info "SSH key generation and Google Authenticator setup."
    echo
    
    if ! is_silent; then
        local response
        read -r -p "${C_YELLOW}${C_BOLD}Continue with reconfiguration? [y/N]:${C_RESET} " response
        case "$response" in
            [yY][eE][sS]|[yY]) ;;
            *) print_info "Reconfiguration cancelled"; exit 0 ;;
        esac
    fi
    
    generate_ssh_key
    setup_google_authenticator
    
    print_success "Reconfiguration complete"
}

cmd_uninstall() {
    print_section "Uninstall Bastion Hardening"
    
    # Confirm with user unless silent
    if ! is_silent; then
        local response
        read -r -p "${C_YELLOW}${C_BOLD}Reverse bastion hardening? This will restore SSH defaults. [y/N]:${C_RESET} " response
        
        case "$response" in
            [yY][eE][sS]|[yY]) ;;
            *) print_info "Uninstall cancelled"; exit 0 ;;
        esac
    fi
    
    # Remove SSH drop-in
    if [[ -f "$BASTION_SSH_DROPIN" ]]; then
        print_step "Removing SSH bastion configuration..."
        sudo rm -f "$BASTION_SSH_DROPIN"
        sudo systemctl restart sshd 2>/dev/null || sudo systemctl restart ssh 2>/dev/null || true
        print_success "SSH bastion drop-in removed"
    fi
    
    # Restore PAM
    if [[ -f "/etc/pam.d/sshd.bak" ]]; then
        print_step "Restoring PAM configuration..."
        sudo mv "/etc/pam.d/sshd.bak" "/etc/pam.d/sshd"
        print_success "PAM configuration restored"
    fi
    
    # Remove Fail2Ban drop-in
    if [[ -f "$BASTION_F2B_DROPIN" ]]; then
        print_step "Removing Fail2Ban bastion configuration..."
        sudo rm -f "$BASTION_F2B_DROPIN"
        sudo systemctl restart fail2ban 2>/dev/null || true
        print_success "Fail2Ban bastion drop-in removed"
    fi
    
    # Remove sysctl drop-in
    if [[ -f "$BASTION_SYSCTL_DROPIN" ]]; then
        print_step "Removing sysctl bastion configuration..."
        sudo rm -f "$BASTION_SYSCTL_DROPIN"
        sudo sysctl --system >/dev/null 2>&1 || true
        print_success "Sysctl bastion drop-in removed"
    fi
    
    # Remove unattended-upgrades drop-in
    if [[ -f "$BASTION_UAU_DROPIN" ]]; then
        print_step "Removing unattended-upgrades bastion configuration..."
        sudo rm -f "$BASTION_UAU_DROPIN"
        print_success "Unattended-upgrades bastion drop-in removed"
    fi
    
    # Unlock root (optional)
    if ! is_silent; then
        read -r -p "${C_YELLOW}Unlock root account? [y/N]:${C_RESET} " response
        if [[ "$response" =~ ^[yY] ]]; then
            sudo passwd -u root >/dev/null 2>&1
            print_success "Root account unlocked"
        fi
    fi
    
    # Remove firewall rules (optional)
    if ! is_silent; then
        read -r -p "${C_YELLOW}Disable UFW firewall? [y/N]:${C_RESET} " response
        if [[ "$response" =~ ^[yY] ]]; then
            sudo ufw --force disable >/dev/null 2>&1 || true
            print_success "UFW disabled"
        fi
    fi
    
    # Remove packages (optional)
    if ! is_silent; then
        read -r -p "${C_YELLOW}Remove installed packages (fail2ban, ufw, etc.)? [y/N]:${C_RESET} " response
        if [[ "$response" =~ ^[yY] ]]; then
            sudo apt-get remove -y fail2ban libpam-google-authenticator libpam-tmpdir 2>/dev/null || true
            print_success "Packages removed"
        fi
    fi
    
    print_success "Bastion hardening has been reversed"
    
    echo
    print_info "Installation logs preserved at: ${LOG_DIR}/${SCRIPT_NAME}-*.log"
    print_warning "You may want to reboot for all changes to take effect"
}

#############################################################################
# Prompt Reboot                                                             #
#############################################################################

prompt_reboot() {
    if [[ "${SKIP_REBOOT}" == "true" ]]; then
        print_info "Reboot skipped (JUMP_SKIP_REBOOT=true)"
        print_warning "Remember to reboot later!"
        log INFO "Reboot skipped by user"
        return 0
    fi
    
    if is_silent; then
        print_info "Reboot skipped (silent mode)"
        log INFO "Reboot skipped (silent mode)"
        return 0
    fi
    
    echo
    local response
    read -r -p "${C_YELLOW}${C_BOLD}Restart now (recommended)? [y/N]:${C_RESET} " response
    
    case "$response" in
        [yY][eE][sS]|[yY])
            print_step "Cleaning up and restarting..."
            log INFO "User initiated reboot"
            sudo apt-get clean -qq
            sudo apt-get autoremove -qq -y
            sudo reboot now
            ;;
        *)
            print_warning "Remember to restart later!"
            log INFO "User deferred reboot"
            ;;
    esac
}

#############################################################################
# Summary Screen                                                            #
#############################################################################

show_summary() {
    local local_ip
    local_ip=$(get_local_ip)
    local user
    user=$(whoami)
    local pubkey=""
    
    if [[ -f "$HOME/.ssh/id_ed25519.pub" ]]; then
        pubkey=$(cat "$HOME/.ssh/id_ed25519.pub")
    fi
    
    echo
    draw_box "Bastion Host Setup Complete!" \
        "" \
        "${C_BOLD}Access Information${C_RESET}" \
        "  ${SYMBOL_BULLET} SSH:  ssh ${user}@${local_ip}" \
        "  ${SYMBOL_BULLET} Jump: ssh -J ${user}@${local_ip}:22 user@remote" \
        "  ${SYMBOL_BULLET} Port: 22" \
        "" \
        "${C_BOLD}Installation Details${C_RESET}" \
        "  ${SYMBOL_BULLET} SSH drop-in:  $BASTION_SSH_DROPIN" \
        "  ${SYMBOL_BULLET} Fail2Ban:     $BASTION_F2B_DROPIN" \
        "  ${SYMBOL_BULLET} Sysctl:       $BASTION_SYSCTL_DROPIN" \
        "  ${SYMBOL_BULLET} Unattended:   $BASTION_UAU_DROPIN" \
        "  ${SYMBOL_BULLET} Log file:     $LOG_FILE" \
        "" \
        "${C_BOLD}Management Commands${C_RESET}" \
        "  ${SYMBOL_BULLET} Status:    $0 --status" \
        "  ${SYMBOL_BULLET} Logs:      $0 --logs [N]" \
        "  ${SYMBOL_BULLET} Configure: $0 --configure" \
        "  ${SYMBOL_BULLET} Uninstall: $0 --uninstall" \
        ""
    
    if [[ -n "$pubkey" ]]; then
        echo
        print_info "SSH Public Key (for VM templates):"
        echo "  $pubkey"
    fi
    
    echo
    print_info "Installation log: ${LOG_FILE}"
    echo
    
    log SUCCESS "Installation completed successfully"
}

#############################################################################
# Main                                                                      #
#############################################################################

main() {
    # Setup logging first
    setup_logging
    
    # Check if already installed (show management menu)
    if [[ -f "$BASTION_SSH_DROPIN" ]] && [[ -f "$BASTION_F2B_DROPIN" ]] && [[ -f "$BASTION_UAU_DROPIN" ]]; then
        show_already_installed
    fi
    
    # Interactive intro
    show_intro
    
    # Detect network info (needed for display and /etc/hosts)
    detect_network_info
    
    # Confirm before proceeding
    confirm_start
    
    # Run preflight checks
    preflight_checks
    
    # Execute hardening steps
    install_packages
    configure_hosts
    configure_unattended_upgrades
    configure_ufw
    configure_fail2ban
    secure_shared_memory
    configure_sysctl
    lock_root_account
    configure_pam_2fa
    configure_ssh
    generate_ssh_key
    setup_google_authenticator
    
    # Show results
    show_summary
    
    # Prompt for reboot
    prompt_reboot
}

#############################################################################
# CLI Dispatch                                                              #
#############################################################################

case "${1:-}" in
    --status)
        LOG_FILE=""
        cmd_status
        ;;
    --logs)
        LOG_FILE=""
        cmd_logs "${2:-50}"
        ;;
    --configure)
        LOG_FILE=""
        cmd_configure
        ;;
    --uninstall)
        LOG_FILE=""
        cmd_uninstall
        ;;
    *)
        main "$@"
        ;;
esac
