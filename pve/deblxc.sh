#!/bin/bash

#############################################################################
# Debian LXC Template Creator for Proxmox VE                                #
# Source: https://github.com/vdarkobar/lab                                  #
#                                                                           #
# This script:                                                              #
#   1. Downloads the latest Debian LXC template                             #
#   2. Creates an unprivileged container with nesting                       #
#   3. Configures non-root user with sudo                                   #
#   4. Sets up Cloud-Init for SSH key regeneration                          #
#   5. Converts the container to a reusable template                        #
#                                                                           #
# REQUIREMENTS:                                                             #
#   - Proxmox VE host (MUST run on PVE host, NOT inside VM/LXC)            #
#   - Root privileges (uses pct, pvesm, pveam commands)                     #
#   - SSH keys at /root/.ssh/authorized_keys (optional)                     #
#   - Storage configured for templates and rootfs                           #
#                                                                           #
# ENVIRONMENT VARIABLES (for non-interactive mode):                         #
#   DEBLXC_SILENT=true           - Non-interactive mode (no prompts)        #
#   DEBLXC_TEMPLATE_STORAGE      - Storage for templates (e.g., "local")   #
#   DEBLXC_ROOTFS_STORAGE        - Storage for rootfs (e.g., "local-lvm")  #
#   DEBLXC_CONTAINER_ID          - Container ID (e.g., "9000")              #
#   DEBLXC_HOSTNAME              - Container hostname (e.g., "deblxc")      #
#   DEBLXC_USERNAME              - Non-root username                        #
#   DEBLXC_PASSWORD              - User password                            #
#   DEBLXC_BRIDGE                - Network bridge (e.g., "vmbr0")           #
#   DEBLXC_CORES                 - CPU cores (default: 4)                   #
#   DEBLXC_MEMORY                - Memory in MB (default: 4096)             #
#   DEBLXC_DISK                  - Disk size in GB (default: 8)             #
#############################################################################

readonly SCRIPT_VERSION="2.1.0"
readonly SCRIPT_NAME="deblxc"

#############################################################################
# Handle --help BEFORE set -euo pipefail                                    #
#############################################################################

if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    cat << 'EOF'
Debian LXC Template Creator for Proxmox VE

DESCRIPTION:
    Creates a reusable Debian LXC template with:
    - Unprivileged container with nesting enabled
    - Non-root user with sudo privileges
    - Cloud-Init for SSH key regeneration on clone
    - Proper locales and system packages
    - Tags: ct,template,debian<version> (e.g., debian13)

USAGE:
    deblxc.sh [COMMAND]

COMMANDS:
    (no args)         Create Debian LXC template (default)
    --status          Show existing template status
    --logs [N]        Show last N lines of logs (default: 50)
    --configure       Create additional template (re-run creation)
    --uninstall       Delete template
    --version, -v     Show version
    --help, -h        Show this help

ENVIRONMENT VARIABLES (for non-interactive mode):
    DEBLXC_SILENT=true           Non-interactive mode
    DEBLXC_TEMPLATE_STORAGE      Storage for templates (e.g., "local")
    DEBLXC_ROOTFS_STORAGE        Storage for rootfs (e.g., "local-lvm")
    DEBLXC_CONTAINER_ID          Container ID (e.g., "9000")
    DEBLXC_HOSTNAME              Hostname (default: deblxc)
    DEBLXC_USERNAME              Non-root username
    DEBLXC_PASSWORD              User password
    DEBLXC_BRIDGE                Network bridge (default: vmbr0)
    DEBLXC_CORES                 CPU cores (default: 4)
    DEBLXC_MEMORY                Memory in MB (default: 4096)
    DEBLXC_DISK                  Disk size in GB (default: 8)

EXAMPLES:
    # Interactive creation:
    ./deblxc.sh

    # Fully automated:
    DEBLXC_SILENT=true \
    DEBLXC_TEMPLATE_STORAGE=local \
    DEBLXC_ROOTFS_STORAGE=local-lvm \
    DEBLXC_CONTAINER_ID=9000 \
    DEBLXC_HOSTNAME=debian-tpl \
    DEBLXC_USERNAME=admin \
    DEBLXC_PASSWORD='SecurePass1!' \
    DEBLXC_BRIDGE=vmbr0 \
    ./deblxc.sh

    # Check template status:
    ./deblxc.sh --status

    # View creation logs:
    ./deblxc.sh --logs 100

    # Delete template:
    ./deblxc.sh --uninstall

FILES:
    /etc/pve/lxc/<id>.conf    Container/template configuration
    /var/log/lab/deblxc-*.log Installation logs

CLONE TEMPLATE:
    pct clone <template-id> <new-id> --hostname <new-name> --full

NOTES:
    - MUST run on Proxmox VE host (not inside VM/LXC)
    - Requires root privileges
    - SSH keys regenerated automatically via Cloud-Init on first boot
    - Password requirements: 8+ chars, 1 number, 1 special character
    - Template version auto-detected and tagged (e.g., debian13, debian12)

EOF
    exit 0
fi

#############################################################################
# Bash Options                                                              #
#############################################################################

set -euo pipefail

# Error debugging trap
trap 'echo "ERROR: Command failed at line ${LINENO}: ${BASH_COMMAND}" >&2' ERR

#############################################################################
# Configuration & Constants                                                 #
#############################################################################

readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="$LOG_DIR/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Defaults (can be overridden via environment variables)
readonly DEFAULT_HOSTNAME="deblxc"
readonly DEFAULT_BRIDGE="vmbr0"
readonly DEFAULT_CORES="${DEBLXC_CORES:-4}"
readonly DEFAULT_MEMORY="${DEBLXC_MEMORY:-4096}"
readonly DEFAULT_SWAP="512"
readonly DEFAULT_DISK="${DEBLXC_DISK:-8}"

# Container initialization wait time
readonly CONTAINER_INIT_WAIT=5

# Reserved hostnames
readonly RESERVED_NAMES=(
    "localhost" "domain" "local" "host" "broadcasthost" 
    "localdomain" "loopback" "wpad" "gateway" "dns" 
    "mail" "ftp" "web"
)

# Set SILENT mode from environment
readonly SILENT="${DEBLXC_SILENT:-false}"

# Track unattended-upgrades state (not applicable on PVE host, but included for consistency)
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

# Spinner characters (declared separately after standard symbols)
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
    
    # Append to log file (if LOG_FILE is set)
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[${timestamp}] [${level}] ${stripped_msg}" >> "${LOG_FILE}"
    fi
}

# Fatal error handler
die() {
    local msg="$*"
    log ERROR "$msg"
    print_error "$msg"
    exit 1
}

# Setup logging directory and file
setup_logging() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR" || {
            print_error "Failed to create log directory: $LOG_DIR"
            exit 1
        }
        chmod 755 "$LOG_DIR"
    fi
    
    # Create log file
    if ! touch "$LOG_FILE" 2>/dev/null; then
        print_error "Failed to create log file: $LOG_FILE"
        exit 1
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

#############################################################################
# Spinner (For Long-Running Operations)                                    #
#############################################################################

# Run a command with an animated spinner, elapsed timer, and log capture.
# Usage: run_with_spinner "Message" command arg1 arg2...
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
    printf "  %s " "$msg"
    while kill -0 "$pid" 2>/dev/null; do
        now_ts="$(date +%s)"
        elapsed=$((now_ts - start_ts))
        printf "\r  %s %s (%ds)" "$msg" "${SPINNER_CHARS:spin_idx++%${#SPINNER_CHARS}:1}" "$elapsed"
        sleep 0.1
    done

    # Capture exit code
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
# Cleanup Handler                                                           #
#############################################################################

cleanup() {
    local exit_code=$?
    
    # Note: unattended-upgrades typically not relevant on PVE host,
    # but included for consistency with skill.md pattern
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == "true" ]]; then
        systemctl start unattended-upgrades 2>/dev/null || true
        log INFO "Restarted unattended-upgrades service"
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        echo
        print_error "Script failed with exit code: $exit_code"
        print_warning "Check log file: $LOG_FILE"
        
        # Warn about partial container
        if [[ -n "${CONTAINER_ID:-}" ]] && pct status "$CONTAINER_ID" &>/dev/null; then
            print_warning "Partial container $CONTAINER_ID may exist - check manually"
            print_info "Delete with: pct destroy $CONTAINER_ID"
        fi
        
        log ERROR "=== Script failed with exit code: $exit_code ==="
    else
        log INFO "=== Script completed successfully ==="
    fi
}

trap cleanup EXIT

# Handle interrupts (CTRL+C) and termination signals
trap 'echo; print_warning "Script interrupted by user"; exit 130' INT
trap 'echo; print_warning "Script terminated"; exit 143' TERM

#############################################################################
# Validation Functions                                                      #
#############################################################################

is_reserved_hostname() {
    local input_name="$1"
    for name in "${RESERVED_NAMES[@]}"; do
        if [[ "$input_name" == "$name" ]]; then
            return 0
        fi
    done
    return 1
}

validate_hostname() {
    local hostname="$1"
    
    if is_reserved_hostname "$hostname"; then
        print_error "Hostname '$hostname' is reserved and cannot be used"
        return 1
    fi
    
    if [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        return 0
    fi
    
    print_error "Invalid hostname format"
    print_info "Requirements: 1-63 chars, alphanumeric + hyphen, start/end with alphanumeric"
    return 1
}

validate_username() {
    local username="$1"
    
    if [[ "$username" == "root" ]]; then
        print_error "Username 'root' is not allowed"
        return 1
    fi
    
    if [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        return 0
    fi
    
    print_error "Invalid username format"
    print_info "Requirements: lowercase letters, numbers, underscore, hyphen (must start with letter or underscore)"
    return 1
}

validate_password() {
    local password="$1"
    local -a errors=()
    
    [[ ${#password} -lt 8 ]] && errors+=("Minimum 8 characters")
    [[ ! "$password" =~ [0-9] ]] && errors+=("Must contain at least one number")
    [[ ! "$password" =~ [^a-zA-Z0-9] ]] && errors+=("Must contain at least one special character (!@#$%^&*)")
    
    if [[ ${#errors[@]} -gt 0 ]]; then
        print_error "Password requirements not met:"
        printf '  %s %s\n' "${SYMBOL_BULLET}" "${errors[@]}"
        return 1
    fi
    return 0
}

#############################################################################
# Preflight Checks                                                          #
#############################################################################

preflight_checks() {
    print_section "Preflight Checks"
    
    # Check if running on Proxmox VE (MUST be on PVE host)
    if [[ ! -f /etc/pve/.version ]]; then
        die "This script MUST run on a Proxmox VE host (not inside VM/LXC)"
    fi
    print_success "Proxmox VE host detected"
    log INFO "Running on Proxmox VE host"
    
    # Check if running as root (REQUIRED for PVE operations)
    if [[ $EUID -ne 0 ]]; then
        die "This script must run as root (uses pct, pvesm, pveam commands)"
    fi
    print_success "Running as root"
    log INFO "Running with root privileges"
    
    # Check for required PVE commands
    local required_cmds=("pct" "pvesm" "pveam" "pvesh")
    for cmd in "${required_cmds[@]}"; do
        if ! command_exists "$cmd"; then
            die "Required PVE command not found: $cmd"
        fi
    done
    print_success "All required PVE commands available"
    log INFO "Verified: pct, pvesm, pveam, pvesh commands present"
    
    # Check for SSH keys (optional but recommended)
    if [[ -f /root/.ssh/authorized_keys ]]; then
        print_success "SSH keys found at /root/.ssh/authorized_keys"
        log INFO "SSH keys will be copied to template"
        SSH_KEYS_AVAILABLE=true
    else
        print_warning "No SSH keys found at /root/.ssh/authorized_keys"
        print_info "Template will be created without SSH keys"
        log WARN "No SSH keys available - template created without keys"
        SSH_KEYS_AVAILABLE=false
    fi
}

#############################################################################
# CLI Command Handlers                                                      #
#############################################################################

cmd_status() {
    # Allow override via environment or use existing value
    local target_id="${DEBLXC_CONTAINER_ID:-${CONTAINER_ID:-}}"
    
    if [[ -z "$target_id" ]]; then
        print_warning "No container ID specified"
        print_info "Set DEBLXC_CONTAINER_ID environment variable or specify during creation"
        return 1
    fi
    
    print_section "Template Status: $target_id"
    
    if ! pct status "$target_id" &>/dev/null; then
        print_warning "Container/template $target_id does not exist"
        log INFO "Status check: container $target_id not found"
        return 1
    fi
    
    local config_file="/etc/pve/lxc/${target_id}.conf"
    if [[ -f "$config_file" ]]; then
        print_info "Template ID: $target_id"
        print_info "Config file: $config_file"
        log INFO "Found config: $config_file"
        
        if grep -q "template: 1" "$config_file" 2>/dev/null; then
            print_success "Status: Template (ready to clone)"
            log INFO "Container $target_id is a template"
            
            # Show template details
            echo
            print_info "Template Details:"
            grep -E "^(hostname|cores|memory|rootfs|net0|tags)" "$config_file" 2>/dev/null | while read -r line; do
                echo "  ${SYMBOL_BULLET} $line"
            done
        else
            print_warning "Status: Container (not yet converted to template)"
            log WARN "Container $target_id exists but is not a template"
        fi
        
        echo
        print_info "Clone with:"
        echo "  pct clone $target_id <new-id> --hostname <new-name> --full"
        
        echo
        print_info "Delete with:"
        echo "  ./deblxc.sh --uninstall"
        echo "  OR: pct destroy $target_id"
    else
        print_error "Config file not found: $config_file"
        log ERROR "Config file missing for container $target_id"
        return 1
    fi
}

cmd_logs() {
    local lines="${1:-50}"
    
    # Find most recent log file
    local latest_log
    latest_log=$(ls -t "$LOG_DIR"/${SCRIPT_NAME}-*.log 2>/dev/null | head -n1)
    
    if [[ -z "$latest_log" ]]; then
        print_error "No log files found in $LOG_DIR"
        return 1
    fi
    
    print_section "Last $lines lines from: $(basename "$latest_log")"
    echo
    tail -n "$lines" "$latest_log"
}

cmd_configure() {
    # Re-run main creation flow (allows creating additional templates)
    print_info "Creating additional template..."
    cmd_install
}

cmd_uninstall() {
    local target_id="${DEBLXC_CONTAINER_ID:-${CONTAINER_ID:-}}"
    
    if [[ -z "$target_id" ]]; then
        print_error "No container ID specified"
        print_info "Set DEBLXC_CONTAINER_ID environment variable"
        return 1
    fi
    
    if ! pct status "$target_id" &>/dev/null; then
        print_error "Container/template $target_id does not exist"
        return 1
    fi
    
    print_section "Uninstall Template: $target_id"
    
    # Show what will be deleted
    local config_file="/etc/pve/lxc/${target_id}.conf"
    if [[ -f "$config_file" ]]; then
        echo
        print_info "Template details:"
        grep -E "^(hostname|rootfs)" "$config_file" 2>/dev/null | while read -r line; do
            echo "  ${SYMBOL_BULLET} $line"
        done
    fi
    
    echo
    print_warning "This will PERMANENTLY delete template $target_id and all its data"
    
    if is_silent; then
        print_info "Silent mode: proceeding with deletion"
        log WARN "Deleting template $target_id (silent mode)"
    else
        read -rp "Type 'yes' to confirm deletion: " confirm
        if [[ "$confirm" != "yes" ]]; then
            print_info "Uninstall cancelled"
            log INFO "Uninstall cancelled by user"
            return 0
        fi
    fi
    
    print_step "Deleting template $target_id..."
    if pct destroy "$target_id" --purge 2>/dev/null; then
        print_success "Template $target_id deleted successfully"
        log INFO "Template $target_id destroyed"
    else
        print_error "Failed to delete template $target_id"
        log ERROR "Failed to destroy template $target_id"
        return 1
    fi
}

#############################################################################
# Interactive Prompts (with Silent Mode Support)                           #
#############################################################################

select_template_storage() {
    if is_silent; then
        TEMPLATE_STORAGE="${DEBLXC_TEMPLATE_STORAGE:-}"
        if [[ -z "$TEMPLATE_STORAGE" ]]; then
            die "DEBLXC_TEMPLATE_STORAGE not set in silent mode"
        fi
        log INFO "Template storage (silent): $TEMPLATE_STORAGE"
        return 0
    fi
    
    print_section "Select Template Storage"
    
    print_info "Available storage locations for templates:"
    echo
    
    local storages
    mapfile -t storages < <(pvesm status -content vztmpl | awk 'NR>1 {print $1}')
    
    if [[ ${#storages[@]} -eq 0 ]]; then
        die "No storage with 'vztmpl' content type found"
    fi
    
    local i=1
    for storage in "${storages[@]}"; do
        echo "  $i) $storage"
        ((i++))
    done
    
    echo
    while true; do
        read -rp "Select template storage [1-${#storages[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#storages[@]} ]]; then
            TEMPLATE_STORAGE="${storages[$((choice-1))]}"
            break
        fi
        print_error "Invalid selection. Please choose 1-${#storages[@]}"
    done
    
    print_success "Template storage: $TEMPLATE_STORAGE"
    log INFO "Selected template storage: $TEMPLATE_STORAGE"
}

select_rootfs_storage() {
    if is_silent; then
        ROOTFS_STORAGE="${DEBLXC_ROOTFS_STORAGE:-}"
        if [[ -z "$ROOTFS_STORAGE" ]]; then
            die "DEBLXC_ROOTFS_STORAGE not set in silent mode"
        fi
        log INFO "Rootfs storage (silent): $ROOTFS_STORAGE"
        return 0
    fi
    
    print_section "Select Rootfs Storage"
    
    print_info "Available storage locations for container rootfs:"
    echo
    
    local storages
    mapfile -t storages < <(pvesm status -content rootdir,images | awk 'NR>1 {print $1}')
    
    if [[ ${#storages[@]} -eq 0 ]]; then
        die "No storage with 'rootdir' or 'images' content type found"
    fi
    
    local i=1
    for storage in "${storages[@]}"; do
        echo "  $i) $storage"
        ((i++))
    done
    
    echo
    while true; do
        read -rp "Select rootfs storage [1-${#storages[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#storages[@]} ]]; then
            ROOTFS_STORAGE="${storages[$((choice-1))]}"
            break
        fi
        print_error "Invalid selection. Please choose 1-${#storages[@]}"
    done
    
    print_success "Rootfs storage: $ROOTFS_STORAGE"
    log INFO "Selected rootfs storage: $ROOTFS_STORAGE"
}

select_container_id() {
    if is_silent; then
        CONTAINER_ID="${DEBLXC_CONTAINER_ID:-}"
        if [[ -z "$CONTAINER_ID" ]]; then
            die "DEBLXC_CONTAINER_ID not set in silent mode"
        fi
        
        # Validate ID is numeric
        if ! [[ "$CONTAINER_ID" =~ ^[0-9]+$ ]]; then
            die "Invalid container ID: $CONTAINER_ID (must be numeric)"
        fi
        
        log INFO "Container ID (silent): $CONTAINER_ID"
        return 0
    fi
    
    print_section "Select Container ID"
    
    # Get next available ID using Proxmox built-in function
    local first_free_id
    first_free_id=$(pvesh get /cluster/nextid 2>/dev/null)
    
    if [[ -z "$first_free_id" ]]; then
        print_warning "Could not determine next available ID"
        first_free_id=""
    fi
    
    # Prompt user for input with first free ID as default
    while true; do
        if [[ -n "$first_free_id" ]]; then
            read -rp "Container ID [$first_free_id]: " input_id
            CONTAINER_ID="${input_id:-$first_free_id}"
        else
            read -rp "Container ID: " CONTAINER_ID
        fi
        
        # Validation loop
        if ! [[ "$CONTAINER_ID" =~ ^[0-9]+$ ]]; then
            print_error "Container ID must be a number"
            continue
        fi
        
        if pct status "$CONTAINER_ID" &>/dev/null; then
            print_error "Container ID $CONTAINER_ID already exists (LXC)"
            continue
        fi
        
        if qm status "$CONTAINER_ID" &>/dev/null; then
            print_error "Container ID $CONTAINER_ID already exists (VM)"
            continue
        fi
        
        break
    done
    
    # Show info about ID ranges
    echo
    print_info "Using container ID: $CONTAINER_ID"
    
    # Success
    print_success "Container ID confirmed"
    log INFO "Selected container ID: $CONTAINER_ID"
}

select_hostname() {
    if is_silent; then
        HOSTNAME="${DEBLXC_HOSTNAME:-$DEFAULT_HOSTNAME}"
        if ! validate_hostname "$HOSTNAME"; then
            die "Invalid hostname in silent mode: $HOSTNAME"
        fi
        log INFO "Hostname (silent): $HOSTNAME"
        return 0
    fi
    
    print_section "Select Hostname"
    
    print_info "Enter hostname for the container template"
    print_info "Default: $DEFAULT_HOSTNAME"
    echo
    
    while true; do
        read -rp "Hostname [$DEFAULT_HOSTNAME]: " input_hostname
        HOSTNAME="${input_hostname:-$DEFAULT_HOSTNAME}"
        
        if validate_hostname "$HOSTNAME"; then
            break
        fi
        echo
    done
    
    print_success "Hostname: $HOSTNAME"
    log INFO "Selected hostname: $HOSTNAME"
}

select_user_credentials() {
    if is_silent; then
        USERNAME="${DEBLXC_USERNAME:-}"
        PASSWORD="${DEBLXC_PASSWORD:-}"
        
        if [[ -z "$USERNAME" ]]; then
            die "DEBLXC_USERNAME not set in silent mode"
        fi
        
        if [[ -z "$PASSWORD" ]]; then
            die "DEBLXC_PASSWORD not set in silent mode"
        fi
        
        if ! validate_username "$USERNAME"; then
            die "Invalid username in silent mode: $USERNAME"
        fi
        
        if ! validate_password "$PASSWORD"; then
            die "Invalid password in silent mode"
        fi
        
        log INFO "Username (silent): $USERNAME"
        log INFO "Password set (silent mode)"
        return 0
    fi
    
    print_section "Configure User Credentials"
    
    # Username
    print_info "Enter non-root username (will have sudo privileges)"
    echo
    
    while true; do
        read -rp "Username: " USERNAME
        
        if validate_username "$USERNAME"; then
            break
        fi
        echo
    done
    
    print_success "Username: $USERNAME"
    log INFO "Username set: $USERNAME"
    
    # Password
    echo
    print_info "Enter password for user $USERNAME"
    print_info "Requirements: 8+ characters, 1 number, 1 special character"
    echo
    
    while true; do
        read -rsp "Password: " PASSWORD
        echo
        
        if validate_password "$PASSWORD"; then
            read -rsp "Confirm password: " PASSWORD_CONFIRM
            echo
            
            if [[ "$PASSWORD" == "$PASSWORD_CONFIRM" ]]; then
                break
            else
                print_error "Passwords do not match"
                echo
            fi
        else
            echo
        fi
    done
    
    print_success "Password set for user $USERNAME"
    log INFO "Password configured for $USERNAME"
}

select_network_bridge() {
    if is_silent; then
        BRIDGE="${DEBLXC_BRIDGE:-$DEFAULT_BRIDGE}"
        log INFO "Network bridge (silent): $BRIDGE"
        return 0
    fi
    
    print_section "Select Network Bridge"
    
    # Get bridges and filter to only vmbr* (exclude firewall bridges fwbr*)
    local bridges
    mapfile -t bridges < <(ip -o link show type bridge | awk -F': ' '{print $2}' | grep '^vmbr')
    
    if [[ ${#bridges[@]} -eq 0 ]]; then
        print_warning "No vmbr bridges detected, using default: $DEFAULT_BRIDGE"
        BRIDGE="$DEFAULT_BRIDGE"
        log WARN "No vmbr bridges found, using default: $DEFAULT_BRIDGE"
        return 0
    fi
    
    # Use first available bridge as default
    local first_bridge="${bridges[0]}"
    
    print_info "Available network bridges:"
    echo
    
    local i=1
    for bridge in "${bridges[@]}"; do
        echo "  $i) $bridge"
        ((i++))
    done
    
    echo
    read -rp "Select bridge [1-${#bridges[@]}] or press Enter for $first_bridge: " choice
    
    if [[ -z "$choice" ]]; then
        BRIDGE="$first_bridge"
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#bridges[@]} ]]; then
        BRIDGE="${bridges[$((choice-1))]}"
    else
        print_warning "Invalid selection, using default: $first_bridge"
        BRIDGE="$first_bridge"
    fi
    
    echo
    print_success "Network bridge: $BRIDGE"
    log INFO "Selected bridge: $BRIDGE"
}

#############################################################################
# Template Operations                                                       #
#############################################################################

download_template() {
    print_section "Download Debian Template"
    
    # Get latest Debian template
    local available_templates
    available_templates=$(pveam available --section system | grep debian)
    
    if [[ -z "$available_templates" ]]; then
        die "No Debian templates available"
    fi
    
    # Get the latest Debian template name
    TEMPLATE_NAME=$(echo "$available_templates" | grep -E 'debian-[0-9]+-standard' | tail -n1 | awk '{print $2}')
    
    if [[ -z "$TEMPLATE_NAME" ]]; then
        die "Could not determine latest Debian template"
    fi
    
    # Parse Debian version from template name (e.g., debian-13-standard → debian13)
    local debian_version
    debian_version=$(echo "$TEMPLATE_NAME" | grep -oP 'debian-\K[0-9]+' || echo "")
    DEBIAN_TAG="${debian_version:+debian${debian_version}}"
    DEBIAN_TAG="${DEBIAN_TAG:-debian}"  # Fallback to "debian" if parsing fails
    
    print_info "Latest Debian template: $TEMPLATE_NAME"
    log INFO "Latest template identified: $TEMPLATE_NAME (version: ${DEBIAN_TAG})"
    
    # Check if template already downloaded
    TEMPLATE_PATH="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE_NAME}"
    
    if pvesm list "$TEMPLATE_STORAGE" | grep -q "$TEMPLATE_NAME"; then
        print_success "Template already downloaded: $TEMPLATE_NAME"
        log INFO "Template already exists: $TEMPLATE_NAME"
    else
        run_with_spinner "Downloading Debian template" \
            pveam download "$TEMPLATE_STORAGE" "$TEMPLATE_NAME"
        
        # Verify download
        if ! pvesm list "$TEMPLATE_STORAGE" | grep -q "$TEMPLATE_NAME"; then
            die "Template download verification failed"
        fi
        
        print_success "Template downloaded: $TEMPLATE_NAME"
        log SUCCESS "Template download completed: $TEMPLATE_NAME"
    fi
}

create_container() {
    print_section "Create Container"
    
    # Build pct create command
    local pct_args=(
        "$CONTAINER_ID"
        "$TEMPLATE_PATH"
        --arch amd64
        --ostype debian
        --hostname "$HOSTNAME"
        --unprivileged 1
        --features nesting=1
        --password "$PASSWORD"
        --ignore-unpack-errors
        --storage "$ROOTFS_STORAGE"
        --rootfs "$ROOTFS_STORAGE:$DEFAULT_DISK"
        --cores "$DEFAULT_CORES"
        --memory "$DEFAULT_MEMORY"
        --swap "$DEFAULT_SWAP"
        --net0 "name=eth0,bridge=$BRIDGE,firewall=1,ip=dhcp"
        --start 1
    )
    
    # Add SSH keys if available
    if [[ "$SSH_KEYS_AVAILABLE" == true ]]; then
        pct_args+=(--ssh-public-keys /root/.ssh/authorized_keys)
        log INFO "Adding SSH keys to container"
    fi
    
    log INFO "Creating container with ID $CONTAINER_ID"
    
    run_with_spinner "Creating and starting container $CONTAINER_ID" \
        pct create "${pct_args[@]}" || die "Failed to create container"
    
    print_success "Container created and started"
    log SUCCESS "Container $CONTAINER_ID created"
    
    # Wait for container to initialize
    print_info "Waiting ${CONTAINER_INIT_WAIT}s for container to initialize..."
    sleep "$CONTAINER_INIT_WAIT"
    log INFO "Container initialization wait completed"
}

configure_container() {
    print_section "Configure Container"
    
    # Configure locales
    log INFO "Configuring locales in container"
    
    run_with_spinner "Configuring locales and upgrading packages" \
        pct exec "$CONTAINER_ID" -- bash -c "
            export DEBIAN_FRONTEND=noninteractive
            export LANG=C.UTF-8 LC_ALL=C.UTF-8
            apt-get update -y
            apt-get upgrade -y
            apt-get install -y locales
            sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
            locale-gen en_US.UTF-8
            update-locale LANG=en_US.UTF-8
            echo 'LANG=en_US.UTF-8' >> /etc/environment
            echo 'LC_ALL=en_US.UTF-8' >> /etc/environment
        " || die "Failed to configure locales"
    
    print_success "Locales configured"
    log SUCCESS "Locales configuration completed"
    
    # Install packages and create user
    log INFO "Installing sudo and cloud-init, creating user $USERNAME"
    
    run_with_spinner "Installing packages and creating user $USERNAME" \
        pct exec "$CONTAINER_ID" -- bash -c "
            apt-get install -y sudo cloud-init
            adduser --gecos ',,,,' --disabled-password '$USERNAME'
            usermod -aG sudo '$USERNAME'
            echo '$USERNAME:$PASSWORD' | chpasswd
            passwd -l root
        " || die "Failed to configure user"
    
    print_success "User '$USERNAME' created with sudo access"
    log SUCCESS "User $USERNAME created with sudo privileges"
    
    # Configure Cloud-Init for SSH key regeneration
    print_step "Configuring Cloud-Init..."
    log INFO "Configuring Cloud-Init for SSH regeneration"
    
    pct exec "$CONTAINER_ID" -- bash -lc '
        set -e
        for u in cloud-init-local.service cloud-init-main.service cloud-init-network.service cloud-config.service cloud-final.service cloud-init.target; do
            systemctl list-unit-files "$u" >/dev/null 2>&1 && systemctl enable "$u" >/dev/null 2>&1 || true
        done
    ' >> "$LOG_FILE" 2>&1 || print_warning "Some Cloud-Init services may not be available"
    
    pct exec "$CONTAINER_ID" -- bash -c "
        mkdir -p /var/lib/cloud/seed/nocloud
        cat > /var/lib/cloud/seed/nocloud/user-data <<EOF
#cloud-config
ssh_deletekeys: true
ssh_genkeytypes: [ \"rsa\", \"ecdsa\", \"ed25519\" ]
EOF
        touch /var/lib/cloud/seed/nocloud/meta-data
    " >> "$LOG_FILE" 2>&1 || die "Failed to configure Cloud-Init"
    
    print_success "Cloud-Init configured for SSH key regeneration"
    log SUCCESS "Cloud-Init configured"
    
    # Clean up for template
    log INFO "Cleaning container for template conversion"
    
    run_with_spinner "Preparing container for template conversion" \
        pct exec "$CONTAINER_ID" -- bash -c "
            apt-get clean
            rm -f /etc/ssh/ssh_host_*
            rm -f /etc/machine-id
            touch /etc/machine-id
            truncate -s 0 /var/log/*log 2>/dev/null || true
        " || die "Failed to clean up container"
    
    print_success "Container prepared for template conversion"
    log SUCCESS "Container cleanup completed"
}

convert_to_template() {
    print_section "Convert to Template"
    
    # Add tags and description
    print_step "Adding template metadata..."
    cat >> "/etc/pve/lxc/${CONTAINER_ID}.conf" <<EOF
tags: ct,template,${DEBIAN_TAG}
description: <details><summary>Click to expand</summary>Debian ${DEBIAN_TAG} LXC Template - Created by lab/deblxc.sh v${SCRIPT_VERSION}</details>
EOF
    log INFO "Added tags (ct,template,${DEBIAN_TAG}) and description to container config"
    
    # Stop and convert
    log INFO "Stopping container $CONTAINER_ID"
    
    run_with_spinner "Stopping container $CONTAINER_ID" \
        pct stop "$CONTAINER_ID" || die "Failed to stop container"
    
    print_success "Container stopped"
    log INFO "Container $CONTAINER_ID stopped"
    
    print_step "Converting to template..."
    if ! pct template "$CONTAINER_ID" 2>&1 | tee -a "$LOG_FILE"; then
        die "Failed to convert to template"
    fi
    
    print_success "Container $CONTAINER_ID converted to template"
    log SUCCESS "Template conversion completed"
}

#############################################################################
# Main Installation Flow                                                    #
#############################################################################

show_intro() {
    echo
    draw_box "Debian LXC Template Creator v${SCRIPT_VERSION}" \
        "Creates reusable Debian LXC templates for Proxmox VE" \
        "" \
        "Features:" \
        "  ${SYMBOL_BULLET} Unprivileged container with nesting" \
        "  ${SYMBOL_BULLET} Non-root user with sudo privileges" \
        "  ${SYMBOL_BULLET} Cloud-Init SSH key regeneration" \
        "  ${SYMBOL_BULLET} Proper locales and packages" \
        "" \
        "Requirements:" \
        "  ${SYMBOL_BULLET} Proxmox VE host (NOT inside VM/LXC)" \
        "  ${SYMBOL_BULLET} Root privileges" \
        "  ${SYMBOL_BULLET} Storage configured for templates"
    echo
}

confirm_start() {
    if is_silent; then
        log INFO "Silent mode: skipping start confirmation"
        return 0
    fi
    
    read -rp "Ready to create Debian LXC template? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        print_info "Template creation cancelled"
        log INFO "User cancelled template creation"
        exit 0
    fi
    echo
}

check_existing_template() {
    local target_id="${DEBLXC_CONTAINER_ID:-}"
    
    # Only check if ID is set (in silent mode or after prompting)
    if [[ -z "$target_id" ]]; then
        return 0
    fi
    
    if pct status "$target_id" &>/dev/null; then
        print_warning "Container/template $target_id already exists"
        echo
        
        if is_silent; then
            die "Container $target_id exists (set different DEBLXC_CONTAINER_ID)"
        fi
        
        print_info "What would you like to do?"
        echo "  1) Delete and recreate"
        echo "  2) View status"
        echo "  3) Exit"
        echo
        read -rp "Choice [1-3]: " choice
        
        case "$choice" in
            1)
                CONTAINER_ID="$target_id"
                cmd_uninstall || exit 1
                return 0
                ;;
            2)
                CONTAINER_ID="$target_id"
                cmd_status
                exit 0
                ;;
            *)
                print_info "Exiting"
                exit 0
                ;;
        esac
    fi
}

show_summary() {
    echo
    draw_separator
    print_success "Debian LXC Template created successfully!"
    echo
    
    print_info "Template Details:"
    echo "  ${SYMBOL_BULLET} Template ID: $CONTAINER_ID"
    echo "  ${SYMBOL_BULLET} Hostname: $HOSTNAME"
    echo "  ${SYMBOL_BULLET} Username: $USERNAME"
    echo "  ${SYMBOL_BULLET} Storage: $ROOTFS_STORAGE"
    echo "  ${SYMBOL_BULLET} Bridge: $BRIDGE"
    echo "  ${SYMBOL_BULLET} Resources: ${DEFAULT_CORES} cores, ${DEFAULT_MEMORY}MB RAM, ${DEFAULT_DISK}GB disk"
    echo "  ${SYMBOL_BULLET} Tags: ct,template,${DEBIAN_TAG}"
    echo
    
    print_info "Template Configuration:"
    echo "  ${SYMBOL_BULLET} Config: /etc/pve/lxc/${CONTAINER_ID}.conf"
    echo "  ${SYMBOL_BULLET} Template storage: $TEMPLATE_STORAGE"
    echo "  ${SYMBOL_BULLET} Log file: $LOG_FILE"
    echo
    
    print_info "Clone Template:"
    echo "  pct clone $CONTAINER_ID <new-id> --hostname <new-name> --full"
    echo
    
    print_info "Manage Template:"
    echo "  ./deblxc.sh --status        # View template status"
    echo "  ./deblxc.sh --logs          # View creation logs"
    echo "  ./deblxc.sh --uninstall     # Delete template"
    echo
    
    print_info "List All Templates:"
    echo "  pct list | grep template"
    echo
    
    print_info "Delete Template:"
    echo "  pct destroy $CONTAINER_ID"
    echo
    
    print_info "Important Notes:"
    echo "  ${SYMBOL_BULLET} SSH keys will be regenerated automatically via Cloud-Init on first boot"
    echo "  ${SYMBOL_BULLET} Use --full flag when cloning to create independent copy"
    echo "  ${SYMBOL_BULLET} Default login: $USERNAME (password set during creation)"
    draw_separator
}

cmd_install() {
    # Clear screen if interactive
    [[ -t 1 ]] && ! is_silent && clear
    
    setup_logging
    
    show_intro
    
    preflight_checks
    
    # Check if template already exists (only if ID specified in silent mode)
    check_existing_template
    
    confirm_start
    
    # Interactive prompts (skipped in silent mode)
    select_template_storage
    select_rootfs_storage
    select_container_id
    
    # Now check again after we have the ID
    check_existing_template
    
    select_hostname
    select_user_credentials
    select_network_bridge
    
    # Template operations
    download_template
    create_container
    configure_container
    convert_to_template
    
    # Summary
    show_summary
    
    log SUCCESS "Template $CONTAINER_ID created successfully"
}

#############################################################################
# Main Entry Point                                                          #
#############################################################################

main() {
    case "${1:-}" in
        --status)
            setup_logging
            cmd_status
            ;;
        --logs)
            cmd_logs "${2:-50}"
            ;;
        --configure)
            cmd_configure
            ;;
        --uninstall)
            setup_logging
            cmd_uninstall
            ;;
        --version|-v)
            echo "${SCRIPT_NAME}.sh version ${SCRIPT_VERSION}"
            exit 0
            ;;
        --help|-h)
            # Already handled above
            exit 0
            ;;
        "")
            # Default: install
            cmd_install
            ;;
        *)
            echo "Unknown command: $1" >&2
            echo "Run './deblxc.sh --help' for usage information" >&2
            exit 1
            ;;
    esac
}

main "$@"
