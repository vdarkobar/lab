#!/bin/bash

#############################################################################
# Debian VM Template Creator for Proxmox VE                                 #
# Source: https://github.com/vdarkobar/lab                                  #
#                                                                           #
# This script:                                                              #
#   1. Downloads Debian cloud image with checksum verification              #
#   2. Customizes image (virt-customize: user, SSH, cloud-init)             #
#   3. Creates Proxmox VM with optimal hardware settings                    #
#   4. Imports disk, configures cloud-init, converts to template            #
#                                                                           #
# REQUIREMENTS:                                                             #
#   - Proxmox VE host (MUST run on PVE host, NOT inside VM/LXC)            #
#   - Root privileges (uses qm, pvesm, pvesh commands)                     #
#   - libguestfs-tools (auto-installed if missing)                          #
#   - Storage configured for VM images                                      #
#                                                                           #
# ENVIRONMENT VARIABLES (for non-interactive mode):                         #
#   DEBVM_SILENT=true              - Non-interactive mode (no prompts)      #
#   DEBVM_ID                       - VM ID (e.g., "9000")                   #
#   DEBVM_HOSTNAME                 - Hostname (default: debvm)              #
#   DEBVM_USERNAME                 - Non-root username                      #
#   DEBVM_PASSWORD                 - User password                          #
#   DEBVM_STORAGE                  - Storage for VM disk (e.g., "local-lvm")#
#   DEBVM_MEMORY                   - Memory in MB (default: 4096)           #
#   DEBVM_CORES                    - CPU cores (default: 4)                 #
#   DEBVM_BRIDGE                   - Network bridge (default: vmbr0)        #
#   DEBVM_IMAGE_URL                - Custom cloud image URL                 #
#   DEBVM_SKIP_CHECKSUM=true       - Skip SHA512 verification              #
#   DEBVM_KEEP_DOWNLOADS=true      - Keep downloaded image after creation   #
#############################################################################

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="debvm"

#############################################################################
# Handle --help BEFORE set -euo pipefail                                    #
#############################################################################

if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    cat << 'EOF'
Debian VM Template Creator for Proxmox VE

DESCRIPTION:
    Creates a reusable Debian VM template with:
    - Debian cloud image with SHA512 checksum verification
    - virt-customize hardening (root locked, SSH cleaned, cloud-init)
    - Non-root user with sudo privileges
    - Optimal hardware: virtio-scsi, cloud-init drive, guest agent
    - Cloud-init userdata for hostname and package installation

USAGE:
    debvm.sh [COMMAND]

COMMANDS:
    (no args)         Create Debian VM template (default)
    --status          Show existing template status
    --logs [N]        Show last N lines of logs (default: 50)
    --configure       Create additional template (re-run creation)
    --uninstall       Delete template
    --version, -v     Show version
    --help, -h        Show this help

ENVIRONMENT VARIABLES (for non-interactive mode):
    DEBVM_SILENT=true              Non-interactive mode
    DEBVM_ID                       VM ID (e.g., "9000")
    DEBVM_HOSTNAME                 Hostname (default: debvm)
    DEBVM_USERNAME                 Non-root username
    DEBVM_PASSWORD                 User password
    DEBVM_STORAGE                  Storage for VM disk (e.g., "local-lvm")
    DEBVM_MEMORY                   Memory in MB (default: 4096)
    DEBVM_CORES                    CPU cores (default: 4)
    DEBVM_BRIDGE                   Network bridge (default: vmbr0)
    DEBVM_IMAGE_URL                Custom cloud image URL
    DEBVM_SKIP_CHECKSUM=true       Skip SHA512 verification
    DEBVM_KEEP_DOWNLOADS=true      Keep downloaded image after creation

EXAMPLES:
    # Interactive creation:
    ./debvm.sh

    # Fully automated:
    DEBVM_SILENT=true \
    DEBVM_ID=9000 \
    DEBVM_HOSTNAME=debian-tpl \
    DEBVM_USERNAME=admin \
    DEBVM_PASSWORD='SecurePass1!' \
    DEBVM_STORAGE=local-lvm \
    DEBVM_BRIDGE=vmbr0 \
    ./debvm.sh

    # Check template status:
    ./debvm.sh --status

    # View creation logs:
    ./debvm.sh --logs 100

    # Delete template:
    ./debvm.sh --uninstall

FILES:
    /var/lib/vz/snippets/userdata-<id>.yaml  Cloud-init config
    /var/log/lab/debvm-*.log                 Installation logs

CLONE TEMPLATE:
    qm clone <template-id> <new-id> --name <hostname> --full

NOTES:
    - MUST run on Proxmox VE host (not inside VM/LXC)
    - Requires root privileges
    - SSH keys regenerated automatically via cloud-init on first boot
    - Uses virt-customize for image hardening (requires libguestfs-tools)
    - Password requirements: 8+ chars, 1 number, 1 special character

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

export DEBIAN_FRONTEND=noninteractive

# Defaults (can be overridden via environment variables)
readonly DEFAULT_IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-nocloud-amd64.qcow2"
readonly DEFAULT_HOSTNAME="debvm"
readonly DEFAULT_MEMORY="${DEBVM_MEMORY:-4096}"
readonly DEFAULT_CORES="${DEBVM_CORES:-4}"
readonly DEFAULT_BRIDGE="${DEBVM_BRIDGE:-vmbr0}"
readonly MIN_MEMORY=512
readonly MIN_DISK_SPACE_GB=8

# Paths
readonly TEMPLATE_DIR="/var/lib/vz/template/iso"
readonly SNIPPET_DIR="/var/lib/vz/snippets"

# Reserved hostnames
readonly RESERVED_NAMES=(
    "localhost" "domain" "local" "host" "broadcasthost"
    "localdomain" "loopback" "wpad" "gateway" "dns"
    "mail" "ftp" "web" "router" "proxy"
)

# Set SILENT mode from environment
readonly SILENT="${DEBVM_SILENT:-false}"

# Track unattended-upgrades state (not applicable on PVE host, but included for consistency)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

# Globals
CLEANUP_FILES=()
CREATED_VM_ID=""
VM_ID=""

# libguestfs backend
export LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}"

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
    
    # Clean up temporary files
    if [[ ${#CLEANUP_FILES[@]} -gt 0 ]]; then
        for file in "${CLEANUP_FILES[@]}"; do
            [[ -f "$file" ]] && rm -f "$file" && log INFO "Removed: $(basename "$file")"
        done
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        echo
        print_error "Script failed with exit code: $exit_code"
        print_warning "Check log file: $LOG_FILE"
        
        # Warn about partial VM
        if [[ -n "${CREATED_VM_ID:-}" ]]; then
            print_warning "Partial VM $CREATED_VM_ID may exist - check manually"
            print_info "Delete with: qm destroy $CREATED_VM_ID --purge 1"
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
        if [[ "${input_name,,}" == "${name,,}" ]]; then
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
    
    if [[ "$username" =~ ^[a-z_][a-z0-9_-]{2,15}$ ]]; then
        return 0
    fi
    
    print_error "Invalid username format"
    print_info "Requirements: 3-16 chars, lowercase letters, numbers, underscore, hyphen (must start with letter or underscore)"
    return 1
}

validate_password() {
    local password="$1"
    local -a errors=()
    
    [[ ${#password} -lt 8 ]] && errors+=("Minimum 8 characters")
    [[ ! "$password" =~ [0-9] ]] && errors+=("Must contain at least one number")
    [[ ! "$password" =~ [^a-zA-Z0-9] ]] && errors+=("Must contain at least one special character (!@#\$%^&*)")
    
    if [[ ${#errors[@]} -gt 0 ]]; then
        print_error "Password requirements not met:"
        printf '  %s %s\n' "${SYMBOL_BULLET}" "${errors[@]}"
        return 1
    fi
    return 0
}

validate_memory() {
    local memory="$1"
    local max_memory
    max_memory="$(free -m | awk '/^Mem:/{print $2}')"
    
    if [[ ! "$memory" =~ ^[0-9]+$ ]]; then
        print_error "Memory must be a number"
        return 1
    fi
    if (( memory < MIN_MEMORY )); then
        print_error "Memory must be at least ${MIN_MEMORY}MB"
        return 1
    fi
    if (( memory > max_memory )); then
        print_error "Memory exceeds available: ${max_memory}MB"
        return 1
    fi
    return 0
}

validate_cores() {
    local cores="$1"
    local max_cores
    max_cores="$(nproc)"
    
    if [[ ! "$cores" =~ ^[0-9]+$ ]]; then
        print_error "Cores must be a number"
        return 1
    fi
    if (( cores < 1 )); then
        print_error "Must have at least 1 core"
        return 1
    fi
    if (( cores > max_cores )); then
        print_error "Cores exceed available: $max_cores"
        return 1
    fi
    return 0
}

validate_storage_space() {
    local storage="$1"
    log STEP "Validating storage space"
    
    # pvesm status columns:
    # Name Type Status Total(KiB) Used(KiB) Available(KiB) %
    local available_kib
    available_kib="$(pvesm status -storage "$storage" 2>/dev/null | awk -v s="$storage" 'NR>1 && $1==s {print $6; exit}')"
    
    if [[ "$available_kib" =~ ^[0-9]+$ ]]; then
        local available_gib=$(( available_kib / 1024 / 1024 ))
        if (( available_gib < MIN_DISK_SPACE_GB )); then
            print_error "Insufficient space on $storage: ${available_gib}GB available, ${MIN_DISK_SPACE_GB}GB required"
            return 1
        fi
        print_success "Storage space: ${available_gib}GB available on $storage"
        log SUCCESS "Storage space: ${available_gib}GB available"
        return 0
    fi
    
    print_warning "Could not determine storage space for $storage (will proceed anyway)"
    log WARN "Could not determine storage space for $storage"
    return 0
}

#############################################################################
# Preflight Checks                                                          #
#############################################################################

preflight_checks() {
    print_section "Preflight Checks"
    
    # Check if running on Proxmox VE (MUST be on PVE host)
    if [[ ! -f /etc/pve/.version ]] && ! command_exists pveversion; then
        die "This script MUST run on a Proxmox VE host (not inside VM/LXC)"
    fi
    print_success "Proxmox VE host detected"
    log INFO "Running on Proxmox VE host"
    
    # Check if running as root (REQUIRED for PVE operations)
    if [[ $EUID -ne 0 ]]; then
        die "This script must run as root (uses qm, pvesm, pvesh commands)"
    fi
    print_success "Running as root"
    log INFO "Running with root privileges"
    
    # Check for required PVE commands
    local required_cmds=("qm" "pvesm" "pvesh" "wget")
    for cmd in "${required_cmds[@]}"; do
        if ! command_exists "$cmd"; then
            die "Required command not found: $cmd"
        fi
    done
    print_success "All required commands available"
    log INFO "Verified: qm, pvesm, pvesh, wget commands present"
    
    # Check/install libguestfs-tools (provides virt-customize)
    if ! command_exists virt-customize; then
        print_step "Installing libguestfs-tools (provides virt-customize)..."
        log INFO "Installing libguestfs-tools..."
        run_with_spinner "Installing libguestfs-tools" \
            apt-get install -y libguestfs-tools || die "Failed to install libguestfs-tools"
        log SUCCESS "libguestfs-tools installed"
    fi
    print_success "virt-customize available"
    log INFO "virt-customize present"
    
    # Verify additional required commands
    local extra_cmds=("sha512sum" "awk" "grep" "sed" "tee")
    local missing=()
    for cmd in "${extra_cmds[@]}"; do
        command_exists "$cmd" || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing commands: ${missing[*]}"
    fi
    
    print_success "Preflight checks passed"
    log SUCCESS "Preflight checks completed"
}

#############################################################################
# CLI Command Handlers                                                      #
#############################################################################

cmd_status() {
    local target_id="${DEBVM_ID:-${VM_ID:-}}"
    
    if [[ -z "$target_id" ]]; then
        print_warning "No VM ID specified"
        print_info "Set DEBVM_ID environment variable or specify during creation"
        return 1
    fi
    
    print_section "Template Status: $target_id"
    
    if ! qm status "$target_id" &>/dev/null; then
        print_warning "VM/template $target_id does not exist"
        log INFO "Status check: VM $target_id not found"
        return 1
    fi
    
    local config_file="/etc/pve/qemu-server/${target_id}.conf"
    if [[ -f "$config_file" ]]; then
        print_info "Template ID: $target_id"
        print_info "Config file: $config_file"
        log INFO "Found config: $config_file"
        
        if grep -q "^template: 1" "$config_file" 2>/dev/null; then
            print_success "Status: Template (ready to clone)"
            log INFO "VM $target_id is a template"
            
            # Show template details
            echo
            print_info "Template Details:"
            grep -E "^(name|cores|memory|balloon|net0|scsi0|cpu)" "$config_file" 2>/dev/null | while read -r line; do
                echo "  ${SYMBOL_BULLET} $line"
            done
        else
            local vm_status
            vm_status=$(qm status "$target_id" 2>/dev/null | awk '{print $2}')
            print_warning "Status: VM ($vm_status) - not yet converted to template"
            log WARN "VM $target_id exists but is not a template"
        fi
        
        # Check for cloud-init userdata
        local userdata_file="$SNIPPET_DIR/userdata-${target_id}.yaml"
        if [[ -f "$userdata_file" ]]; then
            echo
            print_info "Cloud-init userdata: $userdata_file"
        fi
        
        echo
        print_info "Clone with:"
        echo "  qm clone $target_id <new-id> --name <hostname> --full"
        
        echo
        print_info "Delete with:"
        echo "  ./debvm.sh --uninstall"
        echo "  OR: qm destroy $target_id --purge 1"
    else
        print_error "Config file not found: $config_file"
        log ERROR "Config file missing for VM $target_id"
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
    local target_id="${DEBVM_ID:-${VM_ID:-}}"
    
    if [[ -z "$target_id" ]]; then
        print_error "No VM ID specified"
        print_info "Set DEBVM_ID environment variable"
        return 1
    fi
    
    if ! qm status "$target_id" &>/dev/null; then
        print_error "VM/template $target_id does not exist"
        return 1
    fi
    
    print_section "Uninstall Template: $target_id"
    
    # Show what will be deleted
    local config_file="/etc/pve/qemu-server/${target_id}.conf"
    if [[ -f "$config_file" ]]; then
        echo
        print_info "Template details:"
        grep -E "^(name|scsi0)" "$config_file" 2>/dev/null | while read -r line; do
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
    if qm destroy "$target_id" --purge 1 2>/dev/null; then
        print_success "Template $target_id deleted successfully"
        log INFO "Template $target_id destroyed"
    else
        print_error "Failed to delete template $target_id"
        log ERROR "Failed to destroy template $target_id"
        return 1
    fi
    
    # Clean up cloud-init userdata
    local userdata_file="$SNIPPET_DIR/userdata-${target_id}.yaml"
    if [[ -f "$userdata_file" ]]; then
        rm -f "$userdata_file"
        print_success "Removed cloud-init userdata: $userdata_file"
        log INFO "Removed userdata: $userdata_file"
    fi
    
    echo
    print_info "Installation logs preserved at: /var/log/lab/${SCRIPT_NAME}-*.log"
}

#############################################################################
# Interactive Prompts (with Silent Mode Support)                           #
#############################################################################

get_next_vm_id() {
    pvesh get /cluster/nextid 2>/dev/null || echo "100"
}

get_network_bridges() {
    ip -o link show | awk -F': ' '{print $2}' | grep '^vmbr' || echo "vmbr0"
}

get_available_storages() {
    pvesm status -content images 2>/dev/null | awk 'NR>1 && $1 ~ /^[a-zA-Z]/ {print $1}' || echo "local-lvm"
}

select_vm_id() {
    if is_silent; then
        VM_ID="${DEBVM_ID:-}"
        if [[ -z "$VM_ID" ]]; then
            VM_ID=$(get_next_vm_id)
            log INFO "VM ID auto-assigned (silent): $VM_ID"
        fi
        
        if ! [[ "$VM_ID" =~ ^[0-9]+$ ]]; then
            die "Invalid VM ID: $VM_ID (must be numeric)"
        fi
        
        log INFO "VM ID (silent): $VM_ID"
        return 0
    fi
    
    print_section "Select VM ID"
    
    local first_free_id
    first_free_id=$(get_next_vm_id)
    
    if [[ -z "$first_free_id" ]]; then
        print_warning "Could not determine next available ID"
        first_free_id=""
    fi
    
    while true; do
        if [[ -n "$first_free_id" ]]; then
            read -rp "VM ID [$first_free_id]: " input_id
            VM_ID="${input_id:-$first_free_id}"
        else
            read -rp "VM ID: " VM_ID
        fi
        
        if ! [[ "$VM_ID" =~ ^[0-9]+$ ]]; then
            print_error "VM ID must be a number"
            continue
        fi
        
        if qm status "$VM_ID" &>/dev/null; then
            print_error "VM ID $VM_ID already exists"
            continue
        fi
        
        break
    done
    
    echo
    print_success "VM ID: $VM_ID"
    log INFO "Selected VM ID: $VM_ID"
}

select_storage() {
    if is_silent; then
        VM_STORAGE="${DEBVM_STORAGE:-}"
        if [[ -z "$VM_STORAGE" ]]; then
            VM_STORAGE=$(get_available_storages | head -n1)
            log INFO "Storage auto-selected (silent): $VM_STORAGE"
        fi
        log INFO "Storage (silent): $VM_STORAGE"
        return 0
    fi
    
    print_section "Select VM Storage"
    
    local storages
    mapfile -t storages < <(get_available_storages)
    
    if [[ ${#storages[@]} -eq 0 ]]; then
        die "No storage with 'images' content type found"
    fi
    
    print_info "Available storages (content: images):"
    echo
    
    local i=1
    for storage in "${storages[@]}"; do
        echo "  $i) $storage"
        ((i++))
    done
    
    local default_storage="${storages[0]}"
    echo
    while true; do
        read -rp "Select storage [1-${#storages[@]}] or press Enter for $default_storage: " choice
        
        if [[ -z "$choice" ]]; then
            VM_STORAGE="$default_storage"
            break
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#storages[@]} ]]; then
            VM_STORAGE="${storages[$((choice-1))]}"
            break
        fi
        print_error "Invalid selection. Please choose 1-${#storages[@]}"
    done
    
    print_success "Storage: $VM_STORAGE"
    log INFO "Selected storage: $VM_STORAGE"
}

select_hostname() {
    if is_silent; then
        VM_HOSTNAME="${DEBVM_HOSTNAME:-$DEFAULT_HOSTNAME}"
        if ! validate_hostname "$VM_HOSTNAME"; then
            die "Invalid hostname in silent mode: $VM_HOSTNAME"
        fi
        log INFO "Hostname (silent): $VM_HOSTNAME"
        return 0
    fi
    
    print_section "Select Hostname"
    
    print_info "Enter hostname for the VM template"
    print_info "Default: $DEFAULT_HOSTNAME"
    echo
    
    while true; do
        read -rp "Hostname [$DEFAULT_HOSTNAME]: " input_hostname
        VM_HOSTNAME="${input_hostname:-$DEFAULT_HOSTNAME}"
        
        if validate_hostname "$VM_HOSTNAME"; then
            break
        fi
        echo
    done
    
    print_success "Hostname: $VM_HOSTNAME"
    log INFO "Selected hostname: $VM_HOSTNAME"
}

select_user_credentials() {
    if is_silent; then
        VM_USERNAME="${DEBVM_USERNAME:-}"
        VM_PASSWORD="${DEBVM_PASSWORD:-}"
        
        if [[ -z "$VM_USERNAME" ]]; then
            die "DEBVM_USERNAME not set in silent mode"
        fi
        
        if [[ -z "$VM_PASSWORD" ]]; then
            die "DEBVM_PASSWORD not set in silent mode"
        fi
        
        if ! validate_username "$VM_USERNAME"; then
            die "Invalid username in silent mode: $VM_USERNAME"
        fi
        
        if ! validate_password "$VM_PASSWORD"; then
            die "Invalid password in silent mode"
        fi
        
        log INFO "Username (silent): $VM_USERNAME"
        log INFO "Password set (silent mode)"
        return 0
    fi
    
    print_section "Configure User Credentials"
    
    # Username
    print_info "Enter non-root username (will have sudo privileges)"
    echo
    
    while true; do
        read -rp "Username: " VM_USERNAME
        
        if [[ -z "$VM_USERNAME" ]]; then
            print_error "Username cannot be empty"
            continue
        fi
        
        if validate_username "$VM_USERNAME"; then
            break
        fi
        echo
    done
    
    print_success "Username: $VM_USERNAME"
    log INFO "Username set: $VM_USERNAME"
    
    # Password
    echo
    print_info "Enter password for user $VM_USERNAME"
    print_info "Requirements: 8+ characters, 1 number, 1 special character"
    echo
    
    while true; do
        read -rsp "Password: " VM_PASSWORD
        echo
        
        if [[ -z "$VM_PASSWORD" ]]; then
            print_error "Password cannot be empty"
            continue
        fi
        
        if validate_password "$VM_PASSWORD"; then
            read -rsp "Confirm password: " password_confirm
            echo
            
            if [[ "$VM_PASSWORD" == "$password_confirm" ]]; then
                break
            else
                print_error "Passwords do not match"
                echo
            fi
        else
            echo
        fi
    done
    
    print_success "Password set for user $VM_USERNAME"
    log INFO "Password configured for $VM_USERNAME"
}

select_memory() {
    if is_silent; then
        VM_MEMORY="${DEBVM_MEMORY:-$DEFAULT_MEMORY}"
        if ! validate_memory "$VM_MEMORY"; then
            die "Invalid memory in silent mode: $VM_MEMORY"
        fi
        log INFO "Memory (silent): ${VM_MEMORY}MB"
        return 0
    fi
    
    print_section "Select Memory"
    
    local max_memory
    max_memory="$(free -m | awk '/^Mem:/{print $2}')"
    
    print_info "Memory range: ${MIN_MEMORY}MB to ${max_memory}MB"
    echo
    
    while true; do
        read -rp "Memory in MB [$DEFAULT_MEMORY]: " input_memory
        VM_MEMORY="${input_memory:-$DEFAULT_MEMORY}"
        
        if validate_memory "$VM_MEMORY"; then
            break
        fi
        echo
    done
    
    print_success "Memory: ${VM_MEMORY}MB"
    log INFO "Selected memory: ${VM_MEMORY}MB"
}

select_cores() {
    if is_silent; then
        VM_CORES="${DEBVM_CORES:-$DEFAULT_CORES}"
        if ! validate_cores "$VM_CORES"; then
            die "Invalid cores in silent mode: $VM_CORES"
        fi
        log INFO "Cores (silent): $VM_CORES"
        return 0
    fi
    
    print_section "Select CPU Cores"
    
    local max_cores
    max_cores="$(nproc)"
    
    print_info "Cores range: 1 to $max_cores"
    echo
    
    while true; do
        read -rp "CPU Cores [$DEFAULT_CORES]: " input_cores
        VM_CORES="${input_cores:-$DEFAULT_CORES}"
        
        if validate_cores "$VM_CORES"; then
            break
        fi
        echo
    done
    
    print_success "CPU Cores: $VM_CORES"
    log INFO "Selected cores: $VM_CORES"
}

select_network_bridge() {
    if is_silent; then
        VM_BRIDGE="${DEBVM_BRIDGE:-$DEFAULT_BRIDGE}"
        log INFO "Network bridge (silent): $VM_BRIDGE"
        return 0
    fi
    
    print_section "Select Network Bridge"
    
    local bridges
    mapfile -t bridges < <(get_network_bridges)
    
    if [[ ${#bridges[@]} -eq 0 ]]; then
        print_warning "No vmbr bridges detected, using default: $DEFAULT_BRIDGE"
        VM_BRIDGE="$DEFAULT_BRIDGE"
        log WARN "No vmbr bridges found, using default: $DEFAULT_BRIDGE"
        return 0
    fi
    
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
        VM_BRIDGE="$first_bridge"
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#bridges[@]} ]]; then
        VM_BRIDGE="${bridges[$((choice-1))]}"
    else
        print_warning "Invalid selection, using default: $first_bridge"
        VM_BRIDGE="$first_bridge"
    fi
    
    echo
    print_success "Network bridge: $VM_BRIDGE"
    log INFO "Selected bridge: $VM_BRIDGE"
}

select_image_url() {
    if is_silent; then
        IMAGE_URL="${DEBVM_IMAGE_URL:-$DEFAULT_IMAGE_URL}"
        log INFO "Image URL (silent): $IMAGE_URL"
        return 0
    fi
    
    print_section "Select Cloud Image"
    
    print_info "Default: Debian 13 Generic Cloud Image"
    echo "  ${C_DIM}${DEFAULT_IMAGE_URL}${C_RESET}"
    echo
    
    read -rp "Custom image URL (or press Enter for default): " input_url
    IMAGE_URL="${input_url:-$DEFAULT_IMAGE_URL}"
    
    print_success "Image URL set"
    log INFO "Image URL: $IMAGE_URL"
}

#############################################################################
# Template Operations                                                       #
#############################################################################

download_and_verify_image() {
    local image_url="$1"
    local image_name
    image_name="$(basename "$image_url")"
    local checksums_url="${image_url%/*}/SHA512SUMS"
    local skip_checksum="${DEBVM_SKIP_CHECKSUM:-false}"
    local keep_downloads="${DEBVM_KEEP_DOWNLOADS:-false}"
    
    print_section "Download Cloud Image"
    
    mkdir -p "$TEMPLATE_DIR"
    cd "$TEMPLATE_DIR"
    
    # Download checksums
    if [[ "$skip_checksum" != "true" ]]; then
        print_step "Downloading checksums..."
        log INFO "Downloading checksums: $checksums_url"
        wget -q "$checksums_url" -O SHA512SUMS || die "Failed to download checksums"
        CLEANUP_FILES+=("$TEMPLATE_DIR/SHA512SUMS")
    fi
    
    # Download image
    run_with_spinner "Downloading cloud image: $image_name" \
        wget -q -O "$image_name" "$image_url" || die "Failed to download image"
    
    print_success "Image downloaded: $image_name"
    log SUCCESS "Image downloaded: $image_name"
    
    [[ "$keep_downloads" != "true" ]] && CLEANUP_FILES+=("$TEMPLATE_DIR/$image_name")
    
    # Verify checksum
    if [[ "$skip_checksum" != "true" ]]; then
        print_step "Verifying SHA512 checksum..."
        log STEP "Verifying integrity"
        
        local checksum_line
        checksum_line="$(grep -E "([[:space:]]|\\*)${image_name}$" SHA512SUMS | head -n 1 || true)"
        
        if [[ -z "$checksum_line" ]]; then
            die "No checksum found for $image_name in SHA512SUMS"
        fi
        
        echo "$checksum_line" | sha512sum -c --status || die "Checksum verification failed for $image_name"
        
        print_success "Image integrity verified (SHA512)"
        log SUCCESS "Image verified"
    else
        print_warning "Checksum verification skipped (NOT RECOMMENDED)"
        log WARN "Checksum verification skipped"
    fi
    
    # Return image path
    IMAGE_PATH="$TEMPLATE_DIR/$image_name"
}

customize_image() {
    local image_path="$1"
    local username="$2"
    local password="$3"
    
    print_section "Customize Image"
    
    log INFO "Running virt-customize (LIBGUESTFS_BACKEND=$LIBGUESTFS_BACKEND)"
    
    run_with_spinner "Customizing image (lock root, create user, clean SSH)" \
        virt-customize -a "$image_path" \
            --run-command "passwd -l root || true" \
            --run-command "id -u '$username' >/dev/null 2>&1 || useradd -m -s /bin/bash '$username'" \
            --run-command "usermod -aG sudo '$username'" \
            --password "$username:password:$password" \
            --run-command "rm -f /etc/ssh/ssh_host_* || true" \
            --run-command "cloud-init clean --logs --seed || true" \
            --run-command "truncate -s 0 /etc/machine-id || true" \
        || die "virt-customize failed (LIBGUESTFS_BACKEND=$LIBGUESTFS_BACKEND)"
    
    print_success "Image customized"
    log SUCCESS "Image customized"
}

create_cloudinit_userdata() {
    local vm_id="$1"
    local hostname="$2"
    local userdata_file="$SNIPPET_DIR/userdata-${vm_id}.yaml"
    
    mkdir -p "$SNIPPET_DIR"
    
    cat > "$userdata_file" <<EOF
#cloud-config
hostname: ${hostname}
fqdn: ${hostname}
package_update: true
packages:
  - qemu-guest-agent
  - openssh-server
runcmd:
  - systemctl enable --now qemu-guest-agent || true
  - systemctl enable --now ssh || true
EOF
    
    log INFO "Created cloud-init userdata: $userdata_file"
    echo "$userdata_file"
}

create_proxmox_vm() {
    local vm_id="$1"
    local hostname="$2"
    local memory="$3"
    local cores="$4"
    local bridge="$5"
    local storage="$6"
    local image_path="$7"
    local username="$8"
    local password="$9"
    
    print_section "Create VM"
    
    # Step 1: Create VM
    log INFO "Creating VM $vm_id"
    run_with_spinner "Creating VM $vm_id" \
        qm create "$vm_id" --name "$hostname" --memory "$memory" --cores "$cores" \
            --net0 "virtio,bridge=${bridge},firewall=1" \
        || die "Failed to create VM"
    
    CREATED_VM_ID="$vm_id"
    
    # Step 2: Import disk
    print_step "Importing disk into storage: $storage"
    log INFO "Importing disk to $storage"
    
    local tmp_import import_output disk_name
    tmp_import="$(mktemp)"
    CLEANUP_FILES+=("$tmp_import")
    
    run_with_spinner "Importing disk to $storage" \
        bash -c "qm importdisk '$vm_id' '$image_path' '$storage' > '$tmp_import' 2>&1" \
        || die "Failed to import disk"
    
    import_output="$(cat "$tmp_import")"
    
    # Log import output
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "$import_output" >> "$LOG_FILE" 2>/dev/null || true
    fi
    
    # Best-effort parse of the imported volume name
    disk_name="$(echo "$import_output" | grep -oP "successfully imported disk '\K[^']+" | head -n1 || true)"
    [[ -n "$disk_name" ]] || disk_name="${storage}:vm-${vm_id}-disk-0"
    
    log INFO "Disk imported as: $disk_name"
    
    # Step 3: Configure VM hardware
    run_with_spinner "Configuring VM hardware" \
        bash -c "
            qm set '$vm_id' --scsihw virtio-scsi-single --scsi0 '${disk_name},cache=writeback,discard=on,ssd=1'
            qm set '$vm_id' --boot c --bootdisk scsi0
            qm set '$vm_id' --scsi2 '${storage}:cloudinit'
            qm set '$vm_id' --agent enabled=1 --serial0 socket --vga serial0
            qm set '$vm_id' --cpu cputype=host --ostype l26 --ciupgrade 1
            qm set '$vm_id' --balloon 2048
            qm set '$vm_id' --description '<details><summary>Click to expand</summary>Debian VM Template - Created by lab/debvm.sh v${SCRIPT_VERSION}</details>'
            qm set '$vm_id' --ciuser '$username' --cipassword '$password' --ipconfig0 ip=dhcp
            qm set '$vm_id' --tags 'vm,template,debian${DEBIAN_TAG}'
        " || die "Failed to configure VM"
    
    # Step 4: Cloud-init userdata
    # NOTE: qm set does NOT support --hostname; hostname comes from cloud-init user-data.
    print_step "Setting up cloud-init userdata..."
    local userdata_file
    userdata_file="$(create_cloudinit_userdata "$vm_id" "$hostname")"
    qm set "$vm_id" --cicustom "user=local:snippets/$(basename "$userdata_file")" \
        || die "Failed to set cicustom (ensure local storage supports snippets)"
    
    print_success "VM $vm_id created and configured"
    log SUCCESS "VM $vm_id created"
}

convert_to_template() {
    print_section "Convert to Template"
    
    local vm_id="$1"
    
    run_with_spinner "Converting VM $vm_id to template" \
        qm template "$vm_id" || die "Failed to convert to template"
    
    print_success "VM $vm_id converted to template"
    log SUCCESS "Template conversion completed"
}

#############################################################################
# Main Installation Flow                                                    #
#############################################################################

show_intro() {
    echo
    draw_box "Debian VM Template Creator v${SCRIPT_VERSION}" \
        "Creates reusable Debian VM templates for Proxmox VE" \
        "" \
        "Features:" \
        "  ${SYMBOL_BULLET} Debian cloud image with SHA512 verification" \
        "  ${SYMBOL_BULLET} virt-customize hardening (root locked, SSH cleaned)" \
        "  ${SYMBOL_BULLET} Non-root user with sudo privileges" \
        "  ${SYMBOL_BULLET} Cloud-init for hostname and packages" \
        "  ${SYMBOL_BULLET} Optimal hardware: virtio-scsi, guest agent" \
        "" \
        "Requirements:" \
        "  ${SYMBOL_BULLET} Proxmox VE host (NOT inside VM/LXC)" \
        "  ${SYMBOL_BULLET} Root privileges" \
        "  ${SYMBOL_BULLET} Storage configured for VM images"
    echo
}

confirm_start() {
    if is_silent; then
        log INFO "Silent mode: skipping start confirmation"
        return 0
    fi
    
    read -rp "Ready to create Debian VM template? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        print_info "Template creation cancelled"
        log INFO "User cancelled template creation"
        exit 0
    fi
    echo
}

check_existing_template() {
    local target_id="${DEBVM_ID:-${VM_ID:-}}"
    
    # Only check if ID is set
    if [[ -z "$target_id" ]]; then
        return 0
    fi
    
    if qm status "$target_id" &>/dev/null; then
        print_warning "VM/template $target_id already exists"
        echo
        
        if is_silent; then
            die "VM $target_id exists (set different DEBVM_ID)"
        fi
        
        print_info "What would you like to do?"
        echo "  1) Delete and recreate"
        echo "  2) View status"
        echo "  3) Exit"
        echo
        read -rp "Choice [1-3]: " choice
        
        case "$choice" in
            1)
                VM_ID="$target_id"
                cmd_uninstall || exit 1
                return 0
                ;;
            2)
                VM_ID="$target_id"
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
    print_success "Debian VM Template created successfully!"
    echo
    
    print_info "Template Details:"
    echo "  ${SYMBOL_BULLET} Template ID: $VM_ID"
    echo "  ${SYMBOL_BULLET} Hostname: $VM_HOSTNAME"
    echo "  ${SYMBOL_BULLET} Username: $VM_USERNAME"
    echo "  ${SYMBOL_BULLET} Storage: $VM_STORAGE"
    echo "  ${SYMBOL_BULLET} Bridge: $VM_BRIDGE"
    echo "  ${SYMBOL_BULLET} Resources: ${VM_CORES} cores, ${VM_MEMORY}MB RAM, balloon 2048MB"
    echo
    
    print_info "Template Configuration:"
    echo "  ${SYMBOL_BULLET} Config: /etc/pve/qemu-server/${VM_ID}.conf"
    echo "  ${SYMBOL_BULLET} Cloud-init: $SNIPPET_DIR/userdata-${VM_ID}.yaml"
    echo "  ${SYMBOL_BULLET} Log file: $LOG_FILE"
    echo
    
    print_info "Clone Template:"
    echo "  qm clone $VM_ID <new-id> --name <hostname> --full"
    echo
    
    print_info "Manage Template:"
    echo "  ./debvm.sh --status        # View template status"
    echo "  ./debvm.sh --logs          # View creation logs"
    echo "  ./debvm.sh --uninstall     # Delete template"
    echo
    
    print_info "List All Templates:"
    echo "  qm list | grep template"
    echo
    
    print_info "Delete Template:"
    echo "  qm destroy $VM_ID --purge 1"
    echo
    
    print_info "Important Notes:"
    echo "  ${SYMBOL_BULLET} SSH keys regenerated automatically via cloud-init on first boot"
    echo "  ${SYMBOL_BULLET} Use --full flag when cloning to create independent copy"
    echo "  ${SYMBOL_BULLET} Default login: $VM_USERNAME (password set during creation)"
    echo "  ${SYMBOL_BULLET} Cloud-init installs qemu-guest-agent and openssh-server on first boot"
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
    select_vm_id
    
    # Check again after we have the ID
    check_existing_template
    
    select_storage
    select_hostname
    select_user_credentials
    select_memory
    select_cores
    select_network_bridge
    select_image_url
    
    # Validate storage space
    validate_storage_space "$VM_STORAGE" || exit 5
    
    # Show configuration summary
    echo
    draw_separator
    print_info "Configuration Summary:"
    echo "  ${SYMBOL_BULLET} VM ID: $VM_ID"
    echo "  ${SYMBOL_BULLET} Hostname: $VM_HOSTNAME"
    echo "  ${SYMBOL_BULLET} Username: $VM_USERNAME"
    echo "  ${SYMBOL_BULLET} Memory: ${VM_MEMORY}MB"
    echo "  ${SYMBOL_BULLET} Cores: $VM_CORES"
    echo "  ${SYMBOL_BULLET} Bridge: $VM_BRIDGE"
    echo "  ${SYMBOL_BULLET} Storage: $VM_STORAGE"
    echo "  ${SYMBOL_BULLET} Image: $IMAGE_URL"
    draw_separator
    echo
    
    if ! is_silent; then
        read -rp "Proceed with these settings? [Y/n]: " final_confirm
        if [[ "${final_confirm:-Y}" =~ ^[Nn]$ ]]; then
            print_info "Cancelled"
            log INFO "User cancelled after summary"
            exit 0
        fi
    fi
    
    log INFO "Configuration confirmed, proceeding..."
    
    # Derive Debian version tag from image filename (e.g., debian-13-nocloud-amd64.qcow2 → 13)
    DEBIAN_TAG="$(basename "$IMAGE_URL" | grep -oP 'debian-\K[0-9]+' || echo "debian")"
    log INFO "Detected Debian version tag: $DEBIAN_TAG"
    
    # Template operations
    download_and_verify_image "$IMAGE_URL"
    customize_image "$IMAGE_PATH" "$VM_USERNAME" "$VM_PASSWORD"
    create_proxmox_vm "$VM_ID" "$VM_HOSTNAME" "$VM_MEMORY" "$VM_CORES" "$VM_BRIDGE" "$VM_STORAGE" "$IMAGE_PATH" "$VM_USERNAME" "$VM_PASSWORD"
    convert_to_template "$VM_ID"
    
    # Summary
    show_summary
    
    log SUCCESS "Template $VM_ID created successfully"
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
            echo "Run './debvm.sh --help' for usage information" >&2
            exit 1
            ;;
    esac
}

main "$@"
